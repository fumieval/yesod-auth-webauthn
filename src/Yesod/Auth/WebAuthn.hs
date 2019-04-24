{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE Rank2Types, ScopedTypeVariables #-}
{-# LANGUAGE TemplateHaskell #-}
module Yesod.Auth.WebAuthn where
import Yesod.Auth
import Yesod.Core

import Crypto.Random (getRandomBytes)
import Web.WebAuthn as W
import qualified Data.Aeson as J
import qualified Data.ByteString as B
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Conduit as C
import qualified Data.Conduit.Combinators as C
import qualified Data.ByteString.Builder as BB
import qualified Codec.Serialise as CBOR
import qualified Yesod.Auth.Message as Msg
import qualified Text.Julius as Julius

commonUtil :: Julius.JavascriptUrl url
commonUtil = [Julius.js|
function getJSON(path, success)
{
  var xhr = new XMLHttpRequest();
  xhr.onreadystatechange = function()
  {
    if (xhr.readyState === XMLHttpRequest.DONE) {
      if (xhr.status === 200) {
        success(JSON.parse(xhr.responseText));
      } else {
        console.log(xhr);
      }
    }
  };
  xhr.open("GET", path, true);
  xhr.send();
}

function postJSON(path, body, success)
{
  var xhr = new XMLHttpRequest();
  xhr.onreadystatechange = function()
  {
    if (xhr.readyState === XMLHttpRequest.DONE) {
      if (xhr.status === 200) {
        success(xhr.responseText);
      } else {
        console.log(xhr);
      }
    }
  };
  xhr.open("POST", path, true);
  xhr.send(body);
}
|]

addCommonScripts :: MonadWidget m => m ()
addCommonScripts = do
  addScriptRemote "https://cdn.jsdelivr.net/npm/cbor-js@0.1.0/cbor.min.js"
  addScriptRemote "https://cdn.jsdelivr.net/npm/base64-js@1.3.0/base64js.min.js"
  toWidget commonUtil

class YesodAuth site => YesodAuthWebAuthn site where
  webAuthnLookupPubKey :: CredentialId -> AuthHandler site CredentialPublicKey
  webAuthnAddCredential :: CredentialId -> CredentialPublicKey -> AuthHandler site ()
  webAuthnRegisterHandler :: AuthHandler site Html
  webAuthnRegisterHandler = do
    userId <- liftIO $ J.toJSON <$> B.unpack <$> getRandomBytes 64
    authLayout $ do
      addCommonScripts
      setTitleI Msg.RegisterLong
      [whamlet|
        <label for="webauthn-full-name">
          Full name
        <input type="text" id="webauthn-full-name">
        <label for="webauthn-display-name">
          Displayed name
        <input type="text" id="webauthn-display-name">
        <button id="webauthn-register">Register</button>
        <div id="webauthn-result">
      |]
      toWidget [Julius.julius|
        document.getElementById("webauthn-register").addEventListener("click"
          , function(e){
            getJSON("/auth/page/webauthn/challenge", function(challenge){
              let rawChallenge = base64js.toByteArray(challenge);
              let userId = new Uint8Array(#{userId});
              let info =
                  { challenge: rawChallenge
                  , user: {
                    id: userId,
                    name: document.getElementById("webauthn-full-name").value,
                    displayName: document.getElementById("webauthn-display-name").value
                    }
                  , timeout: 60000
                  , rp: {name: "localhost"}
                  , pubKeyCredParams:
                    [{ type: "public-key"
                    , alg: -7
                    }]
                  , attestation: "direct"};
              navigator.credentials.create({publicKey: info})
                .then((cred) => {
                  postJSON("/auth/page/webauthn/register"
                    , CBOR.encode(
                        [ new Uint8Array(cred.response.clientDataJSON)
                        , new Uint8Array(cred.response.attestationObject)
                        , new Uint8Array(rawChallenge)])
                    , function(resp)
                      {
                        window.localStorage.setItem('webauthn-cred-id', cred.id);
                        dump(resp);
                      });
                })
                .catch((err) => {
                  console.log("ERROR", err);
                });
            });
          }
        );|]
  webAuthnLoginHandler :: WidgetFor site ()
  webAuthnLoginHandler = do
    addCommonScripts
    [whamlet|<button id="webauthn-login">Login with WebAuthn</login>|]
    toWidget [Julius.js|
      document.getElementById("webauthn-login").addEventListener("click"
        , function(e){
          getJSON("/auth/page/webauthn/challenge", function(challenge){
            let rawChallenge = base64js.toByteArray(challenge);
            let credStr = window.localStorage.getItem('webauthn-cred-id');
            let credId = base64js.toByteArray((credStr + '==='.slice((credStr.length + 3) % 4))
                .replace(/-/g, '+')
                .replace(/_/g, '/'));
            navigator.credentials.get({publicKey:
              { challenge: rawChallenge
              , allowCredentials:
                [ { type: "public-key", id: credId, transports: ["usb"] }]
              , timeout: 60000
              }})
              .then((cred) => {
                console.log("NEW CREDENTIAL", cred);
                CBOR.encode(cred.response);
                postJSON("/auth/page/webauthn/verify"
                  , CBOR.encode(
                      [ credId
                      , new Uint8Array(cred.response.clientDataJSON)
                      , new Uint8Array(cred.response.authenticatorData)
                      , new Uint8Array(cred.response.signature)
                      , new Uint8Array(rawChallenge)])
                  , function(resp)
                    {
                      dump(resp);
                    });
              })
              .catch((err) => {
                console.log("ERROR", err);
              });
          });
        }
      );
      |]

deserialiseBody :: (CBOR.Serialise a, MonadHandler m) => m a
deserialiseBody = do
  body <- C.runConduit $ rawRequestBody C..| C.map BB.byteString C..| C.sinkLazyBuilder
  case CBOR.deserialiseOrFail body of
    Left _ -> invalidArgs []
    Right a -> pure a

authWebAuthn :: forall master. YesodAuthWebAuthn master => W.RelyingParty -> AuthPlugin master
authWebAuthn theRelyingParty = AuthPlugin {..} where
  apName = "webauthn"
  apDispatch :: Text -> [Text] -> AuthHandler master TypedContent
  apDispatch "GET" ["register"] = webAuthnRegisterHandler >>= sendResponse
  apDispatch "GET" ["challenge"] = do
    challenge <- liftIO $ generateChallenge 16
    return $ toTypedContent $ J.toJSON challenge
  apDispatch "POST" ["register"] = do
    (cdj, att, challenge) <- deserialiseBody
    case registerCredential challenge theRelyingParty Nothing False cdj att of
      Left e -> permissionDenied $ T.pack $ show e
      Right (cid, pub) -> do
        webAuthnAddCredential cid pub
        return $ toTypedContent ("Success" :: Text)
  apDispatch "POST" ["verify"] = do
    (cid, cdj, ad, sig, challenge) <- deserialiseBody
    pub <- webAuthnLookupPubKey cid
    case verify challenge theRelyingParty Nothing False cdj ad sig pub of
      Left e -> permissionDenied $ T.pack $ show e
      Right _ -> return $ toTypedContent ()
  apDispatch _ _ = notFound
  apLogin _ = webAuthnLoginHandler
