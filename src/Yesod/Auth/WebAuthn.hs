{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE Rank2Types, ScopedTypeVariables #-}
{-# LANGUAGE TemplateHaskell #-}
module Yesod.Auth.WebAuthn where
import Yesod.Auth
import Yesod.Core

import Web.WebAuthn as W
import qualified Data.Aeson as J
import Data.ByteString (ByteString)
import Data.Text (Text)
import qualified Data.Text as T
import Control.Concurrent.STM
import qualified Data.HashMap.Strict as HM
import qualified Data.Conduit as C
import qualified Data.Conduit.Combinators as C
import qualified Data.ByteString.Builder as BB
import qualified Codec.Serialise as CBOR
import qualified Yesod.Auth.Message as Msg
import Yesod.Core
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
  webAuthnAddCredential :: CredentialData -> AuthHandler site ()
  webAuthnRegisterHandler :: AuthHandler site Html
  webAuthnRegisterHandler = authLayout $ do
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
    toWidget [Julius.js|
      document.getElementById("webauthn-register").addEventListener("click"
        , function(e){
          getJSON("/auth/page/webauthn/challenge", function(challenge){
            let rawChallenge = base64js.toByteArray(challenge);
            let info =
                { challenge: rawChallenge
                , user: {
                  id: new Uint8Array(26), // actually provided by the server
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
                      [new Uint8Array(cred.response.attestationObject)
                      , new Uint8Array(cred.response.clientDataJSON)])
                  , function(resp)
                    {
                      var msg = document.createElement("div");
                      msg.innerText = resp;
                      document.getElementById("webauthn-result").appendChild(msg);
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
            navigator.credentials.get({publicKey:
              { challenge: rawChallenge
              , timeout: 60000
              }})
              .then((cred) => {
                console.log("NEW CREDENTIAL", cred);
                CBOR.encode(cred.response);
                postJSON("/auth/page/webauthn/verify"
                  , CBOR.encode(
                      [ new Uint8Array(cred.response.attestationObject)
                      , new Uint8Array(cred.response.clientDataJSON)])
                  , function(resp)
                    {
                      console.log(resp);
                    });
              })
              .catch((err) => {
                console.log("ERROR", err);
              });
          });
        }
      );
      |]

obtainData :: MonadHandler m => m (ByteString, ByteString, Challenge)
obtainData = do
  body <- C.runConduit $ rawRequestBody C..| C.map BB.byteString C..| C.sinkLazyBuilder
  (att, cdj) <- case CBOR.deserialiseOrFail body of
    Left _ -> invalidArgs []
    Right a -> pure a
  challenge <- lookupSessionBS "webauthn-challenge"
    >>= maybe (permissionDenied "Challenge not found") (pure . Challenge)
  return (cdj, att, challenge)

authWebAuthn :: forall master. YesodAuthWebAuthn master => W.RelyingParty -> AuthPlugin master
authWebAuthn theRelyingParty = AuthPlugin {..} where
  apName = "webauthn"
  apDispatch :: Text -> [Text] -> AuthHandler master TypedContent
  apDispatch "GET" ["register"] = webAuthnRegisterHandler >>= sendResponse
  apDispatch "GET" ["challenge"] = do
    challenge@(Challenge raw) <- liftIO $ generateChallenge 16
    setSessionBS "webauthn-challenge" raw
    return $ toTypedContent $ J.toJSON challenge
  apDispatch "POST" ["register"] = do
    (cdj, att, challenge) <- obtainData
    case verify Create challenge theRelyingParty Nothing False (AuthenticatorAttestationResponse att cdj) of
      Left e -> permissionDenied $ T.pack $ show e
      Right cred -> do
        webAuthnAddCredential cred
        $logInfo $ T.pack $ "register " ++ show cred
        return $ toTypedContent $ T.pack $ show cred
  apDispatch "POST" ["verify"] = do
    (cdj, att, challenge) <- obtainData
    case verify Get challenge theRelyingParty Nothing False (AuthenticatorAttestationResponse att cdj) of
      Left e -> permissionDenied $ T.pack $ show e
      Right _ -> return $ toTypedContent ()
  apDispatch _ path = notFound
  apLogin _ = webAuthnLoginHandler
