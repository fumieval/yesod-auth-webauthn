{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE MultiParamTypeClasses #-}
import Yesod.Core
import Yesod.Auth
import Yesod.Auth.WebAuthn
import Data.Text (Text)
import Text.Hamlet (hamlet)

import Web.WebAuthn
import Network.Wai.Handler.Warp
import Network.Wai.Handler.WarpTLS
import Network.Wai.Middleware.RequestLogger
import Yesod.Form (FormMessage, defaultFormMessage)

import qualified Data.HashMap.Strict as HM

data WAuth = WAuth

mkYesod "WAuth" [parseRoutes|
/ RootR GET
/after AfterLoginR GET
/auth AuthR Auth getAuth
|]

getRootR :: Handler ()
getRootR = redirect $ AuthR LoginR

getAfterLoginR :: Handler Html
getAfterLoginR = do
    mauth <- maybeAuthId
    defaultLayout $ toWidget [hamlet|
<p>Auth: #{show mauth}
|]

instance RenderMessage WAuth FormMessage where
  renderMessage _ _ = defaultFormMessage

instance Yesod WAuth where
  approot = ApprootStatic "http://localhost:8080"

instance YesodAuth WAuth where
  type AuthId WAuth = Text
  loginDest _ = AfterLoginR
  logoutDest _ = AuthR LoginR
  authenticate creds = return $ ServerError "undefined"
  authPlugins _ = [authWebAuthn (defaultRelyingParty $ Origin "https" "localhost" 8080)]
  maybeAuthId = lookupSession credsKey

instance YesodAuthWebAuthn WAuth where
  webAuthnLookupPubKey cid = case HM.lookup cid authorisedKeys of
    Nothing -> permissionDenied "Unauthorised"
    Just pub -> return pub
  webAuthnAddCredential _ cid pub = liftIO $ print (cid, pub)

authorisedKeys :: HM.HashMap CredentialId CredentialPublicKey
authorisedKeys = HM.fromList [(CredentialId {unCredentialId = "\145\r\130\184\SO;\145\138\198'|H\171F\230\135_\129\207\232\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL"},CredentialPublicKey {unCredentialPublicKey = "\165\SOH\STX\ETX& \SOH!X n\144*\205\236\199eh\253\RS\DC4S\248\129\GS+tq\227\t\162\183\253\&5\142|8*\135\176\253j\"X \\\DC4\155\141\129\230\224\&9\145\188*J%\SUB\216Xp\216\153\203Q\238#ykW\154Z\248\252$\169"})]

main :: IO ()
main = do
  app <- toWaiApp WAuth
  runTLS (tlsSettings "certificate.pem" "key.pem") (setPort 8080 defaultSettings)
    $ logStdoutDev app
