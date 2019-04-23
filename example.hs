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
import Control.Monad.IO.Class (liftIO)

import Web.WebAuthn
import Network.Wai.Handler.Warp
import Network.Wai.Handler.WarpTLS
import Network.Wai.Middleware.RequestLogger
import Yesod.Form (FormMessage, defaultFormMessage)

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
  approot = ApprootStatic "http://192.168.11.37:8080"

instance YesodAuth WAuth where
  type AuthId WAuth = Text
  loginDest _ = AfterLoginR
  logoutDest _ = AuthR LoginR
  authenticate creds = return $ ServerError "undefined"
  authPlugins _ = [authWebAuthn (defaultRelyingParty $ Origin "https" "192.168.11.37" 8080)]
  maybeAuthId = lookupSession credsKey

instance YesodAuthWebAuthn WAuth where
  webAuthnAddCredential _ = return ()

main :: IO ()
main = do
  app <- toWaiApp WAuth
  runTLS (tlsSettings "certificate.pem" "key.pem") (setPort 8080 defaultSettings)
    $ logStdoutDev app
