use std::env;

use openidconnect::core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata};
use openidconnect::reqwest::http_client;
use openidconnect::{
    AdditionalClaims, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce,
    RedirectUrl, Scope,
};
use openidconnect::{OAuth2TokenResponse};
use reqwest::blocking::{Client, RequestBuilder};
use reqwest::{IntoUrl, Method};
use serde::{Deserialize, Serialize};

use url::Url;

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct User {
    pub fxa: FxAUser,
    pub access_token: String,
    pub refresh_token: String,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FxAUser {
    pub email: String,
    pub locale: String,
    pub display_name: Option<String>,
    pub avatar: Option<String>,
    pub avatar_default: bool,
    pub amr_values: Vec<String>,
    pub uid: String,
    pub subscriptions: Vec<String>,
}

impl AdditionalClaims for FxAUser {}

pub struct LoginManager {
    login_client: CoreClient,
    client: Client,
}
use anyhow::Error;

impl LoginManager {
    pub fn init() -> Result<Self, Error> {
        let provider_metadata = CoreProviderMetadata::discover(
            &IssuerUrl::new("https://accounts.stage.mozaws.net".to_string())?,
            http_client,
        )?;

        let login_client = CoreClient::from_provider_metadata(
            provider_metadata,
            ClientId::new(env::var("FXA_CLIENT_ID")?),
            Some(ClientSecret::new(env::var("FXA_CLIENT_SECRET")?)),
        )
        .set_redirect_uri(RedirectUrl::new(
            "http://localhost:8000/users/fxa/login/callback/".to_string(),
        )?);

        Ok(LoginManager {
            login_client,
            client: Client::new(),
        })
    }

    pub fn login(&mut self) -> (Url, CsrfToken) {
        let (auth_url, csrf_token, _nonce) = self
            .login_client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .add_scope(Scope::new("profile".to_string()))
            .add_extra_param("access_type", "offline")
            .url();
        (auth_url, csrf_token)
    }

    pub fn callback(&mut self, code: String) -> Result<(FxAUser, String), Error> {
        let token_response = self
            .login_client
            .exchange_code(AuthorizationCode::new(code))
            // Set the PKCE code verifier.
            .request(http_client)?;

        let access_token = token_response.access_token().secret().clone();

        let res = self
            .request(
                Method::GET,
                "https://profile.stage.mozaws.net/v1/profile",
                &access_token,
            )
            .send()?;

        let user: FxAUser = res.json()?;
        Ok((user, access_token))
    }

    fn request<U: IntoUrl>(&self, method: Method, url: U, bearer: &str) -> RequestBuilder {
        self.client.request(method, url).bearer_auth(bearer)
    }
}
