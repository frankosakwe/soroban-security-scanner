use anyhow::Result;
use axum::{
    extract::{Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::Response,
    Json,
};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{info, warn, error};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,        // User ID
    pub email: String,      // User email
    pub role: String,       // User role
    pub exp: usize,         // Expiration time
    pub iat: usize,         // Issued at
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthResponse {
    pub token: String,
    pub expires_in: usize,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

pub struct AuthService {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
}

impl AuthService {
    pub fn new(secret: &str) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(secret.as_ref()),
            decoding_key: DecodingKey::from_secret(secret.as_ref()),
        }
    }

    pub fn generate_token(&self, user_id: &str, email: &str, role: &str, expires_in_hours: usize) -> Result<String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize;

        let claims = Claims {
            sub: user_id.to_string(),
            email: email.to_string(),
            role: role.to_string(),
            exp: now + (expires_in_hours * 3600),
            iat: now,
        };

        let token = encode(&Header::default(), &claims, &self.encoding_key)?;
        Ok(token)
    }

    pub fn validate_token(&self, token: &str) -> Result<Claims> {
        let token_data = decode::<Claims>(token, &self.decoding_key, &Validation::default())?;
        Ok(token_data.claims)
    }

    pub async fn authenticate_user(&self, email: &str, password: &str) -> Result<(String, String, String)> {
        // In a real implementation, this would:
        // 1. Hash the password and check against database
        // 2. Verify user exists and is active
        // 3. Return user_id, email, and role
        
        // For demo purposes, we'll use a simple check
        if email == "admin@stellar-scanner.io" && password == "admin123" {
            Ok(("user_123".to_string(), email.to_string(), "admin".to_string()))
        } else {
            Err(anyhow::anyhow!("Invalid credentials"))
        }
    }
}

pub async fn auth_middleware(
    State(auth_service): State<AuthService>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth_header = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());

    if let Some(auth_header) = auth_header {
        if let Some(token) = auth_header.strip_prefix("Bearer ") {
            match auth_service.validate_token(token) {
                Ok(claims) => {
                    // Add user info to request extensions
                    request.extensions_mut().insert(claims);
                    return Ok(next.run(request).await);
                }
                Err(e) => {
                    warn!("Invalid token: {}", e);
                    return Err(StatusCode::UNAUTHORIZED);
                }
            }
        }
    }

    // Allow health check without authentication
    if request.uri().path() == "/health" || request.uri().path().starts_with("/metrics") {
        return Ok(next.run(request).await);
    }

    Err(StatusCode::UNAUTHORIZED)
}

pub async fn login_handler(
    State(auth_service): State<AuthService>,
    Json(request): Json<LoginRequest>,
) -> Result<Json<AuthResponse>, StatusCode> {
    match auth_service.authenticate_user(&request.email, &request.password).await {
        Ok((user_id, email, role)) => {
            match auth_service.generate_token(&user_id, &email, &role, 24) {
                Ok(token) => {
                    info!("User {} logged in successfully", email);
                    Ok(Json(AuthResponse {
                        token,
                        expires_in: 24 * 3600, // 24 hours in seconds
                    }))
                }
                Err(e) => {
                    error!("Failed to generate token: {}", e);
                    Err(StatusCode::INTERNAL_SERVER_ERROR)
                }
            }
        }
        Err(e) => {
            warn!("Login failed for {}: {}", request.email, e);
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}
