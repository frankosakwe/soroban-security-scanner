use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server_port: u16,
    pub database_url: String,
    pub redis_url: String,
    pub jwt_secret: String,
    pub kubeconfig_path: Option<String>,
    pub kubernetes_namespace: String,
    pub scanner_image: String,
    pub log_sidecar_image: String,
    pub default_resource_limits: ResourceLimits,
    pub default_timeout_minutes: u32,
    pub max_concurrent_scans: u32,
    pub cleanup_interval_minutes: u32,
    pub encryption_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    pub cpu_millis: u32,
    pub memory_mb: u32,
    pub storage_mb: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server_port: 8080,
            database_url: "postgresql://localhost/stellar_scanner".to_string(),
            redis_url: "redis://localhost".to_string(),
            jwt_secret: "change-me-in-production".to_string(),
            kubeconfig_path: None,
            kubernetes_namespace: "stellar-scanner".to_string(),
            scanner_image: "stellar-security-scanner:latest".to_string(),
            log_sidecar_image: "fluent/fluent-bit:latest".to_string(),
            default_resource_limits: ResourceLimits {
                cpu_millis: 1000,
                memory_mb: 2048,
                storage_mb: 1024,
            },
            default_timeout_minutes: 30,
            max_concurrent_scans: 10,
            cleanup_interval_minutes: 5,
            encryption_key: "change-me-in-production-32-chars".to_string(),
        }
    }
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let mut config = Self::default();

        // Server configuration
        if let Ok(port) = env::var("SERVER_PORT") {
            config.server_port = port.parse()?;
        }

        // Database configuration
        if let Ok(database_url) = env::var("DATABASE_URL") {
            config.database_url = database_url;
        }

        // Redis configuration
        if let Ok(redis_url) = env::var("REDIS_URL") {
            config.redis_url = redis_url;
        }

        // JWT configuration
        if let Ok(jwt_secret) = env::var("JWT_SECRET") {
            config.jwt_secret = jwt_secret;
        }

        // Kubernetes configuration
        if let Ok(kubeconfig_path) = env::var("KUBECONFIG_PATH") {
            config.kubeconfig_path = Some(kubeconfig_path);
        }

        if let Ok(namespace) = env::var("KUBERNETES_NAMESPACE") {
            config.kubernetes_namespace = namespace;
        }

        // Scanner configuration
        if let Ok(scanner_image) = env::var("SCANNER_IMAGE") {
            config.scanner_image = scanner_image;
        }

        if let Ok(log_sidecar_image) = env::var("LOG_SIDECAR_IMAGE") {
            config.log_sidecar_image = log_sidecar_image;
        }

        // Resource limits
        if let Ok(cpu_millis) = env::var("DEFAULT_CPU_MILLIS") {
            config.default_resource_limits.cpu_millis = cpu_millis.parse()?;
        }

        if let Ok(memory_mb) = env::var("DEFAULT_MEMORY_MB") {
            config.default_resource_limits.memory_mb = memory_mb.parse()?;
        }

        if let Ok(storage_mb) = env::var("DEFAULT_STORAGE_MB") {
            config.default_resource_limits.storage_mb = storage_mb.parse()?;
        }

        // Timeout configuration
        if let Ok(timeout_minutes) = env::var("DEFAULT_TIMEOUT_MINUTES") {
            config.default_timeout_minutes = timeout_minutes.parse()?;
        }

        // Concurrency configuration
        if let Ok(max_concurrent_scans) = env::var("MAX_CONCURRENT_SCANS") {
            config.max_concurrent_scans = max_concurrent_scans.parse()?;
        }

        // Cleanup configuration
        if let Ok(cleanup_interval_minutes) = env::var("CLEANUP_INTERVAL_MINUTES") {
            config.cleanup_interval_minutes = cleanup_interval_minutes.parse()?;
        }

        // Encryption configuration
        if let Ok(encryption_key) = env::var("ENCRYPTION_KEY") {
            config.encryption_key = encryption_key;
        }

        Ok(config)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.jwt_secret == "change-me-in-production" {
            anyhow::bail!("JWT_SECRET must be set in production");
        }

        if self.encryption_key == "change-me-in-production-32-chars" {
            anyhow::bail!("ENCRYPTION_KEY must be set in production");
        }

        if self.encryption_key.len() != 32 {
            anyhow::bail!("ENCRYPTION_KEY must be exactly 32 characters");
        }

        if self.default_resource_limits.cpu_millis == 0 {
            anyhow::bail!("CPU limit must be greater than 0");
        }

        if self.default_resource_limits.memory_mb == 0 {
            anyhow::bail!("Memory limit must be greater than 0");
        }

        if self.default_resource_limits.storage_mb == 0 {
            anyhow::bail!("Storage limit must be greater than 0");
        }

        if self.default_timeout_minutes == 0 {
            anyhow::bail!("Timeout must be greater than 0");
        }

        if self.max_concurrent_scans == 0 {
            anyhow::bail!("Max concurrent scans must be greater than 0");
        }

        Ok(())
    }
}
