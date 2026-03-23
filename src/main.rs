use anyhow::Result;
use axum::{
    extract::{Path, Query, State, Request},
    http::{StatusCode, HeaderMap},
    middleware::{self, Next},
    response::{Json, Response},
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing::{info, error, warn, debug};
use uuid::Uuid;

mod config;
mod k8s;
mod models;
mod scanner;
mod auth;
mod metrics;

use config::Config;
use models::*;
use auth::{AuthService, auth_middleware, login_handler};
use metrics::{MetricsCollector, QueueMetrics, KubernetesMetrics, HealthMetrics};
use scanner::{ScanQueue, QueueConfig};

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub k8s_client: Arc<k8s::KubernetesClient>,
    pub auth_service: Arc<AuthService>,
    pub scan_queue: Arc<ScanQueue>,
    pub metrics_collector: Arc<MetricsCollector>,
    pub queue_metrics: Arc<QueueMetrics>,
    pub k8s_metrics: Arc<KubernetesMetrics>,
    pub health_metrics: Arc<HealthMetrics>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    info!("Starting Stellar Security Scanner Backend");

    // Load and validate configuration
    let config = Config::from_env()?;
    config.validate()?;
    info!("Configuration loaded and validated");

    // Initialize metrics collectors
    let metrics_collector = Arc::new(MetricsCollector::new());
    let queue_metrics = Arc::new(QueueMetrics::new());
    let k8s_metrics = Arc::new(KubernetesMetrics::new());
    let health_metrics = Arc::new(HealthMetrics::new());

    // Start system metrics collection
    metrics_collector.start_system_metrics_collection();

    // Initialize Kubernetes client
    let k8s_client = match k8s::KubernetesClient::new(&config.kubeconfig_path).await {
        Ok(client) => {
            health_metrics.record_kubernetes_connection(true);
            info!("Kubernetes client initialized successfully");
            Arc::new(client)
        }
        Err(e) => {
            health_metrics.record_kubernetes_connection(false);
            error!("Failed to initialize Kubernetes client: {}", e);
            return Err(e);
        }
    };

    // Initialize authentication service
    let auth_service = Arc::new(AuthService::new(&config.jwt_secret));

    // Initialize scan queue
    let queue_config = QueueConfig {
        max_concurrent_scans: config.max_concurrent_scans,
        default_timeout_minutes: config.default_timeout_minutes,
        queue_check_interval_seconds: 5,
        cleanup_interval_minutes: config.cleanup_interval_minutes,
        auto_scale_enabled: true,
        scale_up_threshold: 0.8,
        scale_down_threshold: 0.2,
        max_scale_instances: 50,
        min_scale_instances: 2,
    };

    let scan_queue = Arc::new(ScanQueue::new(k8s_client.clone(), queue_config));

    // Start queue processor
    scan_queue.start_queue_processor().await?;

    // Start Kubernetes cleanup worker
    k8s_client.start_cleanup_worker().await?;

    // Create application state
    let state = AppState {
        config: config.clone(),
        k8s_client: k8s_client.clone(),
        auth_service: auth_service.clone(),
        scan_queue: scan_queue.clone(),
        metrics_collector: metrics_collector.clone(),
        queue_metrics: queue_metrics.clone(),
        k8s_metrics: k8s_metrics.clone(),
        health_metrics: health_metrics.clone(),
    };

    // Build router with middleware
    let app = Router::new()
        .route("/health", get(health_check))
        .route("/auth/login", post(login_handler))
        .route("/api/v1/scans", post(create_scan))
        .route("/api/v1/scans/:id", get(get_scan_status))
        .route("/api/v1/scans/:id/logs", get(get_scan_logs))
        .route("/api/v1/scans/:id/results", get(get_scan_results))
        .route("/api/v1/scans", get(list_scans))
        .route("/api/v1/queue/metrics", get(get_queue_metrics))
        .route("/metrics", get(metrics::metrics_handler))
        .layer(middleware::from_fn_with_state(state.clone(), request_logging_middleware))
        .layer(middleware::from_fn_with_state(state.clone(), error_handling_middleware))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    // Start server
    let addr = SocketAddr::from(([0, 0, 0, 0], config.server_port));
    info!("Starting server on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

pub async fn health_check() -> Result<Json<HealthResponse>, StatusCode> {
    Ok(Json(HealthResponse {
        status: "healthy".to_string(),
        timestamp: chrono::Utc::now(),
    }))
}

async fn create_scan(
    State(state): State<AppState>,
    Json(request): Json<CreateScanRequest>,
) -> Result<Json<ScanResponse>, StatusCode> {
    let scan_id = Uuid::new_v4();
    info!("Creating new scan: {}", scan_id);

    // Record metrics
    state.metrics_collector.record_scan_request();

    // Validate request
    if request.repository_url.is_empty() {
        warn!("Empty repository URL in scan request");
        return Err(StatusCode::BAD_REQUEST);
    }

    // Enqueue scan
    let priority = match request.scan_types.first() {
        Some(ScanType::Comprehensive) => scanner::ScanPriority::High,
        Some(ScanType::Security) => scanner::ScanPriority::Normal,
        Some(ScanType::Invariants) => scanner::ScanPriority::Normal,
        None => scanner::ScanPriority::Normal,
    };

    match state.scan_queue.enqueue_scan(scan_id, request.clone(), priority).await {
        Ok(_) => {
            let response = ScanResponse {
                scan_id: scan_id.to_string(),
                status: ScanStatus::Pending,
                created_at: chrono::Utc::now(),
                job_info: JobInfo {
                    pod_name: format!("scan-{}", scan_id),
                    namespace: format!("scan-{}", scan_id),
                    resource_quota: String::new(),
                    network_policy: String::new(),
                },
            };
            Ok(Json(response))
        }
        Err(e) => {
            error!("Failed to enqueue scan {}: {}", scan_id, e);
            state.metrics_collector.record_scan_error();
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn get_scan_status(
    State(state): State<AppState>,
    Path(scan_id): Path<String>,
) -> Result<Json<ScanStatusResponse>, StatusCode> {
    let scan_uuid = Uuid::parse_str(&scan_id)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    match state.scan_queue.get_scan_status(&scan_uuid).await {
        Ok(Some(status)) => Ok(Json(ScanStatusResponse {
            scan_id,
            status,
            timestamp: chrono::Utc::now(),
        })),
        Ok(None) => Err(StatusCode::NOT_FOUND),
        Err(e) => {
            error!("Failed to get scan status: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn get_scan_logs(
    State(state): State<AppState>,
    Path(scan_id): Path<String>,
    Query(params): Query<LogQuery>,
) -> Result<Json<LogResponse>, StatusCode> {
    let scan_uuid = Uuid::parse_str(&scan_id)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    match state.k8s_client.get_scan_logs(&scan_uuid, params.lines.unwrap_or(100)).await {
        Ok(logs) => Ok(Json(LogResponse {
            scan_id,
            logs,
            timestamp: chrono::Utc::now(),
        })),
        Err(e) => {
            error!("Failed to get scan logs: {}", e);
            Err(StatusCode::NOT_FOUND)
        }
    }
}

async fn get_scan_results(
    State(state): State<AppState>,
    Path(scan_id): Path<String>,
) -> Result<Json<ScanResultsResponse>, StatusCode> {
    let scan_uuid = Uuid::parse_str(&scan_id)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    match state.scan_queue.get_scan_results(&scan_uuid).await {
        Ok(Some(results)) => Ok(Json(ScanResultsResponse {
            scan_id,
            results,
            timestamp: chrono::Utc::now(),
        })),
        Ok(None) => Err(StatusCode::NOT_FOUND),
        Err(e) => {
            error!("Failed to get scan results: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn list_scans(
    State(state): State<AppState>,
    Query(params): Query<ListScansQuery>,
) -> Result<Json<ListScansResponse>, StatusCode> {
    match state.k8s_client.list_scans(params.limit.unwrap_or(50), params.offset.unwrap_or(0)).await {
        Ok(scans) => Ok(Json(ListScansResponse {
            scans,
            total: scans.len(),
            timestamp: chrono::Utc::now(),
        })),
        Err(e) => {
            error!("Failed to list scans: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn get_queue_metrics(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    match state.scan_queue.get_metrics().await {
        Ok(metrics) => {
            // Update queue metrics
            state.queue_metrics.record_queue_depth(metrics.queue_depth as f64);
            state.queue_metrics.record_throughput(metrics.throughput_per_minute);
            state.queue_metrics.record_average_wait_time(metrics.average_wait_time_seconds);
            state.queue_metrics.record_success_rate(metrics.success_rate);

            Ok(Json(serde_json::to_value(metrics).unwrap()))
        }
        Err(e) => {
            error!("Failed to get queue metrics: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

// Middleware for request logging
async fn request_logging_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let start = std::time::Instant::now();
    let method = request.method().clone();
    let uri = request.uri().clone();

    let response = next.run(request).await;

    let duration = start.elapsed();
    info!("{} {} completed in {:?}", method, uri, duration);

    Ok(response)
}

// Middleware for error handling
async fn error_handling_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let method = request.method().clone();
    let uri = request.uri().clone();

    let response = next.run(request).await;

    if response.status().is_server_error() {
        error!("Server error for {} {}: {}", method, uri, response.status());
        state.metrics_collector.record_scan_error();
    } else if response.status().is_client_error() {
        warn!("Client error for {} {}: {}", method, uri, response.status());
    }

    Ok(response)
}
