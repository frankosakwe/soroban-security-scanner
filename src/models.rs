use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateScanRequest {
    pub repository_url: String,
    pub branch: Option<String>,
    pub commit_hash: Option<String>,
    pub scan_types: Vec<ScanType>,
    pub resource_limits: Option<ResourceLimits>,
    pub timeout_minutes: Option<u32>,
    pub environment_variables: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScanType {
    Security,
    Invariants,
    Comprehensive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    pub cpu_millis: Option<u32>,
    pub memory_mb: Option<u32>,
    pub storage_mb: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct ScanResponse {
    pub scan_id: String,
    pub status: ScanStatus,
    pub created_at: DateTime<Utc>,
    pub job_info: JobInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScanStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Timeout,
    Cancelled,
}

#[derive(Debug, Serialize)]
pub struct JobInfo {
    pub pod_name: String,
    pub namespace: String,
    pub resource_quota: String,
    pub network_policy: String,
}

#[derive(Debug, Serialize)]
pub struct ScanStatusResponse {
    pub scan_id: String,
    pub status: ScanStatus,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct LogQuery {
    pub lines: Option<usize>,
    pub follow: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct LogResponse {
    pub scan_id: String,
    pub logs: Vec<LogEntry>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct LogEntry {
    pub timestamp: DateTime<Utc>,
    pub level: LogLevel,
    pub message: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

#[derive(Debug, Serialize)]
pub struct ScanResultsResponse {
    pub scan_id: String,
    pub results: ScanResults,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct ScanResults {
    pub vulnerabilities: Vec<Vulnerability>,
    pub invariant_violations: Vec<InvariantViolation>,
    pub summary: ScanSummary,
    pub metadata: ScanMetadata,
}

#[derive(Debug, Serialize)]
pub struct Vulnerability {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub file_path: String,
    pub line_number: Option<u32>,
    pub recommendation: String,
    pub cwe_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct InvariantViolation {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub file_path: String,
    pub line_number: Option<u32>,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Serialize)]
pub struct ScanSummary {
    pub total_files_scanned: u32,
    pub total_vulnerabilities: u32,
    pub total_invariant_violations: u32,
    pub risk_score: f32,
    pub scan_duration_seconds: u64,
}

#[derive(Debug, Serialize)]
pub struct ScanMetadata {
    pub scanner_version: String,
    pub scan_types: Vec<ScanType>,
    pub resource_usage: ResourceUsage,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct ResourceUsage {
    pub cpu_time_seconds: f64,
    pub memory_peak_mb: u32,
    pub storage_used_mb: u32,
}

#[derive(Debug, Deserialize)]
pub struct ListScansQuery {
    pub limit: Option<usize>,
    pub offset: Option<usize>,
    pub status: Option<ScanStatus>,
}

#[derive(Debug, Serialize)]
pub struct ListScansResponse {
    pub scans: Vec<ScanSummaryItem>,
    pub total: usize,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct ScanSummaryItem {
    pub scan_id: String,
    pub status: ScanStatus,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub repository_url: String,
    pub summary: ScanSummary,
}

// Kubernetes-specific models
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PodSpec {
    pub name: String,
    pub namespace: String,
    pub image: String,
    pub resources: PodResources,
    pub security_context: SecurityContext,
    pub volumes: Vec<Volume>,
    pub sidecar: Option<SidecarContainer>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PodResources {
    pub cpu_request: String,
    pub cpu_limit: String,
    pub memory_request: String,
    pub memory_limit: String,
    pub ephemeral_storage_request: String,
    pub ephemeral_storage_limit: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityContext {
    pub run_as_non_root: bool,
    pub run_as_user: Option<u64>,
    pub read_only_root_filesystem: bool,
    pub allow_privilege_escalation: bool,
    pub capabilities: Capabilities,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capabilities {
    pub drop: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Volume {
    pub name: String,
    pub volume_type: String,
    pub encrypted: bool,
    pub size_mb: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SidecarContainer {
    pub name: String,
    pub image: String,
    pub resources: PodResources,
    pub log_destination: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceQuotaSpec {
    pub name: String,
    pub namespace: String,
    pub hard: ResourceQuotaHard,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceQuotaHard {
    pub cpu: String,
    pub memory: String,
    pub pods: String,
    pub ephemeral_storage: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPolicySpec {
    pub name: String,
    pub namespace: String,
    pub pod_selector: PodSelector,
    pub policy_types: Vec<String>,
    pub egress: Vec<EgressRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PodSelector {
    pub match_labels: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EgressRule {
    pub to: Vec<String>,
    pub ports: Vec<Port>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Port {
    pub protocol: String,
    pub port: u16,
}
