use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{RwLock, Semaphore};
use tokio::time::{sleep, Duration, Instant};
use tracing::{info, warn, error, debug};
use uuid::Uuid;

use crate::models::*;
use crate::k8s::KubernetesClient;

#[derive(Debug, Clone)]
pub struct ScanQueue {
    pending_scans: Arc<RwLock<Vec<QueuedScan>>>,
    active_scans: Arc<RwLock<HashMap<String, ActiveScan>>>,
    completed_scans: Arc<RwLock<HashMap<String, CompletedScan>>>,
    semaphore: Arc<Semaphore>,
    k8s_client: Arc<KubernetesClient>,
    config: QueueConfig,
}

#[derive(Debug, Clone)]
pub struct QueueConfig {
    pub max_concurrent_scans: u32,
    pub default_timeout_minutes: u32,
    pub queue_check_interval_seconds: u64,
    pub cleanup_interval_minutes: u32,
    pub auto_scale_enabled: bool,
    pub scale_up_threshold: f32,
    pub scale_down_threshold: f32,
    pub max_scale_instances: u32,
    pub min_scale_instances: u32,
}

impl Default for QueueConfig {
    fn default() -> Self {
        Self {
            max_concurrent_scans: 10,
            default_timeout_minutes: 30,
            queue_check_interval_seconds: 5,
            cleanup_interval_minutes: 5,
            auto_scale_enabled: true,
            scale_up_threshold: 0.8,
            scale_down_threshold: 0.2,
            max_scale_instances: 50,
            min_scale_instances: 2,
        }
    }
}

#[derive(Debug, Clone)]
pub struct QueuedScan {
    pub scan_id: Uuid,
    pub request: CreateScanRequest,
    pub queued_at: Instant,
    pub priority: ScanPriority,
    pub retry_count: u32,
}

#[derive(Debug, Clone)]
pub enum ScanPriority {
    Low,
    Normal,
    High,
    Critical,
}

#[derive(Debug, Clone)]
pub struct ActiveScan {
    pub scan_id: Uuid,
    pub started_at: Instant,
    pub timeout_minutes: u32,
    pub status: ScanStatus,
    pub pod_name: String,
    pub namespace: String,
}

#[derive(Debug, Clone)]
pub struct CompletedScan {
    pub scan_id: Uuid,
    pub status: ScanStatus,
    pub started_at: Instant,
    pub completed_at: Instant,
    pub results: Option<ScanResults>,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueMetrics {
    pub pending_count: usize,
    pub active_count: usize,
    pub completed_count: usize,
    pub average_wait_time_seconds: f64,
    pub average_execution_time_seconds: f64,
    pub success_rate: f64,
    pub queue_depth: usize,
    pub throughput_per_minute: f64,
}

impl ScanQueue {
    pub fn new(k8s_client: Arc<KubernetesClient>, config: QueueConfig) -> Self {
        Self {
            pending_scans: Arc::new(RwLock::new(Vec::new())),
            active_scans: Arc::new(RwLock::new(HashMap::new())),
            completed_scans: Arc::new(RwLock::new(HashMap::new())),
            semaphore: Arc::new(Semaphore::new(config.max_concurrent_scans as usize)),
            k8s_client,
            config,
        }
    }

    pub async fn enqueue_scan(&self, scan_id: Uuid, request: CreateScanRequest, priority: ScanPriority) -> Result<()> {
        let queued_scan = QueuedScan {
            scan_id,
            request,
            queued_at: Instant::now(),
            priority,
            retry_count: 0,
        };

        {
            let mut pending = self.pending_scans.write().await;
            pending.push(queued_scan);
        }

        info!("Enqueued scan: {}", scan_id);
        self.trigger_queue_processing().await;
        Ok(())
    }

    pub async fn get_scan_status(&self, scan_id: &Uuid) -> Result<Option<ScanStatus>> {
        // Check active scans first
        {
            let active = self.active_scans.read().await;
            if let Some(active_scan) = active.get(&scan_id.to_string()) {
                return Ok(Some(active_scan.status.clone()));
            }
        }

        // Check completed scans
        {
            let completed = self.completed_scans.read().await;
            if let Some(completed_scan) = completed.get(&scan_id.to_string()) {
                return Ok(Some(completed_scan.status.clone()));
            }
        }

        // Check if it's in pending queue
        {
            let pending = self.pending_scans.read().await;
            if pending.iter().any(|scan| scan.scan_id == *scan_id) {
                return Ok(Some(ScanStatus::Pending));
            }
        }

        Ok(None)
    }

    pub async fn get_scan_results(&self, scan_id: &Uuid) -> Result<Option<ScanResults>> {
        let completed = self.completed_scans.read().await;
        Ok(completed.get(&scan_id.to_string()).and_then(|scan| scan.results.clone()))
    }

    pub async fn get_metrics(&self) -> Result<QueueMetrics> {
        let pending = self.pending_scans.read().await;
        let active = self.active_scans.read().await;
        let completed = self.completed_scans.read().await;

        let pending_count = pending.len();
        let active_count = active.len();
        let completed_count = completed.len();

        // Calculate average wait time
        let average_wait_time_seconds = if pending_count > 0 {
            let total_wait: Duration = pending.iter()
                .map(|scan| scan.queued_at.elapsed())
                .sum();
            total_wait.as_secs_f64() / pending_count as f64
        } else {
            0.0
        };

        // Calculate average execution time
        let (total_execution_time, execution_count) = completed.values()
            .filter_map(|scan| {
                if scan.results.is_some() {
                    Some(scan.completed_at.duration_since(scan.started_at))
                } else {
                    None
                }
            })
            .fold((Duration::ZERO, 0), |(acc, count), duration| (acc + duration, count + 1));

        let average_execution_time_seconds = if execution_count > 0 {
            total_execution_time.as_secs_f64() / execution_count as f64
        } else {
            0.0
        };

        // Calculate success rate
        let success_count = completed.values()
            .filter(|scan| matches!(scan.status, ScanStatus::Completed))
            .count();
        let success_rate = if completed_count > 0 {
            success_count as f64 / completed_count as f64
        } else {
            0.0
        };

        // Calculate throughput (scans per minute over the last hour)
        let one_hour_ago = Instant::now() - Duration::from_secs(3600);
        let recent_completions = completed.values()
            .filter(|scan| scan.completed_at > one_hour_ago)
            .count();
        let throughput_per_minute = recent_completions as f64 / 60.0;

        Ok(QueueMetrics {
            pending_count,
            active_count,
            completed_count,
            average_wait_time_seconds,
            average_execution_time_seconds,
            success_rate,
            queue_depth: pending_count,
            throughput_per_minute,
        })
    }

    pub async fn start_queue_processor(&self) -> Result<()> {
        info!("Starting scan queue processor");
        
        let queue = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(queue.config.queue_check_interval_seconds));
            
            loop {
                interval.tick().await;
                
                if let Err(e) = queue.process_queue().await {
                    error!("Queue processing error: {}", e);
                }
                
                if let Err(e) = queue.monitor_active_scans().await {
                    error!("Active scan monitoring error: {}", e);
                }
            }
        });

        // Start cleanup worker
        let cleanup_queue = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(cleanup_queue.config.cleanup_interval_minutes as u64 * 60));
            
            loop {
                interval.tick().await;
                
                if let Err(e) = cleanup_queue.cleanup_old_scans().await {
                    error!("Cleanup error: {}", e);
                }
            }
        });

        // Start auto-scaler if enabled
        if self.config.auto_scale_enabled {
            let scaler_queue = self.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(30)); // Check every 30 seconds
                
                loop {
                    interval.tick().await;
                    
                    if let Err(e) = scaler_queue.check_auto_scaling().await {
                        error!("Auto-scaling error: {}", e);
                    }
                }
            });
        }

        Ok(())
    }

    async fn process_queue(&self) -> Result<()> {
        let mut pending = self.pending_scans.write().await;
        
        // Sort by priority and queue time
        pending.sort_by(|a, b| {
            match (&a.priority, &b.priority) {
                (ScanPriority::Critical, ScanPriority::Critical) => a.queued_at.cmp(&b.queued_at),
                (ScanPriority::Critical, _) => std::cmp::Ordering::Less,
                (_, ScanPriority::Critical) => std::cmp::Ordering::Greater,
                (ScanPriority::High, ScanPriority::High) => a.queued_at.cmp(&b.queued_at),
                (ScanPriority::High, ScanPriority::Normal | ScanPriority::Low) => std::cmp::Ordering::Less,
                (ScanPriority::Normal | ScanPriority::Low, ScanPriority::High) => std::cmp::Ordering::Greater,
                (ScanPriority::Normal, ScanPriority::Normal) => a.queued_at.cmp(&b.queued_at),
                (ScanPriority::Normal, ScanPriority::Low) => std::cmp::Ordering::Less,
                (ScanPriority::Low, ScanPriority::Low) => a.queued_at.cmp(&b.queued_at),
                (ScanPriority::Low, ScanPriority::Normal) => std::cmp::Ordering::Greater,
            }
        });

        let mut to_remove = Vec::new();
        
        for (index, queued_scan) in pending.iter().enumerate() {
            // Check if we have capacity
            if self.semaphore.available_permits() == 0 {
                debug!("No available permits for scan execution");
                break;
            }

            // Acquire permit
            if let Ok(permit) = self.semaphore.try_acquire() {
                let scan_id = queued_scan.scan_id;
                let request = queued_scan.request.clone();
                let timeout = request.timeout_minutes.unwrap_or(self.config.default_timeout_minutes);
                
                info!("Starting scan: {}", scan_id);
                
                // Execute scan in background
                let k8s_client = self.k8s_client.clone();
                let active_scans = self.active_scans.clone();
                let completed_scans = self.completed_scans.clone();
                
                tokio::spawn(async move {
                    let _permit = permit; // Hold permit until scan completes
                    
                    let started_at = Instant::now();
                    let scan_id_str = scan_id.to_string();
                    
                    // Create scan job
                    match k8s_client.create_scan_job(&scan_id, &request).await {
                        Ok(job_info) => {
                            // Add to active scans
                            {
                                let mut active = active_scans.write().await;
                                active.insert(scan_id_str.clone(), ActiveScan {
                                    scan_id,
                                    started_at,
                                    timeout_minutes: timeout,
                                    status: ScanStatus::Pending,
                                    pod_name: job_info.pod_name,
                                    namespace: job_info.namespace,
                                });
                            }
                            
                            // Monitor scan progress
                            Self::monitor_scan_progress(
                                scan_id,
                                scan_id_str,
                                started_at,
                                k8s_client,
                                active_scans,
                                completed_scans,
                            ).await;
                        }
                        Err(e) => {
                            error!("Failed to create scan job {}: {}", scan_id, e);
                            
                            // Mark as failed
                            {
                                let mut completed = completed_scans.write().await;
                                completed.insert(scan_id_str, CompletedScan {
                                    scan_id,
                                    status: ScanStatus::Failed,
                                    started_at,
                                    completed_at: Instant::now(),
                                    results: None,
                                    error_message: Some(format!("Failed to create scan job: {}", e)),
                                });
                            }
                        }
                    }
                });
                
                to_remove.push(index);
            } else {
                break;
            }
        }
        
        // Remove started scans from pending queue
        to_remove.reverse();
        for index in to_remove {
            pending.remove(index);
        }
        
        Ok(())
    }

    async fn monitor_active_scans(&self) -> Result<()> {
        let mut active = self.active_scans.write().await;
        let completed = self.completed_scans.clone();
        let k8s_client = self.k8s_client.clone();
        
        let mut to_complete = Vec::new();
        
        for (scan_id_str, active_scan) in active.iter_mut() {
            // Check timeout
            if active_scan.started_at.elapsed().as_secs() > (active_scan.timeout_minutes as u64 * 60) {
                warn!("Scan {} timed out", active_scan.scan_id);
                active_scan.status = ScanStatus::Timeout;
                to_complete.push(scan_id_str.clone());
                continue;
            }
            
            // Check Kubernetes status
            match k8s_client.get_scan_status(&active_scan.scan_id).await {
                Ok(k8s_status) => {
                    match k8s_status {
                        ScanStatus::Completed | ScanStatus::Failed | ScanStatus::Timeout => {
                            active_scan.status = k8s_status.clone();
                            to_complete.push(scan_id_str.clone());
                        }
                        ScanStatus::Running => {
                            if active_scan.status != ScanStatus::Running {
                                active_scan.status = ScanStatus::Running;
                                info!("Scan {} is now running", active_scan.scan_id);
                            }
                        }
                        _ => {}
                    }
                }
                Err(e) => {
                    error!("Failed to get status for scan {}: {}", active_scan.scan_id, e);
                }
            }
        }
        
        // Move completed scans to completed list
        for scan_id_str in to_complete {
            if let Some(active_scan) = active.remove(&scan_id_str) {
                let scan_id = active_scan.scan_id;
                let started_at = active_scan.started_at;
                let status = active_scan.status;
                
                // Get results if completed successfully
                let results = if matches!(status, ScanStatus::Completed) {
                    match k8s_client.get_scan_results(&scan_id).await {
                        Ok(results) => Some(results),
                        Err(e) => {
                            error!("Failed to get results for scan {}: {}", scan_id, e);
                            None
                        }
                    }
                } else {
                    None
                };
                
                let error_message = if matches!(status, ScanStatus::Failed | ScanStatus::Timeout) {
                    Some(format!("Scan ended with status: {:?}", status))
                } else {
                    None
                };
                
                {
                    let mut completed = completed.write().await;
                    completed.insert(scan_id_str, CompletedScan {
                        scan_id,
                        status,
                        started_at,
                        completed_at: Instant::now(),
                        results,
                        error_message,
                    });
                }
                
                // Cleanup Kubernetes resources
                if let Err(e) = k8s_client.cleanup_scan(&scan_id).await {
                    error!("Failed to cleanup scan {}: {}", scan_id, e);
                }
            }
        }
        
        Ok(())
    }

    async fn monitor_scan_progress(
        scan_id: Uuid,
        scan_id_str: String,
        started_at: Instant,
        k8s_client: Arc<KubernetesClient>,
        active_scans: Arc<RwLock<HashMap<String, ActiveScan>>>,
        completed_scans: Arc<RwLock<HashMap<String, CompletedScan>>>,
    ) {
        let mut interval = tokio::time::interval(Duration::from_secs(10));
        
        loop {
            interval.tick().await;
            
            match k8s_client.get_scan_status(&scan_id).await {
                Ok(status) => {
                    match status {
                        ScanStatus::Completed | ScanStatus::Failed | ScanStatus::Timeout => {
                            // Move to completed
                            let results = if matches!(status, ScanStatus::Completed) {
                                k8s_client.get_scan_results(&scan_id).await.ok()
                            } else {
                                None
                            };
                            
                            {
                                let mut active = active_scans.write().await;
                                active.remove(&scan_id_str);
                            }
                            
                            {
                                let mut completed = completed_scans.write().await;
                                completed.insert(scan_id_str, CompletedScan {
                                    scan_id,
                                    status,
                                    started_at,
                                    completed_at: Instant::now(),
                                    results,
                                    error_message: if matches!(status, ScanStatus::Failed | ScanStatus::Timeout) {
                                        Some(format!("Scan ended with status: {:?}", status))
                                    } else {
                                        None
                                    },
                                });
                            }
                            
                            // Cleanup
                            let _ = k8s_client.cleanup_scan(&scan_id).await;
                            break;
                        }
                        _ => {
                            // Update status in active scans
                            let mut active = active_scans.write().await;
                            if let Some(active_scan) = active.get_mut(&scan_id_str) {
                                active_scan.status = status;
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("Error monitoring scan {}: {}", scan_id, e);
                }
            }
        }
    }

    async fn cleanup_old_scans(&self) -> Result<()> {
        let cutoff_time = Instant::now() - Duration::from_secs(24 * 60 * 60); // 24 hours
        
        {
            let mut completed = self.completed_scans.write().await;
            completed.retain(|_, scan| scan.completed_at > cutoff_time);
        }
        
        Ok(())
    }

    async fn check_auto_scaling(&self) -> Result<()> {
        let metrics = self.get_metrics().await?;
        
        // Calculate utilization ratio
        let utilization_ratio = metrics.active_count as f64 / self.config.max_concurrent_scans as f64;
        
        if utilization_ratio > self.config.scale_up_threshold {
            self.scale_up().await?;
        } else if utilization_ratio < self.config.scale_down_threshold {
            self.scale_down().await?;
        }
        
        Ok(())
    }

    async fn scale_up(&self) -> Result<()> {
        info!("Auto-scaling up - queue utilization high");
        
        // In a real implementation, this would:
        // 1. Deploy additional scanner pods
        // 2. Update the semaphore permits
        // 3. Potentially increase resource quotas
        
        // For now, we'll just log the scaling decision
        warn!("Scale-up triggered - implement additional scanner pod deployment");
        
        Ok(())
    }

    async fn scale_down(&self) -> Result<()> {
        info!("Auto-scaling down - queue utilization low");
        
        // In a real implementation, this would:
        // 1. Gracefully terminate excess scanner pods
        // 2. Update the semaphore permits
        // 3. Wait for current scans to complete
        
        // For now, we'll just log the scaling decision
        warn!("Scale-down triggered - implement scanner pod termination");
        
        Ok(())
    }

    async fn trigger_queue_processing(&self) {
        // This is a no-op in this implementation since the queue processor runs continuously
        // In a more sophisticated implementation, this could wake up the processor immediately
    }
}
