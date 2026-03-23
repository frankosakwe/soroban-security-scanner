use anyhow::{anyhow, Result};
use k8s_openapi::api::{
    batch::v1::Job,
    core::v1::{
        Pod, Container, Volume, VolumeMount, ResourceRequirements, PodSecurityContext,
        SecurityContext, Capabilities, EnvVar, EnvVarSource, SecretKeySelector, LocalObjectReference,
    },
    networking::v1::{NetworkPolicy, NetworkPolicyEgressRule, NetworkPolicyPort},
    policy::v1::{PodDisruptionBudget, Eviction},
};
use kube::{
    api::{Api, ListParams, PostParams, DeleteParams, PatchParams, Patch, WatchEvent},
    client::Client,
    runtime::watcher,
    ResourceExt,
};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use tokio::time::{sleep, Duration};
use tracing::{info, warn, error, debug};
use uuid::Uuid;

use crate::models::*;

pub struct KubernetesClient {
    client: Client,
    namespace: String,
}

impl KubernetesClient {
    pub async fn new(kubeconfig_path: &Option<String>) -> Result<Self> {
        let client = if let Some(path) = kubeconfig_path {
            Client::try_from(kube::Config::from_kubeconfig(&kube::config::Kubeconfig::read_from(path)?).await?)?
        } else {
            Client::try_default().await?
        };

        Ok(Self {
            client,
            namespace: "stellar-scanner".to_string(), // Default namespace
        })
    }

    pub async fn create_scan_job(&self, scan_id: &Uuid, request: &CreateScanRequest) -> Result<JobInfo> {
        info!("Creating scan job for scan_id: {}", scan_id);

        // Create unique namespace for this scan
        let scan_namespace = format!("scan-{}", scan_id);
        self.create_scan_namespace(&scan_namespace).await?;

        // Create ResourceQuota for isolation
        let resource_quota = self.create_resource_quota(&scan_namespace, request).await?;

        // Create NetworkPolicy to block egress
        let network_policy = self.create_network_policy(&scan_namespace).await?;

        // Create encrypted volume
        let volume = self.create_encrypted_volume(&scan_namespace).await?;

        // Create the scan job with sidecar
        let job = self.create_scan_pod(&scan_namespace, scan_id, request, &volume).await?;

        Ok(JobInfo {
            pod_name: job.pod_name,
            namespace: job.namespace,
            resource_quota: resource_quota,
            network_policy: network_policy,
        })
    }

    async fn create_scan_namespace(&self, namespace: &str) -> Result<()> {
        let namespace_api: Api<k8s_openapi::api::core::v1::Namespace> = Api::all(self.client.clone());
        
        let namespace_spec = json!({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {
                "name": namespace,
                "labels": {
                    "app": "stellar-scanner",
                    "component": "scan-namespace",
                    "managed-by": "stellar-scanner-backend"
                },
                "annotations": {
                    "stellar.scanner/created-at": chrono::Utc::now().to_rfc3339()
                }
            }
        });

        match namespace_api.create(&PostParams::default(), &serde_json::from_value(namespace_spec)?).await {
            Ok(_) => {
                info!("Created namespace: {}", namespace);
                Ok(())
            }
            Err(kube::Error::Api(ae)) if ae.code == 409 => {
                // Namespace already exists
                warn!("Namespace {} already exists", namespace);
                Ok(())
            }
            Err(e) => Err(anyhow!("Failed to create namespace {}: {}", namespace, e))
        }
    }

    async fn create_resource_quota(&self, namespace: &str, request: &CreateScanRequest) -> Result<String> {
        let quota_api: Api<k8s_openapi::api::policy::v1::ResourceQuota> = Api::namespaced(self.client.clone(), namespace);
        
        let limits = request.resource_limits.as_ref().unwrap_or(&ResourceLimits {
            cpu_millis: 1000,
            memory_mb: 2048,
            storage_mb: 1024,
        });

        let quota_spec = json!({
            "apiVersion": "v1",
            "kind": "ResourceQuota",
            "metadata": {
                "name": format!("scan-quota-{}", Uuid::new_v4()),
                "labels": {
                    "app": "stellar-scanner",
                    "component": "resource-quota"
                }
            },
            "spec": {
                "hard": {
                    "requests.cpu": format!("{}m", limits.cpu_millis),
                    "requests.memory": format!("{}Mi", limits.memory_mb),
                    "limits.cpu": format!("{}m", limits.cpu_millis),
                    "limits.memory": format!("{}Mi", limits.memory_mb),
                    "pods": "1",
                    "requests.storage": format!("{}Mi", limits.storage_mb),
                    "persistentvolumeclaims": "1"
                }
            }
        });

        let quota = quota_api.create(&PostParams::default(), &serde_json::from_value(quota_spec)?).await?;
        let quota_name = quota.name_any();
        info!("Created ResourceQuota: {}", quota_name);
        Ok(quota_name)
    }

    async fn create_network_policy(&self, namespace: &str) -> Result<String> {
        let policy_api: Api<NetworkPolicy> = Api::namespaced(self.client.clone(), namespace);
        
        let policy_spec = json!({
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {
                "name": format!("scan-deny-egress-{}", Uuid::new_v4()),
                "labels": {
                    "app": "stellar-scanner",
                    "component": "network-policy"
                }
            },
            "spec": {
                "podSelector": {},
                "policyTypes": ["Egress"],
                "egress": []
            }
        });

        let policy = policy_api.create(&PostParams::default(), &serde_json::from_value(policy_spec)?).await?;
        let policy_name = policy.name_any();
        info!("Created NetworkPolicy: {}", policy_name);
        Ok(policy_name)
    }

    async fn create_encrypted_volume(&self, namespace: &str) -> Result<String> {
        let pvc_api: Api<k8s_openapi::api::core::v1::PersistentVolumeClaim> = Api::namespaced(self.client.clone(), namespace);
        
        let pvc_spec = json!({
            "apiVersion": "v1",
            "kind": "PersistentVolumeClaim",
            "metadata": {
                "name": format!("scan-storage-{}", Uuid::new_v4()),
                "labels": {
                    "app": "stellar-scanner",
                    "component": "encrypted-storage"
                },
                "annotations": {
                    "volume.beta.kubernetes.io/storage-class": "encrypted-ssd"
                }
            },
            "spec": {
                "accessModes": ["ReadWriteOnce"],
                "storageClassName": "encrypted-ssd",
                "resources": {
                    "requests": {
                        "storage": "1Gi"
                    }
                }
            }
        });

        let pvc = pvc_api.create(&PostParams::default(), &serde_json::from_value(pvc_spec)?).await?;
        let pvc_name = pvc.name_any();
        info!("Created encrypted PVC: {}", pvc_name);
        Ok(pvc_name)
    }

    async fn create_scan_pod(&self, namespace: &str, scan_id: &Uuid, request: &CreateScanRequest, volume_name: &str) -> Result<JobInfo> {
        let job_api: Api<Job> = Api::namespaced(self.client.clone(), namespace);
        
        let job_name = format!("scan-{}", scan_id);
        let limits = request.resource_limits.as_ref().unwrap_or(&ResourceLimits {
            cpu_millis: 1000,
            memory_mb: 2048,
            storage_mb: 1024,
        });

        // Main scanner container
        let scanner_container = json!({
            "name": "scanner",
            "image": "stellar-security-scanner:latest",
            "imagePullPolicy": "IfNotPresent",
            "resources": {
                "requests": {
                    "cpu": format!("{}m", limits.cpu_millis / 2),
                    "memory": format!("{}Mi", limits.memory_mb / 2)
                },
                "limits": {
                    "cpu": format!("{}m", limits.cpu_millis),
                    "memory": format!("{}Mi", limits.memory_mb)
                }
            },
            "securityContext": {
                "runAsNonRoot": true,
                "runAsUser": 1000,
                "readOnlyRootFilesystem": true,
                "allowPrivilegeEscalation": false,
                "capabilities": {
                    "drop": ["ALL"]
                }
            },
            "env": [
                {
                    "name": "SCAN_ID",
                    "value": scan_id.to_string()
                },
                {
                    "name": "REPOSITORY_URL",
                    "value": request.repository_url.clone()
                },
                {
                    "name": "BRANCH",
                    "value": request.branch.clone().unwrap_or_else(|| "main".to_string())
                },
                {
                    "name": "COMMIT_HASH",
                    "value": request.commit_hash.clone().unwrap_or_default()
                },
                {
                    "name": "SCAN_TYPES",
                    "value": serde_json::to_string(&request.scan_types)?
                },
                {
                    "name": "OUTPUT_DIR",
                    "value": "/scan/results"
                },
                {
                    "name": "ENCRYPTION_KEY",
                    "valueFrom": {
                        "secretKeyRef": {
                            "name": "scanner-secrets",
                            "key": "encryption-key"
                        }
                    }
                }
            ],
            "volumeMounts": [
                {
                    "name": "scan-storage",
                    "mountPath": "/scan/results"
                },
                {
                    "name": "tmp",
                    "mountPath": "/tmp"
                }
            ],
            "command": ["/bin/sh", "-c"],
            "args": [
                "git clone $REPOSITORY_URL /scan/source && \
                cd /scan/source && \
                git checkout $BRANCH && \
                stellar-scanner scan /scan/source --format json --output /scan/results/results.json && \
                echo 'Scan completed successfully'"
            ]
        });

        // Log streaming sidecar
        let log_sidecar = json!({
            "name": "log-streamer",
            "image": "fluent/fluent-bit:latest",
            "resources": {
                "requests": {
                    "cpu": "100m",
                    "memory": "128Mi"
                },
                "limits": {
                    "cpu": "200m",
                    "memory": "256Mi"
                }
            },
            "securityContext": {
                "runAsNonRoot": true,
                "runAsUser": 1000,
                "readOnlyRootFilesystem": true,
                "allowPrivilegeEscalation": false,
                "capabilities": {
                    "drop": ["ALL"]
                }
            },
            "env": [
                {
                    "name": "SCAN_ID",
                    "value": scan_id.to_string()
                },
                {
                    "name": "LOG_DESTINATION",
                    "value": "http://log-collector.stellar-scanner.svc.cluster.local:8080/logs"
                }
            ],
            "volumeMounts": [
                {
                    "name": "scan-storage",
                    "mountPath": "/scan/results",
                    "readOnly": true
                },
                {
                    "name": "varlog",
                    "mountPath": "/var/log"
                },
                {
                    "name": "varlibdockercontainers",
                    "mountPath": "/var/lib/docker/containers",
                    "readOnly": true
                }
            ]
        });

        let job_spec = json!({
            "apiVersion": "batch/v1",
            "kind": "Job",
            "metadata": {
                "name": job_name,
                "labels": {
                    "app": "stellar-scanner",
                    "component": "scan-job",
                    "scan-id": scan_id.to_string()
                },
                "annotations": {
                    "stellar.scanner/created-at": chrono::Utc::now().to_rfc3339(),
                    "stellar.scanner/repository": request.repository_url,
                    "stellar.scanner/timeout-minutes": request.timeout_minutes.unwrap_or(30).to_string()
                }
            },
            "spec": {
                "backoffLimit": 0,
                "ttlSecondsAfterFinished": 300,
                "activeDeadlineSeconds": (request.timeout_minutes.unwrap_or(30) * 60),
                "template": {
                    "metadata": {
                        "labels": {
                            "app": "stellar-scanner",
                            "component": "scan-pod",
                            "scan-id": scan_id.to_string()
                        }
                    },
                    "spec": {
                        "restartPolicy": "Never",
                        "securityContext": {
                            "runAsNonRoot": true,
                            "runAsUser": 1000,
                            "fsGroup": 1000
                        },
                        "containers": [scanner_container, log_sidecar],
                        "volumes": [
                            {
                                "name": "scan-storage",
                                "persistentVolumeClaim": {
                                    "claimName": volume_name
                                }
                            },
                            {
                                "name": "tmp",
                                "emptyDir": {}
                            },
                            {
                                "name": "varlog",
                                "hostPath": {
                                    "path": "/var/log",
                                    "type": "Directory"
                                }
                            },
                            {
                                "name": "varlibdockercontainers",
                                "hostPath": {
                                    "path": "/var/lib/docker/containers",
                                    "type": "Directory"
                                }
                            }
                        ],
                        "nodeSelector": {
                            "stellar.scanner/node-type": "scanner"
                        },
                        "tolerations": [
                            {
                                "key": "stellar.scanner/dedicated",
                                "operator": "Equal",
                                "value": "true",
                                "effect": "NoSchedule"
                            }
                        ]
                    }
                }
            }
        });

        let job = job_api.create(&PostParams::default(), &serde_json::from_value(job_spec)?).await?;
        info!("Created scan job: {}", job.name_any());

        Ok(JobInfo {
            pod_name: job_name,
            namespace: namespace.to_string(),
            resource_quota: String::new(), // These will be filled by caller
            network_policy: String::new(),
        })
    }

    pub async fn get_scan_status(&self, scan_id: &Uuid) -> Result<ScanStatus> {
        let namespace = format!("scan-{}", scan_id);
        let job_api: Api<Job> = Api::namespaced(self.client.clone(), &namespace);
        
        let job_name = format!("scan-{}", scan_id);
        
        match job_api.get(&job_name).await {
            Ok(job) => {
                let status = job.status.as_ref().ok_or_else(|| anyhow!("Job status not found"))?;
                
                if let Some(conditions) = &status.conditions {
                    for condition in conditions {
                        if condition.type_ == "Complete" && condition.status == "True" {
                            return Ok(ScanStatus::Completed);
                        }
                        if condition.type_ == "Failed" && condition.status == "True" {
                            return Ok(ScanStatus::Failed);
                        }
                    }
                }
                
                if status.active.unwrap_or(0) > 0 {
                    Ok(ScanStatus::Running)
                } else {
                    Ok(ScanStatus::Pending)
                }
            }
            Err(kube::Error::Api(ae)) if ae.code == 404 => {
                // Check if namespace exists
                let namespace_api: Api<k8s_openapi::api::core::v1::Namespace> = Api::all(self.client.clone());
                if namespace_api.get(&namespace).await.is_err() {
                    Ok(ScanStatus::Cancelled) // Namespace was cleaned up
                } else {
                    Ok(ScanStatus::Pending) // Job doesn't exist yet
                }
            }
            Err(e) => Err(anyhow!("Failed to get scan status: {}", e))
        }
    }

    pub async fn get_scan_logs(&self, scan_id: &Uuid, lines: usize) -> Result<Vec<crate::models::LogEntry>> {
        let namespace = format!("scan-{}", scan_id);
        let pod_api: Api<Pod> = Api::namespaced(self.client.clone(), &namespace);
        
        let pod_name = format!("scan-{}", scan_id);
        
        let logs = pod_api.logs(&pod_name, &kube::api::LogParams {
            tail_lines: Some(lines as i64),
            ..Default::default()
        }).await?;

        // Parse logs into LogEntry format
        let mut log_entries = Vec::new();
        for line in logs.lines() {
            if let Ok(entry) = self.parse_log_line(line) {
                log_entries.push(entry);
            }
        }

        Ok(log_entries)
    }

    fn parse_log_line(&self, line: &str) -> Result<crate::models::LogEntry> {
        // Simple log parsing - in production, you'd want more sophisticated parsing
        let timestamp = chrono::Utc::now();
        let level = if line.contains("ERROR") || line.contains("error") {
            LogLevel::Error
        } else if line.contains("WARN") || line.contains("warn") {
            LogLevel::Warn
        } else if line.contains("DEBUG") || line.contains("debug") {
            LogLevel::Debug
        } else {
            LogLevel::Info
        };

        Ok(crate::models::LogEntry {
            timestamp,
            level,
            message: line.to_string(),
            source: "scanner".to_string(),
        })
    }

    pub async fn get_scan_results(&self, scan_id: &Uuid) -> Result<crate::models::ScanResults> {
        let namespace = format!("scan-{}", scan_id);
        let pod_api: Api<Pod> = Api::namespaced(self.client.clone(), &namespace);
        
        let pod_name = format!("scan-{}", scan_id);
        
        // Get the results file from the pod
        let results = pod_api
            .exec(&pod_name, vec!["cat", "/scan/results/results.json"], &kube::api::PortforwarderConfig::default())
            .await?;

        let results_str = String::from_utf8(results)?;
        let scan_results: crate::models::ScanResults = serde_json::from_str(&results_str)?;
        
        Ok(scan_results)
    }

    pub async fn list_scans(&self, limit: usize, offset: usize) -> Result<Vec<crate::models::ScanSummaryItem>> {
        let namespace_api: Api<k8s_openapi::api::core::v1::Namespace> = Api::all(self.client.clone());
        
        let lp = ListParams::default()
            .labels("app=stellar-scanner,component=scan-namespace")
            .limit(limit as i64);
        
        let namespaces = namespace_api.list(&lp).await?;
        let mut scans = Vec::new();

        for ns in namespaces.items {
            if let Some(scan_id_str) = ns.metadata.name.strip_prefix("scan-") {
                if let Ok(scan_id) = Uuid::parse_str(scan_id_str) {
                    let status = self.get_scan_status(&scan_id).await?;
                    
                    // Get job details for repository URL
                    let job_api: Api<Job> = Api::namespaced(self.client.clone(), &ns.name_any());
                    let job_name = format!("scan-{}", scan_id);
                    
                    let repository_url = if let Ok(job) = job_api.get(&job_name).await {
                        job.metadata.annotations
                            .get("stellar.scanner/repository")
                            .cloned()
                            .unwrap_or_default()
                    } else {
                        String::new()
                    };

                    scans.push(crate::models::ScanSummaryItem {
                        scan_id: scan_id.to_string(),
                        status,
                        created_at: ns.metadata.creation_timestamp.unwrap_or_default().0,
                        completed_at: None, // Would need to check job completion time
                        repository_url,
                        summary: crate::models::ScanSummary {
                            total_files_scanned: 0, // Would need to get from results
                            total_vulnerabilities: 0,
                            total_invariant_violations: 0,
                            risk_score: 0.0,
                            scan_duration_seconds: 0,
                        },
                    });
                }
            }
        }

        Ok(scans)
    }

    pub async fn cleanup_scan(&self, scan_id: &Uuid) -> Result<()> {
        let namespace = format!("scan-{}", scan_id);
        let namespace_api: Api<k8s_openapi::api::core::v1::Namespace> = Api::all(self.client.clone());
        
        info!("Cleaning up scan namespace: {}", namespace);
        
        match namespace_api.delete(&namespace, &DeleteParams::default()).await {
            Ok(_) => {
                info!("Successfully cleaned up scan namespace: {}", namespace);
                Ok(())
            }
            Err(kube::Error::Api(ae)) if ae.code == 404 => {
                warn!("Scan namespace {} not found for cleanup", namespace);
                Ok(())
            }
            Err(e) => Err(anyhow!("Failed to cleanup scan namespace {}: {}", namespace, e))
        }
    }

    pub async fn start_cleanup_worker(&self) -> Result<()> {
        info!("Starting cleanup worker");
        
        let client = self.client.clone();
        let interval = Duration::from_secs(300); // 5 minutes
        
        tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(interval);
            
            loop {
                interval_timer.tick().await;
                
                if let Err(e) = Self::cleanup_old_scans(&client).await {
                    error!("Cleanup worker error: {}", e);
                }
            }
        });
        
        Ok(())
    }

    async fn cleanup_old_scans(client: &Client) -> Result<()> {
        let namespace_api: Api<k8s_openapi::api::core::v1::Namespace> = Api::all(client.clone());
        
        let lp = ListParams::default()
            .labels("app=stellar-scanner,component=scan-namespace");
        
        let namespaces = namespace_api.list(&lp).await?;
        let cutoff_time = chrono::Utc::now() - chrono::Duration::hours(24);
        
        for ns in namespaces.items {
            if let Some(created_at) = ns.metadata.creation_timestamp {
                if created_at.0 < cutoff_time {
                    info!("Cleaning up old scan namespace: {}", ns.name_any());
                    
                    match namespace_api.delete(&ns.name_any(), &DeleteParams::default()).await {
                        Ok(_) => info!("Cleaned up old namespace: {}", ns.name_any()),
                        Err(e) => error!("Failed to cleanup namespace {}: {}", ns.name_any(), e),
                    }
                }
            }
        }
        
        Ok(())
    }
}
