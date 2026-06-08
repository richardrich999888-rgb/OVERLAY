use axum::{
    extract::Json,
    http::{header, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::env;
use std::net::SocketAddr;
use syntriass_overlay::fd_state;

const VOLUME_NAME: &str = "syntriass-overlay";
const INIT_CONTAINER_NAME: &str = "syntriass-binary-copier";
const APP_MOUNT_PATH: &str = "/usr/lib/syntriass";
const INIT_MOUNT_PATH: &str = "/syntriass";
const OVERLAY_LIBRARY_NAME: &str = "libsyntriass_overlay.so";

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct AdmissionReview {
    #[serde(rename = "apiVersion")]
    api_version: String,
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    request: Option<AdmissionRequest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response: Option<AdmissionResponse>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct AdmissionRequest {
    uid: String,
    kind: GroupVersionKind,
    operation: String,
    namespace: Option<String>,
    object: Value,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct GroupVersionKind {
    #[serde(default)]
    group: String,
    #[serde(default)]
    version: String,
    kind: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct AdmissionResponse {
    uid: String,
    allowed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<AdmissionStatus>,
    #[serde(rename = "patchType", skip_serializing_if = "Option::is_none")]
    patch_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    patch: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct AdmissionStatus {
    message: String,
}

#[derive(Debug, Serialize)]
struct JsonPatchOp {
    op: &'static str,
    path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<Value>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let bind_addr = env::var("SYNTRIASS_WEBHOOK_BIND")
        .unwrap_or_else(|_| "0.0.0.0:8443".to_string())
        .parse::<SocketAddr>()?;
    let metrics_addr = env::var("SYNTRIASS_METRICS_BIND")
        .unwrap_or_else(|_| "0.0.0.0:9090".to_string())
        .parse::<SocketAddr>()?;
    let webhook_app = Router::new().route("/mutate", post(mutate));
    let metrics_app = Router::new().route("/metrics", get(metrics));
    let webhook_listener = tokio::net::TcpListener::bind(bind_addr).await?;
    let metrics_listener = tokio::net::TcpListener::bind(metrics_addr).await?;
    tokio::try_join!(
        axum::serve(webhook_listener, webhook_app),
        axum::serve(metrics_listener, metrics_app)
    )?;
    Ok(())
}

async fn metrics() -> impl IntoResponse {
    match fd_state::render_prometheus_metrics() {
        Ok(body) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, prometheus::TEXT_FORMAT)],
            body,
        ),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            "metrics unavailable\n".to_string(),
        ),
    }
}

async fn mutate(Json(review): Json<AdmissionReview>) -> (StatusCode, Json<AdmissionReview>) {
    let response = match review.request.as_ref() {
        Some(request) => mutate_request(request),
        None => deny("", "AdmissionReview request is missing"),
    };
    (
        StatusCode::OK,
        Json(AdmissionReview {
            api_version: review.api_version,
            kind: review.kind,
            request: None,
            response: Some(response),
        }),
    )
}

fn mutate_request(request: &AdmissionRequest) -> AdmissionResponse {
    if request.kind.kind != "Pod" || request.operation != "CREATE" {
        return allow_without_patch(&request.uid);
    }

    // Namespace labels are not embedded in a Pod AdmissionReview object. In a
    // production cluster, configure the MutatingWebhookConfiguration with:
    // namespaceSelector.matchLabels.syntriass-injection=enabled. If this server
    // receives the Pod CREATE request, the Kubernetes API server has already
    // performed the namespace-label routing decision.
    match build_patch(&request.object) {
        Ok(patch) if patch.is_empty() => allow_without_patch(&request.uid),
        Ok(patch) => match serde_json::to_vec(&patch) {
            Ok(bytes) => AdmissionResponse {
                uid: request.uid.clone(),
                allowed: true,
                status: None,
                patch_type: Some("JSONPatch".to_string()),
                patch: Some(base64::engine::general_purpose::STANDARD.encode(bytes)),
            },
            Err(_) => deny(&request.uid, "failed to serialize Syntriass JSON patch"),
        },
        Err(message) => deny(&request.uid, message),
    }
}

fn allow_without_patch(uid: &str) -> AdmissionResponse {
    AdmissionResponse {
        uid: uid.to_string(),
        allowed: true,
        status: None,
        patch_type: None,
        patch: None,
    }
}

fn deny(uid: &str, message: &str) -> AdmissionResponse {
    AdmissionResponse {
        uid: uid.to_string(),
        allowed: false,
        status: Some(AdmissionStatus {
            message: message.to_string(),
        }),
        patch_type: None,
        patch: None,
    }
}

fn build_patch(pod: &Value) -> Result<Vec<JsonPatchOp>, &'static str> {
    let containers = pod
        .pointer("/spec/containers")
        .and_then(Value::as_array)
        .ok_or("Pod spec.containers must be an array")?;
    if containers.is_empty() {
        return Err("Pod spec.containers cannot be empty");
    }

    let mut patch = Vec::new();
    push_volume_patch(pod, &mut patch);
    push_init_container_patch(pod, &mut patch);
    push_target_container_patch(pod, &mut patch, 0)?;
    Ok(patch)
}

fn push_volume_patch(pod: &Value, patch: &mut Vec<JsonPatchOp>) {
    let volume = json!({
        "name": VOLUME_NAME,
        "emptyDir": {
            "medium": "Memory"
        }
    });
    match pod.pointer("/spec/volumes").and_then(Value::as_array) {
        Some(volumes) if has_named_item(volumes, VOLUME_NAME) => {}
        Some(_) => patch.push(add("/spec/volumes/-", volume)),
        None => patch.push(add("/spec/volumes", json!([volume]))),
    }
}

fn push_init_container_patch(pod: &Value, patch: &mut Vec<JsonPatchOp>) {
    let image = env::var("SYNTRIASS_WEBHOOK_COPIER_IMAGE")
        .unwrap_or_else(|_| "syntriass/overlay-copier:latest".to_string());
    let source = env::var("SYNTRIASS_WEBHOOK_SOURCE_LIBRARY")
        .unwrap_or_else(|_| format!("/opt/syntriass/{OVERLAY_LIBRARY_NAME}"));
    let command = format!(
        "cp {source} {INIT_MOUNT_PATH}/{OVERLAY_LIBRARY_NAME} && chmod 0555 {INIT_MOUNT_PATH}/{OVERLAY_LIBRARY_NAME}"
    );
    let init_container = json!({
        "name": INIT_CONTAINER_NAME,
        "image": image,
        "imagePullPolicy": "IfNotPresent",
        "command": ["/bin/sh", "-ec"],
        "args": [command],
        "volumeMounts": [{
            "name": VOLUME_NAME,
            "mountPath": INIT_MOUNT_PATH
        }],
        "securityContext": {
            "allowPrivilegeEscalation": false,
            "readOnlyRootFilesystem": true,
            "runAsNonRoot": true,
            "runAsUser": 65532,
            "runAsGroup": 65532,
            "capabilities": {
                "drop": ["ALL"]
            }
        }
    });
    match pod
        .pointer("/spec/initContainers")
        .and_then(Value::as_array)
    {
        Some(init_containers) if has_named_item(init_containers, INIT_CONTAINER_NAME) => {}
        Some(_) => patch.push(add("/spec/initContainers/-", init_container)),
        None => patch.push(add("/spec/initContainers", json!([init_container]))),
    }
}

fn push_target_container_patch(
    pod: &Value,
    patch: &mut Vec<JsonPatchOp>,
    container_index: usize,
) -> Result<(), &'static str> {
    let container = pod
        .pointer(&format!("/spec/containers/{container_index}"))
        .ok_or("target container is missing")?;
    let mount = json!({
        "name": VOLUME_NAME,
        "mountPath": APP_MOUNT_PATH,
        "readOnly": true
    });
    let mount_path = format!("/spec/containers/{container_index}/volumeMounts");
    match container.pointer("/volumeMounts").and_then(Value::as_array) {
        Some(mounts) if has_named_item(mounts, VOLUME_NAME) => {}
        Some(_) => patch.push(add(&format!("{mount_path}/-"), mount)),
        None => patch.push(add(&mount_path, json!([mount]))),
    }

    let preload_value = format!("{APP_MOUNT_PATH}/{OVERLAY_LIBRARY_NAME}");
    let env_path = format!("/spec/containers/{container_index}/env");
    match container.pointer("/env").and_then(Value::as_array) {
        Some(envs) => {
            if let Some(index) = named_item_index(envs, "LD_PRELOAD") {
                patch.push(replace(
                    &format!("{env_path}/{index}"),
                    json!({
                        "name": "LD_PRELOAD",
                        "value": preload_value
                    }),
                ));
            } else {
                patch.push(add(
                    &format!("{env_path}/-"),
                    json!({
                        "name": "LD_PRELOAD",
                        "value": preload_value
                    }),
                ));
            }
        }
        None => patch.push(add(
            &env_path,
            json!([{
                "name": "LD_PRELOAD",
                "value": preload_value
            }]),
        )),
    }
    Ok(())
}

fn add(path: &str, value: Value) -> JsonPatchOp {
    JsonPatchOp {
        op: "add",
        path: path.to_string(),
        value: Some(value),
    }
}

fn replace(path: &str, value: Value) -> JsonPatchOp {
    JsonPatchOp {
        op: "replace",
        path: path.to_string(),
        value: Some(value),
    }
}

fn has_named_item(items: &[Value], name: &str) -> bool {
    named_item_index(items, name).is_some()
}

fn named_item_index(items: &[Value], name: &str) -> Option<usize> {
    items.iter().position(|item| {
        item.get("name")
            .and_then(Value::as_str)
            .is_some_and(|candidate| candidate == name)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pod_patch_injects_ram_volume_init_container_mount_and_preload() {
        let pod = json!({
            "metadata": {
                "name": "legacy-app",
                "namespace": "enabled-ns"
            },
            "spec": {
                "containers": [{
                    "name": "legacy",
                    "image": "legacy:latest"
                }]
            }
        });

        let patch = build_patch(&pod).expect("patch");
        let encoded = serde_json::to_value(&patch).expect("json patch");

        assert!(encoded
            .as_array()
            .expect("array")
            .iter()
            .any(|op| op["path"] == "/spec/volumes"
                && op["value"][0]["emptyDir"]["medium"] == "Memory"));
        assert!(encoded
            .as_array()
            .expect("array")
            .iter()
            .any(|op| op["path"] == "/spec/initContainers"
                && op["value"][0]["name"] == INIT_CONTAINER_NAME));
        assert!(encoded
            .as_array()
            .expect("array")
            .iter()
            .any(|op| op["path"] == "/spec/containers/0/volumeMounts"
                && op["value"][0]["mountPath"] == APP_MOUNT_PATH));
        assert!(encoded.as_array().expect("array").iter().any(|op| {
            op["path"] == "/spec/containers/0/env"
                && op["value"][0]["name"] == "LD_PRELOAD"
                && op["value"][0]["value"] == format!("{APP_MOUNT_PATH}/{OVERLAY_LIBRARY_NAME}")
        }));
    }

    #[test]
    fn pod_patch_replaces_existing_ld_preload() {
        let pod = json!({
            "spec": {
                "volumes": [],
                "initContainers": [],
                "containers": [{
                    "name": "legacy",
                    "image": "legacy:latest",
                    "env": [{
                        "name": "LD_PRELOAD",
                        "value": "/old/lib.so"
                    }],
                    "volumeMounts": []
                }]
            }
        });

        let patch = build_patch(&pod).expect("patch");
        let encoded = serde_json::to_value(&patch).expect("json patch");
        assert!(encoded.as_array().expect("array").iter().any(|op| {
            op["op"] == "replace"
                && op["path"] == "/spec/containers/0/env/0"
                && op["value"]["value"] == format!("{APP_MOUNT_PATH}/{OVERLAY_LIBRARY_NAME}")
        }));
    }
}
