//! Development-only foundation host. No engines, providers or product actions.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use edy_storage::Storage;
use serde::Serialize;
use tauri::{Manager, WebviewWindow, WebviewWindowBuilder};

#[derive(Clone, Debug, PartialEq, Serialize)]
struct FoundationStatus {
    core: &'static str,
    storage: &'static str,
    ipc: &'static str,
    schema_version: u32,
}

struct FoundationState {
    status: FoundationStatus,
    smoke: bool,
    smoke_received: AtomicBool,
}

fn allowed_navigation(url: &tauri::Url) -> bool {
    url.username().is_empty()
        && url.password().is_none()
        && url.port().is_none()
        && url.query().is_none()
        && matches!(url.path(), "/" | "/index.html")
        && ((url.scheme() == "http" && url.host_str() == Some("tauri.localhost"))
            || (url.scheme() == "tauri" && url.host_str() == Some("localhost")))
}

fn empty_arguments(body: &tauri::ipc::InvokeBody) -> bool {
    matches!(body, tauri::ipc::InvokeBody::Json(value) if value.as_object().is_some_and(serde_json::Map::is_empty))
}

#[tauri::command]
fn foundation_status(
    app: tauri::AppHandle,
    window: WebviewWindow,
    request: tauri::ipc::Request<'_>,
    state: tauri::State<'_, FoundationState>,
) -> Result<FoundationStatus, &'static str> {
    // Defense in depth in addition to AppManifest, capability and Isolation hook.
    if window.label() != "main"
        || !window.url().is_ok_and(|url| allowed_navigation(&url))
        || !empty_arguments(request.body())
    {
        return Err("IPC denied");
    }
    if state.smoke && !state.smoke_received.swap(true, Ordering::SeqCst) {
        println!(
            "FOUNDATION_IPC_RECEIVED core=ready storage=ready ipc=restricted schema_version=1"
        );
        // Only the explicit technical smoke launch exits. No IPC exit argument exists.
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(750));
            app.exit(0);
        });
    }
    Ok(state.status.clone())
}

fn find_project_root(start: &Path) -> Option<PathBuf> {
    start
        .ancestors()
        .find(|path| {
            path.join("Cargo.toml").is_file()
                && path
                    .join("docs/architecture/foundation-contract.md")
                    .is_file()
                && path
                    .join("apps/desktop/src-tauri/tauri.conf.json")
                    .is_file()
        })
        .map(Path::to_path_buf)
}

fn project_root() -> std::io::Result<PathBuf> {
    let executable = std::env::current_exe()?;
    let root = find_project_root(&executable);
    #[cfg(debug_assertions)]
    let root = root.or_else(|| find_project_root(Path::new(env!("CARGO_MANIFEST_DIR"))));
    root.ok_or_else(|| std::io::Error::other("Foundation must run inside its project workspace"))
}

fn reject_link(path: &Path) -> std::io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            #[cfg(windows)]
            let reparse = {
                use std::os::windows::fs::MetadataExt;
                metadata.file_attributes() & 0x400 != 0
            };
            #[cfg(not(windows))]
            let reparse = false;
            if metadata.file_type().is_symlink() || reparse {
                return Err(std::io::Error::other(
                    "Foundation local path must not be a link",
                ));
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn local_directory(root: &Path, name: &str) -> std::io::Result<PathBuf> {
    let local = root.join(".local");
    let directory = local.join(name);
    reject_link(&local)?;
    reject_link(&directory)?;
    std::fs::create_dir_all(&directory)?;
    Ok(directory)
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let smoke = std::env::args_os()
        .skip(1)
        .any(|arg| arg == "--foundation-smoke");
    let root = project_root()?;
    let data = local_directory(&root, "data")?;
    let database = data.join("foundation.sqlite3");
    reject_link(&database)?;
    let storage = Storage::open(&database)?;
    let schema_version = storage.schema_version()?;
    if schema_version != 1 {
        return Err(std::io::Error::other("Unexpected foundation storage schema").into());
    }
    drop(storage);
    let webview_data = local_directory(&root, "webview2")?;
    let state = FoundationState {
        status: FoundationStatus {
            core: "ready",
            storage: "ready",
            ipc: "restricted",
            schema_version,
        },
        smoke,
        smoke_received: AtomicBool::new(false),
    };
    tauri::Builder::default()
        .manage(state)
        .invoke_handler(tauri::generate_handler![foundation_status])
        .setup(move |app| {
            let config = app
                .config()
                .app
                .windows
                .iter()
                .find(|window| window.label == "main")
                .ok_or_else(|| std::io::Error::other("Foundation window configuration absent"))?;
            WebviewWindowBuilder::from_config(app, config)?
                .data_directory(webview_data)
                .devtools(false)
                .browser_extensions_enabled(false)
                .general_autofill_enabled(false)
                .on_navigation(allowed_navigation)
                .on_new_window(|_, _| tauri::webview::NewWindowResponse::Deny)
                .on_download(|_, _| false)
                .build()?;
            if smoke {
                let handle = app.handle().clone();
                std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_secs(15));
                    if !handle
                        .state::<FoundationState>()
                        .smoke_received
                        .load(Ordering::SeqCst)
                    {
                        eprintln!("FOUNDATION_SMOKE_FAILED: IPC not received");
                        handle.exit(2);
                    }
                });
            }
            Ok(())
        })
        .run(tauri::generate_context!())?;
    Ok(())
}

fn main() {
    if run().is_err() {
        // Deliberately avoid paths, engine output or credential material in logs.
        eprintln!("Foundation startup failed; infrastructure readiness is unavailable.");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_exact_local_main_navigation_is_allowed() {
        for url in [
            "http://tauri.localhost/",
            "http://tauri.localhost/index.html",
            "tauri://localhost/",
        ] {
            assert!(allowed_navigation(&url.parse().unwrap()));
        }
        for url in [
            "https://example.com/",
            "http://tauri.localhost.evil/",
            "http://tauri.evil.com/",
            "http://tauri.localhost:8080/",
            "http://user@tauri.localhost/",
            "http://tauri.localhost/?remote=true",
            "http://tauri.localhost/other.html",
            "file:///C:/secret",
            "data:text/html,hello",
        ] {
            assert!(!allowed_navigation(&url.parse().unwrap()), "{url}");
        }
    }

    #[test]
    fn arguments_reject_nonempty_json_and_binary_bodies() {
        assert!(empty_arguments(&tauri::ipc::InvokeBody::Json(
            serde_json::json!({})
        )));
        for value in [
            serde_json::json!({"path":"C:/"}),
            serde_json::json!([]),
            serde_json::Value::Null,
        ] {
            assert!(!empty_arguments(&tauri::ipc::InvokeBody::Json(value)));
        }
        assert!(!empty_arguments(&tauri::ipc::InvokeBody::Raw(vec![])));
    }

    #[test]
    fn wire_contract_is_exact() {
        let status = FoundationStatus {
            core: "ready",
            storage: "ready",
            ipc: "restricted",
            schema_version: 1,
        };
        assert_eq!(
            serde_json::to_value(status).unwrap(),
            serde_json::json!({
                "core":"ready", "storage":"ready", "ipc":"restricted", "schema_version":1
            })
        );
    }
}
