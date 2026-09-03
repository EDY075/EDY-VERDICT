//! Development-only foundation host. No engines, providers or product actions.

#[cfg(all(feature = "native-e2e", not(debug_assertions)))]
compile_error!("native-e2e is forbidden in release builds");

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use edy_core::InstalledApplication;
use edy_desktop::ipc::{
    AuthorizeFileTargetRequest, AuthorizeInstalledApplicationRequest,
    AuthorizeRepositoryTargetRequest, AuthorizeUrlTargetRequest, AuthorizedFileTargetView,
    AuthorizedInstalledApplicationView, AuthorizedRepositoryTargetView, AuthorizedUrlTargetView,
    CreateFileScanRequest, CreateInstalledApplicationScanRequest, CreateRepositoryScanRequest,
    CreateSyntheticScanRequest, CreateUrlScanRequest, EngineStatusView, FileAnalysisView,
    FileTargetPreviewView, FindingRequest, FindingView, GenerateReportRequest,
    InspectFileTargetRequest, InstalledApplicationInventoryView,
    InstalledApplicationPreviewRequest, InstalledApplicationPreviewView,
    InstalledApplicationRequest, Level0Backend, ListFindingsRequest, ListScansRequest,
    PreviewUrlTargetRequest, PublicDataRefreshView, RefreshPublicDataRequest, ReportView,
    RepositoryAuthorizationRequest, SafeIpcError, ScanProgressView, ScanRequest, ScanSummaryView,
    UrlTargetPreviewView, WebAnalysisView,
};
use edy_reporting::installed_apps::DatasetStatus;
use edy_repository::RepositoryInventory;
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
    backend: Level0Backend,
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

fn ipc_guard(window: &WebviewWindow) -> Result<(), SafeIpcError> {
    if window.label() != "main" || !window.url().is_ok_and(|url| allowed_navigation(&url)) {
        return Err(SafeIpcError {
            code: "ipc_denied".into(),
            message_safe: "IPC request was refused".into(),
            correlation_id: uuid::Uuid::now_v7().to_string(),
        });
    }
    Ok(())
}

#[tauri::command]
fn get_foundation_status(
    app: tauri::AppHandle,
    window: WebviewWindow,
    state: tauri::State<'_, FoundationState>,
) -> Result<FoundationStatus, SafeIpcError> {
    // Defense in depth in addition to AppManifest, capability and Isolation hook.
    ipc_guard(&window)?;
    if state.smoke && !state.smoke_received.swap(true, Ordering::SeqCst) {
        println!(
            "FOUNDATION_IPC_RECEIVED core=ready storage=ready ipc=restricted schema_version={}",
            state.status.schema_version
        );
        // Only the explicit technical smoke launch exits. No IPC exit argument exists.
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(750));
            app.exit(0);
        });
    }
    Ok(state.status.clone())
}

#[tauri::command]
fn get_engine_status(
    window: WebviewWindow,
    state: tauri::State<'_, FoundationState>,
) -> Result<Vec<EngineStatusView>, SafeIpcError> {
    ipc_guard(&window)?;
    Ok(state.backend.engine_status())
}

#[tauri::command]
fn authorize_repository_target(
    window: WebviewWindow,
    state: tauri::State<'_, FoundationState>,
    request: AuthorizeRepositoryTargetRequest,
) -> Result<AuthorizedRepositoryTargetView, SafeIpcError> {
    ipc_guard(&window)?;
    state.backend.authorize_repository_target(request)
}

#[tauri::command]
fn inspect_repository_target(
    window: WebviewWindow,
    state: tauri::State<'_, FoundationState>,
    request: RepositoryAuthorizationRequest,
) -> Result<RepositoryInventory, SafeIpcError> {
    ipc_guard(&window)?;
    state.backend.inspect_repository_target(&request)
}

#[tauri::command]
fn create_repository_scan(
    window: WebviewWindow,
    state: tauri::State<'_, FoundationState>,
    request: CreateRepositoryScanRequest,
) -> Result<ScanSummaryView, SafeIpcError> {
    ipc_guard(&window)?;
    state.backend.create_repository_scan(request)
}

#[tauri::command]
fn get_repository_inventory(
    window: WebviewWindow,
    state: tauri::State<'_, FoundationState>,
    request: ScanRequest,
) -> Result<RepositoryInventory, SafeIpcError> {
    ipc_guard(&window)?;
    state.backend.get_repository_inventory(&request)
}

#[tauri::command]
fn inspect_file_target(
    window: WebviewWindow,
    state: tauri::State<'_, FoundationState>,
    request: InspectFileTargetRequest,
) -> Result<FileTargetPreviewView, SafeIpcError> {
    ipc_guard(&window)?;
    state.backend.inspect_file_target(request)
}

#[tauri::command]
fn authorize_file_target(
    window: WebviewWindow,
    state: tauri::State<'_, FoundationState>,
    request: AuthorizeFileTargetRequest,
) -> Result<AuthorizedFileTargetView, SafeIpcError> {
    ipc_guard(&window)?;
    state.backend.authorize_file_target(request)
}

#[tauri::command]
fn create_file_scan(
    window: WebviewWindow,
    state: tauri::State<'_, FoundationState>,
    request: CreateFileScanRequest,
) -> Result<ScanSummaryView, SafeIpcError> {
    ipc_guard(&window)?;
    state.backend.create_file_scan(request)
}

#[tauri::command]
fn get_file_analysis(
    window: WebviewWindow,
    state: tauri::State<'_, FoundationState>,
    request: ScanRequest,
) -> Result<FileAnalysisView, SafeIpcError> {
    ipc_guard(&window)?;
    state.backend.get_file_analysis(&request)
}

#[tauri::command]
fn preview_installed_applications(
    window: WebviewWindow,
    state: tauri::State<'_, FoundationState>,
    request: InstalledApplicationPreviewRequest,
) -> Result<InstalledApplicationPreviewView, SafeIpcError> {
    ipc_guard(&window)?;
    state.backend.preview_installed_applications(request)
}

#[tauri::command]
fn authorize_installed_applications(
    window: WebviewWindow,
    state: tauri::State<'_, FoundationState>,
    request: AuthorizeInstalledApplicationRequest,
) -> Result<AuthorizedInstalledApplicationView, SafeIpcError> {
    ipc_guard(&window)?;
    state.backend.authorize_installed_applications(request)
}

#[tauri::command]
fn create_installed_application_scan(
    window: WebviewWindow,
    state: tauri::State<'_, FoundationState>,
    request: CreateInstalledApplicationScanRequest,
) -> Result<ScanSummaryView, SafeIpcError> {
    ipc_guard(&window)?;
    state.backend.create_installed_application_scan(request)
}

#[tauri::command]
fn get_installed_application_inventory(
    window: WebviewWindow,
    state: tauri::State<'_, FoundationState>,
    request: ScanRequest,
) -> Result<InstalledApplicationInventoryView, SafeIpcError> {
    ipc_guard(&window)?;
    state.backend.get_installed_application_inventory(&request)
}

#[tauri::command]
fn get_installed_application(
    window: WebviewWindow,
    state: tauri::State<'_, FoundationState>,
    request: InstalledApplicationRequest,
) -> Result<InstalledApplication, SafeIpcError> {
    ipc_guard(&window)?;
    state.backend.get_installed_application(&request)
}

#[tauri::command]
fn get_vulnerability_provider_status(
    window: WebviewWindow,
    state: tauri::State<'_, FoundationState>,
) -> Result<Vec<DatasetStatus>, SafeIpcError> {
    ipc_guard(&window)?;
    Ok(state.backend.vulnerability_provider_status())
}

#[tauri::command]
fn refresh_public_vulnerability_data(
    window: WebviewWindow,
    state: tauri::State<'_, FoundationState>,
    request: RefreshPublicDataRequest,
) -> Result<PublicDataRefreshView, SafeIpcError> {
    ipc_guard(&window)?;
    state.backend.refresh_public_vulnerability_data(request)
}

#[tauri::command]
fn preview_url_target(
    window: WebviewWindow,
    state: tauri::State<'_, FoundationState>,
    request: PreviewUrlTargetRequest,
) -> Result<UrlTargetPreviewView, SafeIpcError> {
    ipc_guard(&window)?;
    state.backend.preview_url_target(request)
}

#[tauri::command]
fn authorize_url_target(
    window: WebviewWindow,
    state: tauri::State<'_, FoundationState>,
    request: AuthorizeUrlTargetRequest,
) -> Result<AuthorizedUrlTargetView, SafeIpcError> {
    ipc_guard(&window)?;
    state.backend.authorize_url_target(request)
}

#[tauri::command]
fn create_url_scan(
    window: WebviewWindow,
    state: tauri::State<'_, FoundationState>,
    request: CreateUrlScanRequest,
) -> Result<ScanSummaryView, SafeIpcError> {
    ipc_guard(&window)?;
    state.backend.create_url_scan(request)
}

#[tauri::command]
fn get_url_scan_analysis(
    window: WebviewWindow,
    state: tauri::State<'_, FoundationState>,
    request: ScanRequest,
) -> Result<WebAnalysisView, SafeIpcError> {
    ipc_guard(&window)?;
    state.backend.get_url_scan_analysis(&request)
}

#[tauri::command]
fn get_url_redirect_chain(
    window: WebviewWindow,
    state: tauri::State<'_, FoundationState>,
    request: ScanRequest,
) -> Result<Vec<edy_core::RedirectObservation>, SafeIpcError> {
    ipc_guard(&window)?;
    state.backend.get_url_redirect_chain(&request)
}

#[tauri::command]
fn get_url_security_headers(
    window: WebviewWindow,
    state: tauri::State<'_, FoundationState>,
    request: ScanRequest,
) -> Result<Vec<edy_core::HeaderObservation>, SafeIpcError> {
    ipc_guard(&window)?;
    state.backend.get_url_security_headers(&request)
}

#[tauri::command]
fn get_url_cookie_observations(
    window: WebviewWindow,
    state: tauri::State<'_, FoundationState>,
    request: ScanRequest,
) -> Result<Vec<edy_core::CookieObservation>, SafeIpcError> {
    ipc_guard(&window)?;
    state.backend.get_url_cookie_observations(&request)
}

#[tauri::command]
fn get_url_reputation_status(
    window: WebviewWindow,
    state: tauri::State<'_, FoundationState>,
    request: ScanRequest,
) -> Result<edy_core::ReputationObservation, SafeIpcError> {
    ipc_guard(&window)?;
    state.backend.get_url_reputation_status(&request)
}

#[tauri::command]
fn create_synthetic_scan(
    window: WebviewWindow,
    state: tauri::State<'_, FoundationState>,
    request: CreateSyntheticScanRequest,
) -> Result<ScanSummaryView, SafeIpcError> {
    ipc_guard(&window)?;
    state.backend.create_synthetic_scan(request)
}

#[tauri::command]
fn get_scan(
    window: WebviewWindow,
    state: tauri::State<'_, FoundationState>,
    request: ScanRequest,
) -> Result<ScanSummaryView, SafeIpcError> {
    ipc_guard(&window)?;
    state.backend.get_scan(&request)
}

#[tauri::command]
fn list_scans(
    window: WebviewWindow,
    state: tauri::State<'_, FoundationState>,
    request: ListScansRequest,
) -> Result<Vec<ScanSummaryView>, SafeIpcError> {
    ipc_guard(&window)?;
    state.backend.list_scans(&request)
}

#[tauri::command]
fn get_scan_progress(
    window: WebviewWindow,
    state: tauri::State<'_, FoundationState>,
    request: ScanRequest,
) -> Result<ScanProgressView, SafeIpcError> {
    ipc_guard(&window)?;
    state.backend.progress(&request)
}

#[tauri::command]
fn cancel_scan(
    window: WebviewWindow,
    state: tauri::State<'_, FoundationState>,
    request: ScanRequest,
) -> Result<ScanProgressView, SafeIpcError> {
    ipc_guard(&window)?;
    state.backend.cancel(&request)
}

#[tauri::command]
fn list_findings(
    window: WebviewWindow,
    state: tauri::State<'_, FoundationState>,
    request: ListFindingsRequest,
) -> Result<Vec<FindingView>, SafeIpcError> {
    ipc_guard(&window)?;
    state.backend.list_findings(&request)
}

#[tauri::command]
fn get_finding(
    window: WebviewWindow,
    state: tauri::State<'_, FoundationState>,
    request: FindingRequest,
) -> Result<FindingView, SafeIpcError> {
    ipc_guard(&window)?;
    state.backend.get_finding(&request)
}

#[tauri::command]
fn generate_report(
    window: WebviewWindow,
    state: tauri::State<'_, FoundationState>,
    request: GenerateReportRequest,
) -> Result<ReportView, SafeIpcError> {
    ipc_guard(&window)?;
    state.backend.report(&request)
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
    let _native_level3_degraded = cfg!(debug_assertions)
        && std::env::args().any(|arg| arg.starts_with("--level3-native-qa-degraded="));
    let native_level3 = cfg!(debug_assertions)
        && std::env::args().any(|arg| {
            arg.starts_with("--level3-native-qa=")
                || arg.starts_with("--level3-native-qa-degraded=")
        });
    let native_level4 = cfg!(debug_assertions)
        && std::env::args().any(|arg| arg.starts_with("--level4-native-qa="));
    // Explicit debug-only native QA, not a production setting or IPC surface. Real handlers,
    // Isolation and React remain unchanged; only local data isolation and viewport differ.
    let native_qa_size: Option<(f64, f64)> = if cfg!(debug_assertions) {
        std::env::args().find_map(|arg| match arg.as_str() {
            "--level2-native-qa=1366x768" => Some((1366.0, 768.0)),
            "--level2-native-qa=1920x1080" => Some((1920.0, 1080.0)),
            "--level2-native-qa=2560x1440" => Some((2560.0, 1440.0)),
            "--level3-native-qa=1366x768" => Some((1366.0, 768.0)),
            "--level3-native-qa=1920x1080" => Some((1920.0, 1080.0)),
            "--level3-native-qa=2560x1440" => Some((2560.0, 1440.0)),
            "--level3-native-qa-degraded=1366x768" => Some((1366.0, 768.0)),
            "--level4-native-qa=1366x768" => Some((1366.0, 768.0)),
            "--level4-native-qa=1920x1080" => Some((1920.0, 1080.0)),
            "--level4-native-qa=2560x1440" => Some((2560.0, 1440.0)),
            _ => None,
        })
    } else {
        None
    };
    let data = local_directory(
        &root,
        if native_qa_size.is_some() {
            if native_level4 {
                "level4-native-qa-data"
            } else if native_level3 {
                "level3-native-qa-data"
            } else {
                "level2-native-qa-data"
            }
        } else {
            "data"
        },
    )?;
    let database = data.join("foundation.sqlite3");
    reject_link(&database)?;
    let storage = Storage::open(&database)?;
    // Storage::open verifies and migrates to its current schema (Level 0 introduced v2).
    // Do not reject that valid database with the obsolete pre-Level-0 v1 literal.
    drop(storage);
    #[cfg(all(feature = "native-e2e", debug_assertions))]
    let backend = if native_level4 {
        Level0Backend::open_level4_fixture(&root, &data.join("level0.sqlite3"))?
    } else if _native_level3_degraded {
        Level0Backend::open_level3_degraded_fixture(&root, &data.join("level0.sqlite3"))?
    } else if native_level3 {
        Level0Backend::open_level3_fixture(&root, &data.join("level0.sqlite3"))?
    } else {
        Level0Backend::open(&root, &data.join("level0.sqlite3"))?
    };
    #[cfg(not(all(feature = "native-e2e", debug_assertions)))]
    let backend = Level0Backend::open(&root, &data.join("level0.sqlite3"))?;
    let webview_data = local_directory(
        &root,
        if native_qa_size.is_some() {
            if native_level4 {
                "level4-native-qa-webview2"
            } else if native_level3 {
                "level3-native-qa-webview2"
            } else {
                "level2-native-qa-webview2"
            }
        } else {
            "webview2"
        },
    )?;
    let state = FoundationState {
        status: FoundationStatus {
            core: "ready",
            storage: "ready",
            ipc: "restricted",
            // Frozen infrastructure wire envelope v1, NOT SQLite PRAGMA user_version.
            schema_version: 1,
        },
        backend,
        smoke,
        smoke_received: AtomicBool::new(false),
    };
    let builder = tauri::Builder::default();
    // Explicit opt-in test build AND synthetic-data launch mode. No production listener,
    // additional IPC commands, frontend imports, capability changes or debug port.
    #[cfg(all(feature = "native-e2e", debug_assertions))]
    let builder = {
        if native_qa_size.is_none() {
            return Err("native-e2e requires an explicit bounded QA viewport".into());
        }
        builder.plugin(tauri_plugin_wdio_webdriver::init_with_port(4445))
    };
    builder
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            get_foundation_status,
            get_engine_status,
            authorize_repository_target,
            inspect_repository_target,
            create_repository_scan,
            get_repository_inventory,
            inspect_file_target,
            authorize_file_target,
            create_file_scan,
            get_file_analysis,
            preview_installed_applications,
            authorize_installed_applications,
            create_installed_application_scan,
            get_installed_application_inventory,
            get_installed_application,
            get_vulnerability_provider_status,
            refresh_public_vulnerability_data,
            preview_url_target,
            authorize_url_target,
            create_url_scan,
            get_url_scan_analysis,
            get_url_redirect_chain,
            get_url_security_headers,
            get_url_cookie_observations,
            get_url_reputation_status,
            create_synthetic_scan,
            get_scan,
            list_scans,
            get_scan_progress,
            cancel_scan,
            list_findings,
            get_finding,
            generate_report,
        ])
        .setup(move |app| {
            let config = app
                .config()
                .app
                .windows
                .iter()
                .find(|window| window.label == "main")
                .ok_or_else(|| std::io::Error::other("Foundation window configuration absent"))?;
            let builder = WebviewWindowBuilder::from_config(app, config)?;
            let builder = if let Some((width, height)) = native_qa_size {
                builder.inner_size(width, height)
            } else {
                builder
            };
            let window = builder
                .data_directory(webview_data)
                .devtools(false)
                .browser_extensions_enabled(false)
                .general_autofill_enabled(false)
                .on_navigation(allowed_navigation)
                .on_new_window(|_, _| tauri::webview::NewWindowResponse::Deny)
                .on_download(|_, _| false)
                .build()?;
            if native_qa_size.is_some() {
                let size = window.inner_size()?;
                println!(
                    "NATIVE_QA_VIEWPORT physical_width={} physical_height={} scale={}",
                    size.width,
                    size.height,
                    window.scale_factor()?
                );
            }
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
