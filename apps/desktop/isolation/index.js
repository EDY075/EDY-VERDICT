// Intentionally dependency-free. Tauri inlines this local script at build time.
// Rejecting throws before encryption: the message never reaches Rust.
const UUID_V7 = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const FINDING_ID = /^(?:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}|(?:yara_finding_v1|signature_finding_v1|pe_indicator_v1|reputation_finding_v1)-[0-9a-f]{64}|(?:iav1|webv1)-[0-9a-f]{32})$/;
const APPLICATION_ID = /^appv1-[0-9a-f]{32}$/;
const ownKeys = (value, expected) => value !== null && typeof value === "object" && !Array.isArray(value)
  && Object.keys(value).sort().join("|") === [...expected].sort().join("|");
const idRequest = (payload, field) => ownKeys(payload, ["request"])
  && ownKeys(payload.request, [field]) && UUID_V7.test(payload.request[field]);
const explicitPath = (value) => typeof value === "string" && value.length >= 3 && value.length <= 4096
  && !/[\u0000-\u001f\u007f]/u.test(value);
const validPayload = (cmd, payload) => {
  if (["get_foundation_status", "get_engine_status", "get_vulnerability_provider_status"].includes(cmd)) return ownKeys(payload, []);
  if (cmd === "create_synthetic_scan") return ownKeys(payload, ["request"])
    && ownKeys(payload.request, ["fixture_id"]) && payload.request.fixture_id === "synthetic-target-a";
  if (["get_scan", "get_scan_progress", "cancel_scan", "get_repository_inventory", "get_file_analysis", "get_installed_application_inventory", "get_url_scan_analysis", "get_url_redirect_chain", "get_url_security_headers", "get_url_cookie_observations", "get_url_reputation_status"].includes(cmd)) return idRequest(payload, "scan_id");
  if (["inspect_repository_target", "create_repository_scan", "create_file_scan"].includes(cmd)) return ownKeys(payload, ["request"])
    && ownKeys(payload.request, cmd.startsWith("create_") ? ["authorization_id", "confirmed"] : ["authorization_id"])
    && UUID_V7.test(payload.request.authorization_id)
    && (!cmd.startsWith("create_") || payload.request.confirmed === true);
  if (cmd === "authorize_repository_target" || cmd === "inspect_file_target") return ownKeys(payload, ["request"])
    && ownKeys(payload.request, ["path"]) && explicitPath(payload.request.path);
  if (cmd === "authorize_file_target") return ownKeys(payload, ["request"])
    && ownKeys(payload.request, ["preview_id", "confirmed"]) && UUID_V7.test(payload.request.preview_id)
    && payload.request.confirmed === true;
  if (cmd === "preview_installed_applications") return ownKeys(payload,["request"])
    && ownKeys(payload.request,["include_system_components"]) && typeof payload.request.include_system_components === "boolean";
  if (["authorize_installed_applications","create_installed_application_scan"].includes(cmd)) return ownKeys(payload,["request"])
    && ownKeys(payload.request,[cmd.startsWith("authorize_")?"preview_id":"authorization_id","confirmed"])
    && UUID_V7.test(payload.request[cmd.startsWith("authorize_")?"preview_id":"authorization_id"]) && payload.request.confirmed === true;
  if (cmd === "get_installed_application") return ownKeys(payload,["request"])
    && ownKeys(payload.request,["scan_id","application_id"]) && UUID_V7.test(payload.request.scan_id)
    && APPLICATION_ID.test(payload.request.application_id);
  if (cmd === "refresh_public_vulnerability_data") return ownKeys(payload,["request"])
    && ownKeys(payload.request,["confirmed"]) && payload.request.confirmed === true;
  if (cmd === "preview_url_target") return ownKeys(payload,["request"])
    && ownKeys(payload.request,["url","query_policy"])
    && typeof payload.request.url === "string" && payload.request.url.length >= 10 && payload.request.url.length <= 2048
    && !/[\u0000-\u001f\u007f\\]/u.test(payload.request.url)
    && ["send","strip"].includes(payload.request.query_policy);
  if (["authorize_url_target","create_url_scan"].includes(cmd)) return ownKeys(payload,["request"])
    && ownKeys(payload.request,[cmd === "authorize_url_target" ? "preview_id" : "authorization_id","confirmed"])
    && UUID_V7.test(payload.request[cmd === "authorize_url_target" ? "preview_id" : "authorization_id"])
    && payload.request.confirmed === true;
  if (cmd === "get_finding") return ownKeys(payload, ["request"])
    && ownKeys(payload.request, ["finding_id"]) && FINDING_ID.test(payload.request.finding_id);
  if (cmd === "list_scans") return ownKeys(payload, ["request"]) && ownKeys(payload.request, ["limit", "offset"])
    && Number.isSafeInteger(payload.request.offset) && payload.request.offset >= 0 && payload.request.offset <= 10000
    && Number.isSafeInteger(payload.request.limit) && payload.request.limit >= 1 && payload.request.limit <= 50;
  if (cmd === "list_findings") return ownKeys(payload, ["request"]) && ownKeys(payload.request, ["limit", "offset", "scan_id"])
    && UUID_V7.test(payload.request.scan_id) && Number.isSafeInteger(payload.request.offset)
    && payload.request.offset >= 0 && payload.request.offset <= 10000
    && Number.isSafeInteger(payload.request.limit) && payload.request.limit >= 1 && payload.request.limit <= 100;
  if (cmd === "generate_report") return ownKeys(payload, ["request"])
    && ownKeys(payload.request, ["kind", "scan_id"]) && UUID_V7.test(payload.request.scan_id)
    && ["executive", "technical", "developer"].includes(payload.request.kind);
  return false;
};

window.__TAURI_ISOLATION_HOOK__ = (message) => {
  if (message === null || typeof message !== "object" || Array.isArray(message)
    || typeof message.cmd !== "string" || !validPayload(message.cmd, message.payload)
    || !Number.isSafeInteger(message.callback) || message.callback < 0
    || !Number.isSafeInteger(message.error) || message.error < 0) {
    throw new Error("IPC denied");
  }
  // Do not forward user-supplied headers or alternate transports/options.
  return {
    cmd: message.cmd,
    payload: message.payload,
    callback: message.callback,
    error: message.error,
  };
};
