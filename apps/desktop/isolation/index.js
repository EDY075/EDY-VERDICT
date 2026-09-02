// Intentionally dependency-free. Tauri inlines this local script at build time.
// Rejecting throws before encryption: the message never reaches Rust.
const UUID_V7 = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const ownKeys = (value, expected) => value !== null && typeof value === "object" && !Array.isArray(value)
  && Object.keys(value).sort().join("|") === [...expected].sort().join("|");
const idRequest = (payload, field) => ownKeys(payload, ["request"])
  && ownKeys(payload.request, [field]) && UUID_V7.test(payload.request[field]);
const validPayload = (cmd, payload) => {
  if (cmd === "get_foundation_status" || cmd === "get_engine_status") return ownKeys(payload, []);
  if (cmd === "create_synthetic_scan") return ownKeys(payload, ["request"])
    && ownKeys(payload.request, ["fixture_id"]) && payload.request.fixture_id === "synthetic-target-a";
  if (["get_scan", "get_scan_progress", "cancel_scan"].includes(cmd)) return idRequest(payload, "scan_id");
  if (cmd === "get_finding") return idRequest(payload, "finding_id");
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
