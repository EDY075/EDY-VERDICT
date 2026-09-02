// Intentionally dependency-free. Tauri inlines this local script at build time.
// Rejecting throws before encryption: the message never reaches Rust.
window.__TAURI_ISOLATION_HOOK__ = (message) => {
  if (message === null || typeof message !== "object" || Array.isArray(message)
    || message.cmd !== "foundation_status"
    || message.payload === null || typeof message.payload !== "object"
    || Array.isArray(message.payload) || Object.keys(message.payload).length !== 0
    || !Number.isSafeInteger(message.callback) || message.callback < 0
    || !Number.isSafeInteger(message.error) || message.error < 0) {
    throw new Error("IPC denied");
  }
  // Do not forward user-supplied headers or alternate transports/options.
  return {
    cmd: "foundation_status",
    payload: {},
    callback: message.callback,
    error: message.error,
  };
};
