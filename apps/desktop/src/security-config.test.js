import { readFileSync } from "node:fs";
import { runInNewContext } from "node:vm";
import { describe, expect, it } from "vitest";

const read = (path) => readFileSync(new URL(path, import.meta.url), "utf8");
const config = JSON.parse(read("../src-tauri/tauri.conf.json"));
const capability = JSON.parse(read("../src-tauri/capabilities/main.json"));
const manifest = read("../src-tauri/build.rs");

const commands = [
  "get_foundation_status", "get_engine_status", "authorize_repository_target", "inspect_repository_target",
  "create_repository_scan", "get_repository_inventory", "inspect_file_target", "authorize_file_target",
  "create_file_scan", "get_file_analysis", "preview_installed_applications", "authorize_installed_applications", "create_installed_application_scan",
  "get_installed_application_inventory", "get_installed_application", "get_vulnerability_provider_status",
  "refresh_public_vulnerability_data", "preview_url_target", "authorize_url_target", "create_url_scan",
  "get_url_scan_analysis", "get_url_redirect_chain", "get_url_security_headers",
  "get_url_cookie_observations", "get_url_reputation_status", "create_synthetic_scan", "get_scan", "list_scans",
  "get_scan_progress", "cancel_scan", "list_findings", "get_finding", "generate_report",
  "run_level5_correlation", "cancel_level5_correlation", "list_investigation_clusters", "get_investigation_cluster",
  "list_investigation_cases", "get_investigation_case", "create_investigation_case",
  "update_investigation_case", "get_investigation_graph", "get_investigation_timeline",
  "generate_investigation_report",
  "list_remediation_candidates", "cancel_remediation_verification", "create_remediation_plan", "get_remediation_plan", "list_remediation_plans",
  "preview_remediation_action", "authorize_remediation_action",
  "get_remediation_action_status", "verify_remediation_action", "get_verification_result",
  "list_case_remediation_actions",
  "generate_remediation_report",
];

describe("Tauri security configuration", () => {
  it("keeps synthetic visual fixtures out of the production entrypoint", () => {
    expect(read("../index.html")).not.toContain("level2-visual");
    expect(read("./main.tsx")).not.toContain("level2-visual");
    expect(read("./App.tsx")).not.toContain("visualFixture");
    expect(read("../qa-level2.html")).toContain("level2-visual.fixture.tsx");
    expect(read("./level2-visual.fixture.tsx")).toContain("SYNTHETIC VISUAL QA ONLY");
  });
  it("uses one local capability and explicitly manifests only closed-set workflow commands", () => {
    expect(config.app.security.capabilities).toEqual(["main"]);
    expect(capability.local).toBe(true);
    expect(capability.windows).toEqual(["main"]);
    expect(capability.webviews).toEqual(["main"]);
    expect(capability.remote).toBeUndefined();
    expect(capability.permissions).toEqual(commands.map((command) => `allow-${command.replaceAll("_", "-")}`));
    for (const command of commands) expect(manifest).toContain(`"${command}"`);
  });

  it("keeps runtime content bundled, disables dangerous defaults and forbids plugins", () => {
    expect(config.build.devUrl).toBeUndefined();
    expect(config.build.frontendDist).toBe("../dist");
    expect(config.app.withGlobalTauri).toBe(false);
    expect(config.app.security.freezePrototype).toBe(true);
    expect(config.app.security.assetProtocol).toEqual({ enable: false, scope: [] });
    expect(config.app.security.dangerousDisableAssetCspModification).toBe(false);
    expect(config.app.security.pattern).toEqual({ use: "isolation", options: { dir: "../isolation" } });
    expect(config.app.windows).toHaveLength(1);
    expect(config.app.windows[0].devtools).toBe(false);
    expect(config.app.windows[0].create).toBe(false);
    expect(config.bundle.active).toBe(false);
    expect(config.plugins).toEqual({});
  });

  it("permits only local IPC and leaves the isolated frame scheme to Tauri injection", () => {
    const csp = config.app.security.csp;
    expect(csp["connect-src"]).toBe("ipc: http://ipc.localhost");
    expect(csp["default-src"]).toBe("'none'");
    expect(csp["media-src"]).toBe("'none'");
    expect(csp["frame-ancestors"]).toBe("'none'");
    expect(csp["frame-src"]).toBeUndefined();
    expect(csp["child-src"]).toBeUndefined();
    const serialized = JSON.stringify(csp);
    for (const forbidden of ["unsafe-inline", "unsafe-eval", "https:", "*", "data:", "blob:"]) {
      expect(serialized).not.toContain(forbidden);
    }
  });
});

function isolationHook() {
  const context = { window: {} };
  runInNewContext(read("../isolation/index.js"), context);
  return context.window.__TAURI_ISOLATION_HOOK__;
}

describe("dependency-free Isolation hook", () => {
  it("allows only closed Level 0 payloads and strips additional envelope options", () => {
    const hook = isolationHook();
    const empty = hook({ cmd: "get_foundation_status", payload: {}, callback: 1, error: 2, options: { headers: { secret: "not-forwarded" } } });
    expect(empty).toEqual({ cmd: "get_foundation_status", payload: {}, callback: 1, error: 2 });
    const scan = hook({ cmd: "get_scan", payload: { request: { scan_id: "018f4c2a-1d3b-7abc-8def-0123456789ab" } }, callback: 3, error: 4 });
    expect(scan.cmd).toBe("get_scan");
    expect(scan.payload.request.scan_id).toMatch(/-7/);
    const file = hook({ cmd: "authorize_file_target", payload: { request: { preview_id: "018f4c2a-1d3b-7abc-8def-0123456789ab", confirmed: true } }, callback: 5, error: 6 });
    expect(file.payload.request.preview_id).toBe("018f4c2a-1d3b-7abc-8def-0123456789ab");
    expect(hook({cmd:"preview_installed_applications",payload:{request:{include_system_components:false}},callback:7,error:8}).cmd).toBe("preview_installed_applications");
    expect(hook({cmd:"authorize_installed_applications",payload:{request:{preview_id:"018f4c2a-1d3b-7abc-8def-0123456789ab",confirmed:true}},callback:9,error:10}).cmd).toBe("authorize_installed_applications");
    expect(hook({cmd:"get_installed_application",payload:{request:{scan_id:"018f4c2a-1d3b-7abc-8def-0123456789ab",application_id:`appv1-${"a".repeat(32)}`}},callback:11,error:12}).cmd).toBe("get_installed_application");
    expect(hook({cmd:"preview_url_target",payload:{request:{url:"https://target.example/?token=secret",query_policy:"strip"}},callback:13,error:14}).cmd).toBe("preview_url_target");
    expect(hook({cmd:"authorize_url_target",payload:{request:{preview_id:"018f4c2a-1d3b-7abc-8def-0123456789ab",confirmed:true}},callback:15,error:16}).cmd).toBe("authorize_url_target");
    expect(hook({cmd:"run_level5_correlation",payload:{},callback:17,error:18}).cmd).toBe("run_level5_correlation");
    expect(hook({cmd:"cancel_level5_correlation",payload:{},callback:17,error:18}).cmd).toBe("cancel_level5_correlation");
    expect(hook({cmd:"list_investigation_cases",payload:{request:{run_id:"018f4c2a-1d3b-7abc-8def-0123456789ab",offset:0,limit:100}},callback:19,error:20}).cmd).toBe("list_investigation_cases");
    const action=`rma-v1-${"a".repeat(64)}`;
    expect(hook({cmd:"list_remediation_plans",payload:{request:{offset:0,limit:100}},callback:21,error:22}).cmd).toBe("list_remediation_plans");
    expect(hook({cmd:"preview_remediation_action",payload:{request:{action_id:action}},callback:23,error:24}).cmd).toBe("preview_remediation_action");
    expect(hook({cmd:"authorize_remediation_action",payload:{request:{action_id:action,plan_sha256:"b".repeat(64),confirmed:true}},callback:25,error:26}).cmd).toBe("authorize_remediation_action");
    expect(()=>hook({cmd:"apply_remediation_action",payload:{request:{action_id:action,authorization_token:"c".repeat(64)}},callback:27,error:28})).toThrow("IPC denied");
    expect(()=>hook({cmd:"rollback_remediation_action",payload:{request:{action_id:action}},callback:27,error:28})).toThrow("IPC denied");
  });

  it.each([
    null, [], {},
    { cmd: "plugin:shell|execute", payload: {}, callback: 1, error: 2 },
    { cmd: "get_foundation_status", payload: { path: "C:/" }, callback: 1, error: 2 },
    { cmd: "get_foundation_status", payload: [], callback: 1, error: 2 },
    { cmd: "get_foundation_status", payload: null, callback: 1, error: 2 },
    { cmd: "get_foundation_status", payload: {}, callback: "1", error: 2 },
    { cmd: "get_foundation_status", payload: {}, callback: 1, error: -1 },
    { cmd: "get_scan", payload: { request: { scan_id: "../../etc" } }, callback: 1, error: 2 },
    { cmd: "authorize_file_target", payload: { request: { path: "D:/fixture.bin", confirmed: false } }, callback: 1, error: 2 },
    { cmd: "inspect_file_target", payload: { request: { path: "D:/fixture.bin", extra: true } }, callback: 1, error: 2 },
    { cmd: "list_scans", payload: { request: { offset: 0, limit: 1000 } }, callback: 1, error: 2 },
    { cmd: "generate_report", payload: { request: { scan_id: "018f4c2a-1d3b-7abc-8def-0123456789ab", kind: "html" } }, callback: 1, error: 2 },
    { cmd: "preview_installed_applications", payload: { request: { include_system_components: "yes" } }, callback: 1, error: 2 },
    { cmd: "create_installed_application_scan", payload: { request: { authorization_id: "018f4c2a-1d3b-7abc-8def-0123456789ab", confirmed: false } }, callback: 1, error: 2 },
    { cmd: "get_installed_application", payload: { request: { scan_id: "018f4c2a-1d3b-7abc-8def-0123456789ab", application_id: "../../etc" } }, callback: 1, error: 2 },
    { cmd: "list_investigation_cases", payload: { request: { run_id: "../../etc", offset: 0, limit: 100 } }, callback: 1, error: 2 },
    { cmd: "create_investigation_case", payload: { request: { run_id: "018f4c2a-1d3b-7abc-8def-0123456789ab", item_id: "cluster-v1-unsafe" } }, callback: 1, error: 2 },
    { cmd: "apply_remediation_action", payload: { request: { action_id: `rma-v1-${"a".repeat(64)}`, authorization_token: "raw-token" } }, callback: 1, error: 2 },
    { cmd: "apply_remediation_action", payload: { request: { action_id: `rma-v1-${"a".repeat(64)}`, authorization_token: "b".repeat(64), path: "D:/arbitrary" } }, callback: 1, error: 2 },
    { cmd: "patch_file", payload: { request: { path: "D:/arbitrary", replacement: "owned" } }, callback: 1, error: 2 },
  ])("rejects malformed or forbidden IPC %# before encryption", (message) => {
    expect(() => isolationHook()(message)).toThrow("IPC denied");
  });
});
