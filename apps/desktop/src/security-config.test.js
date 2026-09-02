import { readFileSync } from "node:fs";
import { runInNewContext } from "node:vm";
import { describe, expect, it } from "vitest";

const read = (path) => readFileSync(new URL(path, import.meta.url), "utf8");
const config = JSON.parse(read("../src-tauri/tauri.conf.json"));
const capability = JSON.parse(read("../src-tauri/capabilities/main.json"));
const manifest = read("../src-tauri/build.rs");

describe("Tauri security configuration", () => {
  it("uses one local capability and explicitly manifests only foundation_status", () => {
    expect(config.app.security.capabilities).toEqual(["main"]);
    expect(capability.local).toBe(true);
    expect(capability.windows).toEqual(["main"]);
    expect(capability.webviews).toEqual(["main"]);
    expect(capability.remote).toBeUndefined();
    expect(capability.permissions).toEqual(["allow-foundation-status"]);
    expect(manifest).toContain('AppManifest::new().commands(&["foundation_status"])');
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
  it("allows only the fixed command and strips additional envelope options", () => {
    const hook = isolationHook();
    const output = hook({ cmd: "foundation_status", payload: {}, callback: 1, error: 2, options: { headers: { secret: "not-forwarded" } } });
    expect(output).toEqual({ cmd: "foundation_status", payload: {}, callback: 1, error: 2 });
  });

  it.each([
    null, [], {},
    { cmd: "plugin:shell|execute", payload: {}, callback: 1, error: 2 },
    { cmd: "foundation_status", payload: { path: "C:/" }, callback: 1, error: 2 },
    { cmd: "foundation_status", payload: [], callback: 1, error: 2 },
    { cmd: "foundation_status", payload: null, callback: 1, error: 2 },
    { cmd: "foundation_status", payload: {}, callback: "1", error: 2 },
    { cmd: "foundation_status", payload: {}, callback: 1, error: -1 },
  ])("rejects malformed or forbidden IPC %# before encryption", (message) => {
    expect(() => isolationHook()(message)).toThrow("IPC denied");
  });
});
