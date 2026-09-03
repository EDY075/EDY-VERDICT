import {describe,expect,it,vi} from "vitest";
vi.mock("@tauri-apps/api/core",()=>({invoke:vi.fn()}));
import {parseManualSnapshot,remediationApi} from "./remediation-api";

describe("Level 6 response boundary",()=>{
  it("rejects arbitrary action identifiers and unexpected states",()=>{
    expect(()=>parseManualSnapshot({plan:{actions:[]},state:"fixed"})).toThrow();
  });
  it("exposes purpose-specific operations without generic write or patch",()=>{
    expect(Object.keys(remediationApi)).not.toContain("apply");
    expect(Object.keys(remediationApi)).not.toContain("rollback");
    expect(Object.keys(remediationApi)).not.toContain("writeFile");
    expect(Object.keys(remediationApi)).not.toContain("patchFile");
    expect(Object.keys(remediationApi)).not.toContain("executeCommand");
  });
});
