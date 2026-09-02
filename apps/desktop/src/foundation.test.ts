import { afterEach, describe, expect, it, vi } from "vitest";
import { parseFoundationStatus, readFoundationStatus } from "./foundation";

const READY = { core: "ready", storage: "ready", ipc: "restricted", schema_version: 1 };

afterEach(() => vi.useRealTimers());

describe("foundation IPC contract", () => {
  it("accepts only the exact infrastructure response and freezes it", () => {
    const status = parseFoundationStatus(READY);
    expect(status).toEqual(READY);
    expect(Object.isFrozen(status)).toBe(true);
  });

  it.each([
    null, [], "ready", {},
    { ...READY, core: "clean" },
    { ...READY, storage: "unavailable" },
    { ...READY, ipc: "open" },
    { ...READY, schema_version: 2 },
    { ...READY, secret: "must-not-be-forwarded" },
    { core: "ready", storage: "ready", ipc: "restricted" },
  ])("rejects unexpected response %#", (value) => {
    expect(() => parseFoundationStatus(value)).toThrow("Foundation response rejected");
  });

  it("calls its fixed transport once with no arguments", async () => {
    const transport = vi.fn().mockResolvedValue(READY);
    await expect(readFoundationStatus(transport)).resolves.toEqual(READY);
    expect(transport).toHaveBeenCalledExactlyOnceWith();
  });

  it("fails closed on an IPC failure", async () => {
    await expect(readFoundationStatus(() => Promise.reject(new Error("unavailable"))))
      .rejects.toThrow("unavailable");
  });

  it("times out instead of showing readiness if IPC hangs", async () => {
    vi.useFakeTimers();
    const assertion = expect(readFoundationStatus(() => new Promise(() => {})))
      .rejects.toThrow("Foundation unavailable");
    await vi.advanceTimersByTimeAsync(8000);
    await assertion;
    expect(vi.getTimerCount()).toBe(0);
  });
});
