import { invoke } from "@tauri-apps/api/core";

export interface FoundationStatus {
  readonly core: "ready";
  readonly storage: "ready";
  readonly ipc: "restricted";
  readonly schema_version: 1;
}

const EXPECTED_KEYS = ["core", "ipc", "schema_version", "storage"];

export function parseFoundationStatus(value: unknown): FoundationStatus {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("Foundation response rejected");
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  if (keys.length !== EXPECTED_KEYS.length
    || keys.some((key, index) => key !== EXPECTED_KEYS[index])
    || record.core !== "ready" || record.storage !== "ready"
    || record.ipc !== "restricted" || record.schema_version !== 1) {
    throw new Error("Foundation response rejected");
  }
  return Object.freeze({ core: "ready", storage: "ready", ipc: "restricted", schema_version: 1 });
}

export async function readFoundationStatus(
  transport: () => Promise<unknown> = () => invoke("foundation_status"),
): Promise<FoundationStatus> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const result = await Promise.race([
      transport(),
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error("Foundation unavailable")), 8000);
      }),
    ]);
    return parseFoundationStatus(result);
  } finally {
    clearTimeout(timer);
  }
}
