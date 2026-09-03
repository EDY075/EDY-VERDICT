export const PRODUCT_NAME = "EDY VERDICT";
export const PRODUCT_VERSION = "1.0.0-rc.1";
export const SUPPORTED_OS = "Windows 10 Pro 22H2 (build 19045) or newer";
export const TAURI_PIN = "2.11.5";
export const TAURI_UPSTREAM_STATE = "WAITING_FOR_OFFICIAL_RELEASE";

export type Locale = "pt-BR" | "en";
export type Theme = "professional" | "neon" | "system";

const keys = {
  locale: "edy-verdict.locale",
  theme: "edy-verdict.theme",
  onboarding: "edy-verdict.onboarding-complete",
} as const;

function read<T extends string>(key: string, allowed: readonly T[], fallback: T): T {
  try {
    const value = globalThis.localStorage?.getItem(key) as T | null;
    return value !== null && allowed.includes(value) ? value : fallback;
  } catch {
    return fallback;
  }
}

export function loadLocale(): Locale {
  return read(keys.locale, ["pt-BR", "en"] as const, "pt-BR");
}

export function loadTheme(): Theme {
  return read(keys.theme, ["professional", "neon", "system"] as const, "system");
}

export function onboardingComplete(): boolean {
  try { return globalThis.localStorage?.getItem(keys.onboarding) === "true"; }
  catch { return false; }
}

export function savePreference(key: "locale" | "theme", value: Locale | Theme): void {
  try { globalThis.localStorage?.setItem(keys[key], value); } catch { /* Preference persistence is best effort. */ }
}

export function completeOnboarding(): void {
  try { globalThis.localStorage?.setItem(keys.onboarding, "true"); } catch { /* Non-blocking. */ }
}

export function resetOnboarding(): void {
  try { globalThis.localStorage?.removeItem(keys.onboarding); } catch { /* Non-blocking. */ }
}
