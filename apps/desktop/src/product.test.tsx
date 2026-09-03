import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AboutPage, DiagnosticsPage, PrivacyPage, SettingsPage } from "./ProductPages";
import { completeOnboarding, loadLocale, loadTheme, PRODUCT_VERSION, savePreference } from "./product";
import { translateUiText } from "./i18n";

afterEach(() => vi.unstubAllGlobals());

describe("Level 7 product contract", () => {
  it("keeps the release candidate version identical in all user-facing surfaces", () => {
    expect(PRODUCT_VERSION).toBe("1.0.0-rc.1");
    const about=renderToStaticMarkup(<AboutPage locale="en"/>);
    const diagnostics=renderToStaticMarkup(<DiagnosticsPage locale="en" status={{core:"ready",storage:"ready",ipc:"restricted",schema_version:1}} engines={[]} providers={[]} scans={[]}/>);
    for(const output of [about,diagnostics]) expect(output).toContain(PRODUCT_VERSION);
  });

  it("renders complete product pages in both supported locales without remote content", () => {
    for(const locale of ["pt-BR","en"] as const){
      const settings=renderToStaticMarkup(<SettingsPage locale={locale} theme="system" onLocale={()=>{}} onTheme={()=>{}} onOpen={()=>{}} onResetOnboarding={()=>{}}/>);
      const privacy=renderToStaticMarkup(<PrivacyPage locale={locale}/>);
      const about=renderToStaticMarkup(<AboutPage locale={locale}/>);
      const content=settings+privacy+about;
      for(const forbidden of ["http://","https://","<script","password\""])expect(content).not.toContain(forbidden);
      expect(content).toContain(locale==="pt-BR"?"Telemetria: nenhuma":"Telemetry: none");
      expect(content).toContain("Windows 10 Pro 22H2");
      expect(content).toContain("WAITING_FOR_OFFICIAL_RELEASE");
    }
  });

  it("persists only allowlisted non-sensitive preferences", () => {
    const data=new Map<string,string>();
    vi.stubGlobal("localStorage",{getItem:(key:string)=>data.get(key)??null,setItem:(key:string,value:string)=>data.set(key,value)});
    savePreference("locale","en"); savePreference("theme","neon"); completeOnboarding();
    expect(loadLocale()).toBe("en"); expect(loadTheme()).toBe("neon");
    expect([...data.keys()].sort()).toEqual(["edy-verdict.locale","edy-verdict.onboarding-complete","edy-verdict.theme"]);
    expect(JSON.stringify([...data])).not.toMatch(/secret|token|password|api.?key/i);
  });

  it("localizes security-critical workflow wording without translating identifiers", () => {
    expect(translateUiText("No final security verdict was generated.","pt-BR")).toBe("Nenhum veredito final de segurança foi gerado.");
    expect(translateUiText("File Identity", "pt-BR")).toBe("Arquivo Identidade");
    expect(translateUiText("No final security verdict was generated.","en")).toBe("No final security verdict was generated.");
    expect(translateUiText("CVE-2099-0001", "pt-BR")).toBe("CVE-2099-0001");
  });
});
