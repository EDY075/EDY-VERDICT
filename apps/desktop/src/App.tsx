import { useEffect, useState } from "react";
import { readFoundationStatus } from "./foundation";
import type { FoundationStatus } from "./foundation";

export function FoundationView({ status, failed }: {
  readonly status: FoundationStatus | null;
  readonly failed: boolean;
}) {
  return (
    <main aria-labelledby="title">
      <p className="eyebrow">Foundation Build</p>
      <h1 id="title">EDY VERDICT</h1>
      <p className="subtitle">Technical infrastructure only.</p>
      <section aria-label="Infrastructure status" aria-live="polite" aria-atomic="true">
        {status ? (
          <ul className="checks">
            <li><span className="dot" aria-hidden="true" />Core Ready</li>
            <li><span className="dot" aria-hidden="true" />Storage Ready</li>
            <li><span className="dot" aria-hidden="true" />IPC Restricted</li>
          </ul>
        ) : (
          <p role={failed ? "alert" : "status"}>
            {failed ? "Foundation unavailable. Readiness has not been established." : "Checking infrastructure…"}
          </p>
        )}
      </section>
      <footer>No scanning, providers, network requests or product verdicts.</footer>
    </main>
  );
}

export default function App() {
  const [status, setStatus] = useState<FoundationStatus | null>(null);
  const [failed, setFailed] = useState(false);
  useEffect(() => {
    let active = true;
    void readFoundationStatus().then(
      (result) => { if (active) setStatus(result); },
      () => { if (active) setFailed(true); },
    );
    return () => { active = false; };
  }, []);
  return <FoundationView status={status} failed={failed} />;
}
