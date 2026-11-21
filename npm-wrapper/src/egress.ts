import { REGISTRY } from './tool-registry.js';

export const DEFAULT_OLLAMA_URL = "http://localhost:11434";
export const DEFAULT_VERIFIER_URL = "http://localhost:8098";

/** True only for http(s) addresses whose host is localhost, 127.0.0.0/8 or ::1 (any port, any case). */
export function isLoopbackOrigin(value: string | undefined | null): boolean {
    if (!value) return false;
    let u: URL;
    try { u = new URL(value); } catch { return false; }
    if (u.protocol !== "http:" && u.protocol !== "https:") return false;
    const h = u.hostname.toLowerCase();
    if (h === "localhost" || h === "[::1]") return true;
    const m = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    return !!m && m[1] === "127" && m.slice(2).every((o) => Number(o) <= 255);
}

/** The origin only (host and port), never userinfo, path or query. */
export function displayHost(value: string | undefined | null): string {
    try { return new URL(value || "").host || "an address that is not valid"; } catch { return "an address that is not valid"; }
}

/** True when both addresses have the same origin (used to keep the local-only path away from the hosted service). */
export function sameOrigin(a: string | undefined | null, b: string | undefined | null): boolean {
    try { return new URL(a || "").origin === new URL(b || "").origin; } catch { return false; }
}

export type EgressInfo = { network_egress: boolean; description: string };

export function computeEgress(env: Record<string, string | undefined>): { run_ollama: EgressInfo; arkheia_audit_log: EgressInfo } {
    const ollama = env.OLLAMA_BASE_URL || DEFAULT_OLLAMA_URL;
    const verifier = env.ARKHEIA_PROXY_URL || DEFAULT_VERIFIER_URL;
    const remote: string[] = [];
    if (!isLoopbackOrigin(ollama)) remote.push(`Ollama at ${displayHost(ollama)}`);
    if (!isLoopbackOrigin(verifier)) remote.push(`verifier at ${displayHost(verifier)}`);

    const run_ollama: EgressInfo = remote.length === 0
        ? { network_egress: false, description: "Runs on this machine: calls the Ollama address and the local verifier address configured here (both on this machine). Never contacts the Arkheia hosted service. If the local verifier is unavailable the response is returned unchecked." }
        : { network_egress: true, description: `Calls the Ollama address and verifier address you configured (not on this machine: ${remote.join(" and ")}). Never contacts the Arkheia hosted service.` };

    const audit: EgressInfo = isLoopbackOrigin(verifier)
        ? { network_egress: false, description: "Retrieve structured audit evidence for compliance review. Runs on this machine: reads the audit log from the verifier address configured here (on this machine)." }
        : { network_egress: true, description: `Retrieve structured audit evidence for compliance review. Reads the audit log from the verifier address you configured (not on this machine: ${displayHost(verifier)}).` };
    return { run_ollama, arkheia_audit_log: audit };
}

/** Sets the registry's egress flags and descriptions from the actual configuration; returns them for the tool descriptions. */
export function applyEgress(env: Record<string, string | undefined>) {
    const e = computeEgress(env);
    for (const k of ["run_ollama", "arkheia_audit_log"] as const) {
        REGISTRY[k].network_egress = e[k].network_egress;
        REGISTRY[k].description = e[k].description;
    }
    return e;
}
