"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DEFAULT_VERIFIER_URL = exports.DEFAULT_OLLAMA_URL = exports.HOSTED_API_URL = void 0;
exports.isLoopbackOrigin = isLoopbackOrigin;
exports.displayHost = displayHost;
exports.isArkheiaHostedOrigin = isArkheiaHostedOrigin;
exports.computeEgress = computeEgress;
exports.applyEgress = applyEgress;
const tool_registry_js_1 = require("./tool-registry.js");
// The built-in hosted API address (the same one ProxyClient defaults to).
exports.HOSTED_API_URL = "https://arkheia-proxy-production.up.railway.app";
exports.DEFAULT_OLLAMA_URL = "http://localhost:11434";
exports.DEFAULT_VERIFIER_URL = "http://localhost:8098";
/** True only for http(s) addresses whose host is localhost, 127.0.0.0/8 or ::1 (any port, any case). */
function isLoopbackOrigin(value) {
    if (!value)
        return false;
    let u;
    try {
        u = new URL(value);
    }
    catch {
        return false;
    }
    if (u.protocol !== "http:" && u.protocol !== "https:")
        return false;
    const h = u.hostname.toLowerCase();
    if (h === "localhost" || h === "[::1]")
        return true;
    const m = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    return !!m && m[1] === "127" && m.slice(2).every((o) => Number(o) <= 255);
}
/** The origin only (host and port), never userinfo, path or query. */
function displayHost(value) {
    try {
        return new URL(value || "").host || "an address that is not valid";
    }
    catch {
        return "an address that is not valid";
    }
}
/**
 * True when the address is the Arkheia hosted service: the built-in hosted origin or the configured custom hosted
 * URL (origins compared parsed: host case-insensitive, default ports normalised). An address that cannot be parsed is
 * refused (returns true), so the local-only path never sends to something it cannot classify.
 */
function isArkheiaHostedOrigin(value, customHostedUrl) {
    let origin;
    try {
        origin = new URL(value || "").origin;
    }
    catch {
        return true;
    }
    if (origin === "null")
        return true;
    const hosted = [exports.HOSTED_API_URL, customHostedUrl].filter((x) => !!x);
    for (const h of hosted) {
        try {
            if (new URL(h).origin === origin)
                return true;
        }
        catch { /* an unparseable hosted setting cannot match */ }
    }
    return false;
}
function computeEgress(env) {
    const ollama = env.OLLAMA_BASE_URL || exports.DEFAULT_OLLAMA_URL;
    const verifier = env.ARKHEIA_PROXY_URL || exports.DEFAULT_VERIFIER_URL;
    const remote = [];
    if (!isLoopbackOrigin(ollama))
        remote.push(`Ollama at ${displayHost(ollama)}`);
    if (!isLoopbackOrigin(verifier))
        remote.push(`verifier at ${displayHost(verifier)}`);
    const run_ollama = remote.length === 0
        ? { network_egress: false, description: "Uses local addresses: calls the Ollama address and the verifier address configured here (both recognised local addresses). Never contacts the Arkheia hosted service. If the local verifier is unavailable the response is returned unchecked." }
        : { network_egress: true, description: `Calls the Ollama address and verifier address you configured (outside the recognised local addresses: ${remote.join(" and ")}). Never contacts the Arkheia hosted service.` };
    const audit = isLoopbackOrigin(verifier)
        ? { network_egress: false, description: "Retrieve structured audit evidence for compliance review. Reads the audit log from the verifier address configured here (a recognised local address)." }
        : { network_egress: true, description: `Retrieve structured audit evidence for compliance review. Reads the audit log from the verifier address you configured (outside the recognised local addresses: ${displayHost(verifier)}).` };
    return { run_ollama, arkheia_audit_log: audit };
}
/** Sets the registry's egress flags and descriptions from the actual configuration; returns them for the tool descriptions. */
function applyEgress(env) {
    const e = computeEgress(env);
    for (const k of ["run_ollama", "arkheia_audit_log"]) {
        tool_registry_js_1.REGISTRY[k].network_egress = e[k].network_egress;
        tool_registry_js_1.REGISTRY[k].description = e[k].description;
    }
    return e;
}
