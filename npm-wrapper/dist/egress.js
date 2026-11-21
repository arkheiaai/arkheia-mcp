"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DEFAULT_VERIFIER_URL = exports.DEFAULT_OLLAMA_URL = void 0;
exports.isLoopbackOrigin = isLoopbackOrigin;
exports.displayHost = displayHost;
exports.sameOrigin = sameOrigin;
exports.computeEgress = computeEgress;
exports.applyEgress = applyEgress;
const tool_registry_js_1 = require("./tool-registry.js");
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
/** True when both addresses have the same origin (used to keep the local-only path away from the hosted service). */
function sameOrigin(a, b) {
    try {
        return new URL(a || "").origin === new URL(b || "").origin;
    }
    catch {
        return false;
    }
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
        ? { network_egress: false, description: "Runs on this machine: calls the Ollama address and the local verifier address configured here (both on this machine). Never contacts the Arkheia hosted service. If the local verifier is unavailable the response is returned unchecked." }
        : { network_egress: true, description: `Calls the Ollama address and verifier address you configured (not on this machine: ${remote.join(" and ")}). Never contacts the Arkheia hosted service.` };
    const audit = isLoopbackOrigin(verifier)
        ? { network_egress: false, description: "Retrieve structured audit evidence for compliance review. Runs on this machine: reads the audit log from the verifier address configured here (on this machine)." }
        : { network_egress: true, description: `Retrieve structured audit evidence for compliance review. Reads the audit log from the verifier address you configured (not on this machine: ${displayHost(verifier)}).` };
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
