"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ProxyClient = void 0;
const url_1 = require("url");
const egress_js_1 = require("./egress.js");
const assessment_js_1 = require("./assessment.js");
// Node.js native fetch doesn't have a global logger
const logger = {
    // stdout carries the MCP protocol; log lines go to stderr only.
    info: (m) => { process.stderr.write(`${m}\n`); },
    warn: (m) => { process.stderr.write(`${m}\n`); },
    error: (m) => { process.stderr.write(`${m}\n`); },
};
class ProxyClient {
    base_url;
    timeout; // in milliseconds
    hosted_url;
    api_key;
    _local_available; // optimistic; flips on network errors
    constructor(base_url, timeout = 10.0, // in seconds
    hosted_url, api_key) {
        this.base_url = base_url.endsWith("/") ? base_url.slice(0, -1) : base_url;
        this.timeout = timeout * 1000; // Convert to milliseconds for fetch AbortController
        this.hosted_url = (hosted_url || egress_js_1.HOSTED_API_URL).endsWith("/")
            ? (hosted_url || egress_js_1.HOSTED_API_URL).slice(0, -1)
            : (hosted_url || egress_js_1.HOSTED_API_URL);
        this.api_key = api_key || process.env.ARKHEIA_API_KEY;
        this._local_available = true; // optimistic; flips on ConnectError
    }
    async verify(prompt, response, model_id, session_id, options = {}) {
        /**
         * Detect fabrication in a model response.
         *
         * Tries local proxy first. If unavailable, falls back to hosted API,
         * unless allowHosted is false: then nothing is sent anywhere else.
         * Never raises -- returns NOT_ASSESSED (with a reason) on any error.
         */
        if (options.allowHosted === false) {
            // A verifier address that is (or cannot be told apart from) the hosted origin would route this path to the hosted service: refuse.
            if ((0, egress_js_1.isArkheiaHostedOrigin)(this.base_url, this.hosted_url)) {
                logger.warn("The verifier address is the hosted service; this response is local-only, so nothing was sent");
                return _unavailable("not_checked_local_verification_unavailable");
            }
            const local = await this._verify_local(prompt, response, model_id, session_id);
            if (local.error === "proxy_unavailable" || local.error === "proxy_timeout") {
                logger.warn("Local verification unavailable; this response is local-only, so nothing was sent to the hosted service");
                return _unavailable("not_checked_local_verification_unavailable");
            }
            return local;
        }
        // Try local proxy first (if last attempt didn't fail with ConnectError)
        if (this._local_available) {
            const result = await this._verify_local(prompt, response, model_id, session_id);
            if (result.error !== "proxy_unavailable" && result.error !== "proxy_timeout") {
                return result;
            }
            // Local proxy down -- fall through to hosted
            this._local_available = false;
            logger.info(`Local proxy unavailable, falling back to hosted API at ${(0, egress_js_1.displayOrigin)(this.hosted_url)}`);
        }
        // Fallback: hosted API
        if (this.api_key) {
            const result = await this._verify_hosted(prompt, response, model_id);
            if (result.error !== "hosted_unavailable") {
                return result;
            }
            // Hosted also failed -- try local once more in case it came back
            this._local_available = true; // Reset local availability for next call
        }
        // No hosted API key and local is down
        if (!this.api_key) {
            logger.warn("Local proxy unavailable and no ARKHEIA_API_KEY set for hosted fallback");
            return _unavailable("no_detection_available");
        }
        return _unavailable("all_detection_paths_failed");
    }
    async _verify_local(prompt, response, model_id, session_id) {
        /** POST /detect/verify on local Enterprise Proxy. */
        const payload = {
            prompt: prompt,
            response: response,
            model_id: model_id,
        };
        if (session_id) {
            payload["session_id"] = session_id;
        }
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.timeout);
        try {
            const resp = await fetch(`${this.base_url}/detect/verify`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify(payload),
                redirect: "error", // a redirect is never followed: the request goes only to the configured address
                signal: controller.signal,
            });
            clearTimeout(timeoutId);
            if (!resp.ok) {
                logger.error(`ProxyClient: /detect/verify HTTP error: ${resp.status} ${resp.statusText}`);
                return _unavailable(`proxy_http_error_${resp.status}`);
            }
            const raw = await resp.json();
            // A local proxy's verdict goes through the same fail-closed reading as the hosted one.
            return (0, assessment_js_1.applyAssessment)({ ...raw, source: raw?.source ?? "local" }, (0, assessment_js_1.assessmentFromDetector)(raw, "risk_level", model_id));
        }
        catch (e) {
            clearTimeout(timeoutId);
            if (e.name === 'AbortError') {
                logger.warn(`ProxyClient: /detect/verify timed out`);
                return _unavailable("proxy_timeout");
            }
            else if (e.name === 'TypeError' && e.message.includes('fetch failed')) { // Common for network errors like connection refused
                logger.warn(`ProxyClient: cannot connect to proxy at ${(0, egress_js_1.displayOrigin)(this.base_url)}`);
                return _unavailable("proxy_unavailable");
            }
            else {
                logger.error(`ProxyClient: /detect/verify failed: ${(0, egress_js_1.describeTransportError)(e).text}`);
                return _unavailable("proxy_error");
            }
        }
    }
    async _verify_hosted(prompt, response, model_id) {
        /** POST /v1/detect on hosted Arkheia API (arkheia-proxy-production.up.railway.app). */
        const payload = {
            model: model_id,
            response: response,
            prompt: prompt,
        };
        const headers = { "X-Arkheia-Key": this.api_key || "", "Content-Type": "application/json" };
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.timeout);
        try {
            const resp = await fetch(`${this.hosted_url}/v1/detect`, {
                method: "POST",
                headers: headers,
                body: JSON.stringify(payload),
                redirect: "error", // the key is never re-sent to wherever a redirect points
                signal: controller.signal,
            });
            clearTimeout(timeoutId);
            if (!resp.ok) {
                const status = resp.status;
                if (status === 401) {
                    logger.error("ProxyClient: hosted API rejected API key (401)");
                    return _unavailable("hosted_auth_failed");
                }
                if (status === 429) {
                    logger.warn("ProxyClient: hosted API rate/quota limit (429)");
                    return _unavailable("hosted_quota_exceeded");
                }
                logger.error(`ProxyClient: hosted /v1/detect HTTP error: ${status} ${resp.statusText}`);
                return _unavailable(`hosted_http_error_${status}`);
            }
            const data = await resp.json();
            // Map hosted response format to local format. The band is passed only when the service
            // says it assessed the response (Change A); otherwise NOT_ASSESSED with its reason.
            return (0, assessment_js_1.applyAssessment)({
                confidence: data?.confidence || 0.0,
                features_triggered: data?.features_triggered || [],
                detection_id: data?.detection_id,
                evidence_depth_limited: data?.evidence_depth_limited ?? true,
                source: "hosted",
            }, (0, assessment_js_1.assessmentFromDetector)(data, "risk", model_id));
        }
        catch (e) {
            clearTimeout(timeoutId);
            if (e.name === 'AbortError') {
                logger.warn(`ProxyClient: hosted /v1/detect timed out`);
                return _unavailable("hosted_timeout");
            }
            else if (e.name === 'TypeError' && e.message.includes('fetch failed')) {
                logger.warn(`ProxyClient: cannot connect to hosted API at ${(0, egress_js_1.displayOrigin)(this.hosted_url)}`);
                return _unavailable("hosted_unavailable");
            }
            else {
                logger.error(`ProxyClient: hosted /v1/detect failed: ${(0, egress_js_1.describeTransportError)(e).text}`);
                return _unavailable("hosted_error");
            }
        }
    }
    async get_audit_log(session_id, limit = 50, raw = false) {
        /**
         * GET /audit/log
         *
         * Returns audit log dict. Never raises -- returns empty log on any error.
         * Note: audit log is only available from local proxy, not hosted API.
         */
        const params = new url_1.URLSearchParams({ limit: String(Math.min(limit, 500)) });
        if (session_id) {
            params.append("session_id", session_id);
        }
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.timeout);
        try {
            const resp = await fetch(`${this.base_url}/audit/log?${params.toString()}`, {
                method: "GET",
                redirect: "error", // a redirect is never followed: the request goes only to the configured address
                signal: controller.signal,
            });
            clearTimeout(timeoutId);
            if (!resp.ok) {
                logger.error(`ProxyClient: /audit/log HTTP error: ${resp.status} ${resp.statusText}`);
                return _empty_log(`proxy_http_error_${resp.status}`);
            }
            // Every row is read the same way as a live verdict, including old rows with no
            // assessment fields, and the summary is counted from the normalised rows.
            const body = await resp.json();
            // raw: the stored records exactly as the service sent them, so their hashes verify.
            return (raw ? body : (0, assessment_js_1.normaliseAuditLog)(body));
        }
        catch (e) {
            clearTimeout(timeoutId);
            if (e.name === 'AbortError') {
                logger.warn("ProxyClient: /audit/log timed out");
                return _empty_log("proxy_timeout");
            }
            else if (e.name === 'TypeError' && e.message.includes('fetch failed')) {
                logger.warn(`ProxyClient: cannot connect to proxy at ${(0, egress_js_1.displayOrigin)(this.base_url)}`);
                return _empty_log("proxy_unavailable");
            }
            else {
                logger.error(`ProxyClient: /audit/log failed: ${(0, egress_js_1.describeTransportError)(e).text}`);
                return _empty_log("proxy_error");
            }
        }
    }
}
exports.ProxyClient = ProxyClient;
function _unavailable(error) {
    /** Detection was not reached (timeout, connection failure, HTTP error, no key): not assessed. */
    return {
        ...(0, assessment_js_1.notAssessed)("service_unavailable"),
        confidence: 0.0,
        error: error,
    };
}
function _empty_log(error) {
    return {
        events: [],
        summary: { LOW: 0, MEDIUM: 0, HIGH: 0, NOT_ASSESSED: 0, CANDIDATE_MEDIUM: 0, CANDIDATE_HIGH: 0 },
        error: error,
    };
}
