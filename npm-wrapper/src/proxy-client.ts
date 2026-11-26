import { URLSearchParams } from 'url';
import { isArkheiaHostedOrigin, displayOrigin, describeTransportError, HOSTED_API_URL } from './egress.js';
import { Reason, applyAssessment, assessmentFromDetector, normaliseAuditLog, notAssessed, safeMeta, safeSource } from './assessment.js';

// Node.js native fetch doesn't have a global logger
const logger = {
    // stdout carries the MCP protocol; log lines go to stderr only.
    info: (m: string) => { process.stderr.write(`${m}\n`); },
    warn: (m: string) => { process.stderr.write(`${m}\n`); },
    error: (m: string) => { process.stderr.write(`${m}\n`); },
};

// Hosted API defaults

// Release pack Change A: every result says whether it was assessed. risk_level is LOW, MEDIUM or
// HIGH only when assessed is true; otherwise it is NOT_ASSESSED and not_assessed_reason says why.
type VerifyResult = {
    risk_level: string;
    assessed: boolean;
    not_assessed_reason?: Reason;
    candidate_alert?: "MEDIUM" | "HIGH";
    confidence?: number;
    detection_id?: string;
    source?: string;
    error?: string;
};

type AuditLogResult = {
    events: any[]; // Adjust based on actual event structure if known
    summary: Record<string, number>;
    error?: string;
};

export class ProxyClient {
    private base_url: string;
    private timeout: number; // in milliseconds
    private hosted_url: string;
    private api_key: string | undefined;
    private _local_available: boolean; // optimistic; flips on network errors

    constructor(
        base_url: string,
        timeout: number = 10.0, // in seconds
        hosted_url?: string,
        api_key?: string,
    ) {
        this.base_url = base_url.endsWith("/") ? base_url.slice(0, -1) : base_url;
        this.timeout = timeout * 1000; // Convert to milliseconds for fetch AbortController
        this.hosted_url = (hosted_url || HOSTED_API_URL).endsWith("/")
            ? (hosted_url || HOSTED_API_URL).slice(0, -1)
            : (hosted_url || HOSTED_API_URL);
        this.api_key = api_key || process.env.ARKHEIA_API_KEY;
        this._local_available = true; // optimistic; flips on ConnectError
    }

    async verify(
        prompt: string,
        response: string,
        model_id: string,
        session_id?: string,
        options: { allowHosted?: boolean } = {},
    ): Promise<VerifyResult> {
        /**
         * Detect fabrication in a model response.
         *
         * Tries local proxy first. If unavailable, falls back to hosted API,
         * unless allowHosted is false: then nothing is sent anywhere else.
         * Never raises -- returns NOT_ASSESSED (with a reason) on any error.
         */
        if (options.allowHosted === false) {
            // A verifier address that is (or cannot be told apart from) the hosted origin would route this path to the hosted service: refuse.
            if (isArkheiaHostedOrigin(this.base_url, this.hosted_url)) {
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
            logger.info(`Local proxy unavailable, falling back to hosted API at ${displayOrigin(this.hosted_url)}`);
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

    private async _verify_local(
        prompt: string,
        response: string,
        model_id: string,
        session_id?: string,
    ): Promise<VerifyResult> {
        /** POST /detect/verify on local Enterprise Proxy. */
        const payload: Record<string, any> = {
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
            const resp = await fetch(
                `${this.base_url}/detect/verify`,
                {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                    },
                    body: JSON.stringify(payload),
                    redirect: "error", // a redirect is never followed: the request goes only to the configured address
                    signal: controller.signal,
                }
            );
            clearTimeout(timeoutId);

            if (!resp.ok) {
                logger.error(`ProxyClient: /detect/verify HTTP error: ${resp.status} ${resp.statusText}`);
                return _unavailable(`proxy_http_error_${resp.status}`);
            }
            const raw: any = await resp.json();
            // A local proxy's verdict goes through the same fail-closed reading as the hosted one.
            return applyAssessment({
                ...safeMeta(raw),
                ...(raw?.error !== undefined && raw?.error !== null ? { error: "service_error" } : {}),
                source: safeSource(raw?.source),
            },
                                   assessmentFromDetector(raw, "risk_level", model_id)) as VerifyResult;
        } catch (e: any) {
            clearTimeout(timeoutId);
            if (e.name === 'AbortError') {
                logger.warn(`ProxyClient: /detect/verify timed out`);
                return _unavailable("proxy_timeout");
            } else if (e.name === 'TypeError' && e.message.includes('fetch failed')) { // Common for network errors like connection refused
                logger.warn(`ProxyClient: cannot connect to proxy at ${displayOrigin(this.base_url)}`);
                return _unavailable("proxy_unavailable");
            } else {
                logger.error(`ProxyClient: /detect/verify failed: ${describeTransportError(e).text}`);
                return _unavailable("proxy_error");
            }
        }
    }

    private async _verify_hosted(
        prompt: string,
        response: string,
        model_id: string,
    ): Promise<VerifyResult> {
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
            const resp = await fetch(
                `${this.hosted_url}/v1/detect`,
                {
                    method: "POST",
                    headers: headers,
                    body: JSON.stringify(payload),
                    redirect: "error", // the key is never re-sent to wherever a redirect points
                    signal: controller.signal,
                }
            );
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
            const data: any = await resp.json();
            // Map hosted response format to local format. The band is passed only when the service
            // says it assessed the response (Change A); otherwise NOT_ASSESSED with its reason.
            return applyAssessment({
                ...safeMeta(data),
                source: "hosted",
            }, assessmentFromDetector(data, "risk", model_id)) as VerifyResult;
        } catch (e: any) {
            clearTimeout(timeoutId);
            if (e.name === 'AbortError') {
                logger.warn(`ProxyClient: hosted /v1/detect timed out`);
                return _unavailable("hosted_timeout");
            } else if (e.name === 'TypeError' && e.message.includes('fetch failed')) {
                logger.warn(`ProxyClient: cannot connect to hosted API at ${displayOrigin(this.hosted_url)}`);
                return _unavailable("hosted_unavailable");
            } else {
                logger.error(`ProxyClient: hosted /v1/detect failed: ${describeTransportError(e).text}`);
                return _unavailable("hosted_error");
            }
        }
    }

    async get_audit_log(
        session_id?: string,
        limit: number = 50,
    ): Promise<AuditLogResult> {
        /**
         * GET /audit/log
         *
         * Returns audit log dict. Never raises -- returns empty log on any error.
         * Note: audit log is only available from local proxy, not hosted API.
         */
        const params = new URLSearchParams({ limit: String(Math.min(limit, 500)) });
        if (session_id) {
            params.append("session_id", session_id);
        }

        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.timeout);

        try {
            const resp = await fetch(
                `${this.base_url}/audit/log?${params.toString()}`,
                {
                    method: "GET",
                    redirect: "error", // a redirect is never followed: the request goes only to the configured address
                    signal: controller.signal,
                }
            );
            clearTimeout(timeoutId);

            if (!resp.ok) {
                logger.error(`ProxyClient: /audit/log HTTP error: ${resp.status} ${resp.statusText}`);
                return _empty_log(`proxy_http_error_${resp.status}`);
            }
            const body: any = await resp.json();
            return normaliseAuditLog(body) as AuditLogResult;
        } catch (e: any) {
            clearTimeout(timeoutId);
            if (e.name === 'AbortError') {
                logger.warn("ProxyClient: /audit/log timed out");
                return _empty_log("proxy_timeout");
            } else if (e.name === 'TypeError' && e.message.includes('fetch failed')) {
                logger.warn(`ProxyClient: cannot connect to proxy at ${displayOrigin(this.base_url)}`);
                return _empty_log("proxy_unavailable");
            } else {
                logger.error(`ProxyClient: /audit/log failed: ${describeTransportError(e).text}`);
                return _empty_log("proxy_error");
            }
        }
    }
}

function _unavailable(error: string): VerifyResult {
    /** Detection was not reached (timeout, connection failure, HTTP error, no key): not assessed. */
    return {
        ...notAssessed("service_unavailable"),
        confidence: 0.0,
        error: error,
    };
}

function _empty_log(error: string): AuditLogResult {
    return {
        events: [],
        summary: { LOW: 0, MEDIUM: 0, HIGH: 0, NOT_ASSESSED: 0, CANDIDATE_MEDIUM: 0, CANDIDATE_HIGH: 0 },
        error: error,
    };
}
