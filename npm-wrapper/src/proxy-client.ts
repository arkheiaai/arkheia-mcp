import { URLSearchParams } from 'url';

// Node.js native fetch doesn't have a global logger, use console
const logger = console;

// Hosted API defaults
const HOSTED_API_URL = "https://arkheia-proxy-production.up.railway.app";

type VerifyResult = {
    risk_level: string;
    confidence: number;
    features_triggered: string[];
    detection_id?: string;
    detection_method?: string;
    evidence_depth_limited?: boolean;
    source?: string;
    error?: string;
};

type AuditLogResult = {
    events: any[]; // Adjust based on actual event structure if known
    summary: { LOW: number; MEDIUM: number; HIGH: number; UNKNOWN: number };
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
    ): Promise<VerifyResult> {
        /**
         * Detect fabrication in a model response.
         *
         * Tries local proxy first. If unavailable, falls back to hosted API.
         * Never raises -- returns UNKNOWN on any error.
         */
        // Try local proxy first (if last attempt didn't fail with ConnectError)
        if (this._local_available) {
            const result = await this._verify_local(prompt, response, model_id, session_id);
            if (result.error !== "proxy_unavailable" && result.error !== "proxy_timeout") {
                return result;
            }
            // Local proxy down -- fall through to hosted
            this._local_available = false;
            logger.info(`Local proxy unavailable, falling back to hosted API at ${this.hosted_url}`);
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
                    signal: controller.signal,
                }
            );
            clearTimeout(timeoutId);

            if (!resp.ok) {
                logger.error(`ProxyClient: /detect/verify HTTP error: ${resp.status} ${resp.statusText}`);
                return _unavailable(`proxy_http_error_${resp.status}`);
            }
            return await resp.json() as VerifyResult;
        } catch (e: any) {
            clearTimeout(timeoutId);
            if (e.name === 'AbortError') {
                logger.warn(`ProxyClient: /detect/verify timed out for model=${model_id}`);
                return _unavailable("proxy_timeout");
            } else if (e.name === 'TypeError' && e.message.includes('fetch failed')) { // Common for network errors like connection refused
                logger.warn(`ProxyClient: cannot connect to proxy at ${this.base_url}`);
                return _unavailable("proxy_unavailable");
            } else {
                logger.error(`ProxyClient: /detect/verify unexpected error: ${e.message}`);
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
        const headers = { "X-Arkheia-Key": this.api_key || "" };

        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.timeout);

        try {
            const resp = await fetch(
                `${this.hosted_url}/v1/detect`,
                {
                    method: "POST",
                    headers: headers,
                    body: JSON.stringify(payload),
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
            const data = await resp.json();
            // Map hosted response format to local format
            return {
                risk_level: data.risk || "UNKNOWN",
                confidence: data.confidence || 0.0,
                features_triggered: data.features_triggered || [],
                detection_id: data.detection_id,
                detection_method: data.detection_method,
                evidence_depth_limited: data.evidence_depth_limited ?? true,
                source: "hosted",
            };
        } catch (e: any) {
            clearTimeout(timeoutId);
            if (e.name === 'AbortError') {
                logger.warn(`ProxyClient: hosted /v1/detect timed out for model=${model_id}`);
                return _unavailable("hosted_timeout");
            } else if (e.name === 'TypeError' && e.message.includes('fetch failed')) {
                logger.warn(`ProxyClient: cannot connect to hosted API at ${this.hosted_url}`);
                return _unavailable("hosted_unavailable");
            } else {
                logger.error(`ProxyClient: hosted /v1/detect unexpected error: ${e.message}`);
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
                    signal: controller.signal,
                }
            );
            clearTimeout(timeoutId);

            if (!resp.ok) {
                logger.error(`ProxyClient: /audit/log HTTP error: ${resp.status} ${resp.statusText}`);
                return _empty_log(`proxy_http_error_${resp.status}`);
            }
            return await resp.json() as AuditLogResult;
        } catch (e: any) {
            clearTimeout(timeoutId);
            if (e.name === 'AbortError') {
                logger.warn("ProxyClient: /audit/log timed out");
                return _empty_log("proxy_timeout");
            } else if (e.name === 'TypeError' && e.message.includes('fetch failed')) {
                logger.warn(`ProxyClient: cannot connect to proxy at ${this.base_url}`);
                return _empty_log("proxy_unavailable");
            } else {
                logger.error(`ProxyClient: /audit/log unexpected error: ${e.message}`);
                return _empty_log("proxy_error");
            }
        }
    }
}

function _unavailable(error: string): VerifyResult {
    /** Standard UNKNOWN response when detection is unreachable. */
    return {
        risk_level: "UNKNOWN",
        confidence: 0.0,
        features_triggered: [],
        error: error,
    };
}

function _empty_log(error: string): AuditLogResult {
    return {
        events: [],
        summary: { LOW: 0, MEDIUM: 0, HIGH: 0, UNKNOWN: 0 },
        error: error,
    };
}
