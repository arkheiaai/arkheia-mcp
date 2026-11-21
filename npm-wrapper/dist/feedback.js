"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.FeedbackClient = exports.reportsShape = exports.reportShape = exports.feedbackShape = exports.TIMEOUT_MS = exports.EMAIL_MAX = exports.EVIDENCE_MAX = exports.MESSAGE_MAX = exports.MESSAGE_MIN = exports.REPORT_CATEGORIES = exports.FEEDBACK_KINDS = void 0;
exports.looksLikeCredential = looksLikeCredential;
const crypto_1 = require("crypto");
const zod_1 = require("zod");
// ---------------------------------------------------------------------------
// Customer feedback and reports.
//
// These tools tell the hosted Arkheia API that a piece of feedback or a report was
// typed in by the user (or by their agent). They send only the fields named in the
// tool schemas, and they return only whether the server stored it, and its id.
// Success is claimed only when the server returned an id.
// ---------------------------------------------------------------------------
exports.FEEDBACK_KINDS = [
    "bug", "false_alarm", "missed_problem", "feature_request", "praise", "other",
];
exports.REPORT_CATEGORIES = [
    "invented_api", "invented_file_or_path", "wrong_fact_or_number", "invented_source",
    "wrong_code_behaviour", "misread_context", "other",
];
exports.MESSAGE_MIN = 5;
exports.MESSAGE_MAX = 2000;
exports.EVIDENCE_MAX = 500;
exports.EMAIL_MAX = 200;
exports.TIMEOUT_MS = 10_000;
const ID_PATTERN = /^[A-Za-z0-9_-]{1,64}$/;
const UUID_PATTERN = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
exports.feedbackShape = {
    message: zod_1.z.string().min(exports.MESSAGE_MIN).max(exports.MESSAGE_MAX),
    kind: zod_1.z.enum(exports.FEEDBACK_KINDS).optional(),
    email: zod_1.z.string().max(exports.EMAIL_MAX).optional(),
};
exports.reportShape = {
    detection_id: zod_1.z.string().regex(ID_PATTERN),
    outcome: zod_1.z.enum(["wrong", "fine"]),
    evidence: zod_1.z.string().max(exports.EVIDENCE_MAX).optional(),
    category: zod_1.z.enum(exports.REPORT_CATEGORIES).optional(),
    reporter_kind: zod_1.z.enum(["agent", "human"]).default("agent"),
};
exports.reportsShape = {
    action: zod_1.z.enum(["list", "delete"]),
    report_id: zod_1.z.string().optional(),
    limit: zod_1.z.number().int().min(1).max(100).default(20),
};
// ---------------------------------------------------------------------------
// Credential-shape check: a small, conservative pattern list. It refuses; it never
// edits the text, and it never echoes what it matched.
// ---------------------------------------------------------------------------
const CREDENTIAL_PATTERNS = [
    /\bak_(?:live|test)_[A-Za-z0-9_-]{8,}/,
    /\bbearer\s+[A-Za-z0-9._~+\/=-]{16,}/i,
    /\bsk-[A-Za-z0-9_-]{20,}/,
    /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}/,
    /\bgithub_pat_[A-Za-z0-9_]{30,}/,
    /\bxox[abprs]-[A-Za-z0-9-]{10,}/,
    /\bAKIA[0-9A-Z]{16}\b/,
    /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/,
    /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
];
function looksLikeCredential(text, own_key) {
    if (own_key && own_key.length >= 8 && text.includes(own_key))
        return true;
    return CREDENTIAL_PATTERNS.some((p) => p.test(text));
}
function notRecorded(what, reason, retryable) {
    const tail = retryable
        ? "It is safe to try again."
        : "Retrying the same request will not help.";
    return { recorded: false, error: `${what} was NOT recorded: ${reason} ${tail}`, retryable };
}
function serverDetail(json) {
    let d = json?.detail;
    if (d && typeof d === "object")
        d = d.message;
    if (typeof d !== "string")
        return undefined;
    return d.replace(/\s+/g, " ").slice(0, 200);
}
class FeedbackClient {
    timeout_ms;
    hosted_url;
    api_key;
    constructor(hosted_url, api_key, timeout_ms = exports.TIMEOUT_MS) {
        this.timeout_ms = timeout_ms;
        this.hosted_url = hosted_url.endsWith("/") ? hosted_url.slice(0, -1) : hosted_url;
        this.api_key = api_key;
    }
    /** One request, one retry at most, only when the network or the timeout failed. */
    async call(method, path, body) {
        let last = { ok: false, kind: "network" };
        for (let attempt = 0; attempt < 2; attempt++) {
            const controller = new AbortController();
            const timer = setTimeout(() => controller.abort(), this.timeout_ms);
            try {
                const resp = await fetch(`${this.hosted_url}${path}`, {
                    method,
                    headers: {
                        "X-Arkheia-Key": this.api_key || "",
                        ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
                    },
                    body: body !== undefined ? JSON.stringify(body) : undefined,
                    redirect: "error", // the key is never re-sent to wherever a redirect points
                    signal: controller.signal,
                });
                clearTimeout(timer);
                let json = undefined;
                const text = await resp.text().catch(() => "");
                if (text) {
                    try {
                        json = JSON.parse(text);
                    }
                    catch {
                        json = undefined;
                    }
                }
                if (!resp.ok) {
                    return { ok: false, kind: "http", status: resp.status, detail: serverDetail(json) };
                }
                return { ok: true, status: resp.status, json };
            }
            catch (e) {
                clearTimeout(timer);
                last = { ok: false, kind: e?.name === "AbortError" ? "timeout" : "network" };
                // fall through to the single retry, same body
            }
        }
        return last;
    }
    precheck(what) {
        if (!this.api_key) {
            return notRecorded(what, "ARKHEIA_API_KEY is not set.", false);
        }
        let scheme = "";
        let host = "";
        try {
            const u = new URL(this.hosted_url);
            scheme = u.protocol;
            host = u.hostname;
        }
        catch { /* below */ }
        const loopback = host === "localhost" || host === "127.0.0.1" || host === "[::1]";
        if (scheme !== "https:" && !(scheme === "http:" && loopback)) {
            return notRecorded(what, "the configured Arkheia URL is not https, and the key is never sent in clear.", false);
        }
        return undefined;
    }
    failure(what, r) {
        const via = (s) => s + (r.detail ? ` Server said: ${r.detail}` : "");
        switch (r.kind) {
            case "network":
                return notRecorded(what, "could not reach the Arkheia service.", true);
            case "timeout":
                return notRecorded(what, "the Arkheia service did not answer in time.", true);
            case "malformed":
                return {
                    recorded: false, retryable: true,
                    error: `${what} was NOT recorded: the service reply carried no id, so receipt cannot be confirmed. ` +
                        "Trying again may store it twice.",
                };
            default: {
                const s = r.status ?? 0;
                if (s === 401 || s === 403)
                    return notRecorded(what, `the Arkheia API key was rejected (HTTP ${s}). Check ARKHEIA_API_KEY.`, false);
                if (s === 429)
                    return notRecorded(what, "rate limited (HTTP 429). Wait a little first.", true);
                if (s >= 500)
                    return notRecorded(what, via(`the Arkheia service had an error (HTTP ${s}).`), true);
                return notRecorded(what, via(`the Arkheia service refused the request (HTTP ${s}).`), false);
            }
        }
    }
    static idOf(json, field) {
        const v = json?.[field];
        return typeof v === "string" && v.length > 0 && v.length <= 200 ? v : undefined;
    }
    // -- arkheia_feedback ---------------------------------------------------
    async send_feedback(args) {
        const what = "Your feedback";
        const { message, kind } = args;
        const email = args.email && args.email.trim() ? args.email.trim() : undefined;
        if (message.trim().length < exports.MESSAGE_MIN) {
            return notRecorded(what, `the message must have at least ${exports.MESSAGE_MIN} characters.`, false);
        }
        if (message.length > exports.MESSAGE_MAX) {
            return notRecorded(what, `the message must have at most ${exports.MESSAGE_MAX} characters.`, false);
        }
        if (email && (email.length > exports.EMAIL_MAX || !EMAIL_PATTERN.test(email))) {
            return notRecorded(what, "the email address does not look valid. Leave it out or correct it.", false);
        }
        if (looksLikeCredential(message, this.api_key) || (email !== undefined && looksLikeCredential(email, this.api_key))) {
            return notRecorded(what, "the text looks like it contains an API key or token. Remove it and send again.", false);
        }
        const early = this.precheck(what);
        if (early)
            return early;
        // submission_id lets a server that supports it treat the one retry as the same submission.
        // A server that does not know the field ignores it.
        const body = { message, submission_id: (0, crypto_1.randomUUID)() };
        if (kind)
            body.context = kind;
        if (email)
            body.email = email;
        const r = await this.call("POST", "/v1/feedback", body);
        if (!r.ok)
            return this.failure(what, r);
        const id = FeedbackClient.idOf(r.json, "feedback_id");
        if (!id)
            return this.failure(what, { ok: false, kind: "malformed" });
        return { recorded: true, feedback_id: id, note: "Recorded by the Arkheia service. Quote this id if you follow up." };
    }
    // -- arkheia_report -----------------------------------------------------
    async send_report(args) {
        const what = "Your report";
        if (!ID_PATTERN.test(args.detection_id)) {
            return notRecorded(what, "detection_id is not a valid id. Use the detection_id from the arkheia_verify result.", false);
        }
        const evidence = args.evidence && args.evidence.trim() ? args.evidence : undefined;
        if (evidence !== undefined) {
            if (evidence.length > exports.EVIDENCE_MAX) {
                return notRecorded(what, `evidence must be one line of at most ${exports.EVIDENCE_MAX} characters.`, false);
            }
            if (/[\r\n]/.test(evidence)) {
                return notRecorded(what, "evidence must be a single line. Shorten it and send again.", false);
            }
            if (looksLikeCredential(evidence, this.api_key)) {
                return notRecorded(what, "the evidence looks like it contains an API key or token. Remove it and send again.", false);
            }
        }
        const early = this.precheck(what);
        if (early)
            return early;
        const body = {
            outcome: args.outcome,
            reporter_kind: args.reporter_kind ?? "agent",
        };
        if (evidence)
            body.evidence = evidence;
        if (args.category)
            body.category = args.category;
        const r = await this.call("POST", `/v1/detections/${encodeURIComponent(args.detection_id)}/report`, body);
        if (!r.ok) {
            if (r.kind === "http" && r.status === 409) {
                return notRecorded(what, "this response already has a report. Delete it with arkheia_reports (action: delete) first to change your answer.", false);
            }
            if (r.kind === "http" && r.status === 404) {
                return notRecorded(what, "the service has no detection with that id for your key. Check that detection_id came from an arkheia_verify result made with this key.", false);
            }
            return this.failure(what, r);
        }
        const id = FeedbackClient.idOf(r.json, "report_id");
        if (!id)
            return this.failure(what, { ok: false, kind: "malformed" });
        return { recorded: true, report_id: id, note: "Recorded by the Arkheia service. Quote this id if you follow up." };
    }
    // -- arkheia_reports (list / delete your own reports) ---------------------
    async list_reports(limit = 20) {
        const what = "The report list";
        const early = this.precheck(what);
        if (early)
            return { ...early, error: early.error.replace("was NOT recorded", "could not be fetched") };
        const n = Math.min(Math.max(Math.trunc(limit) || 20, 1), 100);
        const r = await this.call("GET", `/v1/reports?limit=${n}`);
        if (!r.ok)
            return { ...this.failure(what, r), error: this.failure(what, r).error.replace("was NOT recorded", "could not be fetched") };
        if (!Array.isArray(r.json?.reports)) {
            return { recorded: false, retryable: true, error: "The report list could not be fetched: the service reply was not understood. It is safe to try again." };
        }
        // Only the caller's own report fields are passed on, and nothing else the server may add.
        const reports = r.json.reports.map((x) => ({
            report_id: x?.report_id, detection_id: x?.event_id, outcome: x?.outcome,
            category: x?.category ?? null, evidence: x?.evidence ?? null,
            reporter_kind: x?.reporter_kind, created_at: x?.created_at ?? null,
        }));
        return { ok: true, reports };
    }
    async delete_report(report_id) {
        const what = "The report";
        if (!report_id || !UUID_PATTERN.test(report_id)) {
            return { deleted: false, error: "The report was NOT deleted: report_id is required and must be the report_id returned by arkheia_report or the list." };
        }
        const early = this.precheck(what);
        if (early)
            return { deleted: false, error: early.error.replace("was NOT recorded", "was NOT deleted") };
        const r = await this.call("DELETE", `/v1/reports/${encodeURIComponent(report_id)}`);
        if (!r.ok) {
            const f = this.failure(what, r);
            const extra = r.kind === "http" && r.status === 404
                ? " (No such report for your key, or it was already deleted.)" : "";
            return { deleted: false, error: f.error.replace("was NOT recorded", "was NOT deleted") + extra };
        }
        return { deleted: true, report_id };
    }
}
exports.FeedbackClient = FeedbackClient;
