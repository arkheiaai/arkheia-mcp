import { randomUUID } from 'crypto';
import { z } from 'zod';

// ---------------------------------------------------------------------------
// Customer feedback and reports.
//
// These tools tell the hosted Arkheia API that a piece of feedback or a report was
// typed in by the user (or by their agent). They send only the fields named in the
// tool schemas, and they return only whether the server stored it, and its id.
// Success is claimed only when the server acknowledged with an id. When the request may have
// reached the server but no clear answer came back, the outcome is reported as "unknown".
// ---------------------------------------------------------------------------

export const FEEDBACK_KINDS = [
    "bug", "false_alarm", "missed_problem", "feature_request", "praise", "other",
] as const;

export const REPORT_CATEGORIES = [
    "invented_api", "invented_file_or_path", "wrong_fact_or_number", "invented_source",
    "wrong_code_behaviour", "misread_context", "other",
] as const;

export const MESSAGE_MIN = 5;
export const MESSAGE_MAX = 2000;
export const EVIDENCE_MAX = 500;
export const EMAIL_MAX = 200;
export const TIMEOUT_MS = 10_000;

const ID_PATTERN = /^[A-Za-z0-9_-]{1,64}$/;
const UUID_PATTERN = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export const feedbackShape = {
    message: z.string().min(MESSAGE_MIN).max(MESSAGE_MAX),
    kind: z.enum(FEEDBACK_KINDS).optional(),
    email: z.string().max(EMAIL_MAX).optional(),
    submission_id: z.string().regex(UUID_PATTERN).optional(),
};

export const reportShape = {
    detection_id: z.string().regex(ID_PATTERN),
    outcome: z.enum(["wrong", "fine"]),
    evidence: z.string().max(EVIDENCE_MAX).optional(),
    category: z.enum(REPORT_CATEGORIES).optional(),
    reporter_kind: z.enum(["agent", "human"]).default("agent"),
};

export const reportsShape = {
    action: z.enum(["list", "delete"]),
    report_id: z.string().optional(),
    limit: z.number().int().min(1).max(100).default(20),
};

// ---------------------------------------------------------------------------
// Credential-shape check: a small, conservative pattern list. It refuses; it never
// edits the text, and it never echoes what it matched.
// ---------------------------------------------------------------------------

const CREDENTIAL_PATTERNS: RegExp[] = [
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

export function looksLikeCredential(text: string, own_key?: string): boolean {
    if (own_key && own_key.length >= 8 && text.includes(own_key)) return true;
    return CREDENTIAL_PATTERNS.some((p) => p.test(text));
}

// ---------------------------------------------------------------------------
// Results: three honest outcomes.
//   recorded: true       the service acknowledged it and returned this id
//   recorded: false      the service refused it, or the request provably never left
//   recorded: "unknown"  the request may have reached the service; it may have been stored
// No text from the service is ever passed into a result: messages are fixed per status class.
// ---------------------------------------------------------------------------

export type Outcome = {
    recorded: false | "unknown"; error: string; retryable: boolean;
    submission_id?: string; repeat_arguments?: string[]; already_reported?: boolean; conflict?: boolean;
};

function refused(what: string, reason: string, retryable: boolean, extra: Partial<Outcome> = {}): Outcome {
    const tail = retryable ? "It is safe to try again." : "Retrying the same request will not help.";
    return { recorded: false, error: `${what} was NOT recorded: ${reason} ${tail}`, retryable, ...extra };
}

function unknownOutcome(what: string, reason: string, advice: string, extra: Partial<Outcome> = {}): Outcome {
    return {
        recorded: "unknown", retryable: true, ...extra,
        error: `${what} may or may not have been recorded: ${reason} The request may have reached the service, ` +
            `so do not assume it was lost. ${advice}`,
    };
}

// Phase of one request, tracked explicitly:
//   "connecting": fetch() has not produced response headers. Only here can a failure mean "never sent",
//                 and only for a cause that provably happens before sending.
//   "headers":    response headers arrived, so the request WAS sent. A non-success status is a refusal
//                 whatever the body does; a body failure after a success status is unknown.
type Reply =
    | { ok: true; status: number; json: any }
    | { ok: false; kind: "unsent" }
    | { ok: false; kind: "maybe_sent"; why: "timeout" | "error" }
    | { ok: false; kind: "http"; status: number };

const UNSENT_CODES = new Set(["ECONNREFUSED", "ENOTFOUND", "EAI_AGAIN"]);

/** True only for failures that happen before any bytes can have been sent. */
function provablyUnsent(e: any): boolean {
    const code = e?.cause?.code ?? e?.code;
    return typeof code === "string" && UNSENT_CODES.has(code);
}

class Deadline extends Error { constructor() { super("deadline"); this.name = "Deadline"; } }

type PublicReport = {
    report_id: string; detection_id: string; outcome: string; category: string | null;
    evidence: string | null; reporter_kind: string; created_at: string | null;
};

/** One row of GET /v1/reports against the public shape; undefined if it does not fit. */
function validRow(x: any): PublicReport | undefined {
    if (!x || typeof x !== "object" || Array.isArray(x)) return undefined;
    const optStr = (v: any, max = 1000) => v === undefined || v === null || (typeof v === "string" && v.length <= max);
    if (typeof x.report_id !== "string" || !UUID_PATTERN.test(x.report_id)) return undefined;
    if (typeof x.event_id !== "string" || !ID_PATTERN.test(x.event_id)) return undefined;
    if (x.outcome !== "wrong" && x.outcome !== "fine") return undefined;
    if (x.reporter_kind !== "agent" && x.reporter_kind !== "human") return undefined;
    if (x.category !== undefined && x.category !== null && !(REPORT_CATEGORIES as readonly string[]).includes(x.category)) return undefined;
    if (!optStr(x.evidence, EVIDENCE_MAX) || !optStr(x.created_at, 64)) return undefined;
    return {
        report_id: x.report_id, detection_id: x.event_id, outcome: x.outcome,
        category: x.category ?? null, evidence: x.evidence ?? null,
        reporter_kind: x.reporter_kind, created_at: x.created_at ?? null,
    };
}

export class FeedbackClient {
    private hosted_url: string;
    private api_key: string | undefined;

    constructor(hosted_url: string, api_key: string | undefined, private timeout_ms: number = TIMEOUT_MS) {
        this.hosted_url = hosted_url.endsWith("/") ? hosted_url.slice(0, -1) : hosted_url;
        this.api_key = api_key;
    }

    /**
     * One request. The deadline covers the headers AND the body. A second attempt happens only when
     * a failure before any response headers has a provably-unsent cause, or, for a read-only request,
     * on any failure. Once headers have arrived the request was sent: a non-success status is returned
     * as that refusal without reading its body, and a failure reading a success body is "maybe_sent".
     */
    private async call(method: string, path: string, body?: unknown, idempotent = false): Promise<Reply> {
        let last: Reply = { ok: false, kind: "unsent" };
        for (let attempt = 0; attempt < 2; attempt++) {
            const controller = new AbortController();
            let timer: ReturnType<typeof setTimeout> | undefined;
            let phase: "connecting" | "headers" = "connecting";
            const deadline = new Promise<never>((_res, rej) => {
                timer = setTimeout(() => { controller.abort(); rej(new Deadline()); }, this.timeout_ms);
            });
            const work = (async (): Promise<Reply> => {
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
                phase = "headers";
                if (!resp.ok) {
                    try { await resp.body?.cancel(); } catch { /* the status is what matters */ }
                    return { ok: false, kind: "http", status: resp.status };
                }
                const text = await resp.text();
                let json: any = undefined;
                if (text) { try { json = JSON.parse(text); } catch { json = undefined; } }
                return { ok: true, status: resp.status, json };
            })();
            work.catch(() => { /* a lost race must not become an unhandled rejection */ });
            try {
                return await Promise.race([work, deadline]);
            } catch (e: any) {
                if (e instanceof Deadline) {
                    last = { ok: false, kind: "maybe_sent", why: "timeout" };
                    if (!idempotent) return last;
                } else if (phase === "connecting" && provablyUnsent(e)) {
                    last = { ok: false, kind: "unsent" };
                } else {
                    last = { ok: false, kind: "maybe_sent", why: "error" };
                    if (!idempotent) return last;
                }
            } finally {
                clearTimeout(timer);
                controller.abort(); // release the connection if the body is still open
            }
        }
        return last;
    }

    private precheck(what: string): Outcome | undefined {
        if (!this.api_key) {
            return refused(what, "ARKHEIA_API_KEY is not set.", false);
        }
        let scheme = "";
        let host = "";
        try { const u = new URL(this.hosted_url); scheme = u.protocol; host = u.hostname; } catch { /* below */ }
        const loopback = host === "localhost" || host === "127.0.0.1" || host === "[::1]";
        if (scheme !== "https:" && !(scheme === "http:" && loopback)) {
            return refused(what, "the configured Arkheia URL is not https, and the key is never sent in clear.", false);
        }
        return undefined;
    }

    /** Fixed wording per outcome class; nothing from the service's reply text is used. */
    private failure(what: string, r: Extract<Reply, { ok: false }>, advice: string, extra: Partial<Outcome> = {}): Outcome {
        if (r.kind === "unsent") {
            return refused(what, "could not reach the Arkheia service; nothing was sent.", true, extra);
        }
        if (r.kind === "maybe_sent") {
            return unknownOutcome(what, r.why === "timeout"
                ? "the Arkheia service did not answer in time."
                : "the connection failed or was cut after the request may have been sent.", advice, extra);
        }
        const s = r.status;
        if (s === 401 || s === 403) return refused(what, `the Arkheia API key was rejected (HTTP ${s}). Check ARKHEIA_API_KEY.`, false, extra);
        if (s === 429) return refused(what, "the service is rate limiting this key (HTTP 429). Wait a little first.", true, extra);
        if (s >= 500) return unknownOutcome(what, `the Arkheia service reported an error (HTTP ${s}).`, advice, extra);
        return refused(what, `the Arkheia service refused the request (HTTP ${s}).`, false, extra);
    }

    /** A success-class reply that is not the documented acknowledgement is not a confirmed write. */
    private badAck(what: string, status: number, expected: number, advice: string, extra: Partial<Outcome> = {}): Outcome {
        return unknownOutcome(what, status === expected
            ? "the service answered without a valid id, so receipt cannot be confirmed."
            : `the service answered HTTP ${status} instead of the expected ${expected}, so receipt cannot be confirmed.`,
            advice, extra);
    }

    private static uuidOf(json: any, field: string): string | undefined {
        const v = json?.[field];
        return typeof v === "string" && UUID_PATTERN.test(v) ? v : undefined;
    }

    private static readonly ACK = "The Arkheia service acknowledged it with this id. Quote the id if you follow up.";

    // -- arkheia_feedback ---------------------------------------------------

    async send_feedback(args: { message: string; kind?: string; email?: string; submission_id?: string }) {
        const what = "Your feedback";
        const { message, kind } = args;
        const email = args.email && args.email.trim() ? args.email.trim() : undefined;
        if (args.submission_id !== undefined && !UUID_PATTERN.test(args.submission_id)) {
            return refused(what, "submission_id must be a UUID, the one returned by an earlier attempt.", false);
        }
        if (message.trim().length < MESSAGE_MIN) {
            return refused(what, `the message must have at least ${MESSAGE_MIN} characters.`, false);
        }
        if (message.length > MESSAGE_MAX) {
            return refused(what, `the message must have at most ${MESSAGE_MAX} characters.`, false);
        }
        if (email && (email.length > EMAIL_MAX || !EMAIL_PATTERN.test(email))) {
            return refused(what, "the email address does not look valid. Leave it out or correct it.", false);
        }
        if (looksLikeCredential(message, this.api_key) || (email !== undefined && looksLikeCredential(email, this.api_key))) {
            return refused(what, "the text looks like it contains an API key or token. Remove it and send again.", false);
        }
        const early = this.precheck(what);
        if (early) return early;

        // The same submission_id on a later attempt lets a service that supports it recognise the
        // repeat; a service that does not know the field ignores it, and a repeat may then be stored twice.
        const submission_id = args.submission_id ?? randomUUID();
        const body: Record<string, string> = { message, submission_id };
        if (kind) body.context = kind;
        if (email) body.email = email;
        const repeat_arguments = ["message", ...(kind ? ["kind"] : []), ...(email ? ["email"] : [])];
        const advice = `To try again, call arkheia_feedback again with EVERY original argument (${repeat_arguments.join(", ")}) ` +
            `unchanged and this same submission_id (${submission_id}). A changed field under the same submission_id is refused. ` +
            "Whether a repeat is de-duplicated depends on the service.";
        const extra = { submission_id, repeat_arguments };

        const r = await this.call("POST", "/v1/feedback", body);
        if (!r.ok) {
            if (r.kind === "http" && r.status === 409) {
                return {
                    recorded: false as const, retryable: false, conflict: true, ...extra,
                    error: "A submission with this submission_id already exists with different content (message, kind or email). " +
                        "Nothing new was stored. To confirm the earlier one, repeat its original arguments exactly; " +
                        "to send a different message, call again without a submission_id.",
                };
            }
            return this.failure(what, r, advice, extra);
        }
        const id = r.status === 201 ? FeedbackClient.uuidOf(r.json, "feedback_id") : undefined;
        if (!id) return this.badAck(what, r.status, 201, advice, extra);
        return { recorded: true as const, feedback_id: id, submission_id, note: FeedbackClient.ACK };
    }

    // -- arkheia_report -----------------------------------------------------

    async send_report(args: {
        detection_id: string; outcome: "wrong" | "fine"; evidence?: string; category?: string;
        reporter_kind?: "agent" | "human";
    }) {
        const what = "Your report";
        if (!ID_PATTERN.test(args.detection_id)) {
            return refused(what, "detection_id is not a valid id. Use the detection_id from the arkheia_verify result.", false);
        }
        const evidence = args.evidence && args.evidence.trim() ? args.evidence : undefined;
        if (evidence !== undefined) {
            if (evidence.length > EVIDENCE_MAX) {
                return refused(what, `evidence must be one line of at most ${EVIDENCE_MAX} characters.`, false);
            }
            if (/[\r\n]/.test(evidence)) {
                return refused(what, "evidence must be a single line. Shorten it and send again.", false);
            }
            if (looksLikeCredential(evidence, this.api_key)) {
                return refused(what, "the evidence looks like it contains an API key or token. Remove it and send again.", false);
            }
        }
        const early = this.precheck(what);
        if (early) return early;

        const body: Record<string, string> = {
            outcome: args.outcome,
            reporter_kind: args.reporter_kind ?? "agent",
        };
        if (evidence) body.evidence = evidence;
        if (args.category) body.category = args.category;
        const advice = "Before sending it again, check with arkheia_reports (action: list).";

        const r = await this.call("POST", `/v1/detections/${encodeURIComponent(args.detection_id)}/report`, body);
        if (!r.ok) {
            if (r.kind === "http" && r.status === 409) {
                return {
                    recorded: false as const, retryable: false, already_reported: true,
                    error: "No new report was added because a report already exists for this detection. " +
                        "It may be the one from an earlier attempt of yours. See it with arkheia_reports (action: list).",
                };
            }
            if (r.kind === "http" && r.status === 404) {
                return refused(what, "the service has no detection with that id for your key. Check that detection_id came from an arkheia_verify result made with this key.", false);
            }
            return this.failure(what, r, advice);
        }
        const id = r.status === 201 ? FeedbackClient.uuidOf(r.json, "report_id") : undefined;
        if (!id) return this.badAck(what, r.status, 201, advice);
        return { recorded: true as const, report_id: id, note: FeedbackClient.ACK };
    }

    // -- arkheia_reports (list / delete your own reports) ---------------------

    async list_reports(limit: number = 20) {
        const what = "The report list";
        const wording = (o: Outcome): Outcome => ({ ...o, recorded: false, error: o.error.replace("was NOT recorded", "could not be fetched").replace("may or may not have been recorded", "could not be fetched") });
        const early = this.precheck(what);
        if (early) return wording(early);
        const n = Math.min(Math.max(Math.trunc(limit) || 20, 1), 100);
        const r = await this.call("GET", `/v1/reports?limit=${n}`, undefined, true);
        if (!r.ok) return wording(this.failure(what, r, "Try again."));
        const rows = Array.isArray(r.json?.reports) ? r.json.reports.map(validRow) : undefined;
        if (r.status !== 200 || !rows || rows.some((x: any) => x === undefined)) {
            return wording({
                recorded: false, retryable: true,
                error: "The report list was NOT recorded: the service reply was not in the expected shape. It is safe to try again.",
            });
        }
        return { ok: true as const, reports: rows as PublicReport[] };
    }

    async delete_report(report_id: string | undefined) {
        const what = "The report";
        if (!report_id || !UUID_PATTERN.test(report_id)) {
            return { deleted: false as const, error: "The report was NOT deleted: report_id is required and must be the report_id returned by arkheia_report or the list." };
        }
        const early = this.precheck(what);
        const wording = (o: Outcome) => ({
            deleted: (o.recorded === "unknown" ? "unknown" : false) as false | "unknown",
            error: o.error.replace("was NOT recorded", "was NOT deleted").replace("may or may not have been recorded", "may or may not have been deleted"),
        });
        if (early) return wording(early);
        const r = await this.call("DELETE", `/v1/reports/${encodeURIComponent(report_id)}`);
        const advice = "Check with arkheia_reports (action: list) before trying again.";
        if (!r.ok) {
            const w = wording(this.failure(what, r, advice));
            const extra = r.kind === "http" && r.status === 404
                ? " (No such report for your key, or it was already deleted.)" : "";
            return { ...w, error: w.error + extra };
        }
        if (r.status !== 204) {
            return wording(unknownOutcome(what, `the service answered HTTP ${r.status} instead of the expected 204.`, advice));
        }
        return { deleted: true as const, report_id };
    }
}
