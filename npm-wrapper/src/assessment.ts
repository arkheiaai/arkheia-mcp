/**
 * An unscored check never reads as LOW. A band is passed on only when the service says it
 * assessed the response and nothing in the answer contradicts that; anything else is
 * NOT_ASSESSED, and the word LOW appears nowhere in it.
 */

import { createHash } from "node:crypto";

export const ASSESSED_BANDS = ["LOW", "MEDIUM", "HIGH"] as const;
export const CLIENT_REASONS = [
    "screening_disabled", "provider_error", "incomplete_response", "service_unavailable", "unknown",
] as const;
/** The whole vocabulary a result may carry. Nothing else is ever produced. */
export const ALL_REASONS = [
    "not_assessed", "service_unavailable", "incomplete_response", "provider_error",
    "screening_disabled", "unknown",
] as const;

export type Reason = typeof ALL_REASONS[number];
export const NOT_ASSESSED = "NOT_ASSESSED";

const CANDIDATE_LEVELS = ["MEDIUM", "HIGH"];

export type Assessment = {
    risk_level: string;
    assessed: boolean;
    not_assessed_reason?: Reason;
    candidate_alert?: "MEDIUM" | "HIGH";
};

function isBand(v: unknown): v is typeof ASSESSED_BANDS[number] {
    return typeof v === "string" && (ASSESSED_BANDS as readonly string[]).includes(v);
}

const absent = (v: unknown) => v === null || v === undefined;

function serviceCandidate(raw: any, band: unknown): "MEDIUM" | "HIGH" | null | "invalid" {
    const candidate = raw?.candidate_alert;
    if (absent(candidate)) return null;
    if (!CANDIDATE_LEVELS.includes(candidate)) return "invalid";
    if (!candidateFitsBand(raw, band)) return "invalid";
    const level = absent(raw?.risk_demoted_from) ? band : raw.risk_demoted_from;
    return candidate === level ? candidate : "invalid";
}

const RANK: Record<string, number> = { LOW: 1, MEDIUM: 2, HIGH: 3 };
const rankOf = (v: unknown): number | undefined =>
    typeof v === "string" && Object.prototype.hasOwnProperty.call(RANK, v) ? RANK[v] : undefined;

const ID_PATTERN = /^[A-Za-z0-9_.:-]{1,100}$/;
const SOURCES = ["proxy", "local"];

/** The only non-verdict fields a result may carry, each validated, with a fixed fallback. */
export function safeMeta(raw: any): { confidence: number; detection_id?: string } {
    const c = raw?.confidence;
    const confidence = typeof c === "number" && Number.isFinite(c) && c >= 0 && c <= 1 ? c : 0.0;
    const id = raw?.detection_id;
    return { confidence, ...(typeof id === "string" && ID_PATTERN.test(id) ? { detection_id: id } : {}) };
}
const MODEL_PATTERN = /^[A-Za-z0-9_.:/@+-]{1,100}$/;
const TIME_PATTERN = /^[0-9TZ:.+ -]{1,40}$/;
const safeId = (v: unknown): string | undefined => (typeof v === "string" && ID_PATTERN.test(v) ? v : undefined);
const safeModel = (v: unknown): string | undefined => (typeof v === "string" && MODEL_PATTERN.test(v) ? v : undefined);
const safeTime = (v: unknown): string | number | undefined =>
    typeof v === "number" ? (Number.isSafeInteger(v) ? v : undefined) : (typeof v === "string" && TIME_PATTERN.test(v) ? v : undefined);
export const safeSource = (v: unknown): string => (typeof v === "string" && SOURCES.includes(v) ? v : "local");

function candidateFitsBand(raw: any, band: unknown): boolean {
    if (absent(raw?.risk_demoted_from)) return true;
    const from = rankOf(raw.risk_demoted_from);
    const to = rankOf(band);
    return from !== undefined && to !== undefined && to >= 2 && from === to + 1;
}

const sameModel = (a: unknown, b: unknown) =>
    typeof a === "string" && typeof b === "string" && a.trim().toLowerCase() === b.trim().toLowerCase();

function localContradiction(raw: any, requestedModel?: string): boolean {
    if (!absent(raw?.gate_reason)) return true;
    if (!absent(raw?.error)) return true;
    for (const key of ["profile_model_id", "model_id", "model"]) {
        if (raw && key in raw && !(typeof raw[key] === "string" && raw[key].trim())) return true;
    }
    const ids = [raw?.model_id, raw?.model, raw?.profile_model_id].filter((v) => typeof v === "string");
    if (ids.some((v) => !sameModel(v, ids[0]))) return true;
    if (requestedModel !== undefined) {
        for (const named of [raw?.model_id, raw?.model, raw?.profile_model_id]) {
            if (typeof named === "string" && !sameModel(named, requestedModel)) return true;
        }
    }
    return false;
}

export function assessmentFromDetector(raw: any, bandField: "risk" | "risk_level", requestedModel?: string): Assessment {
    const band = raw?.[bandField];
    const assessed = raw?.assessed;
    const reason = raw?.not_assessed_reason;

    if (assessed === true) {
        const consistent = isBand(band)
            && raw?.evidence_depth_limited === false
            && (absent(raw?.profile_fingerprint_borrowed) || raw.profile_fingerprint_borrowed === false)
            && (raw?.model_supported === undefined || raw.model_supported === true)
            && !localContradiction(raw, requestedModel)
            && absent(raw?.risk_demoted_from)
            && absent(reason)
            && absent(raw?.candidate_alert);
        if (consistent) return { risk_level: band, assessed: true };
        return notAssessed("unknown");
    }
    const candidate = serviceCandidate(raw, band);
    if (candidate === "invalid") return notAssessed("unknown");
    if (assessed === false && typeof reason === "string" && reason.trim()) {
        return notAssessed("not_assessed", candidate ?? undefined);
    }
    return notAssessed("unknown", candidate ?? undefined);
}

export function notAssessed(reason: Reason, candidate?: "MEDIUM" | "HIGH"): Assessment {
    return {
        risk_level: NOT_ASSESSED,
        assessed: false,
        not_assessed_reason: reason,
        ...(candidate ? { candidate_alert: candidate } : {}),
    };
}

/**
 * Build the caller-facing result from any verdict-shaped object, keeping the non-verdict fields
 * (detection_id, source, confidence, error) and replacing every verdict field with the
 * normalised assessment.
 */
export function applyAssessment<T extends Record<string, any>>(base: T, a: Assessment): Record<string, any> {
    const { risk, risk_level, assessed, not_assessed_reason, candidate_alert, ...rest } = base;
    void risk; void risk_level; void assessed; void not_assessed_reason; void candidate_alert;
    return { ...rest, ...a };
}

/** The provider's own finish state, from each provider's documented field. */
export type FinishState = "complete" | "incomplete" | "unknown";

export function finishFromOpenAICompatible(data: any): FinishState {
    const r = data?.choices?.[0]?.finish_reason;
    if (r === "stop") return "complete";
    if (typeof r === "string") return "incomplete";
    return "unknown";
}

export function finishFromGemini(data: any): FinishState {
    const r = data?.candidates?.[0]?.finishReason;
    if (r === "STOP") return "complete";
    if (typeof r === "string") return "incomplete";
    return "unknown";
}

export function finishFromOllama(data: any): FinishState {
    // Complete only when Ollama says both: done is the boolean true AND it stopped normally.
    if (data?.done === true && data?.done_reason === "stop") return "complete";
    if (data?.done === false || (data?.done === true && typeof data?.done_reason === "string")) return "incomplete";
    return "unknown";
}

const DETECTION_SOURCES = ["proxy", "passthrough", "interception"];

/** What an audit row records, by the service's own label when it sends one. */
const RECORD_KINDS = ["detection", "refusal", "delivery_receipt", "operational"];

export function auditRecordKind(e: any): string {
    const refused = e?.action_taken === "refused" || e?.action_taken === "refuse" || e?.risk_level === "REFUSED"
        || e?.event_type === "passthrough.forward_refused";
    if (refused) return "refusal";
    if (typeof e?.record_kind === "string" && RECORD_KINDS.includes(e.record_kind)) return e.record_kind;
    if (e?.source === "governance_push" || e?.event_type === "governance_detection_push") return "delivery_receipt";
    if (DETECTION_SOURCES.includes(e?.source)) return "detection";
    return "operational";
}


function assessmentFromService(e: any): Assessment {
    if (!("assessment" in e)) return assessmentFromDetector(e, "risk_level");
    const a = e.assessment;
    if (a === null || typeof a !== "object" || Array.isArray(a)) return notAssessed("unknown");
    const band = e.risk_level;
    if ("assessed" in e && e.assessed !== a.assessed) return notAssessed("unknown");
    if (a.assessed === true) {
        if (!absent(e.not_assessed_reason) || !absent(e.candidate_alert)) return notAssessed("unknown");
        const { assessment: _a, record_kind: _k, read_time_fields: _r, ...facts } = e;
        void _a; void _k; void _r;
        return assessmentFromDetector({ ...facts, assessed: true, not_assessed_reason: a.not_assessed_reason,
                                        candidate_alert: a.candidate_alert }, "risk_level");
    }
    if (a.assessed === false && typeof a.not_assessed_reason === "string" && a.not_assessed_reason.trim()) {
        const candidate = serviceCandidate({ candidate_alert: a.candidate_alert, risk_demoted_from: e.risk_demoted_from }, band);
        if (candidate === "invalid") return notAssessed("unknown");
        return notAssessed("not_assessed", candidate ?? undefined);
    }
    return notAssessed("unknown");
}


export function canonical(v: any): string {
    if (Array.isArray(v)) return `[${v.map(canonical).join(",")}]`;
    if (v !== null && typeof v === "object") {
        return `{${Object.keys(v).sort().map((k) => `${canonical(k)}:${canonical(v[k])}`).join(",")}}`;
    }
    // Non-ASCII is written as lower-case \uXXXX so every client hashes the same bytes.
    return JSON.stringify(v).replace(/[\u007f-\uffff]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`);
}
const sha256 = (t: string) => createHash("sha256").update(t).digest("hex");

/**
 * The audit log as the agent sees it: each row is built from a fixed list of typed fields (id,
 * timestamp, model, record kind and the verdict). Detections carry the assessment; other rows
 * carry no band. Every row has a `view_hash` and the export has an `export_hash`, both computed
 * over this exported view (canonical JSON, sorted keys).
 */
export function normaliseAuditLog(result: any): any {
    const events = Array.isArray(result?.events) ? result.events : [];
    const isRecord = (e: any) => e !== null && typeof e === "object" && !Array.isArray(e);
    const invalid = events.filter((e: any) => !isRecord(e)).length;
    const rows = events.filter(isRecord).map((e: any) => {
        const kind = auditRecordKind(e);
        const view: Record<string, any> = { record_kind: kind };
        const id = safeId(e.detection_id);
        if (id !== undefined) view.id = id;
        const ts = safeTime(e.timestamp);
        if (ts !== undefined) view.timestamp = ts;
        const model = safeModel(e.model_id) ?? safeModel(e.model);
        if (model !== undefined) view.model = model;
        const out = kind === "detection" ? applyAssessment(view, assessmentFromService(e)) : view;
        out.view_hash = sha256(canonical(out));
        return out;
    });
    const summary: Record<string, number> = {
        LOW: 0, MEDIUM: 0, HIGH: 0, NOT_ASSESSED: 0, CANDIDATE_MEDIUM: 0, CANDIDATE_HIGH: 0,
    };
    for (const r of rows) {
        if (r.record_kind !== "detection") continue;
        summary[r.risk_level] = (summary[r.risk_level] ?? 0) + 1;
        if (r.candidate_alert === "MEDIUM") summary.CANDIDATE_MEDIUM += 1;
        if (r.candidate_alert === "HIGH") summary.CANDIDATE_HIGH += 1;
    }
    if (invalid) summary.INVALID_ROWS = invalid;
    const out: Record<string, any> = { events: rows, summary, hash_scheme: "sha256-canonical-json-v1",
                                       export_hash: sha256(canonical(rows)) };
    if (typeof result?.error === "string" && result.error) out.error = "audit_unavailable";
    return out;
}
