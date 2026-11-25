"use strict";
/**
 * Release pack Change A, client half: an unscored check never reads as LOW.
 *
 * The service states whether it assessed a response (`assessed`), why not
 * (`not_assessed_reason`) and any unqualified alert it still carries (`candidate_alert`). This
 * module passes those through and fails closed:
 *
 *   - assessed: true is accepted only with a LOW/MEDIUM/HIGH band, `evidence_depth_limited`
 *     exactly false, and no reason or candidate beside it;
 *   - assessed: false is accepted only with a reason from the service's closed list;
 *   - anything missing or contradictory becomes NOT_ASSESSED with reason `unknown`.
 *
 * Reasons about detection (no_profile, borrowed_profile, limited_evidence) only ever come from
 * the service. The client sets a reason only where there is no detector answer to pass through,
 * in this order: screening_disabled, provider_error, incomplete_response, service_unavailable,
 * unknown. An unassessed result carries risk_level NOT_ASSESSED and the word LOW appears nowhere
 * in it.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.NOT_ASSESSED = exports.ALL_REASONS = exports.CLIENT_REASONS = exports.SERVER_REASONS = exports.ASSESSED_BANDS = void 0;
exports.assessmentFromDetector = assessmentFromDetector;
exports.notAssessed = notAssessed;
exports.applyAssessment = applyAssessment;
exports.finishFromOpenAICompatible = finishFromOpenAICompatible;
exports.finishFromGemini = finishFromGemini;
exports.finishFromOllama = finishFromOllama;
exports.auditRecordKind = auditRecordKind;
exports.normaliseAuditLog = normaliseAuditLog;
exports.ASSESSED_BANDS = ["LOW", "MEDIUM", "HIGH"];
exports.SERVER_REASONS = ["no_profile", "borrowed_profile", "limited_evidence", "unknown"];
exports.CLIENT_REASONS = [
    "screening_disabled", "provider_error", "incomplete_response", "service_unavailable", "unknown",
];
/** The whole vocabulary a result may carry. Nothing else is ever produced. */
exports.ALL_REASONS = [
    "no_profile", "borrowed_profile", "limited_evidence", "service_unavailable",
    "incomplete_response", "provider_error", "screening_disabled", "unknown",
];
exports.NOT_ASSESSED = "NOT_ASSESSED";
const CANDIDATE_LEVELS = ["MEDIUM", "HIGH"];
function isBand(v) {
    return typeof v === "string" && exports.ASSESSED_BANDS.includes(v);
}
/**
 * Normalise a detector answer (hosted `/v1/detect` body, or a local proxy's verdict). `bandField`
 * is the field the source puts its band in (`risk` for hosted, `risk_level` for local).
 */
const absent = (v) => v === null || v === undefined;
/**
 * The candidate the service supplied, if it is coherent: MEDIUM or HIGH, and equal to the
 * service's own level for this verdict (its pre-demotion level when it records a demotion,
 * otherwise its band). Returns null when no candidate was supplied, "invalid" when one was
 * supplied that does not fit.
 */
function serviceCandidate(raw, band) {
    const candidate = raw?.candidate_alert;
    if (absent(candidate))
        return null;
    if (!CANDIDATE_LEVELS.includes(candidate))
        return "invalid";
    if (!demotionIsPossible(raw, band))
        return "invalid";
    const level = absent(raw?.risk_demoted_from) ? band : raw.risk_demoted_from;
    return candidate === level ? candidate : "invalid";
}
/** The only demotion the service makes is an advisory cap: HIGH published as MEDIUM. */
function demotionIsPossible(raw, band) {
    return absent(raw?.risk_demoted_from) || (raw.risk_demoted_from === "HIGH" && band === "MEDIUM");
}
/** Facts a local verifier reports that contradict an affirmative assessment. */
const sameModel = (a, b) => typeof a === "string" && typeof b === "string" && a.trim().toLowerCase() === b.trim().toLowerCase();
function localContradiction(raw, requestedModel) {
    if (!absent(raw?.gate_reason))
        return true; // a suppression gate produced it
    if (!absent(raw?.error))
        return true; // the detector reported an error
    // A field the producer sends is a claim: an explicit null or non-string identity is an explicit
    // unknown, not an omission. Omitted fields stay compatible with verdict-only producers.
    for (const key of ["profile_model_id", "model_id", "model"]) {
        if (raw && key in raw && !(typeof raw[key] === "string" && raw[key].trim()))
            return true;
    }
    // Every identity the producer supplies must agree with every other (model_id, model,
    // profile_model_id), with or without a requested model.
    const ids = [raw?.model_id, raw?.model, raw?.profile_model_id].filter((v) => typeof v === "string");
    if (ids.some((v) => !sameModel(v, ids[0])))
        return true;
    // The verdict must be about the model this call asked about.
    if (requestedModel !== undefined) {
        for (const named of [raw?.model_id, raw?.model, raw?.profile_model_id]) {
            if (typeof named === "string" && !sameModel(named, requestedModel))
                return true;
        }
    }
    return false;
}
function assessmentFromDetector(raw, bandField, requestedModel) {
    const band = raw?.[bandField];
    const assessed = raw?.assessed;
    const reason = raw?.not_assessed_reason;
    if (assessed === true) {
        // The affirmative flag is believed only when nothing else the service said contradicts it:
        // full evidence, its own profile, a supported model, no demotion, no reason, no candidate.
        const consistent = isBand(band)
            && raw?.evidence_depth_limited === false
            && raw?.profile_fingerprint_borrowed !== true
            && raw?.model_supported !== false
            && !localContradiction(raw, requestedModel)
            && absent(raw?.risk_demoted_from)
            && absent(reason)
            && absent(raw?.candidate_alert);
        if (consistent)
            return { risk_level: band, assessed: true };
        return notAssessed("unknown");
    }
    const candidate = serviceCandidate(raw, band);
    if (candidate === "invalid")
        return notAssessed("unknown");
    if (assessed === false && typeof reason === "string" && exports.SERVER_REASONS.includes(reason)) {
        return notAssessed(reason, candidate ?? undefined);
    }
    // No assessment fact, or one we cannot read: the service did not say it assessed this. An
    // explicit, coherent service-supplied candidate (an old audit row's warning) is kept.
    return notAssessed("unknown", candidate ?? undefined);
}
function notAssessed(reason, candidate) {
    return {
        risk_level: exports.NOT_ASSESSED,
        assessed: false,
        not_assessed_reason: reason,
        ...(candidate ? { candidate_alert: candidate } : {}),
    };
}
/**
 * Build the caller-facing result from any verdict-shaped object, keeping the non-verdict fields
 * (detection_id, source, confidence, error) and replacing every verdict field with the
 * normalised assessment. Fields that could carry a band word are dropped from unassessed results.
 */
function applyAssessment(base, a) {
    const { risk, risk_level, assessed, not_assessed_reason, candidate_alert, features_triggered, detection_method, ...rest } = base;
    void risk;
    void risk_level;
    void assessed;
    void not_assessed_reason;
    void candidate_alert;
    const out = { ...rest, ...a };
    if (a.assessed) {
        // A scored result keeps the fields it has always carried.
        if (features_triggered !== undefined)
            out.features_triggered = features_triggered;
        if (detection_method !== undefined)
            out.detection_method = detection_method;
    }
    return out;
}
function finishFromOpenAICompatible(data) {
    const r = data?.choices?.[0]?.finish_reason;
    if (r === "stop")
        return "complete";
    if (typeof r === "string")
        return "incomplete";
    return "unknown";
}
function finishFromGemini(data) {
    const r = data?.candidates?.[0]?.finishReason;
    if (r === "STOP")
        return "complete";
    if (typeof r === "string")
        return "incomplete";
    return "unknown";
}
function finishFromOllama(data) {
    // Complete only when Ollama says both: done is the boolean true AND it stopped normally.
    if (data?.done === true && data?.done_reason === "stop")
        return "complete";
    if (data?.done === false || (data?.done === true && typeof data?.done_reason === "string"))
        return "incomplete";
    return "unknown";
}
const DETECTION_SOURCES = ["proxy", "passthrough", "interception"];
const HASH_FIELDS = ["this_hash", "prev_hash"];
const SERVICE_READ_TIME = ["record_kind", "assessment", "read_time_fields"];
/** What an audit row records, by the service's own label when it sends one. */
function auditRecordKind(e) {
    // A refusal is a refusal whatever a producer labels it: the detector did not run.
    const refused = e?.action_taken === "refused" || e?.action_taken === "refuse" || e?.risk_level === "REFUSED"
        || e?.event_type === "passthrough.forward_refused";
    if (refused)
        return "refusal";
    if (typeof e?.record_kind === "string")
        return e.record_kind;
    if (e?.source === "governance_push" || e?.event_type === "governance_detection_push")
        return "delivery_receipt";
    if (e?.event_type === "passthrough.forward_refused" || e?.action_taken === "refuse"
        || e?.action_taken === "refused" || e?.risk_level === "REFUSED")
        return "refusal";
    if (DETECTION_SOURCES.includes(e?.source))
        return "detection";
    return "operational";
}
/** Read the service's `assessment` object for a detection row, failing closed. */
function assessmentFromService(e) {
    // Omitted: an older service, read the old way. Present but unreadable: fail closed.
    if (!("assessment" in e))
        return assessmentFromDetector(e, "risk_level");
    const a = e.assessment;
    if (a === null || typeof a !== "object" || Array.isArray(a))
        return notAssessed("unknown");
    const band = e.risk_level;
    if (a.assessed === true) {
        // The same checks as a live verdict, against the row's own stored facts: an affirmative
        // assessment beside limited evidence, a gate, an error or another model's profile fails.
        const { assessment: _a, record_kind: _k, read_time_fields: _r, ...facts } = e;
        void _a;
        void _k;
        void _r;
        return assessmentFromDetector({ ...facts, assessed: true, not_assessed_reason: a.not_assessed_reason,
            candidate_alert: a.candidate_alert }, "risk_level");
    }
    if (a.assessed === false && typeof a.not_assessed_reason === "string"
        && exports.SERVER_REASONS.includes(a.not_assessed_reason)) {
        const candidate = serviceCandidate({ candidate_alert: a.candidate_alert, risk_demoted_from: e.risk_demoted_from }, band);
        if (candidate === "invalid")
            return notAssessed("unknown");
        return notAssessed(a.not_assessed_reason, candidate ?? undefined);
    }
    return notAssessed("unknown");
}
/**
 * The audit log as the agent sees it. Each row is a view: detections carry the assessment and a
 * band only when assessed; receipts, refusals and operational rows carry no band at all. The view
 * is not the stored record, so the stored digest is kept as `stored_this_hash` with `hash_scope`
 * saying what it covers; `arkheia_audit_log` with raw: true returns the stored records unchanged.
 */
function normaliseAuditLog(result) {
    const events = Array.isArray(result?.events) ? result.events : [];
    const isRecord = (e) => e !== null && typeof e === "object" && !Array.isArray(e);
    const invalid = events.filter((e) => !isRecord(e)).length;
    const rows = events.filter(isRecord).map((e) => {
        const kind = auditRecordKind(e);
        const view = {};
        for (const [k, v] of Object.entries(e)) {
            if (HASH_FIELDS.includes(k) || SERVICE_READ_TIME.includes(k))
                continue;
            if (["risk", "risk_level", "assessed", "not_assessed_reason", "candidate_alert"].includes(k))
                continue;
            view[k] = v;
        }
        view.record_kind = kind;
        if (typeof e.this_hash === "string") {
            view.stored_this_hash = e.this_hash;
            view.hash_scope = "the stored record, not this view; call arkheia_audit_log with raw: true to verify";
        }
        if (kind !== "detection")
            return view;
        return applyAssessment(view, assessmentFromService(e));
    });
    const summary = {
        LOW: 0, MEDIUM: 0, HIGH: 0, NOT_ASSESSED: 0, CANDIDATE_MEDIUM: 0, CANDIDATE_HIGH: 0,
    };
    for (const r of rows) {
        if (r.record_kind !== "detection")
            continue;
        summary[r.risk_level] = (summary[r.risk_level] ?? 0) + 1;
        if (r.candidate_alert === "MEDIUM")
            summary.CANDIDATE_MEDIUM += 1;
        if (r.candidate_alert === "HIGH")
            summary.CANDIDATE_HIGH += 1;
    }
    if (invalid)
        summary.INVALID_ROWS = invalid;
    return { ...result, events: rows, summary };
}
