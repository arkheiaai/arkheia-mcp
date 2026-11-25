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
function assessmentFromDetector(raw, bandField) {
    const band = raw?.[bandField];
    const assessed = raw?.assessed;
    const reason = raw?.not_assessed_reason;
    const candidate = raw?.candidate_alert;
    if (assessed === true) {
        const consistent = isBand(band)
            && raw?.evidence_depth_limited === false
            && (reason === null || reason === undefined)
            && (candidate === null || candidate === undefined);
        if (consistent)
            return { risk_level: band, assessed: true };
        return notAssessed("unknown");
    }
    if (assessed === false && typeof reason === "string" && exports.SERVER_REASONS.includes(reason)) {
        const candidateOk = candidate === null || candidate === undefined || CANDIDATE_LEVELS.includes(candidate);
        if (!candidateOk)
            return notAssessed("unknown");
        return notAssessed(reason, CANDIDATE_LEVELS.includes(candidate) ? candidate : undefined);
    }
    // No assessment fact, or one we cannot read: the service did not say it assessed this.
    return notAssessed("unknown");
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
        if (features_triggered !== undefined)
            out.features_triggered = features_triggered;
    }
    void detection_method;
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
    if (data?.done === false)
        return "incomplete";
    const r = data?.done_reason;
    if (r === "stop")
        return "complete";
    if (typeof r === "string")
        return "incomplete";
    return "unknown";
}
/** Normalise one audit-log row (a stored local verdict) and count the summary from the rows. */
function normaliseAuditLog(result) {
    const events = Array.isArray(result?.events) ? result.events : [];
    const rows = events.map((e) => {
        const bandField = e && "risk_level" in e ? "risk_level" : "risk";
        return applyAssessment(e ?? {}, assessmentFromDetector(e, bandField));
    });
    const summary = {
        LOW: 0, MEDIUM: 0, HIGH: 0, NOT_ASSESSED: 0, CANDIDATE_MEDIUM: 0, CANDIDATE_HIGH: 0,
    };
    for (const r of rows) {
        summary[r.risk_level] = (summary[r.risk_level] ?? 0) + 1;
        if (r.candidate_alert === "MEDIUM")
            summary.CANDIDATE_MEDIUM += 1;
        if (r.candidate_alert === "HIGH")
            summary.CANDIDATE_HIGH += 1;
    }
    return { ...result, events: rows, summary };
}
