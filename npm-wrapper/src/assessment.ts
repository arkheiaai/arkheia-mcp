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

export const ASSESSED_BANDS = ["LOW", "MEDIUM", "HIGH"] as const;
export const SERVER_REASONS = ["no_profile", "borrowed_profile", "limited_evidence", "unknown"] as const;
export const CLIENT_REASONS = [
    "screening_disabled", "provider_error", "incomplete_response", "service_unavailable", "unknown",
] as const;
/** The whole vocabulary a result may carry. Nothing else is ever produced. */
export const ALL_REASONS = [
    "no_profile", "borrowed_profile", "limited_evidence", "service_unavailable",
    "incomplete_response", "provider_error", "screening_disabled", "unknown",
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

/**
 * Normalise a detector answer (hosted `/v1/detect` body, or a local proxy's verdict). `bandField`
 * is the field the source puts its band in (`risk` for hosted, `risk_level` for local).
 */
export function assessmentFromDetector(raw: any, bandField: "risk" | "risk_level"): Assessment {
    const band = raw?.[bandField];
    const assessed = raw?.assessed;
    const reason = raw?.not_assessed_reason;
    const candidate = raw?.candidate_alert;

    if (assessed === true) {
        const consistent = isBand(band)
            && raw?.evidence_depth_limited === false
            && (reason === null || reason === undefined)
            && (candidate === null || candidate === undefined);
        if (consistent) return { risk_level: band, assessed: true };
        return notAssessed("unknown");
    }
    if (assessed === false && typeof reason === "string" && (SERVER_REASONS as readonly string[]).includes(reason)) {
        const candidateOk = candidate === null || candidate === undefined || CANDIDATE_LEVELS.includes(candidate);
        if (!candidateOk) return notAssessed("unknown");
        return notAssessed(reason as Reason, CANDIDATE_LEVELS.includes(candidate) ? candidate : undefined);
    }
    // No assessment fact, or one we cannot read: the service did not say it assessed this.
    return notAssessed("unknown");
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
 * normalised assessment. Fields that could carry a band word are dropped from unassessed results.
 */
export function applyAssessment<T extends Record<string, any>>(base: T, a: Assessment): Record<string, any> {
    const { risk, risk_level, assessed, not_assessed_reason, candidate_alert, features_triggered,
            detection_method, ...rest } = base;
    void risk; void risk_level; void assessed; void not_assessed_reason; void candidate_alert;
    const out: Record<string, any> = { ...rest, ...a };
    if (a.assessed) {
        if (features_triggered !== undefined) out.features_triggered = features_triggered;
    }
    void detection_method;
    return out;
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
    if (data?.done === false) return "incomplete";
    const r = data?.done_reason;
    if (r === "stop") return "complete";
    if (typeof r === "string") return "incomplete";
    return "unknown";
}

/** Normalise one audit-log row (a stored local verdict) and count the summary from the rows. */
export function normaliseAuditLog(result: any): any {
    const events = Array.isArray(result?.events) ? result.events : [];
    const rows = events.map((e: any) => {
        const bandField = e && "risk_level" in e ? "risk_level" : "risk";
        return applyAssessment(e ?? {}, assessmentFromDetector(e, bandField));
    });
    const summary: Record<string, number> = {
        LOW: 0, MEDIUM: 0, HIGH: 0, NOT_ASSESSED: 0, CANDIDATE_MEDIUM: 0, CANDIDATE_HIGH: 0,
    };
    for (const r of rows) {
        summary[r.risk_level] = (summary[r.risk_level] ?? 0) + 1;
        if (r.candidate_alert === "MEDIUM") summary.CANDIDATE_MEDIUM += 1;
        if (r.candidate_alert === "HIGH") summary.CANDIDATE_HIGH += 1;
    }
    return { ...result, events: rows, summary };
}
