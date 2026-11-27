/**
 * The optional provider_response input of arkheia_verify: the provider's reply object, exactly as
 * received. It is checked only for shape and size, passed on unchanged, and never read, logged or echoed.
 */

export const MAX_PROVIDER_RESPONSE_BYTES = 2 * 1024 * 1024;

export type ProviderResponseCheck =
    | { ok: true; value: Record<string, unknown> | undefined }
    | { ok: false; error: string };

const NOT_OBJECT = "provider_response must be a JSON object, or a JSON string that parses to an object.";
const TOO_LARGE = "provider_response is too large (limit about 2 MB).";

const isObject = (v: unknown): v is Record<string, unknown> =>
    typeof v === "object" && v !== null && !Array.isArray(v);

export function checkProviderResponse(input: unknown): ProviderResponseCheck {
    if (input === undefined || input === null) return { ok: true, value: undefined };
    let value: unknown = input;
    if (typeof input === "string") {
        if (Buffer.byteLength(input, "utf8") > MAX_PROVIDER_RESPONSE_BYTES) return { ok: false, error: TOO_LARGE };
        try { value = JSON.parse(input); } catch { return { ok: false, error: NOT_OBJECT }; }
    }
    if (!isObject(value)) return { ok: false, error: NOT_OBJECT };
    let size: number;
    try { size = Buffer.byteLength(JSON.stringify(value), "utf8"); } catch { return { ok: false, error: NOT_OBJECT }; }
    if (size > MAX_PROVIDER_RESPONSE_BYTES) return { ok: false, error: TOO_LARGE };
    return { ok: true, value };
}
