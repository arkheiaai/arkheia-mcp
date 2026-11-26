"use strict";
/**
 * The optional provider_response input of arkheia_verify: the provider's reply object, exactly as
 * received. It is checked only for shape and size, passed on unchanged, and never read, logged or echoed.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.MAX_PROVIDER_RESPONSE_BYTES = void 0;
exports.checkProviderResponse = checkProviderResponse;
exports.MAX_PROVIDER_RESPONSE_BYTES = 2 * 1024 * 1024;
const NOT_OBJECT = "provider_response must be a JSON object, or a JSON string that parses to an object.";
const TOO_LARGE = "provider_response is too large (limit about 2 MB).";
const isObject = (v) => typeof v === "object" && v !== null && !Array.isArray(v);
function checkProviderResponse(input) {
    if (input === undefined || input === null)
        return { ok: true, value: undefined };
    let value = input;
    if (typeof input === "string") {
        if (Buffer.byteLength(input, "utf8") > exports.MAX_PROVIDER_RESPONSE_BYTES)
            return { ok: false, error: TOO_LARGE };
        try {
            value = JSON.parse(input);
        }
        catch {
            return { ok: false, error: NOT_OBJECT };
        }
    }
    if (!isObject(value))
        return { ok: false, error: NOT_OBJECT };
    let size;
    try {
        size = Buffer.byteLength(JSON.stringify(value), "utf8");
    }
    catch {
        return { ok: false, error: NOT_OBJECT };
    }
    if (size > exports.MAX_PROVIDER_RESPONSE_BYTES)
        return { ok: false, error: TOO_LARGE };
    return { ok: true, value };
}
