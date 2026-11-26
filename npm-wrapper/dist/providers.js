"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.SECRET_ENV_NAMES = void 0;
exports.modelNameError = modelNameError;
exports.call_grok = call_grok;
exports.call_gemini = call_gemini;
exports.call_together = call_together;
exports.call_ollama = call_ollama;
const crypto = __importStar(require("crypto"));
const assessment_js_1 = require("./assessment.js");
const egress_js_1 = require("./egress.js");
const feedback_js_1 = require("./feedback.js");
// Node.js native fetch doesn't have a global logger, use console
const logger = {
    // stdout carries the MCP protocol; log lines go to stderr only.
    info: (m) => { process.stderr.write(`${m}\n`); },
    warn: (m) => { process.stderr.write(`${m}\n`); },
    error: (m) => { process.stderr.write(`${m}\n`); },
};
const _DEFAULT_TIMEOUT = 60 * 1000; // 60 seconds in milliseconds
const _OLLAMA_TIMEOUT = 120 * 1000; // 120 seconds in milliseconds
// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------
function _prompt_hash(prompt) {
    return crypto.createHash('sha256').update(prompt).digest('hex');
}
// A caller-chosen model name goes into diagnostics, results and (Gemini) the request path, so it is
// checked first: a conservative character set, no path tricks, and never anything shaped like a key.
// Every credential the package reads (the Arkheia key may come from the config file, which is loaded into the environment).
exports.SECRET_ENV_NAMES = ["ARKHEIA_API_KEY", "XAI_API_KEY", "GOOGLE_API_KEY", "TOGETHER_API_KEY"];
const MODEL_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:\/-]{0,127}$/;
const MODEL_PATTERN_NO_SLASH_COLON = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
/** Returns a fixed error code when the model name must be refused, else null. Never repeats the name. */
function modelNameError(model, strict = false) {
    if (typeof model !== "string")
        return "invalid_model_name";
    if (!(strict ? MODEL_PATTERN_NO_SLASH_COLON : MODEL_PATTERN).test(model))
        return "invalid_model_name";
    if (model.includes("..") || model.includes("//"))
        return "invalid_model_name";
    if ((0, feedback_js_1.looksLikeCredential)(model, process.env.ARKHEIA_API_KEY))
        return "invalid_model_name";
    // Any secret this package reads from the environment or config, as the whole name or inside it.
    for (const name of exports.SECRET_ENV_NAMES) {
        const secret = process.env[name];
        if (secret && (model === secret || (secret.length >= 8 && model.includes(secret))))
            return "invalid_model_name";
    }
    return null;
}
function _refused_model(prompt) {
    // The refused name is not echoed back.
    return _err_response("", prompt, "invalid_model_name");
}
function _err_response(model, prompt, error) {
    return {
        response: `[provider_error: ${error}]`,
        model: model,
        prompt_hash: _prompt_hash(prompt),
        error: error,
    };
}
// ---------------------------------------------------------------------------
// Grok (xAI) — OpenAI-compatible /v1/chat/completions
// ---------------------------------------------------------------------------
async function call_grok(prompt, model = "grok-4-fast-non-reasoning", kwargs = {}) {
    if (modelNameError(model, false))
        return _refused_model(prompt);
    /**
     * Call xAI Grok chat completions API.
     *
     * Returns: {response, model, prompt_hash, error}
     */
    const api_key = process.env.XAI_API_KEY;
    if (!api_key) {
        return _err_response(model, prompt, "XAI_API_KEY not set");
    }
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), _DEFAULT_TIMEOUT);
    try {
        const resp = await fetch("https://api.x.ai/v1/chat/completions", {
            method: "POST",
            headers: {
                "Authorization": `Bearer ${api_key}`,
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                model: model,
                messages: [{ role: "user", content: prompt }],
                ...kwargs,
            }),
            redirect: "error", // provider keys are never re-sent to wherever a redirect points
            signal: controller.signal,
        });
        clearTimeout(timeoutId);
        if (!resp.ok) {
            logger.error(`call_grok: HTTP ${resp.status} for model=${model}`);
            return _err_response(model, prompt, `http_${resp.status}`);
        }
        const data = await resp.json();
        const response_text = data.choices?.[0]?.message?.content;
        const finish = (0, assessment_js_1.finishFromOpenAICompatible)(data);
        // A non-normal finish (length, content filter) is reported as such even with no text.
        if (finish === "incomplete") {
            return { response: typeof response_text === 'string' ? response_text : "", model: model,
                prompt_hash: _prompt_hash(prompt), usage: data.usage || {}, finish, error: null };
        }
        if (typeof response_text !== 'string') {
            throw new Error("Invalid response format from Grok API");
        }
        return {
            response: response_text,
            finish: finish,
            model: model,
            prompt_hash: _prompt_hash(prompt),
            usage: data.usage || {},
            error: null,
        };
    }
    catch (e) {
        clearTimeout(timeoutId);
        if (e.name === 'AbortError') {
            logger.error(`call_grok: request timed out for model=${model}`);
            return _err_response(model, prompt, "timeout");
        }
        else if (e.name === 'TypeError' && e.message.includes('fetch failed')) {
            logger.error(`call_grok: network error for model=${model}: ${(0, egress_js_1.describeTransportError)(e).text}`);
            return _err_response(model, prompt, "network_error");
        }
        else {
            logger.error(`call_grok: request failed: ${(0, egress_js_1.describeTransportError)(e).text}`);
            return _err_response(model, prompt, (0, egress_js_1.describeTransportError)(e).code);
        }
    }
}
// ---------------------------------------------------------------------------
// Gemini (Google) — generateContent REST API
// ---------------------------------------------------------------------------
async function call_gemini(prompt, model = "gemini-2.5-flash", max_output_tokens = 1000, kwargs = {}) {
    if (modelNameError(model, true))
        return _refused_model(prompt);
    /**
     * Call Google Gemini generateContent API.
     *
     * Note: gemini-2.5-flash and -pro need a larger output limit
     * (max_output_tokens >= 1000) to return content.
     *
     * Returns: {response, model, prompt_hash, error}
     */
    const api_key = process.env.GOOGLE_API_KEY;
    if (!api_key) {
        return _err_response(model, prompt, "GOOGLE_API_KEY not set");
    }
    const url = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent`;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), _DEFAULT_TIMEOUT);
    try {
        const resp = await fetch(`${url}?key=${api_key}`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                contents: [{ parts: [{ text: prompt }] }],
                generationConfig: {
                    maxOutputTokens: max_output_tokens,
                    ...kwargs,
                },
            }),
            redirect: "error", // provider keys are never re-sent to wherever a redirect points
            signal: controller.signal,
        });
        clearTimeout(timeoutId);
        if (!resp.ok) {
            logger.error(`call_gemini: HTTP ${resp.status} for model=${model}`);
            return _err_response(model, prompt, `http_${resp.status}`);
        }
        const data = await resp.json();
        // The whole visible reply, not its first part: screening part of a reply and reporting
        // the verdict as the reply's would misstate what was checked. A reply that did not finish
        // normally is returned as such (not screened, and not a provider error); a finished reply
        // with any part that is not plain text is an unsupported shape and fails closed.
        const finish = (0, assessment_js_1.finishFromGemini)(data);
        const parts = data.candidates?.[0]?.content?.parts;
        // The visible answer is the text parts that are not model thoughts.
        const visible = Array.isArray(parts) ? parts.filter((p) => typeof p?.text === 'string' && p?.thought !== true) : [];
        const allText = Array.isArray(parts) && parts.length > 0 && visible.length > 0
            && parts.every((p) => typeof p?.text === 'string');
        if (finish !== "complete") {
            return {
                response: visible.map((p) => p.text).join(""),
                model: model,
                prompt_hash: _prompt_hash(prompt),
                usage: data.usageMetadata || {},
                finish: finish === "unknown" ? "unknown" : "incomplete",
                error: null,
            };
        }
        if (!allText) {
            throw new Error("Unsupported response format from Gemini API");
        }
        const response_text = visible.map((p) => p.text).join("");
        return {
            response: response_text,
            finish: finish,
            model: model,
            prompt_hash: _prompt_hash(prompt),
            usage: data.usageMetadata || {},
            error: null,
        };
    }
    catch (e) {
        clearTimeout(timeoutId);
        if (e.name === 'AbortError') {
            logger.error(`call_gemini: request timed out for model=${model}`);
            return _err_response(model, prompt, "timeout");
        }
        else if (e.name === 'TypeError' && e.message.includes('fetch failed')) {
            logger.error(`call_gemini: network error for model=${model}: ${(0, egress_js_1.describeTransportError)(e).text}`);
            return _err_response(model, prompt, "network_error");
        }
        else {
            logger.error(`call_gemini: request failed: ${(0, egress_js_1.describeTransportError)(e).text}`);
            return _err_response(model, prompt, (0, egress_js_1.describeTransportError)(e).code);
        }
    }
}
// ---------------------------------------------------------------------------
// Together AI — OpenAI-compatible, cloud inference
// ---------------------------------------------------------------------------
async function call_together(prompt, model = "moonshotai/Kimi-K2.5", max_tokens = 2048, kwargs = {}) {
    if (modelNameError(model, false))
        return _refused_model(prompt);
    /**
     * Call Together AI chat completions API (OpenAI-compatible).
     *
     * Default model is Kimi K2.5, which needs a larger output limit
     * (max_tokens >= 2048) to reliably return a response.
     *
     * Returns: {response, model, prompt_hash, usage, error}
     */
    const api_key = process.env.TOGETHER_API_KEY;
    if (!api_key) {
        return _err_response(model, prompt, "TOGETHER_API_KEY not set");
    }
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), _DEFAULT_TIMEOUT);
    try {
        const resp = await fetch("https://api.together.xyz/v1/chat/completions", {
            method: "POST",
            headers: {
                "Authorization": `Bearer ${api_key}`,
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                model: model,
                max_tokens: max_tokens,
                messages: [{ role: "user", content: prompt }],
                ...kwargs,
            }),
            redirect: "error", // provider keys are never re-sent to wherever a redirect points
            signal: controller.signal,
        });
        clearTimeout(timeoutId);
        if (!resp.ok) {
            logger.error(`call_together: HTTP ${resp.status} for model=${model}`);
            return _err_response(model, prompt, `http_${resp.status}`);
        }
        const data = await resp.json();
        const response_text = data.choices?.[0]?.message?.content;
        const finish = (0, assessment_js_1.finishFromOpenAICompatible)(data);
        // A non-normal finish (length, content filter) is reported as such even with no text.
        if (finish === "incomplete") {
            return { response: typeof response_text === 'string' ? response_text : "", model: model,
                prompt_hash: _prompt_hash(prompt), usage: data.usage || {}, finish, error: null };
        }
        if (typeof response_text !== 'string') {
            throw new Error("Invalid response format from Together AI API");
        }
        return {
            response: response_text,
            finish: finish,
            model: model,
            prompt_hash: _prompt_hash(prompt),
            usage: data.usage || {},
            error: null,
        };
    }
    catch (e) {
        clearTimeout(timeoutId);
        if (e.name === 'AbortError') {
            logger.error(`call_together: request timed out for model=${model}`);
            return _err_response(model, prompt, "timeout");
        }
        else if (e.name === 'TypeError' && e.message.includes('fetch failed')) {
            logger.error(`call_together: network error for model=${model}: ${(0, egress_js_1.describeTransportError)(e).text}`);
            return _err_response(model, prompt, "network_error");
        }
        else {
            logger.error(`call_together: request failed: ${(0, egress_js_1.describeTransportError)(e).text}`);
            return _err_response(model, prompt, (0, egress_js_1.describeTransportError)(e).code);
        }
    }
}
// ---------------------------------------------------------------------------
// Ollama — local inference, no network egress
// ---------------------------------------------------------------------------
async function call_ollama(prompt, model = "phi4:14b", kwargs = {}) {
    if (modelNameError(model, false))
        return _refused_model(prompt);
    /**
     * Call local Ollama model via /api/generate (non-streaming).
     *
     * OLLAMA_BASE_URL defaults to http://localhost:11434.
     * No network egress — local eval only.
     *
     * Returns: {response, model, prompt_hash, eval_count, error}
     */
    const base_url = process.env.OLLAMA_BASE_URL || "http://localhost:11434";
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), _OLLAMA_TIMEOUT);
    try {
        const resp = await fetch(`${base_url}/api/generate`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                model: model,
                prompt: prompt,
                stream: false,
                ...kwargs,
            }),
            redirect: "error", // provider keys are never re-sent to wherever a redirect points
            signal: controller.signal,
        });
        clearTimeout(timeoutId);
        if (!resp.ok) {
            logger.error(`call_ollama: HTTP ${resp.status} for model=${model}`);
            return _err_response(model, prompt, `http_${resp.status}`);
        }
        const data = await resp.json();
        const response_text = data.response;
        if (typeof response_text !== 'string') {
            throw new Error("Invalid response format from Ollama API");
        }
        return {
            response: response_text,
            finish: (0, assessment_js_1.finishFromOllama)(data),
            model: model,
            prompt_hash: _prompt_hash(prompt),
            eval_count: data.eval_count,
            error: null,
        };
    }
    catch (e) {
        clearTimeout(timeoutId);
        if (e.name === 'AbortError') {
            logger.error(`call_ollama: request timed out for model=${model}`);
            return _err_response(model, prompt, "timeout");
        }
        else if (e.name === 'TypeError' && e.message.includes('fetch failed')) {
            logger.error(`call_ollama: cannot connect to Ollama at ${(0, egress_js_1.displayOrigin)(base_url)}`);
            return _err_response(model, prompt, "ollama_unavailable");
        }
        else {
            logger.error(`call_ollama: request failed: ${(0, egress_js_1.describeTransportError)(e).text}`);
            return _err_response(model, prompt, (0, egress_js_1.describeTransportError)(e).code);
        }
    }
}
