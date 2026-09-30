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
exports.call_grok = call_grok;
exports.call_gemini = call_gemini;
exports.call_together = call_together;
exports.call_ollama = call_ollama;
const crypto = __importStar(require("crypto"));
// Node.js native fetch doesn't have a global logger, use console
const logger = console;
const _DEFAULT_TIMEOUT = 60 * 1000; // 60 seconds in milliseconds
const _OLLAMA_TIMEOUT = 120 * 1000; // 120 seconds in milliseconds
// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------
function _prompt_hash(prompt) {
    return crypto.createHash('sha256').update(prompt).digest('hex');
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
            signal: controller.signal,
        });
        clearTimeout(timeoutId);
        if (!resp.ok) {
            logger.error(`call_grok: HTTP ${resp.status} for model=${model}`);
            return _err_response(model, prompt, `http_${resp.status}`);
        }
        const data = await resp.json();
        const response_text = data.choices?.[0]?.message?.content;
        if (typeof response_text !== 'string') {
            throw new Error("Invalid response format from Grok API");
        }
        return {
            response: response_text,
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
            logger.error(`call_grok: network error for model=${model}: ${e.message}`);
            return _err_response(model, prompt, "network_error");
        }
        else {
            logger.error(`call_grok: unexpected error: ${e.message}`);
            return _err_response(model, prompt, e.message);
        }
    }
}
// ---------------------------------------------------------------------------
// Gemini (Google) — generateContent REST API
// ---------------------------------------------------------------------------
async function call_gemini(prompt, model = "gemini-2.5-flash", max_output_tokens = 1000, kwargs = {}) {
    /**
     * Call Google Gemini generateContent API.
     *
     * Note: gemini-2.5-flash and -pro are thinking models — they need
     * max_output_tokens >= 1000 to produce content after thinking tokens.
     *
     * Returns: {response, model, prompt_hash, error}
     */
    const api_key = process.env.GOOGLE_API_KEY;
    if (!api_key) {
        return _err_response(model, prompt, "GOOGLE_API_KEY not set");
    }
    const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`;
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
            signal: controller.signal,
        });
        clearTimeout(timeoutId);
        if (!resp.ok) {
            logger.error(`call_gemini: HTTP ${resp.status} for model=${model}`);
            return _err_response(model, prompt, `http_${resp.status}`);
        }
        const data = await resp.json();
        const response_text = data.candidates?.[0]?.content?.parts?.[0]?.text;
        if (typeof response_text !== 'string') {
            throw new Error("Invalid response format from Gemini API");
        }
        return {
            response: response_text,
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
            logger.error(`call_gemini: network error for model=${model}: ${e.message}`);
            return _err_response(model, prompt, "network_error");
        }
        else {
            logger.error(`call_gemini: unexpected error: ${e.message}`);
            return _err_response(model, prompt, e.message);
        }
    }
}
// ---------------------------------------------------------------------------
// Together AI — OpenAI-compatible, cloud inference
// ---------------------------------------------------------------------------
async function call_together(prompt, model = "moonshotai/Kimi-K2.5", max_tokens = 2048, kwargs = {}) {
    /**
     * Call Together AI chat completions API (OpenAI-compatible).
     *
     * Default model is Kimi K2.5 — a thinking model that consumes
     * 100-500 tokens internally before producing output, so max_tokens
     * must be >= 2048 to reliably get a response.
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
            signal: controller.signal,
        });
        clearTimeout(timeoutId);
        if (!resp.ok) {
            logger.error(`call_together: HTTP ${resp.status} for model=${model}`);
            return _err_response(model, prompt, `http_${resp.status}`);
        }
        const data = await resp.json();
        const response_text = data.choices?.[0]?.message?.content;
        if (typeof response_text !== 'string') {
            throw new Error("Invalid response format from Together AI API");
        }
        return {
            response: response_text,
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
            logger.error(`call_together: network error for model=${model}: ${e.message}`);
            return _err_response(model, prompt, "network_error");
        }
        else {
            logger.error(`call_together: unexpected error: ${e.message}`);
            return _err_response(model, prompt, e.message);
        }
    }
}
// ---------------------------------------------------------------------------
// Ollama — local inference, no network egress
// ---------------------------------------------------------------------------
async function call_ollama(prompt, model = "phi4:14b", kwargs = {}) {
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
            logger.error(`call_ollama: cannot connect to Ollama at ${base_url}`);
            return _err_response(model, prompt, "ollama_unavailable");
        }
        else {
            logger.error(`call_ollama: unexpected error: ${e.message}`);
            return _err_response(model, prompt, e.message);
        }
    }
}
