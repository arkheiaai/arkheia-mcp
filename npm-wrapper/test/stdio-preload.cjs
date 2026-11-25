// Loaded into the child server with --require. No network: fetch is replaced entirely.
// It behaves like the hosted service: a JSON body sent without a JSON content type is answered 422.
const DID = "det_0123456789abcdef";
const json = (status, body) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
const header = (init, name) => Object.entries((init && init.headers) || {}).find(([k]) => k.toLowerCase() === name)?.[1];
const fs = require("fs");
globalThis.fetch = async (url, init) => {
    url = String(url);
    // Test-only: record every request URL so the test can see which origins were contacted.
    if (process.env.ARKHEIA_TEST_REQUEST_LOG) fs.appendFileSync(process.env.ARKHEIA_TEST_REQUEST_LOG, url + "\n");
    // Test-only overrides for the Change A tests: the hosted verdict body, the local audit body,
    // and each provider's finish state (default: a normal finish).
    const finish = process.env.ARKHEIA_TEST_FINISH || "normal";
    if (process.env.ARKHEIA_TEST_AUDIT_BODY && url.includes("/audit/log")) return json(200, JSON.parse(process.env.ARKHEIA_TEST_AUDIT_BODY));
    if (url.startsWith("https://api.x.ai/") || url.startsWith("https://api.together.xyz/")) {
        if (finish === "error") return json(500, { error: "boom" });
        return json(200, { choices: [{ message: { content: "provider answer" }, finish_reason: finish === "length" ? "length" : "stop" }] });
    }
    if (url.startsWith("https://generativelanguage.googleapis.com/")) {
        if (finish === "error") return json(500, { error: "boom" });
        return json(200, { candidates: [{ content: { parts: [{ text: "provider answer" }] }, finishReason: finish === "length" ? "MAX_TOKENS" : "STOP" }] });
    }
    if (finish !== "normal" && url.endsWith("/api/generate")) {
        if (finish === "error") return json(500, { error: "boom" });
        return json(200, { response: "cut off", done: true, done_reason: "length" });
    }
    if (url === "http://127.0.0.1:11434/api/generate") return json(200, { response: "local answer", done: true, done_reason: "stop" }); // local Ollama
    // Like a strict server: a JSON body must say so, otherwise 422.
    if (init && init.body !== undefined && !/^application\/json\b/i.test(String(header(init, "content-type") || ""))) {
        if (!url.startsWith("http://localhost")) return json(422, { detail: "body must be application/json" });
    }
    if (url.startsWith("http://localhost")) throw new TypeError("fetch failed"); // local proxy down: forces the fallback path
    if (url.endsWith("/v1/detect")) {
        if (process.env.ARKHEIA_TEST_DETECT_BODY) return json(200, { detection_id: DID, ...JSON.parse(process.env.ARKHEIA_TEST_DETECT_BODY) });
        return json(200, { risk: "LOW", confidence: 0.1, features_triggered: [], detection_id: DID });
    }
    if (url.endsWith("/v1/feedback")) return json(201, { feedback_id: "11111111-2222-3333-4444-555555555555", status: "received" });
    if (url.endsWith("/report")) return json(201, { report_id: "22222222-3333-4444-5555-666666666666", status: "recorded" });
    if (url.endsWith("/api/generate")) return json(200, { response: "an answer", eval_count: 1, done: true, done_reason: "stop" });
    throw new Error("unexpected network call in test: " + url);
};
