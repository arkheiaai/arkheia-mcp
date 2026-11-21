// Loaded into the child server with --require. No network: fetch is replaced entirely.
// It behaves like the hosted service: a JSON body sent without a JSON content type is answered 422.
const DID = "det_0123456789abcdef";
const json = (status, body) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
globalThis.fetch = async (url, init = {}) => {
    url = String(url);
    if (process.env.ARKHEIA_TEST_REQUEST_LOG) require("fs").appendFileSync(process.env.ARKHEIA_TEST_REQUEST_LOG, url + "\n");
    if (url === "http://127.0.0.1:11434/api/generate") return json(200, { response: "local answer" }); // local Ollama
    if (url.startsWith("http://localhost")) throw new TypeError("fetch failed"); // local proxy down: forces the fallback path
    if (init.body !== undefined) {
        const ct = new Headers(init.headers || {}).get("content-type") || "";
        if (!/^application\/json\b/i.test(ct)) return json(422, { detail: "unprocessable: body is not JSON" });
    }
    if (url.endsWith("/v1/detect")) return json(200, { risk: "LOW", confidence: 0.1, features_triggered: [], detection_id: DID });
    throw new Error("unexpected network call in test: " + url);
};
