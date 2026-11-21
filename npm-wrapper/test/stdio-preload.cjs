// Loaded into the child server with --require. No network: fetch is replaced entirely.
const DID = "det_0123456789abcdef";
const json = (status, body) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
globalThis.fetch = async (url) => {
    url = String(url);
    if (url.startsWith("http://localhost")) throw new TypeError("fetch failed"); // local proxy down: forces the fallback path
    if (url.endsWith("/v1/detect")) return json(200, { risk: "LOW", confidence: 0.1, features_triggered: [], detection_id: DID });
    if (url.endsWith("/v1/feedback")) return json(201, { feedback_id: "11111111-2222-3333-4444-555555555555", status: "received" });
    throw new Error("unexpected network call in test: " + url);
};
