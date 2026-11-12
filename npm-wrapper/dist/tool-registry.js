"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.PolicyViolation = exports.REGISTRY = exports.Permission = void 0;
exports.check = check;
var Permission;
(function (Permission) {
    Permission["READ"] = "read";
    Permission["EXECUTE"] = "execute";
    Permission["WRITE"] = "write";
    Permission["DEPLOY"] = "deploy";
})(Permission || (exports.Permission = Permission = {}));
// ---------------------------------------------------------------------------
// The allowlist
// ---------------------------------------------------------------------------
exports.REGISTRY = {
    arkheia_verify: {
        name: "arkheia_verify",
        permissions: [Permission.READ],
        network_egress: true,
        description: "Screen an AI response for fabrication risk",
    },
    arkheia_audit_log: {
        name: "arkheia_audit_log",
        permissions: [Permission.READ],
        network_egress: false,
        description: "Retrieve structured audit evidence",
    },
    run_grok: {
        name: "run_grok",
        permissions: [Permission.READ, Permission.EXECUTE],
        network_egress: true,
        description: "Call xAI Grok API and screen response through Arkheia",
    },
    run_gemini: {
        name: "run_gemini",
        permissions: [Permission.READ, Permission.EXECUTE],
        network_egress: true,
        description: "Call Google Gemini API and screen response through Arkheia",
    },
    run_together: {
        name: "run_together",
        permissions: [Permission.READ, Permission.EXECUTE],
        network_egress: true,
        description: "Call Together AI API and screen response through Arkheia",
    },
    run_ollama: {
        name: "run_ollama",
        permissions: [Permission.READ, Permission.EXECUTE],
        network_egress: false,
        description: "Call local Ollama model and screen response through Arkheia",
    },
    memory_store: {
        name: "memory_store",
        permissions: [Permission.READ, Permission.WRITE],
        network_egress: false,
        description: "Store an entity and observations in the persistent knowledge graph",
    },
    memory_retrieve: {
        name: "memory_retrieve",
        permissions: [Permission.READ],
        network_egress: false,
        description: "Retrieve entities and their observations from the knowledge graph",
    },
    memory_relate: {
        name: "memory_relate",
        permissions: [Permission.READ, Permission.WRITE],
        network_egress: false,
        description: "Store a named relationship between two entities in the knowledge graph",
    },
};
// ---------------------------------------------------------------------------
// Policy gate
// ---------------------------------------------------------------------------
class PolicyViolation extends Error {
    tool_name;
    reason;
    constructor(tool_name, reason) {
        super(`Policy violation for '${tool_name}': ${reason}`);
        this.tool_name = tool_name;
        this.reason = reason;
    }
}
exports.PolicyViolation = PolicyViolation;
function check(tool_name) {
    const policy = exports.REGISTRY[tool_name];
    if (!policy) {
        throw new PolicyViolation(tool_name, `not in allowlist — default deny. Known tools: ${Object.keys(exports.REGISTRY).sort().join(", ")}`);
    }
    return policy;
}
