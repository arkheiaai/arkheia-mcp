export enum Permission {
    READ = "read",
    EXECUTE = "execute",
    WRITE = "write",
    DEPLOY = "deploy",
}

export interface ToolPolicy {
    name: string;
    permissions: Permission[];
    description?: string;
    network_egress?: boolean;
    requires_human_confirm?: boolean;
}

// ---------------------------------------------------------------------------
// The allowlist
// ---------------------------------------------------------------------------

export const REGISTRY: Record<string, ToolPolicy> = {
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

export class PolicyViolation extends Error {
    tool_name: string;
    reason: string;
    constructor(tool_name: string, reason: string) {
        super(`Policy violation for '${tool_name}': ${reason}`);
        this.tool_name = tool_name;
        this.reason = reason;
    }
}

export function check(tool_name: string): ToolPolicy {
    const policy = REGISTRY[tool_name];
    if (!policy) {
        throw new PolicyViolation(
            tool_name,
            `not in allowlist — default deny. Known tools: ${Object.keys(REGISTRY).sort().join(", ")}`,
        );
    }
    return policy;
}
