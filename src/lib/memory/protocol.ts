export type PracticeTab =
  | "desk"
  | "propose"
  | "review"
  | "retrieve"
  | "audit"
  | "prove"
  | "protocol";

export interface ProtocolStep {
  n: number;
  section: string;
  text: string;
  practice?: PracticeTab;
}

export const PROTOCOL: ProtocolStep[] = [
  {
    n: 1,
    section: "1. Scope and roles",
    practice: "desk",
    text: "Name the product owner, service owner, security owner, data-governance owner, retrieval owner, and release approver. Record each person's authority for requirements, data classification, policy exceptions, deployment, and rollback.",
  },
  {
    n: 2,
    section: "1. Scope and roles",
    practice: "desk",
    text: "Write the MVP boundary. Include scoped retrieval, lifecycle states, provenance, candidate write proposals, approval or rejection, revocation, audit events, tenant isolation, and hybrid retrieval. Explicitly exclude unrestricted autonomous writes, cross-tenant search, secret storage, and broad database access.",
  },
  {
    n: 3,
    section: "1. Scope and roles",
    practice: "desk",
    text: "Define the protected assets and failure conditions: private memory content, tenant boundaries, approval integrity, source provenance, audit integrity, retrieval correctness, and secret references.",
  },
  {
    n: 4,
    section: "2. Policy and data model",
    practice: "propose",
    text: "Define memory classes: working, episodic, semantic, procedural, relationship, and audit. For every class, document permitted sources, default retention, retrieval rule, approval requirement, sensitivity expectations, and deletion behavior.",
  },
  {
    n: 5,
    section: "2. Policy and data model",
    practice: "review",
    text: "Implement lifecycle states: candidate, validated, approved, active, superseded, expired, revoked, and deleted. Define permitted state transitions and the identity or policy authorized to perform each transition.",
  },
  {
    n: 6,
    section: "2. Policy and data model",
    practice: "retrieve",
    text: "Define the required memory metadata: stable ID, tenant, content or protected content reference, type, lifecycle state, trust level, source identifier and locator, source digest, collector, timestamps, retention, scope, sensitivity, creator, validator, approver, version links, and audit correlation ID.",
  },
  {
    n: 7,
    section: "2. Policy and data model",
    practice: "desk",
    text: "Define a default-deny authorization matrix for user, project, department, organization, agent role, workflow, memory class, and action. Ensure that tenant filtering is mandatory before lexical, vector, or graph retrieval.",
  },
  {
    n: 8,
    section: "3. Secure MCP surface",
    practice: "retrieve",
    text: "Expose only narrow operations for search, get, explain, propose_write, approve_write, reject_write, revoke, and audit. Validate each request and response against a strict schema. Do not expose a generic database query or an unrestricted write operation.",
  },
  {
    n: 9,
    section: "3. Secure MCP surface",
    practice: "desk",
    text: "Require an authenticated principal, tenant, agent identity, job or task identifier, requested purpose, and correlation ID on every request. Reject requests missing required context.",
  },
  {
    n: 10,
    section: "3. Secure MCP surface",
    practice: "prove",
    text: "Implement policy enforcement at the gateway and again within the memory service. Return policy-safe denials that do not disclose whether protected memory exists.",
  },
  {
    n: 11,
    section: "3. Secure MCP surface",
    practice: "propose",
    text: "Store references to a secret vault when a workflow requires credentials. Reject attempts to write API keys, tokens, passwords, session cookies, or raw secrets into memory.",
  },
  {
    n: 12,
    section: "4. Ingestion and governance",
    practice: "propose",
    text: "On ingestion, capture source identity and locator, calculate a content digest, classify sensitivity, identify tenant ownership, and retain the original source reference where policy permits.",
  },
  {
    n: 13,
    section: "4. Ingestion and governance",
    practice: "propose",
    text: "Treat web pages, emails, uploaded documents, retrieved resources, and tool outputs as untrusted data. Detect and flag instruction-like content, attempts to alter policy, or content requesting data exfiltration.",
  },
  {
    n: 14,
    section: "4. Ingestion and governance",
    practice: "review",
    text: "Create all new writes as candidate records. Run validation for provenance, duplication, scope, retention, classification, and memory class before any approval decision.",
  },
  {
    n: 15,
    section: "4. Ingestion and governance",
    practice: "review",
    text: "Require a human or defined policy authority to approve high-impact writes, including policies, permissions, legal guidance, financial facts, cross-user memories, and access-scope changes. Record decision rationale.",
  },
  {
    n: 16,
    section: "5. Retrieval and evidence",
    practice: "retrieve",
    text: "Apply authorization, tenant, lifecycle, retention, trust, time, type, and sensitivity filters before candidate retrieval. Exclude deleted, expired, revoked, superseded where appropriate, and unauthorized records.",
  },
  {
    n: 17,
    section: "5. Retrieval and evidence",
    practice: "retrieve",
    text: "Run lexical and vector candidate retrieval. Expand graph neighbors only when task relevance and policy justify it. Re-rank using relevance, recency, source quality, trust, version authority, and scope fit.",
  },
  {
    n: 18,
    section: "5. Retrieval and evidence",
    practice: "retrieve",
    text: "Return a capped evidence packet rather than an archive. Include memory ID, authorized content or excerpt, type, trust and lifecycle state, source label, timestamps, expiration, version reference, and explanation reference.",
  },
  {
    n: 19,
    section: "5. Retrieval and evidence",
    practice: "audit",
    text: "Record the query context, policy decision, result IDs, response size, and correlation ID in the audit ledger. Do not log more protected content than needed for audit.",
  },
  {
    n: 20,
    section: "6. Test security",
    practice: "prove",
    text: "Create unit tests for lifecycle transitions, schema validation, scope checks, tenant isolation, retention expiry, revocation, versioning, approval rules, source digest handling, and audit-event creation.",
  },
  {
    n: 21,
    section: "6. Test security",
    practice: "prove",
    text: "Perform negative authorization tests. Attempt cross-tenant retrieval, access from an unauthorized agent, enumeration through errors, retrieval of revoked content, and access to memories with an expired scope. Verify all attempts fail closed.",
  },
  {
    n: 22,
    section: "6. Test security",
    practice: "prove",
    text: "Perform memory-poisoning tests using external content that contains hostile instructions, policy-bypass requests, misleading provenance, prompt-injection text, and invalid approval claims. Verify that content remains untrusted and cannot self-approve.",
  },
  {
    n: 23,
    section: "6. Test security",
    practice: "prove",
    text: "Perform retrieval-quality tests using known queries and expected evidence sets. Measure precision, missing authoritative records, stale-result rate, response size, latency, and provenance completeness.",
  },
  {
    n: 24,
    section: "6. Test security",
    practice: "prove",
    text: "Run a deletion and revocation test. Revoke an active memory and verify that ordinary retrieval, lexical indexes, vector indexes, and graph expansions stop returning it within the defined service objective. Verify audit preservation follows policy.",
  },
  {
    n: 25,
    section: "7. Approve release",
    practice: "desk",
    text: "Review the threat model, authorization matrix, data-class policy, retention policy, test evidence, monitoring plan, incident response path, rollback plan, and open risks. Document exceptions and their expiry dates.",
  },
  {
    n: 26,
    section: "7. Approve release",
    practice: "desk",
    text: "Deploy first to a limited non-production or pilot scope with least-privilege agents and low-sensitivity memories. Enable enhanced monitoring for denied requests, unexpected retrieval volume, candidate-write spikes, anomalous approvals, and index propagation failures.",
  },
  {
    n: 27,
    section: "7. Approve release",
    practice: "desk",
    text: "Authorize production expansion only after the release approver confirms the acceptance criteria: scoped active-only retrieval, non-automatic trust promotion, complete provenance, auditable writes and retrievals, effective revocation, and demonstrated tenant isolation.",
  },
  {
    n: 28,
    section: "8. Operate and improve",
    practice: "desk",
    text: "Review retrieval quality, policy denials, approval turnaround, retention actions, revocations, audit completeness, and security alerts at a defined cadence. Convert findings into prioritized changes with owner and due date.",
  },
  {
    n: 29,
    section: "8. Operate and improve",
    practice: "audit",
    text: "Version policies, schemas, ranking logic, and MCP operation contracts. Test compatibility before rollout and retain the policy and service version in audit records needed for reproducibility.",
  },
];

export const PROTOCOL_SECTIONS = [...new Set(PROTOCOL.map((step) => step.section))];
