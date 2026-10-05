import { create } from "zustand";
import { persist } from "zustand/middleware";
import {
  createSeed,
  withCorrelation,
  propose,
  approve,
  rejectWrite,
  revoke,
  search,
  getMemory,
  explainMemory,
  readAudit,
  applyRetention,
  type AuditEvent,
  type Draft,
  type MemoryRecord,
  type Outcome,
  type Packet,
  type ServiceState,
  type StandingContext,
} from "./engine";

export interface Finding {
  id: string;
  text: string;
  owner: string;
  due: string;
}

export const DEFAULT_CONTEXT: StandingContext = {
  principal: "operator",
  tenant: "northwind",
  agent: "reviewer",
  jobId: "job_pilot_01",
  purpose: "Pilot review of governed memory",
};

interface Ledger extends ServiceState {
  context: StandingContext;
  findings: Finding[];
  setContext: (patch: Partial<StandingContext>) => void;
  proposeWrite: (draft: Draft) => { outcome: Outcome; record: MemoryRecord | null };
  approveWrite: (id: string, rationale: string) => Outcome;
  reject: (id: string, rationale: string) => Outcome;
  revokeMemory: (id: string, rationale: string) => Outcome;
  runSearch: (query: string) => Packet;
  runGet: (id: string) => Packet;
  runExplain: (id: string, query: string) => Packet;
  runAudit: () => { outcome: Outcome; events: AuditEvent[] };
  runRetention: () => Outcome;
  addFinding: (text: string, owner: string, due: string) => void;
  restore: () => void;
}

function snapshot(state: ServiceState): ServiceState {
  return { memories: state.memories, audit: state.audit, seq: state.seq };
}

export const useLedger = create<Ledger>()(
  persist(
    (set, get) => ({
      ...createSeed(),
      context: DEFAULT_CONTEXT,
      findings: [],
      setContext: (patch) => set({ context: { ...get().context, ...patch } }),
      proposeWrite: (draft) => {
        const current = get();
        const now = new Date().toISOString();
        const result = propose(snapshot(current), withCorrelation(current.context, current.seq), draft, now);
        set(snapshot(result.state));
        return { outcome: result.outcome, record: result.record };
      },
      approveWrite: (id, rationale) => {
        const current = get();
        const now = new Date().toISOString();
        const result = approve(snapshot(current), withCorrelation(current.context, current.seq), id, rationale, now);
        set(snapshot(result.state));
        return result.outcome;
      },
      reject: (id, rationale) => {
        const current = get();
        const now = new Date().toISOString();
        const result = rejectWrite(snapshot(current), withCorrelation(current.context, current.seq), id, rationale, now);
        set(snapshot(result.state));
        return result.outcome;
      },
      revokeMemory: (id, rationale) => {
        const current = get();
        const now = new Date().toISOString();
        const result = revoke(snapshot(current), withCorrelation(current.context, current.seq), id, rationale, now);
        set(snapshot(result.state));
        return result.outcome;
      },
      runSearch: (query) => {
        const current = get();
        const now = new Date().toISOString();
        const result = search(snapshot(current), withCorrelation(current.context, current.seq), query, now);
        set(snapshot(result.state));
        return result.packet;
      },
      runGet: (id) => {
        const current = get();
        const now = new Date().toISOString();
        const result = getMemory(snapshot(current), withCorrelation(current.context, current.seq), id, now);
        set(snapshot(result.state));
        return result.packet;
      },
      runExplain: (id, query) => {
        const current = get();
        const now = new Date().toISOString();
        const result = explainMemory(
          snapshot(current),
          withCorrelation(current.context, current.seq),
          id,
          query,
          now,
        );
        set(snapshot(result.state));
        return result.packet;
      },
      runAudit: () => {
        const current = get();
        const now = new Date().toISOString();
        const result = readAudit(snapshot(current), withCorrelation(current.context, current.seq), now);
        set(snapshot(result.state));
        return { outcome: result.outcome, events: result.events };
      },
      runRetention: () => {
        const current = get();
        const now = new Date().toISOString();
        const result = applyRetention(snapshot(current), withCorrelation(current.context, current.seq), now);
        set(snapshot(result.state));
        return result.outcome;
      },
      addFinding: (text, owner, due) => {
        const clean = text.trim();
        if (clean.length < 4 || !owner || !due) return;
        const id = `find_${get().seq}`;
        set({
          seq: get().seq + 1,
          findings: [{ id, text: clean.slice(0, 240), owner, due }, ...get().findings].slice(0, 12),
        });
      },
      restore: () => set({ ...createSeed(), context: DEFAULT_CONTEXT, findings: [] }),
    }),
    {
      name: "vellum-ledger-v1",
      skipHydration: true,
      partialize: (state) => ({
        memories: state.memories,
        audit: state.audit,
        seq: state.seq,
        context: state.context,
        findings: state.findings,
      }),
    },
  ),
);
