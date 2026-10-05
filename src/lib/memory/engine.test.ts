import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { describe, it } from "node:test";
import { createSeed, sha256 } from "./engine.ts";
import { runProofs } from "./proofs.ts";

describe("vellum memory desk", () => {
  it("matches SHA-256", () => {
    for (const sample of ["", "abc", "Harbor's accrual calendar is local."]) {
      assert.equal(sha256(sample), createHash("sha256").update(sample).digest("hex"));
    }
  });

  it("passes the protocol proofs", () => {
    const groups = runProofs(createSeed());
    const failed = groups.flatMap((group) =>
      group.lines.filter((line) => !line.pass).map((line) => `${group.id}: ${line.name} — ${line.detail}`),
    );
    assert.deepEqual(failed, []);
  });
});
