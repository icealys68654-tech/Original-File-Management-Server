import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { executeCIS } from "../src/controller.mjs";
import { CISRegistry } from "../src/registry.mjs";
import { Database } from "../src/models/database-model.mjs";

const sample = [9, 2, 9, 4, 2, 7];

test("ISO_DUPLICATE_VIEW serializes the DISC duplicate model and sequential controller output", () => {
  const result = executeCIS({ code: 3, id: 2, status: 0.14, mode: "DUPLICATE", values: sample });
  assert.equal(result.schema, "iso.discs.cis.duplicate-view.v1");
  assert.deepEqual(result.input, sample);
  assert.deepEqual(result.output, [2, 2, 4, 7, 9, 9]);
  assert.deepEqual(result.duplicates, [9, 2]);
  assert.equal(result.metrics.count, sample.length);
  assert.equal(result.metrics.mean, 5.5);
  assert.equal(JSON.parse(JSON.stringify(result)).checksum, result.checksum);
  assert.match(result.checksum, /^[0-9a-f]{8}$/); // deterministic FNV-1a integrity aid, not a cryptographic signature
});

test("SORT_CONTROLLER input and random_test paths preserve input and deterministic permutation", () => {
  const passthrough = executeCIS({ mode: "INPUT", values: sample });
  assert.deepEqual(passthrough.output, sample);
  const randomA = executeCIS({ mode: "SYSTEM_CHECK", seed: 2026, values: sample });
  const randomB = executeCIS({ mode: "SYSTEM_CHECK", seed: 2026, values: sample });
  assert.deepEqual(randomA.output, randomB.output);
  assert.deepEqual([...randomA.output].sort((a, b) => a - b), [...sample].sort((a, b) => a - b));
});

test("MATH and JSON registry round-trip the validated DISC configuration through SQLite", async () => {
  const dir = await mkdtemp(join(tmpdir(), "cfs-iso-registry-"));
  const db = new Database(join(dir, "registry.sqlite"));
  try {
    const registry = new CISRegistry(db);
    const saved = await registry.save({ name: "production-gate-duplicate", config: { mode: "DUPLICATE", values: sample } });
    const entries = await registry.list();
    assert.equal(entries.length, 1);
    assert.equal(entries[0].id, saved.id);
    assert.deepEqual(entries[0].config.values, sample);
    assert.equal(await registry.remove(saved.id), true);
    assert.equal((await registry.list()).length, 0);
  } finally {
    db.close();
    await rm(dir, { recursive: true, force: true });
  }
});
