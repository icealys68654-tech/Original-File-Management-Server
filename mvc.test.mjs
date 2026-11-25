import test from "node:test";
import assert from "node:assert/strict";
import { createCISModel } from "../src/model.mjs";
import { executeCIS } from "../src/controller.mjs";
import { findDuplicates, mean, populationVariance, standardDeviation, normalize, checksum, seededRandomSort } from "../src/math.mjs";
import { CISRegistry } from "../src/registry.mjs";
import { Database } from "../src/models/database-model.mjs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

test("default CIS model is validated and immutable", () => {
  const model = createCISModel();
  assert.deepEqual([model.code, model.id, model.status], [3, 2, 0.14]);
  assert.equal(Object.isFrozen(model), true);
  assert.throws(() => createCISModel({ status: 2 }), /status/);
});
test("math library returns expected population statistics", () => {
  assert.deepEqual(findDuplicates([1,2,1,3,2]), [1,2]);
  assert.equal(mean([1,2,3]), 2);
  assert.equal(populationVariance([1,2,3]), 2/3);
  assert.equal(standardDeviation([1,2,3]), Math.sqrt(2/3));
  assert.deepEqual(normalize([2,4,6]), [0,0.5,1]);
  assert.equal(checksum("abc"), checksum("abc"));
});
test("controller supports duplicate, input and deterministic system check", () => {
  const dup = executeCIS({ mode:"DUPLICATE", values:[4,2,4,1,2] });
  assert.deepEqual(dup.output, [1,2,2,4,4]);
  assert.deepEqual(dup.duplicates, [4,2]);
  const input = executeCIS({ mode:"INPUT", values:[3,1] });
  assert.deepEqual(input.output, [3,1]);
  const a = executeCIS({ mode:"SYSTEM_CHECK", seed:44, values:[1,2,3,4] });
  const b = executeCIS({ mode:"SYSTEM_CHECK", seed:44, values:[1,2,3,4] });
  assert.deepEqual(a.output, b.output);
  assert.deepEqual(seededRandomSort([1,2,3], 4), seededRandomSort([1,2,3], 4));
});
test("registry persists validated entries and removes them", async () => {
  const dir = await mkdtemp(join(tmpdir(), "cis-reg-"));
  try {
    const db = new Database(join(dir, "cfs.sqlite"));
    const registry = new CISRegistry(db);
    const saved = await registry.save({ name:"baseline", config:{ values:[1,1], mode:"DUPLICATE" } });
    assert.equal((await registry.list()).length, 1);
    assert.equal(await registry.remove(saved.id), true);
    assert.equal((await registry.list()).length, 0);
    await assert.rejects(() => registry.save({ name:"bad", config:{ status:9 } }));
    db.close();
  } finally { await rm(dir, { recursive:true, force:true }); }
});

test("Node encryption envelope is compatible with the CFS v1 magic and decrypts", async () => {
  const { generateKeyPairSync } = await import("node:crypto");
  const { encryptEnvelope, decryptEnvelope, MAGIC, fingerprint } = await import("../src/services/encryption-service.mjs");
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 3072 });
  const pub = publicKey.export({ type:"spki", format:"pem" });
  const priv = privateKey.export({ type:"pkcs8", format:"pem" });
  const input = Buffer.from("reference file interoperability test");
  const encrypted = encryptEnvelope(input, "test.txt", pub);
  assert.equal(encrypted.subarray(0, MAGIC.length).toString(), "CFS-HYBRID-ENCRYPTED-V1\n");
  assert.deepEqual(decryptEnvelope(encrypted, priv), input);
  assert.equal(fingerprint(pub).length, 64);
  assert.throws(() => decryptEnvelope(Buffer.from("bad"), priv), /Unrecognized/);
});
