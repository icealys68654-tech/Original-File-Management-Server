import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SecureFileController } from "../src/controllers/secure-file-controller.mjs";
import { decryptEnvelope, inspectEnvelope, fingerprint } from "../src/services/encryption-service.mjs";

test("account uploads always include an envelope for its one registered key pair", async () => {
  const dir = await mkdtemp(join(tmpdir(), "cfs-single-key-"));
  try {
    const pair = generateKeyPairSync("rsa", { modulusLength: 3072 });
    const publicKey = pair.publicKey.export({ type: "spki", format: "pem" });
    const privateKey = pair.privateKey.export({ type: "pkcs8", format: "pem" });
    const user = { id: "user-one", email: "owner@example.test", public_key: null, key_fingerprint: null };
    const state = { users: [user], files: [], permissions: [], share_links: [] };
    const db = {
      view: async fn => fn(state),
      transaction: async fn => fn(state)
    };
    const controller = new SecureFileController({ storage: dir, db, audit: async () => {} });
    const registered = await controller.setPublicKey(user.id, publicKey);
    assert.equal(registered.fingerprint, fingerprint(publicKey));
    const plaintext = Buffer.from("all files use the account's registered key");
    const uploaded = await controller.upload(user.id, "key-check.txt", plaintext);
    const file = state.files.find(x => x.id === uploaded.id);
    const raw = await readFile(join(dir, file.stored_name));
    const { envelope, version } = inspectEnvelope(raw);
    assert.equal(version, 2);
    assert.equal(envelope.recipients.length, 1);
    assert.equal(envelope.recipients[0].user_id, user.id);
    assert.equal(envelope.recipients[0].fingerprint, registered.fingerprint);
    assert.deepEqual(decryptEnvelope(raw, privateKey), plaintext);
    const other = generateKeyPairSync("rsa", { modulusLength: 3072 });
    const otherPublic = other.publicKey.export({ type: "spki", format: "pem" });
    await assert.rejects(() => controller.setPublicKey(user.id, otherPublic), /rotation is not automatic/i);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
