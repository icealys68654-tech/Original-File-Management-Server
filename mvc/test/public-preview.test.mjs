import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { SecureFileController } from '../src/controllers/secure-file-controller.mjs';
import { Database } from '../src/models/database-model.mjs';
import { encryptEnvelopeV2, fingerprint } from '../src/services/encryption-service.mjs';

test('public preview links are owner-only, hashed, expiring, and revocable', async () => {
  const storage = await mkdtemp(join(tmpdir(), 'cfs-preview-test-'));
  try {
    const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 3072 });
    const publicPem = publicKey.export({ type: 'spki', format: 'pem' });
    const ownerId = 'a'.repeat(32), fileId = 'b'.repeat(32);
    const encrypted = encryptEnvelopeV2(Buffer.from('local preview payload'), 'note.txt', [{ user_id: ownerId, pem: publicPem }]);
    const storedName = fileId + '.cfs';
    await writeFile(join(storage, storedName), encrypted, { mode: 0o600 });
    const state = {
      users: [{ id: ownerId, key_fingerprint: fingerprint(publicPem) }],
      files: [{ id: fileId, owner_id: ownerId, name: 'note.txt', stored_name: storedName,
        size: 21, encrypted_size: encrypted.length,
        encrypted_sha256: createHash('sha256').update(encrypted).digest('hex') }],
      share_links: []
    };
    const db = {
      view: async fn => fn(state),
      transaction: async fn => fn(state)
    };
    const events = [];
    const controller = new SecureFileController({ storage, db, audit: async (event, details) => events.push({ event, details }) });

    await assert.rejects(controller.createPreviewLink('c'.repeat(32), fileId), error => error.status === 404);
    await assert.rejects(controller.createPreviewLink(ownerId, fileId, 31), error => error.status === 400);

    const created = await controller.createPreviewLink(ownerId, fileId, 7);
    assert.match(created.token, /^[A-Za-z0-9_-]{43}$/);
    assert.equal(state.share_links.length, 1);
    assert.equal(state.share_links[0].token_hash, createHash('sha256').update(created.token).digest('hex'));
    assert.notEqual(state.share_links[0].token_hash, created.token);
    const retrieved = await controller.publicPreview(created.token);
    assert.deepEqual(retrieved.data, encrypted);
    assert.equal(retrieved.name, 'note.txt');

    await controller.revokePreviewLink(ownerId, fileId, created.link_id);
    await assert.rejects(controller.publicPreview(created.token), error => error.status === 404);

    const expiring = await controller.createPreviewLink(ownerId, fileId, 1);
    state.share_links.find(link => link.id === expiring.link_id).expires_at = new Date(Date.now() - 1000).toISOString();
    await assert.rejects(controller.publicPreview(expiring.token), error => error.status === 404);
    await assert.rejects(controller.publicPreview('invalid'), error => error.status === 404);
    assert.ok(events.some(x => x.event === 'preview_link.create'));
    assert.ok(events.some(x => x.event === 'preview_link.revoke'));
    assert.equal(privateKey.asymmetricKeyType, 'rsa');
  } finally {
    await rm(storage, { recursive: true, force: true });
  }
});

test('preview link metadata persists across SQLite database reopen', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'cfs-preview-db-'));
  const path = join(dir, 'cfs.sqlite');
  try {
    const first = new Database(path);
    await first.transaction(state => {
      state.share_links.push({ id: 'c'.repeat(32), file_id: 'd'.repeat(32), token_hash: 'e'.repeat(64),
        created_by: 'f'.repeat(32), created_at: new Date().toISOString(),
        expires_at: new Date(Date.now() + 86400000).toISOString(), revoked: false });
    });
    first.close();
    const second = new Database(path);
    const links = await second.view(state => state.share_links);
    assert.equal(links.length, 1);
    assert.equal(links[0].token_hash, 'e'.repeat(64));
    assert.equal(links[0].revoked, false);
    second.close();
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
