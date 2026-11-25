import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { randomUUID } from "node:crypto";
import { createCISModel } from "./model.mjs";

function validateEntry(entry) {
  if (!entry || typeof entry !== "object" || Array.isArray(entry)) throw new TypeError("registry entry must be an object");
  const config = createCISModel(entry.config ?? entry);
  const name = String(entry.name ?? "Untitled").trim();
  if (!name || name.length > 100) throw new TypeError("name must be 1–100 characters");
  return { id: String(entry.id ?? randomUUID()), name, config, updatedAt: String(entry.updatedAt ?? new Date().toISOString()) };
}
export class CISRegistry {
  constructor(db) { this.db = db; }
  async list() { return this.db.view(s => s.registry.map(validateEntry)); }
  async save(entry) {
    const normalized = validateEntry(entry);
    await this.db.transaction(s => {
      const index = s.registry.findIndex(x => x.id === normalized.id);
      if (index >= 0) s.registry[index] = normalized; else s.registry.push(normalized);
    });
    return normalized;
  }
  async remove(id) {
    let removed = false;
    await this.db.transaction(s => {
      const filtered = s.registry.filter(x => x.id !== String(id));
      removed = filtered.length !== s.registry.length;
      s.registry = filtered;
    });
    return removed;
  }
}
