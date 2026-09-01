// Minimal file-backed job store. No DB dependency — fine for the volume an MVP
// funnel sees. One JSON file, loaded on boot, written on every change.
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { randomUUID } from "node:crypto";

export class Store {
  constructor(file) {
    this.file = file;
    this.jobs = {};
    if (existsSync(file)) {
      try { this.jobs = JSON.parse(readFileSync(file, "utf8")); } catch { this.jobs = {}; }
    } else {
      mkdirSync(dirname(file), { recursive: true });
    }
  }
  _save() { writeFileSync(this.file, JSON.stringify(this.jobs, null, 2) + "\n"); }
  create(fields) {
    const id = randomUUID();
    const now = new Date().toISOString();
    this.jobs[id] = { id, status: "pending_payment", createdAt: now, updatedAt: now, ...fields };
    this._save();
    return this.jobs[id];
  }
  get(id) { return this.jobs[id] || null; }
  update(id, patch) {
    if (!this.jobs[id]) return null;
    this.jobs[id] = { ...this.jobs[id], ...patch, updatedAt: new Date().toISOString() };
    this._save();
    return this.jobs[id];
  }
  list(filter) {
    const all = Object.values(this.jobs).sort((a, b) => b.createdAt.localeCompare(a.createdAt));
    return filter ? all.filter(filter) : all;
  }
}
