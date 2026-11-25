/** Dependency-free mathematical library for CIS workflows. */
export function numericArray(values) {
  if (!Array.isArray(values) || values.some(v => typeof v !== "number" || !Number.isFinite(v))) {
    throw new TypeError("values must be an array of finite numbers");
  }
  return [...values];
}
export const sequentialSort = values => numericArray(values).sort((a, b) => a - b);
export function findDuplicates(values) {
  if (!Array.isArray(values)) throw new TypeError("values must be an array");
  const seen = new Set(), emitted = new Set(), duplicates = [];
  for (const value of values) {
    const key = JSON.stringify(value);
    if (seen.has(key) && !emitted.has(key)) { duplicates.push(value); emitted.add(key); }
    seen.add(key);
  }
  return duplicates;
}
export function mean(values) {
  const xs = numericArray(values);
  return xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : 0;
}
export function populationVariance(values) {
  const xs = numericArray(values);
  if (!xs.length) return 0;
  const m = mean(xs);
  return xs.reduce((sum, x) => sum + (x - m) ** 2, 0) / xs.length;
}
export const standardDeviation = values => Math.sqrt(populationVariance(values));
export function normalize(values) {
  const xs = numericArray(values);
  if (!xs.length) return [];
  const min = Math.min(...xs), max = Math.max(...xs);
  return max === min ? xs.map(() => 0) : xs.map(x => (x - min) / (max - min));
}
/** FNV-1a 32-bit checksum over UTF-8 text; deterministic, not cryptographic. */
export function checksum(value) {
  const bytes = new TextEncoder().encode(String(value));
  let hash = 0x811c9dc5;
  for (const byte of bytes) { hash ^= byte; hash = Math.imul(hash, 0x01000193) >>> 0; }
  return hash.toString(16).padStart(8, "0");
}
export function seededRandom(seed) {
  let state = (Number(seed) >>> 0) || 0x6d2b79f5;
  return () => {
    state += 0x6d2b79f5;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
export function seededRandomSort(values, seed = 1) {
  const random = seededRandom(seed);
  return numericArray(values).map((value, index) => ({ value, index, key: random() }))
    .sort((a, b) => a.key - b.key || a.index - b.index).map(x => x.value);
}
