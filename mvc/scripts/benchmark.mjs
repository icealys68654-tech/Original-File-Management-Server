const base = (process.argv[2] || 'http://127.0.0.1:5080').replace(/\/$/, '');
const total = Math.max(1, Number(process.argv[3] || 1000));
const concurrency = Math.max(1, Math.min(total, Number(process.argv[4] || 25)));
const path = process.argv[5] || '/health';
const samples = new Array(total);
let cursor = 0, failures = 0;
const start = performance.now();
async function worker() {
  while (true) {
    const index = cursor++;
    if (index >= total) return;
    const t0 = performance.now();
    try {
      const response = await fetch(`${base}${path}`, { signal: AbortSignal.timeout(15000) });
      await response.arrayBuffer();
      samples[index] = performance.now() - t0;
      if (!response.ok) failures++;
    } catch { samples[index] = performance.now() - t0; failures++; }
  }
}
await Promise.all(Array.from({ length: concurrency }, worker));
const elapsed = (performance.now() - start) / 1000;
const sorted = samples.sort((a, b) => a - b);
const percentile = p => sorted[Math.min(sorted.length - 1, Math.ceil(sorted.length * p) - 1)];
const result = { url: `${base}${path}`, requests: total, concurrency, failures, duration_seconds: Number(elapsed.toFixed(3)), requests_per_second: Number((total / elapsed).toFixed(2)), latency_ms: { p50: Number(percentile(.50).toFixed(2)), p95: Number(percentile(.95).toFixed(2)), p99: Number(percentile(.99).toFixed(2)), max: Number(sorted.at(-1).toFixed(2)) } };
console.log(JSON.stringify(result, null, 2));
if (failures) process.exitCode = 1;
