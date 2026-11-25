export const MODES = Object.freeze(["DUPLICATE", "INPUT", "SYSTEM_CHECK"]);
const DEFAULTS = Object.freeze({ code: 3, id: 2, status: 0.14, mode: "INPUT", values: [], seed: 1 });
export function createCISModel(input = {}) {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new TypeError("CIS config must be an object");
  const config = { ...DEFAULTS, ...input };
  if (!Number.isInteger(config.code) || config.code < 0) throw new TypeError("code must be a non-negative integer");
  if (!Number.isInteger(config.id) || config.id < 0) throw new TypeError("id must be a non-negative integer");
  if (typeof config.status !== "number" || !Number.isFinite(config.status) || config.status < 0 || config.status > 1)
    throw new TypeError("status must be a number between 0 and 1");
  if (!MODES.includes(config.mode)) throw new TypeError(`mode must be one of ${MODES.join(", ")}`);
  if (!Array.isArray(config.values)) throw new TypeError("values must be an array");
  if (!Number.isInteger(config.seed)) throw new TypeError("seed must be an integer");
  config.values = Object.freeze([...config.values]);
  return Object.freeze(config);
}
export function defaultCISConfig() { return createCISModel(); }
