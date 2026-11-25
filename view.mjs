/** ISO duplicate-view serializer. Output is plain JSON-safe data. */
export function serializeDuplicateView({ config, output, duplicates = [], metrics = {}, checksum }) {
  return Object.freeze({
    schema: "iso.discs.cis.duplicate-view.v1",
    config: { code: config.code, id: config.id, status: config.status, mode: config.mode },
    input: [...config.values],
    output: [...output],
    duplicates: [...duplicates],
    metrics: { ...metrics },
    checksum,
  });
}
