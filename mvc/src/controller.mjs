import { createCISModel } from "./model.mjs";
import { sequentialSort, findDuplicates, mean, populationVariance, standardDeviation, normalize, checksum, seededRandomSort } from "./math.mjs";
import { serializeDuplicateView } from "./view.mjs";

export function executeCIS(input = {}) {
  const config = createCISModel(input);
  const values = [...config.values];
  let output = values, duplicates = [];
  if (config.mode === "DUPLICATE") {
    duplicates = findDuplicates(values);
    output = sequentialSort(values.filter(v => typeof v === "number" && Number.isFinite(v)));
  } else if (config.mode === "INPUT") {
    output = values;
  } else if (config.mode === "SYSTEM_CHECK") {
    output = seededRandomSort(values, config.seed);
  }
  const numeric = values.every(v => typeof v === "number" && Number.isFinite(v)) ? values : [];
  const metrics = {
    count: values.length,
    numericCount: numeric.length,
    mean: mean(numeric),
    populationVariance: populationVariance(numeric),
    standardDeviation: standardDeviation(numeric),
    normalized: normalize(numeric),
  };
  const digest = checksum(JSON.stringify({ config, output, duplicates, metrics }));
  return serializeDuplicateView({ config, output, duplicates, metrics, checksum: digest });
}
