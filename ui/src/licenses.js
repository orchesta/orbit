// licenseBreakdown counts dependencies per license expression, most common
// first (ties by name), with the dependencies of unknown license last as
// { license: null }.
export const licenseBreakdown = (deps) => {
  const counts = new Map();
  let unknown = 0;
  for (const d of deps) {
    if (d.license) counts.set(d.license, (counts.get(d.license) || 0) + 1);
    else unknown++;
  }
  const rows = [...counts].map(([license, count]) => ({ license, count }))
    .sort((a, b) => b.count - a.count || a.license.localeCompare(b.license));
  if (unknown > 0) rows.push({ license: null, count: unknown });
  return rows;
};
