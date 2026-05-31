export function mergeRoleScanResults(roleResults) {
  const findings = [];
  const roleNames = roleResults.map((r) => r.roleName);
  const findingKeysByRole = {};

  for (const { roleName, result } of roleResults) {
    findingKeysByRole[roleName] = new Set();
    for (const f of result.findings || []) {
      const key = `${f.id}|${f.pageUrl || ""}`;
      findingKeysByRole[roleName].add(key);
      findings.push({
        ...f,
        id: roleResults.length > 1 ? `${f.id}@${roleName}` : f.id,
        scanRole: roleName,
        description: roleResults.length > 1
          ? `[${roleName}] ${f.description}`
          : f.description,
      });
    }
  }

  if (roleResults.length > 1) {
    const [a, b] = roleResults;
    const onlyA = [...findingKeysByRole[a.roleName]].filter((k) => !findingKeysByRole[b.roleName].has(k));
    const onlyB = [...findingKeysByRole[b.roleName]].filter((k) => !findingKeysByRole[a.roleName].has(k));

    findings.unshift({
      id: "multi-role-diff",
      severity: onlyA.length || onlyB.length ? "medium" : "info",
      category: "scanner",
      title: `Multi-role comparison: ${a.roleName} vs ${b.roleName}`,
      description: `${onlyA.length} finding(s) only in ${a.roleName}, ${onlyB.length} only in ${b.roleName}.`,
      evidence: `Roles scanned: ${roleNames.join(", ")}`,
      remediation: "Review privilege differences; escalate IDsOR or missing auth controls.",
    });
  }

  const primary = roleResults[0]?.result || {};
  return {
    ...primary,
    findings,
    scanRoles: roleNames,
    multiRole: roleResults.length > 1,
  };
}
