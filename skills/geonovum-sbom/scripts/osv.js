// Shared by build_sbom.js and check_vulns.js: looks up known vulnerabilities at api.osv.dev.
const { execFileSync } = require('child_process');

// Node's fetch ignores the system proxy and certificate store; fall back to curl, which uses them.
const fetchJson = async (url, body) => {
  try {
    const res = await fetch(url, body ? { method: 'POST', headers: { 'content-type': 'application/json' }, body } : undefined);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch {
    const a = ['-sSfL', url];
    if (body) a.push('-H', 'content-type: application/json', '--data-binary', '@-');
    return JSON.parse(execFileSync('curl', a, { input: body, maxBuffer: 1 << 28 }).toString());
  }
};

// OSV knows package ecosystems, not generic or GitHub purls.
const queryable = (c) => !!c.purl && !!c.version && !c.purl.startsWith('pkg:generic') && !c.purl.startsWith('pkg:github');
const purlWithVersion = (c) => (c.purl.includes('@') ? c.purl : `${c.purl}@${c.version}`);

// Returns { vulns: [{ c, osvId, d }], errors: [message] }, where d is the full OSV record.
const lookup = async (components) => {
  const list = components.filter(queryable);
  const vulns = [];
  const errors = [];
  for (let i = 0; i < list.length; i += 500) {
    const batch = list.slice(i, i + 500);
    try {
      const data = await fetchJson('https://api.osv.dev/v1/querybatch',
        JSON.stringify({ queries: batch.map((c) => ({ package: { purl: purlWithVersion(c) } })) }));
      (data.results || []).forEach((r, j) => (r.vulns || []).forEach((v) => vulns.push({ c: batch[j], osvId: v.id })));
    } catch (e) {
      errors.push(e.message);
    }
  }
  const details = {};
  for (const id of [...new Set(vulns.map((v) => v.osvId))]) {
    try { details[id] = await fetchJson(`https://api.osv.dev/v1/vulns/${id}`); } catch { details[id] = { id }; }
  }
  for (const v of vulns) v.d = details[v.osvId];
  return { vulns, errors };
};

// The CVE alias when there is one, so that one CVE with several OSV records counts once.
const vulnId = (v) => (v.d.aliases || []).find((a) => a.startsWith('CVE-')) || v.d.id || v.osvId;

const severity = (v) => {
  const sev = (v.d.database_specific?.severity || '').toLowerCase().replace('moderate', 'medium');
  return sev ? (['low', 'medium', 'high', 'critical'].includes(sev) ? sev : 'unknown') : undefined;
};

// Fixed versions of this component only: an OSV record can also list other packages that embed it.
const fixedVersions = (v) => {
  const base = (v.c.purl || '').split(/[@?#]/)[0];
  const name = base.split('/').pop().toLowerCase();
  const all = v.d.affected || [];
  const own = all.filter((x) => (x.package?.purl || '').split(/[@?#]/)[0] === base || (x.package?.name || '').toLowerCase() === name);
  return [...new Set((own.length ? own : all).flatMap((x) => (x.ranges || []).flatMap((r) => (r.events || []).filter((e) => e.fixed).map((e) => e.fixed))))];
};

module.exports = { fetchJson, lookup, vulnId, severity, fixedVersions, queryable };
