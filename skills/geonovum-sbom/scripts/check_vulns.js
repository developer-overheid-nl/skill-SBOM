#!/usr/bin/env node
// Checks an existing CycloneDX SBOM against the current vulnerability data at api.osv.dev.
// Run it on the SBOM of the version that is in use, not on the source tree: the SBOM says
// what is deployed, and OSV changes every day while the SBOM does not.
//
// Usage: node check_vulns.js <sbom.cdx.json> [--vex <sbom-inventory.json>] [--out <dir>]
//   --vex  inventory whose vex block and used:false components count as assessed, so that an
//          assessment made after the release silences the vulnerability
//   --out  directory for kwetsbaarheden.json (all vulnerabilities) and kwetsbaarheden.md (the
//          ones still to assess, empty when there are none); default: no files
//
// Prints a summary. The exit code is 0 unless the SBOM cannot be read or OSV cannot be reached.

const fs = require('fs');
const path = require('path');
const osv = require('./osv');

const args = process.argv.slice(2);
const opt = (f) => { const i = args.indexOf(f); return i >= 0 ? args[i + 1] : undefined; };
const sbomFile = args.find((a, i) => !a.startsWith('--') && !['--vex', '--out'].includes(args[i - 1]));
if (!sbomFile) {
  console.error('usage: node check_vulns.js <sbom.cdx.json> [--vex <sbom-inventory.json>] [--out <dir>]');
  process.exit(2);
}
const bom = JSON.parse(fs.readFileSync(sbomFile, 'utf8'));
const inv = opt('--vex') ? JSON.parse(fs.readFileSync(opt('--vex'), 'utf8')) : { components: [], vex: {} };

// A purl without version and qualifiers, so that an inventory purl matches the one in the SBOM.
const basePurl = (p) => (p || '').split(/[?#]/)[0].replace(/@[^/@]*$/, '');
const flatten = (list) => (list || []).flatMap((c) => [c, ...flatten(c.components)]);
const components = flatten(bom.components).filter((c) => c.purl && c.version);
const invByPurl = Object.fromEntries((inv.components || []).filter((c) => c.purl).map((c) => [basePurl(c.purl), c]));

// Assessments already in the SBOM, per vulnerability id and component reference.
const inSbom = {};
for (const v of bom.vulnerabilities || []) {
  for (const a of v.affects || []) inSbom[`${v.id}|${a.ref}`] = { ...v.analysis, from: 'SBOM' };
  for (const r of v.references || []) for (const a of v.affects || []) inSbom[`${r.id}|${a.ref}`] = { ...v.analysis, from: 'SBOM' };
}

const assessment = (v, c) => {
  const id = osv.vulnId(v);
  const invC = invByPurl[basePurl(c.purl)];
  const fromInv = invC && ((inv.vex || {})[`${id}@${invC.key}`] || (inv.vex || {})[id] || (inv.vex || {})[v.osvId]);
  if (fromInv) return { ...fromInv, from: 'inventaris' };
  const known = inSbom[`${id}|${c['bom-ref']}`] || inSbom[`${v.osvId}|${c['bom-ref']}`];
  if (known && known.state !== 'in_triage') return known;
  if (invC && invC.used === false) return { state: 'not_affected', justification: 'code_not_reachable', from: 'inventaris (used: false)' };
  return { state: 'in_triage', from: known ? 'SBOM' : 'nieuw' };
};

const main = async () => {
  const { vulns, errors } = await osv.lookup(components);
  if (errors.length) {
    console.error(`api.osv.dev niet bereikbaar: ${errors.join('; ')}`);
    process.exit(1);
  }
  const rows = [];
  for (const v of vulns) {
    const id = osv.vulnId(v);
    if (rows.some((r) => r.id === id && r.ref === v.c['bom-ref'])) continue;
    const a = assessment(v, v.c);
    rows.push({
      id, osvId: v.osvId, ref: v.c['bom-ref'], component: `${v.c.name}@${v.c.version}`,
      severity: osv.severity(v) || 'onbekend', fixed: osv.fixedVersions(v), summary: v.d.summary || '',
      state: a.state, justification: a.justification, from: a.from,
    });
  }
  const open = rows.filter((r) => r.state === 'in_triage');
  const product = bom.metadata?.component ? `${bom.metadata.component.name} ${bom.metadata.component.version || ''}`.trim() : sbomFile;
  console.log(`${product}: ${components.length} componenten bij OSV nagevraagd, ${rows.length} kwetsbaarheden, ${open.length} te beoordelen.`);
  for (const r of rows) console.log(`- ${r.id} ${r.component}: ${r.state} (${r.from})`);

  if (opt('--out')) {
    const out = path.resolve(opt('--out'));
    fs.mkdirSync(out, { recursive: true });
    fs.writeFileSync(path.join(out, 'kwetsbaarheden.json'), JSON.stringify({ product, checked: new Date().toISOString(), vulnerabilities: rows }, null, 2) + '\n');
    const url = (r) => (r.id.startsWith('CVE-') ? `https://nvd.nist.gov/vuln/detail/${r.id}` : `https://osv.dev/vulnerability/${r.id}`);
    const cell = (s) => String(s).replace(/\|/g, '/').replace(/\s+/g, ' ').slice(0, 120);
    const md = open.length ? [
      `Deze kwetsbaarheden in ${product} zijn nog niet beoordeeld. Leg de uitkomst vast in het vex-blok van sbom-inventory.json; de volgende controle neemt die over.`,
      '', '| Kwetsbaarheid | Component | Ernst | Opgelost in | Omschrijving |', '|---|---|---|---|---|',
      ...open.map((r) => `| [${r.id}](${url(r)}) | ${r.component} | ${r.severity} | ${r.fixed.join(', ') || '-'} | ${cell(r.summary)} |`),
    ].join('\n') + '\n' : '';
    fs.writeFileSync(path.join(out, 'kwetsbaarheden.md'), md);
  }
};

main().catch((e) => { console.error(e); process.exit(1); });
