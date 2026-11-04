#!/usr/bin/env node
// Builds a CycloneDX 1.7 SBOM (with VEX) and an SPDX 2.3 SBOM from an inventory file,
// covering the 2026 CISA minimum elements. Needs Node 18+ (global fetch) and git for repo hashes.
//
// Usage: node build_sbom.js <inventory.json> [--out <dir>] [--version <v>] [--no-osv] [--no-fetch]
//   --out       directory for sbom.cdx.json, sbom.spdx.json and sbom-gaps.md (default: the repo root)
//   --version   product version, for example the release tag; overrides product.version
//   --no-osv    skip the vulnerability lookup at api.osv.dev
//   --no-fetch  do not download remote (CDN) files to hash them
//
// The inventory format is described in inventaris-formaat.md, next to SKILL.md.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');
const osv = require('./osv');

const TOOL = { name: 'geonovum-sbom build_sbom.js', version: '1.2.0' };

const args = process.argv.slice(2);
const flag = (f) => args.includes(f);
const opt = (f) => { const i = args.indexOf(f); return i >= 0 ? args[i + 1] : undefined; };
const invFile = args.find((a, i) => !a.startsWith('--') && !['--out', '--version'].includes(args[i - 1]));
if (!invFile) {
  console.error('usage: node build_sbom.js <inventory.json> [--out <dir>] [--version <v>] [--no-osv] [--no-fetch]');
  process.exit(2);
}
const inv = JSON.parse(fs.readFileSync(invFile, 'utf8'));
const repo = path.resolve(path.dirname(invFile), inv.repo || '.');
const outDir = path.resolve(opt('--out') || repo);
const gaps = [];
const gap = (what) => { if (!gaps.includes(what)) gaps.push(what); };

// ---------- helpers ----------
const run = (cmd, a) => execFileSync(cmd, a, { maxBuffer: 1 << 28, stdio: ['ignore', 'pipe', 'ignore'] });
const isGit = (() => { try { run('git', ['-C', repo, 'rev-parse', '--git-dir']); return true; } catch { return false; } })();
const headCommit = isGit ? run('git', ['-C', repo, 'rev-parse', 'HEAD']).toString().trim() : undefined;
const digest = (buf) => Object.fromEntries(['sha1', 'sha256', 'sha512'].map((a) => [a, crypto.createHash(a).update(buf).digest('hex')]));

// Hash the committed blob when the file is tracked: core.autocrlf and similar filters rewrite the
// working copy, so hashing it would give values nobody else can reproduce.
const readRepoFile = (p) => {
  if (isGit) {
    try {
      run('git', ['-C', repo, 'ls-files', '--error-unmatch', p]);
      return run('git', ['-C', repo, 'show', `HEAD:${p.replace(/\\/g, '/')}`]);
    } catch { /* untracked: fall through to the working copy */ }
  }
  return fs.readFileSync(path.join(repo, p));
};
// Node's fetch ignores the system proxy and certificate store; fall back to curl, which uses them.
const fetchBuf = async (url) => {
  try {
    const res = await fetch(url, { redirect: 'follow' });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return Buffer.from(await res.arrayBuffer());
  } catch (e) {
    try { return run('curl', ['-sSfL', url]); } catch { throw new Error(`${e.message}; curl also failed`); }
  }
};

const SPDX_ID = /^(LicenseRef-[A-Za-z0-9.-]+|[A-Za-z0-9.+-]+)$/;
const isSpdxExpr = (s) => !!s && s.replace(/[()]/g, ' ').split(/\s+(?:AND|OR|WITH)\s+/).every((p) => SPDX_ID.test(p.trim()));
const slug = (s) => String(s).replace(/[^A-Za-z0-9.-]+/g, '-').replace(/^-+|-+$/g, '');
const licenseRef = (s) => `LicenseRef-${slug(s)}`;

// ---------- import tool-generated CycloneDX (lockfile ecosystems) ----------
const components = (inv.components || []).map((c) => ({ ...c }));
for (const imp of inv.import || []) {
  const bom = JSON.parse(fs.readFileSync(path.resolve(path.dirname(invFile), imp.path), 'utf8'));
  const rootRef = bom.metadata?.component?.['bom-ref'];
  const graph = Object.fromEntries((bom.dependencies || []).map((d) => [d.ref, d.dependsOn || []]));
  const direct = new Set(graph[rootRef] || []);
  const flat = [];
  const walk = (cs) => { for (const c of cs || []) { flat.push(c); walk(c.components); } };
  walk(bom.components);
  for (const c of flat) {
    if (c.type === 'file') continue;
    const lic = (c.licenses || []).map((l) => l.expression || l.license?.id || l.license?.name).filter(Boolean);
    const expr = lic.length === 1 ? lic[0] : lic.length ? lic.map((l) => (isSpdxExpr(l) && /\s/.test(l) ? `(${l})` : l)).join(' AND ') : undefined;
    const producer = c.supplier?.name || c.publisher || c.author || c.authors?.[0]?.name || c.manufacturer?.name;
    components.push({
      key: c['bom-ref'] || c.purl || `${c.name}@${c.version}`,
      ref: c['bom-ref'],
      name: c.group ? `${c.group}/${c.name}` : c.name,
      version: c.version,
      type: c.type,
      purl: c.purl,
      cpe: c.cpe,
      producer: producer ? { name: producer } : undefined,
      license: expr && isSpdxExpr(expr) ? expr : undefined,
      declared: expr,
      description: c.description,
      hashes: c.hashes,
      website: (c.externalReferences || []).find((r) => r.type === 'website')?.url,
      download: (c.externalReferences || []).find((r) => r.type === 'distribution')?.url,
      scope: c.scope,
      used: c.scope !== 'excluded',
      direct: direct.has(c['bom-ref']),
      dependsOn: graph[c['bom-ref']] || [],
      source: `imported from ${imp.path}${imp.tool ? ` (${imp.tool})` : ''}`,
    });
  }
  if (imp.tool) inv.tools = [...(inv.tools || []), { name: imp.tool.split('@')[0], version: imp.tool.split('@')[1] }];
}
const byKey = Object.fromEntries(components.map((c) => [c.key, c]));
const refOf = (c) => c.ref || (c.purl && c.version ? c.purl : `component:${slug(c.key)}`);
const resolveDep = (k) => (byKey[k] ? refOf(byKey[k]) : components.find((c) => c.ref === k) ? k : undefined);

// ---------- hashes ----------
const main = async () => {
  for (const c of components) {
    c.fileHashes = [];
    for (const f of c.files || []) {
      try {
        if (f.path) c.fileHashes.push({ name: f.path, local: true, ...digest(readRepoFile(f.path)) });
        else if (f.url && !flag('--no-fetch')) c.fileHashes.push({ name: f.name || f.url.split('?')[0].split('/').pop(), url: f.url, ...digest(await fetchBuf(f.url)) });
        else if (f.url) gap(`${c.name}: extern bestand ${f.url} niet gehasht (--no-fetch)`);
      } catch (e) {
        gap(`${c.name}: kon ${f.path || f.url} niet hashen (${e.message})`);
      }
    }
  }
  // A library bundled inside another component's file (yepnope in modernizr.js, Popper in
  // bootstrap.bundle.js) has no file of its own; it carries the hash of the file it lives in.
  for (const c of components.filter((x) => x.embeddedIn)) {
    const host = byKey[c.embeddedIn];
    if (!host) { gap(`${c.name}: embeddedIn verwijst naar onbekende component ${c.embeddedIn}`); continue; }
    c.hostFile = host.fileHashes.find((f) => !c.embeddedFile || f.name === c.embeddedFile || (f.url || '').includes(c.embeddedFile));
    if (!c.hostFile) gap(`${c.name}: omringend bestand ${c.embeddedFile || ''} van ${host.name} niet gehasht`);
    if (c.used === undefined) c.used = host.used;
    if (c.bundled === undefined) c.bundled = false;
  }

  // ---------- vulnerabilities (OSV) ----------
  const vulns = [];
  if (!flag('--no-osv')) {
    const found = await osv.lookup(components);
    vulns.push(...found.vulns);
    for (const e of found.errors) gap(`opzoeken van kwetsbaarheden bij api.osv.dev mislukt (${e}); VEX is onvolledig`);
  }

  // ---------- CycloneDX 1.7 ----------
  const now = new Date().toISOString().replace(/\.\d+Z$/, 'Z');
  const uuid = crypto.randomUUID();
  const p = inv.product;
  const productVersion = opt('--version') || p.version || headCommit;
  if (!productVersion) gap('Product: geen versie (geen product.version en geen git-repository)');
  const ghMatch = (p.vcs || '').match(/github\.com\/([^/]+)\/([^/.]+)/);
  const productPurl = p.purl || (ghMatch ? `pkg:github/${ghMatch[1]}/${ghMatch[2]}${productVersion ? `@${productVersion}` : ''}` : undefined);
  const rootRef = productPurl || `product:${slug(p.name)}`;
  const org = (o) => (o ? { name: o.name, url: o.url ? [].concat(o.url) : undefined } : undefined);
  const cdxHashes = (h) => [['SHA-1', h.sha1], ['SHA-256', h.sha256], ['SHA-512', h.sha512]].map(([alg, content]) => ({ alg, content }));

  const cdxLicenses = (c) => {
    if (c.license) return [{ expression: c.license, acknowledgement: 'concluded' }];
    if (c.declared) return [{ license: { name: c.declared, acknowledgement: 'declared' } }];
    return undefined;
  };
  const cdxComponent = (c) => {
    const single = c.hostFile || (c.fileHashes.length === 1 && c.fileHashes[0].local ? c.fileHashes[0] : null);
    const nested = !single && c.fileHashes.length ? c.fileHashes : [];
    const props = [];
    if (c.usage) props.push({ name: 'geonovum-sbom:usage', value: c.usage });
    if (c.source) props.push({ name: 'geonovum-sbom:source', value: c.source });
    if (c.hostFile) {
      props.push({ name: 'geonovum-sbom:embedded-in', value: refOf(byKey[c.embeddedIn]) });
      props.push({ name: 'geonovum-sbom:hash-scope', value: `hash of the containing file ${c.hostFile.name}, which also holds ${byKey[c.embeddedIn].name}` });
    }
    const evidence = {};
    if (c.hostFile) evidence.occurrences = [{ location: c.hostFile.url || c.hostFile.name }];
    else if (c.fileHashes.some((f) => f.local)) evidence.occurrences = c.fileHashes.filter((f) => f.local).map((f) => ({ location: f.name }));
    if (c.declared && c.license && c.declared !== c.license) {
      evidence.licenses = [isSpdxExpr(c.declared)
        ? { expression: c.declared, acknowledgement: 'declared' }
        : { license: { name: c.declared, acknowledgement: 'declared' } }];
    }
    if (c.copyright) evidence.copyright = [{ text: c.copyright }];
    return {
      type: c.type || 'library',
      'bom-ref': refOf(c),
      supplier: org(c.producer),
      name: c.name,
      ...(c.external && c.range && !c.version ? { isExternal: true, versionRange: c.range.startsWith('vers:') ? c.range : `vers:generic/${c.range}` } : { version: c.version }),
      ...(c.external && c.version ? { isExternal: true } : {}),
      description: c.description,
      // Shipped-but-unused files stay "required": scanners often skip "excluded", and the files are still delivered.
      scope: c.scope || 'required',
      hashes: single ? cdxHashes(single) : c.hashes,
      licenses: cdxLicenses(c),
      copyright: c.copyright,
      cpe: c.cpe,
      purl: c.purl,
      externalReferences: [
        c.website && { type: 'website', url: c.website },
        c.download && { type: 'distribution', url: c.download },
        c.vcs && { type: 'vcs', url: c.vcs },
      ].filter(Boolean),
      properties: props,
      evidence: Object.keys(evidence).length ? evidence : undefined,
      components: nested.map((f) => ({
        type: 'file',
        'bom-ref': `${refOf(c)}#${f.name}`,
        name: f.name,
        hashes: cdxHashes(f),
        externalReferences: f.url ? [{ type: 'distribution', url: f.url }] : undefined,
      })),
    };
  };

  // Direct runtime dependencies of the product: components marked used (or direct for imports).
  const rootDeps = components.filter((c) => !c.embeddedIn && (c.direct !== undefined ? c.direct : c.used !== false)).map(refOf);
  const embeddedRefs = (c) => components.filter((x) => x.embeddedIn === c.key).map(refOf);
  const cdxVulns = [];
  const vexFor = (v) => {
    const id = osv.vulnId(v);
    const o = (inv.vex || {})[`${id}@${v.c.key}`] || (inv.vex || {})[id] || (inv.vex || {})[v.osvId];
    if (o) return { id, ...o };
    if (v.c.used === false) {
      return {
        id, state: 'not_affected', justification: 'code_not_reachable',
        detail: v.c.usage ? `Not used by the product: ${v.c.usage}.` : 'The component is not used by the product, so the vulnerable code never runs.',
      };
    }
    return { id, state: 'in_triage', detail: 'Not analysed yet: the component is used by the product.' };
  };
  for (const v of vulns) {
    const a = vexFor(v);
    const fixed = osv.fixedVersions(v);
    const sev = osv.severity(v);
    const isCve = a.id.startsWith('CVE-');
    const existing = cdxVulns.find((x) => x.id === a.id);
    // OSV often has several records (GHSA, PYSEC, ...) for one CVE and package; list each component once.
    if (existing) {
      if (!existing.affects.some((x) => x.ref === refOf(v.c))) {
        existing.affects.push({ ref: refOf(v.c), versions: [{ version: v.c.version, status: a.state === 'not_affected' ? 'unaffected' : 'affected' }] });
      }
      continue;
    }
    cdxVulns.push({
      'bom-ref': `vuln-${a.id}-${slug(v.c.key)}`,
      id: a.id,
      source: isCve ? { name: 'NVD', url: `https://nvd.nist.gov/vuln/detail/${a.id}` } : { name: 'OSV', url: `https://osv.dev/vulnerability/${a.id}` },
      references: [v.osvId, ...(v.d.aliases || [])].filter((x, i, arr) => x !== a.id && arr.indexOf(x) === i)
        .map((x) => ({ id: x, source: { name: 'OSV', url: `https://osv.dev/vulnerability/${x}` } })),
      ratings: sev ? [{ source: { name: 'OSV' }, severity: sev }] : undefined,
      description: v.d.summary,
      recommendation: fixed.length ? `Upgrade ${v.c.name} to a fixed version (${fixed.join(', ')})${v.c.used === false ? ', or remove it' : ''}.` : undefined,
      analysis: {
        state: a.state, justification: a.justification, response: a.response, detail: a.detail,
        firstIssued: now, lastUpdated: now,
      },
      affects: [{ ref: refOf(v.c), versions: [{ version: v.c.version, status: a.state === 'not_affected' ? 'unaffected' : 'affected' }] }],
    });
  }

  const tools = [{ type: 'application', name: TOOL.name, version: TOOL.version }, ...(inv.tools || []).map((t) => ({ type: 'application', name: t.name, version: t.version }))];
  const cdx = {
    $schema: 'http://cyclonedx.org/schema/bom-1.7.schema.json',
    bomFormat: 'CycloneDX',
    specVersion: '1.7',
    serialNumber: `urn:uuid:${uuid}`,
    version: inv.sbomVersion || 1,
    metadata: {
      timestamp: now,
      lifecycles: [{ phase: inv.lifecycle || 'pre-build' }],
      tools: { components: tools },
      // The commit the SBOM describes, so that scan_repo.js --since can tell what changed after it.
      properties: headCommit ? [{ name: 'geonovum-sbom:commit', value: headCommit }] : undefined,
      // CycloneDX authors only take name, email and phone.
      authors: inv.author ? [{ name: inv.author.name, email: inv.author.email, phone: inv.author.phone }] : undefined,
      manufacturer: org(p.supplier),
      supplier: org(p.supplier),
      component: {
        type: p.type || 'application',
        'bom-ref': rootRef,
        supplier: org(p.supplier),
        name: p.name,
        version: productVersion,
        description: p.description,
        licenses: p.license ? [isSpdxExpr(p.license) ? { expression: p.license, acknowledgement: 'declared' } : { license: { name: p.license, acknowledgement: 'declared' } }] : undefined,
        copyright: p.copyright,
        purl: productPurl,
        externalReferences: [p.vcs && { type: 'vcs', url: p.vcs }, p.website && { type: 'website', url: p.website }].filter(Boolean),
      },
    },
    components: components.map(cdxComponent),
    dependencies: [
      { ref: rootRef, dependsOn: rootDeps },
      ...components.map((c) => ({ ref: refOf(c), dependsOn: [...(c.dependsOn || []).map(resolveDep).filter(Boolean), ...embeddedRefs(c)] })),
    ],
    compositions: [
      { aggregate: inv.complete ? 'complete' : 'incomplete', assemblies: [rootRef] },
      { aggregate: inv.complete ? 'complete' : 'incomplete', dependencies: [rootRef] },
    ],
    vulnerabilities: cdxVulns.length ? cdxVulns : undefined,
  };

  // ---------- SPDX 2.3 ----------
  const used = new Set();
  const sid = (s) => { let id = `SPDXRef-${slug(s)}`; let n = 1; while (used.has(id)) id = `SPDXRef-${slug(s)}-${++n}`; used.add(id); return id; };
  const extracted = {};
  const spdxLicense = (s) => {
    if (!s) return 'NOASSERTION';
    if (isSpdxExpr(s)) return s;
    const id = licenseRef(s);
    extracted[id] = { licenseId: id, name: s, extractedText: `License as stated by the component: "${s}"` };
    return id;
  };
  const spdxSums = (h) => [['SHA1', h.sha1], ['SHA256', h.sha256], ['SHA512', h.sha512]].map(([algorithm, checksumValue]) => ({ algorithm, checksumValue }));
  const cdxToSpdxAlg = { 'SHA-1': 'SHA1', 'SHA-256': 'SHA256', 'SHA-384': 'SHA384', 'SHA-512': 'SHA512', MD5: 'MD5', 'SHA3-256': 'SHA3-256', 'SHA3-512': 'SHA3-512', 'BLAKE2b-256': 'BLAKE2b-256' };
  const purpose = (t) => ({ library: 'LIBRARY', framework: 'FRAMEWORK', application: 'APPLICATION', container: 'CONTAINER', 'operating-system': 'OPERATING-SYSTEM', device: 'DEVICE', firmware: 'FIRMWARE', file: 'FILE' }[t] || 'OTHER');
  const files = [];
  const rels = [];
  const rootId = sid('Package-product');
  rels.push({ spdxElementId: 'SPDXRef-DOCUMENT', relationshipType: 'DESCRIBES', relatedSpdxElement: rootId });
  const pkgId = {};
  const packages = [{
    SPDXID: rootId,
    name: p.name,
    versionInfo: productVersion,
    supplier: p.supplier ? `Organization: ${p.supplier.name}` : 'NOASSERTION',
    originator: p.supplier ? `Organization: ${p.supplier.name}` : undefined,
    downloadLocation: p.vcs ? `git+${p.vcs.replace(/\.git$/, '')}.git${headCommit ? `@${headCommit}` : ''}` : 'NOASSERTION',
    homepage: p.website,
    filesAnalyzed: false,
    licenseConcluded: spdxLicense(p.license),
    licenseDeclared: spdxLicense(p.license),
    copyrightText: p.copyright || 'NOASSERTION',
    description: p.description,
    primaryPackagePurpose: purpose(p.type || 'application'),
    externalRefs: productPurl ? [{ referenceCategory: 'PACKAGE-MANAGER', referenceType: 'purl', referenceLocator: productPurl }] : undefined,
  }];
  for (const c of components) {
    const id = sid(`Package-${c.key}`);
    pkgId[refOf(c)] = id;
    const fids = c.fileHashes.map((f) => {
      const fid = sid(`File-${c.key}-${f.name}`);
      files.push({
        SPDXID: fid,
        fileName: `./${f.name.replace(/^\.?\//, '')}`,
        checksums: spdxSums(f),
        licenseConcluded: c.license ? spdxLicense(c.license) : 'NOASSERTION',
        licenseInfoInFiles: [c.declared ? spdxLicense(c.declared) : 'NOASSERTION'],
        copyrightText: c.copyright || 'NOASSERTION',
        comment: f.url ? `Downloaded from ${f.url}` : undefined,
      });
      rels.push({ spdxElementId: id, relationshipType: 'CONTAINS', relatedSpdxElement: fid });
      return f;
    });
    const sums = c.hostFile ? spdxSums(c.hostFile) : c.fileHashes.length === 1 ? spdxSums(c.fileHashes[0])
      : (c.hashes || []).filter((h) => cdxToSpdxAlg[h.alg]).map((h) => ({ algorithm: cdxToSpdxAlg[h.alg], checksumValue: h.content }));
    const advisories = cdxVulns.filter((v) => v.affects.some((a) => a.ref === refOf(c)));
    packages.push({
      SPDXID: id,
      name: c.name,
      versionInfo: c.version,
      supplier: c.producer ? `Organization: ${c.producer.name}` : 'NOASSERTION',
      originator: c.producer ? `Organization: ${c.producer.name}` : undefined,
      downloadLocation: c.download || c.vcs || 'NOASSERTION',
      homepage: c.website,
      filesAnalyzed: fids.length > 0,
      packageVerificationCode: fids.length ? { packageVerificationCodeValue: crypto.createHash('sha1').update(fids.map((f) => f.sha1).sort().join('')).digest('hex') } : undefined,
      checksums: sums.length ? sums : undefined,
      licenseConcluded: c.license ? spdxLicense(c.license) : 'NOASSERTION',
      licenseDeclared: c.declared ? spdxLicense(c.declared) : 'NOASSERTION',
      licenseInfoFromFiles: fids.length ? [c.declared ? spdxLicense(c.declared) : 'NOASSERTION'] : undefined,
      copyrightText: c.copyright || 'NOASSERTION',
      description: c.description,
      comment: [
        c.external && `Provided by the deployment environment, not bundled${c.range ? `; accepted versions ${c.range}` : ''}.`,
        c.usage,
        c.source,
        c.hostFile && `Embedded in ${byKey[c.embeddedIn].name}; the checksums are those of the containing file ${c.hostFile.name}.`,
      ].filter(Boolean).join(' ') || undefined,
      primaryPackagePurpose: purpose(c.type),
      externalRefs: [
        c.purl && { referenceCategory: 'PACKAGE-MANAGER', referenceType: 'purl', referenceLocator: c.purl },
        c.cpe && { referenceCategory: 'SECURITY', referenceType: 'cpe23Type', referenceLocator: c.cpe },
        ...advisories.map((v) => ({
          referenceCategory: 'SECURITY', referenceType: 'advisory', referenceLocator: v.source.url,
          comment: `${v.id}: ${v.analysis.state}${v.analysis.detail ? ` - ${v.analysis.detail}` : ''}`,
        })),
      ].filter(Boolean),
    });
  }
  for (const c of components) {
    const id = pkgId[refOf(c)];
    if (c.bundled) rels.push({ spdxElementId: rootId, relationshipType: 'CONTAINS', relatedSpdxElement: id });
    if (c.embeddedIn && byKey[c.embeddedIn]) rels.push({ spdxElementId: pkgId[refOf(byKey[c.embeddedIn])], relationshipType: 'CONTAINS', relatedSpdxElement: id });
    if (rootDeps.includes(refOf(c))) rels.push({ spdxElementId: rootId, relationshipType: 'DEPENDS_ON', relatedSpdxElement: id });
    for (const d of (c.dependsOn || []).map(resolveDep).filter(Boolean)) {
      if (pkgId[d]) rels.push({ spdxElementId: id, relationshipType: 'DEPENDS_ON', relatedSpdxElement: pkgId[d] });
    }
  }
  const spdx = {
    spdxVersion: 'SPDX-2.3',
    dataLicense: 'CC0-1.0',
    SPDXID: 'SPDXRef-DOCUMENT',
    name: `${p.name}${productVersion ? `-${String(productVersion).slice(0, 12)}` : ''}`,
    documentNamespace: `${(p.vcs || 'https://spdx.org/spdxdocs').replace(/\.git$/, '')}/sbom/spdx-2.3/${uuid}`,
    creationInfo: {
      created: now,
      creators: [
        ...tools.map((t) => `Tool: ${t.name.replace(/\s+/g, '-')}-${t.version || 'unknown'}`),
        p.supplier && `Organization: ${p.supplier.name}`,
        inv.author && `${inv.author.organization ? 'Organization' : 'Person'}: ${inv.author.name}${inv.author.email ? ` (${inv.author.email})` : ''}`,
      ].filter(Boolean),
      comment: `SBOM version ${inv.sbomVersion || 1}. Generation context: ${inv.lifecycle || 'pre-build'} (source). Companion CycloneDX 1.7 document: urn:uuid:${uuid}.`,
    },
    packages,
    files: files.length ? files : undefined,
    hasExtractedLicensingInfos: Object.keys(extracted).length ? Object.values(extracted) : undefined,
    relationships: rels,
  };

  // ---------- CISA 2026 minimum elements check ----------
  if (!inv.author) gap('SBOM Author: geen auteur in de inventaris');
  gap('SBOM Author Signature: de documenten zijn niet ondertekend; onderteken ze bij de release (bijvoorbeeld met cosign sign-blob) met de sleutel van de organisatie');
  for (const c of components) {
    const comp = cdx.components.find((x) => x['bom-ref'] === refOf(c));
    const hasHash = (comp.hashes || []).length || (comp.components || []).some((f) => (f.hashes || []).length);
    if (!c.producer) gap(`Component Producer ontbreekt: ${c.name}`);
    if (!c.version && !c.range) gap(`Component Version ontbreekt: ${c.name}`);
    if (!c.purl && !c.cpe) gap(`Component Identifier (purl/CPE) ontbreekt: ${c.name}`);
    if (!c.license) gap(`Component License niet vastgesteld: ${c.name}${c.declared ? ` (opgegeven: ${c.declared})` : ''}`);
    if (!hasHash) gap(`Component Hash ontbreekt: ${c.name}${c.external ? ' (geleverd door de omgeving; niets om te hashen)' : ''}`);
  }
  const triage = cdxVulns.filter((v) => v.analysis.state === 'in_triage');
  if (triage.length) gap(`VEX: ${triage.length} kwetsbaarheden staan op in_triage en vragen een analyse door een mens: ${triage.map((v) => v.id).join(', ')}`);

  const clean = (o) => JSON.parse(JSON.stringify(o, (k, v) => (Array.isArray(v) && v.length === 0 && k !== 'dependsOn' ? undefined : v)));
  fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(path.join(outDir, 'sbom.cdx.json'), JSON.stringify(clean(cdx), null, 2) + '\n');
  fs.writeFileSync(path.join(outDir, 'sbom.spdx.json'), JSON.stringify(clean(spdx), null, 2) + '\n');
  const report = [
    '# Ontbrekende CISA-elementen in de SBOM (2026 Minimum Elements)', '',
    `Gemaakt op ${now} met ${TOOL.name} ${TOOL.version} voor ${p.name} ${productVersion || ''}.`, '',
    `Componenten: ${components.length}. Kwetsbaarheden: ${cdxVulns.length} (${cdxVulns.filter((v) => v.analysis.state === 'not_affected').length} not_affected, ${triage.length} in_triage).`, '',
    ...(gaps.length ? gaps.map((g) => `- ${g}`) : ['Geen ontbrekende elementen gevonden.']), '',
  ].join('\n');
  fs.writeFileSync(path.join(outDir, 'sbom-gaps.md'), report);
  console.log(report);
};

main().catch((e) => { console.error(e); process.exit(1); });
