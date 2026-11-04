#!/usr/bin/env node
// Scans a repository for what goes into an SBOM inventory, so that the agent starts from facts
// with file and line instead of reading the whole repository: manifests and lockfiles, third-party
// files with the name and version from their header, libraries embedded in them, CDN links,
// what the environment has to provide, and where the metadata (author, license, product) is.
//
// Usage: node scan_repo.js [<repo>] [--since <git ref | sbom.cdx.json>] [--inventory <sbom-inventory.json>] [--json]
//   --since      only report what changed after that commit; an SBOM made by build_sbom.js 1.2+
//                records its commit, so the previous SBOM can be passed as is
//   --inventory  compare the findings with an existing inventory: what is missing, what is gone
//   --json       print JSON instead of Markdown
//
// The scan reads the files git tracks, so build output and node_modules are left out. It finds
// candidates; whether a candidate belongs in the SBOM, and with which purl, is still for the agent.

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const args = process.argv.slice(2);
const opt = (f) => { const i = args.indexOf(f); return i >= 0 ? args[i + 1] : undefined; };
const repo = path.resolve(args.find((a, i) => !a.startsWith('--') && !['--since', '--inventory'].includes(args[i - 1])) || '.');
const git = (...a) => execFileSync('git', ['-C', repo, ...a], { maxBuffer: 1 << 28, stdio: ['ignore', 'pipe', 'ignore'] }).toString();
const tryGit = (...a) => { try { return git(...a).trim(); } catch { return undefined; } };

// ---------- files ----------
const walk = (dir, base = '') => fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
  if (['.git', 'node_modules'].includes(e.name)) return [];
  const rel = base ? `${base}/${e.name}` : e.name;
  return e.isDirectory() ? walk(path.join(dir, e.name), rel) : [rel];
});
// Only the root of a repository: a folder inside another repository has none of its metadata.
const top = tryGit('rev-parse', '--show-toplevel');
const isGit = !!top && path.resolve(top).toLowerCase() === repo.toLowerCase();
const files = isGit ? git('ls-files', '-z').split('\0').filter(Boolean) : walk(repo);
const cache = {};
const read = (f) => {
  if (!(f in cache)) {
    try {
      const buf = fs.readFileSync(path.join(repo, f));
      cache[f] = buf.length > 5e6 || buf.includes(0) ? null : buf.toString('utf8');
    } catch { cache[f] = null; }
  }
  return cache[f];
};
const lineOf = (text, index) => text.slice(0, index).split('\n').length;
const base = (f) => f.split('/').pop();
const ext = (f) => (base(f).match(/\.([^.]+)$/) || [])[1]?.toLowerCase() || '';

// ---------- 1. manifests and lockfiles ----------
const ECOSYSTEMS = [
  { name: 'npm', cdxgen: 'js', manifest: /^package\.json$/, lock: /^(package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb?)$/ },
  { name: 'Python', cdxgen: 'python', manifest: /^(requirements.*\.txt|pyproject\.toml|setup\.py|setup\.cfg|Pipfile)$/, lock: /^(poetry\.lock|uv\.lock|Pipfile\.lock|pdm\.lock)$/ },
  { name: 'PHP', cdxgen: 'php', manifest: /^composer\.json$/, lock: /^composer\.lock$/ },
  { name: 'Go', cdxgen: 'go', manifest: /^go\.mod$/, lock: /^go\.sum$/ },
  { name: 'Rust', cdxgen: 'rust', manifest: /^Cargo\.toml$/, lock: /^Cargo\.lock$/ },
  { name: 'Java', cdxgen: 'java', manifest: /^(pom\.xml|build\.gradle(\.kts)?)$/, lock: /^gradle\.lockfile$/ },
  { name: 'Ruby', cdxgen: 'ruby', manifest: /^Gemfile$/, lock: /^Gemfile\.lock$/ },
  { name: '.NET', cdxgen: 'dotnet', manifest: /\.(cs|fs|vb)proj$/, lock: /^packages\.lock\.json$/ },
];
const ecosystems = ECOSYSTEMS.map((e) => ({
  name: e.name, cdxgen: e.cdxgen,
  manifests: files.filter((f) => e.manifest.test(base(f))),
  lockfiles: files.filter((f) => e.lock.test(base(f))),
})).filter((e) => e.manifests.length || e.lockfiles.length);
for (const e of ecosystems.filter((x) => x.name === 'Python')) {
  e.unpinned = e.manifests.filter((f) => /requirements.*\.txt$/.test(f)).flatMap((f) => (read(f) || '').split('\n')
    .map((l, i) => ({ l: l.trim(), i })).filter(({ l }) => l && !l.startsWith('#') && !l.startsWith('-') && !/==/.test(l))
    .map(({ l, i }) => `${f}:${i + 1} ${l}`));
}

// ---------- 2. third-party files ----------
const ASSET = new Set(['js', 'mjs', 'cjs', 'css', 'woff', 'woff2', 'ttf', 'eot', 'otf', 'swf']);
const VENDOR_DIR = /(^|\/)(vendor|vendors|lib|libs|third[_-]?party|external|resources|static|assets|public|dist|plugins)\//i;
const VERSION = /v?(\d+\.\d+(?:\.\d+)?(?:-[0-9A-Za-z.]+)?)/;
const NAME_VERSION = /([A-Za-z][A-Za-z0-9 .\-]{0,40}?)\s*[-:,(]?\s*v?(\d+\.\d+(?:\.\d+)?(?:-[0-9A-Za-z.]+)?)/;
const LICENSE = /\b(MIT|BSD[\w-]*|Apache(?:[- ]License)?[- ]?2(?:\.0)?|GPL[\w.-]*|LGPL[\w.-]*|ISC|MPL[\w.-]*|WTFPL|OFL[\w.-]*|CC0[\w.-]*|Unlicense)\b(?:\s*(?:&|and|\/)\s*(?:MIT|BSD|GPL[\w.-]*))?/;
const headerOf = (text) => {
  const m = text.match(/^\s*(?:\/\*[\s\S]*?\*\/|(?:\/\/[^\n]*\n)+)/);
  return m ? m[0].slice(0, 2000) : '';
};
const thirdParty = [];
for (const f of files.filter((x) => ASSET.has(ext(x)))) {
  const text = ['woff', 'woff2', 'ttf', 'eot', 'otf', 'swf'].includes(ext(f)) ? '' : read(f);
  const header = text ? headerOf(text) : '';
  // A header that imports or points at another file names that file, not this one.
  const fromHeader = /@import|url\(/.test(header) ? null : header.match(NAME_VERSION);
  const fromName = base(f).match(new RegExp(`^(.+?)[-.@_]${VERSION.source}(?:\\.min)?\\.[a-z0-9]+$`));
  // Without a name and version, a file in a vendor-like folder counts only if its header names a license or copyright.
  if (!fromHeader && !fromName && !(VENDOR_DIR.test(f) && (LICENSE.test(header) || /copyright|\(c\)|©/i.test(header) || !text))) continue;
  // Other libraries inside the file: a comment that starts with a name and a version, after the header.
  const embedded = [];
  if (text) {
    const re = /\/\*!?\s*([A-Za-z][A-Za-z.\-]{1,30}?)\s*v?(\d+\.\d+\.\d+)/g;
    let m;
    while ((m = re.exec(text))) {
      if (m.index < header.length) continue;
      const name = m[1].replace(/[.-]+$/, '');
      if (fromHeader && name.toLowerCase() === fromHeader[1].trim().toLowerCase()) continue;
      if (!embedded.some((x) => x.name === name)) embedded.push({ name, version: m[2], line: lineOf(text, m.index) });
    }
  }
  thirdParty.push({
    path: f,
    name: fromHeader ? fromHeader[1].trim() : fromName ? fromName[1] : undefined,
    version: fromHeader ? fromHeader[2] : fromName ? fromName[2] : undefined,
    versionFrom: fromHeader ? 'kopregel' : fromName ? 'bestandsnaam' : undefined,
    license: (header.match(LICENSE) || [])[0],
    copyright: (header.match(/(?:\(c\)|©|copyright)[^\n*]{0,100}/i) || [])[0]?.trim(),
    headerLine: header ? header.split('\n').find((l) => l.replace(/[\s/*!]/g, '')).trim().slice(0, 160) : undefined,
    embedded,
  });
}

// ---------- 3. CDN and other external links ----------
const TEXT_SKIP = new Set(['md', 'markdown', 'rst', 'txt', 'lock', 'svg', 'map']);
const textFiles = files.filter((f) => !TEXT_SKIP.has(ext(f)) && !thirdParty.some((t) => t.path === f) && read(f) !== null);
const CDN_HOST = /(cdnjs\.cloudflare\.com|cdn\.jsdelivr\.net|unpkg\.com|bootstrapcdn\.com|ajax\.googleapis\.com|fonts\.googleapis\.com|fonts\.gstatic\.com|code\.jquery\.com|cdn\.[\w.-]+|static\.[\w.-]+)/i;
const LINK = [
  /<(?:script|img|iframe)\b[^>]*?\bsrc\s*=\s*["']((?:https?:)?\/\/[^"']+)["']/gi,
  /<link\b[^>]*?\bhref\s*=\s*["']((?:https?:)?\/\/[^"']+)["']/gi,
  /@import\s+(?:url\()?\s*["']?((?:https?:)?\/\/[^"')\s;]+)/gi,
  /url\(\s*["']?((?:https?:)?\/\/[^"')\s]+)/gi,
];
const external = [];
for (const f of textFiles) {
  const text = read(f);
  for (const re of LINK) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(text))) {
      const url = m[1];
      const pathPart = url.replace(/^(?:https?:)?\/\/[^/]+/, '').split(/[?#]/)[0];
      if (!CDN_HOST.test(url) && !/\.(m?js|css|woff2?|ttf|eot|otf)$/i.test(pathPart)) continue;
      const npm = pathPart.match(/\/(?:npm\/)?((?:@[\w.-]+\/)?[\w.-]+)@(\d[\w.-]*)/);
      const seg = pathPart.match(/\/([A-Za-z][\w.-]*?)\/v?(\d+\.\d+(?:\.\d+)?)\//);
      const file = pathPart.split('/').pop().match(/^([A-Za-z][\w-]*?)[-.@_]v?(\d+\.\d+(?:\.\d+)?)(?:\.(?:slim|min|bundle))*\.[a-z0-9]+$/);
      const guess = npm || seg || file;
      external.push({ url, file: f, line: lineOf(text, m.index), name: guess?.[1], version: guess?.[2] });
    }
  }
}

// ---------- 4. what the environment provides ----------
const environment = [];
const note = (what, file, line, value) => environment.push({ what, file, line, value: value.trim().slice(0, 160) });
for (const f of files) {
  const b = base(f);
  const text = read(f);
  if (text === null) continue;
  if (/^Dockerfile|\.Dockerfile$|^Containerfile/.test(b)) text.split('\n').forEach((l, i) => /^\s*FROM\s/i.test(l) && note('container-image', f, i + 1, l));
  if (['.python-version', '.nvmrc', '.node-version', '.tool-versions', 'runtime.txt', '.ruby-version', '.php-version'].includes(b)) note('runtime-versie', f, 1, text.split('\n')[0]);
  if (b === 'package.json') { try { const e = JSON.parse(text).engines; if (e) note('engines', f, lineOf(text, text.indexOf('"engines"')), JSON.stringify(e)); } catch { /* not JSON */ } }
  if (b === 'composer.json') {
    try {
      const req = JSON.parse(text).require || {};
      for (const [k, v] of Object.entries(req).filter(([k]) => k === 'php' || k.startsWith('ext-'))) note('composer require', f, lineOf(text, text.indexOf(`"${k}"`)), `${k} ${v}`);
    } catch { /* not JSON */ }
  }
  if (b === 'pyproject.toml') { const m = text.match(/requires-python\s*=\s*["']([^"']+)/); if (m) note('requires-python', f, lineOf(text, m.index), m[1]); }
  if (/^(README|INSTALL)/i.test(b)) {
    // Case-sensitive, so that index.php is not PHP; a line counts only with a version or a module.
    text.split('\n').forEach((l, i) => {
      if (/\b(PHP|Python|Node(?:\.js)?|Apache|Apach2|nginx|NGINX|Java|Ruby|Tomcat|MySQL|MariaDB|PostgreSQL|Postgres|Redis|mod_\w+)\b/.test(l) && /\b\d+\.\d+|mod_\w+|module/i.test(l)) note('README', f, i + 1, l);
    });
  }
  if (b === '.htaccess' || /(^|\/)(apache2?|httpd|nginx)\//i.test(f)) note('webserverconfiguratie', f, 1, `${f} (bepaalt welke bestanden publiek bereikbaar zijn)`);
}
// PHP extensions, from the functions and classes the code uses.
const PHP_EXT = {
  zip: /\bZipArchive\b/, openssl: /\bopenssl_\w+\s*\(/, curl: /\bcurl_\w+\s*\(/, mbstring: /\bmb_\w+\s*\(/,
  pdo: /\bnew\s+PDO\b|\bPDO::/, mysqli: /\bmysqli\b/, gd: /\bimage(create|png|jpeg|copyresampled)\w*\s*\(/,
  dom: /\bDOMDocument\b/, simplexml: /\bsimplexml_\w+\s*\(|\bSimpleXMLElement\b/, xml: /\bxml_parser_create\b/,
  intl: /\b(NumberFormatter|IntlDateFormatter|Collator)\b/, sodium: /\bsodium_\w+\s*\(/, ldap: /\bldap_\w+\s*\(/,
};
const phpExtensions = [];
for (const f of files.filter((x) => ext(x) === 'php')) {
  const text = read(f) || '';
  for (const [name, re] of Object.entries(PHP_EXT)) {
    const m = text.match(re);
    if (m && !phpExtensions.some((p) => p.name === name)) phpExtensions.push({ name, file: f, line: lineOf(text, m.index), match: m[0].trim() });
  }
}
// Reading an https URL with file_get_contents, fopen or copy needs the openssl extension for the stream wrapper.
const phpFiles = files.filter((x) => ext(x) === 'php');
const httpsUrl = phpFiles.find((f) => /['"]https:\/\//.test(read(f) || ''));
const streamRead = phpFiles.map((f) => ({ f, m: (read(f) || '').match(/\b(file_get_contents|fopen|copy)\s*\(/) })).find((x) => x.m);
if (httpsUrl && streamRead && !phpExtensions.some((p) => p.name === 'openssl')) {
  phpExtensions.push({ name: 'openssl', file: streamRead.f, line: lineOf(read(streamRead.f), streamRead.m.index), match: `${streamRead.m[1]}() met https-URL's (zoals in ${httpsUrl})` });
}

// ---------- 5. metadata: product, license, author ----------
const metadata = [];
const meta = (field, value, from) => value && metadata.push({ field, value: String(value).trim(), from });
meta('product.vcs', isGit && tryGit('remote', 'get-url', 'origin')?.replace(/\.git$/, ''), 'git remote get-url origin');
meta('product.version (laatste tag)', isGit && tryGit('describe', '--tags', '--abbrev=0'), 'git describe --tags --abbrev=0');
meta('author (wie de scan draait)', isGit && [tryGit('config', 'user.name'), tryGit('config', 'user.email') && `<${tryGit('config', 'user.email')}>`].filter(Boolean).join(' '), 'git config user.name / user.email');
for (const f of files.filter((x) => /^(LICEN[CS]E|COPYING)(\.\w+)?$/i.test(base(x)) && !x.includes('/'))) {
  const text = read(f) || '';
  meta('product.license (eerste regel)', text.split('\n').find((l) => l.trim()), `${f}:1`);
  const c = text.match(/^.*copyright.*$/im);
  if (c) meta('product.copyright', c[0], `${f}:${lineOf(text, c.index)}`);
}
const pc = files.find((f) => /^publiccode\.ya?ml$/.test(f));
if (pc) {
  const text = read(pc) || '';
  const grab = (re, field) => { const m = text.match(re); if (m) meta(field, m[1].replace(/^["']|["']$/g, ''), `${pc}:${lineOf(text, m.index)}`); };
  grab(/^name:\s*(.+)$/m, 'product.name');
  grab(/^\s+license:\s*(.+)$/m, 'product.license');
  grab(/^\s+mainCopyrightOwner:\s*(.+)$/m, 'product.supplier');
  grab(/^landingURL:\s*(.+)$/m, 'product.website');
  const contacts = text.slice(text.search(/^\s+contacts:/m)).match(/-\s*name:\s*(.+)/g) || [];
  if (text.search(/^\s+contacts:/m) >= 0) contacts.forEach((c) => meta('author (contact in publiccode.yml)', c.replace(/-\s*name:\s*/, ''), pc));
}
for (const f of ['.github/CODEOWNERS', 'CODEOWNERS', 'docs/CODEOWNERS'].filter((x) => files.includes(x))) {
  (read(f) || '').split('\n').filter((l) => l.trim() && !l.startsWith('#')).slice(0, 5).forEach((l) => meta('author (CODEOWNERS)', l, f));
}
for (const f of ['package.json', 'composer.json'].filter((x) => files.includes(x))) {
  try {
    const j = JSON.parse(read(f));
    meta('product.name', j.name, f); meta('product.version', j.version, f); meta('product.license', j.license, f);
    const a = j.author || (j.authors || [])[0];
    meta('author', typeof a === 'string' ? a : a && [a.name, a.email && `<${a.email}>`].filter(Boolean).join(' '), f);
  } catch { /* not JSON */ }
}
if (files.includes('pyproject.toml')) {
  const text = read('pyproject.toml') || '';
  for (const [re, field] of [[/^name\s*=\s*"([^"]+)"/m, 'product.name'], [/^version\s*=\s*"([^"]+)"/m, 'product.version'], [/^license\s*=\s*(?:\{[^}]*?"([^"]+)"|"([^"]+)")/m, 'product.license'], [/^authors\s*=\s*\[\s*\{([^}]+)\}/m, 'author']]) {
    const m = text.match(re); if (m) meta(field, m[1] || m[2], `pyproject.toml:${lineOf(text, m.index)}`);
  }
}

// ---------- 6. usage of third-party files ----------
// The file name as a reference, not as part of a longer name: elem.style.cssText is not style.css.
// SBOMs, the inventory and publiccode.yml name the files but do not load them.
const METADATA_FILE = /(^|\/)(sbom[^/]*\.json|publiccode\.ya?ml)$/i;
// A reference inside a comment, such as /*@import url("x.css");*/, loads nothing.
const uncommented = {};
const code = (f) => (uncommented[f] ??= (read(f) || '').replace(/\/\*[\s\S]*?\*\//g, '').replace(/<!--[\s\S]*?-->/g, ''));
for (const t of thirdParty) {
  const ref = new RegExp(`(^|[^\\w.-])${base(t.path).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?![\\w-])`);
  t.usedBy = [...textFiles, ...thirdParty.map((o) => o.path)].filter((f) => f !== t.path && !METADATA_FILE.test(f) && ref.test(code(f)));
}

// ---------- 7. changes since the previous SBOM ----------
let since;
if (opt('--since')) {
  let ref = opt('--since');
  if (/\.json$/i.test(ref) && fs.existsSync(ref)) {
    const bom = JSON.parse(fs.readFileSync(ref, 'utf8'));
    const p = (bom.metadata?.properties || []).find((x) => x.name === 'geonovum-sbom:commit');
    ref = p ? p.value : undefined;
    if (!ref) since = { error: `${opt('--since')} noemt geen commit (geonovum-sbom:commit); geef een tag of commit mee` };
  }
  if (ref) {
    const changed = (tryGit('diff', '--name-only', `${ref}`, 'HEAD') ?? '').split('\n').filter(Boolean);
    if (tryGit('rev-parse', '--verify', `${ref}^{commit}`) === undefined) since = { error: `onbekende ref ${ref}` };
    else {
      const linesChanged = (f, re) => (tryGit('diff', '-U0', ref, 'HEAD', '--', f) || '').split('\n').some((l) => /^[+-][^+-]/.test(l) && re.test(l));
      const isManifest = (f) => ECOSYSTEMS.some((e) => e.manifest.test(base(f)) || e.lock.test(base(f)));
      const isEnv = (f) => /^(Dockerfile|Containerfile|\.python-version|\.nvmrc|\.node-version|\.tool-versions|runtime\.txt|\.htaccess)/.test(base(f)) || /^(README|INSTALL)/i.test(base(f));
      since = {
        ref,
        changed: changed.length,
        manifests: changed.filter(isManifest),
        thirdParty: changed.filter((f) => ASSET.has(ext(f)) && (thirdParty.some((t) => t.path === f) || VENDOR_DIR.test(f) || !files.includes(f))),
        links: changed.filter((f) => !TEXT_SKIP.has(ext(f)) && files.includes(f) && linesChanged(f, /(?:src|href|@import|url\()[^\n]*\/\//i)),
        environment: changed.filter(isEnv),
        phpExtensions: changed.filter((f) => ext(f) === 'php' && files.includes(f) && linesChanged(f, new RegExp(Object.values(PHP_EXT).map((r) => r.source).join('|')))),
      };
      since.relevant = since.manifests.length + since.thirdParty.length + since.links.length + since.environment.length + since.phpExtensions.length > 0;
    }
  }
}

// ---------- 8. comparison with an existing inventory ----------
let inventory;
if (opt('--inventory')) {
  const inv = JSON.parse(fs.readFileSync(opt('--inventory'), 'utf8'));
  const invPaths = (inv.components || []).flatMap((c) => (c.files || []).filter((x) => x.path).map((x) => x.path.replace(/\\/g, '/')));
  const invUrls = (inv.components || []).flatMap((c) => (c.files || []).filter((x) => x.url).map((x) => x.url.replace(/^https?:/, '')));
  inventory = {
    gone: invPaths.filter((p) => !files.includes(p)),
    notInInventory: thirdParty.filter((t) => !invPaths.includes(t.path) && !/\.(woff2?|ttf|eot|otf)$/.test(t.path)).map((t) => t.path),
    linksNotInInventory: [...new Set(external.map((e) => e.url.replace(/^https?:/, '')).filter((u) => !invUrls.includes(u)))],
    lockfilesNotImported: ecosystems.flatMap((e) => e.lockfiles).filter(() => !(inv.import || []).length),
  };
}

// ---------- output ----------
const result = { repo, commit: isGit ? tryGit('rev-parse', 'HEAD') : undefined, ecosystems, thirdParty, external, environment, phpExtensions, metadata, since, inventory };
if (args.includes('--json')) {
  console.log(JSON.stringify(result, null, 2));
  process.exit(0);
}
const out = [];
const say = (...l) => out.push(...l);
say(`# Scan van ${path.basename(repo)}${result.commit ? ` op ${result.commit.slice(0, 12)}` : ''}`, '');
if (since) {
  say('## Sinds de vorige SBOM', '');
  if (since.error) say(`- ${since.error}`, '');
  else {
    say(`${since.changed} bestanden gewijzigd sinds ${since.ref.slice(0, 12)}.`, '');
    if (!since.relevant) say('Geen wijzigingen aan manifests, lockfiles, bestanden van derden, externe links, omgeving of PHP-extensies. De inventaris kan blijven zoals hij is: maak de SBOM opnieuw met build_sbom.js (nieuwe versie, hashes en kwetsbaarheden).', '');
    for (const [k, label] of [['manifests', 'Manifests en lockfiles'], ['thirdParty', 'Bestanden van derden'], ['links', 'Externe links gewijzigd in'], ['environment', 'Omgeving'], ['phpExtensions', 'PHP-extensies mogelijk gewijzigd in']]) {
      if (since[k].length) say(`- **${label}:** ${since[k].join(', ')}`);
    }
    say('');
  }
}
if (inventory) {
  say('## Vergeleken met de inventaris', '');
  if (!inventory.gone.length && !inventory.notInInventory.length && !inventory.linksNotInInventory.length && !inventory.lockfilesNotImported.length) say('Geen verschillen gevonden.');
  if (inventory.gone.length) say(`- **Staat in de inventaris, niet meer in de repo:** ${inventory.gone.join(', ')}`);
  if (inventory.notInInventory.length) say(`- **Bestanden van derden die niet in de inventaris staan:** ${inventory.notInInventory.join(', ')}`);
  if (inventory.linksNotInInventory.length) say(`- **Externe links die niet in de inventaris staan:** ${inventory.linksNotInInventory.join(', ')}`);
  if (inventory.lockfilesNotImported.length) say(`- **Lockfiles zonder import van tooluitvoer:** ${inventory.lockfilesNotImported.join(', ')}`);
  say('');
}
say('## Manifests en lockfiles', '');
if (!ecosystems.length) say('Geen gevonden. Alles wat van derden komt, staat dus als bestand in de repo, achter een externe link, of in de omgeving.');
for (const e of ecosystems) {
  say(`- **${e.name}:** manifests ${e.manifests.join(', ') || '-'}; lockfiles ${e.lockfiles.join(', ') || 'geen'}. ${e.lockfiles.length ? `Laat een tool de boom maken: \`npx --yes @cyclonedx/cdxgen@11 -t ${e.cdxgen} ...\`.` : 'Zonder lockfile bepaalt pas de installatie de indirecte versies (zie de buildstap in SKILL.md).'}`);
  if (e.unpinned?.length) say(`  Zonder vaste versie: ${e.unpinned.join('; ')}`);
}
say('', '## Bestanden van derden', '');
if (!thirdParty.length) say('Geen gevonden.');
for (const t of thirdParty) {
  say(`- \`${t.path}\`: ${t.name || '?'} ${t.version || '(versie onbekend)'}${t.versionFrom ? ` (uit ${t.versionFrom})` : ''}${t.license ? `, licentie in kop: ${t.license}` : ''}`);
  if (t.headerLine) say(`  Kop: \`${t.headerLine.replace(/`/g, "'")}\``);
  for (const x of t.embedded) say(`  Ingebed: ${x.name} ${x.version} (regel ${x.line})`);
  say(`  Geladen door: ${t.usedBy.length ? t.usedBy.join(', ') : '**niets gevonden**: waarschijnlijk ongebruikt (used: false), controleer dat'}`);
}
say('', '## Externe links', '');
if (!external.length) say('Geen gevonden.');
for (const e of external) say(`- ${e.url} (${e.file}:${e.line})${e.name ? `: ${e.name} ${e.version}` : ''}`);
say('', '## Omgeving', '');
if (!environment.length && !phpExtensions.length) say('Geen aanwijzingen gevonden.');
for (const e of environment) say(`- ${e.what}: \`${e.value.replace(/`/g, "'")}\` (${e.file}:${e.line})`);
for (const p of phpExtensions) say(`- PHP-extensie ${p.name}: \`${p.match}\` (${p.file}:${p.line})`);
say('', '## Metadata', '');
if (!metadata.length) say('Geen gevonden.');
for (const m of metadata) say(`- ${m.field}: ${m.value} (${m.from})`);
console.log(out.join('\n'));
