---
name: geonovum-sbom
description: "Maak een SBOM (software bill of materials) voor een repository als CycloneDX 1.7 met VEX én SPDX 2.3, volgens de 2026 CISA Minimum Elements en de Cyber Resilience Act (CRA): per component producent, versie, purl/CPE, licentie en hash, alle directe en indirecte afhankelijkheden, tool, auteur en generatiecontext, plus een VEX-analyse van bekende kwetsbaarheden via OSV. Werkt ook voor repositories zonder lockfile: met de hand meegeleverde (vendored) JavaScript/CSS-bestanden, CDN-links in HTML-, PHP- of andere templates, en componenten die de server levert (PHP, Apache, Node.js, Python). Gebruik deze skill zodra iemand vraagt om een SBOM, software bill of materials, sbom.cdx.json of sbom.spdx.json te maken, te vernieuwen of te controleren, om CycloneDX- of SPDX-bestanden, om CRA- of CISA-conformiteit van een SBOM, om VEX voor een project, om SBOMs automatisch bij elke release te laten maken, of om een overzicht van componenten en afhankelijkheden voor een aanbesteding of compliance, ook als het woord SBOM niet valt."
license: EUPL-1.2
allowed-tools: "Bash(node *) Bash(git *)"
metadata:
  nl.gov.status: concept
  nl.gov.review-by: "2027-04-29"
  nl.gov.source: https://www.cisa.gov/resources-tools/resources/2026-minimum-elements-software-bill-materials-sbom
  nl.gov.category: beveiliging
  nl.gov.tags: sbom, cyclonedx, spdx, vex, cra, cisa, supply-chain, kwetsbaarheden
  nl.gov.bundle: geonovum-sbom
  nl.gov.generated-with: generatieve AI
---

> **Status: concept.** Deze skill is een hulpmiddel en geen conformiteitsverklaring. Een SBOM die met deze skill is gemaakt, voldoet niet vanzelf aan de CRA of aan andere regelgeving: de opsteller blijft verantwoordelijk voor de inhoud, en de officiële teksten van de [2026 CISA Minimum Elements](https://www.cisa.gov/resources-tools/resources/2026-minimum-elements-software-bill-materials-sbom), [CycloneDX](https://cyclonedx.org/specification/overview/) en [SPDX](https://spdx.dev/) zijn leidend. Overheidsorganisaties die generatieve AI inzetten dienen te voldoen aan het [Overheidsbreed standpunt voor de inzet van generatieve AI](https://open.overheid.nl/documenten/bc03ce31-0cf1-4946-9c94-e934a62ebe73/file). Zie ook de [disclaimer](https://github.com/fterpstra/skill-SBOM/blob/main/DISCLAIMER.md).

# SBOM volgens de CISA Minimum Elements 2026

Deze skill maakt twee SBOMs die elkaar aanvullen:

- **`sbom.cdx.json`**: CycloneDX 1.7, met de kwetsbaarheden en hun VEX-analyse in hetzelfde bestand.
- **`sbom.spdx.json`**: SPDX 2.3. Niet 3.0: de meeste tools lezen nog 2.3, en 2.2.1 is de ISO-norm (ISO/IEC 5962). SPDX 2.3 heeft geen VEX; kwetsbaarheden staan daar als `advisory`-verwijzing per pakket.

Daarnaast schrijft het script `sbom-gaps.md`: welke CISA-elementen nog ontbreken. Dat bestand is voor de gebruiker, niet om te committen.

## Wat CISA 2026 vraagt, en waarom het ertoe doet

De 2026 CISA Minimum Elements vervangen de NTIA-baseline uit 2021. Nieuw verplicht ten opzichte van 2021:

| Element | Waar het in de SBOM staat |
|---|---|
| SBOM Author, Author Signature | `metadata.authors`; handtekening: zie stap 6 |
| Formaatnaam en -versie, SBOM-versie | `bomFormat`/`specVersion`, `version`; SPDX `spdxVersion` |
| Generatiecontext (voor de build, tijdens de build, of achteraf uit binaries) | `metadata.lifecycles`; SPDX `creationInfo.comment` |
| Toolnaam en toolversie | `metadata.tools`; SPDX `creators: Tool: ...` |
| Component Producer, Version, Identifiers (purl of CPE) | per component |
| Component Hash met algoritme, Component License | per component |
| Dekking: **alle** directe en indirecte afhankelijkheden, "no minimum depth" | ook wat een CDN-bestand zelf weer laadt of bevat |

Een SBOM die wel het formaat volgt maar deze gegevens mist, is voor afnemers en toezichthouders weinig waard. Het script zorgt voor de structuur; jouw werk is de inventaris juist en volledig krijgen.

## Werkwijze

### 1. Breng de repository in kaart

Zoek uit wat er werkelijk geleverd en gebruikt wordt. Kijk naar:

- **Lockfiles en manifests**: `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `poetry.lock`, `uv.lock`, `Pipfile.lock`, `requirements*.txt` met vaste versies, `composer.lock`, `Cargo.lock`, `go.sum`, `pom.xml`, `gradle.lockfile`, `Gemfile.lock`.
- **Vendored bestanden**: `.js`, `.css` en fonts in `static/`, `vendor/`, `resources/`, `public/`, `lib/` en dergelijke. Lees de eerste regels: naam, versie, copyright en licentie staan meestal in de kopregel. Herken ook bestanden met een versie in de naam (`jquery-3.4.1.min.js`).
- **Ingebedde bibliotheken**: sommige bestanden bevatten een tweede bibliotheek. Voorbeelden zijn Sizzle in jQuery, yepnope in Modernizr, en Popper in `bootstrap.bundle.js`. Zoek in de kopregel en in commentaarblokken verderop in het bestand naar andere naam- en versieregels. Neem zo'n bibliotheek op als eigen component met `embeddedIn`, zodat hij met de hash van het omringende bestand in de SBOM komt en kwetsbaarheden ervan gevonden worden.
- **CDN- en andere externe links**: zoek in HTML, templates, PHP en JSX naar `<script src=`, `<link href=`, `@import` en `url(` met `//` of `https://`. Een CDN-bestand is een runtime-afhankelijkheid, ook al staat het niet in de repo. Haal het op en kijk of het zelf weer bestanden laadt, zoals een CSS die fonts laadt. Die horen erbij, als bestanden van dezelfde component.
- **Wat de omgeving levert**: runtime en server uit README, Dockerfile, CI-configuratie, `composer.json` `require.php`, `engines` in package.json of `.python-version`. Zoek naar gebruikte extensies, bijvoorbeeld `ZipArchive` voor de PHP zip-extensie. Neem deze op als `external` met een `range`.
- **Gebruikt of niet?** Zoek voor elk vendored bestand of een pagina of module het laadt. Ook een ongebruikt bestand blijft in de SBOM, want het wordt geleverd en vaak publiek geserveerd, maar dan met `used: false`. Dat bepaalt de VEX-analyse, dus controleer het echt met een zoekopdracht op de bestandsnaam.
- **Configuratie van webserver of build** (rewrite-regels, `static`-mappen, bundler-configuratie): die bepaalt of vendored bestanden publiek bereikbaar zijn. Noem dat in `usage`.

Neem geen eigen code, documentatie, afbeeldingen of logo's op als component; alleen software van derden en wat de omgeving moet leveren. De eigen code is het product (`product`).

### 2. Gebruik een tool voor ecosystemen met een lockfile

Heeft de repo een lockfile, laat dan een tool de afhankelijkheidsboom maken, want met de hand mis je indirecte afhankelijkheden. Bijvoorbeeld:

```bash
npx --yes @cyclonedx/cdxgen@11 -t <ecosysteem> -o bom.tool.cdx.json --spec-version 1.6 <repo>
```

`syft <repo> -o cyclonedx-json=bom.tool.cdx.json` kan ook. Schrijf de tooluitvoer buiten de repo en neem hem op via `import` in de inventaris. Vraag de gebruiker toestemming voordat je een tool downloadt die nog niet geïnstalleerd is.

Let op twee dingen in tooluitvoer:

- Zonder geïnstalleerde `node_modules` markeert cdxgen indirecte afhankelijkheden soms als `optional`. Zijn het runtime-afhankelijkheden, zet de scope dan op `required`.
- Tooluitvoer heeft vaak geen producent per pakket. Vul die aan uit de registry (auteur, anders de eerste maintainer) en noem dat in het verslag.

Is er alleen een `requirements.txt` met de directe afhankelijkheden, bepaal de indirecte dan met de pakketbeheerder voor het juiste platform, bijvoorbeeld `pip install --dry-run --report` voor de Python-versie en het besturingssysteem uit de Dockerfile. Zeg in het verslag dat een nieuwe build andere indirecte versies kan opleveren dan de draaiende installatie.

Vendored bestanden en CDN-links zitten nooit in de tooluitvoer, ook niet in een repo met lockfile. Voeg die altijd met de hand toe.

### 3. Schrijf de inventaris

Schrijf een `inventory.json` volgens [`inventaris-formaat.md`](inventaris-formaat.md). Lees dat bestand voordat je begint; het beschrijft elk veld en de VEX-standaarden.

Aandachtspunten die vaak fout gaan:

- **purl**: gebruik het ecosysteem waar de code vandaan komt, ook als het bestand met de hand is gekopieerd (`pkg:npm/jquery@1.9.1`). Alleen zo vindt OSV de kwetsbaarheden.
- **licentie**: `declared` is wat de component zelf zegt, letterlijk. `license` is wat jij concludeert, als SPDX-expressie. Verschillen ze (de kop zegt "MIT & BSD", jij concludeert `MIT`), noem dat dan.
- **producent**: de organisatie die de component maakt (de OpenJS Foundation voor jQuery), niet de CDN.
- **productversie**: een release-tag als die er is, anders de versie uit het manifest. Ontbreken beide, dan vult het script de commit-hash in.
- **auteur**: vraag de gebruiker wie als SBOM-auteur moet staan als dat niet uit de context blijkt. Is de auteur een organisatie of team, zet dan `"organization": true`.

### 4. Draai het script

```bash
node <skillmap>/scripts/build_sbom.js <inventory.json> --out <map>
```

Het script hasht bestanden uit de repo vanaf de **gecommitte versie** (`git show HEAD:pad`), niet vanaf de werkkopie. Op Windows zet `core.autocrlf` de regeleinden om, en dan krijg je hashes die niemand anders kan reproduceren. Externe bestanden worden gedownload en gehasht. Kwetsbaarheden komen van api.osv.dev.

Schrijf eerst naar een tijdelijke map en vergelijk met bestaande SBOMs in de repo voordat je iets overschrijft. Zeg wat er inhoudelijk verschilt.

### 5. Valideer

```bash
npm install --prefix <tijdelijke-map> ajv@8 ajv-formats@3
node <skillmap>/scripts/validate_sbom.js <map> --deps <tijdelijke-map>
```

Dit valideert offline tegen de meegeleverde schema's (CycloneDX 1.7 met subschema's, en SPDX 2.3). Het controleert ook of SPDX-relaties en `LicenseRef-`s kloppen. Is `cyclonedx-cli` (v0.30 of nieuwer) beschikbaar, valideer dan ook daarmee:
`cyclonedx validate --input-file sbom.cdx.json --input-version v1_7 --fail-on-errors`.
Los fouten op in de inventaris, niet door velden weg te laten.

### 6. Rond af met de gebruiker

Lees `sbom-gaps.md` en bespreek de open punten. Typisch zijn dat:

- **Handtekening**: het script ondertekent niet, want daarvoor is de sleutel van de organisatie nodig. Stel voor om bij de release te ondertekenen (bijvoorbeeld met `cosign sign-blob`) of de SBOM als release-asset met attestatie te publiceren.
- **Kwetsbaarheden op `in_triage`**: het script weet niet of de kwetsbare code bereikbaar is. Analyseer ze samen met de gebruiker, leg de uitkomst vast in `vex` in de inventaris en draai opnieuw. Maak van een gebruikte component alleen `not_affected` als je in de code aanwijst waarom de kwetsbare functie niet wordt aangeroepen, en schrijf die reden in `detail`. Zonder gebruiker om mee te overleggen mag je zo'n onderbouwde inschatting maken, maar zeg dat in het verslag.
- **Volledigheid van OSV**: OSV mist soms een melding voor een oude versie. Noem bekende CVE's die je mist in het verslag, met de vraag ze na te lopen.
- **Ongebruikte kwetsbare bestanden**: de eenvoudigste oplossing is ze te verwijderen. Stel dat voor.
- **Componenten zonder hash**: bij componenten die de omgeving levert (`external`) is dat normaal. Noem het, maar het is geen fout.
- **Ander risico dat je tegenkomt**, zoals CDN-links zonder Subresource Integrity of gebruikersinvoer die ongefilterd in de pagina komt: noem het kort, ook al hoort het niet in de SBOM.

Werk ook de README bij als die de SBOM-bestanden of hun formaat beschrijft. Stel voor de inventaris te committen, bijvoorbeeld als `sbom-inventory.json`, zodat de SBOM later reproduceerbaar te vernieuwen is.

### 7. Automatiseer: een SBOM bij elke release

Een SBOM hoort bij één versie. Stel daarom voor om hem bij elke release opnieuw te laten maken, in plaats van hem met de hand te verversen. Op GitHub gaat dat met het sjabloon [`assets/workflows/sbom.yml`](assets/workflows/sbom.yml). Bij het publiceren van een release maakt die workflow de SBOMs uit de gecommitte inventaris. Hij valideert ze, ondertekent ze met een build-attestatie van GitHub, en hangt ze als asset aan de release. Elke week legt hij de componenten opnieuw naast OSV en opent hij een issue als er kwetsbaarheden te beoordelen zijn.

Zo zet je het op:

1. Commit de inventaris als `sbom-inventory.json` in de root, met `"repo": "."`. Laat `product.version` weg: de workflow gebruikt de release-tag.
2. Kopieer het sjabloon naar `.github/workflows/sbom.yml`. Vervang `__SKILL_REF__` door een release-tag of commit-SHA van de skill-repository. Gebruik nooit een branchnaam: dan komt elke wijziging aan de skill ongemerkt in de workflow terecht.
3. Heeft de repository een lockfile, voeg dan vóór "SBOM maken" een stap toe die de tool draait (bijvoorbeeld cdxgen) en de uitvoer schrijft naar het pad dat in `import` staat.
4. Haal gecommitte SBOMs weg zodra de eerste release met SBOM er is, en verwijs in de README naar de release-assets.

Heeft de repository geen releases, omdat de hoofdbranch direct wordt uitgerold? Stel dan voor om bij elke uitrol een tag te zetten. De workflow is ook met de hand te starten; het resultaat staat dan als artefact bij de run.

De inventaris blijft mensenwerk. Pas hem aan als er een component bijkomt, verdwijnt of een andere versie krijgt, en leg in het `vex`-blok vast hoe kwetsbaarheden uit de issues zijn beoordeeld.

## Wat je oplevert

- `sbom.cdx.json` en `sbom.spdx.json`, gevalideerd.
- Een kort verslag: welke componenten, welke kwetsbaarheden met welke VEX-status, wat er verschilt met de vorige SBOM (als die er was), welke aannames je deed, en de open punten uit `sbom-gaps.md`.
- Als de gebruiker dat wil: `sbom-inventory.json` en `.github/workflows/sbom.yml`, zodat de SBOM bij elke release opnieuw wordt gemaakt.
