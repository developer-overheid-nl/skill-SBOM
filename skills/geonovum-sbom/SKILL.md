---
name: geonovum-sbom
description: "Maak een SBOM (software bill of materials) voor een repository als CycloneDX 1.7 met VEX én SPDX 2.3, volgens de 2026 CISA Minimum Elements en de Cyber Resilience Act (CRA): per component producent, versie, purl/CPE, licentie en hash, alle directe en indirecte afhankelijkheden, tool, auteur en generatiecontext, plus een VEX-analyse van bekende kwetsbaarheden via OSV. Werkt ook voor repositories zonder lockfile: met de hand meegeleverde (vendored) JavaScript/CSS-bestanden, CDN-links in HTML-, PHP- of andere templates, en componenten die de server levert (PHP, Apache, Node.js, Python). Gebruik deze skill zodra iemand vraagt om een SBOM, software bill of materials, sbom.cdx.json of sbom.spdx.json te maken, te vernieuwen of te controleren, om CycloneDX- of SPDX-bestanden, om CRA- of CISA-conformiteit van een SBOM, om VEX voor een project, om SBOMs automatisch bij elke release te laten maken, om een bestaande SBOM bij te werken of doorlopend op kwetsbaarheden te controleren, of om een overzicht van componenten en afhankelijkheden voor een aanbesteding of compliance, ook als het woord SBOM niet valt."
license: EUPL-1.2
allowed-tools: "Bash(node *) Bash(git *) Bash(sed *) Bash(grep *) Bash(cat *)"
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
| SBOM Author, Author Signature | `metadata.authors`; handtekening: zie stap 7 |
| Formaatnaam en -versie, SBOM-versie | `bomFormat`/`specVersion`, `version`; SPDX `spdxVersion` |
| Generatiecontext (voor de build, tijdens de build, of achteraf uit binaries) | `metadata.lifecycles`; SPDX `creationInfo.comment` |
| Toolnaam en toolversie | `metadata.tools`; SPDX `creators: Tool: ...` |
| Component Producer, Version, Identifiers (purl of CPE) | per component |
| Component Hash met algoritme, Component License | per component |
| Dekking: **alle** directe en indirecte afhankelijkheden, "no minimum depth" | ook wat een CDN-bestand zelf weer laadt of bevat |

Een SBOM die wel het formaat volgt maar deze gegevens mist, is voor afnemers en toezichthouders weinig waard. Het script zorgt voor de structuur; jouw werk is de inventaris juist en volledig krijgen.

## Werkwijze

Laat de tooling het werk doen en zoek zelf alleen waar die ophoudt. De meegeleverde scripts geven feiten met bestand en regel. Lees niet de hele repository door: dat kost veel en mist dingen die een script wel vindt.

### 1. Begin bij de vorige SBOM

Staat er al een SBOM of een `sbom-inventory.json`, maak dan geen nieuwe inventaris maar kijk wat er sindsdien veranderd is:

```bash
node <skillmap>/scripts/scan_repo.js <repo> --since <vorige sbom.cdx.json of tag> --inventory sbom-inventory.json
```

Een SBOM die met deze skill is gemaakt (versie 1.2 of later), noemt de commit die hij beschrijft; anders geef je de tag of commit van de vorige SBOM mee. Het script zegt welke manifests, lockfiles, bestanden van derden, externe links, omgevingsbestanden en PHP-extensies zijn gewijzigd, en wat er niet meer klopt met de inventaris.

- **Niets relevants gewijzigd:** de inventaris blijft zoals hij is. Ga door naar stap 6; het script maakt een nieuwe SBOM met de nieuwe versie, de hashes en de actuele kwetsbaarheden.
- **Wel wijzigingen:** werk alleen die bij, met stap 2 tot en met 5.

### 2. Draai de tooling

Eerst de scan van de hele repository:

```bash
node <skillmap>/scripts/scan_repo.js <repo>
```

Die geeft, met bestand en regel:

- **Manifests en lockfiles** per ecosysteem, en in `requirements.txt` de regels zonder vaste versie.
- **Bestanden van derden**: `.js`, `.css` en fonts met naam, versie en licentie uit de kopregel of de bestandsnaam, en bibliotheken die erin zijn ingebed (zoals yepnope in Modernizr).
- **Of ze geladen worden**: welke bestanden ernaar verwijzen, zonder commentaar mee te tellen. "Niets gevonden" wijst op `used: false`.
- **CDN- en andere externe links** in HTML, templates, PHP en CSS, met de naam en versie uit de URL.
- **Wat de omgeving levert**: `FROM` in Dockerfiles, runtimeversies, `engines`, `require.php` en `ext-*` in composer.json, versies in de README, en PHP-extensies uit de functies die de code gebruikt.
- **Metadata**: product, licentie, copyright, auteur en contactpersonen, elk met het bestand waar het staat.

Heeft de repo een lockfile, laat dan een tool de afhankelijkheidsboom maken, want met de hand mis je indirecte afhankelijkheden:

```bash
npx --yes @cyclonedx/cdxgen@11 -t <ecosysteem> -o bom.tool.cdx.json --spec-version 1.6 <repo>
```

`syft <repo> -o cyclonedx-json=bom.tool.cdx.json` kan ook. Schrijf de tooluitvoer buiten de repo en neem hem op via `import` in de inventaris. Vraag de gebruiker toestemming voordat je een tool downloadt die nog niet geïnstalleerd is. Let op twee dingen in tooluitvoer:

- Zonder geïnstalleerde `node_modules` markeert cdxgen indirecte afhankelijkheden soms als `optional`. Zijn het runtime-afhankelijkheden, zet de scope dan op `required`.
- Tooluitvoer heeft vaak geen producent per pakket. Vul die aan uit de registry (auteur, anders de eerste maintainer) en noem dat in het verslag.

### 3. Bouw, als de versies daarvan afhangen

Welke versies er echt geleverd worden, hangt af van de build. Met een lockfile ligt alles vast. Zonder lockfile, met versiebereiken in een manifest of met een `requirements.txt` zonder `==`, bepaalt pas de installatie welke versies het worden, en die kunnen per build verschillen. Een SBOM die dan alleen uit de broncode komt, beschrijft een gok.

Bouw of installeer in dat geval zoals de release wordt gebouwd, en laat de tool de geïnstalleerde boom lezen, bijvoorbeeld:

- **npm**: `npm ci --omit=dev`, dan cdxgen met `--required-only`.
- **Python**: installeer in een schone virtuele omgeving met de Python-versie en het platform uit de Dockerfile, dan cdxgen of `syft` op die omgeving. Kan dat niet, gebruik dan `pip install --dry-run --report` en zeg in het verslag dat een nieuwe build andere versies kan opleveren.
- **PHP**: `composer install --no-dev`, dan cdxgen op `vendor/`.
- **Een container-image**: `syft <image>` op het gebouwde image.

Zet `lifecycle` in de inventaris dan op `build`. Het beste gebeurt dit in de release-workflow (stap 8), zodat de SBOM de build van die release beschrijft. Heeft de repo geen buildstap, zoals een PHP-site met meegeleverde bestanden, dan is `pre-build` juist.

Vendored bestanden en CDN-links zitten nooit in de tooluitvoer, ook niet na een build. Die komen uit de scan.

### 4. Zoek zelf waar de tooling ophoudt

Loop de kandidaten uit de scan na. Neem ze niet blind over:

- **Naam of versie onbekend**: lees de kop van het bestand (`sed -n '1,15p' <bestand>`) of zoek naar een versie (`grep -m3 -nE 'v?[0-9]+\.[0-9]+\.[0-9]+' <bestand>`).
- **Ingebedde bibliotheken**: controleer de gevonden regel en neem de bibliotheek op als eigen component met `embeddedIn`. Bekende gevallen die de scan kan missen: Sizzle in jQuery, Popper in `bootstrap.bundle.js`.
- **CDN-bestanden**: haal ze op en kijk of ze zelf weer bestanden laden, zoals een CSS die fonts laadt. Die horen erbij, als bestanden van dezelfde component.
- **Gebruikt of niet**: "niets gevonden" is een aanwijzing, geen bewijs. Een bestand kan via een bundler, een variabele of een rewrite-regel geladen worden. Controleer het en leg de conclusie vast in `used` en `usage`, want die bepaalt de VEX-analyse. Ook een ongebruikt bestand blijft in de SBOM: het wordt geleverd en vaak publiek geserveerd.
- **Omgeving**: neem runtime, server en extensies uit de scan op als `external` met een `range`.
- **Eigen code**: de scan kan eigen bestanden in een map als `static/` melden. Neem geen eigen code, documentatie, afbeeldingen of logo's op als component, alleen software van derden en wat de omgeving moet leveren. De eigen code is het product (`product`).

### 5. Schrijf de inventaris

Schrijf een `inventory.json` volgens [`inventaris-formaat.md`](inventaris-formaat.md). Lees dat bestand voordat je begint; het beschrijft elk veld en de VEX-standaarden.

Haal de metavelden uit de bestanden die de scan noemt, niet uit de context van het gesprek. Controleer ze met een korte opdracht:

```bash
git remote get-url origin                                         # product.vcs
git describe --tags --abbrev=0                                    # product.version
sed -n '1p;/[Cc]opyright/p' LICENSE                               # licentie en copyrighthouder
sed -n '/^legal:/,/^[a-z]/p;/^maintenance:/,/^[a-z]/p' publiccode.yml   # licentie, eigenaar, contactpersonen
cat .github/CODEOWNERS                                            # beheerders
git config user.name; git config user.email                       # wie de SBOM nu maakt
```

Aandachtspunten die vaak fout gaan:

- **auteur**: de SBOM-auteur is wie verantwoordelijk is voor de SBOM, meestal de beheerder uit `publiccode.yml` of `CODEOWNERS`, anders wie de skill draait. Vraag het de gebruiker alleen als die bronnen ontbreken of elkaar tegenspreken. Is de auteur een organisatie of team, zet dan `"organization": true`.
- **purl**: gebruik het ecosysteem waar de code vandaan komt, ook als het bestand met de hand is gekopieerd (`pkg:npm/jquery@1.9.1`). Alleen zo vindt OSV de kwetsbaarheden.
- **licentie**: `declared` is wat de component zelf zegt, letterlijk. `license` is wat jij concludeert, als SPDX-expressie. Verschillen ze (de kop zegt "MIT & BSD", jij concludeert `MIT`), noem dat dan.
- **producent**: de organisatie die de component maakt (de OpenJS Foundation voor jQuery), niet de CDN.
- **productversie**: een release-tag als die er is, anders de versie uit het manifest. Ontbreken beide, dan vult het script de commit-hash in.

### 6. Maak en valideer de SBOM

```bash
node <skillmap>/scripts/build_sbom.js <inventory.json> --out <map>
```

Het script hasht bestanden uit de repo vanaf de **gecommitte versie** (`git show HEAD:pad`), niet vanaf de werkkopie. Op Windows zet `core.autocrlf` de regeleinden om, en dan krijg je hashes die niemand anders kan reproduceren. Externe bestanden worden gedownload en gehasht. Kwetsbaarheden komen van api.osv.dev. De commit komt in de SBOM, zodat stap 1 de volgende keer werkt.

Schrijf eerst naar een tijdelijke map en vergelijk met bestaande SBOMs in de repo voordat je iets overschrijft. Zeg wat er inhoudelijk verschilt.

Valideer daarna:

```bash
npm install --prefix <tijdelijke-map> ajv@8 ajv-formats@3
node <skillmap>/scripts/validate_sbom.js <map> --deps <tijdelijke-map>
```

Dit valideert offline tegen de meegeleverde schema's (CycloneDX 1.7 met subschema's, en SPDX 2.3). Het controleert ook of SPDX-relaties en `LicenseRef-`s kloppen. Is `cyclonedx-cli` (v0.30 of nieuwer) beschikbaar, valideer dan ook daarmee:
`cyclonedx validate --input-file sbom.cdx.json --input-version v1_7 --fail-on-errors`.
Los fouten op in de inventaris, niet door velden weg te laten.

### 7. Rond af met de gebruiker

Lees `sbom-gaps.md` en bespreek de open punten. Typisch zijn dat:

- **Handtekening**: het script ondertekent niet, want daarvoor is de sleutel van de organisatie nodig. Stel voor om bij de release te ondertekenen (bijvoorbeeld met `cosign sign-blob`) of de SBOM als release-asset met attestatie te publiceren.
- **Kwetsbaarheden op `in_triage`**: het script weet niet of de kwetsbare code bereikbaar is. Analyseer ze samen met de gebruiker, leg de uitkomst vast in `vex` in de inventaris en draai opnieuw. Maak van een gebruikte component alleen `not_affected` als je in de code aanwijst waarom de kwetsbare functie niet wordt aangeroepen, en schrijf die reden in `detail`. Zonder gebruiker om mee te overleggen mag je zo'n onderbouwde inschatting maken, maar zeg dat in het verslag.
- **Volledigheid van OSV**: OSV mist soms een melding voor een oude versie. Noem bekende CVE's die je mist in het verslag, met de vraag ze na te lopen.
- **Ongebruikte kwetsbare bestanden**: de eenvoudigste oplossing is ze te verwijderen. Stel dat voor.
- **Componenten zonder hash**: bij componenten die de omgeving levert (`external`) is dat normaal. Noem het, maar het is geen fout.
- **Ander risico dat je tegenkomt**, zoals CDN-links zonder Subresource Integrity of gebruikersinvoer die ongefilterd in de pagina komt: noem het kort, ook al hoort het niet in de SBOM.

Werk ook de README bij als die de SBOM-bestanden of hun formaat beschrijft. Stel voor de inventaris te committen, bijvoorbeeld als `sbom-inventory.json`, zodat de SBOM later reproduceerbaar te vernieuwen is.

### 8. Automatiseer: een SBOM bij elke release, en een doorlopende controle

Een SBOM hoort bij één versie. De kwetsbaarheden van die versie veranderen wel: er komen elke dag meldingen bij. Dat zijn twee aparte taken, met elk een eigen sjabloon:

- [`assets/workflows/sbom.yml`](assets/workflows/sbom.yml) maakt bij elke gepubliceerde release de SBOMs uit de gecommitte inventaris. Hij valideert ze, ondertekent ze met een build-attestatie van GitHub, en hangt ze als asset aan de release.
- [`assets/workflows/sbom-kwetsbaarheden.yml`](assets/workflows/sbom-kwetsbaarheden.yml) legt elke week de SBOM van de versie die in gebruik is naast OSV, met `check_vulns.js`. Dat is de SBOM die aan de release hangt, niet de broncode op de hoofdbranch. Welke release in gebruik is, staat in de repository-variabele `SBOM_IN_GEBRUIK`; zonder die variabele is het de laatste release. Wat nog beoordeeld moet worden, komt in een issue met het label `sbom`. Beoordelingen in het `vex`-blok van de inventaris tellen mee, ook als ze van na de release zijn.

Zo zet je het op:

1. Commit de inventaris als `sbom-inventory.json` in de root, met `"repo": "."`. Laat `product.version` weg: de workflow gebruikt de release-tag.
2. Kopieer beide sjablonen naar `.github/workflows/`. Vervang `__SKILL_REF__` door een release-tag of commit-SHA van de skill-repository. Gebruik nooit een branchnaam: dan komt elke wijziging aan de skill ongemerkt in de workflow terecht.
3. De actions in de sjablonen zijn vastgezet op een commit-hash, met het versienummer als commentaar. Een tag als `@v7` kan later naar andere code wijzen, een hash niet. Kopieer [`assets/dependabot.yml`](assets/dependabot.yml) naar `.github/dependabot.yml`, zodat Dependabot een pull request opent als er een nieuwe versie is.
4. Moeten de versies uit een build komen (stap 3), vul dan in `sbom.yml` de stap "Bouwen en afhankelijkheden lezen" in die als commentaar klaarstaat.
5. Haal gecommitte SBOMs weg zodra de eerste release met SBOM er is, en verwijs in de README naar de release-assets.

Heeft de repository geen releases, omdat de hoofdbranch direct wordt uitgerold? Stel dan voor om bij elke uitrol een tag te zetten. Beide workflows zijn ook met de hand te starten.

Een controle kan ook zonder workflow, op elke SBOM:

```bash
node <skillmap>/scripts/check_vulns.js sbom.cdx.json --vex sbom-inventory.json --out <map>
```

De inventaris blijft mensenwerk. Pas hem aan als er een component bijkomt, verdwijnt of een andere versie krijgt; stap 1 laat zien wanneer dat nodig is. Leg in het `vex`-blok vast hoe kwetsbaarheden uit de issues zijn beoordeeld.

## Wat je oplevert

- `sbom.cdx.json` en `sbom.spdx.json`, gevalideerd.
- Een kort verslag: welke componenten, welke kwetsbaarheden met welke VEX-status, wat er verschilt met de vorige SBOM (als die er was), welke aannames je deed, en de open punten uit `sbom-gaps.md`.
- Als de gebruiker dat wil: `sbom-inventory.json`, `.github/workflows/sbom.yml`, `.github/workflows/sbom-kwetsbaarheden.yml` en `.github/dependabot.yml`, zodat de SBOM bij elke release opnieuw wordt gemaakt en de kwetsbaarheden doorlopend worden gecontroleerd.
