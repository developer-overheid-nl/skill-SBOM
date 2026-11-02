# SBOM-skill

Agent-skill van [Geonovum](https://www.geonovum.nl) voor het maken van een SBOM (software bill of materials) volgens de [2026 CISA Minimum Elements](https://www.cisa.gov/resources-tools/resources/2026-minimum-elements-software-bill-materials-sbom), als voorbereiding op de SBOM-verplichting uit de Cyber Resilience Act (CRA).

Een agent-skill is een map met een instructiedocument (`SKILL.md`) dat een AI-assistent erbij pakt zodra het onderwerp langskomt. De metadata staat in `publiccode.yml` en in de frontmatter van de skill, en de status staat in `nl.gov.status`.

> **Let op.** De skill is een hulpmiddel en levert geen conformiteitsverklaring. De opsteller van een SBOM blijft verantwoordelijk voor de inhoud. Zie [DISCLAIMER.md](DISCLAIMER.md).

## Skills

| Skill | Status | Doel |
| --- | --- | --- |
| [`geonovum-sbom`](skills/geonovum-sbom/SKILL.md) | concept | Maakt voor een repository een CycloneDX 1.7-SBOM met VEX en een SPDX 2.3-SBOM, met per component producent, versie, purl of CPE, licentie en hash, en een VEX-analyse van bekende kwetsbaarheden via OSV. Werkt ook voor repositories zonder lockfile: met meegeleverde (vendored) JavaScript- en CSS-bestanden, CDN-links en componenten die de server levert. |

De status `concept` betekent dat de skill nog niet is vastgesteld. Een hogere status vraagt een expertreview, een gepubliceerde reviewprocedure met acceptatiecriteria, en een test met minstens twee assistenten waarvan één open source of Europees.

## Installeren

Kopieer de map `skills/geonovum-sbom/` naar de skillmap van je assistent. Welke map dat is, staat in de documentatie van de assistent.

De repository is ook ingericht als plugin `geonovum-sbom`, met manifesten per assistent in de verborgen mappen. Zodra de skill via de [skills-marketplace van developer.overheid.nl](https://github.com/developer-overheid-nl/skills-marketplace) wordt aangeboden, staan de installatie-instructies per assistent in de README van die marketplace.

## Gebruik

Vraag je assistent om een SBOM voor een repository, bijvoorbeeld: "Maak een SBOM voor deze repo volgens de CISA minimum elements, in CycloneDX en SPDX." De skill:

1. brengt de repository in kaart: lockfiles, meegeleverde bestanden (ook bibliotheken die in een ander bestand zijn ingebed), CDN-links, en wat de server moet leveren;
2. laat voor ecosystemen met een lockfile een tool zoals cdxgen of syft de afhankelijkheidsboom maken;
3. schrijft een inventaris en maakt daarmee met `scripts/build_sbom.js` de twee SBOMs, met hashes van de gecommitte bestanden en kwetsbaarheden uit [OSV](https://osv.dev);
4. valideert beide bestanden offline tegen de meegeleverde schema's met `scripts/validate_sbom.js`;
5. rapporteert welke CISA-elementen nog ontbreken (zoals de handtekening) en welke kwetsbaarheden nog geanalyseerd moeten worden;
6. zet desgevraagd de inventaris en de workflow [`assets/workflows/sbom.yml`](skills/geonovum-sbom/assets/workflows/sbom.yml) in de repository. Die maakt de SBOMs dan bij elke GitHub-release opnieuw, valideert en ondertekent ze, en hangt ze aan de release. Elke week controleert hij de componenten opnieuw bij OSV.

Nodig: Node.js 18 of nieuwer en git. Voor de validatie installeert de skill [ajv](https://ajv.js.org) in een tijdelijke map; voor repositories met een lockfile gebruikt hij een SBOM-tool zoals [cdxgen](https://github.com/CycloneDX/cdxgen), na toestemming.

## Relatie tot de bronnen

| Bron | Rol |
| --- | --- |
| [2026 CISA Minimum Elements for a Software Bill of Materials](https://www.cisa.gov/resources-tools/resources/2026-minimum-elements-software-bill-materials-sbom) | Welke gegevens een SBOM minimaal moet bevatten (`nl.gov.source`) |
| [Cyber Resilience Act, bijlage I deel II](https://eur-lex.europa.eu/eli/reg/2024/2847/oj) | De wettelijke SBOM-verplichting voor producten met digitale elementen |
| [CycloneDX 1.7 (ECMA-424)](https://cyclonedx.org/specification/overview/) | Formaat van `sbom.cdx.json`, inclusief VEX |
| [SPDX 2.3](https://spdx.github.io/spdx-spec/v2.3/) | Formaat van `sbom.spdx.json` |
| [OSV](https://osv.dev) | Bron van bekende kwetsbaarheden |

De JSON-schema's in `skills/geonovum-sbom/assets/schemas/` zijn ongewijzigde kopieën van de officiële schema's van CycloneDX (Apache-2.0) en SPDX, voor validatie zonder netwerk.

## Testen

In `skills/geonovum-sbom/evals/` staan drie testcases: een repository zonder lockfile met meegeleverde bestanden, een Node.js-app met lockfile, en een Flask-app met alleen `requirements.txt`. Elke testcase heeft een prompt, invoerbestanden en controles die beschrijven wat een goed resultaat is.

## Bijdragen

Fouten in de skill meld je als [issue](https://github.com/fterpstra/skill-SBOM/issues). Werkafspraken voor wijzigingen staan in [CONTRIBUTING.md](CONTRIBUTING.md).

## Licentie

Copyright © 2026 Geonovum. Licensed under the EUPL.

De skill valt onder de [EUPL-1.2](LICENSE). Alle taalversies van de EUPL zijn gelijkwaardig; de [Nederlandse tekst](https://eur-lex.europa.eu/legal-content/NL/TXT/?uri=CELEX:32017D0863) staat in het Publicatieblad van de EU. De meegeleverde CycloneDX-schema's vallen onder Apache-2.0, het SPDX-schema onder de licentie van het SPDX-project.
