# Bijdragen aan de SBOM-skill

Allereerst bedankt dat je wilt bijdragen aan dit project! Zonder jouw input
wordt dit nooit een beter open source project.

## Code of Conduct

Dit project hanteert een [Code of Conduct](CODE_OF_CONDUCT.md). Door bij te
dragen aan dit project ga je akkoord met de voorwaarden hiervan.

## Hoe kan je bijdragen?

Er zijn verschillende manieren om bij te dragen aan dit project:

### Meld een bug

Heb je een bug gevonden? Maak dan een [issue](https://github.com/developer-overheid-nl/skill-sbom/issues/new) aan met:

- Een duidelijke en beschrijvende titel
- Stappen om de bug te reproduceren
- Verwacht gedrag vs. daadwerkelijk gedrag
- Foutmeldingen, de SBOM of het verslag dat de skill opleverde (indien van toepassing)
- Welke assistent je gebruikte en de versie van Node.js

### Features voorstellen

Heb je een idee voor een nieuwe feature? Open een issue met:

- Een duidelijke beschrijving van de feature
- Waarom deze feature waardevol zou zijn
- Eventuele voorbeelden, zoals een repository waarvoor de skill een onvolledige SBOM maakt

### Documentatie verbeteren

Documentatie kan altijd beter! Pull requests voor verbeteringen aan de
documentatie zijn zeer welkom.

### Code bijdragen

Wil je code bijdragen? Volg dan onderstaand proces.

## Ontwikkelproces

### Werkafspraken

- **Taal.** Alles in deze repository is Nederlands: skillteksten, omschrijvingen, commits en documentatie. Engelse vaktermen (skill, SBOM, VEX, purl) blijven Engels. Teksten die in een SBOM terechtkomen mogen Engels zijn.
- **Branch en pull request.** Wijzigingen gaan via een branch en een pull request met een review. Op `main` commit je niet rechtstreeks.
- **Changeset per wijziging.** Elke pull request die een skill of de repo-opzet wijzigt, voegt met `npx changeset` een changeset toe: `patch` voor een correctie, `minor` voor nieuwe functionaliteit of een nieuwe standaardversie, `major` voor een ander SBOM-formaat of ander standaardgedrag. De releaseworkflow bundelt open changesets in een versie-PR; bij merge daarvan volgen tag en GitHub-release. Zie `.changeset/README.md`.
- **Eén bron, gegenereerde afgeleiden.** `.plugin/plugin.json` is het enige manifest dat je bewerkt. De manifesten in de mappen per assistent genereer je met `python3 scripts/generate_plugin.py`; `npm run check` faalt als ze afwijken. Bewerk ze nooit met de hand.
- **Geen productnamen.** Buiten de gegenereerde manifestmappen (de verborgen mappen met de naam van een assistent) komt geen naam van een AI-assistent of model voor, ook niet in de skilltekst of in `allowed-tools`. Beschrijf een handeling, niet het product. De enige uitzondering is `scripts/generate_plugin.py`, dat de mappen per assistent bij naam moet noemen om ze te kunnen schrijven.

### Een skill wijzigen

- De map heet gelijk aan `name` in de frontmatter en begint met de slug `geonovum-`.
- De frontmatter bevat `name`, `description`, `license` en in `metadata` de `nl.gov.`-sleutels. Datums schrijf je als JJJJ-MM-DD; een sleutel zonder waarde laat je weg.
- Een gepubliceerde skillnaam wijzigt niet meer. Moet het toch, zet dan de oude naam in `nl.gov.previous-name`.
- Een skill is een samenvatting, niet de norm zelf. Waar de skill een keuze maakt die de bronnen open laten (zoals SPDX 2.3 in plaats van 3.0), leg je die met de reden vast in `SKILL.md`.
- `SKILL.md` blijft onder de 500 regels; naslag hoort in een apart bestand, zoals `inventaris-formaat.md`.
- Wijzig je een script, draai dan de testcases in `evals/` en controleer dat de SBOMs geldig blijven.
- Bewaak `nl.gov.review-by`: bij een nieuwe versie van de CISA Minimum Elements, CycloneDX of SPDX, bij een uitvoeringshandeling onder de CRA, of bij het verstrijken van de datum wordt de skill herzien en krijgt hij een nieuwe release.

### Status van een skill

`nl.gov.status` is een van `concept`, `development`, `beta`, `stable` of `obsolete`. Een status boven `concept` vraagt een expertreview van de inhoud en van wat de skill aanroept, een gepubliceerde reviewprocedure met acceptatiecriteria, en een test met minstens twee assistenten waarvan één open source of Europees. De vaststelling als `stable` doet Geonovum; dan wordt ook `nl.gov.approved-by` ingevuld.

### Lokaal controleren

Nodig: Node.js 22.11 of nieuwer en Python 3.

```bash
npm ci
npm run check
```

Dat controleert of de manifesten per assistent gelijk zijn aan wat `.plugin/plugin.json` oplevert en of de versie in `package.json`, `.plugin/plugin.json` en `publiccode.yml` gelijk is.

## Licentie

Door bij te dragen aan dit project ga je ermee akkoord dat je bijdragen worden
gelicenseerd onder de [EUPL-1.2](LICENSE) licentie. Dit betekent dat:

- Je het auteursrecht behoudt op je bijdragen
- Je bijdragen beschikbaar komen onder dezelfde open source licentie
- De code gebruikt mag worden door andere overheidsorganisaties

---

Bedankt voor je bijdrage!

_Dit project wordt onderhouden door Geonovum en de open source
community._
