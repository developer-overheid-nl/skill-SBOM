# geonovum-sbom

## 0.0.2

### Patch Changes

- 52cef9c: De release-workflow werkt met GITHUB_TOKEN, zoals bij de andere skill-repositories van developer-overheid-nl, zodat releases weer automatisch worden gemaakt. De versie in `package.json`, `.plugin/plugin.json` en `publiccode.yml` volgt nu de releases: 0.0.1 was met de hand uitgebracht en stond daar nog als 0.0.0.
  
  De repository heet nu developer-overheid-nl/skills-sbom. De sjablonen halen de scripts daar op, en de links in de documentatie en in publiccode.yml wijzen ernaar.

## 0.0.1

### Patch Changes

- Eerste release. Skill `geonovum-sbom`: maakt voor een repository een CycloneDX 1.7-SBOM met VEX en een SPDX 2.3-SBOM volgens de 2026 CISA Minimum Elements, ook zonder lockfile, met offline validatie en een overzicht van ontbrekende elementen. Status `concept`.
- De skill kan een GitHub-workflow in een repository zetten die bij elke release de SBOMs maakt uit de gecommitte inventaris, ze valideert, ondertekent met een build-attestatie en aan de release hangt. Elke week controleert de workflow de componenten opnieuw bij OSV en opent hij een issue als er kwetsbaarheden te beoordelen zijn. `build_sbom.js` heeft daarvoor de optie `--version`, zodat de release-tag de productversie wordt.
- Verwerkt de review van de skill:

  - **Tooling eerst:** de werkwijze begint met de meegeleverde tooling en laat het zelf zoeken over aan wat die niet kan vaststellen. Het nieuwe script `scan_repo.js` vindt lockfiles, bestanden van derden met naam, versie en licentie uit de kop, ingebedde bibliotheken, of bestanden geladen worden, CDN-links, wat de omgeving levert en waar de metadata staan, telkens met bestand en regel.
  - **Bijwerken in plaats van opnieuw maken:** `scan_repo.js --since` vergelijkt met de vorige SBOM. `build_sbom.js` (nu 1.2.0) zet daarvoor de commit in de SBOM. Zonder relevante wijzigingen blijft de inventaris zoals hij is.
  - **Buildstap:** de skill beschrijft wanneer de versies pas na een build of installatie vastliggen, en het releasesjabloon heeft daarvoor een stap die als commentaar klaarstaat.
  - **Metavelden uit bestanden:** auteur, licentie en product komen uit `publiccode.yml`, `CODEOWNERS`, `LICENSE` en git, met korte opdrachten om ze te controleren.
  - **Kwetsbaarheden los van de build:** het nieuwe script `check_vulns.js` legt een bestaande SBOM naast OSV. Het nieuwe sjabloon `sbom-kwetsbaarheden.yml` doet dat elke week op de SBOM van de release die in gebruik is, in plaats van op de broncode.
  - **Actions vastgezet:** de actions in de sjablonen en in de release-workflow staan op een commit-hash, met Dependabot om ze bij te werken.
- De repository staat nu op github.com/developer-overheid-nl/skill-sbom. De sjablonen halen de scripts daar op, en de links in de documentatie en in publiccode.yml wijzen ernaar.
