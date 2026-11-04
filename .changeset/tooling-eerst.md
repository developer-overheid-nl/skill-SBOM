---
"geonovum-sbom": minor
---

Verwerkt de review van de skill:

- **Tooling eerst:** de werkwijze begint met de meegeleverde tooling en laat het zelf zoeken over aan wat die niet kan vaststellen. Het nieuwe script `scan_repo.js` vindt lockfiles, bestanden van derden met naam, versie en licentie uit de kop, ingebedde bibliotheken, of bestanden geladen worden, CDN-links, wat de omgeving levert en waar de metadata staan, telkens met bestand en regel.
- **Bijwerken in plaats van opnieuw maken:** `scan_repo.js --since` vergelijkt met de vorige SBOM. `build_sbom.js` (nu 1.2.0) zet daarvoor de commit in de SBOM. Zonder relevante wijzigingen blijft de inventaris zoals hij is.
- **Buildstap:** de skill beschrijft wanneer de versies pas na een build of installatie vastliggen, en het releasesjabloon heeft daarvoor een stap die als commentaar klaarstaat.
- **Metavelden uit bestanden:** auteur, licentie en product komen uit `publiccode.yml`, `CODEOWNERS`, `LICENSE` en git, met korte opdrachten om ze te controleren.
- **Kwetsbaarheden los van de build:** het nieuwe script `check_vulns.js` legt een bestaande SBOM naast OSV. Het nieuwe sjabloon `sbom-kwetsbaarheden.yml` doet dat elke week op de SBOM van de release die in gebruik is, in plaats van op de broncode.
- **Actions vastgezet:** de actions in de sjablonen en in de release-workflow staan op een commit-hash, met Dependabot om ze bij te werken.
