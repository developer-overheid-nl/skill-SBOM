---
"geonovum-sbom": patch
---

De release-workflow werkt met GITHUB_TOKEN, zoals bij de andere skill-repositories van developer-overheid-nl, zodat releases weer automatisch worden gemaakt. De versie in `package.json`, `.plugin/plugin.json` en `publiccode.yml` volgt nu de releases: 0.0.1 was met de hand uitgebracht en stond daar nog als 0.0.0.

De repository heet nu developer-overheid-nl/skills-sbom. De sjablonen halen de scripts daar op, en de links in de documentatie en in publiccode.yml wijzen ernaar.
