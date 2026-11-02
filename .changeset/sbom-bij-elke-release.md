---
"geonovum-sbom": minor
---

De skill kan een GitHub-workflow in een repository zetten die bij elke release de SBOMs maakt uit de gecommitte inventaris, ze valideert, ondertekent met een build-attestatie en aan de release hangt. Elke week controleert de workflow de componenten opnieuw bij OSV en opent hij een issue als er kwetsbaarheden te beoordelen zijn. `build_sbom.js` heeft daarvoor de optie `--version`, zodat de release-tag de productversie wordt.
