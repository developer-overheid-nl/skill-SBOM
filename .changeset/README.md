# Changesets

Deze map hoort bij [Changesets](https://github.com/changesets/changesets), waarmee versie en CHANGELOG van deze repository worden bijgehouden.

Elke pull request die een skill of de repo-opzet wijzigt, voegt een changeset toe:

```bash
npx changeset
```

Kies `patch` voor een correctie in de SBOMs die de skill maakt, `minor` voor nieuwe functionaliteit of ondersteuning van een nieuwe versie van CycloneDX, SPDX of de CISA Minimum Elements, en `major` voor een ander SBOM-formaat of ander standaardgedrag. Beschrijf de wijziging in het Nederlands, vanuit de gebruiker van de skill.

Zodra er changesets op `main` staan, opent de workflow in `.github/workflows/release.yml` een pull request "Nieuwe release". Daarin is `npm run version` gedraaid: dat verhoogt de versie in `package.json`, schrijft de CHANGELOG, zet dezelfde versie en de datum van die dag in `.plugin/plugin.json` en `publiccode.yml`, en genereert de manifesten per assistent opnieuw. Wie die PR merget, geeft de release vrij: de workflow zet dan de tag `v<versie>` en maakt de GitHub-release aan met de CHANGELOG-tekst van die versie. Draai `npm run version` niet zelf op `main`. De releasedatum in `publiccode.yml` is de dag waarop de versie-PR het laatst is bijgewerkt; merge hem op die dag, dan klopt hij met de GitHub-release.

De eerste release, 0.0.1 van 4 november 2026, is met de hand gemaakt, met de tag `0.0.1`. Vanaf 0.0.2 maakt de workflow de releases.

Dit pakket wordt niet naar npm gepubliceerd; `package.json` is privaat en bestaat alleen voor Changesets.
