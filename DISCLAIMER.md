# Disclaimer

De skill in deze repository is een hulpmiddel van [Geonovum](https://www.geonovum.nl) voor het maken van SBOMs. Hij is **informatief**: een SBOM die met deze skill is gemaakt, is geen bewijs dat een product aan de Cyber Resilience Act (CRA) of aan andere regelgeving voldoet.

## De skill is niet de norm

Een skill is een samenvatting en een werkinstructie, niet de regel zelf. Leidend zijn altijd:

- de [2026 CISA Minimum Elements for a Software Bill of Materials](https://www.cisa.gov/resources-tools/resources/2026-minimum-elements-software-bill-materials-sbom);
- de [Cyber Resilience Act](https://eur-lex.europa.eu/eli/reg/2024/2847/oj) en de uitvoeringshandelingen die op grond daarvan worden vastgesteld;
- de specificaties van [CycloneDX](https://cyclonedx.org/specification/overview/) en [SPDX](https://spdx.dev/).

De CRA schrijft (nog) geen SBOM-formaat voor. De keuze voor CycloneDX 1.7 en SPDX 2.3 is een werkkeuze op basis van de huidige tools, geen definitieve nalevingskeuze.

## Geen conformiteitsverklaring

Een SBOM of VEX-oordeel van deze skill is geen goedkeuring, aanbeveling of conformiteitsverklaring van Geonovum. Wie een SBOM publiceert of aanlevert, blijft verantwoordelijk voor de juistheid en volledigheid ervan. Dat geldt in het bijzonder voor VEX-oordelen als `not_affected`: laat die door iemand met kennis van de code controleren. Een VEX-oordeel is geen vrijstelling van de meldplicht voor actief misbruikte kwetsbaarheden.

## Gebruik van generatieve AI

De skill wordt uitgevoerd door AI-assistenten. Een SBOM kan daardoor onvolledig of onjuist zijn, ook als de skill zelf klopt. Of bij het schrijven van de skill generatieve AI is gebruikt, staat in het veld `nl.gov.generated-with` van de skill. Overheidsorganisaties die generatieve AI inzetten, ook via deze skill, dienen te voldoen aan het [Overheidsbreed standpunt voor de inzet van generatieve AI](https://open.overheid.nl/documenten/bc03ce31-0cf1-4946-9c94-e934a62ebe73/file) en aan eigen beleid en kaders over AI.

## Externe diensten

De skill haalt kwetsbaarheden op bij [api.osv.dev](https://osv.dev) en downloadt bestanden van CDNs om ze te hashen. Daarbij worden pakketnamen en versies naar OSV gestuurd, geen broncode. Gebruik de optie `--no-osv` of `--no-fetch` van `build_sbom.js` als dat niet mag.

## Status en onderhoud

De status van de skill staat in het veld `nl.gov.status` in de frontmatter van `SKILL.md`, met een herzieningsdatum in `nl.gov.review-by`. Een skill met status `concept` is nog niet vastgesteld.

## Geen garantie

De inhoud wordt aangeboden zonder garantie van volledigheid, juistheid of actualiteit. Fouten en verbeteringen graag als [issue](https://github.com/developer-overheid-nl/skills-sbom/issues) in deze repository.
