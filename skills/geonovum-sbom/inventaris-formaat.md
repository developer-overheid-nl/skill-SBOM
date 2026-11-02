# Inventarisformaat voor build_sbom.js

De inventaris is een JSON-bestand dat je schrijft nadat je de repository hebt onderzocht. Paden erin zijn relatief ten opzichte van het inventarisbestand. Zet het buiten de repository, bijvoorbeeld in een tijdelijke map, tenzij de gebruiker het wil committen om de SBOM later opnieuw te kunnen maken.

```json
{
  "repo": "../pad/naar/repo",
  "author": { "name": "Team Digitale Dienstverlening, Gemeente Voorbeeldstad", "email": "dd@voorbeeldstad.nl", "organization": true },
  "sbomVersion": 1,
  "lifecycle": "pre-build",
  "complete": false,
  "product": {
    "name": "mijn-app",
    "version": "2.4.0",
    "description": "Wat de software doet, in één zin",
    "supplier": { "name": "Voorbeeldorganisatie", "url": "https://voorbeeld.nl" },
    "license": "EUPL-1.2",
    "copyright": "Copyright (c) 2024 Voorbeeldorganisatie",
    "vcs": "https://github.com/voorbeeld/mijn-app",
    "website": "https://mijn-app.voorbeeld.nl"
  },
  "import": [
    { "path": "bom.tool.cdx.json", "tool": "cdxgen@11.11.0" }
  ],
  "components": [
    {
      "key": "jquery",
      "name": "jquery",
      "version": "1.9.1",
      "type": "library",
      "purl": "pkg:npm/jquery@1.9.1",
      "cpe": "cpe:2.3:a:jquery:jquery:1.9.1:*:*:*:*:*:*:*",
      "producer": { "name": "OpenJS Foundation", "url": "https://openjsf.org" },
      "license": "MIT",
      "declared": "MIT",
      "copyright": "Copyright 2005, 2012 jQuery Foundation, Inc. and other contributors",
      "description": "jQuery JavaScript Library",
      "website": "https://jquery.com",
      "download": "https://code.jquery.com/jquery-1.9.1.js",
      "files": [{ "path": "static/js/jquery-1.9.1.js" }],
      "bundled": true,
      "used": false,
      "usage": "bundled in static/js and publicly served, but not loaded by any page"
    },
    {
      "key": "modernizr",
      "name": "modernizr",
      "version": "2.6.2",
      "purl": "pkg:npm/modernizr@2.6.2",
      "producer": { "name": "Modernizr" },
      "license": "MIT",
      "declared": "MIT & BSD",
      "files": [{ "path": "static/js/modernizr.js" }],
      "bundled": true,
      "used": false
    },
    {
      "key": "yepnope",
      "name": "yepnope",
      "version": "1.5.4",
      "purl": "pkg:npm/yepnope@1.5.4",
      "producer": { "name": "Alex Sexton" },
      "license": "WTFPL",
      "declared": "WTFPL",
      "embeddedIn": "modernizr"
    },
    {
      "key": "font-awesome",
      "name": "font-awesome",
      "version": "4.2.0",
      "purl": "pkg:npm/font-awesome@4.2.0",
      "producer": { "name": "Fonticons, Inc.", "url": "https://fontawesome.com" },
      "license": "OFL-1.1 AND MIT",
      "declared": "OFL-1.1 AND MIT",
      "files": [
        { "url": "https://maxcdn.bootstrapcdn.com/font-awesome/4.2.0/css/font-awesome.min.css", "name": "css/font-awesome.min.css" },
        { "url": "https://maxcdn.bootstrapcdn.com/font-awesome/4.2.0/fonts/fontawesome-webfont.woff?v=4.2.0", "name": "fonts/fontawesome-webfont.woff" }
      ],
      "bundled": false,
      "used": true,
      "usage": "loaded at runtime from a CDN by templates/base.html"
    },
    {
      "key": "php",
      "name": "PHP",
      "type": "platform",
      "range": ">=7.2",
      "external": true,
      "purl": "pkg:generic/php",
      "cpe": "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*",
      "producer": { "name": "The PHP Group", "url": "https://www.php.net" },
      "license": "PHP-3.01",
      "declared": "PHP-3.01",
      "used": true
    }
  ],
  "vex": {
    "CVE-2020-11023@jquery": {
      "state": "not_affected",
      "justification": "code_not_reachable",
      "detail": "Why this vulnerability does not apply here, pointing at the code"
    }
  }
}
```

Teksten die in de SBOM terechtkomen (`description`, `usage`, VEX-`detail`) mogen Engels zijn: SBOMs worden vaak internationaal gelezen en door tools verwerkt. Houd ze in één taal per SBOM.

## Velden

**Bovenste niveau**

| Veld | Betekenis |
|---|---|
| `repo` | Root van de repository, relatief ten opzichte van het inventarisbestand. Standaard de map van de inventaris. |
| `author` | SBOM Author (CISA): de persoon of organisatie die verantwoordelijk is voor de SBOM, meestal de gebruiker. Alleen `name`, `email`, `phone` en `organization` (`true` voor een organisatie of team). |
| `product.version` | Productversie. Laat weg als de SBOM in een releaseworkflow wordt gemaakt: `build_sbom.js --version <tag>` gaat voor dit veld. Zonder beide wordt de commit-hash gebruikt. |
| `sbomVersion` | SBOM Version (CISA). Verhoog dit als de SBOM voor dezelfde productversie opnieuw wordt gemaakt. |
| `lifecycle` | Generatiecontext: `pre-build` (vanuit de broncode, het gewone geval), `build` of `post-build`. |
| `complete` | Alleen `true` als je zeker weet dat de inventaris alle componenten bevat, ook de indirecte. |
| `import` | CycloneDX-bestanden van een tool die lockfiles leest. Componenten, hashes, licenties en de afhankelijkheidsboom worden overgenomen. `tool` (`naam@versie`) komt in de SBOM als tool. |
| `vex` | Eigen VEX-oordelen, met als sleutel `CVE-ID@component-key`, of `CVE-ID` voor alle componenten. Gaat voor de standaarden hieronder. |

**Component**

| Veld | Betekenis |
|---|---|
| `key` | Unieke korte id; gebruikt in `vex`-sleutels, `dependsOn` en `embeddedIn`. |
| `name`, `version` | Naam en exacte versie. Voor componenten die de omgeving levert zonder exacte versie gebruik je `range` (bijvoorbeeld `">=7.2"`). |
| `type` | CycloneDX-componenttype: `library` (standaard), `framework`, `application`, `platform`, `operating-system`, `container`, `firmware`, `file`. |
| `purl`, `cpe` | Machineleesbare identifiers; CISA vraagt er minstens één. Gebruik de purl van het ecosysteem waar de code vandaan komt (`pkg:npm/jquery@1.9.1` voor een met de hand gekopieerd jQuery-bestand); `pkg:generic/<naam>` alleen als geen ecosysteem past. Alleen purls van echte ecosystemen worden bij OSV opgezocht. |
| `producer` | Component Producer (CISA, voorheen "supplier"): de organisatie die de component maakt. |
| `license` | De licentie die jij hebt vastgesteld, als SPDX-expressie. Laat weg als je die niet kon bepalen. |
| `declared` | De licentie precies zoals de component die noemt (kopregel, pakketmetadata). Vrije tekst zoals `"MIT & BSD"` mag; die wordt in SPDX een `LicenseRef-`. |
| `copyright` | Copyrightregel, overgenomen uit de component. |
| `files` | Bestanden waaruit de component bestaat. `{ "path": ... }` voor bestanden in de repository (gehasht vanaf de gecommitte versie), `{ "url": ..., "name": ... }` voor bestanden die van elders komen (gedownload en gehasht). Eén lokaal bestand: de hash komt op de component zelf. Meerdere of externe bestanden: die worden geneste bestandscomponenten. |
| `embeddedIn` | Key van de component in wiens bestand deze bibliotheek zit (yepnope in Modernizr, Popper in de Bootstrap-bundle). De component krijgt de hash van dat bestand, met een eigenschap die zegt dat het de hash van het omringende bestand is, en de omringende component krijgt een afhankelijkheid ernaar. `used` neemt hij over van de omringende component. |
| `embeddedFile` | Bij `embeddedIn`: welk bestand van de omringende component, als die er meer heeft (naam of deel van de URL). Standaard het eerste. |
| `bundled` | `true` als de bestanden van de component in de repository zitten. |
| `used` | `false` als het product de component wel levert maar nooit laadt of aanroept. Kwetsbaarheden van ongebruikte componenten krijgen standaard `not_affected` / `code_not_reachable`. |
| `usage` | Eén zin over hoe het product de component gebruikt, of juist niet. Komt in de SBOM en dient als VEX-detail. |
| `external` | `true` voor componenten die de omgeving levert (runtime, webserver, extensies). |
| `dependsOn` | Keys van componenten waarvan deze afhangt. |
| `scope` | Overschrijft de CycloneDX-scope. Standaard `required`, ook voor geleverde maar ongebruikte bestanden: ze worden wel geleverd, en scanners slaan `excluded` vaak over. |

## VEX-standaarden

Het script zoekt elke component met een ecosysteem-purl en een versie op bij api.osv.dev.

- Component met `used: false`: `not_affected`, met justification `code_not_reachable` en de `usage` als detail.
- Anders: `in_triage` met de detailtekst "Not analysed yet". Dat is eerlijk, want het script kan niet weten of de kwetsbare functie bereikbaar is. Analyseer deze samen met de gebruiker, leg de uitkomst vast in `vex` en draai opnieuw.

Geldige states zijn `resolved`, `resolved_with_pedigree`, `exploitable`, `in_triage`, `false_positive` en `not_affected`. Geldige justifications (bij `not_affected`) zijn `code_not_present`, `code_not_reachable`, `requires_configuration`, `requires_dependency`, `requires_environment`, `protected_by_compiler`, `protected_at_runtime`, `protected_at_perimeter` en `protected_by_mitigating_control`.

OSV geeft voor één CVE soms meerdere meldingen (GHSA, PYSEC). Het script voegt die samen tot één kwetsbaarheid per CVE.
