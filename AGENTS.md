# AGENTS.md

Hinweise für zukünftige Agents, die in diesem Repository arbeiten.

## Repository-Kontext

Dies ist das zentrale HackTricks-mdBook-Repository. Das zugehörige Cloud-Buch befindet sich unter:

`/Users/carlospolop/git/hacktricks-cloud`

Änderungen am gemeinsamen Theme-/Suchverhalten müssen häufig in beiden Repositories vorgenommen werden.

## Vertrag zum Laden des Suchindex

Die benutzerdefinierte Suchoberfläche befindet sich in:

`theme/ht_searcher.js`

Es kann außerdem eine generierte Kopie unter folgendem Pfad geben:

`book/theme/ht_searcher.js`

Wenn die Produktion das bereits erstellte Verzeichnis `book/` bereitstellt, aktualisiere beide Kopien oder erstelle das Buch neu.

Die Reihenfolge beim Laden des Suchindex ist wichtig und kostenrelevant:

1. Lade jeden sprachspezifischen und jeden Fallback-Suchindex aus dem GitHub-Repository:
`HackTricks-wiki/hacktricks-searchindex`
2. Verwende den Same-Origin-mdBook-Output nur dann als Fallback, wenn alle von GitHub gehosteten Kandidaten fehlschlagen.

Platziere den lokalen `/searchindex.js`-Fallback nicht vor einem von GitHub gehosteten Fallback wie `searchindex-en.js.gz`. Das Bereitstellen von `searchindex.js` von `hacktricks.wiki` ist in der Produktion teuer.

Für dieses Repository lautet der erwartete lokale Fallback:

`/searchindex.js`

Der Cloud-Index sollte keinen lokalen Fallback von dieser Origin verwenden. Er sollte sich auf die entfernten Dateien `searchindex-cloud-<lang>.js.gz` stützen.

## Veröffentlichung des Suchindex

Die Workflows, die verschlüsselte komprimierte Suchindizes in `HackTricks-wiki/hacktricks-searchindex` veröffentlichen, sind:

- `.github/workflows/build_master.yml`
- `.github/workflows/translate_all.yml`

Die generierte Quelldatei ist `book/searchindex.js`. Die Namen der veröffentlichten Remote-Artefakte sind:

- `searchindex-v2-en.json.gz` (bevorzugter kompakter Index)
- `searchindex-v2-<lang>.json.gz` (bevorzugter kompakter Index)
- `searchindex-en.js.gz`
- `searchindex-<lang>.js.gz`

Der Browser-Loader bevorzugt das kompakte v2-Artefakt und verwendet das `.js.gz`-Artefakt weiterhin als Legacy-Fallback. Beide sind XOR-verschlüsselte gzip-Payloads und verwenden den in `theme/ht_searcher.js` definierten Schlüssel.

Der Loader muss lazy bleiben: Bei der normalen Seitennavigation darf weder der Search Worker erstellt noch ein Index heruntergeladen werden, bevor der Besucher die Suche öffnet oder verwendet. Komprimierte Remote-Antworten werden 24 Stunden pro Origin im Cache Storage gespeichert, damit nachfolgende Seiten sie wiederverwenden können. Behalte den Fallback auf den veralteten Cache bei, wenn die Aktualisierung eines abgelaufenen Eintrags fehlschlägt.

## Build und Validierung

Übliche lokale Prüfungen:

- `node --check theme/ht_searcher.js`
- `mdbook build`

Wenn `mdbook build` fehlschlägt, überprüfe:

- `hacktricks-preprocessor-error.log`
- `hacktricks-preprocessor.log`

## Hinweise zur Bearbeitung

- Verwende zum Suchen bevorzugt `rg`.
- Halte generierte `book/`-Ausgaben aus Commits heraus, sofern dies nicht ausdrücklich angefordert wurde. Änderungen am Search Loader sind eine Ausnahme, wenn die bereits erstellten Seiten sofort korrigiert werden müssen.
- Wenn du das gemeinsame Theme-Verhalten änderst, vergleiche die entsprechende Datei in `/Users/carlospolop/git/hacktricks-cloud` und aktualisiere sie ebenfalls.
- Mache keine nicht zusammenhängenden lokalen Änderungen rückgängig.
