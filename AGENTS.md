# AGENTS.md

Hinweise für zukünftige Agents, die in diesem Repository arbeiten.

## Repository-Kontext

Dies ist das zentrale HackTricks-mdBook-Repository. Das zugehörige Cloud-Buch befindet sich unter:

`/Users/carlospolop/git/hacktricks-cloud`

Änderungen am gemeinsamen Theme-/Search-Verhalten müssen häufig in beiden Repositories angewendet werden.

## Vertrag zum Laden des Search-Index

Die benutzerdefinierte Search-Oberfläche befindet sich in:

`theme/ht_searcher.js`

Es kann außerdem eine generierte Kopie unter folgendem Pfad geben:

`book/theme/ht_searcher.js`

Wenn die Produktion das bereits erstellte Verzeichnis `book/` deployed, müssen beide Kopien aktualisiert oder das Buch vor dem Deployment neu erstellt werden.

Die Richtlinie für die Quelle des Search-Index ist wichtig und kostenrelevant:

- Auf öffentlichen Hosts dürfen alle sprachspezifischen und Fallback-Kandidaten ausschließlich von `HackTricks-wiki/hacktricks-searchindex` geladen werden. Es darf kein Fallback auf die mdBook-Ausgabe desselben Ursprungs erfolgen. Das Bereitstellen des großen Index von `hacktricks.wiki` in der Produktion ist teuer.
- Auf localhost, `.local`-/`.internal`-Hosts, Loopback-, RFC1918-, Carrier-Grade-NAT-, Link-Local- oder privaten IPv6-Adressen darf ausschließlich die mdBook-Ausgabe desselben Ursprungs geladen werden, damit lokale/Container-Deployments eigenständig bleiben. Bei einer nicht-englischen Seite muss zuerst der lokale sprachpräfixierte Pfad versucht werden (zum Beispiel `/es/searchindex.js`); der englische Root-Index darf nur als Fallback verwendet werden.

Für dieses Repository ist der erwartete lokale Fallback:

`/searchindex.js`

Auf privaten Hosts ist der Cloud-Index von diesem Ursprung aus nicht verfügbar und darf keinen Remote-Download auslösen. Auf öffentlichen Hosts müssen die Remote-Dateien `searchindex-cloud-<lang>.js.gz` verwendet werden.

## Veröffentlichung des Search-Index

Die Workflows, die verschlüsselte komprimierte Search-Indexe in `HackTricks-wiki/hacktricks-searchindex` veröffentlichen, sind:

- `.github/workflows/build_master.yml`
- `.github/workflows/translate_all.yml`

Die generierte Quelldatei ist `book/searchindex.js`. Die veröffentlichten Namen der Remote-Artefakte sind:

- `searchindex-v2-en.json.gz` (bevorzugter kompakter Index)
- `searchindex-v2-<lang>.json.gz` (bevorzugter kompakter Index)
- `searchindex-en.js.gz`
- `searchindex-<lang>.js.gz`

Der Browser-Loader bevorzugt das kompakte v2-Artefakt und verwendet das `.js.gz`-Artefakt weiterhin als Legacy-Fallback. Beide sind XOR-verschlüsselte gzip-Payloads und verwenden den in `theme/ht_searcher.js` definierten Schlüssel.

Der Loader muss lazy bleiben: Die normale Seitennavigation darf weder den Search-Worker erstellen noch einen Index herunterladen, bevor der Besucher die Suche öffnet oder verwendet. Komprimierte Remote-Antworten werden 24 Stunden pro Origin im Cache Storage gespeichert, damit nachfolgende Seiten sie wiederverwenden können. Der Fallback auf den veralteten Cache muss erhalten bleiben, wenn die Aktualisierung eines abgelaufenen Eintrags fehlschlägt.

## Build und Validierung

Übliche lokale Prüfungen:

- `node --check theme/ht_searcher.js`
- `mdbook build`

Wenn `mdbook build` fehlschlägt, prüfe:

- `hacktricks-preprocessor-error.log`
- `hacktricks-preprocessor.log`

## Hinweise zur Bearbeitung

- Verwende für die Suche bevorzugt `rg`.
- Halte generierte `book/`-Ausgaben aus Commits heraus, sofern dies nicht ausdrücklich angefordert wurde. Korrekturen am Search-Loader sind eine Ausnahme, wenn die bereits erstellten Seiten sofort korrigiert werden müssen.
- Wenn du das gemeinsame Theme-Verhalten änderst, vergleiche die entsprechende Datei in `/Users/carlospolop/git/hacktricks-cloud` und aktualisiere sie ebenfalls.
- Setze keine nicht zusammenhängenden lokalen Änderungen zurück.
