# AGENTS.md

Hinweise für zukünftige Agents, die in diesem Repository arbeiten.

## Repository-Kontext

Dies ist das wichtigste HackTricks-mdBook-Repository. Das zugehörige Cloud-Buch befindet sich unter:

`/Users/carlospolop/git/hacktricks-cloud`

Änderungen am gemeinsamen Theme-/Search-Verhalten müssen häufig in beiden Repositories vorgenommen werden.

## Vertrag zum Laden des Search-Index

Die benutzerdefinierte Search-UI befindet sich in:

`theme/ht_searcher.js`

Möglicherweise gibt es auch eine generierte Kopie unter:

`book/theme/ht_searcher.js`

Wenn die Production das bereits erstellte `book/`-Verzeichnis deployt, aktualisiere beide Kopien oder baue das Buch vor dem Deployment neu.

Die Quellrichtlinie für den Search-Index ist wichtig und kostenabhängig:

- Auf öffentlichen Hosts dürfen alle sprachspezifischen und fallback-Kandidaten ausschließlich von
`HackTricks-wiki/hacktricks-searchindex` geladen werden. Führe niemals einen Fallback auf die mdBook-Ausgabe derselben Origin durch; das Bereitstellen des großen Index von `hacktricks.wiki` in der Production ist teuer.
- Auf Localhost-, `.local`-/`.internal`-Hosts, Loopback-, RFC1918-, Carrier-Grade-NAT-, Link-Local- oder privaten IPv6-Adressen darf nur die mdBook-Ausgabe derselben Origin geladen werden, damit lokale/Container-Deployments in sich geschlossen bleiben.

Für dieses Repo ist der erwartete lokale Fallback:

`/searchindex.js`

Auf privaten Hosts ist der Cloud-Index von dieser Origin aus nicht verfügbar und darf keinen Remote-Download auslösen. Auf öffentlichen Hosts sollten die Remote-Dateien `searchindex-cloud-<lang>.js.gz` verwendet werden.

## Veröffentlichung des Search-Index

Die Workflows, die verschlüsselte komprimierte Search-Indexes in
`HackTricks-wiki/hacktricks-searchindex` veröffentlichen, sind:

- `.github/workflows/build_master.yml`
- `.github/workflows/translate_all.yml`

Die generierte Quelldatei ist `book/searchindex.js`. Die Namen der veröffentlichten Remote-Artefakte sind:

- `searchindex-v2-en.json.gz` (bevorzugter kompakter Index)
- `searchindex-v2-<lang>.json.gz` (bevorzugter kompakter Index)
- `searchindex-en.js.gz`
- `searchindex-<lang>.js.gz`

Der Browser-Loader bevorzugt das kompakte v2-Artefakt und behält das `.js.gz`-Artefakt als Legacy-Fallback bei. Beide sind XOR-verschlüsselte gzip-Payloads und verwenden den in `theme/ht_searcher.js` definierten Schlüssel.

Der Loader muss lazy bleiben: Die normale Seitennavigation darf weder den Search-Worker erstellen noch einen Index herunterladen, bevor der Besucher die Search öffnet oder verwendet. Komprimierte Remote-Antworten werden 24 Stunden pro Origin im Cache Storage gespeichert, damit nachfolgende Seiten sie wiederverwenden können. Behalte den Stale-Cache-Fallback bei, wenn die Aktualisierung eines abgelaufenen Eintrags fehlschlägt.

## Build und Validierung

Übliche lokale Prüfungen:

- `node --check theme/ht_searcher.js`
- `mdbook build`

Wenn `mdbook build` fehlschlägt, prüfe:

- `hacktricks-preprocessor-error.log`
- `hacktricks-preprocessor.log`

## Hinweise zur Bearbeitung

- Bevorzuge `rg` für die Suche.
- Halte generierte `book/`-Ausgaben aus Commits heraus, sofern dies nicht ausdrücklich angefordert wurde. Änderungen am Search-Loader sind eine Ausnahme, wenn die bereits erstellten Seiten sofort korrigiert werden müssen.
- Wenn du das Verhalten des gemeinsamen Themes änderst, vergleiche die entsprechende Datei in
`/Users/carlospolop/git/hacktricks-cloud` und aktualisiere sie ebenfalls.
- Mache keine nicht zusammenhängenden lokalen Änderungen rückgängig.
