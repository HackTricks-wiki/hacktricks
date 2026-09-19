# AGENTS.md

Riglyne vir toekomstige agents wat in hierdie repository werk.

## Repositorykonteks

Dit is die hoof HackTricks mdBook-repository. Die verwante cloud-book is by:

`/Users/carlospolop/git/hacktricks-cloud`

Veranderinge aan gedeelde theme-/search-gedrag moet dikwels in albei repositories toegepas word.

## Kontrak vir die laai van die soekindeks

Die pasgemaakte search-UI is in:

`theme/ht_searcher.js`

Daar kan ook 'n gegenereerde kopie wees by:

`book/theme/ht_searcher.js`

As production die reeds geboude `book/`-directory deploy, dateer albei kopieë op of rebuild die
book voor deployment.

Die bronbeleid vir die search index is belangrik en kostesensitief:

- Op publieke hosts, laai elke taalspesifieke en fallback-kandidaat slegs vanaf
`HackTricks-wiki/hacktricks-searchindex`. Moet nooit terugval na die same-origin mdBook-output nie;
om die groot index vanaf `hacktricks.wiki` in production te bedien, is duur.
- Op localhost, `.local`/`.internal`-hosts, loopback, RFC1918, carrier-grade NAT, link-local of
private IPv6-adresse, laai slegs die same-origin mdBook-output sodat
local/container-deployments selfonderhoudend bly.

Vir hierdie repo is die verwagte local fallback:

`/searchindex.js`

Op private hosts is die cloud-index nie vanaf hierdie origin beskikbaar nie en moet dit nie 'n
remote download aktiveer nie. Op publieke hosts moet dit die remote
`searchindex-cloud-<lang>.js.gz`-lêers gebruik.

## Publisering van die soekindeks

Die workflows wat encrypted compressed search indexes na
`HackTricks-wiki/hacktricks-searchindex` publiseer, is:

- `.github/workflows/build_master.yml`
- `.github/workflows/translate_all.yml`

Die gegenereerde source file is `book/searchindex.js`. Die gepubliseerde remote artifact-name is:

- `searchindex-v2-en.json.gz` (preferred compact index)
- `searchindex-v2-<lang>.json.gz` (preferred compact index)
- `searchindex-en.js.gz`
- `searchindex-<lang>.js.gz`

Die browser loader verkies die compact v2-artifact en hou die `.js.gz`-artifact as 'n legacy
fallback. Albei is XOR-encrypted gzip-payloads wat die sleutel gebruik wat in
`theme/ht_searcher.js` gedefinieer is.

Die loader moet lazy bly: normale page navigation mag nie die search worker skep of 'n index
download voordat die besoeker search oopmaak of gebruik nie. Remote compressed responses word
24 uur per origin in Cache Storage gestoor sodat daaropvolgende bladsye dit kan hergebruik.
Behoud die stale-cache fallback wanneer die verfrissing van 'n vervalde entry misluk.

## Bou en validering

Algemene plaaslike kontroles:

- `node --check theme/ht_searcher.js`
- `mdbook build`

As `mdbook build` misluk, kontroleer:

- `hacktricks-preprocessor-error.log`
- `hacktricks-preprocessor.log`

## Redigeringsnotas

- Verkies `rg` vir soektogte.
- Hou gegenereerde `book/`-output uit commits, tensy dit uitdruklik versoek word. Search-loader-fixes
  is 'n uitsondering wanneer die reeds geboude bladsye onmiddellik reggestel moet word.
- As gedeelde theme-gedrag verander word, vergelyk en dateer die ooreenstemmende lêer in
  `/Users/carlospolop/git/hacktricks-cloud` op.
- Moenie onverwante plaaslike veranderinge terugrol nie.
