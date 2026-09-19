# AGENTS.md

Riglyne vir toekomstige agente wat in hierdie bewaarplek werk.

## Bewaarplekkonteks

Dit is die hoof HackTricks mdBook-bewaarplek. Die verwante cloud-boek is by:

`/Users/carlospolop/git/hacktricks-cloud`

Veranderinge aan gedeelde tema-/soekgedrag moet dikwels in albei bewaarplekke toegepas word.

## Kontrak vir die laai van soekindekse

Die pasgemaakte soek-UI is in:

`theme/ht_searcher.js`

Daar kan ook 'n gegenereerde kopie wees by:

`book/theme/ht_searcher.js`

As produksie die reeds geboude `book/`-gids ontplooi, werk albei kopieë by of bou die
boek weer voordat dit ontplooi word.

Die laai-orde van die soekindeks is belangrik en kostegevoelig:

1. Laai elke taalspesifieke en terugval-soekindeks uit die GitHub-bewaarplek:
`HackTricks-wiki/hacktricks-searchindex`
2. Slegs as alle GitHub-gehoste kandidate misluk, val terug na die mdBook-uitvoer vanaf dieselfde oorsprong.

Moenie die plaaslike `/searchindex.js`-terugval voor enige GitHub-gehoste terugval, soos
`searchindex-en.js.gz`, plaas nie. Die bediening van `searchindex.js` vanaf `hacktricks.wiki` in produksie is duur.

Vir hierdie repo is die verwagte plaaslike terugval:

`/searchindex.js`

Die cloud-indeks moet nie 'n plaaslike terugval vanaf hierdie oorsprong gebruik nie. Dit moet op die afgeleë
`searchindex-cloud-<lang>.js.gz`-lêers staatmaak.

## Publisering van soekindekse

Die workflows wat geënkripteerde, saamgeperste soekindekse na
`HackTricks-wiki/hacktricks-searchindex` publiseer, is:

- `.github/workflows/build_master.yml`
- `.github/workflows/translate_all.yml`

Die gegenereerde bronlêer is `book/searchindex.js`. Die name van die gepubliseerde afgeleë artefakte is:

- `searchindex-v2-en.json.gz` (voorkeur-kompakte indeks)
- `searchindex-v2-<lang>.json.gz` (voorkeur-kompakte indeks)
- `searchindex-en.js.gz`
- `searchindex-<lang>.js.gz`

Die blaaierlaaier verkies die kompakte v2-artefak en behou die `.js.gz`-artefak as 'n
verouderde terugval. Albei is XOR-geënkripteerde gzip-vragte wat die sleutel gebruik wat in `theme/ht_searcher.js` gedefinieer is.

Die laaier moet lui bly: normale bladsynavigasie mag nie die soekwerker skep of 'n indeks aflaai
voordat die besoeker soek oopmaak of gebruik nie. Afgeleë saamgeperste antwoorde word vir 24 uur per oorsprong in Cache Storage
bewaar sodat daaropvolgende bladsye dit kan hergebruik. Behou die terugval na die verouderde kas wanneer die verfrissing van 'n vervalde inskrywing misluk.

## Bou en validering

Algemene plaaslike kontroles:

- `node --check theme/ht_searcher.js`
- `mdbook build`

As `mdbook build` misluk, kontroleer:

- `hacktricks-preprocessor-error.log`
- `hacktricks-preprocessor.log`

## Redigeringsnotas

- Verkies `rg` vir soektogte.
- Hou gegenereerde `book/`-uitset uit commits, tensy dit uitdruklik versoek word. Soeklaaier-regstellings is
'n uitsondering wanneer die reeds geboude bladsye onmiddellik reggestel moet word.
- As gedeelde temagedrag verander word, vergelyk en werk die ooreenstemmende lêer in
`/Users/carlospolop/git/hacktricks-cloud` by.
- Moenie onverwante plaaslike veranderinge terugstel nie.
