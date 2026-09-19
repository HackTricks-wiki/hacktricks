# AGENTS.md

Mwongozo kwa agents wa baadaye wanaofanya kazi katika repository hii.

## Muktadha wa Repository

Hii ni main HackTricks mdBook repository. Cloud book inayohusiana inapatikana kwenye:

`/Users/carlospolop/git/hacktricks-cloud`

Mabadiliko kwenye shared theme/search behavior mara nyingi yanahitaji kutekelezwa katika repositories zote mbili.

## Search Index Loading Contract

Custom search UI iko kwenye:

`theme/ht_searcher.js`

Pia kunaweza kuwa na copy iliyotengenezwa kwenye:

`book/theme/ht_searcher.js`

Ikiwa production inadeploy directory ya `book/` iliyokwisha tengenezwa, sasisha copies zote mbili au build upya
book kabla ya deployment.

Mpangilio wa kupakia search index ni muhimu na unaathiri gharama:

1. Pakia kila language-specific na fallback search index kutoka GitHub repository:
`HackTricks-wiki/hacktricks-searchindex`
2. Ni pale tu candidates zote zinazohostiwa na GitHub zinaposhindwa ndipo utumie same-origin mdBook output kama fallback.

Usiweke local `/searchindex.js` fallback kabla ya fallback yoyote inayohostiwa na GitHub kama
`searchindex-en.js.gz`. Kutumikia `searchindex.js` kutoka `hacktricks.wiki` katika production ni ghali.

Kwa repository hii, local fallback inayotarajiwa ni:

`/searchindex.js`

Cloud index haipaswi kutumia local fallback kutoka origin hii. Inapaswa kutegemea remote
`searchindex-cloud-<lang>.js.gz` files.

## Search Index Publishing

Workflows zinazopublish encrypted compressed search indexes kwenye
`HackTricks-wiki/hacktricks-searchindex` ni:

- `.github/workflows/build_master.yml`
- `.github/workflows/translate_all.yml`

Generated source file ni `book/searchindex.js`. Majina ya published remote artifacts ni:

- `searchindex-v2-en.json.gz` (preferred compact index)
- `searchindex-v2-<lang>.json.gz` (preferred compact index)
- `searchindex-en.js.gz`
- `searchindex-<lang>.js.gz`

Browser loader inapendelea compact v2 artifact na inaweka `.js.gz` artifact kama
legacy fallback. Zote mbili ni XOR-encrypted gzip payloads kwa kutumia key iliyofafanuliwa kwenye `theme/ht_searcher.js`.

Loader lazima ibaki lazy: page navigation ya kawaida haipaswi kuunda search worker au kudownload index hadi
visitor afungue au atumie search. Remote compressed responses huhifadhiwa kwenye Cache
Storage kwa saa 24 kwa kila origin ili pages zinazofuata ziweze kuzitumia tena. Hifadhi stale-cache
fallback wakati refreshing expired entry inaposhindwa.

## Build And Validation

Checks za kawaida za ndani:

- `node --check theme/ht_searcher.js`
- `mdbook build`

Ikiwa `mdbook build` itashindwa, angalia:

- `hacktricks-preprocessor-error.log`
- `hacktricks-preprocessor.log`

## Editing Notes

- Pendelea `rg` kwa ajili ya searching.
- Weka generated `book/` output nje ya commits isipokuwa ikiwa imeombwa wazi. Search loader fixes ni
exception wakati pages zilizokwisha build zinahitaji kusahihishwa mara moja.
- Ukibadilisha shared theme behavior, linganisha na usasishe file inayolingana katika
`/Users/carlospolop/git/hacktricks-cloud`.
- Usirevert unrelated local changes.
