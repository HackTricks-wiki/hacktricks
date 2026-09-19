# AGENTS.md

Mwongozo kwa agents wa baadaye wanaofanya kazi katika repository hii.

## Muktadha wa Repository

Hii ni main HackTricks mdBook repository. Cloud book inayohusiana iko kwenye:

`/Users/carlospolop/git/hacktricks-cloud`

Mabadiliko ya shared theme/search behavior mara nyingi yanahitaji kutekelezwa katika repositories zote mbili.

## Search Index Loading Contract

Custom search UI iko kwenye:

`theme/ht_searcher.js`

Huenda pia kukawa na copy iliyotengenezwa kwenye:

`book/theme/ht_searcher.js`

Ikiwa production inadeploy directory ya `book/` ambayo tayari imejengwa, sasisha copies zote mbili au build tena
book kabla ya deployment.

Search index source policy ni muhimu na inaathiri gharama:

- Kwenye public hosts, pakia kila language-specific na fallback candidate kutoka
`HackTricks-wiki/hacktricks-searchindex` pekee. Usitumie fallback ya same-origin mdBook output;
ku-serve index kubwa kutoka `hacktricks.wiki` katika production ni ghali.
- Kwenye localhost, hosts za `.local`/`.internal`, loopback, RFC1918, carrier-grade NAT, link-local, au
private IPv6 addresses, pakia same-origin mdBook output pekee ili deployments za local/container zibaki
self-contained.

Kwa repository hii, local fallback inayotarajiwa ni:

`/searchindex.js`

Kwenye private hosts, cloud index haipatikani kutoka origin hii na haipaswi kuanzisha remote
download. Kwenye public hosts inapaswa kutumia remote `searchindex-cloud-<lang>.js.gz` files.

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

Browser loader inapendelea compact v2 artifact na huhifadhi `.js.gz` artifact kama
legacy fallback. Zote ni XOR-encrypted gzip payloads zinazotumia key iliyofafanuliwa kwenye
`theme/ht_searcher.js`.

Loader lazima ibaki lazy: normal page navigation haipaswi kuunda search worker au kupakua
index hadi visitor afungue au atumie search. Remote compressed responses zinahifadhiwa kwenye Cache
Storage kwa saa 24 kwa kila origin ili pages zinazofuata ziweze kuzitumia tena. Hifadhi stale-cache
fallback wakati refreshing entry iliyokwisha muda kunaposhindikana.

## Build And Validation

Local checks za kawaida:

- `node --check theme/ht_searcher.js`
- `mdbook build`

Ikiwa `mdbook build` itashindwa, angalia:

- `hacktricks-preprocessor-error.log`
- `hacktricks-preprocessor.log`

## Editing Notes

- Pendelea `rg` kwa searching.
- Weka generated `book/` output nje ya commits isipokuwa ikiwa imeombwa wazi. Search loader fixes ni
exception wakati pages zilizokwisha kujengwa zinahitaji kusahihishwa mara moja.
- Ikiwa unabadilisha shared theme behavior, linganisha na usasishe file inayolingana kwenye
`/Users/carlospolop/git/hacktricks-cloud`.
- Usirevert local changes zisizohusiana.
