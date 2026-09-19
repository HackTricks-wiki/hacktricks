# AGENTS.md

Mwongozo kwa agents watakaofanya kazi kwenye repository hii.

## Muktadha wa Repository

Hii ni repository kuu ya HackTricks mdBook. Kitabu cha cloud kinachohusiana kinapatikana kwenye:

`/Users/carlospolop/git/hacktricks-cloud`

Mabadiliko kwenye shared theme/search behavior mara nyingi yanahitaji kutumika kwenye repositories zote mbili.

## Mkataba wa Kupakia Search Index

Custom search UI inapatikana kwenye:

`theme/ht_searcher.js`

Huenda pia kukawa na nakala iliyotengenezwa kwenye:

`book/theme/ht_searcher.js`

Ikiwa production inadeploy directory ya `book/` iliyokwisha kujengwa, sasisha nakala zote mbili au build upya
kitabu kabla ya deployment.

Sera ya source ya search index ni muhimu na ina athari kwenye gharama:

- Kwenye public hosts, pakia kila language-specific na fallback candidate kutoka
`HackTricks-wiki/hacktricks-searchindex` pekee. Usifanye fallback kwenda kwenye mdBook output yenye same-origin;
kuhudumia index kubwa kutoka `hacktricks.wiki` kwenye production ni ghali.
- Kwenye localhost, `.local`/`.internal` hosts, loopback, RFC1918, carrier-grade NAT, link-local, au
private IPv6 addresses, pakia same-origin mdBook output pekee ili local/container deployments zibaki
self-contained. Kwa ukurasa usio wa Kiingereza, jaribu language-prefixed local path kwanza
(kwa mfano `/es/searchindex.js`) na utumie root English index kama fallback pekee.

Kwa repo hii, local fallback inayotarajiwa ni:

`/searchindex.js`

Kwenye private hosts, cloud index haipatikani kutoka origin hii na haipaswi kuanzisha remote
download. Kwenye public hosts inapaswa kutumia remote `searchindex-cloud-<lang>.js.gz` files.

## Kuchapisha Search Index

Workflows zinazochapisha encrypted compressed search indexes kwenye
`HackTricks-wiki/hacktricks-searchindex` ni:

- `.github/workflows/build_master.yml`
- `.github/workflows/translate_all.yml`

Generated source file ni `book/searchindex.js`. Majina ya published remote artifacts ni:

- `searchindex-v2-en.json.gz` (preferred compact index)
- `searchindex-v2-<lang>.json.gz` (preferred compact index)
- `searchindex-en.js.gz`
- `searchindex-<lang>.js.gz`

Browser loader hupendelea compact v2 artifact na huhifadhi `.js.gz` artifact kama
legacy fallback. Zote mbili ni XOR-encrypted gzip payloads zikitumia key iliyofafanuliwa kwenye
`theme/ht_searcher.js`.

Loader lazima ibaki lazy: page navigation ya kawaida haipaswi kuunda search worker au kupakua index hadi
visitor afungue au atumie search. Remote compressed responses huhifadhiwa kwenye Cache
Storage kwa saa 24 kwa kila origin ili pages zinazofuata ziweze kuzitumia tena. Hifadhi
stale-cache fallback wakati ku-refresh entry iliyokwisha muda kunashindikana.

## Build Na Validation

Local checks za kawaida:

- `node --check theme/ht_searcher.js`
- `mdbook build`

Ikiwa `mdbook build` itashindikana, angalia:

- `hacktricks-preprocessor-error.log`
- `hacktricks-preprocessor.log`

## Maelezo ya Kuhariri

- Pendelea `rg` kwa utafutaji.
- Weka generated `book/` output nje ya commits isipokuwa imeombwa wazi. Search loader fixes ni
exception wakati pages zilizokwisha kujengwa lazima zirekebishwe mara moja.
- Ukibadilisha shared theme behavior, linganisha na usasishe file inayolingana kwenye
`/Users/carlospolop/git/hacktricks-cloud`.
- Usirevert local changes zisizohusiana.
