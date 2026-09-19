# AGENTS.md

이 저장소에서 작업하는 향후 agents를 위한 지침입니다.

## Repository Context

이 저장소는 기본 HackTricks mdBook repository입니다. 관련 cloud book은 다음 위치에 있습니다.

`/Users/carlospolop/git/hacktricks-cloud`

공유 theme/search 동작에 대한 변경 사항은 두 repository 모두에 적용해야 하는 경우가 많습니다.

## Search Index Loading Contract

custom search UI는 다음 위치에 있습니다.

`theme/ht_searcher.js`

다음 위치에 generated copy가 있을 수도 있습니다.

`book/theme/ht_searcher.js`

production에서 이미 빌드된 `book/` directory를 배포하는 경우 두 copy를 모두 업데이트하거나, 배포 전에 book을 다시 빌드하세요.

search index source policy는 중요하며 비용에 영향을 줍니다.

- public hosts에서는 모든 language-specific 및 fallback candidate를
`HackTricks-wiki/hacktricks-searchindex`에서만 load하세요. 동일 origin의 mdBook output으로 fallback하지 마세요. production에서 `hacktricks.wiki`가 큰 index를 제공하면 비용이 많이 듭니다.
- localhost, `.local`/`.internal` hosts, loopback, RFC1918, carrier-grade NAT, link-local 또는 private IPv6 addresses에서는 동일 origin의 mdBook output만 load하여 local/container deployments가 self-contained 상태로 유지되도록 하세요.

이 repo에서 예상되는 local fallback은 다음과 같습니다.

`/searchindex.js`

private hosts에서는 cloud index를 이 origin에서 사용할 수 없으므로 remote download를 trigger해서는 안 됩니다. public hosts에서는 `searchindex-cloud-<lang>.js.gz` files를 사용해야 합니다.

## Search Index Publishing

encrypted compressed search indexes를
`HackTricks-wiki/hacktricks-searchindex`에 publish하는 workflows는 다음과 같습니다.

- `.github/workflows/build_master.yml`
- `.github/workflows/translate_all.yml`

generated source file은 `book/searchindex.js`입니다. published remote artifact names는 다음과 같습니다.

- `searchindex-v2-en.json.gz` (preferred compact index)
- `searchindex-v2-<lang>.json.gz` (preferred compact index)
- `searchindex-en.js.gz`
- `searchindex-<lang>.js.gz`

browser loader는 compact v2 artifact를 우선 사용하며, `.js.gz` artifact는 legacy fallback으로 유지합니다. 두 artifact 모두 `theme/ht_searcher.js`에 정의된 key를 사용하는 XOR-encrypted gzip payload입니다.

loader는 lazy 상태를 유지해야 합니다. 일반적인 page navigation은 visitor가 search를 열거나 사용할 때까지 search worker를 생성하거나 index를 download해서는 안 됩니다. Remote compressed responses는 origin별로 24시간 동안 Cache Storage에 persist되므로 이후 pages에서 재사용할 수 있습니다. expired entry를 refresh하지 못할 때 stale-cache fallback을 유지하세요.

## Build And Validation

일반적인 local checks:

- `node --check theme/ht_searcher.js`
- `mdbook build`

`mdbook build`가 실패하면 다음을 확인하세요.

- `hacktricks-preprocessor-error.log`
- `hacktricks-preprocessor.log`

## Editing Notes

- 검색에는 `rg`를 우선 사용하세요.
- 명시적으로 요청되지 않는 한 generated `book/` output을 commits에 포함하지 마세요. 단, 이미 빌드된 pages를 즉시 수정해야 하는 경우에는 search loader fixes가 예외입니다.
- shared theme behavior를 변경하는 경우
`/Users/carlospolop/git/hacktricks-cloud`의 matching file을 비교하고 업데이트하세요.
- 관련 없는 local changes를 되돌리지 마세요.
