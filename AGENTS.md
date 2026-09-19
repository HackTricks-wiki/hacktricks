# AGENTS.md

이 저장소에서 작업하는 향후 agent를 위한 지침입니다.

## Repository Context

이 저장소는 기본 HackTricks mdBook repository입니다. 관련 cloud book은 다음 위치에 있습니다:

`/Users/carlospolop/git/hacktricks-cloud`

공유 theme/search 동작 변경 사항은 두 repository 모두에 적용해야 하는 경우가 많습니다.

## Search Index Loading Contract

custom search UI는 다음 위치에 있습니다:

`theme/ht_searcher.js`

다음 위치에 generated copy가 있을 수도 있습니다:

`book/theme/ht_searcher.js`

production에서 이미 build된 `book/` directory를 배포하는 경우 두 copy를 모두 업데이트하거나 배포 전에 book을 다시 build하세요.

search index loading 순서는 중요하며 비용에 영향을 줍니다:

1. GitHub repository에서 모든 language-specific 및 fallback search index를 load합니다:
`HackTricks-wiki/hacktricks-searchindex`
2. GitHub-hosted 후보가 모두 실패한 경우에만 same-origin mdBook output으로 fallback합니다.

`searchindex-en.js.gz`와 같은 GitHub-hosted fallback보다 먼저 local `/searchindex.js` fallback을 배치하지 마세요. production에서 `hacktricks.wiki`의 `searchindex.js`를 제공하는 것은 비용이 많이 듭니다.

이 repo에서 예상되는 local fallback은 다음과 같습니다:

`/searchindex.js`

cloud index는 이 origin의 local fallback을 사용하지 않아야 합니다. remote
`searchindex-cloud-<lang>.js.gz` 파일에 의존해야 합니다.

## Search Index Publishing

암호화된 압축 search index를
`HackTricks-wiki/hacktricks-searchindex`에 publish하는 workflows는 다음과 같습니다:

- `.github/workflows/build_master.yml`
- `.github/workflows/translate_all.yml`

generated source file은 `book/searchindex.js`입니다. publish되는 remote artifact 이름은 다음과 같습니다:

- `searchindex-v2-en.json.gz` (권장 compact index)
- `searchindex-v2-<lang>.json.gz` (권장 compact index)
- `searchindex-en.js.gz`
- `searchindex-<lang>.js.gz`

browser loader는 compact v2 artifact를 우선 사용하며 `.js.gz` artifact를 legacy fallback으로 유지합니다. 두 artifact 모두 `theme/ht_searcher.js`에 정의된 key를 사용하는 XOR-encrypted gzip payload입니다.

loader는 lazy 상태를 유지해야 합니다. 일반적인 page navigation에서는 visitor가 search를 열거나 사용할 때까지 search worker를 생성하거나 index를 download해서는 안 됩니다. remote compressed response는 origin별로 24시간 동안 Cache Storage에 저장되므로 이후 페이지에서 재사용할 수 있습니다. 만료된 entry의 refresh가 실패할 때 stale-cache fallback을 유지하세요.

## Build And Validation

일반적인 local check:

- `node --check theme/ht_searcher.js`
- `mdbook build`

`mdbook build`가 실패하면 다음을 확인하세요:

- `hacktricks-preprocessor-error.log`
- `hacktricks-preprocessor.log`

## Editing Notes

- 검색에는 `rg` 사용을 권장합니다.
- 명시적으로 요청되지 않는 한 generated `book/` output을 commit에 포함하지 마세요. 이미 build된 페이지를 즉시 수정해야 하는 경우에는 search loader 수정이 예외입니다.
- 공유 theme 동작을 변경하는 경우
`/Users/carlospolop/git/hacktricks-cloud`의 대응 파일을 비교하고 업데이트하세요.
- 관련 없는 local 변경 사항을 되돌리지 마세요.
