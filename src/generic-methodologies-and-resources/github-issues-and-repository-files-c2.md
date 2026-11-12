# GitHub Issues와 Repository Files를 C2 Channel로 사용하기

{{#include ../banners/hacktricks-training.md}}

비공개 repository는 **session state**와 **payload 전송**을 분리할 수 있습니다. issue에는 각 호스트와 핸드셰이크 상태를 기록하고, repository 파일은 양방향으로 암호화된 데이터를 전달합니다. 이는 단순히 issue 본문에서 명령을 폴링하는 것 이상입니다. 관찰된 구현은 두 API에 모두 액세스하기 위해 GitHub personal access token (PAT)을 사용합니다.<sup>[[1]](#references)</sup> Fine-grained PAT로 issue를 생성하거나 업데이트하려면 Issues write 권한이 필요하고, 파일을 업로드하려면 Contents write 권한이 필요합니다. 반면 classic PAT에는 `repo` scope가 필요합니다. 충분한 권한을 가진 토큰을 획득한 사람은 누구나 같은 채널에 액세스할 수 있습니다.<sup>[[2]](#references)[[3]](#references)</sup>

## Issue와 파일 핸드셰이크

관찰된 워크플로 중 하나는 짧은 hexadecimal 호스트 ID와 다음 상태 머신을 사용합니다. 정확한 ID 범위, 문자열 및 prefix는 프로토콜 표식이지 GitHub API의 요구사항은 아닙니다.<sup>[[1]](#references)</sup>

1. 시작 시 `GET /repos/{owner}/{repo}/issues?state=open` (및 `state=closed`)를 사용해 open 및 closed issue를 조회하고 이전 session state를 찾습니다. `POST /repos/{owner}/{repo}/issues`로 본문이 `hel`인 `1[ID]` 제목의 open issue를 생성합니다.
2. 이름이 `2[ID]`로 시작하는 repository 파일을 읽습니다. 이 파일은 서버의 RSA public key를 제공합니다. 새 16-byte session key를 생성해 RSA로 암호화한 다음, `1[ID]` prefix가 붙은 파일로 업로드합니다.
3. 내장된 IV와 해당 session key를 XOR하여 이후 사용할 IV를 도출합니다. 주고받는 각 파일의 경우, 파일 이름에 포함된 임의의 16-byte key를 사용해 콘텐츠를 AES로 암호화하거나 복호화합니다. `2` prefix는 서버에서 호스트로 전송되는 데이터를, `1` prefix는 호스트에서 서버로 전송되는 데이터를 나타냅니다. 따라서 파일 이름에는 라우팅 정보와 파일별 key material이 담기고, issue에는 상태가 담깁니다.
4. 다음 `2` prefix 파일을 읽고 복호화된 콘텐츠가 `hel`과 일치하는지 확인합니다. 암호화된 호스트 정보를 업로드한 다음, `PATCH /repos/{owner}/{repo}/issues/{issue_number}`로 issue 본문을 `hey`로 변경합니다. 그제야 명령 폴링을 시작합니다.

GitHub Contents API는 `GET /repos/{owner}/{repo}/contents/{path}`로 파일을 읽고, 해당 경로에 `PUT` 요청을 보내 파일을 생성하거나 교체합니다. 1 MB 이하의 파일은 기본 JSON 응답에 Base64로 인코딩된 콘텐츠가 포함됩니다. 1~100 MB 파일의 콘텐츠를 가져오려면 raw media type이 필요합니다. 업로드 요청 본문에는 commit message와 Base64로 인코딩된 파일 콘텐츠가 필요합니다. 기존 파일을 교체할 때는 현재 blob SHA도 필요합니다. 이러한 API 세부사항은 위의 암호화 프로토콜과는 별개입니다.<sup>[[2]](#references)[[3]](#references)</sup>

승인된 테스트 repository에서는 REST API를 사용해 issue 제어 부분을 시험할 수 있습니다(테스트용 repository와 테스트 PAT로 대체하세요). 실제 token을 URL, issue 본문 또는 commit된 파일에 넣지 마세요.<sup>[[2]](#references)</sup>

```bash
base="https://api.github.com/repos/$OWNER/$REPO"
curl -fsS -H "Authorization: Bearer $GH_TOKEN" "$base/issues?state=open"
issue_number=$(curl -fsS -X POST -H "Authorization: Bearer $GH_TOKEN" -H 'Accept: application/vnd.github+json' \
  "$base/issues" -d '{"title":"11000","body":"hel"}' | jq -r .number)
curl -fsS -X PATCH -H "Authorization: Bearer $GH_TOKEN" -H 'Accept: application/vnd.github+json' \
  "$base/issues/$issue_number" -d '{"body":"hey"}'
```

이 메커니즘은 이슈 제목, `hel`/`hey` 마커 또는 여기에 표시된 특정 암호 선택을 필요로 하지 않습니다. 이러한 요소는 하나의 구현을 나타냅니다. 재사용 가능한 핵심 아이디어는 변경 가능한 호스트 상태를 양방향 암호화 객체와 분리하고, 둘 다 호스트 ID에 연결하는 것입니다.<sup>[[1]](#references)</sup> 다른 GitHub 이슈 전송 방식은 [AdaptixC2 custom listener notes](basic-forensic-methodology/adaptixc2-config-extraction-and-ttps.md#custom-listener-profiles-dont-hard-code-only-the-classic-http-schema)를 참조하세요. 세션 상태를 전달하는 대신 저장소 자격 증명을 교체하는 이슈 댓글 대체 방식은 [Web services and dead-drop resolvers](../privacy/offensive-infrastructure-and-attribution-evasion.md#web-services-and-dead-drop-resolvers)를 참조하세요.

## References

- [1] [Kaspersky Securelist – Operation FlashHole](https://securelist.com/lazarus-operation-flashhole/121541/)
- [2] [GitHub 문서 – 이슈 관련 REST API 엔드포인트](https://docs.github.com/en/rest/issues/issues)
- [3] [GitHub 문서 – 저장소 콘텐츠 관련 REST API 엔드포인트](https://docs.github.com/en/rest/repos/contents)
