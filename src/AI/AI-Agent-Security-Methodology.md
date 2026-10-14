# AI Agent Security Methodology

{{#include ../banners/hacktricks-training.md}}

에이전트 평가는 **공격자가 제어하는 입력에서 외부로 관찰 가능한 영향까지** 이어지는 경로를 따라야 합니다. Jailbreaking, 문자 변경, system prompt 공개는 추론 채널에 영향을 줄 수 있음을 보여 주지만, 영향도가 큰 취약점은 데이터 접근, 무단 도구 동작, 후속 injection sink, 지속성 또는 다른 에이전트로 이어지는 체인입니다.<sup>[[2]](#references)</sup>

[OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)은 평가 범위를 분류하는 데 유용합니다(목표 하이재킹, 도구 오용, 권한 남용, 공급망, 코드 실행, 메모리 오염, 에이전트 간 신뢰, 연쇄 장애, 인간 신뢰, rogue agent). 모델의 예상치 못한 텍스트를 테스트의 끝으로 취급하지 말고, end-to-end 공격 경로를 구성한 뒤 이 분류를 적용하세요.<sup>[[1]](#references)[[2]](#references)</sup>

## 대상 맵 작성

payload를 작성하기 전에 각 에이전트 워크플로에 대해 다음 다섯 가지 차원을 기록하세요.<sup>[[2]](#references)</sup>

| 차원 | 열거할 항목 | 보안 질문 |
|---|---|---|
| **신뢰할 수 없는 입력** | Chat/API 매개변수, URL, 문서, 이메일, 티켓, 캘린더 항목, 검색된 청크, 메모리, 도구 결과, 피어 에이전트 메시지 | 나중에 모델 컨텍스트에 들어가는 콘텐츠를 공격자가 어디에 삽입할 수 있나요? |
| **도구** | 도구 이름과 스키마, 부작용, 자동 실행, 확인 동작, 동적으로 로드되는 도구 | 어떤 호출이 비밀을 읽고, 상태를 변경하고, 메시지를 보내고, 데이터를 삭제하고, 코드를 실행하거나, 가치를 이전하나요? |
| **권한** | 사용자 위임, 서비스 계정, API 토큰, 자격 증명 유효 기간, 테넌트/리소스 범위, 네트워크 접근 범위 | 각 호출은 어떤 ID로 실행되며, 도구 경계에서 권한 부여를 다시 확인하나요? |
| **처리** | 쿼리 빌더, 셸, URL fetcher, 템플릿 엔진, 인터프리터, 파서, 파일 작업, 역직렬화기 | 모델이 생성한 데이터가 다른 인터프리터의 구문이 되는 지점은 어디인가요? |
| **출력** | 응답, 렌더링된 Markdown/HTML, 링크, 이미지 fetch, 웹훅, 이메일, 파일, 로그, 보고서, 메트릭, 피어 에이전트 트래픽 | 어떤 관찰 가능한 채널이 비밀을 전달하거나 2차 요청을 유발할 수 있나요? |

이를 광고된 통합 목록으로 축약하지 마세요. 유용한 산출물은 각 소스가 도달하는 정확한 컨텍스트 위치, 해당 위치에서 사용 가능한 도구, 각 도구가 사용하는 자격 증명, 후속 인터프리터, 모든 egress 경로를 연결해 보여 줍니다. 동일한 도구라도 사용자별 읽기 토큰을 사용하면 영향도가 낮을 수 있고, 공유 관리자 자격 증명을 사용하면 치명적일 수 있습니다.<sup>[[2]](#references)</sup>

## 정찰

### 모든 전달 및 수집 경로 매핑

전달 표면(web, mobile, API, email, chat platform, browser extension)부터 시작해 클라이언트와 백엔드 간 트래픽을 프록시하세요. UI에서 숨겨진 필드, 검색/자동 완성/필터 매개변수, 대화 상태 객체, 업로드 및 인덱싱 작업, 도구 응답, 하위 에이전트 트래픽을 살펴보세요. 모바일 전용 클라이언트는 실제 요청 스키마를 확인하기 전에 certificate pinning을 우회하기 위해 에뮬레이터와 계측이 필요할 수 있습니다.<sup>[[2]](#references)</sup>

그런 다음 모델 아래의 스택을 매핑하세요. 오케스트레이션 프레임워크, 프롬프트 조립, 검색 및 메모리 저장소, 런타임(예: Python, 컨테이너 또는 WASM), 마운트된 볼륨, 호스트 서비스, 내부 API, cloud metadata 접근 가능성, 인접 네트워크를 확인합니다. 일부 “도구 호출”은 코드를 생성하거나 평가해 구현되므로 프레임워크의 기본 설정이 중요합니다. 런타임/샌드박스 경계에 따라 그 결과가 격리된 상태로 유지되는지가 결정됩니다.<sup>[[2]](#references)</sup>

### 비파괴 프로브로 라우팅 식별

범위 내 요청과 관련 없는 여러 요청을 비교하면서 전체 응답, 상태 코드, 지연 시간, 스트리밍 동작을 보존하세요. 작업별 추론이 시작되기 전에 일관되게 거부된다면 별도의 gateway/classifier일 수 있고, 맥락에 맞는 거부는 요청이 모델에 도달했음을 시사하며, 비어 있거나 추출만 하는 응답은 키워드 검색 또는 제한적인 검색을 나타낼 수 있습니다. 이를 가설로 취급하고 동일한 프로브를 다른 API 필드와 수집 경로를 통해 재전송해 확인하세요.<sup>[[2]](#references)</sup>

정찰은 평가자가 에이전트의 동작을 바꾸는 공격자 제어 소스의 가장 앞단과, 해당 소스에서 도달 가능한 도구, ID, 인터프리터, 출력을 명시할 수 있을 때 완료됩니다.<sup>[[2]](#references)</sup>

## Exploitation: 신뢰 경계 넘기

프롬프트 표현만이 아니라 채널을 테스트하세요. 먼저 직접 injection으로 사용자에게 보이는 진입점에서 무엇이 차단되는지 확인한 다음, 아래의 덜 드러나는 경로를 통해 동등한 의도를 다시 테스트하세요.<sup>[[2]](#references)</sup>

- **간접 콘텐츠:** 페이지, 파일, 이메일, 티켓, 메타데이터, alt text, HTML 주석, 화면에 보이지 않는 텍스트 또는 zero-width 문자. payload 전달 기법은 [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection)를 참조하세요.
- **검색 및 메모리:** 나중에 검색될 콘텐츠 또는 이후 세션에서 다시 로드될 상태를 오염시키세요. 원본 소스를 삭제하면 동작도 사라지는지 기록하세요.
- **도구 출력 및 피어 에이전트:** 도구 응답이나 에이전트 간 메시지에 마커를 넣어 내부 트래픽이 사용자 입력과 최종 출력에만 적용되는 필터를 우회하는지 테스트하세요.
- **공급망:** 도구 설명자, 플러그인, 연결된 서버, skill, 모델, 종속성을 신뢰할 수 있는 지시 소스로 검토하세요. MCP 관련 테스트는 [MCP Servers](AI-MCP-Servers.md#mcp-vulns)를 참조하세요.
- **인간 승인:** 실제 구조화된 도구 호출과 모델이 생성한 승인 문구를 비교하세요. 공격자의 영향으로 대상, 범위, 영향을 받는 객체 또는 되돌릴 수 없는 부작용이 생략될 수 있는지 테스트하세요.

먼저 무해하고 고유한 마커를 사용하세요. 소스 아티팩트, 관찰 가능한 경우 조립된 컨텍스트, 선택된 도구 호출, 승인 데이터, 백엔드 요청/응답, 최종 상태를 보존하세요. 이를 통해 영향력 행사와 실제 동작이 발생했다는 환각 주장을 구분할 수 있습니다.<sup>[[2]](#references)</sup>

### 하위 에이전트 컨텍스트 격리

fork가 아닌 Claude Agent SDK 하위 에이전트는 자체 `AgentDefinition.prompt`, 위임 프롬프트, 사용 가능한 도구를 받지만 부모 system prompt나 대화 내용은 받지 않습니다. 정의에서 `tools`를 생략하면 하위 에이전트가 사용할 수 있는 도구를 상속합니다. 프로젝트의 `CLAUDE.md`는 여전히 로드될 수 있습니다. 따라서 자식이 동일한 파일 시스템이나 실행 도구를 사용할 수 있다면 부모에만 적용되는 프롬프트 제한은 신뢰할 수 있는 경계가 아닙니다.<sup>[[4]](#references)</sup>

부모가 거부하는 직접 요청과, 이름이 지정된 하위 에이전트에 위임한 동일 작업을 비교해 경계를 테스트하세요. NCC Group은 운영 체제 파일 목록 조회 요청이 거부되었지만, 자식에게 무해한 "layout map"으로 재구성해 전달하자 성공했다고 보고합니다.<sup>[[3]](#references)</sup>

부모의 최종 답변만 보지 말고 자식의 실제 도구 호출과 유효 도구 허용 목록을 확인하세요. 자식이 부모라면 접근하지 못했을 파일에 접근했는지 확인합니다.<sup>[[4]](#references)</sup> 이는 guardrail 상속 실패이지, [Python sandbox](../generic-methodologies-and-resources/python/bypass-python-sandboxes/) 또는 컨테이너 탈출의 증거는 아닙니다.<sup>[[3]](#references)[[4]](#references)</sup>

## 실행: 실제 영향 입증

영향력 행사에서 실제 영향으로 이어지는 경로는 서로 다른 두 가지입니다.<sup>[[2]](#references)</sup>

1. **기능 남용:** 권한이 부여된 도구 자체가 이미 목적한 작업을 수행합니다. 예를 들면 한 테넌트의 레코드를 읽어 공격자가 볼 수 있는 보고서에 기록하기, 이메일 보내기, 레코드 변경, 파일 삭제, 결제 시작 등이 있습니다. 추가 소프트웨어 취약점은 필요하지 않습니다.
2. **후속 sink 악용:** 공격자가 유도한 모델 출력이 다른 구성 요소의 구문이 됩니다. 데이터베이스 쿼리에서 [SQL injection](../pentesting-web/sql-injection/README.md) 또는 [NoSQL injection](../pentesting-web/nosql-injection.md), 셸 래퍼에서 [command injection](../pentesting-web/command-injection.md), 선택된 URL에서 [SSRF](../pentesting-web/ssrf-server-side-request-forgery/README.md), 파일 작업에서 경로 순회, 템플릿/코드 평가기에서 RCE, 객체 파서에서 [unsafe deserialization](../pentesting-web/deserialization/README.md)이 가능한지 검토하세요.

각 후보에 대해 다음 체인을 입증하세요.<sup>[[2]](#references)</sup>

```text
attacker-controlled source
  -> model/context influence
  -> selected tool and arguments
  -> effective identity/credential
  -> capability or vulnerable sink
  -> externally verified state change or data egress
```

읽기 전용 integration이라도 이후의 어떤 구성 요소든 읽은 내용을 게시할 수 있다면 악용될 수 있습니다. 일반적인 응답뿐 아니라 공격자가 제어하는 링크, 자동 이미지 가져오기, webhooks, 로그, 보고서, 카운터, 알림, 다른 agent에게 보내는 메시지 등 덜 분명한 egress도 테스트하세요.<sup>[[2]](#references)</sup>

## 목표에 대한 작업

한 가지 작업을 확인한 뒤에는 처음 눈에 보이는 효과에서 멈추지 말고 전체 blast radius를 평가하세요.<sup>[[2]](#references)</sup>

- **유출:** secrets, 사용자 레코드, 내부 파일, 대화 데이터 또는 prompt/context 내용이 관찰 가능한 채널을 통해 외부로 나갑니다.
- **무단 작업:** agent가 공격자의 목적을 위해 정당한 쓰기 권한을 사용합니다.
- **서비스 거부:** 파괴적인 도구나 반복적인 고비용 작업이 무결성 또는 가용성에 영향을 줍니다.
- **지속성:** 오염된 memory, 인덱싱된 콘텐츠, 신뢰된 상태 또는 런타임 변경 사항이 원래 세션이나 출처가 제거된 뒤에도 남습니다.
- **전파:** 신뢰된 피어가 침해된 agent의 메시지나 공유 상태를 받아들여 자신의 도구와 자격 증명으로 작업을 반복합니다.

심각도는 모델의 응답이 얼마나 놀라운지가 아니라, 접근 가능한 데이터, 실효 권한, sink의 악용 가능성, egress, 지속성 및 전파 가능성에 따라 판단해야 합니다.<sup>[[2]](#references)</sup>

## 평가 중 검증할 통제

Prompt filter와 더 나은 system prompt는 공격 비용을 높일 수 있지만, 이를 권한 부여 경계로 간주해서는 안 됩니다. 아래 통제를 직접 입력, 간접 콘텐츠, memory, 도구 및 피어 agent를 통한 동일한 chain을 다시 실행해 검증하세요.<sup>[[2]](#references)</sup>

- 결정론적 policy 계층이 **모든 도구 호출**에서 인증된 사용자, tenant, 객체, 작업 및 목적지를 확인합니다. 모델은 호출자 신원을 제공하거나 덮어쓸 수 없습니다.
- 읽기 및 쓰기 권한은 별도의 최소 권한 단기 자격 증명을 사용합니다. 영향이 큰 도구는 필요한 시점에만 제공되며 수집된 콘텐츠로부터 자동 실행되지 않습니다.
- 네트워크 egress 및 내부 목적지는 모델이 선택한 URL과 별도로 allowlist로 제한합니다. 런타임의 metadata endpoint, 마운트된 secrets 및 인접 서비스 접근은 필요한 경우가 아니면 차단합니다.
- 승인 UI는 표준 구조화 요청으로 생성되며, 자유 형식의 모델 요약이 아니라 정확한 인수, 신원, 목적지, 영향받는 객체 및 부수 효과를 표시합니다.
- 성공 여부는 대상 시스템 또는 기준 시스템에서 검증합니다. agent의 설명, 도구 호출 요청 또는 HTTP redirect는 주장된 상태 변경의 증거가 아닙니다.
- Memory 및 검색 항목에는 출처와 신뢰 레이블이 유지되고, 무효화할 수 있으며, 이후 작업에 사용될 때 다시 권한을 확인합니다.
- Agent 간 메시지는 인증되며 신뢰할 수 없는 요청으로 취급됩니다. 피어의 평판이나 agent card만으로 수신자의 도구 사용 권한이 위임되지는 않습니다.

## References

- [1] [2026년 Agentic Applications를 위한 OWASP Top 10](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [2] [AI Agent 공격을 위한 해커 가이드](https://darkmarc.substack.com/p/the-hackers-guide-to-attacking-ai)
- [3] [AI Agent를 샌드박스에서 탈출시키는 일은 실제로 얼마나 어려운가?](https://www.nccgroup.com/research/how-hard-is-it-really-to-break-an-ai-agent-out-of-its-sandbox/)
- [4] [SDK의 Subagent](https://code.claude.com/docs/en/agent-sdk/subagents)
{{#include ../banners/hacktricks-training.md}}
