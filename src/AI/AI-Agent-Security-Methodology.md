# AI Agent 보안 방법론

{{#include ../banners/hacktricks-training.md}}

에이전트 평가는 **공격자가 제어하는 입력에서 외부에서 관찰 가능한 영향까지** 이어지는 경로를 따라야 합니다. Jailbreaking, 캐릭터 변경, system prompt 공개는 추론 채널이 조작될 수 있음을 보여주지만, 영향도가 큰 finding은 데이터 접근, 무단 tool 동작, 다운스트림 injection sink, 지속성 또는 다른 에이전트로 이어지는 연쇄입니다.<sup>[[2]](#references)</sup>

[OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)은 테스트 범위(goal hijacking, tool misuse, privilege abuse, supply chain, code execution, memory poisoning, inter-agent trust, cascading failures, human trust, rogue agents)를 분류하는 데 유용합니다. 모델이 예상하지 못한 텍스트를 생성한 것을 테스트의 끝으로 간주하지 말고, end-to-end attack path를 구성한 뒤 이 분류를 사용하세요.<sup>[[1]](#references)[[2]](#references)</sup>

## 대상 맵 작성

payload를 작성하기 전에 각 에이전트 workflow에 대해 다음 다섯 가지 차원을 기록하세요.<sup>[[2]](#references)</sup>

| 차원 | 열거할 항목 | 보안 질문 |
|---|---|---|
| **신뢰할 수 없는 입력** | Chat/API 매개변수, URL, 문서, 이메일, 티켓, 캘린더 항목, 검색된 청크, 메모리, tool 결과, 피어 에이전트 메시지 | 공격자가 나중에 모델 컨텍스트에 들어갈 콘텐츠를 어디에 배치할 수 있는가? |
| **Tools** | Tool 이름과 스키마, 부작용, 자동 실행 여부, 확인 동작, 동적으로 로드되는 tools | 어떤 호출이 비밀을 읽고, 상태를 쓰고, 메시지를 보내고, 데이터를 삭제하고, 코드를 실행하거나, 자산을 이전하는가? |
| **권한** | 사용자 위임, 서비스 계정, API 토큰, 자격 증명 수명, 테넌트/리소스 범위, 네트워크 접근성 | 각 호출은 어떤 identity로 실행되며, tool 경계에서 권한 부여를 다시 확인하는가? |
| **처리** | Query builder, shell, URL fetcher, template engine, interpreter, parser, 파일 작업, deserializer | 모델이 생성한 데이터가 다른 interpreter의 구문이 되는 지점은 어디인가? |
| **출력** | 응답, 렌더링된 Markdown/HTML, 링크, 이미지 fetch, webhook, 이메일, 파일, 로그, 보고서, 메트릭, 피어 에이전트 트래픽 | 어떤 관찰 가능한 채널이 비밀을 전달하거나 2차 요청을 트리거할 수 있는가? |

이를 광고된 통합 기능 목록으로 축약하지 마세요. 유용한 산출물은 각 입력 출처가 도달하는 정확한 컨텍스트 위치, 그 시점에 사용 가능한 tools, 각 tool이 사용하는 자격 증명, 다운스트림 interpreter, 모든 egress 경로를 매핑합니다. 사용자별 읽기 토큰을 사용하는 동일한 tool은 영향도가 낮을 수 있지만, 공유 관리자 자격 증명을 사용하면 치명적일 수 있습니다.<sup>[[2]](#references)</sup>

## 정찰

### 모든 전달 및 수집 경로 매핑

전달 표면(web, mobile, API, email, chat platform, browser extension)에서 시작해 클라이언트와 백엔드 간 트래픽을 프록시하세요. UI에서 숨겨진 필드, 검색/autocomplete/filter 매개변수, 대화 상태 객체, 업로드 및 인덱싱 작업, tool 응답, 하위 에이전트 트래픽을 검사하세요. 실제 요청 스키마를 확인하기 전에 certificate pinning을 우회해야 하는 경우, 모바일 전용 클라이언트에 emulator와 instrumentation이 필요할 수 있습니다.<sup>[[2]](#references)</sup>

그런 다음 모델 아래의 스택을 매핑하세요. orchestration framework, prompt assembly, retrieval 및 memory 저장소, runtime(예: Python, container, WASM), 마운트된 볼륨, 호스트 서비스, 내부 API, cloud metadata 접근성, 인접 네트워크가 여기에 포함됩니다. 일부 “tool call”은 코드를 생성하거나 평가해 구현되므로 framework 기본 설정이 중요합니다. 결과가 격리된 상태로 유지되는지는 runtime/sandbox 경계에 달려 있습니다.<sup>[[2]](#references)</sup>

### 비파괴 probe로 라우팅 식별

범위 내 요청과 관련 없는 몇 가지 요청을 비교하면서 전체 응답, 상태 코드, 지연 시간, streaming 동작을 보존하세요. 작업별 추론이 시작되기 전 일관되게 거부되면 별도의 gateway/classifier일 수 있고, 맥락에 따른 거부는 요청이 모델에 도달했음을 시사하며, 비어 있거나 순수하게 추출된 답변은 keyword search 또는 제한적 retrieval을 시사할 수 있습니다. 이는 가설로 취급하고, 동일한 probe를 다른 API 필드와 수집 경로를 통해 재전송해 확인하세요.<sup>[[2]](#references)</sup>

평가자가 에이전트 동작을 바꾸는 최초의 공격자 제어 입력 출처와, 그 출처에서 접근할 수 있는 tools, identities, interpreters, outputs를 명시할 수 있다면 정찰이 완료된 것입니다.<sup>[[2]](#references)</sup>

## 공격: 신뢰 경계 넘기

prompt 표현만이 아니라 채널을 테스트하세요. 먼저 직접 injection으로 사용자에게 보이는 진입점이 무엇을 차단하는지 확인한 뒤, 아래의 덜 보이는 경로를 통해 동일한 의도를 전달하세요.<sup>[[2]](#references)</sup>

- **간접 콘텐츠:** 페이지, 파일, 이메일, 티켓, 메타데이터, alt text, HTML 주석, 화면 밖 텍스트 또는 zero-width 문자. payload 전달 기법은 [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection)를 참고하세요.
- **Retrieval 및 memory:** 나중에 검색될 콘텐츠 또는 이후 세션에서 다시 로드될 상태를 오염시키세요. 원본을 삭제했을 때 동작이 사라지는지 기록하세요.
- **Tool 출력 및 피어 에이전트:** tool 응답이나 에이전트 간 메시지에 marker를 넣어 내부 트래픽이 사용자 입력과 최종 출력에만 적용되는 필터를 우회하는지 테스트하세요.
- **Supply chain:** tool 설명자, 플러그인, 연결된 서버, skills, 모델, 의존성을 신뢰할 수 있는 지시 출처로 검토하세요. MCP 전용 테스트는 [MCP Servers](AI-MCP-Servers.md#mcp-vulns)를 참고하세요.
- **사람의 승인:** 실제 구조화된 tool call과 모델이 생성한 승인 문구를 비교하세요. 공격자의 영향으로 목적지, 범위, 영향받는 객체 또는 되돌릴 수 없는 부작용이 누락될 수 있는지 테스트하세요.

먼저 무해하고 고유한 marker를 사용하세요. 출처 artifact, 관찰 가능한 경우 조립된 컨텍스트, 선택된 tool call, 승인 데이터, 백엔드 요청/응답, 최종 상태를 보존하세요. 이렇게 하면 실제 영향 없이 모델이 조치가 일어났다고 주장하는 경우와 실제 조작을 구분할 수 있습니다.<sup>[[2]](#references)</sup>

### Tool-risk judge의 정책을 가장한 텍스트

모델 기반 tool gate는 유용한 분류 컨텍스트 안에 공격자가 제어하는 텍스트를 받을 수 있습니다. 예를 들어 LangChain의 experimental `AutoModeMiddleware`는 제안된 tool call, 해당 인수, 선택적 tool 설명, 최근 메시지 최대 30개를 TypeSafe `is_risky` judge에 전달합니다. 반환된 Noul 확률이 `0.5` 이상이면 설정된 tools를 차단하며, 목록에 없는 tools는 이 middleware에서 분류하지 않습니다.<sup>[[5]](#references)</sup> TypeSafe는 state가 데이터 용도로 쓰이더라도 state 안의 adversarial text가 분류에 영향을 줄 수 있다고 경고합니다.<sup>[[6]](#references)</sup>

**위조된 정책**은 단순히 system message라고 주장하는 것과 다릅니다. 신뢰도가 낮은 state에 대체 label이나 위험 정의를 넣고, judge가 developer가 정의한 기준 대신 이 정의를 사용하도록 유도합니다. Datadog의 테스트에서는 사용자가 수정할 수 있는 `profile_description`이 `can_edit:false`와 함께 tool 인수에 복사되었습니다. 정책처럼 보이는 해당 텍스트는 별도의 권한 확인이 변경 전에 쓰기 시도를 거부해야 하므로 쓰기 시도는 위험도가 낮다고 주장했습니다. 40회 실행에서 평균 `is_risky` 점수는 `0.893`에서 `0.290`으로 낮아졌고, 직접적인 role-spoofing 비교의 평균은 `0.905`였습니다. 평균이 `0.5` 미만이라고 해서 모든 개별 호출이 gate를 통과했다는 뜻은 아니며, 이 실험에서 무단 쓰기가 완료된 것도 입증되지 않았습니다.<sup>[[7]](#references)</sup>

이 경계를 테스트할 때는 classifier 판정과 tool의 실제 권한 부여 결과를 구분하세요. 수정 가능한 필드 중 어떤 것이 judge에 전달되는지 확인하고, 정책처럼 보이는 텍스트가 있는 경우와 없는 경우의 동일한 동작을 비교한 다음 최종 상태를 독립적으로 확인하세요. 별도의 권한 확인은 connector의 서비스 계정 권한이 아니라 인증된 요청자의 권한을 사용해야 합니다.<sup>[[7]](#references)</sup> 다른 classifier 실패 유형은 [prompt-filter bypasses](AI-Prompts.md#prompt-waf-bypass)를 참고하세요. [LLM gateway trust boundaries](AI-LLM-Gateway-Security.md)는 다른 라우팅 및 자격 증명 경계를 다룹니다.

### 하위 에이전트 컨텍스트 격리

fork되지 않은 Claude Agent SDK 하위 에이전트는 자체 `AgentDefinition.prompt`, 위임 prompt, 사용 가능한 tools를 받지만 부모 system prompt나 대화는 받지 않습니다. 정의에서 `tools`를 생략하면 하위 에이전트에 제공되는 tools를 상속합니다. 프로젝트의 `CLAUDE.md`는 여전히 로드될 수 있습니다. 따라서 자식이 동일한 파일 시스템이나 실행 tools를 사용할 수 있는 경우, 부모에만 설정된 prompt 제한은 신뢰할 수 있는 경계가 아닙니다.<sup>[[4]](#references)</sup>

경계를 테스트하려면 부모가 거부하는 직접 요청과 동일한 작업을 명명된 하위 에이전트에게 위임한 경우를 비교하세요. NCC Group은 운영 체제 파일 열거 요청이 거부된 후, 자식에게는 무해한 “layout map”으로 바꿔 요청하자 성공했다고 보고했습니다.<sup>[[3]](#references)</sup>

부모의 최종 답변만 보지 말고 자식의 실제 tool call과 유효한 tool allowlist를 검사하세요. 자식이 부모라면 접근하지 않았을 파일에 접근했는지 확인하세요.<sup>[[4]](#references)</sup> 이는 guardrail 상속 실패이지 [Python sandbox](../generic-methodologies-and-resources/python/bypass-python-sandboxes/) 또는 container escape의 증거는 아닙니다.<sup>[[3]](#references)[[4]](#references)</sup>

## 실행: 실제 영향 입증

영향을 유발하는 경로는 두 가지로 구분됩니다.<sup>[[2]](#references)</sup>

1. **기능 남용:** 권한이 부여된 tool 자체가 목적을 수행합니다. 예를 들어 한 테넌트의 레코드를 읽고 공격자가 볼 수 있는 보고서에 기록하거나, 이메일을 보내거나, 레코드를 변경하거나, 파일을 삭제하거나, 결제를 시작하는 경우입니다. 2차 소프트웨어 취약점은 필요하지 않습니다.
2. **다운스트림 sink 악용:** 공격자가 유도한 모델 출력이 다른 구성 요소의 구문이 됩니다. 데이터베이스 query에서 [SQL injection](../pentesting-web/sql-injection/README.md) 또는 [NoSQL injection](../pentesting-web/nosql-injection.md), shell wrapper에서 [command injection](../pentesting-web/command-injection.md), 선택된 URL에서 [SSRF](../pentesting-web/ssrf-server-side-request-forgery/README.md), 파일 작업에서 traversal, template/code evaluator에서 RCE, 객체 parser에서 [unsafe deserialization](../pentesting-web/deserialization/README.md)을 검토하세요.

각 후보에 대해 다음 연쇄를 입증하세요.<sup>[[2]](#references)</sup>

```text
attacker-controlled source
  -> model/context influence
  -> selected tool and arguments
  -> effective identity/credential
  -> capability or vulnerable sink
  -> externally verified state change or data egress
```

읽기 전용 통합도 이후의 어떤 구성 요소든 읽은 내용을 게시할 수 있다면 악용될 수 있습니다. 일반적인 응답뿐 아니라 공격자가 제어하는 링크, 자동 이미지 가져오기, 웹훅, 로그, 보고서, 카운터, 알림, 다른 agent에 보내는 메시지 등 눈에 잘 띄지 않는 egress 경로도 테스트하세요.<sup>[[2]](#references)</sup>

## 목표에 대한 조치

한 가지 조치를 확인한 뒤에는 처음 눈에 보이는 효과에서 멈추지 말고 전체 영향 범위를 평가하세요.<sup>[[2]](#references)</sup>

- **Exfiltration:** 비밀, 사용자 기록, 내부 파일, 대화 데이터 또는 프롬프트/컨텍스트 내용이 관찰 가능한 채널을 통해 외부로 유출됩니다.
- **Unauthorized action:** agent가 공격자의 목적을 위해 합법적인 쓰기 권한을 사용합니다.
- **Denial of service:** 파괴적인 도구나 반복적인 고비용 작업이 무결성 또는 가용성에 영향을 줍니다.
- **Persistence:** 오염된 메모리, 색인된 콘텐츠, 신뢰된 상태 또는 런타임 변경 사항이 원래 세션이나 출처를 제거한 뒤에도 유지됩니다.
- **Propagation:** 신뢰된 피어가 침해된 agent의 메시지나 공유 상태를 사용하고, 자체 도구와 자격 증명으로 해당 조치를 반복합니다.

심각도는 모델의 응답이 얼마나 놀라운지가 아니라 접근 가능한 데이터, 실질적인 권한, sink의 악용 가능성, egress, 지속성 및 전파 가능성을 기준으로 판단해야 합니다.<sup>[[2]](#references)</sup>

## 평가 중 검증할 통제 항목

프롬프트 필터와 개선된 system prompt는 공격자의 비용을 높일 수 있지만, 권한 부여 경계로 간주해서는 안 됩니다. 직접 입력, 간접 콘텐츠, 메모리, 도구, 피어 agent를 통해 동일한 공격 체인을 다시 실행하여 아래 통제를 검증하세요.<sup>[[2]](#references)</sup>

- 결정론적 정책 계층이 **모든 도구 호출**에서 인증된 사용자, 테넌트, 객체, 작업 및 대상을 확인합니다. 모델은 호출자의 ID를 제공하거나 덮어쓸 수 없습니다.
- 읽기 및 쓰기 권한은 분리된 최소 권한의 단기 자격 증명을 사용합니다. 영향이 큰 도구는 필요한 시점에만 제공하며 수집된 콘텐츠로부터 자동 실행되지 않습니다.
- 네트워크 egress와 내부 대상은 모델이 선택한 URL과 별도로 허용 목록으로 관리합니다. 필요한 경우가 아니라면 런타임에서 메타데이터 엔드포인트, 마운트된 비밀 정보 및 인접 서비스에 접근하지 못하도록 차단합니다.
- 승인 UI는 표준 구조화 요청을 바탕으로 생성되며, 모델이 자유 형식으로 요약한 내용이 아니라 정확한 인수, ID, 대상, 영향을 받는 객체 및 부수 효과를 표시합니다.
- 성공 여부는 대상 시스템 또는 기준 시스템에서 확인합니다. agent의 설명, 도구 호출 요청 또는 HTTP 리디렉션은 주장된 상태 변경의 증거가 아닙니다.
- 메모리 및 검색 항목에는 출처와 신뢰 레이블이 유지되고, 무효화할 수 있으며, 이후 작업에 사용될 때 다시 권한을 확인합니다.
- agent 간 메시지는 인증 및 권한 확인을 거치는 신뢰할 수 없는 요청으로 취급합니다. 피어의 평판이나 agent card가 수신자의 도구 사용 권한을 암묵적으로 위임하지는 않습니다.

A2A agent card, 작업 흐름 및 공격 표면은 [A2A Protocol Security](AI-A2A-Protocol.md)를 확인하세요.

## References

- [1] [2026년 Agentic 애플리케이션을 위한 OWASP Top 10](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [2] [AI Agent 공격을 위한 해커 가이드](https://darkmarc.substack.com/p/the-hackers-guide-to-attacking-ai)
- [3] [AI Agent를 샌드박스에서 탈출시키는 것은 실제로 얼마나 어려운가?](https://www.nccgroup.com/research/how-hard-is-it-really-to-break-an-ai-agent-out-of-its-sandbox/)
- [4] [SDK의 Subagents](https://code.claude.com/docs/en/agent-sdk/subagents)
- [5] [LangChain TypeSafe Auto Mode 미들웨어 소스 코드](https://github.com/langchain-ai/langchain/blob/master/libs/partners/typesafe/langchain_typesafe/experimental/middleware/auto_mode.py)
- [6] [TypeSafe AI Jev 모델의 들쭉날쭉함: 적대적 콘텐츠](https://docs.typesafe.ai/model-jaggedness/jev-1.13#adversarial-content)
- [7] [판사로서의 Jev: 위조된 정책은 Jev를 어떻게 유도하는가](https://securitylabs.datadoghq.com/articles/jev-as-a-judge-how-counterfeit-policy-steers-jev/)
{{#include ../banners/hacktricks-training.md}}
