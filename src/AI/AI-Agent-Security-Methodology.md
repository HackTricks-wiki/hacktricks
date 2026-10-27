# AI Agent Security Methodology

{{#include ../banners/hacktricks-training.md}}

에이전트 평가는 **공격자가 제어하는 입력에서 외부에 관찰 가능한 효과까지**를 따라가야 합니다. Jailbreaking, 문자 변경, system prompt 공개는 추론 채널에 영향을 줄 수 있음을 보여주지만, 영향력이 큰 finding은 데이터 접근, 권한 없는 tool 작업, 후속 injection sink, 지속성 또는 다른 에이전트로 이어지는 공격 체인입니다.<sup>[[2]](#references)</sup>

[OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)은 테스트 범위에 라벨을 붙이는 데 유용합니다(goal hijacking, tool misuse, privilege abuse, supply chain, code execution, memory poisoning, inter-agent trust, cascading failures, human trust, rogue agents). 모델이 예상치 못한 텍스트를 출력한 것을 테스트의 끝으로 보지 말고, end-to-end 공격 경로를 구성한 뒤 이러한 라벨을 사용하세요.<sup>[[1]](#references)[[2]](#references)</sup>

## 대상 맵 구성

payload를 작성하기 전에 모든 에이전트 워크플로에서 다음 다섯 가지 차원을 기록하세요.<sup>[[2]](#references)</sup>

| 차원 | 열거할 항목 | 보안 질문 |
|---|---|---|
| **신뢰할 수 없는 입력** | Chat/API 매개변수, URL, 문서, 이메일, 티켓, 캘린더 항목, 검색된 청크, 메모리, tool 결과, 피어 에이전트 메시지 | 나중에 모델 context에 들어가는 콘텐츠를 공격자가 어디에 배치할 수 있는가? |
| **Tools** | Tool 이름과 스키마, 부작용, 자동 실행, 확인 동작, 동적으로 로드되는 tools | 어떤 호출이 비밀을 읽거나, 상태를 쓰거나, 메시지를 보내거나, 데이터를 삭제하거나, 코드를 실행하거나, 가치를 이전하는가? |
| **권한** | 사용자 위임, service account, API token, credential 수명, tenant/resource 범위, 네트워크 접근 범위 | 각 호출은 어떤 identity로 실행되며, tool 경계에서 권한 부여를 다시 확인하는가? |
| **처리** | Query builder, shell, URL fetcher, template engine, interpreter, parser, 파일 작업, deserializer | 모델이 생성한 데이터가 다른 interpreter의 구문이 되는 지점은 어디인가? |
| **출력** | 응답, 렌더링된 Markdown/HTML, 링크, 이미지 fetch, webhook, 이메일, 파일, 로그, 보고서, 지표, 피어 에이전트 트래픽 | 비밀을 전달하거나 2차 요청을 유발할 수 있는 관찰 가능한 채널은 무엇인가? |

이를 광고된 통합 목록으로 뭉뚱그리지 마세요. 유용한 산출물은 각 소스를 그 소스가 도달하는 정확한 context 위치, 해당 지점에서 사용 가능한 tools, 각 tool이 사용하는 credential, 후속 interpreter, 모든 egress 경로에 연결해 보여줍니다. 사용자별 read token을 사용하는 경우 영향이 낮은 tool도 공유 관리자 credential을 사용하면 치명적일 수 있습니다.<sup>[[2]](#references)</sup>

## 정찰

### 모든 전달 및 수집 경로 파악

전달 표면(web, mobile, API, email, chat platform, browser extension)에서 시작해 client-to-backend 트래픽을 프록시하세요. UI에서 숨겨진 필드, 검색/autocomplete/filter 매개변수, 대화 상태 객체, 업로드 및 인덱싱 작업, tool 응답, sub-agent 트래픽을 살펴보세요. 실제 요청 스키마를 확인하기 전에 certificate pinning을 우회하려면 모바일 전용 client에 emulator와 instrumentation이 필요할 수 있습니다.<sup>[[2]](#references)</sup>

그런 다음 모델 아래의 stack을 파악하세요. orchestration framework, prompt assembly, retrieval 및 memory store, runtime(예: Python, container, WASM), 마운트된 volume, host service, 내부 API, cloud metadata 접근 가능성, 인접 네트워크가 여기에 해당합니다. 일부 “tool call”은 코드를 생성하거나 평가해 구현되므로 framework 기본 설정이 중요합니다. runtime/sandbox 경계에 따라 그 결과가 격리된 상태로 유지될지가 결정됩니다.<sup>[[2]](#references)</sup>

### 비파괴 probe로 라우팅 식별

범위 내 요청과 관련 없는 여러 요청을 비교하면서 전체 응답, 상태 코드, 지연 시간, streaming 동작을 보존하세요. 작업별 추론이 시작되기 전에 일관되게 거부된다면 별도의 gateway/classifier가 있을 수 있고, 맥락에 따른 거부라면 요청이 모델에 도달했을 수 있으며, 비어 있거나 순수하게 내용을 추출한 답변이라면 키워드 검색 또는 제한적인 retrieval일 수 있습니다. 이를 가설로 취급하고 동일한 probe를 다른 API 필드와 수집 경로로 재전송해 확인하세요.<sup>[[2]](#references)</sup>

정찰은 평가자가 에이전트 동작을 바꾸는 가장 이른 공격자 제어 소스와 그 소스에서 접근 가능한 tools, identity, interpreter, output을 명시할 수 있을 때 완료됩니다.<sup>[[2]](#references)</sup>

## Exploitation: 신뢰 경계 넘기

prompt 문구만이 아니라 채널을 테스트하세요. 눈에 보이는 진입점에서 차단되는 항목을 확인하기 위해 직접 injection부터 시작한 뒤, 아래의 덜 눈에 띄는 경로를 통해 같은 의도를 다시 테스트하세요.<sup>[[2]](#references)</sup>

- **간접 콘텐츠:** 페이지, 파일, 이메일, 티켓, metadata, alt text, HTML 주석, 화면 밖 텍스트, zero-width 문자. payload 전달 기법은 [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection)를 참고하세요.
- **Retrieval 및 memory:** 나중에 검색될 콘텐츠나 이후 세션에 다시 로드될 상태를 오염시키세요. 원본 소스를 삭제했을 때 동작이 사라지는지 기록하세요.
- **Tool output 및 피어 에이전트:** tool 응답이나 에이전트 간 메시지에 marker를 넣어 내부 트래픽이 사용자 입력과 최종 출력에만 적용되는 필터를 우회하는지 테스트하세요.
- **Supply chain:** tool descriptor, plugin, 연결된 server, skill, model, dependency를 신뢰할 수 있는 instruction source로 검토하세요. MCP 전용 테스트는 [MCP Servers](AI-MCP-Servers.md#mcp-vulns)를 참고하세요.
- **Human approval:** 실제 structured tool call과 모델이 생성한 승인 텍스트를 비교하세요. 공격자의 영향으로 대상, 범위, 영향을 받는 객체 또는 되돌릴 수 없는 부작용이 빠질 수 있는지 테스트하세요.

먼저 무해하고 고유한 marker를 사용하세요. 가능한 경우 소스 artifact, 조합된 context, 선택된 tool call, 승인 데이터, backend 요청/응답, 최종 상태를 보존하세요. 이를 통해 실제 영향과 작업이 실행되었다는 환각성 주장을 구분할 수 있습니다.<sup>[[2]](#references)</sup>

### Tool-risk judge에 영향을 주는 정책 형태의 텍스트

모델 기반 tool gate는 유용한 분류 context 안에 공격자가 제어하는 텍스트를 받을 수 있습니다. 예를 들어 LangChain의 실험적 `AutoModeMiddleware`는 제안된 tool call, 인수, 선택적 tool 설명, 최근 메시지 최대 30개를 TypeSafe `is_risky` judge에 전달합니다. 반환된 Noul 확률이 `0.5` 이상이면 설정된 tools를 차단합니다. 목록에 없는 tools는 이 middleware에서 분류되지 않습니다.<sup>[[5]](#references)</sup> TypeSafe는 state가 데이터로 쓰이도록 의도되었더라도 state의 적대적 텍스트가 분류에 영향을 줄 수 있다고 경고합니다.<sup>[[6]](#references)</sup>

**위조 정책(counterfeit policy)**은 단순히 system message라고 주장하는 것과 다릅니다. 낮은 신뢰도의 state 안에 대체 라벨이나 위험 정의를 넣고, judge가 개발자가 정의한 기준 대신 그 정의를 사용하도록 유도합니다. Datadog 테스트에서는 사용자가 수정할 수 있는 `profile_description`이 `can_edit:false`와 함께 tool 인수에 복사되었습니다. 정책처럼 보이는 해당 텍스트는 별도의 권한 검사가 변경 전에 거부할 것이므로 쓰기 시도가 위험도가 낮다고 주장했습니다. 40회 실행에서 평균 `is_risky` 점수는 `0.893`에서 `0.290`으로 낮아졌고, 직접적인 role-spoofing 비교의 평균은 `0.905`였습니다. 평균이 `0.5` 아래로 떨어졌다고 해서 모든 개별 호출이 gate를 통과했다는 뜻은 아니며, 이 실험은 권한 없는 쓰기가 완료되었음을 입증하지 **않았습니다**.<sup>[[7]](#references)</sup>

이 경계를 테스트할 때는 classifier 판정과 tool의 실제 권한 부여 결과를 구분하세요. 수정 가능한 필드 중 어떤 것이 judge에 전달되는지 확인하고, 정책처럼 보이는 텍스트가 있을 때와 없을 때 동일한 제안 작업을 비교한 뒤 최종 상태를 독립적으로 검증하세요. 별도의 권한 검사는 connector의 service-account 권한이 아니라 인증된 요청자의 권한을 사용해야 합니다.<sup>[[7]](#references)</sup> 다른 classifier 오류 유형은 [prompt-filter bypasses](AI-Prompts.md#prompt-waf-bypass)를 참고하세요. [LLM gateway trust boundaries](AI-LLM-Gateway-Security.md)는 다른 라우팅 및 credential 경계를 다룹니다.

### Subagent context 격리

fork되지 않은 Claude Agent SDK subagent는 자체 `AgentDefinition.prompt`, 위임 prompt, 사용 가능한 tools를 받지만, parent system prompt나 대화는 받지 않습니다. 정의에서 `tools`를 생략하면 subagent가 사용할 수 있는 tools를 상속합니다. 프로젝트의 `CLAUDE.md`는 여전히 로드될 수 있습니다. 따라서 child가 동일한 파일 시스템이나 실행 tools를 사용할 수 있는 경우 parent에만 적용된 prompt 제한은 신뢰할 수 있는 경계가 아닙니다.<sup>[[4]](#references)</sup>

parent가 거부하는 직접 요청과, 동일한 작업을 이름이 지정된 subagent에 위임한 경우를 비교해 경계를 테스트하세요. NCC Group은 운영체제 파일 열거 요청을 거부한 뒤, child에게 무해한 "layout map"을 만드는 일로 바꾸어 요청하자 성공했다고 보고했습니다.<sup>[[3]](#references)</sup>

parent의 최종 답변만이 아니라 child가 실제로 호출한 tools와 유효 tool allowlist를 살펴보세요. child가 parent라면 접근하지 못했을 파일에 접근했는지 확인하세요.<sup>[[4]](#references)</sup> 이는 guardrail 상속 실패이지 [Python sandbox](../generic-methodologies-and-resources/python/bypass-python-sandboxes/) 또는 container escape의 증거는 아닙니다.<sup>[[3]](#references)[[4]](#references)</sup>

### Mobile GUI agent: 화면 지시 및 action rebinding

phone GUI agent는 다음 cross-app 작업을 선택하기 전에 각 screenshot을 cloud model로 보낼 수 있습니다. **간접 visual injection**을 테스트하려면 agent가 승인된 작업 중 확인할 SMS, 이메일 또는 페이지에 공격자가 제어하는 텍스트를 배치하세요. 직접적인 작업 prompt와 screenshot에만 보이는 동일 지시를 비교한 다음, 다음 작업 및 고위험 작업 결정 여부를 살펴보세요. 평가한 assistant는 직접적인 작업 텍스트를 `checkPrompt`로 client 측에서 필터링했지만 screenshot 콘텐츠에는 이에 상응하는 필터링을 적용하지 않았습니다. 이는 [agentic-browser screenshot injection](../generic-methodologies-and-resources/phishing-methodology/ai-agent-mode-phishing-abusing-hosted-agent-browsers.md)의 모바일 cross-app 변형이지, Android component authentication을 우회하는 방법은 아닙니다.<sup>[[9]](#references)</sup>

부작용을 확인하는 예시 테스트에서는 공격자가 제어하는 양식에 민감한 필드를 입력하도록 agent에 요청한 뒤, 사용자에게 “upload”를 클릭하도록 요청합니다. 페이지는 필드가 변경되는 즉시 입력된 데이터를 제출합니다. 페이지 코드가 이미 전송한 데이터를 사용자에게 넘기는 절차로 보호할 수는 없습니다. agent의 설명을 증거로 간주하지 말고 실제 제출 여부를 확인하세요. 해당 소스는 이를 가능한 패턴으로 제시할 뿐, 모든 assistant가 침해되었음을 입증하지는 않습니다.<sup>[[9]](#references)</sup>

**GUI TOCTOU / action rebinding**은 별개의 오류 유형입니다. agent는 `t0`에 관찰한 화면을 바탕으로 입력을 계획하지만, 입력이 주입되기 전인 `t1`에 foreground UI가 바뀝니다.<sup>[[8]](#references)</sup> 이후 `t2`에 찍은 screenshot으로 이미 실행된 작업을 되돌릴 수는 없습니다.<sup>[[9]](#references)</sup> 승인된 Android 테스트에서 재사용할 수 있는 워크플로는 다음과 같습니다.<sup>[[8]](#references)</sup>

1. 대상 컨트롤의 화면 좌표를 파악하고, 통제된 앱에서 같은 위치에 무해한 컨트롤을 표시합니다.
2. agent가 관찰할 때까지 해당 carrier를 표시한 상태로 유지한 다음, 관찰과 작업 사이의 공백에 정상적인 foreground 전환을 발생시킵니다.
3. 계획된 탭이 새 앱의 컨트롤에 적용되는지 확인하고 agent의 설명에 의존하지 말고 대상 앱에서 결과 상태를 검증합니다.

원래 action-rebinding 연구는 위험한 권한이 없는 앱으로 이를 입증하며, 여러 단계의 흐름에서 agent의 task-recovery loop를 통해 전환을 반복하는 방법도 설명합니다.<sup>[[8]](#references)</sup>

모든 assistant에서 이 primitive가 그대로 작동한다고 **가정하지 마세요**. Doubao 평가에서는 최상위 Activity가 바뀌면 `OpClickUI`가 클릭을 건너뛰었으며, 직전 세 단계 안에 `OpOpenApp`이 있으면 screenshot을 비교했습니다. 따라서 single tap, long press, double tap은 공격자가 제어할 수 있는 타이밍 수단으로 거의 신뢰할 수 없었습니다. `OpTypeText`, `OpSwipeUI`, `OpScrollWheelAction`에는 이에 상응하는 보호가 없었지만, 보고서는 이들의 실질적 영향을 더 제한적인 것으로 평가했습니다.<sup>[[9]](#references)</sup>

## Execution: 실제 영향 입증

영향력에서 실제 영향으로 이어지는 경로는 두 가지로 구분됩니다.<sup>[[2]](#references)</sup>

1. **기능 악용:** 권한이 부여된 tool이 이미 목표 작업을 수행합니다. 예를 들면 한 tenant의 레코드를 읽어 공격자가 볼 수 있는 보고서에 쓰기, 이메일 보내기, 레코드 변경, 파일 삭제, 결제 시작 등이 있습니다. 별도의 소프트웨어 취약점은 필요하지 않습니다.
2. **후속 sink 악용:** 공격자가 방향을 유도한 모델 출력이 다른 구성 요소의 구문이 됩니다. [SQL injection](../pentesting-web/sql-injection/README.md) 또는 [NoSQL injection](../pentesting-web/nosql-injection.md)에 취약한 database query, [command injection](../pentesting-web/command-injection.md)에 취약한 shell wrapper, [SSRF](../pentesting-web/ssrf-server-side-request-forgery/README.md)에 사용되는 지정 URL, traversal이 가능한 파일 작업, RCE가 가능한 template/code evaluator, [unsafe deserialization](../pentesting-web/deserialization/README.md)에 취약한 객체 parser를 검토하세요.

각 후보에 대해 다음 체인을 입증하세요.<sup>[[2]](#references)</sup>

```text
attacker-controlled source
  -> model/context influence
  -> selected tool and arguments
  -> effective identity/credential
  -> capability or vulnerable sink
  -> externally verified state change or data egress
```

읽기 전용 통합도 이후 구성 요소가 읽은 내용을 게시할 수 있다면 여전히 악용될 수 있습니다. 일반 응답뿐 아니라 공격자가 제어하는 링크, 자동 이미지 가져오기, webhook, 로그, 보고서, 카운터, 알림, 다른 agent에 보내는 메시지처럼 간과하기 쉬운 egress도 테스트하세요.<sup>[[2]](#references)</sup>

## 목표에 대한 조치

한 가지 조치를 확인한 후에는 처음 보이는 효과에서 멈추지 말고 전체 영향 범위를 평가하세요:<sup>[[2]](#references)</sup>

- **Exfiltration:** 비밀 정보, 사용자 기록, 내부 파일, 대화 데이터 또는 prompt/context 콘텐츠가 관찰 가능한 채널을 통해 외부로 유출됩니다.
- **무단 조치:** agent가 공격자의 목적을 위해 정당한 write 기능을 사용합니다.
- **서비스 거부:** 파괴적인 도구나 반복적인 고비용 작업이 무결성 또는 가용성에 영향을 줍니다.
- **지속성:** 오염된 메모리, 인덱싱된 콘텐츠, 신뢰된 상태 또는 런타임 변경이 원래 세션이나 소스가 제거된 뒤에도 유지됩니다.
- **전파:** 신뢰된 peer가 침해된 agent의 메시지나 공유 상태를 받아들여 자신의 도구와 자격 증명으로 해당 조치를 반복합니다.

심각도는 모델의 문구가 얼마나 놀라운지가 아니라 접근 가능한 데이터, 실효 권한, sink의 악용 가능성, egress, 지속성 및 전파 가능성을 기준으로 판단해야 합니다.<sup>[[2]](#references)</sup>

## 평가 중 검증할 통제

Prompt 필터와 더 나은 system prompt는 공격 비용을 높일 수 있지만, 권한 경계로 취급해서는 안 됩니다. 아래 통제를 검증할 때는 직접 입력, 간접 콘텐츠, 메모리, 도구 및 peer agent를 통해 동일한 chain을 다시 실행하세요:<sup>[[2]](#references)</sup>

- 결정론적 정책 계층이 **모든 도구 호출**에서 인증된 사용자, tenant, 객체, 작업 및 대상을 확인합니다. 모델은 호출자 ID를 지정하거나 덮어쓸 수 없습니다.
- 읽기 및 쓰기 권한은 별도의 최소 권한 단기 자격 증명을 사용합니다. 영향이 큰 도구는 필요한 시점에만 제공되며, 수집된 콘텐츠로부터 자동 실행되지 않습니다.
- 네트워크 egress와 내부 대상은 모델이 선택한 URL과 별개로 allowlist를 적용합니다. 필요한 경우가 아니면 런타임의 metadata endpoint, 마운트된 비밀 정보 및 인접 서비스에 대한 접근을 차단합니다.
- 승인 UI는 정형화된 원본 요청을 바탕으로 생성되며, 자유 형식의 모델 요약이 아니라 정확한 인수, ID, 대상, 영향을 받는 객체 및 부수 효과를 표시합니다.
- 성공 여부는 대상 시스템 또는 기록 시스템에서 확인합니다. agent의 설명, 도구 호출 요청 또는 HTTP redirect는 주장된 상태 변경의 증거가 아닙니다.
- 메모리 및 검색 항목은 출처와 신뢰 레이블을 유지하고 무효화할 수 있어야 하며, 이후 작업에 사용될 때 다시 권한을 확인해야 합니다.
- agent 간 메시지는 인증되고 권한이 확인된 비신뢰 요청으로 취급합니다. peer의 평판이나 agent card가 수신자의 도구 사용 권한을 암묵적으로 위임하지 않습니다.

A2A agent card, task flow 및 공격 표면은 [A2A Protocol Security](AI-A2A-Protocol.md)를 확인하세요.

## References

- [1] [2026년 Agentic Applications를 위한 OWASP Top 10](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [2] [AI Agent 공격을 위한 Hacker 가이드](https://darkmarc.substack.com/p/the-hackers-guide-to-attacking-ai)
- [3] [AI Agent를 Sandbox에서 탈출시키는 일은 실제로 얼마나 어려울까?](https://www.nccgroup.com/research/how-hard-is-it-really-to-break-an-ai-agent-out-of-its-sandbox/)
- [4] [SDK의 Subagent](https://code.claude.com/docs/en/agent-sdk/subagents)
- [5] [LangChain TypeSafe Auto Mode middleware 소스](https://github.com/langchain-ai/langchain/blob/master/libs/partners/typesafe/langchain_typesafe/experimental/middleware/auto_mode.py)
- [6] [TypeSafe AI Jev 모델의 jaggedness: 적대적 콘텐츠](https://docs.typesafe.ai/model-jaggedness/jev-1.13#adversarial-content)
- [7] [판사로서의 Jev: 위조된 정책이 Jev를 조종하는 방식](https://securitylabs.datadoghq.com/articles/jev-as-a-judge-how-counterfeit-policy-steers-jev/)
- [8] [권한 없는 조작: 대규모 멀티모달 모델 기반 GUI Agent를 신뢰할 수 있을까?](https://arxiv.org/html/2601.12349v1)
- [9] [AI Assistant가 Hacker의 공격 chain에 포함될 때 | Doubao Phone 보안 분석](https://www.darknavy.org/blog/security_analysis_of_doubao_phone/)
{{#include ../banners/hacktricks-training.md}}
