# AI Agent Security Methodology

{{#include ../banners/hacktricks-training.md}}

Agent assessment는 **공격자가 제어하는 입력에서 외부로 관찰 가능한 영향까지** 추적해야 합니다. Jailbreak, 문자 변경, system prompt 공개는 추론 채널에 영향을 줄 수 있음을 보여주지만, 중요한 finding은 데이터 접근, 무단 tool 동작, 후속 injection sink, persistence 또는 다른 agent로 이어지는 chain입니다.<sup>[[2]](#references)</sup>

[OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)은 coverage를 분류할 때 유용합니다(goal hijacking, tool misuse, privilege abuse, supply chain, code execution, memory poisoning, inter-agent trust, cascading failures, human trust, rogue agents). model이 예상치 못한 텍스트를 출력하는 것을 테스트의 끝으로 취급하지 말고, end-to-end attack path를 구성한 뒤 이 분류를 사용하세요.<sup>[[1]](#references)[[2]](#references)</sup>

## 대상 맵 작성

payload를 작성하기 전에 모든 agent workflow에 대해 다음 다섯 가지 차원을 기록하세요.<sup>[[2]](#references)</sup>

| 차원 | 열거할 항목 | 보안 질문 |
|---|---|---|
| **신뢰할 수 없는 입력** | Chat/API 매개변수, URL, 문서, 이메일, 티켓, 캘린더 항목, 검색된 청크, 메모리, tool 결과, peer-agent 메시지 | 공격자가 나중에 model context에 들어갈 콘텐츠를 어디에 둘 수 있는가? |
| **Tools** | Tool 이름과 스키마, side effect, 자동 실행, 확인 동작, 동적으로 로드되는 tools | 어떤 호출이 비밀을 읽고, 상태를 쓰고, 메시지를 보내고, 데이터를 삭제하고, 코드를 실행하거나, 가치를 이전하는가? |
| **권한** | 사용자 위임, service account, API token, credential 수명, tenant/resource 범위, 네트워크 접근 범위 | 각 호출은 어떤 identity로 실행되며, tool 경계에서 권한 확인을 반복하는가? |
| **처리** | Query builder, shell, URL fetcher, template engine, interpreter, parser, 파일 작업, deserializer | model이 생성한 데이터가 다른 interpreter의 구문이 되는 지점은 어디인가? |
| **출력** | 응답, 렌더링된 Markdown/HTML, 링크, 이미지 fetch, webhook, 이메일, 파일, 로그, 보고서, 메트릭, peer-agent 트래픽 | 어떤 관찰 가능한 채널이 비밀을 전달하거나 2차 요청을 유발할 수 있는가? |

이를 제공된 integration 목록으로 축소하지 마세요. 유용한 산출물은 각 source가 도달하는 정확한 context 위치, 해당 지점에서 사용 가능한 tools, 각 tool이 사용하는 credential, 후속 interpreter, 모든 egress 경로를 매핑합니다. 동일한 tool도 사용자별 read token으로는 영향이 작을 수 있지만, 공유 administrator credential을 사용하면 치명적인 영향을 줄 수 있습니다.<sup>[[2]](#references)</sup>

## 정찰

### 모든 전달 및 수집 경로 매핑

전달 표면(web, mobile, API, email, chat platform, browser extension)에서 시작해 client-to-backend 트래픽을 proxy로 확인하세요. UI에 숨겨진 필드, 검색/autocomplete/filter 매개변수, conversation-state 객체, 업로드 및 indexing 작업, tool 응답, sub-agent 트래픽을 살펴보세요. 실제 request schema를 확인하려면 인증서 pinning을 우회할 emulator와 instrumentation이 필요한 mobile 전용 client도 있습니다.<sup>[[2]](#references)</sup>

그런 다음 model 아래의 stack을 매핑하세요. orchestration framework, prompt 조립, retrieval 및 memory 저장소, runtime(예: Python, container, WASM), mount된 volume, host service, internal API, cloud metadata 접근 가능성, 인접 네트워크를 포함합니다. 일부 framework는 코드를 생성하거나 평가하는 방식으로 “tool call”을 구현하므로 기본 설정이 중요합니다. runtime/sandbox 경계가 그 결과를 격리된 상태로 유지할 수 있는지를 결정합니다.<sup>[[2]](#references)</sup>

### 비파괴적 probe로 라우팅 식별

대상 범위 내 요청과 서로 관련 없는 여러 요청을 비교하면서 전체 응답, status code, latency, streaming 동작을 보존하세요. 작업별 추론이 시작되기 전에 일관되게 거부된다면 별도의 gateway/classifier일 수 있고, 문맥에 따른 거부는 요청이 model에 도달했음을 시사하며, 비어 있거나 추출만 하는 답변은 keyword search 또는 제한적인 retrieval을 나타낼 수 있습니다. 이를 가설로 취급하고 동일한 probe를 대체 API 필드와 수집 경로로 재전송해 확인하세요.<sup>[[2]](#references)</sup>

정찰은 assessment에서 agent 동작을 바꾸는 가장 이른 공격자 제어 source **그리고** 그 source에서 접근 가능한 tools, identity, interpreter, output을 특정할 수 있을 때 완료됩니다.<sup>[[2]](#references)</sup>

## Exploitation: 신뢰 경계 넘기

prompt 문구뿐 아니라 채널도 테스트하세요. 먼저 직접 injection으로 사용자에게 보이는 진입점에서 무엇이 차단되는지 확인한 다음, 아래에 있는 덜 눈에 띄는 경로를 통해 같은 의도를 다시 테스트하세요.<sup>[[2]](#references)</sup>

- **간접 콘텐츠:** 페이지, 파일, 이메일, 티켓, metadata, alt text, HTML 주석, 화면 밖 텍스트, zero-width character. payload 전달 기법은 [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection)를 참조하세요.
- **Retrieval 및 memory:** 나중에 검색될 콘텐츠나 후속 session에서 다시 로드될 상태를 오염시키세요. 원본 source를 삭제하면 동작도 사라지는지 기록하세요.
- **Tool output 및 peer agent:** tool 응답이나 agent 간 메시지에 marker를 넣어 내부 트래픽이 사용자 입력과 최종 output에만 적용되는 filter를 우회하는지 테스트하세요.
- **Supply chain:** tool descriptor, plugin, 연결된 server, skill, model, dependency를 신뢰할 수 있는 instruction source로 검토하세요. MCP 전용 테스트는 [MCP Servers](AI-MCP-Servers.md#mcp-vulns)를 참조하세요.
- **Human approval:** 실제 structured tool call과 model이 생성한 승인 문구를 비교하세요. 공격자 영향으로 목적지, 범위, 대상 객체 또는 되돌릴 수 없는 side effect가 누락될 수 있는지 테스트하세요.

먼저 무해하고 고유한 marker를 사용하세요. source artifact, 확인할 수 있다면 조립된 context, 선택된 tool call, 승인 데이터, backend request/response, 최종 상태를 보존하세요. 이를 통해 실제로 실행된 행동에 대한 환각성 주장과 영향력을 구분할 수 있습니다.<sup>[[2]](#references)</sup>

### Tool-risk judge의 정책처럼 보이는 텍스트

model 기반 tool gate는 유용한 분류 context 안에 공격자가 제어하는 텍스트를 받을 수 있습니다. 예를 들어 LangChain의 실험적 `AutoModeMiddleware`는 제안된 tool call, 인수, 선택적 tool 설명, 최근 메시지 최대 30개를 TypeSafe `is_risky` judge에 전달합니다. 반환된 Noul 확률이 `0.5` 이상이면 설정된 tools를 차단합니다. 목록에 없는 tools는 이 middleware에서 분류하지 않습니다.<sup>[[5]](#references)</sup> TypeSafe도 state를 데이터로 사용할 의도였더라도 state 안의 adversarial text가 분류에 영향을 줄 수 있다고 경고합니다.<sup>[[6]](#references)</sup>

**위조 정책(counterfeit policy)**은 단순히 system message라고 주장하는 것과 다릅니다. 낮은 신뢰도의 state 안에 대안적인 label이나 위험 정의를 넣고, judge가 개발자가 정의한 기준 대신 해당 정의를 사용하도록 유도합니다. Datadog의 테스트에서는 사용자가 편집 가능한 `profile_description`이 `can_edit:false`와 함께 tool 인수에 복사되었습니다. 정책처럼 보이는 해당 텍스트는 별도의 권한 확인이 변경 전에 쓰기 시도를 거부해야 하므로 write 시도가 위험도가 낮다고 주장했습니다. 40회 실행에서 평균 `is_risky` 점수는 `0.893`에서 `0.290`으로 하락했고, 직접적인 role-spoofing 비교의 평균은 `0.905`였습니다. 평균이 `0.5` 미만으로 내려갔다고 해서 모든 개별 호출이 gate를 통과했음을 증명하는 것은 아니며, 이 실험은 **무단 쓰기가 완료되었음을 입증하지 않았습니다.**<sup>[[7]](#references)</sup>

이 경계를 테스트할 때는 classifier 판정과 tool의 실제 권한 확인 결과를 구분하세요. 편집 가능한 필드 중 어떤 것이 judge에 전달되는지 확인하고, 정책처럼 보이는 텍스트의 유무에 따라 동일한 제안 동작을 비교한 뒤 최종 상태를 독립적으로 검증하세요. 별도의 권한 확인은 connector의 service-account 권한이 아니라 인증된 요청자의 권한을 사용해야 합니다.<sup>[[7]](#references)</sup> 다른 classifier failure mode는 [prompt-filter bypasses](AI-Prompts.md#prompt-waf-bypass)를 참조하세요. [LLM gateway trust boundaries](AI-LLM-Gateway-Security.md)는 다른 라우팅 및 credential 경계를 다룹니다.

### Subagent context 격리

fork가 아닌 Claude Agent SDK subagent는 자체 `AgentDefinition.prompt`, 위임 prompt, 사용 가능한 tools를 받지만, parent system prompt나 대화는 받지 않습니다. 정의에서 `tools`를 생략하면 subagent에 사용 가능한 tools를 상속합니다. 프로젝트의 `CLAUDE.md`는 여전히 로드될 수 있습니다. 따라서 child가 동일한 파일 시스템이나 실행 tools를 사용할 수 있다면 parent에만 적용된 prompt 제한은 신뢰할 수 있는 경계가 아닙니다.<sup>[[4]](#references)</sup>

parent가 거부하는 직접 요청과 동일한 작업을 이름이 지정된 subagent에 위임했을 때를 비교해 경계를 테스트하세요. NCC Group은 운영 체제 파일 열거 요청이 거부된 뒤, child에게 무해한 "layout map"으로 표현하자 성공했다고 보고했습니다.<sup>[[3]](#references)</sup>

parent의 최종 답변만 보지 말고 child의 실제 tool call과 유효한 tool allowlist를 확인하세요. child가 parent라면 접근하지 않았을 파일에 접근했는지 검증하세요.<sup>[[4]](#references)</sup> 이는 guardrail 상속 실패이지, [Python sandbox](../generic-methodologies-and-resources/python/bypass-python-sandboxes/) 또는 container escape의 증거는 아닙니다.<sup>[[3]](#references)[[4]](#references)</sup>

## 실행: 실제 영향 입증

영향력에서 실제 영향으로 이어지는 경로는 서로 다릅니다.<sup>[[2]](#references)</sup>

1. **Capability abuse:** 권한이 부여된 tool이 이미 목적에 부합하는 동작을 수행합니다. 예를 들어 한 tenant의 record를 읽어 공격자가 볼 수 있는 보고서에 쓰거나, 이메일을 보내거나, record를 변경하거나, 파일을 삭제하거나, 결제를 시작할 수 있습니다. 별도의 software bug는 필요하지 않습니다.
2. **후속 sink 악용:** 공격자가 유도한 model output이 다른 component의 구문이 됩니다. [SQL injection](../pentesting-web/sql-injection/README.md) 또는 [NoSQL injection](../pentesting-web/nosql-injection.md)이 가능한 database query, [command injection](../pentesting-web/command-injection.md)이 가능한 shell wrapper, [SSRF](../pentesting-web/ssrf-server-side-request-forgery/README.md)가 가능한 선택 URL, path traversal가 가능한 파일 작업, RCE가 가능한 template/code evaluator, [unsafe deserialization](../pentesting-web/deserialization/README.md)이 가능한 object parser를 검토하세요.

각 후보에 대해 다음 chain을 입증하세요.<sup>[[2]](#references)</sup>

```text
attacker-controlled source
  -> model/context influence
  -> selected tool and arguments
  -> effective identity/credential
  -> capability or vulnerable sink
  -> externally verified state change or data egress
```

읽기 전용 통합도 이후의 어떤 구성 요소든 읽은 내용을 외부로 내보낼 수 있다면 악용될 수 있습니다. 일반 응답뿐 아니라 공격자가 제어하는 링크, 자동 이미지 가져오기, 웹훅, 로그, 보고서, 카운터, 알림, 다른 에이전트에 보내는 메시지 등 눈에 잘 띄지 않는 데이터 유출 경로도 테스트하세요.<sup>[[2]](#references)</sup>

## 목표에 대한 조치

한 가지 조치를 확인한 후에는 처음으로 눈에 보이는 결과에서 멈추지 말고, 전체 영향을 평가하세요:<sup>[[2]](#references)</sup>

- **데이터 유출:** 비밀 정보, 사용자 기록, 내부 파일, 대화 데이터 또는 프롬프트/컨텍스트 내용이 관찰 가능한 채널을 통해 외부로 유출됩니다.
- **무단 조치:** 에이전트가 정당한 쓰기 권한을 공격자의 목적에 사용합니다.
- **서비스 거부:** 파괴적인 도구나 반복적인 고비용 작업이 무결성 또는 가용성에 영향을 줍니다.
- **지속성:** 오염된 메모리, 색인된 콘텐츠, 신뢰 상태 또는 런타임 변경 사항이 해당 세션이 끝나거나 원본이 제거된 후에도 남습니다.
- **전파:** 신뢰하는 피어가 침해된 에이전트의 메시지나 공유 상태를 받아 자체 도구와 자격 증명으로 해당 조치를 반복합니다.

심각도는 모델의 응답이 얼마나 놀라운지가 아니라 접근 가능한 데이터, 실효 권한, 싱크의 악용 가능성, 데이터 유출 경로, 지속성 및 전파 가능성을 기준으로 판단해야 합니다.<sup>[[2]](#references)</sup>

## 평가 중 검증할 통제

프롬프트 필터와 개선된 시스템 프롬프트는 공격 비용을 높일 수 있지만, 이를 권한 경계로 간주해서는 안 됩니다. 직접 입력, 간접 콘텐츠, 메모리, 도구 및 피어 에이전트를 통해 동일한 공격 체인을 다시 실행하여 아래 통제를 검증하세요:<sup>[[2]](#references)</sup>

- 결정론적 정책 계층이 **모든 도구 호출**에서 인증된 사용자, 테넌트, 객체, 조치 및 대상을 확인합니다. 모델이 호출자 ID를 제공하거나 재정의할 수 없어야 합니다.
- 읽기 및 쓰기 권한에 별도의 최소 권한 단기 자격 증명을 사용합니다. 영향력이 큰 도구는 필요한 시점에만 제공하며, 수집된 콘텐츠로 자동 실행되지 않아야 합니다.
- 네트워크 송신과 내부 대상은 모델이 선택한 URL과 별도로 허용 목록으로 제한합니다. 필요한 경우가 아니면 런타임의 메타데이터 엔드포인트, 마운트된 비밀 정보 및 인접 서비스에 대한 접근을 차단합니다.
- 승인 UI는 표준 구조화 요청으로 생성하고 정확한 인수, ID, 대상, 영향을 받는 객체 및 부작용을 표시해야 합니다. 모델이 자유 형식으로 요약한 내용을 표시해서는 안 됩니다.
- 대상 시스템 또는 기록 시스템에서 성공 여부를 확인합니다. 에이전트의 설명, 도구 호출 요청 또는 HTTP 리디렉션은 주장된 상태 변경의 증거가 아닙니다.
- 메모리 및 검색 항목은 출처와 신뢰 레이블을 유지하고 무효화할 수 있어야 하며, 이후 조치에 사용될 때 다시 권한을 확인해야 합니다.
- 에이전트 간 메시지는 인증 및 권한 확인이 필요한 신뢰할 수 없는 요청으로 취급합니다. 피어의 평판이나 에이전트 카드가 수신 에이전트의 도구 사용 권한을 암묵적으로 위임하지 않아야 합니다.

## References

- [1] [2026년 Agentic Applications를 위한 OWASP Top 10](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [2] [AI 에이전트 공격을 위한 해커 가이드](https://darkmarc.substack.com/p/the-hackers-guide-to-attacking-ai)
- [3] [AI 에이전트를 샌드박스에서 탈출시키는 일은 실제로 얼마나 어려운가?](https://www.nccgroup.com/research/how-hard-is-it-really-to-break-an-ai-agent-out-of-its-sandbox/)
- [4] [SDK의 서브에이전트](https://code.claude.com/docs/en/agent-sdk/subagents)
- [5] [LangChain TypeSafe Auto Mode 미들웨어 소스 코드](https://github.com/langchain-ai/langchain/blob/master/libs/partners/typesafe/langchain_typesafe/experimental/middleware/auto_mode.py)
- [6] [TypeSafe AI Jev 모델의 들쭉날쭉함: 적대적 콘텐츠](https://docs.typesafe.ai/model-jaggedness/jev-1.13#adversarial-content)
- [7] [판정자로서의 Jev: 위조된 정책이 Jev를 조종하는 방식](https://securitylabs.datadoghq.com/articles/jev-as-a-judge-how-counterfeit-policy-steers-jev/)
{{#include ../banners/hacktricks-training.md}}
