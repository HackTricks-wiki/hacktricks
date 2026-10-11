# AI Agent 보안 방법론

{{#include ../banners/hacktricks-training.md}}

Agent 평가는 **공격자가 제어하는 입력부터 외부에서 관찰 가능한 영향까지**를 따라가야 합니다. Jailbreak, 캐릭터 변경, system prompt 공개는 추론 채널이 영향을 받을 수 있음을 보여주지만, 영향이 큰 finding은 데이터 접근, 무단 tool 작업, 후속 injection sink, persistence 또는 다른 agent로 이어지는 chain입니다.<sup>[[2]](#references)</sup>

[OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)은 커버리지를 분류할 때 유용합니다(goal hijacking, tool misuse, privilege abuse, supply chain, code execution, memory poisoning, inter-agent trust, cascading failures, human trust, rogue agents). 예상치 못한 모델 출력 자체를 테스트의 끝으로 간주하지 말고, end-to-end 공격 경로를 구성한 뒤 이 분류를 사용하세요.<sup>[[1]](#references)[[2]](#references)</sup>

## 대상 맵 작성

payload를 작성하기 전에 각 agent workflow에 대해 다음 다섯 가지 차원을 기록하세요.<sup>[[2]](#references)</sup>

| 차원 | 열거할 항목 | 보안 관련 질문 |
|---|---|---|
| **신뢰할 수 없는 입력** | Chat/API 매개변수, URL, 문서, 이메일, 티켓, 캘린더 항목, 검색된 청크, 메모리, tool 결과, peer-agent 메시지 | 공격자가 나중에 모델 컨텍스트에 들어갈 콘텐츠를 어디에 배치할 수 있나요? |
| **Tools** | Tool 이름과 스키마, 부작용, 자동 실행, 확인 동작, 동적으로 로드되는 tool | 어떤 호출이 비밀을 읽거나, 상태를 쓰거나, 메시지를 보내거나, 데이터를 삭제하거나, 코드를 실행하거나, 가치를 이전하나요? |
| **권한** | 사용자 위임, service account, API token, credential 수명, tenant/resource 범위, 네트워크 도달성 | 각 호출은 어떤 identity로 실행되며, tool 경계에서 권한 부여를 다시 확인하나요? |
| **처리** | Query builder, shell, URL fetcher, template engine, interpreter, parser, 파일 작업, deserializer | 모델 생성 데이터가 다른 interpreter의 구문이 되는 지점은 어디인가요? |
| **출력** | 응답, 렌더링된 Markdown/HTML, 링크, 이미지 fetch, webhook, 이메일, 파일, 로그, 보고서, metric, peer-agent 트래픽 | 비밀을 전달하거나 2차 요청을 유발할 수 있는 관찰 가능한 채널은 무엇인가요? |

이를 광고된 통합 기능 목록으로 축약하지 마세요. 유용한 산출물은 각 source가 도달하는 정확한 context 위치, 해당 지점에서 사용 가능한 tool, 각 tool이 사용하는 credential, 후속 interpreter, 모든 egress 경로를 매핑합니다. 동일한 tool도 사용자별 read token을 사용하면 영향이 낮을 수 있지만, 공유 관리자 credential을 사용하면 치명적일 수 있습니다.<sup>[[2]](#references)</sup>

## 정찰

### 모든 전달 및 입력 경로 매핑

전달 표면(web, mobile, API, 이메일, chat platform, browser extension)에서 시작해 client-to-backend 트래픽을 프록시로 확인하세요. UI에 숨겨진 필드, 검색/autocomplete/filter 매개변수, 대화 상태 객체, 업로드 및 인덱싱 작업, tool 응답, sub-agent 트래픽을 살펴보세요. 실제 요청 스키마를 확인하기 전에 certificate pinning을 우회해야 하는 mobile 전용 client는 emulator와 instrumentation이 필요할 수 있습니다.<sup>[[2]](#references)</sup>

그런 다음 모델 아래의 stack을 매핑하세요. orchestration framework, prompt 구성, retrieval 및 memory store, runtime(예: Python, container 또는 WASM), mounted volume, host service, 내부 API, cloud metadata 도달성, 인접 네트워크를 확인합니다. framework 기본값도 중요합니다. 일부 “tool call”은 코드를 생성하거나 평가하는 방식으로 구현되며, 결과가 격리된 상태로 유지되는지는 runtime/sandbox 경계에 달려 있습니다.<sup>[[2]](#references)</sup>

### 비파괴 probe로 라우팅 식별

범위 내 요청과 관련 없는 여러 요청을 비교하되, 전체 응답, status code, latency, streaming 동작을 보존하세요. 작업별 추론이 시작되기 전 안정적으로 거부된다면 별도의 gateway/classifier일 수 있고, 맥락에 따른 거부는 요청이 모델에 도달했음을 시사하며, 비어 있거나 순전히 발췌된 답변은 keyword search 또는 제한된 retrieval을 나타낼 수 있습니다. 이는 가설로 취급하고, 같은 probe를 다른 API 필드와 입력 경로로 재전송해 확인하세요.<sup>[[2]](#references)</sup>

정찰은 평가자가 agent 동작을 바꾸는 가장 이른 공격자 제어 source와 해당 source에서 도달 가능한 tool, identity, interpreter, output을 파악했을 때 완료됩니다.<sup>[[2]](#references)</sup>

## Exploitation: 신뢰 경계 넘기

prompt 문구만이 아니라 채널을 테스트하세요. 직접 injection으로 눈에 보이는 진입점이 차단하는 항목을 확인한 다음, 아래의 덜 드러나는 경로를 통해 동일한 의도를 전달해 다시 테스트하세요.<sup>[[2]](#references)</sup>

- **간접 콘텐츠:** 페이지, 파일, 이메일, 티켓, metadata, alt text, HTML comment, 화면 밖 텍스트 또는 zero-width character. payload 전달 기법은 [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection)를 참조하세요.
- **Retrieval 및 memory:** 나중에 검색될 콘텐츠 또는 이후 세션에서 다시 로드될 상태를 오염시키세요. 원본 source를 삭제했을 때 동작이 사라지는지 기록하세요.
- **Tool output 및 peer agent:** tool 응답이나 agent 간 메시지에 marker를 넣어, 사용자 입력과 최종 출력에만 적용되는 filter를 내부 트래픽이 우회하는지 테스트하세요.
- **Supply chain:** tool descriptor, plugin, 연결된 server, skill, model, dependency를 신뢰할 수 있는 instruction source로 검토하세요. MCP 전용 테스트는 [MCP Servers](AI-MCP-Servers.md#mcp-vulns)를 참조하세요.
- **Human approval:** 실제 구조화된 tool call을 모델 생성 승인 문구와 비교하세요. 공격자의 영향으로 대상, 범위, 영향을 받는 객체 또는 되돌릴 수 없는 부작용이 생략될 수 있는지 테스트하세요.

먼저 무해하고 고유한 marker를 사용하세요. source artifact, 관찰 가능한 경우 조합된 context, 선택된 tool call, 승인 데이터, backend 요청/응답, 최종 상태를 보존하세요. 이렇게 하면 영향이 실제로 발생한 경우와 발생했다고 주장하는 환각을 구분할 수 있습니다.<sup>[[2]](#references)</sup>

## 실행: 실제 영향 입증

영향을 미치는 경로는 두 가지로 구분됩니다.<sup>[[2]](#references)</sup>

1. **Capability abuse:** 이미 권한이 있는 tool이 목표 작업을 수행합니다. 예를 들어 한 tenant의 레코드를 읽어 공격자가 볼 수 있는 보고서에 기록하거나, 이메일을 보내거나, 레코드를 변경하거나, 파일을 삭제하거나, 결제를 시작하는 경우입니다. 별도의 소프트웨어 취약점은 필요하지 않습니다.
2. **후속 sink 악용:** 공격자가 유도한 모델 출력이 다른 구성 요소의 구문이 됩니다. [SQL injection](../pentesting-web/sql-injection/README.md) 또는 [NoSQL injection](../pentesting-web/nosql-injection.md)을 위한 database query, [command injection](../pentesting-web/command-injection.md)을 위한 shell wrapper, [SSRF](../pentesting-web/ssrf-server-side-request-forgery/README.md)를 위한 선택 가능한 URL, 경로 탐색을 위한 파일 작업, RCE를 위한 template/code evaluator, [unsafe deserialization](../pentesting-web/deserialization/README.md)을 위한 객체 parser를 검토하세요.

모든 후보에 대해 다음 chain을 입증하세요.<sup>[[2]](#references)</sup>

```text
attacker-controlled source
  -> model/context influence
  -> selected tool and arguments
  -> effective identity/credential
  -> capability or vulnerable sink
  -> externally verified state change or data egress
```

읽기 전용 통합도 읽은 내용을 나중의 구성 요소가 게시할 수 있다면 여전히 악용될 수 있습니다. 일반 응답뿐 아니라 공격자가 제어하는 링크, 자동 이미지 가져오기, webhooks, logs, reports, counters, notifications, 다른 agents에게 보내는 messages 등 눈에 잘 띄지 않는 egress도 테스트하세요.<sup>[[2]](#references)</sup>

## 목표에 대한 작업

한 가지 작업을 확인한 후, 처음 눈에 보이는 효과에서 멈추지 말고 전체 blast radius를 평가하세요.<sup>[[2]](#references)</sup>

- **유출:** secrets, 사용자 records, 내부 files, 대화 data 또는 prompt/context 내용이 관찰 가능한 채널을 통해 외부로 나갑니다.
- **무단 작업:** agent가 공격자의 목표를 위해 합법적인 write capabilities를 사용합니다.
- **서비스 거부:** 파괴적인 tools 또는 반복적인 고비용 작업이 무결성이나 가용성에 영향을 줍니다.
- **지속성:** 오염된 memory, 색인된 content, 신뢰 상태 또는 runtime 변경 사항이 최초 세션이나 출처를 제거한 뒤에도 남습니다.
- **전파:** 신뢰할 수 있는 peer가 침해된 agent의 message 또는 공유 상태를 사용하고, 자신의 tools와 credentials로 해당 작업을 반복합니다.

심각도는 모델의 응답이 얼마나 놀라운지가 아니라, 접근 가능한 data, 실효 권한, sink의 악용 가능성, egress, 지속성 및 전파를 기준으로 판단해야 합니다.<sup>[[2]](#references)</sup>

## 평가 중 검증할 controls

Prompt filters와 더 나은 system prompt는 공격자의 비용을 높일 수 있지만, 권한 경계로 간주해서는 안 됩니다. direct input, 간접 content, memory, tools 및 peer agents를 통해 동일한 chain을 다시 실행하여 아래 controls를 검증하세요.<sup>[[2]](#references)</sup>

- 결정론적 policy layer가 **모든 tool 호출**에서 인증된 사용자, tenant, object, action 및 destination을 확인합니다. 모델은 호출자 identity를 지정하거나 재정의할 수 없습니다.
- Read와 write capabilities는 서로 분리된 최소 권한의 단기 credentials를 사용합니다. 영향이 큰 tools는 just-in-time 방식으로만 제공하며, 수집된 content를 기반으로 자동 실행하지 않습니다.
- Network egress와 내부 destinations는 모델이 선택한 URLs와 별개로 allowlist를 적용합니다. 필요한 경우가 아니면 runtime이 metadata endpoints, 마운트된 secrets 및 인접 services에 접근하지 못하도록 차단합니다.
- Approval UI는 표준 구조화 요청을 기반으로 생성되며, 자유 형식의 모델 요약이 아니라 정확한 arguments, identity, destination, 영향을 받는 objects 및 부작용을 표시합니다.
- 성공 여부는 destination system 또는 system of record에서 확인합니다. Agent의 설명, tool-call 요청 또는 HTTP redirect는 주장된 상태 변경의 증거가 아닙니다.
- Memory 및 retrieval 항목은 출처와 신뢰 label을 유지하고 무효화할 수 있어야 하며, 이후 작업에 사용될 때 다시 권한을 확인해야 합니다.
- Agent 간 messages는 인증 및 권한 확인이 필요한 신뢰할 수 없는 요청으로 취급합니다. peer의 평판이나 agent card가 수신자의 tools에 대한 권한을 암묵적으로 위임하지는 않습니다.

## References

- [1] [2026년 Agentic Applications를 위한 OWASP Top 10](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [2] [AI Agents 공격을 위한 Hacker's Guide](https://darkmarc.substack.com/p/the-hackers-guide-to-attacking-ai)
{{#include ../banners/hacktricks-training.md}}
