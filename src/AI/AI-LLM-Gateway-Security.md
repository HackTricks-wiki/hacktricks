# LLM Gateway Trust Boundaries

{{#include ../banners/hacktricks-training.md}}

LLM gateway는 모델 라우팅을 처리하고 제공업체 자격 증명을 보유하는 경우가 많으므로, 일반 API 호출자에게 구성 권한이나 제공업체 수준의 권한이 부여되어서는 안 됩니다. LiteLLM 1.77.7 버전의 gateway 평가에서는 서로 다른 두 가지 경계가 드러났습니다. 하나는 관리 구성에 대한 UI 세션 권한 부여이고, 다른 하나는 추론 요청에 포함된 호출자 제공 라우팅 구성입니다. 보고된 문제는 1.83.9 버전에서 수정되었습니다.<sup>[[1]](#references)</sup>

## UI 경로 분류는 권한 부여가 아니다

평가 대상 LiteLLM 버전에서 UI 로그인 키는 `litellm-dashboard` 팀에 속했습니다. 권한 부여 과정에서는 사용자의 역할과 관계없이 팀 식별자만으로 키를 UI 토큰으로 분류했습니다. 이어서 UI 경로 검사는 허용 목록의 접두사로 시작하는 모든 경로를 허용했습니다. 그 결과 `/config` 항목이 관리용 `/config/update` 핸들러에도 일치했습니다. 해당 핸들러는 일반 인증만 요구하고 `PROXY_ADMIN`을 별도로 요구하지 않았으므로, 낮은 권한의 UI 세션이 구성 쓰기 권한까지 얻게 되었습니다.<sup>[[1]](#references)</sup>

이는 프록시와 백엔드 간 경로 정규화 불일치와는 다릅니다. 권한 부여 코드와 핸들러가 *동일한* 경로의 권한을 서로 다르게 해석합니다.<sup>[[1]](#references)</sup> gateway를 검토할 때는 토큰 분류, 정확한 경로 및 메서드 일치 여부, 핸들러 자체의 역할 검사를 비교하세요.<sup>[[1]](#references)</sup> 관련되지만 별개의 경계에 대해서는 [web API 권한 부여](../pentesting-web/web-api-pentesting.md), [401/403 우회](../pentesting-web/403-and-401-bypasses.md), [프록시 접두사 예외](../pentesting-web/proxy-waf-protections-bypass.md#prefix-exemptions-become-routing-keys)를 참조하세요.

## 구성 쓰기는 구성 저장소 너머까지 영향을 미친다

동일한 LiteLLM 구성 업데이트는 환경 변수 값을 받아 실행 중인 프로세스에 적용했습니다. 한 소비자는 `UI_LOGO_PATH`를 `FileResponse`에 사용할 로컬 경로로 처리하면서 해당 경로가 로고인지 검증하지 않았습니다. 다른 소비자는 비-SSO 로그인 중 `UI_USERNAME`과 `UI_PASSWORD`를 읽고, 값이 일치하면 `PROXY_ADMIN`을 할당했습니다. 따라서 구성 쓰기 권한은 하위 소비자에 따라 로컬 파일 노출과 관리자 신원 변경으로 이어질 수 있었습니다. 응답의 미디어 유형만으로 제공되는 파일이 이미지라고 보장할 수는 없습니다.<sup>[[1]](#references)</sup>

패스스루 endpoint 구성도 또 다른 하위 sink였습니다. 초기화 과정에서 원격 S3/GCS 어댑터 대상을 허용하고, Python 모듈을 다운로드한 뒤 `importlib`의 `exec_module`을 사용해 가져왔습니다. 가져오기를 수행하면 어댑터 인스턴스를 사용하기 전에 최상위 코드가 실행됩니다. 어댑터 호출만 제한해도 이 실행 경계는 사라지지 않습니다. 이를 모델 파일 역직렬화가 아닌 구성 제어 코드 로딩으로 취급하세요.<sup>[[1]](#references)</sup> 별도의 파일 읽기 primitive는 [파일 포함 및 경로 순회](../pentesting-web/file-inclusion/)를 참조하세요.

## 요청별 모델 라우팅으로 gateway 자격 증명이 leak될 수 있다

LiteLLM의 클라이언트 측 자격 증명 기능은 LLM 요청에서 `user_config` 객체를 허용했습니다. 평가 대상 경로는 모델 목록과 제공업체 `api_base`를 포함한 해당 객체로 임시 `litellm.Router`를 생성했습니다. 호출자가 제어하는 제공업체 대상은 gateway의 아웃바운드 completion 요청과 구성된 제공업체 인증 헤더를 수신할 수 있었습니다. 최상위 `api_base` 또는 `api_key` 필드에 대한 제한은 이 별도의 중첩 구성 경로에 적용되지 않았습니다. 이는 prompt injection 문제가 아니라 자격 증명이 포함된 SSRF 경계입니다.<sup>[[1]](#references)</sup>

승인된 gateway 평가에서는 요청별 구성을 포함해 router나 제공업체 클라이언트를 생성할 수 있는 모든 경로를, 정상 구성 경로에서 사용하는 대상 및 자격 증명 정책과 비교하세요.<sup>[[1]](#references)</sup> [SSRF 가이드](../pentesting-web/ssrf-server-side-request-forgery/)에서는 일반적인 서버 측 대상 제어를 다룹니다. gateway 특유의 문제는 신뢰도가 낮은 요청 객체가 대상을 선택하면서 권한이 높은 아웃바운드 자격 증명을 재사용하도록 허용하는 것입니다.<sup>[[1]](#references)</sup>

## Guardrail 등록은 UI 전용 sandbox를 우회할 수 있다

gateway의 코드 테스트 경로와 코드 등록 경로는 서로 다른 검증을 적용할 수 있습니다. LiteLLM v1.82.0 이전 버전에서는 UI의 사용자 지정 guardrail 테스트가 위험한 구문을 거부하고 `__builtins__ = {}`로 실행했지만, `POST /guardrails`는 해당 검사 없이 제출된 `custom_code`를 `exec(compile(...), exec_globals)`로 컴파일했습니다. `__builtins__`가 없는 globals 딕셔너리에 Python이 builtins를 삽입하므로, 모듈 수준의 import와 명령은 guardrail이 등록될 때, 추론 호출이 이루어지기 전에 실행되었습니다. 이후 `apply_guardrail` callback은 차단 사유를 통해 저장된 결과를 노출할 수 있었습니다.<sup>[[2]](#references)[[3]](#references)</sup>

승인된 테스트에서는 UI sandbox 테스트가 성공했다고 해서 등록도 안전하다고 가정하지 말고, 테스트 핸들러와 등록 핸들러를 비교하세요. 수정 전 보고된 요청 형식은 다음과 같습니다.<sup>[[2]](#references)</sup>

```http
POST /guardrails HTTP/1.1
Authorization: Bearer <master_key>
Content-Type: application/json

{
  "guardrail": {
    "guardrail_name": "probe",
    "litellm_params": {
      "guardrail": "custom_code", "mode": "pre_call", "default_on": true,
      "custom_code": "import os\nresult = os.popen('id').read()\ndef apply_guardrail(inputs, request_data, input_type):\n    return {'action': 'block', 'reason': result}"
    }
  }
}
```

등록 endpoint는 `PROXY_ADMIN` 검사가 없어서 일반 API 키도 허용했습니다. master key 또는 JWT/OAuth2 인증이 구성되지 않은 경우, 수정 전 auth handler는 익명 요청에도 `PROXY_ADMIN`을 부여했습니다. 수정 사항에서는 인증이 없는 경우의 역할을 `INTERNAL_USER`로 변경하고, guardrail admin 검사를 추가했으며, 등록 시 builtins를 검증하고 제한했습니다. 이러한 역할 및 코드 실행 경계는 [MCP token-fallback issue](AI-MCP-Servers.md#mcp-token-passthrough-must-not-create-an-anonymous-session)와 별개입니다.<sup>[[2]](#references)[[3]](#references)</sup>

## Admin pass-through routes can proxy cloud metadata

LiteLLM의 pass-through endpoint 기능을 사용하면 관리자가 HTTP target을 구성하고 선택적으로 하위 경로를 추가할 수 있습니다. 위의 요청별 `user_config` 라우팅 문제와 달리, 이 기능에는 **configuration-write authority**가 필요하며, 기능 자체는 관리자를 신뢰하도록 설계되었습니다. 보고된 배포 환경에서는 target이 private 또는 link-local 주소를 가리키는지 확인하지 않았습니다.<sup>[[2]](#references)[[4]](#references)</sup> v1.83.0 이전에는 관리자 역할 검사가 없어 일반 인증 키도 `/config/update`에 접근할 수 있었습니다. 관련 configuration-write 경계는 [UI route classification](#ui-route-classification-is-not-authorization)을 참조하세요.<sup>[[2]](#references)[[6]](#references)</sup>

이 권한과 proxy에서 EC2 metadata로의 네트워크 연결이 있으면, 다음과 같은 route를 통해 gateway에서 metadata를 노출할 수 있습니다. `include_subpath` flag는 `/meta/meta-data/iam/security-credentials/`를 `/latest/` 아래의 경로로 매핑합니다.<sup>[[2]](#references)[[4]](#references)</sup>

```http
POST /config/pass_through_endpoint HTTP/1.1
Authorization: Bearer <master_key>
Content-Type: application/json

{"path":"/meta","target":"http://169.254.169.254/latest/","headers":{},"include_subpath":true}
```

[Cloud SSRF 가이드](../pentesting-web/ssrf-server-side-request-forgery/cloud-ssrf.md#aws)에서는 IMDSv2 토큰 교환을 다룹니다. 이 경로는 `PUT` 요청을 허용하고 두 메타데이터 헤더를 모두 전달해야 합니다.<sup>[[5]](#references)</sup> LiteLLM의 일반적인 pass-through 헤더 처리는 전달 전에 `x-pass-` 접두사를 제거하므로, `x-pass-X-aws-ec2-metadata-token-ttl-seconds: 21600` 및 `x-pass-X-aws-ec2-metadata-token: <token>`으로 해당 헤더를 설정할 수 있습니다.<sup>[[2]](#references)[[7]](#references)</sup> 프록시가 IMDS에 도달할 수 있어야 하고, 토큰 응답이 구성된 hop limit을 통과해야 하며, 토큰 요청에는 `X-Forwarded-For`가 포함되지 않아야 합니다.<sup>[[5]](#references)</sup> 이 gateway에 특화된 변형은 **관리자가 제어하는 영구 경로와 요청 헤더 전달**입니다.

## References

- [1] [Check Point Research — LLM Gateway의 문제: LiteLLM 조사 결과](https://research.checkpoint.com/2026/when-llm-gateways-go-wrong-findings-from-litellm/)
- [2] [Wiz — 방심한 틈을 노리다: 인증 우회에서 cloud 침해까지 LiteLLM 공략하기](https://wiz.io/blog/off-guard-breaking-litellm-from-authentication-bypass-to-cloud-compromise)
- [3] [LiteLLM PR #22095 — custom code guardrail의 인증되지 않은 RCE 및 sandbox escape 수정](https://github.com/BerriAI/litellm/pull/22095)
- [4] [LiteLLM — Pass Through Endpoint 생성하기](https://docs.litellm.ai/docs/proxy/pass_through)
- [5] [AWS — Instance Metadata Service 버전 2의 작동 방식](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-metadata-v2-how-it-works.html)
- [6] [LiteLLM 권고문 — 제한 없는 proxy 구성 endpoint](https://github.com/advisories/GHSA-53mr-6c8q-9789)
- [7] [LiteLLM pass-through 헤더 전달 구현](https://github.com/BerriAI/litellm/blob/v1.84.0/litellm/passthrough/utils.py)
{{#include ../banners/hacktricks-training.md}}
