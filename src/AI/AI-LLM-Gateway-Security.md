# LLM Gateway 신뢰 경계

{{#include ../banners/hacktricks-training.md}}

LLM gateway는 모델 라우팅을 처리하고 provider 인증 정보를 보유하는 경우가 많으므로, 일반 API 호출자에게 설정 권한이나 provider 수준의 권한을 부여해서는 안 됩니다. LiteLLM 버전 1.77.7에 대한 gateway 평가는 서로 다른 두 가지 경계를 보여 줍니다. 관리자 설정을 위한 UI 세션 권한 부여와 추론을 위한 호출자 제공 라우팅 설정입니다. 보고된 문제는 버전 1.83.9에서 수정되었습니다.<sup>[[1]](#references)</sup>

## UI 경로 분류는 권한 부여가 아닙니다

평가 대상 LiteLLM 버전에서 UI 로그인 키는 `litellm-dashboard` 팀에 속했습니다. 권한 부여 로직은 사용자의 역할과 관계없이 해당 팀 식별자를 기준으로 키를 UI 토큰으로 분류했습니다. 이후 UI 경로 검사는 허용 목록에 있는 접두사로 시작하는 모든 경로를 허용했습니다. 그 결과 `/config` 항목이 관리자용 `/config/update` 핸들러에도 일치했습니다. 해당 핸들러는 일반 인증을 요구했지만 `PROXY_ADMIN` 권한은 별도로 요구하지 않았으므로, 낮은 권한의 UI 세션이 설정 쓰기 권한을 얻을 수 있었습니다.<sup>[[1]](#references)</sup>

이는 proxy와 backend 간 경로 정규화 불일치와는 다릅니다. 권한 부여 코드와 핸들러가 *동일한* 경로의 권한을 서로 다르게 판단합니다.<sup>[[1]](#references)</sup> gateway를 검토할 때는 토큰 분류, 정확한 경로 및 메서드 일치 여부, 핸들러 자체의 역할 검사 로직을 비교하세요.<sup>[[1]](#references)</sup> 관련은 있지만 서로 다른 경계에 대해서는 [웹 API 권한 부여](../pentesting-web/web-api-pentesting.md), [401/403 우회](../pentesting-web/403-and-401-bypasses.md), [proxy 접두사 예외](../pentesting-web/proxy-waf-protections-bypass.md#prefix-exemptions-become-routing-keys)를 참고하세요.

## 설정 쓰기는 설정 저장소 외부에도 영향을 미칩니다

동일한 LiteLLM 설정 업데이트 기능은 환경 변수 값을 받아 실행 중인 프로세스에 적용했습니다. 한 소비자는 `UI_LOGO_PATH`를 `FileResponse`에 전달할 로컬 경로로 사용하면서 해당 경로가 로고 파일인지 검증하지 않았습니다. 다른 소비자는 SSO가 아닌 로그인 과정에서 `UI_USERNAME`과 `UI_PASSWORD`를 읽고, 값이 일치하면 `PROXY_ADMIN`을 부여했습니다. 따라서 설정 쓰기 권한은 후속 소비자에 따라 로컬 파일 노출과 관리자 신원 변경 모두로 이어질 수 있었습니다. 응답의 미디어 유형만으로 제공된 파일이 이미지라고 단정할 수는 없습니다.<sup>[[1]](#references)</sup>

pass-through endpoint 설정은 또 다른 후속 sink였습니다. 초기화 과정에서 원격 S3/GCS adapter 대상을 허용하고, Python 모듈을 다운로드한 뒤 `importlib`의 `exec_module`을 사용해 가져왔습니다. import는 adapter 인스턴스를 사용하기 전에 최상위 코드를 실행합니다. 따라서 adapter 호출만 제한해도 이 실행 경계는 제거되지 않습니다. 이를 모델 파일 역직렬화가 아니라 설정으로 제어되는 코드 로딩으로 취급하세요.<sup>[[1]](#references)</sup> 별도의 파일 읽기 primitive에 대해서는 [파일 포함 및 경로 탐색](../pentesting-web/file-inclusion/)을 참고하세요.

## 요청별 모델 라우팅으로 gateway 인증 정보가 leak될 수 있습니다

LiteLLM의 클라이언트 측 인증 정보 기능은 LLM 요청에서 `user_config` 객체를 허용했습니다. 평가 대상 경로는 해당 객체로부터 모델 목록과 provider `api_base`를 포함하는 임시 `litellm.Router`를 생성했습니다. 호출자가 제어하는 provider 대상은 gateway의 아웃바운드 completion 요청과 설정된 provider 인증 헤더를 수신할 수 있었습니다. 최상위 `api_base` 또는 `api_key` 필드에 대한 제한은 별도의 중첩 설정 경로에는 적용되지 않았습니다. 이는 prompt-injection 문제가 아니라 인증 정보를 수반하는 SSRF 경계입니다.<sup>[[1]](#references)</sup>

승인된 gateway 평가에서는 요청별 설정을 포함해 router나 provider client를 생성할 수 있는 모든 경로를, 일반적으로 설정된 경로에 적용되는 대상 및 인증 정보 정책과 비교하세요.<sup>[[1]](#references)</sup> [SSRF 가이드](../pentesting-web/ssrf-server-side-request-forgery/)에서는 일반적인 서버 측 대상 제어를 다룹니다. gateway에서 발생하는 특유의 취약점은 신뢰도가 더 낮은 요청 객체가 대상을 선택하면서 권한이 높은 아웃바운드 인증 정보를 재사용하도록 허용하는 것입니다.<sup>[[1]](#references)</sup>

## References

- [1] [Check Point Research — LLM Gateway의 문제: LiteLLM 분석 결과](https://research.checkpoint.com/2026/when-llm-gateways-go-wrong-findings-from-litellm/)
{{#include ../banners/hacktricks-training.md}}
