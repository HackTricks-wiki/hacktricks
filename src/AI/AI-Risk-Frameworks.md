# AI 위험

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

OWASP는 AI 시스템에 영향을 줄 수 있는 상위 10가지 machine learning 취약점을 식별했습니다. 이러한 취약점은 data poisoning, model inversion, adversarial attack 등 다양한 보안 문제를 일으킬 수 있습니다. 안전한 AI 시스템을 구축하려면 이러한 취약점을 이해하는 것이 중요합니다.

상위 10가지 machine learning 취약점에 대한 최신 상세 목록은 [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/) 프로젝트를 참조하세요.<sup>[[1]](#references)</sup>

- **Input Manipulation Attack**: 공격자는 **입력 데이터**에 아주 작고 눈에 잘 띄지 않는 변화를 추가해 모델이 잘못된 결정을 내리도록 합니다.\
    *예시*: 정지 표지판에 페인트를 몇 점 찍어 자율주행차가 이를 제한 속도 표지판으로 "인식"하게 합니다.

- **Data Poisoning Attack**: **훈련 데이터셋**을 의도적으로 오염시켜 모델이 해로운 규칙을 학습하게 합니다.\
*예시*: 백신 학습 데이터에서 malware 바이너리를 "정상"으로 잘못 분류하면 유사한 malware가 이후 탐지를 피할 수 있습니다.

- **Model Inversion Attack**: 공격자는 출력값을 조사해 **역모델**을 구축하고, 이를 통해 원본 입력의 민감한 특성을 재구성합니다.\
*예시*: 암 진단 모델의 예측 결과로 환자의 MRI 이미지를 재구성합니다.

- **Membership Inference Attack**: 공격자는 신뢰도 차이를 감지해 **특정 레코드**가 훈련 과정에 사용되었는지 확인합니다.\
*예시*: 특정인의 은행 거래 내역이 사기 탐지 모델의 훈련 데이터에 포함되었는지 확인합니다.

- **Model Theft**: 반복적인 질의를 통해 공격자는 결정 경계를 파악하고 **모델의 동작을 복제**합니다(IP도 탈취할 수 있습니다).\
*예시*: ML-as-a-Service API에서 충분한 Q&A 쌍을 수집해 거의 동등한 로컬 모델을 구축합니다.

- **AI Supply‑Chain Attack**: **ML 파이프라인**의 구성 요소(데이터, 라이브러리, 사전 훈련된 가중치, CI/CD 등)를 침해해 이후 모델을 오염시킵니다.\
*예시*: model hub의 오염된 종속 항목이 백도어가 삽입된 감성 분석 모델을 여러 앱에 설치합니다.

- **Transfer Learning Attack**: 악성 로직을 **사전 훈련된 모델**에 심어 피해자의 작업에 맞게 fine-tuning한 뒤에도 유지되도록 합니다.\
*예시*: 숨겨진 트리거가 있는 vision backbone은 의료 영상 분석용으로 조정된 후에도 레이블을 바꿉니다.

- **Model Skewing**: 편향되거나 잘못 레이블링된 데이터를 은밀하게 사용해 **모델 출력을 공격자의 의도에 유리하게 바꿉니다**.\
*예시*: 스팸 이메일을 "정상"으로 레이블링해 주입하면 스팸 필터가 이후 유사한 이메일을 통과시킵니다.

- **Output Integrity Attack**: 공격자는 모델 자체가 아니라 **전송 중인 모델 예측값을 변경**해 후속 시스템을 속입니다.\
*예시*: 파일 격리 단계에 도달하기 전에 malware 분류기의 "악성" 판정을 "정상"으로 바꿉니다.

- **Model Poisoning** --- **모델 파라미터**를 직접 표적으로 삼아 변경하는 공격으로, 동작을 바꾸기 위해 쓰기 권한을 획득한 뒤 수행되는 경우가 많습니다.\
*예시*: 운영 중인 사기 탐지 모델의 가중치를 조정해 특정 카드의 거래가 항상 승인되도록 합니다.


## Google SAIF Risks

Google의 [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks)는 AI 시스템과 관련된 여러 위험을 설명합니다:<sup>[[2]](#references)</sup>

- **데이터 오염**: 악의적인 행위자가 훈련 또는 튜닝 데이터를 변경하거나 주입해 정확도를 떨어뜨리고, 백도어를 심거나 결과를 왜곡하여 전체 데이터 수명 주기에 걸쳐 모델 무결성을 훼손합니다.

- **승인되지 않은 훈련 데이터**: 저작권이 있거나 민감하거나 사용 허가를 받지 않은 데이터셋을 수집하면 법적·윤리적·성능상의 책임이 발생합니다. 모델이 사용 권한이 없는 데이터로 학습하기 때문입니다.

- **모델 소스 변조**: 훈련 전이나 도중에 공급망 또는 내부자가 모델 코드, 종속 항목, 가중치를 조작하면 재훈련 후에도 지속되는 숨겨진 로직이 삽입될 수 있습니다.

- **과도한 데이터 처리**: 데이터 보존 및 관리 통제가 취약하면 시스템이 필요한 양보다 많은 개인정보를 저장하거나 처리하게 되어 노출 및 규정 준수 위험이 커집니다.

- **모델 유출**: 공격자가 모델 파일이나 가중치를 탈취하면 지식재산이 손실되고, 모방 서비스나 후속 공격이 가능해집니다.

- **모델 배포 변조**: 공격자가 모델 아티팩트나 서비스 인프라를 변경하면 실행 중인 모델이 검증된 버전과 달라져 동작이 바뀔 수 있습니다.

- **ML 서비스 거부**: API에 트래픽을 퍼붓거나 "sponge" 입력을 보내면 컴퓨팅 자원과 에너지를 소진시켜 모델을 오프라인으로 만들 수 있습니다. 이는 일반적인 DoS 공격과 유사합니다.

- **모델 역공학**: 공격자는 다량의 입력-출력 쌍을 수집해 모델을 복제하거나 distillation할 수 있으며, 이를 통해 모방 제품을 만들고 맞춤형 adversarial attack을 수행할 수 있습니다.

- **안전하지 않은 통합 구성 요소**: 취약한 플러그인, 에이전트 또는 상위 서비스로 인해 공격자가 AI 파이프라인에 코드를 삽입하거나 권한을 상승시킬 수 있습니다.

- **Prompt Injection**: 프롬프트를 직접 또는 간접적으로 조작해 시스템의 의도를 덮어쓰는 지시를 숨겨 넣고, 모델이 의도하지 않은 명령을 수행하게 합니다.

- **모델 회피**: 세심하게 설계된 입력으로 모델이 오분류하거나 환각을 일으키거나 허용되지 않은 콘텐츠를 출력하게 해 안전성과 신뢰를 훼손합니다.

- **민감한 데이터 공개**: 모델이 훈련 데이터나 사용자 컨텍스트에서 개인정보 또는 기밀 정보를 노출해 개인정보 보호와 규정을 위반합니다.

- **추론된 민감 데이터**: 모델이 제공된 적 없는 개인 속성을 추론하여 개인정보 침해를 일으킵니다.

- **안전하지 않은 모델 출력**: 정제되지 않은 응답이 유해한 코드, 잘못된 정보 또는 부적절한 콘텐츠를 사용자나 후속 시스템에 전달합니다.

- **무단 동작**: 자율적으로 통합된 에이전트가 충분한 사용자 감독 없이 파일 쓰기, API 호출, 구매 등 의도하지 않은 실제 작업을 실행합니다.

## Mitre AI ATLAS Matrix

[MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS)는 AI 시스템과 관련된 위험을 이해하고 완화하기 위한 포괄적인 프레임워크를 제공합니다. 이 프레임워크는 적대자가 AI 모델을 공격하는 데 사용할 수 있는 다양한 공격 기법과 전술, 그리고 AI 시스템을 사용해 여러 공격을 수행하는 방법을 분류합니다.<sup>[[3]](#references)</sup>

## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

공격자는 활성 세션 토큰이나 cloud API 자격 증명을 탈취해 권한 없이 유료 cloud-hosted LLM을 호출합니다. 피해자의 계정을 앞단에 두는 reverse proxy를 통해 접근 권한을 재판매하는 경우가 많습니다. 예를 들어 "oai-reverse-proxy" 배포가 있습니다. 그 결과 금전적 손실, 정책에 어긋나는 모델 사용, 피해자 테넌트로의 귀속 등이 발생할 수 있습니다.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

TTPs:
- 감염된 개발자 컴퓨터나 브라우저에서 토큰을 수집하고, CI/CD secrets를 탈취하거나 유출된 쿠키를 구매합니다.<sup>[[5]](#references)</sup>
- 실제 제공업체로 요청을 전달하는 reverse proxy를 구축해 상위 키를 숨기고 여러 고객을 연결합니다.<sup>[[5]](#references)</sup><sup>[[7]](#references)</sup>
- 직접적인 base-model endpoint를 악용해 기업의 guardrail 및 rate limit을 우회합니다.<sup>[[4]](#references)</sup>

Mitigations:
- 토큰을 기기 지문, IP 범위, 클라이언트 증명에 연결하고, 만료 시간을 짧게 설정한 뒤 MFA로 갱신합니다.
- 키의 범위를 최소화합니다(도구 접근을 허용하지 않고, 해당되는 경우 읽기 전용으로 설정). 이상 징후가 있으면 키를 교체합니다.
- 모든 트래픽을 정책 게이트웨이 뒤의 서버 측에서 종료하고, 안전 필터, 경로별 할당량, 테넌트 격리를 적용합니다.
- 갑작스러운 지출 급증, 비정상적인 지역, 특이한 UA 문자열 등 사용 패턴을 모니터링하고 의심스러운 세션을 자동으로 취소합니다.
- 장기간 유효한 정적 API 키 대신 IdP가 발급한 mTLS 또는 서명된 JWT를 사용합니다.

## Self-hosted LLM inference hardening

기밀 데이터를 처리하는 로컬 LLM 서버는 cloud-hosted API와는 다른 공격 표면을 만듭니다. inference/debug endpoint를 통해 프롬프트가 유출될 수 있고, 서빙 스택은 보통 reverse proxy를 노출하며, GPU device node는 광범위한 `ioctl()` 표면에 접근할 수 있습니다. 온프레미스 inference 서비스를 평가하거나 배포하는 경우 최소한 다음 항목을 검토하세요.<sup>[[8]](#references)</sup>

### Prompt leakage via debug and monitoring endpoints

inference API를 **여러 사용자가 이용하는 민감 서비스**로 취급하세요. 디버그 또는 모니터링 경로를 통해 프롬프트 내용, 슬롯 상태, 모델 메타데이터 또는 내부 큐 정보가 노출될 수 있습니다. `llama.cpp`에서 `/slots` endpoint는 슬롯별 상태를 노출하고 슬롯 검사 및 관리 용도로만 사용되므로 특히 민감합니다.<sup>[[8]](#references)</sup>

- inference server 앞에 reverse proxy를 두고 **기본적으로 차단**합니다.
- 클라이언트/UI에 필요한 정확한 HTTP method 및 path 조합만 allowlist에 추가합니다.
- 가능하면 백엔드 자체에서 introspection endpoint를 비활성화합니다. 예: `llama-server --no-slots`.<sup>[[9]](#references)</sup>
- reverse proxy를 `127.0.0.1`에 바인딩하고 LAN에 공개하는 대신 SSH local port forwarding과 같은 인증된 전송 방식을 통해 노출합니다.

nginx allowlist 예시:

```nginx
map "$request_method:$uri" $llm_whitelist {
    default 0;

    "GET:/health"              1;
    "GET:/v1/models"           1;
    "POST:/v1/completions"     1;
    "POST:/v1/chat/completions" 1;
}

server {
    listen 127.0.0.1:80;

    location / {
        if ($llm_whitelist = 0) { return 403; }
        proxy_pass http://unix:/run/llama-cpp/llama-cpp.sock:;
    }
}
```

### 네트워크와 UNIX 소켓을 사용하지 않는 Rootless 컨테이너

추론 데몬이 UNIX 소켓에서 수신 대기할 수 있다면 TCP보다 이를 우선하고, 컨테이너를 **네트워크 스택 없이** 실행하세요:<sup>[[8]](#references)</sup>

```bash
podman run --rm -d \
  --network none \
  --user 1000:1000 \
  --userns=keep-id \
  --umask=007 \
  --volume /var/lib/models:/models:ro \
  --volume /srv/llm/socks:/run/llama-cpp \
  ghcr.io/ggml-org/llama.cpp:server-cuda13 \
    --host /run/llama-cpp/llama-cpp.sock \
    --model /models/model.gguf \
    --parallel 4 \
    --no-slots
```

혜택:
- `--network none`은 인바운드/아웃바운드 TCP/IP 노출을 제거하고, rootless 컨테이너에 필요한 사용자 모드 헬퍼를 사용하지 않도록 합니다.
- UNIX socket을 사용하면 socket 경로의 POSIX 권한/ACL을 첫 번째 접근 제어 계층으로 적용할 수 있습니다.
- `--userns=keep-id`와 rootless Podman은 컨테이너 탈출의 영향을 줄입니다. 컨테이너의 root는 호스트의 root가 아니기 때문입니다.
- 모델을 읽기 전용으로 마운트하면 컨테이너 내부에서 모델이 변조될 가능성을 줄일 수 있습니다.

영구 배포의 경우, 동일한 제한을 Podman Quadlet 유닛으로 표현할 수 있습니다. Container Device Interface를 통해 GPU 액세스를 위임하는 경우, 모든 가속기 노드를 노출하는 대신 CDI 장치 사양을 가능한 한 제한적으로 유지하세요.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>

### GPU 장치 노드 최소화

GPU 기반 추론에서 `/dev/nvidia*` 파일은 대규모 드라이버 `ioctl()` 핸들러와 공유 GPU 메모리 관리 경로에 대한 접근을 노출할 수 있으므로, 가치가 높은 로컬 공격 표면입니다.<sup>[[8]](#references)</sup>

- `/dev/nvidia*`를 모든 사용자가 쓸 수 있는 상태로 두지 마세요.
- `NVreg_DeviceFileUID/GID/Mode`, udev 규칙, ACL을 사용해 `nvidia`, `nvidiactl`, `nvidia-uvm`을 제한하고, 매핑된 컨테이너 UID만 해당 장치를 열 수 있도록 하세요.
- 헤드리스 추론 호스트에서는 `nvidia_drm`, `nvidia_modeset`, `nvidia_peermem` 등 불필요한 모듈을 블랙리스트에 추가하세요.
- 추론 시작 중 런타임이 필요에 따라 `modprobe`를 실행하게 두지 말고, 부팅 시 필요한 모듈만 미리 로드하세요.

예시:

```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```

중요한 검토 항목 중 하나는 **`/dev/nvidia-uvm`**입니다. 워크로드에서 `cudaMallocManaged()`를 명시적으로 사용하지 않더라도 최신 CUDA 런타임에는 `nvidia-uvm`이 필요할 수 있습니다. 이 장치는 공유되며 GPU 가상 메모리 관리를 처리하므로, 테넌트 간 데이터 노출 표면으로 간주하세요. 추론 백엔드에서 지원한다면 Vulkan backend는 컨테이너에 `nvidia-uvm`을 전혀 노출하지 않을 수 있어 흥미로운 절충안이 될 수 있습니다.<sup>[[8]](#references)</sup>

### 추론 워커를 위한 LSM 격리

추론 프로세스를 심층 방어하기 위해 AppArmor/SELinux/seccomp를 사용해야 합니다:<sup>[[8]](#references)</sup>

- 실제로 필요한 공유 라이브러리, 모델 경로, 소켓 디렉터리, GPU 장치 노드만 허용합니다.
- `sys_admin`, `sys_module`, `sys_rawio`, `sys_ptrace`와 같은 고위험 capability를 명시적으로 거부합니다.
- 모델 디렉터리는 읽기 전용으로 유지하고, 쓰기 가능한 경로는 런타임 소켓/캐시 디렉터리로만 제한합니다.
- 거부 로그를 모니터링합니다. 모델 서버나 post-exploitation payload가 예상된 동작 범위를 벗어나려고 할 때 유용한 탐지 텔레메트리를 제공하기 때문입니다.

GPU 기반 워커를 위한 AppArmor 규칙 예시:

```text
deny capability sys_admin,
deny capability sys_module,
deny capability sys_rawio,
deny capability sys_ptrace,

/usr/lib/x86_64-linux-gnu/** mr,
/dev/nvidiactl rw,
/dev/nvidia0 rw,
/var/lib/models/** r,
owner /srv/llm/** rw,
```

## Phantom Squatting: LLM이 환각으로 만들어내는 도메인을 이용한 AI 공급망 공격 벡터

Phantom squatting은 **slopsquatting의 도메인/URL 버전**입니다. 존재하지 않는 패키지 이름을 환각하는 대신, LLM은 실제 브랜드의 **포털, API, webhook, 결제, SSO, 다운로드 또는 지원 도메인**을 그럴듯하게 환각하며, 공격자는 사람이나 에이전트가 사용하기 전에 해당 네임스페이스를 등록합니다.<sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

많은 AI 지원 워크플로에서 모델 출력이 **신뢰할 수 있는 종속성**으로 취급되기 때문에 이는 중요합니다:
- 개발자는 제안된 엔드포인트를 코드나 CI/CD 통합에 붙여넣습니다.
- AI 에이전트는 문서, 스키마, APK, ZIP 또는 webhook 대상을 자동으로 가져옵니다.
- 생성된 런북이나 문서에 가짜 URL이 권위 있는 주소인 것처럼 포함될 수 있습니다.

### 공격 워크플로

1. **환각 표면 탐색**: `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` 또는 `mobile app` 포털처럼 현실적인 워크플로와 관련해 특정 브랜드를 대상으로 질문합니다.<sup>[[12]](#references)</sup>
2. **후보 정규화**: 생성된 URL을 확인하고, NXDOMAIN 응답은 등록 가능한 상위 도메인으로 축약한 다음, 프롬프트 계열별 중복을 제거합니다. 예를 들어 **Jaccard 유사도**를 사용해 거의 중복되는 항목을 제거하여 프롬프트 모음을 다양하게 유지합니다.
3. **예측 가능한 환각 우선 처리**:
   - **Thermal Hallucination Persistence (THP)**: 동일한 가짜 도메인이 낮은 온도인 `T=0.1`을 포함해 여러 온도 설정에서 나타납니다.
   - **모델 간 합의**: 여러 LLM 계열이 동일한 가짜 도메인을 생성합니다.
4. 상위 도메인을 **등록하고 무기화한** 다음, 피싱 페이지, 가짜 APK/ZIP 다운로드, 자격 증명 수집 도구, 악성 문서 또는 비밀 정보/webhook 페이로드를 수집하는 API 엔드포인트를 호스팅합니다. **순수한 도메인 수준의 환각**은 공격자가 네임스페이스 전체를 제어하므로 수익화하기 가장 쉽습니다. 정규화된 상위 도메인이 미등록 상태라면 하위 도메인/경로 환각도 악용할 수 있습니다.
5. **평판이 없는 초기 기간 악용**: 신규 등록 도메인은 차단 목록 기록, URL 평판, 충분한 텔레메트리가 없는 경우가 많아 탐지 체계가 따라잡을 때까지 보안 통제를 우회할 수 있습니다. 공격자는 크롤러에만 정상 응답을 제공하거나, 리디렉션 클로킹, CAPTCHA 게이트, 지연 페이로드 스테이징을 이용해 이 기간을 늘릴 수 있습니다.

### 에이전트에 위험한 이유

사람이 피해자인 경우 가짜 도메인은 보통 클릭과 추가 행동이 필요합니다. 하지만 **에이전트 기반 워크플로**에서는 LLM이 **미끼**이자 **실행자**가 될 수 있습니다. 에이전트는 환각된 URL을 받아 가져오고 응답을 파싱한 뒤, 사람의 검토 없이 토큰을 leak하거나, 명령을 실행하거나, 종속성을 다운로드하거나, 오염된 데이터를 CI/CD에 전달할 수 있습니다.<sup>[[12]](#references)</sup>

### 실용적인 공격자 프롬프트

효과가 높은 프롬프트는 대개 노골적인 피싱 미끼 대신 일반적인 기업 업무처럼 보입니다:<sup>[[12]](#references)</sup>
- “`<brand>` 통합을 위한 결제 sandbox URL은 무엇인가요?”
- “`<brand>` 빌드 알림에 사용할 webhook 엔드포인트는 무엇인가요?”
- “`<brand>`의 직원 복리후생 / 결제 / SSO 포털은 어디에 있나요?”
- “`<brand>`의 Android APK 또는 데스크톱 클라이언트를 직접 다운로드할 수 있는 링크를 알려주세요.”

### 방어적 대응

이를 단순한 프롬프트 인젝션 문제가 아니라 선제적인 도메인 모니터링 문제로 다룹니다:<sup>[[12]](#references)</sup>
- **브랜드 프롬프트 모음**을 만들고 사용자/에이전트가 의존하는 LLM을 주기적으로 테스트합니다.
- 환각된 URL을 저장하고, 온도 설정/모델 간에 어떤 URL이 안정적으로 나타나는지 추적합니다.
- **Adversarial Exploitation Window (AEW)**를 추적합니다. 이는 첫 환각 발생부터 공격자의 도메인 등록까지 걸리는 시간입니다. AEW가 양수이면 방어자가 무기화 전에 선제 등록, 싱크홀링 또는 사전 차단을 할 수 있습니다.
- 상위 도메인의 **NXDOMAIN → 등록** 전환을 모니터링합니다.
- 도메인이 등록되면 등록기관, 생성일, 네임서버, 개인정보 보호 설정, 페이지 콘텐츠, 스크린샷, 파킹 페이지 여부, 브랜드 자산 유사성을 분류합니다.
- 에이전트/개발자가 **LLM이 생성한 도메인을 기본적으로 신뢰하지 않도록** 정책 게이트를 추가합니다. 최초 사용 전에 허용 목록, 소유권 검증, CT/RDAP 검사 또는 사람의 승인을 요구합니다.

이는 여러 AI 위험 범주에 해당합니다. **AI 공급망 공격**, **안전하지 않은 모델 출력**, 그리고 에이전트가 환각된 URL을 자율적으로 사용하는 경우의 **불법 행위**가 포함됩니다.

## References

- [1] [OWASP 머신러닝 취약점 상위 10개](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google SAIF (Secure AI Framework) – 위험](https://saif.google/secure-ai-framework/risks)
- [3] [MITRE ATLAS 위협 매트릭스](https://atlas.mitre.org/)
- [4] [Unit 42 – 코드 어시스턴트 LLM의 위험: 유해 콘텐츠, 오용 및 기만](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [5] [Sysdig – LLMjacking: 새로운 AI 공격에 사용된 탈취된 클라우드 자격 증명](https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/)
- [6] [LLMJacking 수법 개요 – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [7] [oai-reverse-proxy (탈취한 LLM 액세스 재판매)](https://gitgud.io/khanon/oai-reverse-proxy)
- [8] [Synacktiv - 온프레미스 저권한 LLM 서버 배포 심층 분석](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [9] [llama.cpp 서버 README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [10] [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [11] [CNCF Container Device Interface (CDI) 사양](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [12] [Unit 42 – Phantom Squatting: AI 환각 도메인을 이용한 소프트웨어 공급망 공격 벡터](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [13] [Socket – Slopsquatting: AI 환각이 새로운 유형의 공급망 공격을 부추기는 방식](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)
{{#include ../banners/hacktricks-training.md}}
