# AI 위험

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

OWASP는 AI 시스템에 영향을 줄 수 있는 상위 10가지 machine learning 취약점을 식별했습니다. 이러한 취약점은 data poisoning, model inversion, adversarial attacks 등 다양한 보안 문제를 일으킬 수 있습니다. 안전한 AI 시스템을 구축하려면 이러한 취약점을 이해하는 것이 중요합니다.

상위 10가지 machine learning 취약점의 최신 상세 목록은 [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/) 프로젝트를 참고하세요.<sup>[[1]](#references)</sup>

- **Input Manipulation Attack**: 공격자는 **들어오는 데이터**를 조금, 흔히 눈에 띄지 않게 변경해 모델이 잘못된 결정을 내리도록 합니다.\
    *예시*: 정지 표지판에 페인트를 조금 튀기면 자율주행차가 이를 제한 속도 표지판으로 "인식"하게 됩니다.

- **Data Poisoning Attack**: **training set**에 의도적으로 잘못된 샘플을 섞어 모델이 해로운 규칙을 학습하게 합니다.\
*예시*: antivirus training corpus에서 malware 바이너리를 "benign"으로 잘못 분류하면 이후 유사한 malware가 탐지를 피할 수 있습니다.

- **Model Inversion Attack**: 공격자는 출력을 조사해 **역모델**을 만들고, 이를 통해 원래 입력의 민감한 특성을 재구성합니다.\
*예시*: 암 진단 모델의 예측 결과를 바탕으로 환자의 MRI 이미지를 재현합니다.

- **Membership Inference Attack**: 공격자는 신뢰도 차이를 확인해 **특정 레코드**가 학습에 사용됐는지 검사합니다.\
*예시*: 특정인의 은행 거래 내역이 fraud-detection 모델의 training data에 포함되어 있는지 확인합니다.

- **Model Theft**: 반복해서 질의하면 공격자는 decision boundary를 파악해 **모델의 동작(및 IP)을 복제**할 수 있습니다.\
*예시*: ML-as-a-Service API에서 충분한 Q&A 쌍을 수집해 거의 동등한 로컬 모델을 만듭니다.

- **AI Supply‑Chain Attack**: **ML pipeline**의 구성 요소(data, libraries, pre-trained weights, CI/CD)를 하나라도 침해해 이후 모델을 손상시킵니다.\
*예시*: model hub의 오염된 dependency가 여러 앱에 backdoor가 포함된 sentiment-analysis 모델을 설치합니다.

- **Transfer Learning Attack**: 악성 로직을 **pre-trained model**에 심으면 피해자의 task에 맞춰 fine-tuning한 뒤에도 남아 있습니다.\
*예시*: 숨겨진 trigger가 있는 vision backbone이 medical imaging용으로 조정된 뒤에도 label을 바꿉니다.

- **Model Skewing**: 미묘하게 편향되거나 잘못 label된 data로 **모델의 출력이 바뀌어** 공격자의 목적에 유리해집니다.\
*예시*: "clean" spam 이메일에 ham label을 붙여 주입하면 spam filter가 이후 유사한 이메일을 통과시킵니다.

- **Output Integrity Attack**: 공격자는 모델 자체가 아니라 **전송 중인 모델 예측을 변경**해 후속 시스템을 속입니다.\
*예시*: malware classifier의 "malicious" 판정을 파일 격리 단계에 전달되기 전에 "benign"으로 바꿉니다.

- **Model Poisoning** --- **모델 파라미터** 자체를 직접 표적 변경합니다. 보통 write access를 얻은 뒤 동작을 바꾸기 위해 수행합니다.\
*예시*: production 환경의 fraud-detection 모델에서 weights를 조정해 특정 카드의 거래가 항상 승인되게 합니다.


## Google SAIF Risks

Google의 [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks)는 AI 시스템과 관련된 여러 위험을 설명합니다:<sup>[[2]](#references)</sup>

- **Data Poisoning**: 악의적인 행위자가 training/tuning data를 변경하거나 주입해 정확도를 낮추고, backdoor를 심거나, 결과를 왜곡합니다. 이로 인해 전체 data lifecycle에 걸쳐 모델 무결성이 저해됩니다. 

- **Unauthorized Training Data**: 저작권이 있거나 민감하거나 사용이 허가되지 않은 데이터셋을 수집하면 법적·윤리적·성능상 책임이 발생합니다. 모델이 사용 허가를 받지 않은 data로 학습하기 때문입니다. 

- **Model Source Tampering**: training 전이나 도중에 supply-chain 또는 내부자가 모델 코드, dependencies, weights를 조작하면 재학습 후에도 남는 숨겨진 로직이 심어질 수 있습니다. 

- **Excessive Data Handling**: 취약한 data 보존 및 거버넌스 통제로 인해 시스템이 필요한 수준보다 더 많은 개인정보를 저장하거나 처리하게 되어 노출 위험과 규정 준수 위험이 커집니다. 

- **Model Exfiltration**: 공격자가 모델 파일/weights를 훔쳐 지적 재산 손실을 일으키고, 모방 서비스나 후속 공격을 가능하게 합니다. 

- **Model Deployment Tampering**: 공격자가 모델 산출물이나 serving infrastructure를 변경해 실행 중인 모델이 검증된 버전과 달라지고, 잠재적으로 동작이 바뀔 수 있습니다. 

- **Denial of ML Service**: API에 과도한 요청을 보내거나 “sponge” 입력을 전송해 연산/에너지를 고갈시키고 모델을 중단시킵니다. 기존 DoS 공격과 유사합니다. 

- **Model Reverse Engineering**: 다량의 입력-출력 쌍을 수집하면 공격자가 모델을 복제하거나 distil할 수 있어 모방 제품과 맞춤형 adversarial attacks에 악용될 수 있습니다. 

- **Insecure Integrated Component**: 취약한 plugins, agents, upstream services를 통해 공격자가 AI pipeline에 코드를 주입하거나 권한을 상승시킬 수 있습니다. 

- **Prompt Injection**: 직접 또는 간접적으로 지시를 몰래 삽입하는 prompts를 작성해 시스템의 의도를 무시하게 만들고, 모델이 의도하지 않은 명령을 수행하게 합니다. 

- **Model Evasion**: 신중하게 설계한 입력으로 모델이 잘못 분류하거나, hallucinate하거나, 허용되지 않은 콘텐츠를 출력하게 해 안전성과 신뢰를 훼손합니다. 

- **Sensitive Data Disclosure**: 모델이 training data 또는 사용자 맥락에 포함된 개인 정보나 기밀 정보를 드러내 개인정보 보호 및 규정을 위반합니다. 

- **Inferred Sensitive Data**: 모델이 제공된 적 없는 개인 특성을 추론해 새로운 개인정보 침해를 일으킵니다. 

- **Insecure Model Output**: 정제되지 않은 응답이 유해한 코드, 잘못된 정보 또는 부적절한 콘텐츠를 사용자나 후속 시스템에 전달합니다. 

- **Rogue Actions**: 자율적으로 통합된 agents가 충분한 사용자 감독 없이 의도하지 않은 실제 작업(file writes, API calls, purchases 등)을 실행합니다.

## Mitre AI ATLAS Matrix

[MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS)는 AI 시스템과 관련된 위험을 이해하고 완화하기 위한 포괄적인 framework를 제공합니다. 이 framework는 적대자가 AI 모델에 사용할 수 있는 다양한 공격 기법과 전술, 그리고 AI 시스템을 활용해 여러 공격을 수행하는 방법을 분류합니다.<sup>[[3]](#references)</sup>

## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

공격자는 활성 session tokens 또는 cloud API credentials를 훔쳐 유료 cloud-hosted LLM을 무단으로 호출합니다. 이 접근 권한은 피해자의 계정을 중계하는 reverse proxies를 통해 재판매되는 경우가 많습니다. 예를 들어 "oai-reverse-proxy" deployments가 있습니다. 그 결과 금전적 손실, 정책을 벗어난 모델 오용, 피해자 tenant로의 귀속이 발생할 수 있습니다.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

TTPs:
- 감염된 개발자 컴퓨터나 browsers에서 tokens를 수집하고, CI/CD secrets를 훔치거나, 유출된 cookies를 구매합니다.<sup>[[5]](#references)</sup>
- 실제 provider로 requests를 전달하는 reverse proxy를 구축해 upstream key를 숨기고 여러 고객의 요청을 다중화합니다.<sup>[[5]](#references)</sup><sup>[[7]](#references)</sup>
- enterprise guardrails와 rate limits를 우회하기 위해 direct base-model endpoints를 악용합니다.<sup>[[4]](#references)</sup>

**호스트 내 API-key 재사용:** 호스트가 침해된 후 implant는 피해자 호스트에서 직접 모델 API requests를 보내고 C2를 통해 응답을 전달할 수 있습니다. 이때 cloud API key를 내보내거나 로컬 AI CLI를 실행할 필요가 없습니다. 관찰된 handler에서는 C2가 제공한 key가 우선 사용되며, 해당 key가 없을 때만 implant가 자체 process environment에서 `OPENAI_API_KEY`를 읽습니다. 따라서 피해자의 계정을 사용하려면 해당 process에서 확인할 수 있는 유효한 key와 model API에 대한 접근 권한이 필요합니다. 운영자의 prompt는 Chat Completions API로 전송되며 모델 출력과 token 사용량은 C2를 통해 반환됩니다. 이를 이용하면 개발자의 AI 도구를 실행하지 않고도 피해자가 구매한 모델 접근 권한을 사용할 수 있습니다. 이는 [로컬 AI CLI 또는 MCP 설정 악용](../generic-methodologies-and-resources/phishing-methodology/ai-agent-abuse-local-ai-cli-tools-and-mcp.md)과는 다릅니다.<sup>[[14]](#references)</sup>

완화策:
- tokens를 device fingerprint, IP ranges, client attestation에 연결하고, 만료 시간을 짧게 설정하며 MFA로 갱신을 강제합니다.
- keys의 권한 범위를 최소화하고(도구 접근 금지, 가능한 경우 read-only), 이상 징후가 있으면 교체합니다.
- safety filters, 경로별 quotas, tenant 격리를 적용하는 policy gateway 뒤에서 모든 트래픽을 서버 측에서 종료합니다.
- 비정상적인 사용 패턴(갑작스러운 지출 급증, 이례적인 지역, UA strings)을 모니터링하고 의심스러운 sessions를 자동으로 취소합니다.
- 수명이 긴 static API keys 대신 IdP에서 발급한 mTLS 또는 signed JWTs를 사용합니다.

## 자체 호스팅 LLM inference 보안 강화

기밀 데이터를 처리하기 위해 로컬 LLM 서버를 운영하면 cloud-hosted APIs와는 다른 공격 표면이 생깁니다. inference/debug endpoints에서 prompts가 유출될 수 있고, serving stack에는 대개 reverse proxy가 노출되며, GPU device nodes를 통해 광범위한 `ioctl()` 표면에 접근할 수 있습니다. on-prem inference 서비스를 평가하거나 배포한다면 최소한 다음 사항을 검토하세요.<sup>[[8]](#references)</sup>

### debug 및 monitoring endpoints를 통한 prompt 유출

inference API를 **여러 사용자가 이용하는 민감한 서비스**로 취급하세요. debug 또는 monitoring routes에서 prompt 내용, slot state, 모델 metadata, 내부 queue 정보를 노출할 수 있습니다. `llama.cpp`의 `/slots` endpoint는 특히 민감합니다. slot별 state를 노출하며 slot 검사/관리에만 사용하도록 되어 있기 때문입니다.<sup>[[8]](#references)</sup>

노출된 model runners 및 관련 AI services의 black-box fingerprinting과 테스트는 [노출된 자체 호스팅 AI 서비스](AI-Exposed-Self-Hosted-AI-Services.md)를 확인하세요.

- inference server 앞에 reverse proxy를 두고 **기본적으로 모두 거부**합니다.
- 클라이언트/UI에 필요한 정확한 HTTP method + path 조합만 allowlist에 추가합니다.
- 가능한 경우 backend 자체에서 introspection endpoints를 비활성화합니다. 예를 들어 `llama-server --no-slots`를 사용합니다.<sup>[[9]](#references)</sup>
- reverse proxy를 `127.0.0.1`에 bind하고 LAN에 공개하는 대신 SSH local port forwarding 같은 인증된 transport를 통해 노출합니다.

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

### 네트워크와 UNIX 소켓이 없는 Rootless 컨테이너

추론 데몬이 UNIX 소켓에서 수신 대기하는 기능을 지원한다면, TCP 대신 이를 사용하고 컨테이너를 **네트워크 스택 없이** 실행하세요:<sup>[[8]](#references)</sup>

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

이점:
- `--network none`은 인바운드/아웃바운드 TCP/IP 노출을 제거하고, rootless containers에 필요한 user-mode helper를 사용하지 않도록 합니다.
- UNIX socket을 사용하면 socket 경로에 POSIX 권한/ACL을 적용해 첫 번째 접근 제어 계층으로 활용할 수 있습니다.
- `--userns=keep-id`와 rootless Podman은 컨테이너 breakout의 영향을 줄입니다. 컨테이너의 root는 호스트의 root가 아니기 때문입니다.
- 읽기 전용 모델 마운트는 컨테이너 내부에서 모델이 변조될 가능성을 줄입니다.

영구 배포에서는 동일한 제한을 Podman Quadlet unit으로 설정할 수 있습니다. Container Device Interface를 통해 GPU 접근을 위임하는 경우, 모든 accelerator node를 노출하는 대신 CDI device specification의 범위를 가능한 한 좁게 유지하세요.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>

### GPU device-node 최소화

GPU 기반 추론에서 `/dev/nvidia*` 파일은 높은 가치의 로컬 공격 표면입니다. 대규모 드라이버 `ioctl()` handler와 잠재적으로 공유되는 GPU 메모리 관리 경로에 접근할 수 있기 때문입니다.<sup>[[8]](#references)</sup>

- `/dev/nvidia*`를 world writable 상태로 두지 마세요.
- `NVreg_DeviceFileUID/GID/Mode`, udev 규칙, ACL을 사용해 `nvidia`, `nvidiactl`, `nvidia-uvm`을 제한하고, 매핑된 컨테이너 UID만 해당 파일을 열 수 있도록 하세요.
- 헤드리스 추론 호스트에서는 `nvidia_drm`, `nvidia_modeset`, `nvidia_peermem` 같은 불필요한 모듈을 블랙리스트에 추가하세요.
- 추론 시작 중 runtime이 필요에 따라 `modprobe`를 실행하게 두는 대신, 필요한 모듈만 부팅 시 미리 로드하세요.

예시:

```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```

중요한 검토 항목 중 하나는 **`/dev/nvidia-uvm`**입니다. 워크로드에서 `cudaMallocManaged()`를 명시적으로 사용하지 않더라도 최신 CUDA 런타임에는 `nvidia-uvm`이 필요할 수 있습니다. 이 장치는 공유되며 GPU 가상 메모리 관리를 처리하므로 테넌트 간 데이터 노출 표면으로 간주하세요. 추론 백엔드가 지원한다면 Vulkan 백엔드를 사용하는 것도 고려할 만한 절충안입니다. 컨테이너에 `nvidia-uvm`을 전혀 노출하지 않을 수 있기 때문입니다.<sup>[[8]](#references)</sup>

### 추론 워커를 위한 LSM 격리

추론 프로세스를 심층 방어하기 위해 AppArmor/SELinux/seccomp를 사용해야 합니다:<sup>[[8]](#references)</sup>

- 실제로 필요한 공유 라이브러리, 모델 경로, 소켓 디렉터리, GPU 장치 노드만 허용합니다.
- `sys_admin`, `sys_module`, `sys_rawio`, `sys_ptrace`와 같은 고위험 권한은 명시적으로 거부합니다.
- 모델 디렉터리는 읽기 전용으로 유지하고, 쓰기 가능한 경로는 런타임 소켓/캐시 디렉터리로만 제한합니다.
- 모델 서버나 post-exploitation 페이로드가 예상된 동작 범위를 벗어나려 할 때 유용한 탐지 텔레메트리를 제공하므로 거부 로그를 모니터링합니다.

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

## Phantom Squatting: LLM이 환각으로 만들어낸 도메인을 이용한 AI 공급망 공격 벡터

Phantom squatting은 **slopsquatting의 도메인/URL 버전**입니다. 존재하지 않는 패키지 이름을 환각으로 만들어내는 대신, LLM은 실제 브랜드의 **포털, API, webhook, 결제, SSO, 다운로드 또는 지원 도메인**으로 그럴듯한 주소를 환각으로 만들어내고, 공격자는 사람이나 에이전트가 사용하기 전에 해당 네임스페이스를 등록합니다.<sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

많은 AI 지원 워크플로에서 모델의 출력이 **신뢰할 수 있는 종속성**으로 취급되므로 이는 중요합니다.
- 개발자는 제안된 엔드포인트를 코드나 CI/CD 통합에 붙여 넣습니다.
- AI 에이전트는 문서, 스키마, APK, ZIP 또는 webhook 대상에 자동으로 접근합니다.
- 생성된 런북이나 문서에는 가짜 URL이 권위 있는 주소인 것처럼 포함될 수 있습니다.

### 공격 워크플로

1. **환각 표면 탐색**: `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` 또는 `mobile app` 포털 등 현실적인 워크플로에 관한 브랜드별 질문을 합니다.<sup>[[12]](#references)</sup>
2. **후보 정규화**: 생성된 URL을 확인하고, NXDOMAIN 응답은 등록 가능한 상위 도메인으로 축약한 다음, 프롬프트군별 중복을 제거합니다. 프롬프트 말뭉치의 다양성을 유지하려면 **Jaccard 유사도**를 사용해 거의 중복되는 항목을 제거할 수 있습니다.
3. **예측 가능한 환각 우선 처리**:
   - **열적 환각 지속성(Thermal Hallucination Persistence, THP)**: 동일한 가짜 도메인이 낮은 온도인 `T=0.1`을 포함해 여러 온도 설정에서 나타납니다.
   - **모델 간 합의**: 여러 LLM 계열이 동일한 가짜 도메인을 생성합니다.
4. 상위 도메인을 **등록하고 무기화**한 다음, 피싱, 가짜 APK/ZIP 다운로드, 자격 증명 수집기, 악성 문서 또는 비밀 정보/webhook 페이로드를 수집하는 API 엔드포인트를 호스팅합니다. **순수 도메인 수준의 환각**은 공격자가 네임스페이스 전체를 통제하므로 수익화하기 가장 쉽습니다. 정규화된 상위 도메인이 미등록 상태라면 하위 도메인/경로 수준의 환각도 악용할 수 있습니다.
5. **평판이 없는 기간 악용**: 새로 등록된 도메인은 차단 목록 기록, URL 평판 및 충분한 텔레메트리가 없는 경우가 많아 탐지 시스템이 따라잡기 전까지 통제를 우회할 수 있습니다. 공격자는 크롤러에만 정상 응답을 제공하거나, 리디렉션을 은폐하거나, CAPTCHA를 적용하거나, 페이로드 배포를 지연해 이 기간을 늘릴 수 있습니다.

### 에이전트에 특히 위험한 이유

사람을 노리는 경우 가짜 도메인은 보통 클릭과 추가 행동이 필요합니다. **에이전트 기반 워크플로**에서는 LLM이 **유인책**이자 **실행자**가 될 수 있습니다. 에이전트는 환각으로 생성된 URL을 받아 접근하고, 응답을 분석한 뒤, 사람의 검토 없이 토큰을 leak하거나, 지시를 실행하거나, 종속성을 다운로드하거나, 오염된 데이터를 CI/CD에 입력할 수 있습니다.<sup>[[12]](#references)</sup>

### 공격자가 사용할 수 있는 실용적인 프롬프트

성공률이 높은 프롬프트는 명시적인 피싱 유인책보다 일반적인 기업 업무처럼 보이는 경우가 많습니다.<sup>[[12]](#references)</sup>
- “`<brand>` 통합을 위한 결제 sandbox URL은 무엇인가요?”
- “`<brand>` 빌드 알림에 사용할 webhook 엔드포인트는 무엇인가요?”
- “`<brand>`의 직원 복리후생 / 결제 / SSO 포털은 어디에 있나요?”
- “`<brand>`의 Android APK 또는 데스크톱 클라이언트를 바로 다운로드할 수 있는 링크를 알려주세요.”

### 방어적 전환

이를 프롬프트 인젝션 문제로만 보지 말고, 선제적인 도메인 모니터링 문제로 다루세요.<sup>[[12]](#references)</sup>
- **브랜드 프롬프트 말뭉치**를 만들고 사용자/에이전트가 의존하는 LLM을 주기적으로 탐색합니다.
- 환각으로 생성된 URL을 저장하고, 온도 설정 및 모델이 달라져도 안정적으로 나타나는 URL을 추적합니다.
- **Adversarial Exploitation Window(AEW)**를 추적합니다. 이는 최초 환각 발생부터 공격자의 도메인 등록까지의 시간입니다. AEW가 양수이면 방어자가 무기화 전에 선제 등록, sinkhole 또는 사전 차단을 할 수 있습니다.
- 상위 도메인의 **NXDOMAIN → 등록 완료** 전환을 모니터링합니다.
- 도메인 등록 시 등록기관, 생성 날짜, 네임서버, 개인정보 보호, 페이지 콘텐츠, 스크린샷, 파킹 페이지 여부 및 브랜드 자산과의 유사도를 조사합니다.
- 에이전트/개발자가 **LLM이 생성한 도메인을 기본적으로 신뢰하지 않도록** 정책 게이트를 추가합니다. 최초 사용 전에 allowlist, 소유권 검증, CT/RDAP 확인 또는 사람의 승인을 요구합니다.

이는 여러 AI 위험 범주에 해당합니다. **AI 공급망 공격**, **안전하지 않은 모델 출력**, 그리고 에이전트가 환각으로 생성된 URL을 자율적으로 사용할 때의 **불량 행위**입니다.

{{#include ../banners/hacktricks-training.md}}

## References

- [1] [OWASP 기계 학습 취약점 Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google SAIF (Secure AI Framework) – 위험](https://saif.google/secure-ai-framework/risks)
- [3] [MITRE ATLAS 위협 매트릭스](https://atlas.mitre.org/)
- [4] [Unit 42 – 코드 어시스턴트 LLM의 위험: 유해한 콘텐츠, 오용 및 기만](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [5] [Sysdig – LLMjacking: 도난당한 cloud 자격 증명을 이용한 새로운 AI 공격](https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/)
- [6] [LLMJacking 공격 개요 – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [7] [oai-reverse-proxy (도난당한 LLM 액세스 재판매)](https://gitgud.io/khanon/oai-reverse-proxy)
- [8] [Synacktiv - 온프레미스 저권한 LLM 서버 배포 심층 분석](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [9] [llama.cpp 서버 README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [10] [Podman quadlet: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [11] [CNCF Container Device Interface (CDI) 사양](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [12] [Unit 42 – Phantom Squatting: AI 환각 도메인을 이용한 소프트웨어 공급망 공격 벡터](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [13] [Socket – Slopsquatting: AI 환각이 새로운 공급망 공격 유형을 촉진하는 방식](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)
- [14] [Cisco Talos – NIK C2: 새로운 AI 기반 명령 및 제어 프레임워크](https://blog.talosintelligence.com/nik-c2-new-ai-enabled-framework/)
