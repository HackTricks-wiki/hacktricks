# AI 위험

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owasp는 AI 시스템에 영향을 줄 수 있는 상위 10가지 machine learning 취약점을 식별했습니다. 이러한 취약점은 data poisoning, model inversion, adversarial attacks 등을 포함한 다양한 보안 문제로 이어질 수 있습니다. 이러한 취약점을 이해하는 것은 안전한 AI 시스템을 구축하는 데 중요합니다.

업데이트된 자세한 상위 10개 machine learning 취약점 목록은 [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/) 프로젝트를 참조하세요.

- **Input Manipulation Attack**: 공격자는 모델이 잘못된 결정을 내리도록 **incoming data**에 작고 종종 보이지 않는 변경을 추가합니다.\
*예시*: 몇 점의 페인트가 묻은 stop‑sign이 self‑driving car를 속여 speed‑limit sign으로 "인식"하게 함.

- **Data Poisoning Attack**: **training set**을 의도적으로 오염시켜 모델에 해로운 규칙을 학습시킵니다.\
*예시*: 악성코드 바이너리가 antivirus training corpus에서 "benign"으로 잘못 라벨링되어 유사한 malware가 이후 탐지를 피할 수 있게 함.

- **Model Inversion Attack**: 출력 값을 탐지해 공격자가 원래 입력의 민감한 특징을 재구성하는 **reverse model**을 만듭니다.\
*예시*: cancer‑detection 모델의 예측으로부터 환자의 MRI 이미지를 재생성함.

- **Membership Inference Attack**: 공격자는 자신이 관심 있는 **specific record**가 training에 사용되었는지 confidence 차이를 통해 판단합니다.\
*예시*: 특정인의 은행 거래가 fraud‑detection 모델의 training 데이터에 포함되었는지 확인함.

- **Model Theft**: 반복적인 쿼리로 공격자는 결정 경계를 학습하고 **clone the model's behavior**(및 IP)를 획득합니다.\
*예시*: ML‑as‑a‑Service API에서 충분한 Q&A 쌍을 수집해 거의 동등한 로컬 모델을 구축함.

- **AI Supply‑Chain Attack**: ML pipeline의 어떤 구성요소(data, libraries, pre‑trained weights, CI/CD)를 손상시켜 downstream 모델을 오염시킵니다.\
*예시*: model‑hub의 poisoned dependency가 backdoored sentiment‑analysis model을 여러 앱에 설치함.

- **Transfer Learning Attack**: 악의적 로직이 **pre‑trained model**에 심어져 피해자의 작업으로 fine‑tuning해도 남아 있습니다.\
*예시*: hidden trigger가 있는 vision backbone이 medical imaging에 적응된 후에도 라벨을 뒤집음.

- **Model Skewing**: 미묘하게 편향되거나 잘못 라벨된 데이터가 **shifts the model's outputs**하여 공격자의 의제를 돕습니다.\
*예시*: "clean" spam 이메일을 ham으로 라벨링해 spam filter가 유사한 미래 이메일을 통과시키게 함.

- **Output Integrity Attack**: 공격자는 모델 자체가 아니라 전송 중에 **alters model predictions**, downstream 시스템을 속입니다.\
*예시*: malware classifier의 "malicious" 판정을 file‑quarantine 단계에 도달하기 전에 "benign"으로 바꿈.

- **Model Poisoning** --- 쓰기 권한을 얻은 후 종종 **model parameters** 자체에 직접적이고 표적화된 변경을 가해 동작을 바꿉니다.\
*예시*: production의 fraud‑detection 모델의 가중치를 조정해 특정 카드의 거래가 항상 승인되도록 함.


## Google SAIF Risks

Google의 [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks)는 AI 시스템과 관련된 다양한 위험을 정리합니다:

- **Data Poisoning**: 악의적 행위자가 training/tuning 데이터를 변경하거나 주입하여 정확도를 저하시켜 backdoors를 심거나 결과를 왜곡하여 모델 무결성을 손상시킵니다.

- **Unauthorized Training Data**: 저작권이 있거나 민감하거나 허가되지 않은 데이터셋을 수집하면 모델이 사용해서는 안 되는 데이터를 학습하게 되어 법적·윤리적·성능 상의 위험을 초래합니다.

- **Model Source Tampering**: 공급망 또는 내부자의 모델 코드, dependencies, 또는 weights에 대한 조작은 retraining 후에도 남는 숨겨진 로직을 심을 수 있습니다.

- **Excessive Data Handling**: 약한 데이터 보관 및 거버넌스 통제로 시스템이 필요한 것보다 더 많은 개인 데이터를 저장·처리하게 되어 노출 및 규정 준수 위험을 높입니다.

- **Model Exfiltration**: 공격자가 모델 파일/weights를 탈취하면 지적재산권 손실과 모방 서비스 또는 후속 공격을 가능하게 합니다.

- **Model Deployment Tampering**: 공격자가 모델 아티팩트나 serving 인프라를 수정하여 실행 중인 모델이 검증된 버전과 달라져 동작이 바뀔 수 있습니다.

- **Denial of ML Service**: API를 폭주시키거나 “sponge” 입력을 보내 compute/energy를 고갈시켜 모델을 오프라인으로 만드는 DoS 유사 공격을 수행할 수 있습니다.

- **Model Reverse Engineering**: 많은 수의 input‑output 쌍을 수집해 공격자가 모델을 복제하거나 distill하여 모방 제품 및 맞춤형 adversarial 공격을 조장할 수 있습니다.

- **Insecure Integrated Component**: 취약한 plugins, agents, 또는 upstream 서비스가 공격자에게 코드 주입이나 권한 상승을 허용합니다.

- **Prompt Injection**: 직접적이거나 간접적으로 모델에 system intent를 무시하도록 지시를 밀어넣는 prompts를 제작합니다.

- **Model Evasion**: 정교하게 설계된 입력이 모델을 오분류시키거나 hallucinate하게 하거나 금지된 내용을 출력하게 하여 안전성과 신뢰를 저하시킵니다.

- **Sensitive Data Disclosure**: 모델이 training 데이터나 사용자 컨텍스트에서 개인 또는 기밀 정보를 노출하여 프라이버시 및 규정 위반을 초래합니다.

- **Inferred Sensitive Data**: 모델이 제공되지 않은 개인 속성을 추론하여 새로운 프라이버시 피해를 만들어냅니다.

- **Insecure Model Output**: 정제되지 않은 응답이 유해한 코드, 허위정보, 또는 부적절한 콘텐츠를 사용자나 downstream 시스템에 전달합니다.

- **Rogue Actions**: 자율 통합된 agents가 적절한 사용자 감독 없이 의도치 않은 실제 작업(file writes, API calls, purchases 등)을 실행합니다.

## Mitre AI ATLAS Matrix

The [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS)는 AI 시스템과 관련된 위험을 이해하고 완화하기 위한 포괄적인 프레임워크를 제공합니다. 이 매트릭스는 공격자가 AI 모델에 사용할 수 있는 다양한 공격 기법과 전술을 분류하고, 또한 AI 시스템을 사용해 다양한 공격을 수행하는 방법을 다룹니다.

## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

공격자는 활성 세션 tokens 또는 cloud API credentials를 탈취하고 무단으로 유료 cloud‑hosted LLM을 호출합니다. 접근은 종종 피해자의 계정을 전면에 둔 reverse proxies(예: "oai-reverse-proxy" 배포)를 통해 재판매됩니다. 결과로는 금전적 손실, 정책 외 모델 오용, 피해 테넌트에 대한 귀속 문제가 발생할 수 있습니다.

TTPs:
- 감염된 developer 머신이나 브라우저에서 tokens를 수집; CI/CD secrets를 훔치거나 leaked cookies를 구매합니다.
- genuine provider로 요청을 전달하고 upstream key를 숨기며 다수 고객을 multiplex하는 reverse proxy를 세웁니다.
- enterprise guardrails와 rate limits를 우회하기 위해 직접 base‑model endpoints를 남용합니다.

Mitigations:
- tokens를 device fingerprint, IP ranges, 및 client attestation에 바인딩; 짧은 만료 시간과 MFA로 갱신을 강제합니다.
- 키의 권한을 최소화(도구 접근 금지, 가능한 경우 read‑only); 이상 징후 시 회전합니다.
- per‑route quotas와 tenant isolation을 시행하는 정책 게이트웨이 뒤에서 서버 측에서 모든 트래픽을 종료하고 안전 필터를 적용합니다.
- 비정상적 사용 패턴(급격한 비용 증가, 이례적 지역, UA 문자열)을 모니터링하고 의심스러운 세션을 자동으로 폐기합니다.
- 장기 정적 API 키 대신 IdP에서 발급한 mTLS 또는 signed JWTs를 우선 사용합니다.

## Self-hosted LLM inference hardening

confidential data를 처리하기 위해 로컬 LLM server를 운영하면 cloud‑hosted APIs와는 다른 공격 표면이 생깁니다: inference/debug endpoints가 prompts를 leak할 수 있고, serving stack은 보통 reverse proxy를 노출하며 GPU device nodes는 방대한 ioctl() 면을 제공합니다. on‑prem inference service를 평가하거나 배포하는 경우 최소한 다음 사항을 검토하세요.

### Prompt leakage via debug and monitoring endpoints

inference API를 **multi-user sensitive service**로 취급하세요. Debug 또는 monitoring 경로는 prompt 내용, slot 상태, model metadata, 또는 내부 큐 정보를 노출할 수 있습니다. `llama.cpp`에서는 `/slots` endpoint가 특히 민감한데, 이는 슬롯별 상태를 노출하며 슬롯 검사/관리를 위해서만 의도되었습니다.

- Put a reverse proxy in front of the inference server and **deny by default**.
- Only allowlist the exact HTTP method + path combinations that are needed by the client/UI.
- Disable introspection endpoints in the backend itself whenever possible, for example `llama-server --no-slots`.
- Bind the reverse proxy to `127.0.0.1` and expose it through an authenticated transport such as SSH local port forwarding instead of publishing it on the LAN.

Example allowlist with nginx:
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
### no network와 UNIX sockets를 사용하는 Rootless containers

만약 inference daemon이 UNIX socket에서 listen을 지원한다면, TCP보다 UNIX socket을 우선 사용하고 컨테이너를 **no network stack** 상태로 실행하세요:
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
- `--network none`은 인바운드/아웃바운드 TCP/IP 노출을 제거하고 rootless 컨테이너가 그렇지 않으면 필요로 하는 user-mode helpers를 회피합니다.
- UNIX socket을 사용하면 첫 번째 접근 제어 계층으로서 소켓 경로에 POSIX 권한/ACLs를 적용할 수 있습니다.
- `--userns=keep-id`와 rootless Podman은 컨테이너 루트가 호스트 루트가 아니므로 container breakout의 영향을 줄입니다.
- 읽기 전용 모델 마운트는 컨테이너 내부에서 모델 변조가 일어날 가능성을 줄입니다.

### GPU 디바이스 노드 최소화

GPU 기반 inference의 경우, `/dev/nvidia*` 파일은 큰 드라이버 `ioctl()` 핸들러와 잠재적으로 공유되는 GPU 메모리 관리 경로를 노출하므로 가치가 높은 로컬 공격 표면입니다.

- Do not leave `/dev/nvidia*` world writable.
- Restrict `nvidia`, `nvidiactl`, and `nvidia-uvm` with `NVreg_DeviceFileUID/GID/Mode`, udev rules, and ACLs so only the mapped container UID can open them.
- Blacklist unnecessary modules such as `nvidia_drm`, `nvidia_modeset`, and `nvidia_peermem` on headless inference hosts.
- Preload only required modules at boot instead of letting the runtime opportunistically `modprobe` them during inference startup.

예시:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
One important review point is **`/dev/nvidia-uvm`**. Even if the workload does not explicitly use `cudaMallocManaged()`, recent CUDA runtimes may still require `nvidia-uvm`. Because this device is shared and handles GPU virtual memory management, treat it as a cross-tenant data-exposure surface. If the inference backend supports it, a Vulkan backend can be an interesting trade-off because it may avoid exposing `nvidia-uvm` to the container at all.

### 추론 워커를 위한 LSM 격리

AppArmor/SELinux/seccomp는 추론 프로세스 주변에 방어층(defense in depth)으로 사용되어야 합니다:

- 실제로 필요한 공유 라이브러리, 모델 경로, 소켓 디렉터리 및 GPU 디바이스 노드만 허용하세요.
- 명시적으로 `sys_admin`, `sys_module`, `sys_rawio`, `sys_ptrace` 같은 고위험 capabilities를 거부하세요.
- 모델 디렉터리는 읽기 전용으로 유지하고, 쓰기 가능한 경로는 런타임 소켓/캐시 디렉터리로만 한정하세요.
- 거부 로그(denial logs)를 모니터링하세요. 모델 서버나 post-exploitation 페이로드가 예상 동작을 벗어나려 할 때 유용한 탐지 텔레메트리를 제공합니다.

Example AppArmor rules for a GPU-backed worker:
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
## 참고자료
- [Unit 42 – Code Assistant LLMs의 위험: 유해 콘텐츠, 오용 및 기만](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [LLMJacking 개요 – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [oai-reverse-proxy (도난당한 LLM 접근권 재판매)](https://gitgud.io/khanon/oai-reverse-proxy)
- [Synacktiv - 온프레미스 저권한 LLM 서버 배포 심층 분석](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [CNCF Container Device Interface (CDI) 명세](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)

{{#include ../banners/hacktricks-training.md}}
