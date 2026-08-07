# AI Risks

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owasp는 AI 시스템에 영향을 미칠 수 있는 상위 10개의 machine learning vulnerabilities를 식별했습니다. 이러한 취약점은 data poisoning, model inversion, adversarial attacks를 비롯한 다양한 보안 문제로 이어질 수 있습니다. 안전한 AI 시스템을 구축하려면 이러한 취약점을 이해하는 것이 중요합니다.

상위 10개의 machine learning vulnerabilities에 대한 최신의 자세한 목록은 [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/) 프로젝트를 참조하세요.<sup>[[1]](#references)</sup>

- **Input Manipulation Attack**: 공격자는 **incoming data**에 아주 작고 대개 눈에 보이지 않는 변경을 추가하여 모델이 잘못된 결정을 내리도록 합니다.\
*Example*: 정지 표지판에 소량의 페인트를 뿌리면 self-driving car가 이를 속도 제한 표지판으로 "인식"할 수 있습니다.

- **Data Poisoning Attack**: **training set**을 의도적으로 악성 샘플로 오염시켜 모델이 유해한 규칙을 학습하도록 합니다.\
*Example*: antivirus training corpus에서 malware binaries를 "benign"으로 잘못 라벨링하여 이후 유사한 malware가 탐지되지 않도록 합니다.

- **Model Inversion Attack**: 출력을 탐색하여 공격자는 원본 입력의 민감한 특징을 재구성하는 **reverse model**을 구축합니다.\
*Example*: cancer-detection model의 예측 결과로 환자의 MRI image를 재생성합니다.

- **Membership Inference Attack**: 공격자는 confidence 차이를 확인하여 **specific record**가 training에 사용되었는지 검사합니다.\
*Example*: 특정인의 bank transaction이 fraud-detection model의 training data에 포함되어 있었는지 확인합니다.

- **Model Theft**: 반복적인 querying을 통해 공격자는 decision boundaries와 **clone the model's behavior**(및 IP)를 학습할 수 있습니다.\
*Example*: ML-as-a-Service API에서 충분한 Q&A pairs를 수집하여 거의 동일한 동작을 하는 local model을 구축합니다.

- **AI Supply‑Chain Attack**: **ML pipeline**의 구성 요소(data, libraries, pre-trained weights, CI/CD 등)를 침해하여 downstream models를 오염시킵니다.\
*Example*: model-hub의 poisoned dependency가 여러 앱에 backdoored sentiment-analysis model을 설치합니다.

- **Transfer Learning Attack**: **pre-trained model**에 악성 로직을 심고, victim의 task에 맞게 fine-tuning한 후에도 해당 로직이 유지되도록 합니다.\
*Example*: 숨겨진 trigger가 있는 vision backbone이 medical imaging용으로 조정된 후에도 label을 뒤집습니다.

- **Model Skewing**: 미묘하게 편향되었거나 잘못 라벨링된 data가 **model's outputs**를 공격자의 목적에 유리하도록 변경합니다.\
*Example*: "clean" spam emails를 ham으로 라벨링하여 주입하면 spam filter가 이후 유사한 이메일을 통과시킵니다.

- **Output Integrity Attack**: 공격자는 model 자체가 아니라 **model predictions in transit**를 변경하여 downstream systems를 속입니다.\
*Example*: file-quarantine stage가 확인하기 전에 malware classifier의 "malicious" 판정을 "benign"으로 뒤집습니다.

- **Model Poisoning** --- 직접적이고 표적화된 방식으로 **model parameters** 자체를 변경하며, write access를 획득한 후 동작을 변경하는 경우가 많습니다.\
*Example*: production 환경의 fraud-detection model weights를 조정하여 특정 카드의 transaction이 항상 승인되도록 합니다.


## Google SAIF Risks

Google의 [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks)는 AI 시스템과 관련된 다양한 risks를 설명합니다:<sup>[[2]](#references)</sup>

- **Data Poisoning**: 악성 행위자가 training/tuning data를 변경하거나 주입하여 정확도를 저하시키고, backdoors를 심거나, 결과를 왜곡합니다. 이로 인해 전체 data-lifecycle에서 model integrity가 약화됩니다.

- **Unauthorized Training Data**: 저작권이 있거나 민감하거나 사용 허가를 받지 않은 datasets를 수집하면, 모델이 사용이 허용되지 않은 data로부터 학습하므로 법적, 윤리적, 성능상의 책임이 발생합니다.

- **Model Source Tampering**: training 전이나 training 중에 model code, dependencies 또는 weights를 supply-chain이나 내부자가 조작하면, retraining 후에도 유지되는 숨겨진 로직이 삽입될 수 있습니다.

- **Excessive Data Handling**: 취약한 data-retention 및 governance controls로 인해 시스템이 필요 이상으로 많은 personal data를 저장하거나 처리하게 되어, 노출 및 compliance risk가 증가합니다.

- **Model Exfiltration**: 공격자가 model files/weights를 탈취하여 intellectual property 손실을 일으키고, copy-cat services 또는 후속 attacks를 가능하게 합니다.

- **Model Deployment Tampering**: 공격자가 model artifacts 또는 serving infrastructure를 수정하여 실행 중인 모델이 검증된 version과 달라지도록 하고, 잠재적으로 동작을 변경합니다.

- **Denial of ML Service**: APIs를 flooding하거나 “sponge” inputs를 전송하여 compute/energy를 고갈시키고 모델을 offline 상태로 만들며, 이는 전통적인 DoS attacks와 유사합니다.

- **Model Reverse Engineering**: 대량의 input-output pairs를 수집하여 공격자가 모델을 clone하거나 distil하고, 이를 통해 imitation products 및 맞춤형 adversarial attacks를 만들어낼 수 있습니다.

- **Insecure Integrated Component**: 취약한 plugins, agents 또는 upstream services를 통해 공격자가 AI pipeline 내부에 code를 주입하거나 privileges를 상승시킬 수 있습니다.

- **Prompt Injection**: 직접 또는 간접적으로 prompts를 조작하여 system intent를 무시하는 instructions를 삽입하고, 모델이 의도하지 않은 commands를 실행하도록 합니다.

- **Model Evasion**: 정교하게 설계된 inputs가 모델의 mis-classify, hallucinate 또는 금지된 content 출력을 유발하여 safety와 trust를 약화시킵니다.

- **Sensitive Data Disclosure**: 모델이 training data 또는 user context에서 private 또는 confidential information을 노출하여 privacy 및 regulations를 위반합니다.

- **Inferred Sensitive Data**: 모델이 제공되지 않은 personal attributes를 추론하여, inference를 통한 새로운 privacy harms를 발생시킵니다.

- **Insecure Model Output**: Sanitization되지 않은 responses가 harmful code, misinformation 또는 inappropriate content를 users나 downstream systems에 전달합니다.

- **Rogue Actions**: 자율적으로 통합된 agents가 적절한 user oversight 없이 의도하지 않은 real-world operations(file writes, API calls, purchases 등)을 실행합니다.

## Mitre AI ATLAS Matrix

[MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS)는 AI 시스템과 관련된 risks를 이해하고 완화하기 위한 종합적인 framework를 제공합니다. 이 framework는 adversaries가 AI models를 대상으로 사용할 수 있는 다양한 attack techniques와 tactics를 분류하며, AI systems를 사용하여 다양한 attacks를 수행하는 방법도 다룹니다.<sup>[[3]](#references)</sup>

## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

공격자는 active session tokens 또는 cloud API credentials를 탈취하여 권한 없이 유료 cloud-hosted LLMs를 호출합니다. 이러한 access는 피해자의 account를 앞단에서 중계하는 reverse proxies를 통해 재판매되는 경우가 많습니다. 예를 들어 "oai-reverse-proxy" deployments가 있습니다. 그 결과 financial loss, policy를 벗어난 model misuse, 그리고 victim tenant에 대한 attribution이 발생할 수 있습니다.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

TTPs:
- 감염된 developer machines 또는 browsers에서 tokens를 수집하고, CI/CD secrets를 탈취하며, leaked cookies를 구매합니다.<sup>[[5]](#references)</sup>
- genuine provider로 requests를 전달하는 reverse proxy를 구축하여 upstream key를 숨기고 여러 customers를 multiplexing합니다.<sup>[[5]](#references)[[7]](#references)</sup>
- direct base-model endpoints를 악용하여 enterprise guardrails 및 rate limits를 우회합니다.<sup>[[4]](#references)</sup>

Mitigations:
- tokens를 device fingerprint, IP ranges 및 client attestation에 binding하고, 짧은 expiration을 적용하며 MFA로 refresh합니다.
- keys의 scope를 최소화하고(도구 access를 허용하지 않으며, 가능한 경우 read-only로 설정), anomaly 발생 시 rotate합니다.
- safety filters, route별 quotas 및 tenant isolation을 적용하는 policy gateway 뒤에서 모든 traffic을 server-side로 종료합니다.
- 비정상적인 usage patterns(sudden spend spikes, atypical regions, UA strings 등)을 모니터링하고 의심스러운 sessions를 자동으로 revoke합니다.
- 수명이 긴 static API keys 대신 IdP에서 발급한 mTLS 또는 signed JWTs를 우선 사용합니다.

## Self-hosted LLM inference hardening

confidential data를 처리하기 위해 local LLM server를 실행하면 cloud-hosted APIs와는 다른 attack surface가 발생합니다. inference/debug endpoints에서 prompts가 leak될 수 있고, serving stack은 일반적으로 reverse proxy를 노출하며, GPU device nodes는 광범위한 `ioctl()` surfaces에 access를 제공합니다. on-prem inference service를 평가하거나 배포하는 경우 최소한 다음 항목을 검토하세요.<sup>[[8]](#references)</sup>

### Prompt leakage via debug and monitoring endpoints

inference API를 **multi-user sensitive service**로 취급하세요. Debug 또는 monitoring routes는 prompt contents, slot state, model metadata 또는 internal queue information을 노출할 수 있습니다. `llama.cpp`에서 `/slots` endpoint는 slot별 state를 노출하며 slot inspection/management 용도로만 사용되어야 하므로 특히 민감합니다.<sup>[[8]](#references)</sup>

- inference server 앞에 reverse proxy를 배치하고 **deny by default**를 적용합니다.
- client/UI에 필요한 정확한 HTTP method + path combinations만 allowlist에 추가합니다.
- 가능한 경우 backend 자체에서 introspection endpoints를 비활성화합니다. 예: `llama-server --no-slots`.<sup>[[9]](#references)</sup>
- reverse proxy를 `127.0.0.1`에 binding하고, LAN에 publish하는 대신 SSH local port forwarding과 같은 authenticated transport를 통해 노출합니다.

nginx를 사용한 allowlist 예시:
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
### 네트워크와 UNIX 소켓이 없는 Rootless containers

inference daemon이 UNIX socket에서 수신 대기를 지원한다면 TCP보다 이를 우선하고, **네트워크 스택 없이** container를 실행하세요:<sup>[[8]](#references)</sup>
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
Benefits:
- `--network none`은 인바운드/아웃바운드 TCP/IP 노출을 제거하고, rootless containers에 필요할 수 있는 user-mode helpers를 사용하지 않도록 합니다.
- UNIX socket을 사용하면 socket path에 POSIX permissions/ACLs를 적용하여 첫 번째 access-control layer로 사용할 수 있습니다.
- `--userns=keep-id`와 rootless Podman은 container breakout의 영향을 줄입니다. container root는 host root가 아니기 때문입니다.
- Read-only model mounts는 container 내부에서 model tampering이 발생할 가능성을 줄입니다.

### GPU device-node 최소화

GPU-backed inference의 경우 `/dev/nvidia*` files는 대규모 driver `ioctl()` handlers와 잠재적으로 shared GPU memory-management paths를 노출하므로 가치가 높은 local attack surfaces입니다.<sup>[[8]](#references)</sup>

- `/dev/nvidia*`를 world writable 상태로 두지 마세요.
- `NVreg_DeviceFileUID/GID/Mode`, udev rules, ACLs를 사용하여 `nvidia`, `nvidiactl`, `nvidia-uvm`을 제한하고, mapped container UID만 해당 device를 열 수 있도록 하세요.
- Headless inference hosts에서는 `nvidia_drm`, `nvidia_modeset`, `nvidia_peermem`과 같은 불필요한 modules를 blacklist하세요.
- Inference startup 중 runtime이 opportunistically `modprobe`하도록 두지 말고, boot 시 필요한 modules만 preload하세요.

Example:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
중요한 검토 항목 중 하나는 **`/dev/nvidia-uvm`**입니다. workload가 `cudaMallocManaged()`를 명시적으로 사용하지 않더라도, 최신 CUDA runtime은 여전히 `nvidia-uvm`을 요구할 수 있습니다. 이 device는 공유되며 GPU virtual memory management를 처리하므로, cross-tenant data-exposure surface로 간주해야 합니다. inference backend가 이를 지원한다면, Vulkan backend는 container에 `nvidia-uvm`을 전혀 노출하지 않을 수 있다는 점에서 흥미로운 trade-off가 될 수 있습니다.<sup>[[8]](#references)</sup>

### inference worker를 위한 LSM confinement

inference process를 보호하는 defense in depth 수단으로 AppArmor/SELinux/seccomp를 사용해야 합니다:<sup>[[8]](#references)</sup>

- 실제로 필요한 shared library, model path, socket directory 및 GPU device node만 허용합니다.
- `sys_admin`, `sys_module`, `sys_rawio`, `sys_ptrace`와 같은 high-risk capability를 명시적으로 거부합니다.
- model directory를 read-only로 유지하고, writable path의 범위를 runtime socket/cache directory로만 제한합니다.
- denial log를 모니터링합니다. model server 또는 post-exploitation payload가 예상된 동작 범위를 벗어나려고 할 때 유용한 detection telemetry를 제공하기 때문입니다.

GPU-backed worker를 위한 AppArmor rule 예시:
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
## Phantom Squatting: LLM이 환각한 도메인을 이용한 AI 공급망 벡터

Phantom squatting은 **slopsquatting의 도메인/URL 버전**입니다. 존재하지 않는 패키지 이름을 환각하는 대신, LLM이 실제 브랜드에 대한 그럴듯한 **포털, API, webhook, 결제, SSO, 다운로드 또는 지원 도메인**을 환각하고, 사람이 해당 도메인을 사용하기 전에 공격자가 그 네임스페이스를 등록합니다.<sup>[[12]](#references)[[13]](#references)</sup>

이는 많은 AI 지원 workflow에서 모델 출력을 **신뢰된 dependency**로 취급하기 때문에 중요합니다:
- 개발자가 제안된 endpoint를 코드 또는 CI/CD 통합에 붙여 넣습니다.
- AI agent가 문서, schema, APK, ZIP 또는 webhook 대상을 자동으로 가져옵니다.
- 생성된 runbook이나 문서에 가짜 URL이 권위 있는 주소인 것처럼 포함될 수 있습니다.

### Offensive workflow

1. **환각 표면을 탐색합니다**: `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` 또는 `mobile app` 포털과 같은 현실적인 workflow에 대해 브랜드별 질문을 합니다.<sup>[[12]](#references)</sup>
2. **후보를 정규화합니다**: 생성된 URL을 resolve하고, NXDOMAIN 응답을 등록 가능한 상위 domain으로 축약하며, prompt family의 중복을 제거합니다. Prompt corpus는 다양하게 유지해야 합니다. 예를 들어 **Jaccard similarity**를 사용해 유사한 중복 항목을 제거할 수 있습니다.
3. **예측 가능한 환각을 우선 처리합니다**:
- **Thermal Hallucination Persistence (THP)**: 동일한 가짜 domain이 낮은 온도인 `T=0.1`을 포함해 여러 temperature에서 나타납니다.
- **Cross-model consensus**: 여러 LLM family가 동일한 가짜 domain을 생성합니다.
4. 상위 domain을 **등록하고 weaponize**한 다음, phishing, 가짜 APK/ZIP 다운로드, credential harvester, 악성 문서 또는 secret/webhook payload를 수집하는 API endpoint를 호스팅합니다. **순수한 domain-level 환각**은 공격자가 전체 namespace를 제어하므로 수익화하기 가장 쉽습니다. 정규화된 상위 domain이 등록되지 않은 경우에는 subdomain/path 환각도 악용할 수 있습니다.
5. **zero-reputation window를 악용합니다**: 새로 등록된 domain은 blocklist 기록, URL reputation 및 성숙한 telemetry가 없는 경우가 많으므로, 탐지 기능이 따라잡을 때까지 보안 통제를 우회할 수 있습니다. 공격자는 crawler에만 benign response를 제공하거나, redirect cloaking, CAPTCHA gate 또는 지연된 payload staging을 사용해 이 시간을 늘릴 수 있습니다.

### agent에 위험한 이유

사람인 피해자의 경우 가짜 domain은 대개 click과 추가 행동을 필요로 합니다. 그러나 **agentic workflow**에서는 LLM이 **lure**와 **executor** 역할을 모두 수행할 수 있습니다. agent가 환각된 URL을 받고, 이를 fetch하고, 응답을 parse한 다음, human review 없이 token을 leak하거나 instruction을 execute하거나 dependency를 download하거나 오염된 데이터를 CI/CD에 push할 수 있습니다.<sup>[[12]](#references)</sup>

### Practical attacker prompts

효과가 높은 prompt는 대개 명시적인 phishing lure가 아니라 일반적인 enterprise 작업처럼 보입니다:<sup>[[12]](#references)</sup>
- “`<brand>` integration에 사용할 payment sandbox URL은 무엇인가요?”
- “`<brand>` build notification에 사용해야 할 webhook endpoint는 무엇인가요?”
- “`<brand>`의 employee benefits / billing / SSO portal은 어디에 있나요?”
- “`<brand>`의 Android APK 또는 desktop client를 직접 download할 수 있는 주소를 알려주세요.”

### Defensive inversion

이를 단순한 prompt-injection 문제가 아니라 사전 예방적 domain-monitoring 문제로 다루어야 합니다:<sup>[[12]](#references)</sup>
- **brand prompt corpus**를 구축하고, 사용자/agent가 의존하는 LLM을 주기적으로 probe합니다.
- 환각된 URL을 저장하고, temperature/model에 걸쳐 어떤 URL이 안정적으로 나타나는지 추적합니다.
- **Adversarial Exploitation Window (AEW)**를 추적합니다. 이는 최초 환각부터 공격자의 등록까지 걸리는 시간입니다. AEW가 양수이면 방어자가 weaponization 전에 선제 등록, sinkhole 또는 사전 차단을 수행할 수 있습니다.
- 상위 domain의 **NXDOMAIN → registered** 전환을 모니터링합니다.
- 등록되면 registrar, creation date, nameserver, privacy shielding, page content, screenshot, parked-page 상태 및 brand asset 유사성을 triage합니다.
- agent/developer가 **기본적으로 LLM-generated domain을 신뢰하지 않도록** policy gate를 추가합니다. 최초 사용 전에 allowlist, 소유권 검증, CT/RDAP 확인 또는 human approval을 요구해야 합니다.

이는 여러 AI risk category에 동시에 해당합니다: **AI supply-chain attack**, **insecure model output**, 그리고 agent가 환각된 URL을 자율적으로 소비할 때 발생하는 **rogue actions**입니다.

## References

- [1] [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google SAIF (Secure AI Framework) – Risks](https://saif.google/secure-ai-framework/risks)
- [3] [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS)
- [4] [Unit 42 – Code Assistant LLM의 위험: 유해 콘텐츠, 오용 및 기만](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [5] [Sysdig – LLMjacking: 새로운 AI 공격에 사용된 탈취된 Cloud Credential](https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/)
- [6] [LLMJacking scheme 개요 – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [7] [oai-reverse-proxy (탈취한 LLM access 재판매)](https://gitgud.io/khanon/oai-reverse-proxy)
- [8] [Synacktiv - on-premise 저권한 LLM server 배포 심층 분석](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [9] [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [10] [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [11] [CNCF Container Device Interface (CDI) specification](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [12] [Unit 42 – Phantom Squatting: Software Supply Chain Vector로서의 AI-Hallucinated Domain](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [13] [Socket – Slopsquatting: AI 환각이 새로운 유형의 Supply Chain Attack을 부추기는 방식](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)

{{#include ../banners/hacktricks-training.md}}
