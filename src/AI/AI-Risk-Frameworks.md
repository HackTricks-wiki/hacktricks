# AI Risks

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owasp는 AI 시스템에 영향을 미칠 수 있는 상위 10개의 machine learning 취약점을 식별했습니다. 이러한 취약점은 data poisoning, model inversion, adversarial attacks를 비롯한 다양한 보안 문제로 이어질 수 있습니다. 안전한 AI 시스템을 구축하려면 이러한 취약점을 이해하는 것이 중요합니다.

상위 10개의 machine learning 취약점에 대한 최신의 상세 목록은 [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/) 프로젝트를 참조하세요.

- **Input Manipulation Attack**: 공격자는 **incoming data**에 아주 작고 흔히 눈에 보이지 않는 변경을 추가하여 모델이 잘못된 결정을 내리도록 합니다.\
*Example*: 정지 표지판에 소량의 페인트를 뿌리면 자율주행 자동차가 이를 제한 속도 표지판으로 "인식"하도록 속일 수 있습니다.

- **Data Poisoning Attack**: **training set**을 의도적으로 악성 샘플로 오염시켜 모델이 유해한 규칙을 학습하도록 합니다.\
*Example*: antivirus training corpus에서 malware 바이너리를 "benign"으로 잘못 라벨링하면, 이후 유사한 malware가 탐지되지 않고 통과할 수 있습니다.

- **Model Inversion Attack**: 출력값을 조사하여 공격자는 원래 입력의 민감한 특징을 재구성하는 **reverse model**을 만들 수 있습니다.\
*Example*: cancer-detection model의 예측값을 이용해 환자의 MRI 이미지를 재생성할 수 있습니다.

- **Membership Inference Attack**: 공격자는 confidence 차이를 확인하여 **specific record**가 training 중 사용되었는지 테스트합니다.\
*Example*: 특정인의 bank transaction이 fraud-detection model의 training data에 포함되어 있는지 확인할 수 있습니다.

- **Model Theft**: 반복적인 querying을 통해 공격자는 decision boundary와 **clone the model's behavior**(및 IP)를 학습할 수 있습니다.\
*Example*: ML-as-a-Service API에서 충분한 Q&A 쌍을 수집하여 거의 동등한 local model을 구축할 수 있습니다.

- **AI Supply-Chain Attack**: **ML pipeline**의 모든 구성 요소(data, libraries, pre-trained weights, CI/CD 등)를 compromise하여 downstream model을 오염시킵니다.\
*Example*: model-hub의 poisoned dependency가 여러 앱에 backdoored sentiment-analysis model을 설치할 수 있습니다.

- **Transfer Learning Attack**: 악성 로직을 **pre-trained model**에 심어 피해자의 task에 맞게 fine-tuning한 뒤에도 유지되도록 합니다.\
*Example*: 숨겨진 trigger가 있는 vision backbone은 medical imaging에 맞게 적용된 후에도 label을 계속 뒤집을 수 있습니다.

- **Model Skewing**: 미묘하게 편향되었거나 잘못 라벨링된 data가 **model's outputs**를 공격자의 목적에 유리하도록 변경합니다.\
*Example*: "clean" spam email을 ham으로 라벨링하여 주입하면 spam filter가 이후 유사한 email을 통과시킬 수 있습니다.

- **Output Integrity Attack**: 공격자는 model 자체가 아니라 **model predictions in transit**를 **alter**하여 downstream system을 속입니다.\
*Example*: file-quarantine stage에서 확인하기 전에 malware classifier의 "malicious" 판정을 "benign"으로 뒤집을 수 있습니다.

- **Model Poisoning** --- 직접적이고 표적화된 변경을 **model parameters** 자체에 가하며, write access를 획득한 후 동작을 변경하는 경우가 많습니다.\
*Example*: production 환경의 fraud-detection model에서 특정 카드의 transaction이 항상 승인되도록 weights를 조정할 수 있습니다.


## Google SAIF Risks

Google의 [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks)는 AI 시스템과 관련된 다양한 risks를 설명합니다:

- **Data Poisoning**: 악성 행위자가 training/tuning data를 변경하거나 주입하여 정확도를 저하시키고, backdoor를 심거나, 결과를 편향시켜 전체 data-lifecycle에서 model integrity를 훼손합니다.

- **Unauthorized Training Data**: 저작권이 있거나 민감하거나 사용 허가를 받지 않은 dataset을 수집하면, model이 사용이 허용되지 않은 data로부터 학습하기 때문에 법적, 윤리적, 성능상의 문제가 발생합니다.

- **Model Source Tampering**: training 전 또는 training 중에 model code, dependencies 또는 weights를 supply-chain 또는 insider가 조작하면, retraining 후에도 지속되는 숨겨진 로직이 삽입될 수 있습니다.

- **Excessive Data Handling**: 취약한 data-retention 및 governance control로 인해 system이 필요 이상으로 많은 personal data를 저장하거나 처리하게 되어, 노출 및 compliance risk가 증가합니다.

- **Model Exfiltration**: 공격자가 model files/weights를 탈취하여 intellectual property가 손실되고, copy-cat service 또는 후속 attack이 가능해집니다.

- **Model Deployment Tampering**: 공격자가 model artifacts 또는 serving infrastructure를 수정하여 실행 중인 model이 검증된 version과 달라지도록 만들 수 있으며, 이로 인해 behaviour가 변경될 수 있습니다.

- **Denial of ML Service**: API를 flooding하거나 “sponge” input을 전송하여 compute/energy를 고갈시키고 model을 offline 상태로 만들 수 있으며, 이는 전통적인 DoS attack과 유사합니다.

- **Model Reverse Engineering**: 많은 수의 input-output pair를 수집하여 공격자가 model을 clone하거나 distil할 수 있으며, 이를 통해 모방 제품과 맞춤형 adversarial attack을 만들 수 있습니다.

- **Insecure Integrated Component**: 취약한 plugin, agent 또는 upstream service를 통해 공격자가 AI pipeline 내부에 code를 주입하거나 privilege를 상승시킬 수 있습니다.

- **Prompt Injection**: 직접 또는 간접적으로 prompt를 조작하여 system intent를 무시하는 instruction을 몰래 삽입하고, model이 의도하지 않은 command를 수행하도록 합니다.

- **Model Evasion**: 정교하게 설계된 input이 model을 오분류하거나 hallucinate하거나 금지된 content를 출력하도록 하여 safety와 trust를 약화시킵니다.

- **Sensitive Data Disclosure**: model이 training data 또는 user context에 포함된 private 또는 confidential information을 공개하여 privacy 및 regulations를 위반합니다.

- **Inferred Sensitive Data**: model이 제공되지 않은 personal attribute를 추론하여 inference를 통한 새로운 privacy harm을 일으킵니다.

- **Insecure Model Output**: 정제되지 않은 response가 harmful code, misinformation 또는 부적절한 content를 user 또는 downstream system에 전달합니다.

- **Rogue Actions**: 자율적으로 통합된 agent가 적절한 user oversight 없이 의도하지 않은 실제 작업(file writes, API calls, purchases 등)을 실행합니다.

## Mitre AI ATLAS Matrix

[MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS)는 AI 시스템과 관련된 risks를 이해하고 완화하기 위한 comprehensive framework를 제공합니다. 이 framework는 adversary가 AI model에 사용할 수 있는 다양한 attack technique과 tactic을 분류하며, AI system을 사용해 다양한 attack을 수행하는 방법도 다룹니다.


## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

공격자는 active session token 또는 cloud API credential을 탈취하고 authorization 없이 유료 cloud-hosted LLM을 호출합니다. 이러한 access는 reverse proxy를 통해 재판매되는 경우가 많으며, reverse proxy는 피해자의 account를 전면에 내세웁니다. 예를 들어 "oai-reverse-proxy" deployment가 있습니다. 결과적으로 financial loss, policy를 벗어난 model misuse, 그리고 victim tenant로의 attribution이 발생할 수 있습니다.

TTPs:
- 감염된 developer machine 또는 browser에서 token을 수집하고, CI/CD secret을 탈취하며, leaked cookie를 구매합니다.
- genuine provider로 request를 전달하는 reverse proxy를 구축하여 upstream key를 숨기고 여러 customer의 request를 multiplex합니다.
- direct base-model endpoint를 악용하여 enterprise guardrail과 rate limit을 우회합니다.

Mitigations:
- token을 device fingerprint, IP range 및 client attestation에 bind하고, 짧은 expiration을 적용하며 MFA로 refresh합니다.
- key의 scope를 최소화하고(no tool access, 해당되는 경우 read-only), anomaly 발생 시 rotate합니다.
- safety filter, route별 quota 및 tenant isolation을 적용하는 policy gateway 뒤에서 모든 traffic을 server-side로 terminate합니다.
- 비정상적인 usage pattern(sudden spend spike, atypical region, UA string)을 모니터링하고 의심스러운 session을 자동으로 revoke합니다.
- 수명이 긴 static API key보다 IdP가 발급한 mTLS 또는 signed JWT를 우선 사용합니다.

## Self-hosted LLM inference hardening

confidential data를 대상으로 local LLM server를 실행하면 cloud-hosted API와는 다른 attack surface가 생성됩니다. inference/debug endpoint에서 prompt가 leak될 수 있고, serving stack은 일반적으로 reverse proxy를 노출하며, GPU device node는 대규모 `ioctl()` surface에 access를 제공합니다. on-prem inference service를 평가하거나 deployment하는 경우 최소한 다음 항목을 검토하세요.

### Prompt leakage via debug and monitoring endpoints

inference API를 **multi-user sensitive service**로 취급하세요. debug 또는 monitoring route는 prompt content, slot state, model metadata 또는 internal queue information을 노출할 수 있습니다. `llama.cpp`에서 `/slots` endpoint는 slot별 state를 노출하며 slot inspection/management 용도로만 사용되므로 특히 민감합니다.

- inference server 앞에 reverse proxy를 배치하고 **deny by default**를 적용합니다.
- client/UI에 필요한 정확한 HTTP method + path 조합만 allowlist에 등록합니다.
- 가능한 경우 backend 자체에서 introspection endpoint를 비활성화합니다. 예: `llama-server --no-slots`.
- reverse proxy를 `127.0.0.1`에 bind하고 LAN에 publish하는 대신 SSH local port forwarding과 같은 authenticated transport를 통해 노출합니다.

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
### 네트워크와 UNIX 소켓이 없는 Rootless 컨테이너

추론 데몬이 UNIX 소켓 수신을 지원한다면 TCP보다 이를 우선하고, **네트워크 스택 없이** 컨테이너를 실행합니다:
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
- `--network none`은 인바운드/아웃바운드 TCP/IP 노출을 제거하고, rootless containers에 필요할 수 있는 user-mode helpers를 사용하지 않도록 합니다.
- UNIX socket을 사용하면 socket path에 POSIX permissions/ACLs를 적용하여 첫 번째 access-control 계층으로 사용할 수 있습니다.
- `--userns=keep-id`와 rootless Podman은 container breakout의 영향을 줄입니다. container root는 host root가 아니기 때문입니다.
- Read-only model mounts는 container 내부에서 model tampering이 발생할 가능성을 줄입니다.

### GPU device-node 최소화

GPU-backed inference에서 `/dev/nvidia*` 파일은 대규모 driver `ioctl()` handlers와 잠재적으로 shared GPU memory-management paths를 노출하므로 가치가 높은 local attack surfaces입니다.

- `/dev/nvidia*`를 world writable 상태로 두지 마십시오.
- `NVreg_DeviceFileUID/GID/Mode`, udev rules 및 ACLs를 사용하여 `nvidia`, `nvidiactl`, `nvidia-uvm`을 제한하고, mapped container UID만 해당 파일을 열 수 있도록 하십시오.
- Headless inference hosts에서는 `nvidia_drm`, `nvidia_modeset`, `nvidia_peermem`과 같은 불필요한 modules를 blacklist하십시오.
- Runtime이 inference startup 중 opportunistically `modprobe`하도록 두지 말고, boot 시 required modules만 preload하십시오.

예시:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
중요한 검토 항목 중 하나는 **`/dev/nvidia-uvm`**입니다. workload가 명시적으로 `cudaMallocManaged()`를 사용하지 않더라도 최신 CUDA runtime에는 여전히 `nvidia-uvm`이 필요할 수 있습니다. 이 device는 공유되며 GPU virtual memory management를 처리하므로, cross-tenant data-exposure surface로 간주해야 합니다. inference backend가 지원한다면 Vulkan backend는 흥미로운 trade-off가 될 수 있습니다. container에 `nvidia-uvm`을 전혀 노출하지 않을 수 있기 때문입니다.

### inference worker를 위한 LSM confinement

inference process 주변에서 defense in depth를 구현하려면 AppArmor/SELinux/seccomp를 사용해야 합니다.

- 실제로 필요한 shared library, model path, socket directory 및 GPU device node만 허용합니다.
- `sys_admin`, `sys_module`, `sys_rawio`, `sys_ptrace`와 같은 high-risk capability를 명시적으로 거부합니다.
- model directory는 read-only로 유지하고, writable path의 범위를 runtime socket/cache directory로만 제한합니다.
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
## Phantom Squatting: AI가 환각한 도메인을 AI Supply-Chain Vector로 악용

Phantom squatting은 **slopsquatting의 domain/URL equivalent**입니다. 존재하지 않는 package name을 환각하는 대신, LLM이 실제 브랜드에 대한 그럴듯한 **portal, API, webhook, billing, SSO, download 또는 support domain**을 환각하고, 사람이 또는 agent가 사용하기 전에 공격자가 해당 namespace를 등록합니다.

이는 많은 AI-assisted workflow에서 model output이 **trusted dependency**로 취급되기 때문에 중요합니다.
- 개발자가 제안된 endpoint를 code 또는 CI/CD integration에 붙여 넣습니다.
- AI agent가 documentation, schema, APK, ZIP 또는 webhook target을 자동으로 가져옵니다.
- 생성된 runbook 또는 doc가 fake URL을 authoritative한 것처럼 포함할 수 있습니다.

### Offensive workflow

1. **환각 표면 조사**: `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` 또는 `mobile app` portal과 같은 현실적인 workflow에 대해 brand-specific question을 묻습니다.
2. **후보 정규화**: 생성된 URL을 resolve하고, NXDOMAIN response를 parent registerable domain으로 축약하며, prompt family를 deduplicate합니다. Prompt corpus는 다양하게 유지해야 하며, 예를 들어 **Jaccard similarity**를 사용해 거의 중복된 항목을 제거할 수 있습니다.
3. **예측 가능한 환각의 우선순위 지정**:
- **Thermal Hallucination Persistence (THP)**: 동일한 fake domain이 낮은 temperature인 `T=0.1`을 포함해 여러 temperature에서 나타납니다.
- **Cross-model consensus**: 여러 LLM family가 동일한 fake domain을 생성합니다.
4. **parent domain을 등록하고 weaponize**한 다음, phishing, fake APK/ZIP download, credential harvester, malicious doc 또는 secret/webhook payload를 수집하는 API endpoint를 호스팅합니다. **Pure domain-level hallucination**은 공격자가 전체 namespace를 제어하기 때문에 monetize하기 가장 쉽습니다. 다만 normalized parent가 미등록 상태라면 subdomain/path hallucination도 악용할 수 있습니다.
5. **zero-reputation window 악용**: 새로 등록된 domain은 blocklist history, URL reputation 및 성숙한 telemetry가 없는 경우가 많으므로 detection이 따라잡을 때까지 control을 우회할 수 있습니다. 공격자는 crawler에만 benign response를 제공하거나, redirect cloaking, CAPTCHA gate 또는 지연된 payload staging을 사용해 이 window를 늘릴 수 있습니다.

### Agent에 위험한 이유

Human victim의 경우 fake domain은 보통 click과 추가 action을 필요로 합니다. 그러나 **agentic workflow**에서는 LLM이 **lure**와 **executor**를 동시에 담당할 수 있습니다. Agent는 hallucinated URL을 받아 이를 fetch하고 response를 parse한 후, human review 없이 token을 leak하거나 instruction을 실행하거나 dependency를 download하거나 poisoned data를 CI/CD에 주입할 수 있습니다.

### Practical attacker prompts

High-yield prompt는 일반적으로 명시적인 phishing lure가 아니라 일반적인 enterprise task처럼 보입니다.
- “`<brand>` integration을 위한 payment sandbox URL은 무엇인가요?”
- “`<brand>` build notification에 사용해야 하는 webhook endpoint는 무엇인가요?”
- “`<brand>`의 employee benefits / billing / SSO portal은 어디에 있나요?”
- “`<brand>`의 direct Android APK 또는 desktop client download를 제공해 주세요.”

### Defensive inversion

이를 단순한 prompt-injection 문제가 아니라 proactive domain-monitoring 문제로 다뤄야 합니다.
- **brand prompt corpus**를 구축하고 사용자가 의존하는 LLM 및 agent를 주기적으로 probe합니다.
- hallucinated URL을 저장하고 temperature/model 간에 어떤 URL이 stable한지 추적합니다.
- **Adversarial Exploitation Window (AEW)**를 추적합니다. 이는 first hallucination과 attacker registration 사이의 시간입니다. Positive AEW라면 defenders가 weaponization 전에 pre-register, sinkhole 또는 pre-block할 수 있습니다.
- parent domain의 **NXDOMAIN → registered** transition을 모니터링합니다.
- 등록 시 registrar, creation date, nameserver, privacy shielding, page content, screenshot, parked-page status 및 brand-asset similarity를 triage합니다.
- Agent와 developer가 **기본적으로 LLM-generated domain을 trust하지 않도록** policy gate를 추가합니다. 최초 사용 전에 allowlist, ownership validation, CT/RDAP check 또는 human approval을 요구해야 합니다.

이는 여러 AI risk bucket에 동시에 해당합니다. **AI supply-chain attack**, **insecure model output**, 그리고 agent가 hallucinated URL을 자율적으로 consume할 때의 **rogue actions**가 이에 포함됩니다.

## References
- [Unit 42 – The Risks of Code Assistant LLMs: Harmful Content, Misuse and Deception](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [LLMJacking scheme overview – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [oai-reverse-proxy (reselling stolen LLM access)](https://gitgud.io/khanon/oai-reverse-proxy)
- [Synacktiv - Deep-dive into the deployment of an on-premise low-privileged LLM server](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [CNCF Container Device Interface (CDI) specification](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [Unit 42 – Phantom Squatting: AI-Hallucinated Domains as a Software Supply Chain Vector](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [Socket – Slopsquatting: How AI Hallucinations Are Fueling a New Class of Supply Chain Attacks](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)

{{#include ../banners/hacktricks-training.md}}
