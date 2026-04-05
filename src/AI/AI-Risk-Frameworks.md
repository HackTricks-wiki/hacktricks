# AI Risks

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owasp는 AI 시스템에 영향을 줄 수 있는 상위 10가지 머신러닝 취약점을 식별했습니다. 이러한 취약점은 데이터 poisoning, model inversion, adversarial 공격 등 다양한 보안 문제로 이어질 수 있습니다. 이러한 취약점을 이해하는 것은 안전한 AI 시스템을 구축하는 데 매우 중요합니다.

For an updated and detailed list of the top 10 machine learning vulnerabilities, refer to the [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/) project.

- **Input Manipulation Attack**: 공격자는 **수신 데이터(incoming data)**에 작고 거의 보이지 않는 변경을 추가하여 모델이 잘못된 결정을 내리게 만듭니다.\
*Example*: 몇 점의 페인트로 stop‑sign을 변형해 자율주행차(self‑driving car)가 이를 속도 제한 표지로 오인하게 만듭니다.

- **Data Poisoning Attack**: **학습 세트(training set)**가 고의로 오염되어 모델이 해로운 규칙을 배우게 됩니다.\
*Example*: 악성코드(malware) 바이너리가 antivirus 학습 코퍼스에서 "benign"으로 잘못 라벨링되어 유사한 악성코드가 나중에 탐지되지 않게 됩니다.

- **Model Inversion Attack**: 출력값을 탐침(probing)하여 공격자는 원래 입력의 민감한 특징을 재구성하는 **역모델(reverse model)**을 구축합니다.\
*Example*: 암 진단 모델의 예측값으로부터 환자의 MRI 이미지를 재생성합니다.

- **Membership Inference Attack**: 공격자는 **특정 레코드(specific record)**가 학습에 사용되었는지 확신하기 위해 신뢰도(confidence) 차이를 이용해 테스트합니다.\
*Example*: 어떤 사람의 은행 거래가 fraud‑detection 모델의 학습 데이터에 포함되었는지 확인합니다.

- **Model Theft**: 반복적인 쿼리로 공격자가 의사결정 경계를 학습하고 **모델의 동작을 복제(clone the model's behavior)**합니다(지적 재산권 침해).\
*Example*: ML‑as‑a‑Service API에서 충분한 Q&A 페어를 수집해 거의 동등한 로컬 모델을 구축합니다.

- **AI Supply‑Chain Attack**: **ML pipeline**의 어느 구성요소(데이터, 라이브러리, pre‑trained weights, CI/CD)를 손상시켜 다운스트림 모델을 오염시킵니다.\
*Example*: model‑hub의 오염된 의존성이 많은 앱에 백도어가 있는 sentiment‑analysis 모델을 설치합니다.

- **Transfer Learning Attack**: 악성 로직이 **pre‑trained model**에 심어지고 피해자의 작업으로 fine‑tuning하여도 살아남습니다.\
*Example*: 숨겨진 트리거가 있는 vision backbone이 의료 영상으로 적응된 후에도 라벨을 반전시킵니다.

- **Model Skewing**: 미묘하게 편향되거나 잘못 라벨된 데이터가 **모델의 출력을 이동(shift)**시켜 공격자의 의제를 유리하게 만듭니다.\
*Example*: "clean" 스팸 이메일을 ham으로 라벨링해 스팸 필터가 향후 유사한 이메일을 통과시키게 합니다.

- **Output Integrity Attack**: 공격자는 모델 자체가 아니라 **전송 중인 모델 예측을 변경(alters model predictions in transit)**하여 다운스트림 시스템을 속입니다.\
*Example*: 파일 검역 단계(file‑quarantine)에 도달하기 전에 malware classifier의 "malicious" 판정을 "benign"으로 뒤바꿉니다.

- **Model Poisoning** --- 쓰기 권한을 얻은 후 **모델 파라미터(model parameters)** 자체를 직접적이고 표적적으로 변경하여 동작을 바꿉니다.\
*Example*: 프로덕션의 fraud‑detection 모델의 가중치를 조정해 특정 카드의 거래를 항상 승인하도록 만듭니다.


## Google SAIF Risks

Google의 [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks)은 AI 시스템과 관련된 다양한 위험을 정리합니다:

- **Data Poisoning**: 악의적 행위자가 학습/튜닝 데이터를 변경하거나 주입하여 정확도를 저하시킬 수 있고, 백도어를 심거나 결과를 왜곡하여 모델 무결성을 훼손합니다.

- **Unauthorized Training Data**: 저작권이 있거나 민감하거나 허용되지 않은 데이터셋을 수집하면 모델이 사용해서는 안 되는 데이터로 학습하여 법적, 윤리적, 성능상의 위험을 초래합니다.

- **Model Source Tampering**: 공급망(supply‑chain) 또는 내부자에 의한 모델 코드, 의존성, weights의 조작은 retraining 이후에도 지속되는 숨겨진 로직을 심을 수 있습니다.

- **Excessive Data Handling**: 약한 데이터 보관 및 거버넌스 통제로 인해 시스템이 필요 이상으로 개인 데이터를 저장하거나 처리하면 노출 및 규정 준수 위험이 증가합니다.

- **Model Exfiltration**: 공격자가 모델 파일/weights를 탈취하면 지적 재산권 손실과 모방 서비스 또는 후속 공격을 가능하게 합니다.

- **Model Deployment Tampering**: 공격자가 모델 아티팩트나 서빙 인프라를 수정하면 실행 중인 모델이 검증된 버전과 달라져 동작이 변경될 수 있습니다.

- **Denial of ML Service**: API를 폭주시키거나 “sponge” 입력을 보내면 계산/에너지가 소진되어 모델이 오프라인이 될 수 있으며, 이는 전형적인 DoS 공격과 유사합니다.

- **Model Reverse Engineering**: 많은 수의 입력‑출력 쌍을 수집하면 공격자가 모델을 복제하거나 distill하여 모방 제품과 맞춤형 적대적 공격을 촉진할 수 있습니다.

- **Insecure Integrated Component**: 취약한 플러그인, 에이전트 또는 업스트림 서비스는 공격자가 코드 주입하거나 AI 파이프라인 내에서 권한 상승을 할 수 있게 합니다.

- **Prompt Injection**: (직접 또는 간접으로) 시스템 의도를 무력화하는 명령을 밀어 넣는 프롬프트를 설계하여 모델이 의도하지 않은 명령을 수행하게 만듭니다.

- **Model Evasion**: 정교하게 설계된 입력이 모델을 오분류하게 하거나, hallucinate하게 하거나, 허용되지 않은 콘텐츠를 출력하게 하여 안전성과 신뢰를 훼손합니다.

- **Sensitive Data Disclosure**: 모델이 학습 데이터나 사용자 컨텍스트에서 개인적이거나 기밀 정보를 노출하여 프라이버시 및 규정 위반을 초래합니다.

- **Inferred Sensitive Data**: 모델이 제공되지 않은 개인 속성을 추론하여 추론을 통한 새로운 프라이버시 피해를 만듭니다.

- **Insecure Model Output**: 정제되지 않은 응답이 유해한 코드, 허위정보, 부적절한 콘텐츠를 사용자나 다운스트림 시스템으로 전달합니다.

- **Rogue Actions**: 자율적으로 통합된 에이전트가 파일 쓰기, API 호출, 구매 등 적절한 사용자 감독 없이 의도하지 않은 실제 작업을 실행합니다.

## Mitre AI ATLAS Matrix

The [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS)는 AI 시스템과 관련된 위험을 이해하고 완화하기 위한 포괄적인 프레임워크를 제공합니다. 이 매트릭스는 공격자가 AI 모델에 사용할 수 있는 다양한 공격 기법과 전술을 분류하고, 또한 AI 시스템을 이용해 수행할 수 있는 다양한 공격 방법을 정리합니다.


## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

공격자는 활성 세션 토큰이나 클라우드 API 자격증명을 훔쳐 무단으로 유료 클라우드 LLM을 호출합니다. 접근권은 종종 피해자의 계정을 가리키는 reverse proxy를 통해 재판매되며, 예로 "oai-reverse-proxy" 배포가 있습니다. 결과로는 금전적 손실, 정책 외 모델 오용, 피해자 테넌트에 대한 귀속(attribution) 문제가 발생할 수 있습니다.

TTPs:
- 감염된 개발자 기계나 브라우저에서 토큰을 수집하거나; CI/CD 비밀을 훔치거나; leaked cookies를 구매합니다.
- 실제 제공자의 키를 숨기고 여러 고객을 다중화하는 요청을 전달하는 reverse proxy를 세웁니다.
- 직접 base‑model 엔드포인트를 남용하여 enterprise guardrails와 rate limits를 우회합니다.

Mitigations:
- 토큰을 디바이스 지문, IP 범위, 클라이언트 attestation에 바인딩하고; 짧은 만료 시간을 강제하며 MFA로 갱신합니다.
- 키 권한을 최소화(툴 접근 금지, 가능한 경우 read‑only); 이상 징후 발생 시 회전(rotation)시킵니다.
- 정책 게이트웨이 뒤에서 모든 트래픽을 서버 측에서 종단시켜 경로별 쿼터, 테넌트 격리 및 안전 필터를 강제합니다.
- 비정상적 사용 패턴(갑작스런 지출 급증, 비정형 지역, UA 문자열 등)을 모니터링하고 의심스러운 세션을 자동 취소합니다.
- 장기 고정 API 키 대신 IdP가 발행한 mTLS 또는 서명된 JWTs를 선호합니다.

## Self-hosted LLM inference hardening

기밀 데이터를 위해 로컬 LLM 서버를 운영하면 클라우드 호스팅 API와는 다른 공격 표면이 생성됩니다: inference/debug 엔드포인트가 prompts를 leak할 수 있고, serving 스택은 보통 reverse proxy를 노출하며, GPU 디바이스 노드는 큰 ioctl() 표면을 제공합니다. 온프레미스 추론 서비스를 평가하거나 배포할 경우 최소한 다음 점들을 검토하세요.

### Prompt leakage via debug and monitoring endpoints

추론 API를 **다중 사용자 민감 서비스(multi-user sensitive service)**로 취급하세요. 디버그나 모니터링 경로는 prompt 내용, 슬롯 상태(slot state), 모델 메타데이터, 내부 큐 정보를 노출할 수 있습니다. `llama.cpp`에서는 `/slots` 엔드포인트가 특히 민감한데, 슬롯별 상태를 노출하며 슬롯 검사/관리용으로만 의도되었습니다.

- inference 서버 앞에 reverse proxy를 두고 **기본적으로 차단(deny by default)** 하세요.
- 클라이언트/UI가 필요로 하는 정확한 HTTP method + path 조합만 화이트리스트(allowlist)로 허용하세요.
- 가능한 경우 백엔드 자체에서 introspection 엔드포인트를 비활성화하세요. 예: `llama-server --no-slots`.
- reverse proxy를 `127.0.0.1`에 바인딩하고 LAN에 공개하는 대신 SSH local port forwarding과 같은 인증된 전송으로 노출하세요.

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
### 네트워크 없이 UNIX 소켓을 사용하는 Rootless 컨테이너

추론 데몬이 UNIX 소켓에서 수신(listen)을 지원한다면 TCP보다 이를 우선 사용하고 컨테이너를 **네트워크 스택 없이** 실행하세요:
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
- `--network none`는 inbound/outbound TCP/IP 노출을 제거하고 rootless containers가 필요로 할 수 있는 user-mode helpers를 회피합니다.
- A UNIX socket는 socket path에 대해 POSIX permissions/ACLs를 첫 번째 접근 제어 계층으로 사용할 수 있게 합니다.
- `--userns=keep-id` 및 rootless Podman은 컨테이너 탈출의 영향을 줄여줍니다. 컨테이너의 root가 호스트의 root가 아니기 때문입니다.
- Read-only model mounts는 컨테이너 내부에서 발생하는 모델 변조 가능성을 줄입니다.

### GPU device-node 최소화

For GPU-backed inference, `/dev/nvidia*` files are high-value local attack surfaces because they expose large driver `ioctl()` handlers and potentially shared GPU memory-management paths.

- Do not leave `/dev/nvidia*` world writable.
- Restrict `nvidia`, `nvidiactl`, and `nvidia-uvm` with `NVreg_DeviceFileUID/GID/Mode`, udev rules, and ACLs so only the mapped container UID can open them.
- Blacklist unnecessary modules such as `nvidia_drm`, `nvidia_modeset`, and `nvidia_peermem` on headless inference hosts.
- Preload only required modules at boot instead of letting the runtime opportunistically `modprobe` them during inference startup.

Example:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
One important review point is **`/dev/nvidia-uvm`**. Even if the workload does not explicitly use `cudaMallocManaged()`, recent CUDA runtimes may still require `nvidia-uvm`. Because this device is shared and handles GPU virtual memory management, treat it as a cross-tenant data-exposure surface. If the inference backend supports it, a Vulkan backend can be an interesting trade-off because it may avoid exposing `nvidia-uvm` to the container at all.

### LSM confinement for inference workers

AppArmor/SELinux/seccomp should be used as defense in depth around the inference process:

- Allow only the shared libraries, model paths, socket directory, and GPU device nodes that are actually required.
- Explicitly deny high-risk capabilities such as `sys_admin`, `sys_module`, `sys_rawio`, and `sys_ptrace`.
- Keep the model directory read-only and scope writable paths to the runtime socket/cache directories only.
- Monitor denial logs because they provide useful detection telemetry when the model server or a post-exploitation payload tries to escape its expected behaviour.

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
- [Unit 42 – 코드 어시스턴트 LLM의 위험: 유해 콘텐츠, 오용 및 기만](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [LLMJacking 스킴 개요 – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [oai-reverse-proxy (도난당한 LLM 접근 권한 재판매)](https://gitgud.io/khanon/oai-reverse-proxy)
- [Synacktiv - 온프레미스 저권한 LLM 서버 배포에 대한 심층 분석](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [CNCF Container Device Interface (CDI) 명세](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)

{{#include ../banners/hacktricks-training.md}}
