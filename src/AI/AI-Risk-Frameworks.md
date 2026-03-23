# AI Risks

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owasp has identified the top 10 machine learning vulnerabilities that can affect AI systems. These vulnerabilities can lead to various security issues, including data poisoning, model inversion, and adversarial attacks. Understanding these vulnerabilities is crucial for building secure AI systems.

For an updated and detailed list of the top 10 machine learning vulnerabilities, refer to the [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/) project.

- **Input Manipulation Attack**: An attacker adds tiny, often invisible changes to **incoming data** so the model makes the wrong decision.\
    *Example*: A few specks of paint on a stop‑sign fool a self‑driving car into "seeing" a speed‑limit sign.

- **Data Poisoning Attack**: The **training set** is deliberately polluted with bad samples, teaching the model harmful rules.\
*Example*: Malware binaries are mislabeled as "benign" in an antivirus training corpus, letting similar malware slip past later.

- **Model Inversion Attack**: By probing outputs, an attacker builds a **reverse model** that reconstructs sensitive features of the original inputs.\
*Example*: Re‑creating a patient's MRI image from a cancer‑detection model's predictions.

- **Membership Inference Attack**: The adversary tests whether a **specific record** was used during training by spotting confidence differences.\
*Example*: Confirming that a person's bank transaction appears in a fraud‑detection model's training data.

- **Model Theft**: Repeated querying lets an attacker learn decision boundaries and **clone the model's behavior** (and IP).\
*Example*: Harvesting enough Q&A pairs from an ML‑as‑a‑Service API to build a near‑equivalent local model.

- **AI Supply‑Chain Attack**: Compromise any component (data, libraries, pre‑trained weights, CI/CD) in the **ML pipeline** to corrupt downstream models.\
*Example*: A poisoned dependency on a model‑hub installs a backdoored sentiment‑analysis model across many apps.

- **Transfer Learning Attack**: Malicious logic is planted in a **pre‑trained model** and survives fine‑tuning on the victim's task.\
*Example*: A vision backbone with a hidden trigger still flips labels after being adapted for medical imaging.

- **Model Skewing**: Subtly biased or mislabeled data **shifts the model's outputs** to favor the attacker's agenda.\
*Example*: Injecting "clean" spam emails labeled as ham so a spam filter lets similar future emails through.

- **Output Integrity Attack**: The attacker **alters model predictions in transit**, not the model itself, tricking downstream systems.\
*Example*: Flipping a malware classifier's "malicious" verdict to "benign" before the file‑quarantine stage sees it.

- **Model Poisoning** --- Direct, targeted changes to the **model parameters** themselves, often after gaining write access, to alter behavior.\
*Example*: Tweaking weights on a fraud‑detection model in production so transactions from certain cards are always approved.


## Google SAIF Risks

Google's [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) outlines various risks associated with AI systems:

- **Data Poisoning**: Malicious actors alter or inject training/tuning data to degrade accuracy, implant backdoors, or skew results, undermining model integrity across the entire data-lifecycle. 

- **Unauthorized Training Data**: Ingesting copyrighted, sensitive, or unpermitted datasets creates legal, ethical, and performance liabilities because the model learns from data it was never allowed to use. 

- **Model Source Tampering**: Supply-chain or insider manipulation of model code, dependencies, or weights before or during training can embed hidden logic that persists even after retraining. 

- **Excessive Data Handling**: Weak data-retention and governance controls lead systems to store or process more personal data than necessary, heightening exposure and compliance risk. 

- **Model Exfiltration**: Attackers steal model files/weights, causing loss of intellectual property and enabling copy-cat services or follow-on attacks. 

- **Model Deployment Tampering**: Adversaries modify model artifacts or serving infrastructure so the running model differs from the vetted version, potentially changing behaviour. 

- **Denial of ML Service**: Flooding APIs or sending “sponge” inputs can exhaust compute/energy and knock the model offline, mirroring classic DoS attacks. 

- **Model Reverse Engineering**: By harvesting large numbers of input-output pairs, attackers can clone or distil the model, fueling imitation products and customized adversarial attacks. 

- **Insecure Integrated Component**: Vulnerable plugins, agents, or upstream services let attackers inject code or escalate privileges within the AI pipeline. 

- **Prompt Injection**: Crafting prompts (directly or indirectly) to smuggle instructions that override system intent, making the model perform unintended commands. 

- **Model Evasion**: Carefully designed inputs trigger the model to mis-classify, hallucinate, or output disallowed content, eroding safety and trust. 

- **Sensitive Data Disclosure**: The model reveals private or confidential information from its training data or user context, violating privacy and regulations. 

- **Inferred Sensitive Data**: The model deduces personal attributes that were never provided, creating new privacy harms through inference. 

- **Insecure Model Output**: Unsanitized responses pass harmful code, misinformation, or inappropriate content to users or downstream systems. 

- **Rogue Actions**: Autonomously-integrated agents execute unintended real-world operations (file writes, API calls, purchases, etc.) without adequate user oversight.

## Mitre AI ATLAS Matrix

The [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) provides a comprehensive framework for understanding and mitigating risks associated with AI systems. It categorizes various attack techniques and tactics that adversaries may use against AI models and also how to use AI systems to perform different attacks.


## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Attackers steal active session tokens or cloud API credentials and invoke paid, cloud-hosted LLMs without authorization. Access is often resold via reverse proxies that front the victim’s account, e.g. "oai-reverse-proxy" deployments. Consequences include financial loss, model misuse outside policy, and attribution to the victim tenant.

TTPs:
- Harvest tokens from infected developer machines or browsers; steal CI/CD secrets; buy leaked cookies.
- Stand up a reverse proxy that forwards requests to the genuine provider, hiding the upstream key and multiplexing many customers.
- Abuse direct base-model endpoints to bypass enterprise guardrails and rate limits.

Mitigations:
- Bind tokens to device fingerprint, IP ranges, and client attestation; enforce short expirations and refresh with MFA.
- Scope keys minimally (no tool access, read-only where applicable); rotate on anomaly.
- Terminate all traffic server-side behind a policy gateway that enforces safety filters, per-route quotas, and tenant isolation.
- Monitor for unusual usage patterns (sudden spend spikes, atypical regions, UA strings) and auto-revoke suspicious sessions.
- Prefer mTLS or signed JWTs issued by your IdP over long-lived static API keys.

## Self-hosted LLM inference hardening

Running a local LLM server for confidential data creates a different attack surface from cloud-hosted APIs: inference/debug endpoints may leak prompts, the serving stack usually exposes a reverse proxy, and GPU device nodes give access to large `ioctl()` surfaces. If you are assessing or deploying an on-prem inference service, review at least the following points.

### Prompt leakage via debug and monitoring endpoints

Treat the inference API as a **multi-user sensitive service**. Debug or monitoring routes can expose prompt contents, slot state, model metadata, or internal queue information. In `llama.cpp`, the `/slots` endpoint is especially sensitive because it exposes per-slot state and is only meant for slot inspection/management.

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

### Rootless containers with no network and UNIX sockets

If the inference daemon supports listening on a UNIX socket, prefer that over TCP and run the container with **no network stack**:

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
- `--network none` removes inbound/outbound TCP/IP exposure and avoids user-mode helpers that rootless containers would otherwise need.
- A UNIX socket lets you use POSIX permissions/ACLs on the socket path as the first access-control layer.
- `--userns=keep-id` and rootless Podman reduce the impact of a container breakout because container root is not host root.
- Read-only model mounts reduce the chance of model tampering from inside the container.

### GPU device-node minimization

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

## References
- [Unit 42 – The Risks of Code Assistant LLMs: Harmful Content, Misuse and Deception](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [LLMJacking scheme overview – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [oai-reverse-proxy (reselling stolen LLM access)](https://gitgud.io/khanon/oai-reverse-proxy)
- [Synacktiv - Deep-dive into the deployment of an on-premise low-privileged LLM server](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [CNCF Container Device Interface (CDI) specification](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)

{{#include ../banners/hacktricks-training.md}}
