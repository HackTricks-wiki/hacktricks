# Riscos de IA

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owasp identificou as 10 principais vulnerabilidades de machine learning que podem afetar sistemas de IA. Essas vulnerabilidades podem causar diversos problemas de segurança, incluindo data poisoning, model inversion e adversarial attacks. Entender essas vulnerabilidades é crucial para construir sistemas de IA seguros.

Para uma lista atualizada e detalhada das top 10 vulnerabilidades de machine learning, consulte o projeto [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).

- **Input Manipulation Attack**: Um atacante adiciona pequenas mudanças, muitas vezes invisíveis, aos **incoming data** para fazer o modelo tomar a decisão errada.\
*Exemplo*: Alguns respingos de tinta em uma placa de pare fazem um carro self‑driving "ver" uma placa de limite de velocidade.

- **Data Poisoning Attack**: O **training set** é deliberadamente poluído com amostras ruins, ensinando o modelo regras prejudiciais.\
*Exemplo*: Binaries de malware são rotulados incorretamente como "benign" em um corpus de treinamento de antivírus, permitindo que malware similar passe despercebido depois.

- **Model Inversion Attack**: Ao sondar outputs, um atacante constrói um **reverse model** que reconstrói características sensíveis dos inputs originais.\
*Exemplo*: Recriar a imagem de uma ressonância magnética de um paciente a partir das previsões de um modelo de detecção de câncer.

- **Membership Inference Attack**: O adversário testa se um **specific record** foi usado durante o treinamento identificando diferenças de confiança.\
*Exemplo*: Confirmar que a transação bancária de uma pessoa aparece nos dados de treinamento de um modelo de detecção de fraudes.

- **Model Theft**: Queries repetidas permitem que um atacante aprenda as fronteiras de decisão e **clone the model's behavior** (e a propriedade intelectual).\
*Exemplo*: Colher pares Q&A suficientes de uma API ML‑as‑a‑Service para construir um modelo local quase equivalente.

- **AI Supply‑Chain Attack**: Comprometer qualquer componente (dados, libraries, pre‑trained weights, CI/CD) no **ML pipeline** para corromper modelos a jusante.\
*Exemplo*: Uma dependência envenenada em um model‑hub instala um modelo de análise de sentimento backdoored em várias aplicações.

- **Transfer Learning Attack**: Lógica maliciosa é plantada em um **pre‑trained model** e sobrevive ao fine‑tuning na tarefa da vítima.\
*Exemplo*: Um backbone de visão com um trigger escondido ainda inverte labels após ser adaptado para imagens médicas.

- **Model Skewing**: Dados sutilmente tendenciosos ou mal rotulados **shifts the model's outputs** para favorecer a agenda do atacante.\
*Exemplo*: Injetar e‑mails de spam "limpos" rotulados como ham para que um filtro de spam permita e‑mails similares no futuro.

- **Output Integrity Attack**: O atacante **alters model predictions in transit**, não o modelo em si, enganando sistemas a jusante.\
*Exemplo*: Inverter o veredicto "malicious" de um classificador de malware para "benign" antes da etapa de quarentena de arquivos.

- **Model Poisoning** --- Direct, targeted changes to the **model parameters** themselves, often after gaining write access, to alter behavior.\
*Exemplo*: Tweaking weights on a fraud‑detection model in production so transactions from certain cards are always approved.


## Google SAIF Risks

O [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) do Google descreve vários riscos associados a sistemas de IA:

- **Data Poisoning**: Atores maliciosos alteram ou injetam dados de treinamento/tuning para degradar a acurácia, implantar backdoors ou enviesar resultados, minando a integridade do modelo ao longo de todo o ciclo de vida dos dados.

- **Unauthorized Training Data**: Ingerir datasets com copyright, sensíveis ou não permitidos cria responsabilidades legais, éticas e de performance porque o modelo aprende a partir de dados que nunca deveria usar.

- **Model Source Tampering**: Manipulação da cadeia de suprimentos ou insiders no código do modelo, dependencies ou weights antes ou durante o treinamento pode embutir lógica oculta que persiste mesmo após retraining.

- **Excessive Data Handling**: Controles fracos de retention e governança fazem os sistemas armazenarem ou processarem mais dados pessoais do que o necessário, aumentando exposição e risco de conformidade.

- **Model Exfiltration**: Ataques roubam arquivos do modelo/weights, causando perda de propriedade intelectual e possibilitando serviços clonados ou ataques subsequentes.

- **Model Deployment Tampering**: Adversários modificam artifacts do modelo ou infraestrutura de serving para que o modelo em execução difira da versão validada, podendo alterar o comportamento.

- **Denial of ML Service**: Saturar APIs ou enviar inputs "sponge" pode esgotar compute/energia e derrubar o modelo, espelhando ataques clássicos de DoS.

- **Model Reverse Engineering**: Ao colher grande número de pares input‑output, atacantes podem clonar ou destilar o modelo, alimentando produtos imitadores e ataques adversariais customizados.

- **Insecure Integrated Component**: Plugins, agents ou serviços a montante vulneráveis permitem que atacantes injetem código ou escalem privilégios dentro do pipeline de IA.

- **Prompt Injection**: Construir prompts (direta ou indiretamente) para contrabandear instruções que sobrescrevem a intenção do sistema, fazendo o modelo executar comandos não intencionados.

- **Model Evasion**: Inputs cuidadosamente desenhados disparam o modelo para misclassify, hallucinate ou output conteúdo proibido, corroendo segurança e confiança.

- **Sensitive Data Disclosure**: O modelo revela informações privadas ou confidenciais de seus dados de treinamento ou do contexto do usuário, violando privacidade e regulações.

- **Inferred Sensitive Data**: O modelo deduz atributos pessoais que nunca foram fornecidos, criando novos danos de privacidade por inferência.

- **Insecure Model Output**: Respostas sem sanitização passam código nocivo, desinformação ou conteúdo inadequado para usuários ou sistemas a jusante.

- **Rogue Actions**: Agentes integrados autonomamente executam operações no mundo real não intencionadas (writes em arquivos, chamadas de API, compras, etc.) sem supervisão adequada do usuário.

## Mitre AI ATLAS Matrix

A [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) fornece um framework abrangente para entender e mitigar riscos associados a sistemas de IA. Ela categoriza várias técnicas e táticas de ataque que adversários podem usar contra modelos de IA e também como usar sistemas de IA para realizar diferentes ataques.


## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Ataques roubam tokens de sessão ativos ou credenciais de API cloud e invocam LLMs hospedados na nuvem pagos sem autorização. O acesso frequentemente é revendido via reverse proxies que ficam na frente da conta da vítima, ex.: deployments "oai-reverse-proxy". As consequências incluem perda financeira, misuse do modelo fora da política e atribuição à tenant vítima.

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

Executar um servidor LLM local para dados confidenciais cria uma superfície de ataque diferente das APIs hospedadas na nuvem: endpoints de inference/debug podem leak prompts, a stack de serving normalmente expõe um reverse proxy, e nós de dispositivo GPU dão acesso a amplas superfícies de `ioctl()`. Se você está avaliando ou implantando um serviço de inferência on‑prem, revise pelo menos os seguintes pontos.

### Prompt leakage via debug and monitoring endpoints

Trate a inference API como um **multi-user sensitive service**. Rotas de debug ou monitoring podem expor conteúdos de prompts, estado de slots, model metadata ou informações da fila interna. Em `llama.cpp`, o endpoint `/slots` é especialmente sensível porque expõe estado por slot e é destinado apenas para inspeção/gerenciamento de slots.

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
### Containers rootless sem rede e sockets UNIX

Se o daemon de inferência suportar escutar em um socket UNIX, prefira isso ao TCP e execute o container sem **pilha de rede**:
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
Benefícios:
- `--network none` remove a exposição TCP/IP de entrada e saída e evita helpers em modo usuário que containers sem root precisariam.
- Um socket UNIX permite usar permissões POSIX/ACLs no caminho do socket como a primeira camada de controle de acesso.
- `--userns=keep-id` e o Podman rootless reduzem o impacto de um container breakout porque o root do container não é o root do host.
- Montagens de modelo em somente leitura reduzem a chance de adulteração do modelo de dentro do container.

### Minimização de device-nodes de GPU

Para inferência com GPU, os arquivos `/dev/nvidia*` são superfícies de ataque locais de alto valor porque expõem grandes handlers de driver `ioctl()` e, potencialmente, caminhos compartilhados de gerenciamento de memória da GPU.

- Não deixe `/dev/nvidia*` gravável por todos.
- Restrinja `nvidia`, `nvidiactl` e `nvidia-uvm` com `NVreg_DeviceFileUID/GID/Mode`, regras udev e ACLs para que apenas o UID mapeado do container possa abri-los.
- Coloque em blacklist módulos desnecessários, como `nvidia_drm`, `nvidia_modeset` e `nvidia_peermem`, em hosts de inferência headless.
- Pré-carregue apenas os módulos necessários na inicialização em vez de permitir que o runtime os `modprobe` oportunisticamente durante a inicialização da inferência.

Exemplo:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
One important review point is **`/dev/nvidia-uvm`**. Even if the workload does not explicitly use `cudaMallocManaged()`, recent CUDA runtimes may still require `nvidia-uvm`. Because this device is shared and handles GPU virtual memory management, treat it as a cross-tenant data-exposure surface. If the inference backend supports it, a Vulkan backend can be an interesting trade-off because it may avoid exposing `nvidia-uvm` to the container at all.

### Confinamento LSM para workers de inferência

AppArmor/SELinux/seccomp devem ser usados como defesa em profundidade em torno do processo de inferência:

- Permita apenas as bibliotecas compartilhadas, caminhos de modelo, diretório de sockets e nós de dispositivos GPU que são realmente necessários.
- Negue explicitamente capacidades de alto risco como `sys_admin`, `sys_module`, `sys_rawio` e `sys_ptrace`.
- Mantenha o diretório do modelo como somente leitura e limite os caminhos graváveis apenas aos diretórios de socket/cache em tempo de execução.
- Monitore os logs de negação, pois eles fornecem telemetria útil de detecção quando o model server ou um post-exploitation payload tenta escapar do comportamento esperado.

Exemplo de regras AppArmor para um worker com GPU:
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
## Referências
- [Unit 42 – The Risks of Code Assistant LLMs: Harmful Content, Misuse and Deception](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [LLMJacking scheme overview – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [oai-reverse-proxy (reselling stolen LLM access)](https://gitgud.io/khanon/oai-reverse-proxy)
- [Synacktiv - Deep-dive into the deployment of an on-premise low-privileged LLM server](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [CNCF Container Device Interface (CDI) specification](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)

{{#include ../banners/hacktricks-training.md}}
