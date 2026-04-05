# Riscos de IA

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Vulnerabilidades de Machine Learning

OWASP identificou as 10 principais vulnerabilidades de machine learning que podem afetar sistemas de IA. Essas vulnerabilidades podem levar a diversos problemas de segurança, incluindo data poisoning, model inversion e adversarial attacks. Entender essas vulnerabilidades é crucial para construir sistemas de IA seguros.

Para uma lista atualizada e detalhada das 10 principais vulnerabilidades de machine learning, consulte o projeto [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).

- **Input Manipulation Attack**: Um atacante adiciona alterações minúsculas, muitas vezes invisíveis, aos **incoming data** para que o modelo tome a decisão errada.\
*Example*: Alguns respingos de tinta em uma placa de pare enganam um carro autônomo fazendo‑o "ver" uma placa de limite de velocidade.

- **Data Poisoning Attack**: O **training set** é deliberadamente poluído com amostras maliciosas, ensinando o modelo regras prejudiciais.\
*Example*: Binaries de malware são rotulados incorretamente como "benign" em um corpus de treinamento de antivírus, permitindo que malware similar passe despercebido depois.

- **Model Inversion Attack**: Ao sondar saídas, um atacante constrói um **reverse model** que reconstrói características sensíveis das entradas originais.\
*Example*: Recriar a imagem de uma ressonância magnética (MRI) de um paciente a partir das previsões de um modelo de detecção de câncer.

- **Membership Inference Attack**: O adversário testa se um **specific record** foi usado durante o treinamento ao detectar diferenças de confiança.\
*Example*: Confirmar que a transação bancária de uma pessoa aparece nos dados de treinamento de um modelo de detecção de fraude.

- **Model Theft**: Consultas repetidas permitem que um atacante aprenda fronteiras de decisão e **clone the model's behavior** (e IP).\
*Example*: Coletar pares Q&A suficientes de uma ML‑as‑a‑Service API para construir um modelo local quase equivalente.

- **AI Supply‑Chain Attack**: Comprometer qualquer componente (dados, bibliotecas, pre‑trained weights, CI/CD) na **ML pipeline** para corromper modelos a jusante.\
*Example*: Uma dependência envenenada em um model‑hub instala um modelo de análise de sentimento com backdoor em muitos apps.

- **Transfer Learning Attack**: Lógica maliciosa é plantada em um **pre‑trained model** e sobrevive ao fine‑tuning na tarefa da vítima.\
*Example*: Um vision backbone com um gatilho oculto ainda inverte labels após ser adaptado para imagem médica.

- **Model Skewing**: Dados sutilmente enviesados ou mal rotulados **shifts the model's outputs** para favorecer a agenda do atacante.\
*Example*: Injetar e‑mails de spam "limpos" rotulados como ham para que um filtro de spam permita e‑mails semelhantes no futuro.

- **Output Integrity Attack**: O atacante **alters model predictions in transit**, não o modelo em si, enganando sistemas a jusante.\
*Example*: Inverter o veredicto "malicious" de um classificador de malware para "benign" antes que a etapa de quarentena de arquivos o veja.

- **Model Poisoning** --- Alterações diretas e direcionadas aos **model parameters** em si, frequentemente após obter acesso de escrita, para alterar o comportamento.\
*Example*: Ajustar pesos em um modelo de detecção de fraude em produção para que transações de determinados cartões sejam sempre aprovadas.


## Riscos do Google SAIF

O [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) do Google descreve vários riscos associados a sistemas de IA:

- **Data Poisoning**: Atores maliciosos alteram ou injetam dados de treinamento/ajuste para degradar a acurácia, implantar backdoors ou enviesar resultados, comprometendo a integridade do modelo ao longo de todo o ciclo de vida dos dados.

- **Unauthorized Training Data**: Ingerir conjuntos de dados com copyright, sensíveis ou não permitidos cria responsabilidades legais, éticas e de desempenho porque o modelo aprende a partir de dados que não deveria usar.

- **Model Source Tampering**: Manipulação na supply‑chain ou por insiders do código do modelo, dependências ou weights antes ou durante o treinamento pode embutir lógica oculta que persiste mesmo após retraining.

- **Excessive Data Handling**: Controles fracos de retenção e governança de dados levam os sistemas a armazenar ou processar mais dados pessoais do que o necessário, aumentando exposição e risco de conformidade.

- **Model Exfiltration**: Atacantes roubam arquivos/weights do modelo, causando perda de propriedade intelectual e permitindo serviços imitadores ou ataques subsequentes.

- **Model Deployment Tampering**: Adversários modificam artefatos do modelo ou a infraestrutura de serving para que o modelo em execução difira da versão validada, potencialmente alterando comportamento.

- **Denial of ML Service**: Saturar APIs ou enviar inputs "sponge" pode esgotar compute/energia e derrubar o modelo, espelhando ataques clássicos de DoS.

- **Model Reverse Engineering**: Ao colher muitos pares input‑output, atacantes podem clonar ou destilar o modelo, alimentando produtos de imitação e ataques adversariais customizados.

- **Insecure Integrated Component**: Plugins, agentes ou serviços upstream vulneráveis permitem que atacantes injetem código ou escalem privilégios dentro do pipeline de IA.

- **Prompt Injection**: Criar prompts (direta ou indiretamente) para contrabandear instruções que sobrescrevem a intenção do sistema, fazendo o modelo executar comandos não desejados.

- **Model Evasion**: Inputs cuidadosamente projetados fazem o modelo mis‑classify, hallucinate ou output conteúdo proibido, corroendo segurança e confiança.

- **Sensitive Data Disclosure**: O modelo revela informações privadas ou confidenciais do seu training data ou do contexto do usuário, violando privacidade e regulações.

- **Inferred Sensitive Data**: O modelo deduz atributos pessoais que nunca foram fornecidos, criando novos danos de privacidade por inferência.

- **Insecure Model Output**: Respostas não sanitizadas passam código perigoso, misinformation ou conteúdo impróprio para usuários ou sistemas a jusante.

- **Rogue Actions**: Agentes integrados autonomamente executam operações do mundo real não intencionadas (gravar arquivos, chamadas de API, compras, etc.) sem supervisão de usuário adequada.

## Matriz MITRE AI ATLAS

A [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) fornece uma estrutura abrangente para entender e mitigar riscos associados a sistemas de IA. Ela categoriza várias técnicas e táticas de ataque que adversários podem usar contra modelos de IA e também como usar sistemas de IA para realizar diferentes ataques.


## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Atacantes roubam tokens de sessão ativos ou credenciais de API de cloud e invocam LLMs hospedados na nuvem pagos sem autorização. O acesso é frequentemente revendido via reverse proxies que fazem front para a conta da vítima, p.ex. deployments "oai-reverse-proxy". As consequências incluem perda financeira, uso indevido do modelo fora da política e atribuição ao tenant vítima.

TTPs:
- Harvest tokens de máquinas de desenvolvedor infectadas ou browsers; roubar segredos de CI/CD; comprar cookies leaked.
- Stand up um reverse proxy que encaminha requisições para o provedor genuíno, ocultando a upstream key e multiplexando muitos clientes.
- Abuse endpoints de base‑model diretos para contornar enterprise guardrails e rate limits.

Mitigations:
- Bind tokens a device fingerprint, ranges de IP e client attestation; impor short expirations e refresh com MFA.
- Scope keys minimamente (sem acesso a ferramentas, read‑only onde aplicável); rotate on anomaly.
- Terminate todo o tráfego server‑side atrás de um policy gateway que aplica filtros de segurança, quotas por rota e tenant isolation.
- Monitorar padrões de uso incomuns (picos súbitos de gasto, regiões atípicas, UA strings) e auto‑revoke sessões suspeitas.
- Preferir mTLS ou signed JWTs emitidos pelo seu IdP em vez de API keys estáticas de longa duração.

## Endurecimento da inferência de LLM auto-hospedada

Rodar um servidor local de LLM para dados confidenciais cria uma superfície de ataque diferente das APIs hospedadas na nuvem: endpoints de inference/debug podem leak prompts, a stack de serving geralmente expõe um reverse proxy, e nodos de dispositivo GPU dão acesso a grandes superfícies de `ioctl()`. Se você estiver avaliando ou implantando um serviço de inferência on‑prem, revise pelo menos os pontos abaixo.

### Prompt leakage via debug and monitoring endpoints

Trate a API de inference como um **serviço sensível multiusuário**. Rotas de debug ou monitoring podem expor conteúdos de prompt, slot state, model metadata ou informações de fila interna. Em `llama.cpp`, o endpoint `/slots` é especialmente sensível porque expõe per‑slot state e destina‑se apenas à inspeção/gerenciamento de slots.

- Coloque um reverse proxy na frente do servidor de inference e **deny by default**.
- Allowlist apenas as combinações exatas de HTTP method + path que são necessárias pelo client/UI.
- Disable introspection endpoints no backend sempre que possível, por exemplo `llama-server --no-slots`.
- Bind o reverse proxy a `127.0.0.1` e exponha‑o através de um transporte autenticado, como SSH local port forwarding, em vez de publicá‑lo na LAN.

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
### Contêineres rootless sem rede e UNIX sockets

Se o daemon de inferência suportar escutar em um UNIX socket, prefira isso ao TCP e execute o contêiner **sem a pilha de rede**:
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
- `--network none` remove a exposição TCP/IP de entrada/saída e evita os user-mode helpers que rootless containers precisariam de outra forma.
- Um socket UNIX permite usar permissões/ACLs POSIX no caminho do socket como a primeira camada de controle de acesso.
- `--userns=keep-id` e rootless Podman reduzem o impacto de um breakout de container porque o root dentro do container não é o root do host.
- Montagens de modelo em modo somente leitura reduzem a chance de adulteração do modelo de dentro do container.

### Minimização de device-node de GPU

Para inferência suportada por GPU, os arquivos `/dev/nvidia*` são superfícies de ataque locais de alto valor porque expõem grandes manipuladores de driver `ioctl()` e, potencialmente, caminhos compartilhados de gerenciamento de memória da GPU.

- Não deixe `/dev/nvidia*` gravável por todos (world writable).
- Restrinja `nvidia`, `nvidiactl` e `nvidia-uvm` com `NVreg_DeviceFileUID/GID/Mode`, regras udev e ACLs para que apenas o UID mapeado do container possa abri-los.
- Coloque na blacklist módulos desnecessários como `nvidia_drm`, `nvidia_modeset` e `nvidia_peermem` em hosts de inferência headless.
- Pré-carregue apenas os módulos necessários na inicialização em vez de permitir que o runtime os `modprobe` oportunisticamente durante a inicialização da inferência.

Exemplo:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
Um ponto importante de revisão é **`/dev/nvidia-uvm`**. Mesmo que a carga de trabalho não use explicitamente `cudaMallocManaged()`, runtimes CUDA recentes ainda podem exigir `nvidia-uvm`. Como este dispositivo é compartilhado e gerencia a memória virtual da GPU, trate-o como uma superfície de exposição de dados entre tenants. Se o backend de inferência suportar, um backend Vulkan pode ser um trade-off interessante porque pode evitar expor `nvidia-uvm` ao container por completo.

### Confinamento LSM para processos de inferência

AppArmor/SELinux/seccomp devem ser usados como defesa em profundidade em torno do processo de inferência:

- Permitir apenas as bibliotecas compartilhadas, caminhos do modelo, diretório de sockets e nós de dispositivo GPU que são realmente necessários.
- Negar explicitamente capacidades de alto risco como `sys_admin`, `sys_module`, `sys_rawio` e `sys_ptrace`.
- Manter o diretório do modelo somente leitura e limitar os caminhos graváveis apenas aos diretórios de socket/cache do runtime.
- Monitorar logs de negação, pois eles fornecem telemetria útil de detecção quando o model server ou um post-exploitation payload tenta escapar do seu comportamento esperado.

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
## References
- [Unit 42 – The Risks of Code Assistant LLMs: Harmful Content, Misuse and Deception](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [LLMJacking scheme overview – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [oai-reverse-proxy (reselling stolen LLM access)](https://gitgud.io/khanon/oai-reverse-proxy)
- [Synacktiv - Deep-dive into the deployment of an on-premise low-privileged LLM server](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [CNCF Container Device Interface (CDI) specification](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)

{{#include ../banners/hacktricks-training.md}}
