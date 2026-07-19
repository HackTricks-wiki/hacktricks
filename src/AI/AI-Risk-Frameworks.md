# Riscos de IA

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

A Owasp identificou as 10 principais vulnerabilidades de machine learning que podem afetar sistemas de IA. Essas vulnerabilidades podem levar a vários problemas de segurança, incluindo data poisoning, model inversion e adversarial attacks. Compreender essas vulnerabilidades é essencial para criar sistemas de IA seguros.

Para obter uma lista atualizada e detalhada das 10 principais vulnerabilidades de machine learning, consulte o projeto [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).

- **Input Manipulation Attack**: Um atacante adiciona pequenas alterações, frequentemente invisíveis, aos **dados de entrada** para fazer o modelo tomar a decisão errada.\
*Exemplo*: Alguns pontos de tinta em uma placa de pare fazem um carro autônomo "ver" uma placa de limite de velocidade.

- **Data Poisoning Attack**: O **training set** é deliberadamente contaminado com amostras ruins, ensinando regras prejudiciais ao modelo.\
*Exemplo*: Binários de malware são rotulados incorretamente como "benign" em um corpus de treinamento de antivírus, permitindo que malwares semelhantes passem despercebidos posteriormente.

- **Model Inversion Attack**: Ao sondar as saídas, um atacante cria um **reverse model** que reconstrói características sensíveis das entradas originais.\
*Exemplo*: Recriar a imagem de ressonância magnética de um paciente a partir das previsões de um modelo de detecção de câncer.

- **Membership Inference Attack**: O adversário testa se um **registro específico** foi usado durante o treinamento, observando diferenças de confiança.\
*Exemplo*: Confirmar que uma transação bancária de uma pessoa aparece nos dados de treinamento de um modelo de detecção de fraude.

- **Model Theft**: Consultas repetidas permitem que um atacante aprenda os limites de decisão e **clone o comportamento do modelo** (e sua IP).\
*Exemplo*: Coletar pares suficientes de perguntas e respostas de uma API de ML-as-a-Service para criar um modelo local quase equivalente.

- **AI Supply-Chain Attack**: Comprometer qualquer componente (dados, bibliotecas, pesos pré-treinados, CI/CD) no **ML pipeline** para corromper os modelos downstream.\
*Exemplo*: Uma dependência comprometida em um model-hub instala um modelo de análise de sentimento com backdoor em vários aplicativos.

- **Transfer Learning Attack**: Uma lógica maliciosa é inserida em um **pre-trained model** e sobrevive ao fine-tuning na tarefa da vítima.\
*Exemplo*: Um backbone de visão com um gatilho oculto continua invertendo rótulos após ser adaptado para imagens médicas.

- **Model Skewing**: Dados sutilmente enviesados ou rotulados incorretamente **alteram as saídas do modelo** para favorecer a agenda do atacante.\
*Exemplo*: Injetar e-mails de spam "limpos" rotulados como ham para que um filtro de spam permita a passagem de e-mails futuros semelhantes.

- **Output Integrity Attack**: O atacante **altera as previsões do modelo em trânsito**, e não o próprio modelo, enganando os sistemas downstream.\
*Exemplo*: Alterar o veredito "malicious" de um classificador de malware para "benign" antes que o estágio de quarentena do arquivo o receba.

- **Model Poisoning** --- Alterações diretas e direcionadas nos **parâmetros do modelo**, geralmente após obter acesso de escrita, para modificar seu comportamento.\
*Exemplo*: Ajustar os pesos de um modelo de detecção de fraude em produção para que transações de determinados cartões sejam sempre aprovadas.


## Riscos do Google SAIF

O [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework) do Google descreve vários riscos associados a sistemas de IA:

- **Data Poisoning**: Atores maliciosos alteram ou injetam dados de treinamento/tuning para degradar a precisão, implantar backdoors ou distorcer resultados, comprometendo a integridade do modelo em todo o ciclo de vida dos dados.

- **Unauthorized Training Data**: A ingestão de datasets protegidos por direitos autorais, sensíveis ou não autorizados cria responsabilidades legais, éticas e de desempenho, pois o modelo aprende com dados que nunca teve permissão para usar.

- **Model Source Tampering**: A manipulação da supply chain ou por insiders do código, dependências ou pesos do modelo antes ou durante o treinamento pode inserir lógica oculta que persiste mesmo após o retreinamento.

- **Excessive Data Handling**: Controles fracos de retenção e governança de dados fazem com que os sistemas armazenem ou processem mais dados pessoais do que o necessário, aumentando a exposição e o risco de não conformidade.

- **Model Exfiltration**: Atacantes roubam arquivos/pesos do modelo, causando perda de propriedade intelectual e permitindo serviços imitadores ou ataques subsequentes.

- **Model Deployment Tampering**: Adversários modificam artefatos do modelo ou a infraestrutura de serving para que o modelo em execução seja diferente da versão validada, potencialmente alterando seu comportamento.

- **Denial of ML Service**: Inundar APIs ou enviar entradas “sponge” pode esgotar recursos computacionais/energia e deixar o modelo offline, reproduzindo ataques DoS clássicos.

- **Model Reverse Engineering**: Ao coletar grandes quantidades de pares de entrada-saída, atacantes podem clonar ou destilar o modelo, alimentando produtos de imitação e ataques adversariais personalizados.

- **Insecure Integrated Component**: Plugins, agents ou serviços upstream vulneráveis permitem que atacantes injetem código ou escalem privilégios dentro do AI pipeline.

- **Prompt Injection**: Criar prompts, direta ou indiretamente, para inserir instruções que substituam a intenção do sistema, fazendo o modelo executar comandos não desejados.

- **Model Evasion**: Entradas cuidadosamente elaboradas fazem o modelo classificar incorretamente, alucinar ou produzir conteúdo não permitido, comprometendo a segurança e a confiança.

- **Sensitive Data Disclosure**: O modelo revela informações privadas ou confidenciais de seus dados de treinamento ou do contexto do usuário, violando a privacidade e regulamentações.

- **Inferred Sensitive Data**: O modelo deduz atributos pessoais que nunca foram fornecidos, criando novos danos à privacidade por meio de inferência.

- **Insecure Model Output**: Respostas não sanitizadas transmitem código prejudicial, desinformação ou conteúdo inadequado aos usuários ou sistemas downstream.

- **Rogue Actions**: Agents integrados de forma autônoma executam operações não desejadas no mundo real (gravações de arquivos, chamadas de API, compras etc.) sem supervisão adequada do usuário.

## Mitre AI ATLAS Matrix

A [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) fornece um framework abrangente para compreender e mitigar riscos associados a sistemas de IA. Ela categoriza várias técnicas e táticas de ataque que adversários podem usar contra modelos de IA e também como usar sistemas de IA para realizar diferentes ataques.

## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Atacantes roubam tokens de sessão ativos ou credenciais de API cloud e invocam LLMs pagos e hospedados na cloud sem autorização. O acesso frequentemente é revendendido por meio de reverse proxies que ficam na frente da conta da vítima, por exemplo, deployments de "oai-reverse-proxy". As consequências incluem perdas financeiras, uso indevido do modelo fora da política e atribuição das ações ao tenant da vítima.

TTPs:
- Coletar tokens de máquinas de desenvolvedores ou browsers infectados; roubar secrets de CI/CD; comprar cookies vazados.
- Configurar um reverse proxy que encaminha requests ao provider legítimo, ocultando a upstream key e multiplexando vários clientes.
- Abusar de endpoints de base-model diretos para contornar guardrails corporativos e rate limits.

Mitigações:
- Vincular tokens ao fingerprint do dispositivo, intervalos de IP e client attestation; impor expirações curtas e renovar com MFA.
- Limitar as keys ao mínimo necessário (sem acesso a tools, somente leitura quando aplicável); fazer rotação diante de anomalias.
- Encerrar todo o tráfego server-side atrás de um policy gateway que imponha filtros de segurança, quotas por rota e isolamento de tenants.
- Monitorar padrões de uso incomuns (picos repentinos de gastos, regiões atípicas, strings de UA) e revogar automaticamente sessões suspeitas.
- Preferir mTLS ou JWTs assinados emitidos pelo seu IdP em vez de API keys estáticas de longa duração.

## Hardening de inferência de LLM self-hosted

Executar um servidor local de LLM para dados confidenciais cria uma attack surface diferente daquela das APIs hospedadas na cloud: endpoints de inferência/debug podem causar leak de prompts, a serving stack normalmente expõe um reverse proxy e os device nodes da GPU fornecem acesso a grandes superfícies `ioctl()`. Se você estiver avaliando ou implantando um serviço de inferência on-prem, revise pelo menos os seguintes pontos.

### Prompt leakage via endpoints de debug e monitoramento

Trate a API de inferência como um **serviço sensível multiusuário**. Rotas de debug ou monitoramento podem expor conteúdos de prompts, estado dos slots, metadados do modelo ou informações sobre filas internas. No `llama.cpp`, o endpoint `/slots` é especialmente sensível porque expõe o estado de cada slot e destina-se apenas à inspeção/gerenciamento de slots.

- Coloque um reverse proxy na frente do servidor de inferência e **negue por padrão**.
- Permita somente as combinações exatas de método HTTP + path necessárias ao cliente/UI.
- Desative endpoints de introspecção no próprio backend sempre que possível, por exemplo `llama-server --no-slots`.
- Faça o reverse proxy escutar em `127.0.0.1` e exponha-o por meio de um transporte autenticado, como o encaminhamento local de portas via SSH, em vez de publicá-lo na LAN.

Exemplo de allowlist com nginx:
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

Se o daemon de inferência for compatível com escuta em um socket UNIX, prefira essa opção em vez de TCP e execute o container com **nenhuma pilha de rede**:
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
- `--network none` remove a exposição TCP/IP de entrada/saída e evita helpers em user-mode que, de outra forma, containers rootless precisariam.
- Um UNIX socket permite usar permissões/ACLs POSIX no caminho do socket como primeira camada de controle de acesso.
- `--userns=keep-id` e o Podman rootless reduzem o impacto de um breakout do container, pois o root do container não é o root do host.
- Montagens de modelos somente leitura reduzem a chance de adulteração do modelo a partir de dentro do container.

### Minimização de nós de dispositivo GPU

Para inference com GPU, os arquivos `/dev/nvidia*` são superfícies de ataque locais de alto valor, pois expõem grandes handlers `ioctl()` do driver e, potencialmente, caminhos compartilhados de gerenciamento de memória da GPU.

- Não deixe `/dev/nvidia*` gravável por todos.
- Restrinja `nvidia`, `nvidiactl` e `nvidia-uvm` com `NVreg_DeviceFileUID/GID/Mode`, regras do udev e ACLs, para que somente o UID mapeado do container possa abri-los.
- Coloque na blacklist módulos desnecessários, como `nvidia_drm`, `nvidia_modeset` e `nvidia_peermem`, em hosts de inference headless.
- Faça preload apenas dos módulos necessários durante o boot, em vez de permitir que o runtime execute `modprobe` oportunisticamente durante a inicialização do inference.

Exemplo:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
Um ponto importante da revisão é **`/dev/nvidia-uvm`**. Mesmo que o workload não use explicitamente `cudaMallocManaged()`, runtimes recentes do CUDA ainda podem exigir `nvidia-uvm`. Como esse dispositivo é compartilhado e gerencia a memória virtual da GPU, trate-o como uma superfície de exposição de dados entre tenants. Se o inference backend for compatível, um Vulkan backend pode ser uma alternativa interessante, pois talvez evite expor `nvidia-uvm` ao container.

### Confinamento por LSM para inference workers

AppArmor/SELinux/seccomp devem ser usados como defesa em profundidade ao redor do processo de inference:

- Permita apenas as shared libraries, os model paths, o diretório de sockets e os GPU device nodes realmente necessários.
- Negue explicitamente capabilities de alto risco, como `sys_admin`, `sys_module`, `sys_rawio` e `sys_ptrace`.
- Mantenha o diretório do modelo somente para leitura e limite os caminhos graváveis exclusivamente aos diretórios de runtime socket/cache.
- Monitore os denial logs, pois eles fornecem telemetria de detecção útil quando o model server ou um post-exploitation payload tenta escapar do comportamento esperado.

Exemplo de regras do AppArmor para um worker com GPU:
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
## Phantom Squatting: Domínios alucinados por LLM como vetor de AI Supply-Chain

Phantom squatting é o **equivalente de domínio/URL do slopsquatting**. Em vez de alucinar um nome de pacote inexistente, o LLM alucina um **domínio plausível de portal, API, webhook, billing, SSO, download ou suporte** de uma marca real, e um atacante registra esse namespace antes que um humano ou agente o utilize.

Isso é importante porque, em muitos fluxos de trabalho assistidos por AI, a saída do modelo é tratada como uma **dependência confiável**:
- Developers colam o endpoint sugerido no código ou em integrações de CI/CD.
- Agentes de AI buscam automaticamente documentação, schemas, APKs, ZIPs ou destinos de webhook.
- Runbooks ou documentos gerados podem incorporar a URL falsa como se fosse oficial.

### Offensive workflow

1. **Probe a superfície de alucinação**: faça perguntas específicas sobre marcas e fluxos de trabalho realistas, como portais de `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` ou `mobile app`.
2. **Normalize os candidatos**: resolva as URLs geradas, reduza respostas NXDOMAIN ao parent registerable domain e elimine duplicatas entre famílias de prompts. Os corpora de prompts devem permanecer diversificados, por exemplo, descartando quase duplicatas com **similaridade de Jaccard**.
3. **Priorize alucinações previsíveis**:
- **Thermal Hallucination Persistence (THP)**: o mesmo domínio falso aparece em diferentes temperaturas, incluindo temperaturas baixas como `T=0.1`.
- **Consenso entre modelos**: múltiplas famílias de LLM geram o mesmo domínio falso.
4. **Registre e weaponize** o parent domain; depois hospede phishing, downloads de APK/ZIP falsos, credential harvesters, documentos maliciosos ou endpoints de API que coletem secrets/payloads de webhook. **Alucinações puramente em nível de domínio** são as mais fáceis de monetizar porque o atacante controla todo o namespace; alucinações de subdomínio/caminho ainda podem ser abusadas quando o parent normalizado não está registrado.
5. **Explore a janela de reputação zero**: domínios recém-registrados geralmente não possuem histórico em blocklists, reputação de URL ou telemetria madura, podendo contornar controles até que as detecções sejam atualizadas. Atacantes podem ampliar essa janela usando respostas benignas exclusivas para crawlers, redirect cloaking, CAPTCHA gates ou staging atrasado de payloads.

### Why it is dangerous for agents

Para uma vítima humana, o domínio falso geralmente ainda exige um clique e outra ação. Em um **fluxo de trabalho agentic**, o LLM pode ser tanto a **isca** quanto o **executor**: o agente recebe a URL alucinada, acessa a URL, interpreta a resposta e pode então vazar tokens, executar instruções, baixar uma dependência ou enviar dados envenenados para CI/CD sem qualquer revisão humana.

### Practical attacker prompts

Prompts de alto rendimento geralmente se parecem com tarefas empresariais normais, em vez de iscas explícitas de phishing:
- “Qual é a URL do sandbox de pagamentos para integrações de `<brand>`?”
- “Qual endpoint de webhook devo usar para notificações de build de `<brand>`?”
- “Onde fica o portal de benefícios de funcionários / billing / SSO de `<brand>`?”
- “Forneça o download direto do APK Android ou do cliente desktop de `<brand>`.”

### Defensive inversion

Trate isso como um problema proativo de monitoramento de domínios, não apenas como um problema de prompt injection:
- Crie um **corpus de prompts de marcas** e faça probes periódicos nos LLMs dos quais seus usuários/agentes dependem.
- Armazene as URLs alucinadas e acompanhe quais permanecem estáveis entre temperaturas/modelos.
- Acompanhe a **Adversarial Exploitation Window (AEW)**: o tempo entre a primeira alucinação e o registro pelo atacante. Uma AEW positiva significa que os defensores podem fazer pre-registration, sinkhole ou pre-block antes da weaponization.
- Monitore transições de **NXDOMAIN → registrado** para os parent domains.
- Após o registro, faça a triagem do registrar, data de criação, nameservers, privacy shielding, conteúdo da página, screenshots, status de página estacionada e similaridade com brand assets.
- Adicione policy gates para que agents/developers **não confiem por padrão em domínios gerados por LLM**: exija allowlists, validação de propriedade, verificações de CT/RDAP ou aprovação humana antes do primeiro uso.

Isso se encaixa simultaneamente em várias categorias de risco de AI: **AI supply-chain attack**, **insecure model output** e **rogue actions** quando agentes consomem autonomamente a URL alucinada.

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
