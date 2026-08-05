# Riscos de IA

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

A Owasp identificou as 10 principais vulnerabilidades de machine learning que podem afetar sistemas de IA. Essas vulnerabilidades podem levar a vários problemas de segurança, incluindo data poisoning, model inversion e adversarial attacks. Compreender essas vulnerabilidades é essencial para criar sistemas de IA seguros.

Para obter uma lista atualizada e detalhada das 10 principais vulnerabilidades de machine learning, consulte o projeto [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).<sup>[[10]](#references)</sup>

- **Input Manipulation Attack**: Um atacante adiciona pequenas alterações, frequentemente invisíveis, aos **dados recebidos**, fazendo com que o modelo tome a decisão errada.\
*Exemplo*: Alguns respingos de tinta em uma placa de pare enganam um carro autônomo, fazendo-o "enxergar" uma placa de limite de velocidade.

- **Data Poisoning Attack**: O **conjunto de treinamento** é deliberadamente contaminado com amostras maliciosas, ensinando regras prejudiciais ao modelo.\
*Exemplo*: Binários de malware são rotulados incorretamente como "benignos" em um corpus de treinamento de antivírus, permitindo que malwares semelhantes passem despercebidos posteriormente.

- **Model Inversion Attack**: Ao sondar as saídas, um atacante cria um **modelo reverso** que reconstrói características sensíveis das entradas originais.\
*Exemplo*: Recriar a imagem de ressonância magnética de um paciente a partir das previsões de um modelo de detecção de câncer.

- **Membership Inference Attack**: O adversário testa se um **registro específico** foi usado durante o treinamento, identificando diferenças nos níveis de confiança.\
*Exemplo*: Confirmar que a transação bancária de uma pessoa aparece nos dados de treinamento de um modelo de detecção de fraude.

- **Model Theft**: Consultas repetidas permitem que um atacante aprenda os limites de decisão e **clone o comportamento do modelo** (e sua propriedade intelectual).\
*Exemplo*: Coletar pares suficientes de perguntas e respostas de uma API de ML-as-a-Service para criar um modelo local quase equivalente.

- **AI Supply-Chain Attack**: Comprometer qualquer componente (dados, bibliotecas, pesos pré-treinados, CI/CD) do **pipeline de ML** para corromper os modelos downstream.\
*Exemplo*: Uma dependência envenenada em um model-hub instala um modelo de análise de sentimento com backdoor em vários aplicativos.

- **Transfer Learning Attack**: Uma lógica maliciosa é inserida em um **modelo pré-treinado** e sobrevive ao fine-tuning na tarefa da vítima.\
*Exemplo*: Um backbone de visão computacional com um gatilho oculto continua invertendo rótulos após ser adaptado para imagens médicas.

- **Model Skewing**: Dados sutilmente tendenciosos ou rotulados incorretamente **alteram as saídas do modelo** para favorecer a agenda do atacante.\
*Exemplo*: Injetar e-mails de spam "limpos" rotulados como ham para que um filtro de spam permita a passagem de e-mails futuros semelhantes.

- **Output Integrity Attack**: O atacante **altera as previsões do modelo em trânsito**, e não o modelo em si, enganando os sistemas downstream.\
*Exemplo*: Alterar o veredito "malicioso" de um classificador de malware para "benigno" antes que o estágio de quarentena de arquivos o receba.

- **Model Poisoning** --- Alterações diretas e direcionadas aos **parâmetros do modelo**, geralmente após obter acesso de escrita, para modificar seu comportamento.\
*Exemplo*: Ajustar os pesos de um modelo de detecção de fraude em produção para que transações de determinados cartões sejam sempre aprovadas.


## Riscos do Google SAIF

O [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework) do Google descreve vários riscos associados a sistemas de IA:<sup>[[11]](#references)</sup>

- **Data Poisoning**: Agentes maliciosos alteram ou injetam dados de treinamento/tuning para degradar a precisão, implantar backdoors ou distorcer resultados, comprometendo a integridade do modelo em todo o ciclo de vida dos dados.

- **Unauthorized Training Data**: A ingestão de datasets protegidos por direitos autorais, sensíveis ou não autorizados cria riscos legais, éticos e de desempenho, pois o modelo aprende com dados que nunca teve permissão para usar.

- **Model Source Tampering**: A manipulação da supply chain ou por pessoas internas do código do modelo, dependências ou pesos antes ou durante o treinamento pode inserir lógica oculta que persiste mesmo após o retreinamento.

- **Excessive Data Handling**: Controles fracos de retenção e governança de dados levam os sistemas a armazenar ou processar mais dados pessoais do que o necessário, aumentando a exposição e o risco de compliance.

- **Model Exfiltration**: Atacantes roubam arquivos/pesos do modelo, causando perda de propriedade intelectual e permitindo serviços imitadores ou ataques subsequentes.

- **Model Deployment Tampering**: Adversários modificam artefatos do modelo ou a infraestrutura de serving para que o modelo em execução seja diferente da versão validada, podendo alterar seu comportamento.

- **Denial of ML Service**: Inundar APIs ou enviar entradas "sponge" pode esgotar recursos computacionais/energia e deixar o modelo offline, reproduzindo ataques DoS clássicos.

- **Model Reverse Engineering**: Ao coletar grandes quantidades de pares de entrada e saída, atacantes podem clonar ou destilar o modelo, alimentando produtos imitadores e ataques adversariais personalizados.

- **Insecure Integrated Component**: Plugins, agentes ou serviços upstream vulneráveis permitem que atacantes injetem código ou escalem privilégios dentro do pipeline de IA.

- **Prompt Injection**: Criar prompts (direta ou indiretamente) para inserir instruções que substituam a intenção do sistema, fazendo o modelo executar comandos não intencionais.

- **Model Evasion**: Entradas cuidadosamente elaboradas fazem o modelo classificar incorretamente, alucinar ou gerar conteúdo não permitido, comprometendo a segurança e a confiança.

- **Sensitive Data Disclosure**: O modelo revela informações privadas ou confidenciais de seus dados de treinamento ou do contexto do usuário, violando a privacidade e as regulamentações.

- **Inferred Sensitive Data**: O modelo deduz atributos pessoais que nunca foram fornecidos, criando novos danos à privacidade por meio de inferência.

- **Insecure Model Output**: Respostas não sanitizadas transmitem código prejudicial, desinformação ou conteúdo inadequado aos usuários ou sistemas downstream.

- **Rogue Actions**: Agentes integrados autonomamente executam operações não intencionais no mundo real (gravações de arquivos, chamadas de API, compras etc.) sem supervisão adequada do usuário.

## Matriz MITRE AI ATLAS

A [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) fornece uma estrutura abrangente para compreender e mitigar riscos associados a sistemas de IA. Ela categoriza várias técnicas e táticas de ataque que adversários podem usar contra modelos de IA e também como usar sistemas de IA para realizar diferentes ataques.<sup>[[12]](#references)</sup>

## LLMJacking (Roubo e Revenda de Tokens de Acesso a LLMs Hospedados na Cloud)

Atacantes roubam tokens de sessão ativos ou credenciais de API da cloud e invocam LLMs pagos e hospedados na cloud sem autorização. O acesso costuma ser revendido por meio de reverse proxies que usam a conta da vítima, por exemplo, deployments de "oai-reverse-proxy". As consequências incluem perda financeira, uso indevido do modelo fora da política e atribuição das ações ao tenant da vítima.<sup>[[2]](#references)[[3]](#references)</sup>

TTPs:
- Coletar tokens de máquinas de desenvolvedores ou browsers infectados; roubar secrets de CI/CD; comprar cookies vazados.
- Configurar um reverse proxy que encaminha requests ao provedor legítimo, ocultando a chave upstream e multiplexando vários clientes.
- Abusar de endpoints de base-model diretos para contornar guardrails empresariais e rate limits.

Mitigações:
- Vincular tokens à impressão digital do dispositivo, intervalos de IP e atestação do cliente; impor expirações curtas e renovar com MFA.
- Limitar as chaves ao mínimo necessário (sem acesso a ferramentas, somente leitura quando aplicável); fazer rotation diante de anomalias.
- Encerrar todo o tráfego no servidor, atrás de um policy gateway que imponha filtros de segurança, quotas por rota e isolamento de tenants.
- Monitorar padrões de uso incomuns (picos repentinos de gastos, regiões atípicas, strings de UA) e revogar automaticamente sessões suspeitas.
- Preferir mTLS ou JWTs assinados emitidos pelo seu IdP em vez de chaves de API estáticas de longa duração.

## Hardening de inferência de LLM self-hosted

Executar um servidor local de LLM para dados confidenciais cria uma attack surface diferente das APIs hospedadas na cloud: endpoints de inferência/debug podem vazar prompts, a serving stack geralmente expõe um reverse proxy e os device nodes de GPU fornecem acesso a grandes superfícies de `ioctl()`. Se você estiver avaliando ou implantando um serviço de inferência on-premises, revise pelo menos os seguintes pontos.<sup>[[4]](#references)</sup>

### Vazamento de prompts por meio de endpoints de debug e monitoramento

Trate a API de inferência como um **serviço sensível multiusuário**. Rotas de debug ou monitoramento podem expor o conteúdo dos prompts, o estado dos slots, metadados do modelo ou informações sobre a fila interna. No `llama.cpp`, o endpoint `/slots` é especialmente sensível porque expõe o estado por slot e destina-se apenas à inspeção/gerenciamento de slots.<sup>[[4]](#references)[[5]](#references)</sup>

- Coloque um reverse proxy na frente do servidor de inferência e **negue por padrão**.
- Permita somente as combinações exatas de método HTTP + path necessárias ao cliente/UI.
- Desabilite endpoints de introspecção no próprio backend sempre que possível, por exemplo `llama-server --no-slots`.
- Vincule o reverse proxy a `127.0.0.1` e exponha-o por meio de um transporte autenticado, como o encaminhamento local de portas via SSH, em vez de publicá-lo na LAN.

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
### Containers sem root, sem rede e com sockets UNIX

Se o daemon de inferência for compatível com a escuta em um socket UNIX, prefira essa opção ao TCP e execute o container com **nenhuma pilha de rede**:
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
- `--network none` remove a exposição TCP/IP de entrada/saída e evitam user-mode helpers que containers rootless precisariam de outra forma.
- Um UNIX socket permite usar permissões/ACLs POSIX no caminho do socket como primeira camada de controle de acesso.
- `--userns=keep-id` e o Podman rootless reduzem o impacto de um container breakout, pois o root do container não é o root do host.
- Model mounts somente leitura reduzem a possibilidade de adulteração do modelo de dentro do container.

### Minimização de device nodes da GPU

Para inference com GPU, os arquivos `/dev/nvidia*` são superfícies de ataque locais de alto valor, pois expõem grandes handlers `ioctl()` do driver e possíveis caminhos compartilhados de gerenciamento de memória da GPU.<sup>[[4]](#references)</sup>

- Não deixe `/dev/nvidia*` com permissão de escrita para todos.
- Restrinja `nvidia`, `nvidiactl` e `nvidia-uvm` com `NVreg_DeviceFileUID/GID/Mode`, regras do udev e ACLs, para que somente o UID mapeado do container possa abri-los.
- Faça blacklist de módulos desnecessários, como `nvidia_drm`, `nvidia_modeset` e `nvidia_peermem`, em hosts de inference headless.
- Pré-carregue apenas os módulos necessários durante o boot, em vez de permitir que o runtime execute `modprobe` oportunisticamente durante a inicialização do inference.

Exemplo:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
Um ponto importante da revisão é **`/dev/nvidia-uvm`**. Mesmo que o workload não use explicitamente `cudaMallocManaged()`, runtimes CUDA recentes ainda podem exigir `nvidia-uvm`. Como esse device é compartilhado e gerencia a memória virtual da GPU, trate-o como uma superfície de exposição de dados cross-tenant. Se o backend de inferência oferecer suporte, um backend Vulkan pode ser uma alternativa interessante, pois pode evitar completamente a exposição de `nvidia-uvm` ao container.

### Confinamento LSM para inference workers

AppArmor/SELinux/seccomp devem ser usados como defesa em profundidade ao redor do processo de inferência:<sup>[[4]](#references)</sup>

- Permita apenas as shared libraries, model paths, socket directory e GPU device nodes que forem realmente necessários.
- Negue explicitamente capabilities de alto risco, como `sys_admin`, `sys_module`, `sys_rawio` e `sys_ptrace`.
- Mantenha o model directory somente para leitura e limite os writable paths apenas aos runtime socket/cache directories.
- Monitore os denial logs, pois eles fornecem telemetry útil de detecção quando o model server ou um post-exploitation payload tenta escapar do seu comportamento esperado.

Exemplo de regras AppArmor para um worker com suporte a GPU:
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
## Phantom Squatting: Domínios alucinados por LLM como vetor de AI Supply Chain

Phantom squatting é o **equivalente de domínio/URL do slopsquatting**. Em vez de alucinar o nome de um pacote inexistente, o LLM alucina um **domínio plausível de portal, API, webhook, billing, SSO, download ou suporte** para uma marca real, e um atacante registra esse namespace antes que um humano ou agente o utilize.<sup>[[8]](#references)[[9]](#references)</sup>

Isso é importante porque, em muitos fluxos de trabalho assistidos por AI, a saída do modelo é tratada como uma **dependência confiável**:
- Desenvolvedores colam o endpoint sugerido em código ou integrações de CI/CD.
- Agentes de AI obtêm documentação, schemas, APKs, ZIPs ou destinos de webhook automaticamente.
- Runbooks ou documentos gerados podem incorporar a URL falsa como se fosse oficial.

### Fluxo de trabalho ofensivo

1. **Sondar a superfície de alucinação**: faça perguntas específicas sobre marcas e fluxos de trabalho realistas, como portais de `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` ou `mobile app`.
2. **Normalizar candidatos**: resolva as URLs geradas, reduza respostas NXDOMAIN ao domínio pai registrável e remova duplicatas entre famílias de prompts. Os corpora de prompts devem permanecer diversificados, por exemplo, eliminando quase duplicatas com **similaridade de Jaccard**.
3. **Priorizar alucinações previsíveis**:
- **Thermal Hallucination Persistence (THP)**: o mesmo domínio falso aparece em diferentes temperaturas, inclusive em temperaturas baixas como `T=0.1`.
- **Consenso entre modelos**: várias famílias de LLM geram o mesmo domínio falso.
4. **Registrar e weaponize** o domínio pai; depois, hospede phishing, downloads falsos de APK/ZIP, coletores de credenciais, documentos maliciosos ou endpoints de API que coletem secrets/payloads de webhook. **Alucinações puramente no nível do domínio** são as mais fáceis de monetizar porque o atacante controla todo o namespace; alucinações de subdomínio/caminho ainda podem ser abusadas quando o domínio pai normalizado não está registrado.
5. **Explorar a janela de reputação zero**: domínios recém-registrados geralmente não possuem histórico em blocklists, reputação de URL ou telemetria madura, podendo contornar controles até que as detecções sejam atualizadas. Atacantes podem ampliar essa janela usando respostas benignas apenas para crawlers, redirect cloaking, gates de CAPTCHA ou staging atrasado do payload.

### Por que isso é perigoso para agentes

Para uma vítima humana, o domínio falso normalmente ainda exige um clique e outra ação. Em um **fluxo de trabalho agentic**, o LLM pode ser tanto a **isca** quanto o **executor**: o agente recebe a URL alucinada, acessa-a, analisa a resposta e pode então vazar tokens, executar instruções, baixar uma dependência ou inserir dados envenenados no CI/CD sem qualquer revisão humana.<sup>[[8]](#references)</sup>

### Prompts ofensivos práticos

Prompts de alto rendimento geralmente se parecem com tarefas empresariais normais, em vez de iscas explícitas de phishing:
- “Qual é a URL do sandbox de pagamento para integrações de `<brand>`?”
- “Qual endpoint de webhook devo usar para notificações de build de `<brand>`?”
- “Onde fica o portal de benefícios dos funcionários / billing / SSO de `<brand>`?”
- “Forneça o download direto do APK Android ou do cliente desktop de `<brand>`.”

### Inversão defensiva

Trate isso como um problema de monitoramento proativo de domínios, não apenas como um problema de prompt injection:
- Crie um **corpus de prompts de marcas** e faça sondagens periódicas nos LLMs dos quais seus usuários/agentes dependem.
- Armazene as URLs alucinadas e acompanhe quais permanecem estáveis entre temperaturas/modelos.
- Acompanhe a **Adversarial Exploitation Window (AEW)**: o tempo entre a primeira alucinação e o registro pelo atacante. Uma AEW positiva significa que os defensores podem registrar previamente, criar um sinkhole ou bloquear previamente antes da weaponization.
- Monitore transições de **NXDOMAIN → registrado** para os domínios pai.
- Após o registro, analise registrar, data de criação, nameservers, privacy shielding, conteúdo da página, screenshots, status de página estacionada e similaridade com ativos da marca.
- Adicione gates de política para que agentes/desenvolvedores **não confiem em domínios gerados por LLM por padrão**: exija allowlists, validação de propriedade, verificações de CT/RDAP ou aprovação humana antes do primeiro uso.

Isso se enquadra simultaneamente em várias categorias de risco de AI: **AI supply-chain attack**, **insecure model output** e **rogue actions** quando agentes consomem autonomamente a URL alucinada.

## Referências
- [1] [Unit 42 – Os riscos dos LLMs de assistentes de código: conteúdo prejudicial, uso indevido e deception](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [2] [Visão geral do esquema de LLMJacking – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [3] [oai-reverse-proxy (revenda de acesso roubado a LLM)](https://gitgud.io/khanon/oai-reverse-proxy)
- [4] [Synacktiv - Análise aprofundada da implantação de um servidor LLM on-premise com poucos privilégios](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [5] [README do servidor llama.cpp](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [6] [Quadlets do Podman: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [7] [Especificação da Container Device Interface (CDI) da CNCF](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [8] [Unit 42 – Phantom Squatting: domínios alucinados por AI como vetor de Software Supply Chain](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [9] [Socket – Slopsquatting: como as alucinações de AI estão alimentando uma nova classe de ataques à Supply Chain](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)
- [10] [As 10 principais vulnerabilidades de Machine Learning da OWASP](https://owasp.org/www-project-machine-learning-security-top-10/)
- [11] [Riscos do Google SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks)
- [12] [Matriz MITRE AI ATLAS](https://atlas.mitre.org/matrices/ATLAS)

{{#include ../banners/hacktricks-training.md}}
