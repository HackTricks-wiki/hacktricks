# Riscos de IA

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

A Owasp identificou as 10 principais vulnerabilidades de machine learning que podem afetar sistemas de IA. Essas vulnerabilidades podem levar a vários problemas de segurança, incluindo data poisoning, model inversion e adversarial attacks. Entender essas vulnerabilidades é essencial para criar sistemas de IA seguros.

Para consultar uma lista atualizada e detalhada das 10 principais vulnerabilidades de machine learning, consulte o projeto [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).<sup>[[1]](#references)</sup>

- **Input Manipulation Attack**: Um atacante adiciona pequenas alterações, muitas vezes invisíveis, aos **dados recebidos**, fazendo o modelo tomar a decisão errada.\
*Exemplo*: Alguns pontos de tinta em uma placa de "pare" fazem um carro autônomo "enxergar" uma placa de limite de velocidade.

- **Data Poisoning Attack**: O **training set** é deliberadamente contaminado com amostras maliciosas, ensinando regras prejudiciais ao modelo.\
*Exemplo*: Binários de malware são rotulados incorretamente como "benignos" em um corpus de treinamento de antivírus, permitindo que malwares semelhantes passem despercebidos posteriormente.

- **Model Inversion Attack**: Ao sondar as saídas, um atacante cria um **modelo reverso** que reconstrói características sensíveis das entradas originais.\
*Exemplo*: Recriar a imagem de ressonância magnética de um paciente a partir das previsões de um modelo de detecção de câncer.

- **Membership Inference Attack**: O adversário testa se um **registro específico** foi usado durante o treinamento, identificando diferenças nos níveis de confiança.\
*Exemplo*: Confirmar que uma transação bancária de uma pessoa aparece nos dados de treinamento de um modelo de detecção de fraude.

- **Model Theft**: Consultas repetidas permitem que um atacante aprenda os limites de decisão e **clone o comportamento do modelo** (e sua propriedade intelectual).\
*Exemplo*: Coletar pares suficientes de perguntas e respostas de uma API de ML-as-a-Service para criar um modelo local quase equivalente.

- **AI Supply-Chain Attack**: Comprometer qualquer componente (dados, bibliotecas, pesos pré-treinados, CI/CD) no **pipeline de ML** para corromper os modelos downstream.\
*Exemplo*: Uma dependency envenenada em um model-hub instala um modelo de análise de sentimento com backdoor em vários aplicativos.

- **Transfer Learning Attack**: Uma lógica maliciosa é inserida em um **modelo pré-treinado** e sobrevive ao fine-tuning na tarefa da vítima.\
*Exemplo*: Uma rede backbone de visão computacional com um trigger oculto continua invertendo rótulos após ser adaptada para imagens médicas.

- **Model Skewing**: Dados sutilmente tendenciosos ou rotulados incorretamente **alteram as saídas do modelo** para favorecer a agenda do atacante.\
*Exemplo*: Injetar e-mails de spam "limpos" rotulados como ham para que um filtro de spam permita a passagem de e-mails futuros semelhantes.

- **Output Integrity Attack**: O atacante **altera as previsões do modelo durante o trânsito**, sem modificar o próprio modelo, enganando os sistemas downstream.\
*Exemplo*: Alterar o veredito "malicioso" de um classificador de malware para "benigno" antes que o estágio de quarentena do arquivo o receba.

- **Model Poisoning** --- Alterações diretas e direcionadas nos **parâmetros do modelo**, geralmente após obter acesso de escrita, para modificar seu comportamento.\
*Exemplo*: Ajustar os pesos de um modelo de detecção de fraude em produção para que transações de determinados cartões sejam sempre aprovadas.


## Riscos do Google SAIF

O [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/) do Google descreve vários riscos associados a sistemas de IA:<sup>[[2]](#references)</sup>

- **Data Poisoning**: Atores maliciosos alteram ou injetam dados de treinamento/tuning para degradar a precisão, implantar backdoors ou distorcer resultados, comprometendo a integridade do modelo em todo o ciclo de vida dos dados.

- **Unauthorized Training Data**: A ingestão de datasets protegidos por direitos autorais, sensíveis ou não autorizados cria responsabilidades legais, éticas e de desempenho, pois o modelo aprende com dados que nunca teve permissão para usar.

- **Model Source Tampering**: A manipulação da supply chain ou por agentes internos do código, das dependências ou dos pesos do modelo antes ou durante o treinamento pode inserir lógica oculta que persiste mesmo após o retraining.

- **Excessive Data Handling**: Controles fracos de retenção e governança de dados fazem com que os sistemas armazenem ou processem mais dados pessoais do que o necessário, aumentando a exposição e o risco de não conformidade.

- **Model Exfiltration**: Atacantes roubam arquivos/pesos do modelo, causando perda de propriedade intelectual e permitindo serviços imitadores ou ataques subsequentes.

- **Model Deployment Tampering**: Adversários modificam artefatos do modelo ou a infraestrutura de serving, fazendo com que o modelo em execução seja diferente da versão validada e potencialmente alterando seu comportamento.

- **Denial of ML Service**: Inundar APIs ou enviar entradas “sponge” pode esgotar capacidade computacional/energia e deixar o modelo offline, reproduzindo ataques clássicos de DoS.

- **Model Reverse Engineering**: Ao coletar grandes quantidades de pares de entrada e saída, atacantes podem clonar ou destilar o modelo, alimentando produtos imitadores e ataques adversariais personalizados.

- **Insecure Integrated Component**: Plugins, agents ou serviços upstream vulneráveis permitem que atacantes injetem código ou escalem privilégios dentro do pipeline de IA.

- **Prompt Injection**: Criar prompts (direta ou indiretamente) para inserir instruções que substituem a intenção do sistema, fazendo com que o modelo execute comandos não pretendidos.

- **Model Evasion**: Entradas cuidadosamente elaboradas fazem o modelo classificar incorretamente, alucinar ou produzir conteúdo não permitido, prejudicando a segurança e a confiança.

- **Sensitive Data Disclosure**: O modelo revela informações privadas ou confidenciais de seus dados de treinamento ou do contexto do usuário, violando a privacidade e regulamentações.

- **Inferred Sensitive Data**: O modelo deduz atributos pessoais que nunca foram fornecidos, criando novos danos à privacidade por meio de inferência.

- **Insecure Model Output**: Respostas não sanitizadas passam código malicioso, desinformação ou conteúdo inadequado para usuários ou sistemas downstream.

- **Rogue Actions**: Agents integrados de forma autônoma executam operações não pretendidas no mundo real (escritas em arquivos, chamadas de API, compras etc.) sem supervisão adequada do usuário.

## Mitre AI ATLAS Matrix

A [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) oferece um framework abrangente para entender e mitigar riscos associados a sistemas de IA. Ela categoriza várias técnicas e táticas de ataque que adversários podem usar contra modelos de IA e também como usar sistemas de IA para realizar diferentes ataques.<sup>[[3]](#references)</sup>

## LLMJacking (Roubo de Tokens e Revenda de Acesso a LLM Hospedados na Cloud)

Atacantes roubam tokens de sessão ativos ou credenciais de API da cloud e utilizam LLMs pagos e hospedados na cloud sem autorização. O acesso costuma ser revendido por meio de reverse proxies que usam a conta da vítima, por exemplo, deployments de "oai-reverse-proxy". As consequências incluem perda financeira, uso indevido do modelo fora da política e atribuição das ações ao tenant da vítima.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

TTPs:
- Coletar tokens de máquinas de desenvolvimento ou browsers infectados; roubar secrets de CI/CD; comprar cookies vazados.<sup>[[5]](#references)</sup>
- Criar um reverse proxy que encaminha requisições ao provedor legítimo, ocultando a chave upstream e multiplexando vários clientes.<sup>[[5]](#references)[[7]](#references)</sup>
- Abusar de endpoints diretos do modelo-base para contornar guardrails corporativos e limites de taxa.<sup>[[4]](#references)</sup>

Mitigações:
- Vincular tokens à fingerprint do dispositivo, a intervalos de IP e à atestação do cliente; aplicar expirações curtas e renovar com MFA.
- Limitar as chaves ao mínimo necessário (sem acesso a tools, somente leitura quando aplicável); fazer rotation ao detectar anomalias.
- Encerrar todo o tráfego no lado do servidor, atrás de um policy gateway que aplique filtros de segurança, quotas por rota e isolamento de tenants.
- Monitorar padrões de uso incomuns (picos repentinos de gastos, regiões atípicas, strings de UA) e revogar automaticamente sessões suspeitas.
- Preferir mTLS ou JWTs assinados emitidos pelo seu IdP em vez de API keys estáticas de longa duração.

## Hardening de inferência de LLM self-hosted

Executar um servidor local de LLM para dados confidenciais cria uma attack surface diferente daquela das APIs hospedadas na cloud: endpoints de inferência/debug podem vazar prompts, a serving stack geralmente expõe um reverse proxy e os device nodes da GPU fornecem acesso a grandes superfícies de `ioctl()`. Se você estiver avaliando ou implementando um serviço de inferência on-premises, revise pelo menos os pontos a seguir.<sup>[[8]](#references)</sup>

### Vazamento de prompts por meio de endpoints de debug e monitoramento

Trate a API de inferência como um **serviço sensível multiusuário**. Rotas de debug ou monitoramento podem expor o conteúdo dos prompts, o estado dos slots, metadados do modelo ou informações sobre filas internas. No `llama.cpp`, o endpoint `/slots` é especialmente sensível porque expõe o estado de cada slot e destina-se apenas à inspeção/gerenciamento de slots.<sup>[[8]](#references)</sup>

- Coloque um reverse proxy na frente do servidor de inferência e **negue por padrão**.
- Permita somente as combinações exatas de método HTTP + caminho necessárias ao cliente/UI.
- Desabilite endpoints de introspecção no próprio backend sempre que possível, por exemplo, `llama-server --no-slots`.<sup>[[9]](#references)</sup>
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
### Containers rootless sem rede e sockets UNIX

Se o daemon de inferência for compatível com a escuta em um socket UNIX, prefira essa opção em vez de TCP e execute o container com **nenhuma pilha de rede**:<sup>[[8]](#references)</sup>
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
- `--network none` remove a exposição TCP/IP de entrada/saída e evita helpers em user mode que, de outra forma, os containers rootless precisariam.
- Um UNIX socket permite usar permissões/ACLs POSIX no caminho do socket como a primeira camada de controle de acesso.
- `--userns=keep-id` e o Podman rootless reduzem o impacto de um container breakout, pois o root do container não é o root do host.
- Montagens de modelos somente leitura reduzem a probabilidade de adulteração do modelo a partir de dentro do container.

### Minimização de device nodes da GPU

Para inferência baseada em GPU, os arquivos `/dev/nvidia*` são superfícies de ataque locais de alto valor, pois expõem grandes handlers de `ioctl()` do driver e possíveis caminhos compartilhados de gerenciamento de memória da GPU.<sup>[[8]](#references)</sup>

- Não deixe `/dev/nvidia*` graváveis por todos.
- Restrinja `nvidia`, `nvidiactl` e `nvidia-uvm` com `NVreg_DeviceFileUID/GID/Mode`, regras do udev e ACLs, de modo que somente o UID mapeado do container possa abri-los.
- Coloque na blacklist módulos desnecessários, como `nvidia_drm`, `nvidia_modeset` e `nvidia_peermem`, em hosts de inferência headless.
- Carregue previamente apenas os módulos necessários durante o boot, em vez de permitir que o runtime execute `modprobe` oportunisticamente durante a inicialização da inferência.

Exemplo:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
Um ponto importante da revisão é **`/dev/nvidia-uvm`**. Mesmo que o workload não use explicitamente `cudaMallocManaged()`, runtimes recentes do CUDA ainda podem exigir `nvidia-uvm`. Como esse dispositivo é compartilhado e gerencia a memória virtual da GPU, trate-o como uma superfície de exposição de dados entre tenants. Se o backend de inferência oferecer suporte, um backend Vulkan pode ser uma alternativa interessante, pois talvez evite expor `nvidia-uvm` ao container. <sup>[[8]](#references)</sup>

### Confinamento LSM para inference workers

AppArmor/SELinux/seccomp devem ser usados como defesa em profundidade ao redor do processo de inferência:<sup>[[8]](#references)</sup>

- Permita somente as bibliotecas compartilhadas, os caminhos dos modelos, o diretório de sockets e os nós de dispositivos da GPU realmente necessários.
- Negue explicitamente recursos de alto risco, como `sys_admin`, `sys_module`, `sys_rawio` e `sys_ptrace`.
- Mantenha o diretório do modelo somente para leitura e restrinja os caminhos graváveis apenas aos diretórios de sockets/cache do runtime.
- Monitore os logs de negação, pois eles fornecem telemetria útil para detecção quando o model server ou um payload de post-exploitation tenta escapar de seu comportamento esperado.

Exemplo de regras do AppArmor para um worker baseado em GPU:
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

Phantom squatting é o **equivalente de domínio/URL do slopsquatting**. Em vez de alucinar o nome de um pacote inexistente, o LLM alucina um **domínio plausível de portal, API, webhook, cobrança, SSO, download ou suporte** de uma marca real, e um atacante registra esse namespace antes que um humano ou agente o utilize.<sup>[[12]](#references)[[13]](#references)</sup>

Isso é importante porque, em muitos fluxos de trabalho assistidos por AI, a saída do modelo é tratada como uma **dependência confiável**:
- Desenvolvedores colam o endpoint sugerido no código ou em integrações de CI/CD.
- Agentes de AI obtêm automaticamente documentação, schemas, APKs, ZIPs ou destinos de webhook.
- Runbooks ou documentos gerados podem incorporar a URL falsa como se fosse autoritativa.

### Fluxo de trabalho ofensivo

1. **Sonde a superfície de alucinação**: faça perguntas específicas sobre marcas e relacionadas a fluxos de trabalho realistas, como portais de `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` ou `mobile app`.<sup>[[12]](#references)</sup>
2. **Normalize os candidatos**: resolva as URLs geradas, reduza as respostas NXDOMAIN ao domínio pai registrável e elimine duplicatas entre famílias de prompts. Os corpora de prompts devem permanecer diversos, por exemplo, removendo quase duplicatas com **similaridade de Jaccard**.
3. **Priorize alucinações previsíveis**:
- **Thermal Hallucination Persistence (THP)**: o mesmo domínio falso aparece em diferentes temperaturas, incluindo temperaturas baixas como `T=0.1`.
- **Consenso entre modelos**: várias famílias de LLM geram o mesmo domínio falso.
4. **Registre e weaponize** o domínio pai, depois hospede phishing, downloads falsos de APK/ZIP, credential harvesters, documentos maliciosos ou endpoints de API que coletem secrets/payloads de webhook. **Alucinações puramente no nível de domínio** são as mais fáceis de monetizar porque o atacante controla todo o namespace; alucinações de subdomínio/caminho ainda podem ser abusadas quando o domínio pai normalizado não está registrado.
5. **Explore a janela de reputação zero**: domínios recém-registrados geralmente não possuem histórico em blocklists, reputação de URL nem telemetria madura, podendo assim contornar controles até que as detecções se atualizem. Os atacantes podem ampliar essa janela usando respostas benignas apenas para crawlers, redirect cloaking, CAPTCHA gates ou staging atrasado de payloads.

### Por que isso é perigoso para agentes

Para uma vítima humana, o domínio falso geralmente ainda exige um clique e outra ação. Em um **fluxo de trabalho agentic**, o LLM pode ser tanto a **isca** quanto o **executor**: o agente recebe a URL alucinada, acessa-a, analisa a resposta e pode então vazar tokens, executar instruções, fazer download de uma dependência ou inserir dados envenenados no CI/CD sem qualquer revisão humana.<sup>[[12]](#references)</sup>

### Prompts ofensivos práticos

Prompts de alto rendimento normalmente se parecem com tarefas corporativas comuns, em vez de iscas explícitas de phishing:<sup>[[12]](#references)</sup>
- “Qual é a URL do payment sandbox para integrações de `<brand>`?”
- “Qual endpoint de webhook devo usar para notificações de build de `<brand>`?”
- “Onde fica o portal de employee benefits / billing / SSO de `<brand>`?”
- “Forneça o download direto do APK Android ou do cliente desktop de `<brand>`.”

### Inversão defensiva

Trate isso como um problema proativo de monitoramento de domínios, não apenas como um problema de prompt injection:<sup>[[12]](#references)</sup>
- Crie um **corpus de prompts de marcas** e sonde periodicamente os LLMs dos quais seus usuários/agentes dependem.
- Armazene as URLs alucinadas e acompanhe quais permanecem estáveis entre temperaturas/modelos.
- Acompanhe a **Adversarial Exploitation Window (AEW)**: o tempo entre a primeira alucinação e o registro pelo atacante. Uma AEW positiva significa que os defensores podem registrar previamente, fazer sinkhole ou bloquear previamente antes da weaponization.
- Monitore as transições **NXDOMAIN → registrado** dos domínios pai.
- Após o registro, faça a triagem do registrar, data de criação, nameservers, privacy shielding, conteúdo da página, screenshots, status de página estacionada e similaridade com os assets da marca.
- Adicione policy gates para que agentes/desenvolvedores **não confiem por padrão em domínios gerados por LLM**: exija allowlists, validação de propriedade, verificações de CT/RDAP ou aprovação humana antes do primeiro uso.

Isso se encaixa simultaneamente em várias categorias de risco de AI: **AI supply-chain attack**, **insecure model output** e **rogue actions** quando agentes consomem autonomamente a URL alucinada.

## Referências

- [1] [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google SAIF (Secure AI Framework) – Risks](https://saif.google/secure-ai-framework/risks)
- [3] [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS)
- [4] [Unit 42 – The Risks of Code Assistant LLMs: Harmful Content, Misuse and Deception](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [5] [Sysdig – LLMjacking: Stolen Cloud Credentials Used in New AI Attack](https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/)
- [6] [LLMJacking scheme overview – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [7] [oai-reverse-proxy (reselling stolen LLM access)](https://gitgud.io/khanon/oai-reverse-proxy)
- [8] [Synacktiv - Deep-dive into the deployment of an on-premise low-privileged LLM server](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [9] [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [10] [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [11] [CNCF Container Device Interface (CDI) specification](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [12] [Unit 42 – Phantom Squatting: AI-Hallucinated Domains as a Software Supply Chain Vector](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [13] [Socket – Slopsquatting: How AI Hallucinations Are Fueling a New Class of Supply Chain Attacks](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)

{{#include ../banners/hacktricks-training.md}}
