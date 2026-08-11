# Riscos de IA

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

A Owasp identificou as 10 principais vulnerabilidades de machine learning que podem afetar sistemas de IA. Essas vulnerabilidades podem levar a vários problemas de segurança, incluindo data poisoning, model inversion e adversarial attacks. Entender essas vulnerabilidades é essencial para criar sistemas de IA seguros.

Para obter uma lista atualizada e detalhada das 10 principais vulnerabilidades de machine learning, consulte o projeto [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).<sup>[[1]](#references)</sup>

- **Input Manipulation Attack**: Um atacante adiciona pequenas alterações, muitas vezes invisíveis, aos **dados de entrada** para fazer o modelo tomar a decisão errada.\
*Exemplo*: Alguns pontos de tinta em uma placa de pare fazem um carro autônomo "enxergar" uma placa de limite de velocidade.

- **Data Poisoning Attack**: O **conjunto de treinamento** é deliberadamente contaminado com amostras maliciosas, ensinando regras prejudiciais ao modelo.\
*Exemplo*: Binários de malware são classificados incorretamente como "benignos" em um corpus de treinamento de antivírus, permitindo que malwares semelhantes passem despercebidos posteriormente.

- **Model Inversion Attack**: Ao sondar as saídas, um atacante cria um **modelo reverso** que reconstrói características sensíveis das entradas originais.\
*Exemplo*: Recriar a imagem de ressonância magnética de um paciente a partir das previsões de um modelo de detecção de câncer.

- **Membership Inference Attack**: O adversário testa se um **registro específico** foi usado durante o treinamento, observando diferenças nos níveis de confiança.\
*Exemplo*: Confirmar que uma transação bancária de uma pessoa aparece nos dados de treinamento de um modelo de detecção de fraude.

- **Model Theft**: Consultas repetidas permitem que um atacante aprenda os limites de decisão e **clone o comportamento do modelo** (e sua propriedade intelectual).\
*Exemplo*: Coletar pares suficientes de perguntas e respostas de uma API de ML-as-a-Service para criar um modelo local quase equivalente.

- **AI Supply-Chain Attack**: Comprometer qualquer componente (dados, bibliotecas, pesos pré-treinados, CI/CD) no **pipeline de ML** para corromper os modelos downstream.\
*Exemplo*: Uma dependência envenenada em um model hub instala um modelo de análise de sentimento com backdoor em vários aplicativos.

- **Transfer Learning Attack**: Uma lógica maliciosa é inserida em um **modelo pré-treinado** e sobrevive ao fine-tuning na tarefa da vítima.\
*Exemplo*: Um backbone de visão computacional com um gatilho oculto continua invertendo rótulos após ser adaptado para imagens médicas.

- **Model Skewing**: Dados sutilmente enviesados ou rotulados incorretamente **alteram as saídas do modelo** para favorecer a agenda do atacante.\
*Exemplo*: Injetar e-mails de spam "limpos" rotulados como ham para que um filtro de spam permita a passagem de e-mails semelhantes no futuro.

- **Output Integrity Attack**: O atacante **altera as previsões do modelo em trânsito**, e não o próprio modelo, enganando os sistemas downstream.\
*Exemplo*: Alterar o veredito "malicioso" de um classificador de malware para "benigno" antes que o estágio de quarentena de arquivos o veja.

- **Model Poisoning** --- Alterações diretas e direcionadas nos **parâmetros do modelo**, geralmente após obter acesso de escrita, para modificar seu comportamento.\
*Exemplo*: Ajustar os pesos de um modelo de detecção de fraude em produção para que transações de determinados cartões sejam sempre aprovadas.


## Riscos do Google SAIF

O [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework) do Google descreve vários riscos associados a sistemas de IA:<sup>[[2]](#references)</sup>

- **Data Poisoning**: Atores maliciosos alteram ou injetam dados de treinamento/tuning para degradar a precisão, implantar backdoors ou distorcer os resultados, comprometendo a integridade do modelo durante todo o ciclo de vida dos dados.

- **Dados de Treinamento Não Autorizados**: A ingestão de datasets protegidos por direitos autorais, sensíveis ou não autorizados cria responsabilidades legais, éticas e de desempenho, pois o modelo aprende com dados que nunca teve permissão para usar.

- **Adulteração da Origem do Modelo**: A manipulação da cadeia de suprimentos ou por insiders do código, das dependências ou dos pesos do modelo antes ou durante o treinamento pode inserir uma lógica oculta que persiste mesmo após o retraining.

- **Processamento Excessivo de Dados**: Controles fracos de retenção e governança de dados fazem com que os sistemas armazenem ou processem mais dados pessoais do que o necessário, aumentando a exposição e o risco de não conformidade.

- **Exfiltração do Modelo**: Atacantes roubam arquivos/pesos do modelo, causando perda de propriedade intelectual e permitindo serviços imitadores ou ataques subsequentes.

- **Adulteração da Implantação do Modelo**: Adversários modificam artefatos do modelo ou a infraestrutura de serving para que o modelo em execução seja diferente da versão validada, podendo alterar seu comportamento.

- **Negação de Serviço de ML**: Inundar APIs ou enviar entradas “sponge” pode esgotar recursos computacionais/energia e deixar o modelo offline, reproduzindo ataques clássicos de DoS.

- **Engenharia Reversa do Modelo**: Ao coletar grandes quantidades de pares de entrada e saída, os atacantes podem clonar ou destilar o modelo, impulsionando produtos imitadores e ataques adversariais personalizados.

- **Componente Integrado Inseguro**: Plugins, agentes ou serviços upstream vulneráveis permitem que atacantes injetem código ou escalem privilégios no pipeline de IA.

- **Prompt Injection**: Criar prompts, direta ou indiretamente, para inserir instruções que substituam a intenção do sistema, fazendo o modelo executar comandos não pretendidos.

- **Model Evasion**: Entradas cuidadosamente projetadas fazem o modelo classificar incorretamente, alucinar ou produzir conteúdo proibido, comprometendo a segurança e a confiança.

- **Divulgação de Dados Sensíveis**: O modelo revela informações privadas ou confidenciais de seus dados de treinamento ou do contexto do usuário, violando a privacidade e regulamentações.

- **Dados Sensíveis Inferidos**: O modelo deduz atributos pessoais que nunca foram fornecidos, criando novos danos à privacidade por meio de inferência.

- **Saída Insegura do Modelo**: Respostas não sanitizadas transmitem código prejudicial, desinformação ou conteúdo inadequado aos usuários ou sistemas downstream.

- **Ações Não Autorizadas**: Agentes integrados de forma autônoma executam operações reais não pretendidas (gravações de arquivos, chamadas de API, compras etc.) sem supervisão adequada do usuário.

## Matriz MITRE AI ATLAS

A [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) fornece uma estrutura abrangente para entender e mitigar riscos associados a sistemas de IA. Ela categoriza diversas técnicas e táticas de ataque que adversários podem usar contra modelos de IA, além de mostrar como usar sistemas de IA para realizar diferentes ataques.<sup>[[3]](#references)</sup>

## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Atacantes roubam tokens de sessão ativos ou credenciais de API da cloud e invocam LLMs pagos e hospedados na cloud sem autorização. O acesso frequentemente é revendido por meio de reverse proxies que usam a conta da vítima, por exemplo, implantações de "oai-reverse-proxy". As consequências incluem prejuízo financeiro, uso indevido do modelo fora da política e atribuição das ações ao tenant da vítima.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

TTPs:
- Coletar tokens de máquinas ou browsers de desenvolvedores infectados; roubar secrets de CI/CD; comprar cookies em leak.<sup>[[5]](#references)</sup>
- Configurar um reverse proxy que encaminha solicitações ao provedor legítimo, ocultando a chave upstream e multiplexando vários clientes.<sup>[[5]](#references)</sup><sup>[[7]](#references)</sup>
- Abusar de endpoints de modelo-base diretos para contornar guardrails corporativos e limites de taxa.<sup>[[4]](#references)</sup>

Mitigações:
- Vincular tokens à impressão digital do dispositivo, intervalos de IP e atestação do cliente; impor expirações curtas e renovar com MFA.
- Definir o escopo mínimo das chaves (sem acesso a ferramentas, somente leitura quando aplicável); fazer rotação diante de anomalias.
- Encerrar todo o tráfego no lado do servidor, atrás de um policy gateway que imponha filtros de segurança, quotas por rota e isolamento de tenants.
- Monitorar padrões de uso incomuns (picos repentinos de gastos, regiões atípicas, strings de UA) e revogar automaticamente sessões suspeitas.
- Preferir mTLS ou JWTs assinados emitidos pelo seu IdP em vez de chaves de API estáticas de longa duração.

## Hardening de inferência de LLM self-hosted

Executar um servidor local de LLM para dados confidenciais cria uma superfície de ataque diferente daquela das APIs hospedadas na cloud: endpoints de inferência/debug podem vazar prompts, a stack de serving geralmente expõe um reverse proxy e os device nodes de GPU fornecem acesso a grandes superfícies de `ioctl()`. Se você estiver avaliando ou implantando um serviço de inferência on-premises, revise pelo menos os pontos a seguir.<sup>[[8]](#references)</sup>

### Vazamento de prompts por endpoints de debug e monitoramento

Trate a API de inferência como um **serviço sensível multiusuário**. Rotas de debug ou monitoramento podem expor o conteúdo dos prompts, o estado dos slots, metadados do modelo ou informações sobre a fila interna. No `llama.cpp`, o endpoint `/slots` é especialmente sensível porque expõe o estado por slot e destina-se apenas à inspeção/gerenciamento de slots.<sup>[[8]](#references)</sup>

- Coloque um reverse proxy na frente do servidor de inferência e **negue por padrão**.
- Permita somente as combinações exatas de método HTTP + caminho necessárias ao cliente/UI.
- Desative endpoints de introspecção no próprio backend sempre que possível, por exemplo `llama-server --no-slots`.<sup>[[9]](#references)</sup>
- Vincule o reverse proxy a `127.0.0.1` e exponha-o por meio de um transporte autenticado, como o encaminhamento local de portas SSH, em vez de publicá-lo na LAN.

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
### Containers rootless sem rede e UNIX sockets

Se o inference daemon permitir escutar em um UNIX socket, prefira essa opção em vez de TCP e execute o container com **no network stack**:<sup>[[8]](#references)</sup>
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
- `--network none` remove a exposição TCP/IP de entrada/saída e evitam helpers em user mode que containers rootless normalmente precisariam.
- Um UNIX socket permite usar permissões/ACLs POSIX no caminho do socket como primeira camada de controle de acesso.
- `--userns=keep-id` e o Podman rootless reduzem o impacto de um container breakout, pois o root do container não é o root do host.
- Montagens de modelos somente leitura reduzem a chance de adulteração dos modelos de dentro do container.

Para deployments persistentes, as mesmas restrições podem ser expressas como unidades do Podman Quadlet. Se o acesso à GPU for delegado por meio do Container Device Interface, mantenha a especificação do dispositivo CDI o mais restrita possível, em vez de expor todos os nós de aceleradores.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>

### Minimização de nós de dispositivo da GPU

Para inferência com GPU, os arquivos `/dev/nvidia*` são superfícies de ataque locais de alto valor, pois expõem grandes handlers de driver `ioctl()` e potencialmente caminhos compartilhados de gerenciamento de memória da GPU.<sup>[[8]](#references)</sup>

- Não deixe `/dev/nvidia*` com permissão de escrita para todos.
- Restrinja `nvidia`, `nvidiactl` e `nvidia-uvm` com `NVreg_DeviceFileUID/GID/Mode`, regras do udev e ACLs, para que somente o UID mapeado do container possa abri-los.
- Coloque na blacklist módulos desnecessários, como `nvidia_drm`, `nvidia_modeset` e `nvidia_peermem`, em hosts de inferência headless.
- Carregue previamente apenas os módulos necessários durante o boot, em vez de permitir que o runtime execute `modprobe` oportunisticamente durante a inicialização da inferência.

Exemplo:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
Um ponto importante da revisão é **`/dev/nvidia-uvm`**. Mesmo que o workload não use explicitamente `cudaMallocManaged()`, runtimes recentes do CUDA ainda podem exigir `nvidia-uvm`. Como esse dispositivo é compartilhado e gerencia a memória virtual da GPU, trate-o como uma superfície de exposição de dados entre tenants. Se o inference backend oferecer suporte, um backend Vulkan pode ser uma alternativa interessante, pois pode evitar completamente a exposição de `nvidia-uvm` ao container.<sup>[[8]](#references)</sup>

### Confinamento por LSM para processos de inferência

AppArmor/SELinux/seccomp devem ser usados como defesa em profundidade ao redor do processo de inferência:<sup>[[8]](#references)</sup>

- Permita somente as shared libraries, os caminhos dos modelos, o diretório de sockets e os nós de dispositivos da GPU realmente necessários.
- Negue explicitamente capabilities de alto risco, como `sys_admin`, `sys_module`, `sys_rawio` e `sys_ptrace`.
- Mantenha o diretório do modelo somente para leitura e limite os caminhos graváveis exclusivamente aos diretórios de socket/cache do runtime.
- Monitore os logs de negação, pois eles fornecem telemetria de detecção útil quando o model server ou um payload de post-exploitation tenta escapar do seu comportamento esperado.

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

Phantom squatting é o **equivalente de domínio/URL do slopsquatting**. Em vez de alucinar um nome de pacote inexistente, o LLM alucina um **domínio plausível de portal, API, webhook, billing, SSO, download ou suporte** para uma marca real, e um atacante registra esse namespace antes que um humano ou agente o utilize.<sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Isso é importante porque, em muitos workflows assistidos por AI, a saída do modelo é tratada como uma **dependência confiável**:
- Desenvolvedores colam o endpoint sugerido no código ou em integrações de CI/CD.
- Agentes de AI buscam automaticamente documentação, schemas, APKs, ZIPs ou destinos de webhook.
- Runbooks ou documentos gerados podem incorporar a URL falsa como se fosse oficial.

### Offensive workflow

1. **Probe the hallucination surface**: faça perguntas específicas sobre marcas e workflows realistas, como portais de `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` ou `mobile app`.<sup>[[12]](#references)</sup>
2. **Normalize candidates**: resolva as URLs geradas, reduza as respostas NXDOMAIN ao parent registerable domain e remova duplicatas entre famílias de prompts. Os corpora de prompts devem permanecer diversos, por exemplo, removendo quase-duplicatas com **Jaccard similarity**.
3. **Prioritize predictable hallucinations**:
- **Thermal Hallucination Persistence (THP)**: o mesmo domínio falso aparece em diferentes temperaturas, inclusive em temperaturas baixas, como `T=0.1`.
- **Cross-model consensus**: várias famílias de LLM geram o mesmo domínio falso.
4. **Register and weaponize** o parent domain e, em seguida, hospede phishing, downloads de APK/ZIP falsos, credential harvesters, documentos maliciosos ou endpoints de API que coletem secrets/payloads de webhook. **Pure domain-level hallucinations** são as mais fáceis de monetizar porque o atacante controla todo o namespace; hallucinations de subdomínio/path ainda podem ser abusadas quando o parent normalizado não está registrado.
5. **Exploit the zero-reputation window**: domínios recém-registrados geralmente não têm histórico em blocklists, reputação de URL ou telemetria madura, podendo contornar controles até que as detecções sejam atualizadas. Os atacantes podem ampliar essa janela usando respostas benignas apenas para crawlers, redirect cloaking, CAPTCHA gates ou staging atrasado de payloads.

### Why it is dangerous for agents

Para uma vítima humana, o domínio falso normalmente ainda exige um clique e outra ação. Em um **agentic workflow**, o LLM pode ser tanto a **isca** quanto o **executor**: o agente recebe a URL alucinada, acessa-a, analisa a resposta e pode então realizar leak de tokens, executar instruções, baixar uma dependência ou enviar dados envenenados para CI/CD sem qualquer revisão humana.<sup>[[12]](#references)</sup>

### Practical attacker prompts

Prompts de alto rendimento normalmente se parecem com tarefas corporativas comuns, em vez de iscas explícitas de phishing:<sup>[[12]](#references)</sup>
- “Qual é a URL do payment sandbox para integrações de `<brand>`?”
- “Qual endpoint de webhook devo usar para notificações de build de `<brand>`?”
- “Onde fica o portal de employee benefits / billing / SSO de `<brand>`?”
- “Forneça o download direto do APK Android ou do cliente desktop de `<brand>`.”

### Defensive inversion

Trate isso como um problema proativo de domain monitoring, não apenas como um problema de prompt injection:<sup>[[12]](#references)</sup>
- Crie um **brand prompt corpus** e faça sondagens periódicas nos LLMs dos quais seus usuários/agentes dependem.
- Armazene as URLs alucinadas e acompanhe quais permanecem estáveis entre temperaturas/modelos.
- Monitore o **Adversarial Exploitation Window (AEW)**: o período entre a primeira alucinação e o registro pelo atacante. Um AEW positivo significa que os defensores podem fazer pre-registration, sinkhole ou pre-block antes da weaponization.
- Monitore transições de **NXDOMAIN → registered** para os parent domains.
- Após o registro, faça a triagem do registrar, data de criação, nameservers, privacy shielding, conteúdo da página, screenshots, status de parked-page e similaridade com brand assets.
- Adicione policy gates para que agentes/desenvolvedores **não confiem por padrão em domínios gerados por LLM**: exija allowlists, validação de propriedade, verificações de CT/RDAP ou aprovação humana antes do primeiro uso.

Isso se enquadra simultaneamente em várias categorias de risco de AI: **AI supply-chain attack**, **insecure model output** e **rogue actions** quando agentes consomem autonomamente a URL alucinada.

## References

- [1] [OWASP Top 10 de Vulnerabilidades de Machine Learning](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google SAIF (Secure AI Framework) – Riscos](https://saif.google/secure-ai-framework/risks)
- [3] [Matriz de Ameaças MITRE ATLAS](https://atlas.mitre.org/)
- [4] [Unit 42 – Os riscos dos LLMs de assistentes de código: conteúdo prejudicial, uso indevido e deception](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [5] [Sysdig – LLMjacking: credenciais roubadas de Cloud usadas em um novo ataque de AI](https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/)
- [6] [Visão geral do esquema de LLMJacking – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [7] [oai-reverse-proxy (revenda de acesso roubado a LLM)](https://gitgud.io/khanon/oai-reverse-proxy)
- [8] [Synacktiv - Análise aprofundada da implantação de um servidor LLM on-premise com poucos privilégios](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [9] [README do servidor llama.cpp](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [10] [Quadlets do Podman: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [11] [Especificação CNCF Container Device Interface (CDI)](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [12] [Unit 42 – Phantom Squatting: domínios alucinados por AI como vetor de Software Supply Chain](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [13] [Socket – Slopsquatting: como as alucinações de AI estão alimentando uma nova classe de ataques de Supply Chain](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)
{{#include ../banners/hacktricks-training.md}}
