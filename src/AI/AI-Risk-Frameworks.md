# Riscos de AI

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Vulnerabilidades de Machine Learning

A Owasp identificou as 10 principais vulnerabilidades de Machine Learning que podem afetar sistemas de AI. Essas vulnerabilidades podem levar a diversos problemas de segurança, incluindo envenenamento de dados, inversão de modelo e ataques adversariais. Compreender essas vulnerabilidades é essencial para criar sistemas de AI seguros.

Para obter uma lista atualizada e detalhada das 10 principais vulnerabilidades de Machine Learning, consulte o projeto [OWASP Top 10 Vulnerabilidades de Machine Learning](https://owasp.org/www-project-machine-learning-security-top-10/).

- **Input Manipulation Attack**: Um atacante adiciona pequenas alterações, geralmente invisíveis, aos **dados recebidos**, fazendo com que o modelo tome a decisão errada.\
*Exemplo*: Alguns pontos de tinta em uma placa de pare fazem um carro autônomo "enxergar" uma placa de limite de velocidade.

- **Data Poisoning Attack**: O **conjunto de treinamento** é deliberadamente contaminado com amostras maliciosas, ensinando regras prejudiciais ao modelo.\
*Exemplo*: Binários de malware são classificados incorretamente como "benignos" em um corpus de treinamento de antivírus, permitindo que malwares semelhantes passem despercebidos posteriormente.

- **Model Inversion Attack**: Ao sondar as saídas, um atacante cria um **modelo reverso** que reconstrói características sensíveis das entradas originais.\
*Exemplo*: Recriar a imagem de MRI de um paciente a partir das previsões de um modelo de detecção de câncer.

- **Membership Inference Attack**: O adversário testa se um **registro específico** foi usado durante o treinamento, observando diferenças nos níveis de confiança.\
*Exemplo*: Confirmar que uma transação bancária de uma pessoa aparece nos dados de treinamento de um modelo de detecção de fraude.

- **Model Theft**: Consultas repetidas permitem que um atacante aprenda os limites de decisão e **clone o comportamento do modelo** (e sua propriedade intelectual).\
*Exemplo*: Coletar pares suficientes de perguntas e respostas de uma API de ML-as-a-Service para criar um modelo local quase equivalente.

- **AI Supply-Chain Attack**: Comprometer qualquer componente (dados, bibliotecas, pesos pré-treinados, CI/CD) no **pipeline de ML** para corromper os modelos subsequentes.\
*Exemplo*: Uma dependência comprometida em um model hub instala um modelo de análise de sentimento com backdoor em diversos aplicativos.

- **Transfer Learning Attack**: Uma lógica maliciosa é implantada em um **modelo pré-treinado** e sobrevive ao fine-tuning na tarefa da vítima.\
*Exemplo*: Um backbone de visão computacional com um gatilho oculto continua invertendo rótulos após ser adaptado para imagens médicas.

- **Model Skewing**: Dados sutilmente enviesados ou rotulados incorretamente **alteram as saídas do modelo** para favorecer a agenda do atacante.\
*Exemplo*: Injetar e-mails de spam "limpos" rotulados como ham para que um filtro de spam permita a passagem de e-mails futuros semelhantes.

- **Output Integrity Attack**: O atacante **altera as previsões do modelo em trânsito**, e não o modelo em si, enganando os sistemas subsequentes.\
*Exemplo*: Alterar a decisão "malicioso" de um classificador de malware para "benigno" antes que o estágio de quarentena do arquivo a veja.

- **Model Poisoning** --- Alterações diretas e direcionadas nos próprios **parâmetros do modelo**, geralmente após obter acesso de escrita, para modificar seu comportamento.\
*Exemplo*: Ajustar os pesos de um modelo de detecção de fraude em produção para que transações de determinados cartões sejam sempre aprovadas.


## Riscos do Google SAIF

O [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) do Google descreve vários riscos associados a sistemas de AI:

- **Data Poisoning**: Agentes maliciosos alteram ou injetam dados de treinamento ou ajuste para degradar a precisão, implantar backdoors ou distorcer resultados, comprometendo a integridade do modelo em todo o ciclo de vida dos dados.

- **Unauthorized Training Data**: A ingestão de datasets protegidos por direitos autorais, sensíveis ou não autorizados cria responsabilidades legais, éticas e de desempenho, pois o modelo aprende com dados que nunca teve permissão para usar.

- **Model Source Tampering**: A manipulação da cadeia de suprimentos ou por insiders do código, das dependências ou dos pesos do modelo antes ou durante o treinamento pode incorporar uma lógica oculta que persiste mesmo após o retreinamento.

- **Excessive Data Handling**: Controles fracos de retenção e governança de dados fazem com que os sistemas armazenem ou processem mais dados pessoais do que o necessário, aumentando a exposição e o risco de não conformidade.

- **Model Exfiltration**: Atacantes roubam arquivos ou pesos do modelo, causando perda de propriedade intelectual e permitindo serviços imitadores ou ataques subsequentes.

- **Model Deployment Tampering**: Adversários modificam artefatos do modelo ou a infraestrutura de serving para que o modelo em execução seja diferente da versão validada, podendo alterar seu comportamento.

- **Denial of ML Service**: Inundar APIs ou enviar entradas "sponge" pode esgotar recursos computacionais e energia e tirar o modelo do ar, reproduzindo ataques DoS clássicos.

- **Model Reverse Engineering**: Ao coletar grandes quantidades de pares de entrada e saída, os atacantes podem clonar ou destilar o modelo, impulsionando produtos imitadores e ataques adversariais personalizados.

- **Insecure Integrated Component**: Plugins, agentes ou serviços upstream vulneráveis permitem que atacantes injetem código ou elevem privilégios no pipeline de AI.

- **Prompt Injection**: Criar prompts, direta ou indiretamente, para inserir instruções que substituem a intenção do sistema, fazendo com que o modelo execute comandos não intencionais.

- **Model Evasion**: Entradas cuidadosamente projetadas fazem com que o modelo classifique incorretamente, alucine ou produza conteúdo não permitido, reduzindo a segurança e a confiança.

- **Sensitive Data Disclosure**: O modelo revela informações privadas ou confidenciais de seus dados de treinamento ou do contexto do usuário, violando a privacidade e regulamentações.

- **Inferred Sensitive Data**: O modelo deduz atributos pessoais que nunca foram fornecidos, criando novos danos à privacidade por meio de inferência.

- **Insecure Model Output**: Respostas não sanitizadas transmitem código prejudicial, desinformação ou conteúdo inadequado aos usuários ou sistemas subsequentes.

- **Rogue Actions**: Agentes integrados autonomamente executam operações não intencionais no mundo real (gravações de arquivos, chamadas de API, compras etc.) sem supervisão adequada do usuário.

## Matriz Mitre AI ATLAS

A [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) fornece uma estrutura abrangente para compreender e mitigar riscos associados a sistemas de AI. Ela categoriza várias técnicas e táticas de ataque que os adversários podem usar contra modelos de AI e também como usar sistemas de AI para realizar diferentes ataques.


## LLMJacking (Roubo e Revenda de Tokens de Acesso a LLM Hospedado na Nuvem)

Atacantes roubam tokens de sessão ativos ou credenciais de API da nuvem e invocam LLMs pagos e hospedados na nuvem sem autorização. O acesso geralmente é revendido por meio de reverse proxies que ficam na frente da conta da vítima, por exemplo, implantações de "oai-reverse-proxy". As consequências incluem perdas financeiras, uso indevido do modelo fora da política e atribuição ao tenant da vítima.

TTPs:
- Coletar tokens de máquinas de desenvolvedores ou browsers infectados; roubar secrets de CI/CD; comprar cookies vazados.
- Configurar um reverse proxy que encaminha requisições ao provedor legítimo, ocultando a chave upstream e multiplexando vários clientes.
- Abusar de endpoints de base-model diretos para contornar guardrails empresariais e limites de taxa.

Mitigações:
- Vincular tokens à fingerprint do dispositivo, intervalos de IP e atestação do cliente; impor expirações curtas e renovar com MFA.
- Limitar as chaves ao mínimo necessário (sem acesso a tools, somente leitura quando aplicável); rotacioná-las em caso de anomalia.
- Encaminhar todo o tráfego no lado do servidor por um policy gateway que imponha filtros de segurança, quotas por rota e isolamento de tenants.
- Monitorar padrões de uso incomuns (picos repentinos de gastos, regiões atípicas, strings de UA) e revogar automaticamente sessões suspeitas.
- Preferir mTLS ou JWTs assinados emitidos pelo seu IdP em vez de chaves de API estáticas de longa duração.

## Hardening de inferência de LLM self-hosted

Executar um servidor local de LLM para dados confidenciais cria uma superfície de ataque diferente daquela das APIs hospedadas na nuvem: endpoints de inferência ou debug podem vazar prompts, a stack de serving geralmente expõe um reverse proxy e os device nodes da GPU fornecem acesso a grandes superfícies de `ioctl()`. Se você estiver avaliando ou implantando um serviço de inferência on-premises, revise pelo menos os seguintes pontos.

### Vazamento de prompts por meio de endpoints de debug e monitoramento

Trate a API de inferência como um **serviço sensível multiusuário**. Rotas de debug ou monitoramento podem expor o conteúdo dos prompts, o estado dos slots, metadados do modelo ou informações sobre filas internas. No `llama.cpp`, o endpoint `/slots` é especialmente sensível porque expõe o estado de cada slot e destina-se apenas à inspeção ou ao gerenciamento de slots.

- Coloque um reverse proxy na frente do servidor de inferência e **negue por padrão**.
- Permita somente as combinações exatas de método HTTP + caminho necessárias para o cliente ou a UI.
- Desabilite endpoints de introspecção no próprio backend sempre que possível, por exemplo `llama-server --no-slots`.
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

Se o daemon de inferência for compatível com a escuta em um UNIX socket, prefira essa opção ao TCP e execute o container com **nenhuma pilha de rede**:
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
- `--network none` remove a exposição TCP/IP de entrada/saída e evitam helpers em user-mode que containers rootless precisariam de outra forma.
- Um UNIX socket permite usar permissões/ACLs POSIX no caminho do socket como a primeira camada de controle de acesso.
- `--userns=keep-id` e o Podman rootless reduzem o impacto de um container breakout, pois o root do container não é o root do host.
- Mounts de modelos somente leitura reduzem a possibilidade de adulteração do modelo a partir de dentro do container.

### Minimização de device nodes de GPU

Para inference com GPU, os arquivos `/dev/nvidia*` são attack surfaces locais de alto valor, pois expõem grandes handlers `ioctl()` do driver e possíveis caminhos compartilhados de gerenciamento de memória da GPU.

- Não deixe `/dev/nvidia*` gravável por todos.
- Restrinja `nvidia`, `nvidiactl` e `nvidia-uvm` com `NVreg_DeviceFileUID/GID/Mode`, regras do udev e ACLs, de modo que somente o UID mapeado do container possa abri-los.
- Coloque na blacklist módulos desnecessários, como `nvidia_drm`, `nvidia_modeset` e `nvidia_peermem`, em hosts de inference headless.
- Carregue previamente apenas os módulos necessários no boot, em vez de permitir que o runtime execute `modprobe` oportunisticamente durante a inicialização do inference.

Exemplo:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
Um ponto importante da revisão é **`/dev/nvidia-uvm`**. Mesmo que o workload não use explicitamente `cudaMallocManaged()`, runtimes CUDA recentes ainda podem exigir `nvidia-uvm`. Como esse device é compartilhado e lida com o gerenciamento de memória virtual da GPU, trate-o como uma superfície de exposição de dados entre tenants. Se o inference backend oferecer suporte, um backend Vulkan pode ser uma alternativa interessante, pois talvez evite expor `nvidia-uvm` ao container.

### Confinamento por LSM para inference workers

AppArmor/SELinux/seccomp devem ser usados como defesa em profundidade ao redor do processo de inference:

- Permita apenas as shared libraries, model paths, socket directory e GPU device nodes realmente necessários.
- Negue explicitamente capabilities de alto risco, como `sys_admin`, `sys_module`, `sys_rawio` e `sys_ptrace`.
- Mantenha o model directory somente para leitura e limite os writable paths apenas aos runtime socket/cache directories.
- Monitore os denial logs, pois eles fornecem telemetria de detecção útil quando o model server ou um payload de post-exploitation tenta escapar do comportamento esperado.

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
## Phantom Squatting: Domínios Alucinados por LLM como Vetor de Cadeia de Suprimentos de IA

Phantom squatting é o **equivalente de domínio/URL do slopsquatting**. Em vez de alucinar o nome de um pacote inexistente, o LLM alucina um **domínio plausível de portal, API, webhook, billing, SSO, download ou suporte** para uma marca real, e um atacante registra esse namespace antes que um humano ou agente o utilize.

Isso é importante porque, em muitos fluxos de trabalho assistidos por IA, a saída do modelo é tratada como uma **dependência confiável**:
- Desenvolvedores colam o endpoint sugerido no código ou em integrações de CI/CD.
- Agentes de IA buscam automaticamente documentação, schemas, APKs, ZIPs ou destinos de webhook.
- Runbooks ou documentos gerados podem incorporar a URL falsa como se fosse oficial.

### Fluxo ofensivo

1. **Sonde a superfície de alucinação**: faça perguntas específicas sobre marcas e workflows realistas, como portais de `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` ou `mobile app`.
2. **Normalize os candidatos**: resolva as URLs geradas, reduza as respostas NXDOMAIN ao domínio registrável pai e remova duplicatas entre famílias de prompts. Os corpora de prompts devem permanecer diversificados, por exemplo, eliminando quase duplicatas com **similaridade de Jaccard**.
3. **Priorize alucinações previsíveis**:
- **Thermal Hallucination Persistence (THP)**: o mesmo domínio falso aparece em diferentes temperaturas, incluindo temperaturas baixas como `T=0.1`.
- **Consenso entre modelos**: várias famílias de LLM geram o mesmo domínio falso.
4. **Registre e weaponize** o domínio pai; em seguida, hospede phishing, downloads falsos de APK/ZIP, credential harvesters, documentos maliciosos ou endpoints de API que coletem secrets/payloads de webhook. **Alucinações puramente no nível de domínio** são as mais fáceis de monetizar porque o atacante controla todo o namespace; alucinações de subdomínio/caminho ainda podem ser abusadas quando o pai normalizado não está registrado.
5. **Explore a janela de reputação zero**: domínios recém-registrados geralmente não possuem histórico em blocklists, reputação de URL ou telemetria madura, podendo contornar controles até que as detecções se atualizem. Atacantes podem prolongar essa janela usando respostas benignas apenas para crawlers, redirect cloaking, CAPTCHA gates ou staging atrasado de payloads.

### Por que isso é perigoso para agentes

Para uma vítima humana, o domínio falso geralmente ainda exige um clique e outra ação. Em um **workflow agentic**, o LLM pode ser tanto a **isca** quanto o **executor**: o agente recebe a URL alucinada, acessa a URL, analisa a resposta e pode então vazar tokens, executar instruções, baixar uma dependência ou enviar dados envenenados para CI/CD sem qualquer revisão humana.

### Prompts ofensivos práticos

Prompts de alto rendimento geralmente se parecem com tarefas corporativas normais, em vez de iscas explícitas de phishing:
- “Qual é a URL do sandbox de pagamentos para integrações de `<brand>`?”
- “Qual endpoint de webhook devo usar para notificações de build de `<brand>`?”
- “Onde fica o portal de benefícios de funcionários / billing / SSO de `<brand>`?”
- “Forneça o download direto do APK Android ou do cliente desktop de `<brand>`.”

### Inversão defensiva

Trate isso como um problema de monitoramento proativo de domínios, não apenas como um problema de prompt injection:
- Crie um **corpus de prompts de marcas** e sonde periodicamente os LLMs dos quais seus usuários/agentes dependem.
- Armazene as URLs alucinadas e acompanhe quais permanecem estáveis entre temperaturas/modelos.
- Acompanhe a **Adversarial Exploitation Window (AEW)**: o tempo entre a primeira alucinação e o registro pelo atacante. Uma AEW positiva significa que os defensores podem pré-registrar, fazer sinkhole ou bloquear previamente antes da weaponization.
- Monitore transições de **NXDOMAIN → registrado** para os domínios pai.
- Após o registro, faça a triagem do registrador, data de criação, nameservers, privacy shielding, conteúdo da página, screenshots, status de página estacionada e similaridade dos brand assets.
- Adicione policy gates para que agentes/desenvolvedores **não confiem por padrão em domínios gerados por LLM**: exija allowlists, validação de propriedade, verificações CT/RDAP ou aprovação humana antes do primeiro uso.

Isso se enquadra simultaneamente em várias categorias de risco de IA: **ataque à cadeia de suprimentos de IA**, **saída insegura do modelo** e **ações rogue** quando agentes consomem autonomamente a URL alucinada.

## Referências
- [Unit 42 – Os riscos dos LLMs de assistentes de código: conteúdo nocivo, uso indevido e engano](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [Visão geral do esquema LLMJacking – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [oai-reverse-proxy (revenda de acesso roubado a LLMs)](https://gitgud.io/khanon/oai-reverse-proxy)
- [Synacktiv - Análise detalhada da implantação de um servidor LLM on-premise com poucos privilégios](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [README do servidor llama.cpp](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [Quadlets do Podman: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [Especificação do Container Device Interface (CDI) da CNCF](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [Unit 42 – Phantom Squatting: domínios alucinados por IA como vetor da cadeia de suprimentos de software](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [Socket – Slopsquatting: como as alucinações de IA estão alimentando uma nova classe de ataques à cadeia de suprimentos](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)

{{#include ../banners/hacktricks-training.md}}
