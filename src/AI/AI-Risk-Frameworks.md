# Riscos de IA

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

A OWASP identificou as 10 principais vulnerabilidades de machine learning que podem afetar sistemas de IA. Essas vulnerabilidades podem levar a vários problemas de segurança, incluindo data poisoning, model inversion e ataques adversariais. Entender essas vulnerabilidades é essencial para criar sistemas de IA seguros.

Para consultar uma lista atualizada e detalhada das 10 principais vulnerabilidades de machine learning, veja o projeto [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).<sup>[[1]](#references)</sup>

- **Input Manipulation Attack**: Um atacante adiciona pequenas alterações, muitas vezes invisíveis, aos **dados de entrada** para fazer o modelo tomar uma decisão incorreta.\
    *Exemplo*: Algumas manchas de tinta em uma placa de pare fazem um carro autônomo "ver" uma placa de limite de velocidade.

- **Data Poisoning Attack**: O **conjunto de treinamento** é deliberadamente contaminado com amostras ruins, ensinando regras prejudiciais ao modelo.\
*Exemplo*: Binários de malware são rotulados incorretamente como "benignos" em um corpus de treinamento de antivírus, permitindo que malwares semelhantes passem despercebidos posteriormente.

- **Model Inversion Attack**: Ao sondar as saídas, um atacante cria um **modelo reverso** que reconstrói características sensíveis das entradas originais.\
*Exemplo*: Recriar a imagem de ressonância magnética de um paciente com base nas previsões de um modelo de detecção de câncer.

- **Membership Inference Attack**: O adversário testa se um **registro específico** foi usado durante o treinamento, identificando diferenças nos níveis de confiança.\
*Exemplo*: Confirmar que uma transação bancária de uma pessoa aparece nos dados de treinamento de um modelo de detecção de fraude.

- **Model Theft**: Consultas repetidas permitem que um atacante aprenda os limites de decisão e **clone o comportamento do modelo** (e a propriedade intelectual).\
*Exemplo*: Coletar pares suficientes de perguntas e respostas de uma API de ML-as-a-Service para criar um modelo local quase equivalente.

- **AI Supply‑Chain Attack**: Comprometer qualquer componente (dados, bibliotecas, pesos pré-treinados, CI/CD) do **pipeline de ML** para corromper os modelos downstream.\
*Exemplo*: Uma dependência envenenada em um model hub instala um modelo de análise de sentimento com backdoor em vários aplicativos.

- **Transfer Learning Attack**: Uma lógica maliciosa é implantada em um **modelo pré-treinado** e sobrevive ao fine-tuning para a tarefa da vítima.\
*Exemplo*: Um backbone de visão com um gatilho oculto continua invertendo rótulos após ser adaptado para imagens médicas.

- **Model Skewing**: Dados sutilmente enviesados ou rotulados incorretamente **alteram as saídas do modelo** para favorecer os objetivos do atacante.\
*Exemplo*: Injetar e-mails de spam "limpos" rotulados como ham para fazer um filtro de spam permitir a passagem de e-mails semelhantes no futuro.

- **Output Integrity Attack**: O atacante **altera as previsões do modelo em trânsito**, sem modificar o próprio modelo, enganando sistemas downstream.\
*Exemplo*: Alterar o veredito "malicioso" de um classificador de malware para "benigno" antes que o estágio de quarentena de arquivos o receba.

- **Model Poisoning** --- Alterações diretas e direcionadas aos **parâmetros do modelo**, geralmente após obter acesso de gravação, para modificar seu comportamento.\
*Exemplo*: Ajustar os pesos de um modelo de detecção de fraude em produção para que transações de determinados cartões sejam sempre aprovadas.


## Riscos do Google SAIF

O [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) do Google descreve vários riscos associados a sistemas de IA:<sup>[[2]](#references)</sup>

- **Data Poisoning**: Agentes maliciosos alteram ou injetam dados de treinamento ou ajuste para reduzir a precisão, implantar backdoors ou enviesar resultados, comprometendo a integridade do modelo durante todo o ciclo de vida dos dados.

- **Unauthorized Training Data**: A ingestão de conjuntos de dados protegidos por direitos autorais, sensíveis ou não autorizados cria responsabilidades legais, éticas e de desempenho, pois o modelo aprende com dados que não tinha permissão para usar.

- **Model Source Tampering**: A manipulação da cadeia de suprimentos ou por agentes internos do código, das dependências ou dos pesos do modelo, antes ou durante o treinamento, pode incorporar uma lógica oculta que persiste mesmo após o retreinamento.

- **Excessive Data Handling**: Controles fracos de governança e retenção de dados levam os sistemas a armazenar ou processar mais dados pessoais do que o necessário, aumentando a exposição e os riscos de conformidade.

- **Model Exfiltration**: Atacantes roubam arquivos ou pesos do modelo, causando perda de propriedade intelectual e possibilitando serviços imitadores ou ataques subsequentes.

- **Model Deployment Tampering**: Adversários modificam artefatos do modelo ou a infraestrutura de serving, fazendo com que o modelo em execução seja diferente da versão validada e potencialmente alterando seu comportamento.

- **Denial of ML Service**: Inundar APIs ou enviar entradas do tipo “sponge” pode esgotar recursos computacionais e energia e tirar o modelo do ar, de forma semelhante aos ataques DoS clássicos.

- **Model Reverse Engineering**: Ao coletar grandes quantidades de pares de entrada e saída, atacantes podem clonar ou destilar o modelo, alimentando produtos imitadores e ataques adversariais personalizados.

- **Insecure Integrated Component**: Plugins, agentes ou serviços upstream vulneráveis permitem que atacantes injetem código ou elevem privilégios no pipeline de IA.

- **Prompt Injection**: Criar prompts, direta ou indiretamente, para inserir instruções que sobreponham a intenção do sistema e façam o modelo executar comandos não pretendidos.

- **Model Evasion**: Entradas cuidadosamente elaboradas fazem o modelo classificar incorretamente, alucinar ou gerar conteúdo proibido, comprometendo a segurança e a confiança.

- **Sensitive Data Disclosure**: O modelo revela informações privadas ou confidenciais dos dados de treinamento ou do contexto do usuário, violando a privacidade e as regulamentações.

- **Inferred Sensitive Data**: O modelo deduz atributos pessoais que nunca foram fornecidos, criando novos danos à privacidade por meio de inferências.

- **Insecure Model Output**: Respostas não sanitizadas podem transmitir código malicioso, desinformação ou conteúdo inadequado aos usuários ou sistemas downstream.

- **Rogue Actions**: Agentes integrados de forma autônoma executam operações não pretendidas no mundo real (gravação de arquivos, chamadas de API, compras etc.) sem supervisão adequada do usuário.

## Matriz MITRE AI ATLAS

A [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) oferece uma estrutura abrangente para entender e mitigar os riscos associados a sistemas de IA. Ela categoriza várias técnicas e táticas de ataque que adversários podem usar contra modelos de IA e também mostra como usar sistemas de IA para realizar diferentes ataques.<sup>[[3]](#references)</sup>

## LLMJacking (Roubo de tokens e revenda de acesso a LLMs hospedados na nuvem)

Atacantes roubam tokens de sessão ativos ou credenciais de API da nuvem e invocam LLMs pagos hospedados na nuvem sem autorização. O acesso costuma ser revendido por meio de proxies reversos que encaminham as solicitações pela conta da vítima, por exemplo, implantações de "oai-reverse-proxy". As consequências incluem prejuízo financeiro, uso indevido do modelo fora das políticas e atribuição das atividades ao tenant da vítima.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

TTPs:
- Coletar tokens de máquinas de desenvolvedores ou navegadores infectados; roubar segredos de CI/CD; comprar cookies vazados.<sup>[[5]](#references)</sup>
- Configurar um proxy reverso que encaminha solicitações ao provedor legítimo, ocultando a chave upstream e multiplexando vários clientes.<sup>[[5]](#references)</sup><sup>[[7]](#references)</sup>
- Abusar de endpoints diretos do modelo base para contornar as proteções corporativas e os limites de taxa.<sup>[[4]](#references)</sup>

**Reutilização de chave de API no host:** Após comprometer um host, um implante pode enviar solicitações à API do modelo diretamente do host da vítima e retransmitir as respostas por C2, sem exportar uma chave de API da nuvem ou iniciar uma CLI de IA local. No handler observado, uma chave fornecida por C2 tem prioridade; somente se ela estiver ausente o implante lê `OPENAI_API_KEY` do ambiente do próprio processo. Portanto, para usar a conta da vítima, é necessária uma chave válida visível para esse processo e acesso à API do modelo. O prompt do operador é enviado à API Chat Completions, enquanto a saída do modelo e o uso de tokens retornam por C2. Isso pode consumir o acesso pago da vítima ao modelo sem executar as ferramentas de IA do desenvolvedor, diferentemente do abuso de [configurações de CLI de IA local ou MCP](../generic-methodologies-and-resources/phishing-methodology/ai-agent-abuse-local-ai-cli-tools-and-mcp.md).<sup>[[14]](#references)</sup>

Mitigações:
- Vincular tokens à impressão digital do dispositivo, a intervalos de IP e à atestação do cliente; impor expirações curtas e exigir MFA para renová-los.
- Limitar as chaves ao escopo mínimo necessário (sem acesso a ferramentas, somente leitura quando aplicável); rotacioná-las diante de anomalias.
- Encaminhar todo o tráfego pelo lado do servidor, por trás de um gateway de políticas que aplique filtros de segurança, cotas por rota e isolamento de tenants.
- Monitorar padrões de uso incomuns (aumento repentino de gastos, regiões atípicas, strings de UA) e revogar automaticamente sessões suspeitas.
- Preferir mTLS ou JWTs assinados e emitidos pelo IdP em vez de chaves de API estáticas de longa duração.

## Proteção de inferência de LLMs auto-hospedados

Executar um servidor local de LLM para dados confidenciais cria uma superfície de ataque diferente daquela de APIs hospedadas na nuvem: endpoints de inferência ou depuração podem vazar prompts, a stack de serving normalmente expõe um proxy reverso e os nós de dispositivo GPU dão acesso a grandes superfícies de `ioctl()`. Se estiver avaliando ou implantando um serviço de inferência on-prem, revise pelo menos os pontos a seguir.<sup>[[8]](#references)</sup>

### Vazamento de prompts por endpoints de depuração e monitoramento

Trate a API de inferência como um **serviço sensível multiusuário**. Rotas de depuração ou monitoramento podem expor o conteúdo dos prompts, o estado dos slots, metadados do modelo ou informações de filas internas. No `llama.cpp`, o endpoint `/slots` é especialmente sensível porque expõe o estado de cada slot e destina-se apenas à inspeção ou ao gerenciamento de slots.<sup>[[8]](#references)</sup>

Para fingerprinting black-box e testes de model runners expostos e serviços de IA relacionados, consulte [Exposed Self-Hosted AI Services](AI-Exposed-Self-Hosted-AI-Services.md).

- Coloque um proxy reverso na frente do servidor de inferência e **negue por padrão**.
- Permita apenas as combinações exatas de método HTTP e caminho necessárias para o cliente/UI.
- Desative endpoints de introspecção no próprio backend sempre que possível, por exemplo, `llama-server --no-slots`.<sup>[[9]](#references)</sup>
- Vincule o proxy reverso a `127.0.0.1` e exponha-o por um transporte autenticado, como o encaminhamento de porta local SSH, em vez de publicá-lo na LAN.

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

Se o daemon de inferência permitir escutar em um socket UNIX, prefira essa opção em vez de TCP e execute o container **sem pilha de rede**:<sup>[[8]](#references)</sup>

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
- `--network none` remove a exposição TCP/IP de entrada/saída e evita auxiliares em modo de usuário que, de outra forma, seriam necessários para contêineres rootless.
- Um socket UNIX permite usar permissões/ACLs POSIX no caminho do socket como primeira camada de controle de acesso.
- `--userns=keep-id` e o Podman rootless reduzem o impacto de uma saída do contêiner, pois o root do contêiner não é o root do host.
- Montagens de modelos somente leitura reduzem a chance de adulteração dos modelos a partir de dentro do contêiner.

Em implantações persistentes, as mesmas restrições podem ser expressas como unidades Podman Quadlet. Se o acesso à GPU for delegado por meio da Container Device Interface, mantenha a especificação do dispositivo CDI o mais restrita possível, em vez de expor todos os nós aceleradores.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>

### Minimização dos nós de dispositivo de GPU

Para inferência com GPU, os arquivos `/dev/nvidia*` são superfícies de ataque locais de alto valor, pois expõem grandes manipuladores de driver `ioctl()` e caminhos potencialmente compartilhados de gerenciamento de memória da GPU.<sup>[[8]](#references)</sup>

- Não deixe `/dev/nvidia*` graváveis por todos.
- Restrinja `nvidia`, `nvidiactl` e `nvidia-uvm` com `NVreg_DeviceFileUID/GID/Mode`, regras udev e ACLs, para que somente o UID mapeado do contêiner possa abri-los.
- Coloque na lista de bloqueio módulos desnecessários, como `nvidia_drm`, `nvidia_modeset` e `nvidia_peermem`, em hosts de inferência sem interface gráfica.
- Pré-carregue apenas os módulos necessários durante a inicialização, em vez de permitir que o runtime execute `modprobe` oportunisticamente durante a inicialização da inferência.

Exemplo:

```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```

Um ponto importante da revisão é **`/dev/nvidia-uvm`**. Mesmo que a carga de trabalho não use explicitamente `cudaMallocManaged()`, runtimes recentes do CUDA ainda podem exigir `nvidia-uvm`. Como esse dispositivo é compartilhado e gerencia a memória virtual da GPU, trate-o como uma superfície de exposição de dados entre tenants. Se o backend de inferência oferecer suporte, um backend Vulkan pode ser uma alternativa interessante, pois talvez evite expor `nvidia-uvm` ao contêiner.<sup>[[8]](#references)</sup>

### Confinamento LSM para workers de inferência

AppArmor/SELinux/seccomp devem ser usados como defesa em profundidade em torno do processo de inferência:<sup>[[8]](#references)</sup>

- Permita apenas as bibliotecas compartilhadas, os caminhos dos modelos, o diretório de sockets e os nós de dispositivo da GPU realmente necessários.
- Negue explicitamente recursos de alto risco, como `sys_admin`, `sys_module`, `sys_rawio` e `sys_ptrace`.
- Mantenha o diretório do modelo somente para leitura e restrinja os caminhos graváveis apenas aos diretórios de sockets/cache do runtime.
- Monitore os logs de negação, pois eles fornecem telemetria útil para detecção quando o servidor do modelo ou um payload de post-exploitation tenta escapar do comportamento esperado.

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

## Phantom Squatting: Domínios alucinados por LLMs como vetor da cadeia de suprimentos de IA

Phantom squatting é o **equivalente de domínio/URL do slopsquatting**. Em vez de alucinar o nome de um pacote inexistente, o LLM alucina um **domínio plausível de portal, API, webhook, faturamento, SSO, download ou suporte** para uma marca real, e um atacante registra esse namespace antes que uma pessoa ou um agente o use.<sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Isso importa porque, em muitos fluxos de trabalho assistidos por IA, a saída do modelo é tratada como uma **dependência confiável**:
- Desenvolvedores colam o endpoint sugerido no código ou em integrações de CI/CD.
- Agentes de IA buscam automaticamente documentação, schemas, APKs, ZIPs ou destinos de webhook.
- Runbooks ou documentos gerados podem incorporar a URL falsa como se fosse oficial.

### Fluxo ofensivo

1. **Investigue a superfície de alucinação**: faça perguntas específicas sobre marcas e fluxos de trabalho realistas, como portais de `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` ou `mobile app`.<sup>[[12]](#references)</sup>
2. **Normalize os candidatos**: resolva as URLs geradas, reduza as respostas NXDOMAIN ao domínio registrável pai e elimine duplicatas entre famílias de prompts. Os corpora de prompts devem permanecer diversos, por exemplo, descartando quase duplicatas com **similaridade de Jaccard**.
3. **Priorize alucinações previsíveis**:
   - **Persistência de Alucinação Térmica (THP)**: o mesmo domínio falso aparece em diferentes temperaturas, inclusive em temperaturas baixas, como `T=0.1`.
   - **Consenso entre modelos**: várias famílias de LLMs geram o mesmo domínio falso.
4. **Registre e arme** o domínio pai; em seguida, hospede phishing, downloads falsos de APK/ZIP, coletores de credenciais, documentos maliciosos ou endpoints de API que coletam segredos/payloads de webhook. **Alucinações puramente no nível do domínio** são as mais fáceis de monetizar porque o atacante controla todo o namespace; alucinações de subdomínio/caminho ainda podem ser exploradas quando o domínio pai normalizado não está registrado.
5. **Explore a janela de reputação zero**: domínios recém-registrados geralmente não têm histórico em blocklists, reputação de URL nem telemetria madura, então podem contornar controles até que as detecções sejam atualizadas. Atacantes podem prolongar essa janela com respostas benignas apenas para crawlers, cloaking de redirecionamento, desafios CAPTCHA ou preparação tardia do payload.

### Por que isso é perigoso para agentes

Para uma vítima humana, o domínio falso geralmente ainda exige um clique e outra ação. Em um **fluxo de trabalho agêntico**, o LLM pode ser tanto a **isca** quanto o **executor**: o agente recebe a URL alucinada, acessa-a, analisa a resposta e pode então fazer leak de tokens, executar instruções, baixar uma dependência ou enviar dados envenenados para CI/CD sem qualquer revisão humana.<sup>[[12]](#references)</sup>

### Prompts práticos para atacantes

Prompts de alto rendimento geralmente parecem tarefas empresariais normais, em vez de iscas explícitas de phishing:<sup>[[12]](#references)</sup>
- “Qual é a URL do sandbox de pagamentos para integrações de `<brand>`?”
- “Qual endpoint de webhook devo usar para notificações de build de `<brand>`?”
- “Onde fica o portal de benefícios para funcionários / faturamento / SSO de `<brand>`?”
- “Forneça o link direto para baixar o APK Android ou o cliente para desktop de `<brand>`.”

### Inversão defensiva

Trate isso como um problema de monitoramento proativo de domínios, não apenas como um problema de prompt injection:<sup>[[12]](#references)</sup>
- Crie um **corpus de prompts de marcas** e teste periodicamente os LLMs dos quais seus usuários/agentes dependem.
- Armazene as URLs alucinadas e acompanhe quais permanecem estáveis entre temperaturas/modelos.
- Acompanhe a **Janela de Exploração Adversarial (AEW)**: o tempo entre a primeira alucinação e o registro pelo atacante. Uma AEW positiva significa que os defensores podem registrar preventivamente, direcionar para um sinkhole ou bloquear antes da weaponização.
- Monitore transições de **NXDOMAIN → registrado** para os domínios pai.
- Após o registro, faça a triagem do registrar, data de criação, nameservers, proteção de privacidade, conteúdo da página, capturas de tela, status de página estacionada e similaridade com ativos da marca.
- Adicione controles de política para que agentes/desenvolvedores **não confiem por padrão em domínios gerados por LLMs**: exija allowlists, validação de propriedade, verificações de CT/RDAP ou aprovação humana antes do primeiro uso.

Isso se enquadra em várias categorias de risco de IA ao mesmo tempo: **ataque à cadeia de suprimentos de IA**, **saída insegura do modelo** e **ações maliciosas** quando agentes consomem autonomamente a URL alucinada.

{{#include ../banners/hacktricks-training.md}}

## References

- [1] [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google SAIF (Secure AI Framework) – Riscos](https://saif.google/secure-ai-framework/risks)
- [3] [MITRE ATLAS Threat Matrix](https://atlas.mitre.org/)
- [4] [Unit 42 – Os riscos dos LLMs assistentes de código: conteúdo nocivo, uso indevido e engano](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [5] [Sysdig – LLMjacking: credenciais de cloud roubadas usadas em novo ataque de IA](https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/)
- [6] [Visão geral do esquema LLMJacking – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [7] [oai-reverse-proxy (revenda de acesso roubado a LLMs)](https://gitgud.io/khanon/oai-reverse-proxy)
- [8] [Synacktiv - Análise aprofundada da implantação de um servidor LLM local com poucos privilégios](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [9] [README do servidor llama.cpp](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [10] [Quadlets do Podman: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [11] [Especificação da Container Device Interface (CDI) da CNCF](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [12] [Unit 42 – Phantom Squatting: domínios alucinados por IA como vetor da cadeia de suprimentos de software](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [13] [Socket – Slopsquatting: como as alucinações de IA estão impulsionando uma nova classe de ataques à cadeia de suprimentos](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)
- [14] [Cisco Talos – NIK C2: a nova estrutura de comando e controle habilitada por IA](https://blog.talosintelligence.com/nik-c2-new-ai-enabled-framework/)
