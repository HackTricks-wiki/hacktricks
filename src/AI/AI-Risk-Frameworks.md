# Riscos de IA

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

A OWASP identificou as 10 principais vulnerabilidades de machine learning que podem afetar sistemas de IA. Essas vulnerabilidades podem levar a vários problemas de segurança, incluindo data poisoning, model inversion e ataques adversariais. Compreender essas vulnerabilidades é fundamental para criar sistemas de IA seguros.

Para consultar uma lista atualizada e detalhada das 10 principais vulnerabilidades de machine learning, veja o projeto [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).<sup>[[1]](#references)</sup>

- **Input Manipulation Attack**: Um invasor adiciona pequenas alterações, muitas vezes invisíveis, aos **dados de entrada**, fazendo com que o modelo tome a decisão errada.\
    *Exemplo*: Algumas manchas de tinta em uma placa de pare enganam um carro autônomo, fazendo-o "ver" uma placa de limite de velocidade.

- **Data Poisoning Attack**: O **conjunto de treinamento** é deliberadamente contaminado com amostras nocivas, ensinando regras prejudiciais ao modelo.\
*Exemplo*: Binários de malware são rotulados incorretamente como "benignos" em um corpus de treinamento de antivírus, permitindo que malwares semelhantes passem despercebidos depois.

- **Model Inversion Attack**: Ao sondar as saídas, um invasor cria um **modelo reverso** que reconstrói características sensíveis das entradas originais.\
*Exemplo*: Recriar a imagem de ressonância magnética de um paciente a partir das previsões de um modelo de detecção de câncer.

- **Membership Inference Attack**: O adversário testa se um **registro específico** foi usado durante o treinamento, observando diferenças nos níveis de confiança.\
*Exemplo*: Confirmar que uma transação bancária de uma pessoa consta nos dados de treinamento de um modelo de detecção de fraude.

- **Model Theft**: Consultas repetidas permitem que um invasor aprenda os limites de decisão e **clone o comportamento do modelo** (e sua propriedade intelectual).\
*Exemplo*: Coletar pares suficientes de perguntas e respostas de uma API de ML-as-a-Service para criar um modelo local quase equivalente.

- **AI Supply‑Chain Attack**: Comprometer qualquer componente (dados, bibliotecas, pesos pré-treinados, CI/CD) do **pipeline de ML** para corromper os modelos subsequentes.\
*Exemplo*: Uma dependência envenenada em um model hub instala um modelo de análise de sentimento com backdoor em vários aplicativos.

- **Transfer Learning Attack**: Uma lógica maliciosa é inserida em um **modelo pré-treinado** e sobrevive ao fine-tuning para a tarefa da vítima.\
*Exemplo*: Um backbone de visão com um gatilho oculto continua invertendo rótulos mesmo depois de ser adaptado para imagens médicas.

- **Model Skewing**: Dados sutilmente enviesados ou rotulados incorretamente **alteram as saídas do modelo** para favorecer os objetivos do invasor.\
*Exemplo*: Injetar e-mails de spam "limpos" rotulados como ham para que um filtro de spam deixe passar e-mails semelhantes no futuro.

- **Output Integrity Attack**: O invasor **altera as previsões do modelo em trânsito**, sem alterar o próprio modelo, enganando os sistemas subsequentes.\
*Exemplo*: Alterar a classificação "malicioso" de um classificador de malware para "benigno" antes que o estágio de quarentena de arquivos a receba.

- **Model Poisoning** --- Alterações diretas e direcionadas nos **parâmetros do modelo**, muitas vezes após obter acesso de gravação, para mudar seu comportamento.\
*Exemplo*: Ajustar os pesos de um modelo de detecção de fraude em produção para que as transações de determinados cartões sejam sempre aprovadas.


## Riscos do Google SAIF

O [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) do Google descreve vários riscos associados a sistemas de IA:<sup>[[2]](#references)</sup>

- **Data Poisoning**: Agentes maliciosos alteram ou injetam dados de treinamento/ajuste para reduzir a precisão, inserir backdoors ou enviesar resultados, comprometendo a integridade do modelo ao longo de todo o ciclo de vida dos dados.

- **Unauthorized Training Data**: A ingestão de conjuntos de dados protegidos por direitos autorais, sensíveis ou não autorizados cria riscos legais, éticos e de desempenho, pois o modelo aprende com dados que não tinha permissão para usar.

- **Model Source Tampering**: A manipulação de código, dependências ou pesos do modelo na cadeia de suprimentos ou por agentes internos, antes ou durante o treinamento, pode inserir lógica oculta que persiste mesmo após um novo treinamento.

- **Excessive Data Handling**: Controles fracos de retenção e governança de dados levam os sistemas a armazenar ou processar mais dados pessoais do que o necessário, aumentando a exposição e os riscos de conformidade.

- **Model Exfiltration**: Invasores roubam arquivos/pesos do modelo, causando perda de propriedade intelectual e possibilitando serviços imitadores ou ataques subsequentes.

- **Model Deployment Tampering**: Adversários modificam artefatos do modelo ou a infraestrutura de serving para que o modelo em execução seja diferente da versão validada, podendo alterar seu comportamento.

- **Denial of ML Service**: Sobrecarregar APIs ou enviar entradas “sponge” pode esgotar recursos computacionais/energia e deixar o modelo offline, de forma semelhante aos ataques DoS clássicos.

- **Model Reverse Engineering**: Ao coletar grandes quantidades de pares de entrada e saída, invasores podem clonar ou destilar o modelo, impulsionando produtos imitadores e ataques adversariais personalizados.

- **Insecure Integrated Component**: Plugins, agentes ou serviços upstream vulneráveis permitem que invasores injetem código ou elevem privilégios no pipeline de IA.

- **Prompt Injection**: Criar prompts, direta ou indiretamente, para inserir instruções que se sobreponham à intenção do sistema, fazendo o modelo executar comandos não pretendidos.

- **Model Evasion**: Entradas cuidadosamente elaboradas fazem com que o modelo classifique incorretamente, alucine ou produza conteúdo proibido, prejudicando a segurança e a confiança.

- **Sensitive Data Disclosure**: O modelo revela informações privadas ou confidenciais dos dados de treinamento ou do contexto do usuário, violando a privacidade e as regulamentações.

- **Inferred Sensitive Data**: O modelo deduz atributos pessoais que nunca foram fornecidos, criando novos danos à privacidade por meio de inferências.

- **Insecure Model Output**: Respostas não sanitizadas transmitem código nocivo, desinformação ou conteúdo impróprio a usuários ou sistemas subsequentes.

- **Rogue Actions**: Agentes integrados de forma autônoma executam operações não pretendidas no mundo real (gravação de arquivos, chamadas de API, compras etc.) sem supervisão adequada do usuário.

## Matriz MITRE AI ATLAS

A [Matriz MITRE AI ATLAS](https://atlas.mitre.org/matrices/ATLAS) fornece uma estrutura abrangente para compreender e mitigar os riscos associados a sistemas de IA. Ela categoriza várias técnicas de ataque e táticas que adversários podem usar contra modelos de IA, bem como formas de usar sistemas de IA para realizar diferentes ataques.<sup>[[3]](#references)</sup>

## LLMJacking (Roubo de tokens e revenda de acesso a LLMs hospedados na nuvem)

Invasores roubam tokens de sessão ativos ou credenciais de API na nuvem e invocam LLMs pagos, hospedados na nuvem, sem autorização. Muitas vezes, o acesso é revendido por meio de proxies reversos que encaminham solicitações pela conta da vítima, por exemplo, implantações de "oai-reverse-proxy". As consequências incluem perdas financeiras, uso indevido do modelo fora das políticas e atribuição à conta da vítima.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

TTPs:
- Coletar tokens de máquinas de desenvolvedores ou navegadores infectados; roubar segredos de CI/CD; comprar cookies vazados.<sup>[[5]](#references)</sup>
- Configurar um proxy reverso que encaminhe solicitações ao provedor legítimo, ocultando a chave upstream e atendendo vários clientes.<sup>[[5]](#references)</sup><sup>[[7]](#references)</sup>
- Abusar diretamente dos endpoints do modelo-base para contornar as proteções corporativas e os limites de taxa.<sup>[[4]](#references)</sup>

Mitigações:
- Vincular tokens à impressão digital do dispositivo, a intervalos de IP e à atestação do cliente; aplicar expirações curtas e exigir MFA para renovação.
- Limitar as chaves ao mínimo necessário (sem acesso a ferramentas, somente leitura quando aplicável); rotacioná-las quando houver anomalias.
- Encaminhar todo o tráfego pelo lado do servidor, por trás de um gateway de políticas que aplique filtros de segurança, cotas por rota e isolamento entre contas.
- Monitorar padrões de uso incomuns (aumentos repentinos de gastos, regiões atípicas, strings de UA) e revogar automaticamente sessões suspeitas.
- Preferir mTLS ou JWTs assinados emitidos pelo seu IdP em vez de chaves de API estáticas de longa duração.

## Proteção de inferência de LLMs auto-hospedados

Executar um servidor local de LLM para dados confidenciais cria uma superfície de ataque diferente das APIs hospedadas na nuvem: endpoints de inferência/depuração podem vazar prompts, a stack de serving geralmente expõe um proxy reverso e os nós de dispositivo GPU dão acesso a grandes superfícies de `ioctl()`. Se você estiver avaliando ou implantando um serviço de inferência on-prem, examine pelo menos os pontos a seguir.<sup>[[8]](#references)</sup>

### Vazamento de prompts por endpoints de depuração e monitoramento

Trate a API de inferência como um **serviço sensível para múltiplos usuários**. Rotas de depuração ou monitoramento podem expor o conteúdo dos prompts, o estado dos slots, metadados do modelo ou informações internas da fila. No `llama.cpp`, o endpoint `/slots` é particularmente sensível porque expõe o estado de cada slot e destina-se apenas à inspeção/gerenciamento de slots.<sup>[[8]](#references)</sup>

- Coloque um proxy reverso na frente do servidor de inferência e **negue o acesso por padrão**.
- Permita apenas as combinações exatas de método HTTP + caminho necessárias para o cliente/UI.
- Desative endpoints de introspecção no próprio backend sempre que possível, por exemplo, `llama-server --no-slots`.<sup>[[9]](#references)</sup>
- Vincule o proxy reverso a `127.0.0.1` e exponha-o por meio de um transporte autenticado, como o encaminhamento local de portas SSH, em vez de publicá-lo na LAN.

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
- `--network none` remove a exposição TCP/IP de entrada/saída e evita auxiliares em modo de usuário que, de outro modo, seriam necessários para contêineres rootless.
- Um socket UNIX permite usar permissões/ACLs POSIX no caminho do socket como primeira camada de controle de acesso.
- `--userns=keep-id` e o Podman rootless reduzem o impacto de uma fuga do contêiner, pois o root do contêiner não é o root do host.
- Montagens de modelo somente leitura reduzem a chance de adulteração do modelo a partir de dentro do contêiner.

Em implantações persistentes, as mesmas restrições podem ser expressas como unidades Podman Quadlet. Se o acesso à GPU for delegado por meio da Container Device Interface, mantenha a especificação do dispositivo CDI o mais restrita possível, em vez de expor todos os nós aceleradores.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>

### Minimização de nós de dispositivo da GPU

Para inferência com GPU, os arquivos `/dev/nvidia*` são superfícies de ataque locais de alto valor, pois expõem grandes manipuladores de driver `ioctl()` e caminhos potencialmente compartilhados de gerenciamento de memória da GPU.<sup>[[8]](#references)</sup>

- Não deixe `/dev/nvidia*` com permissão de escrita para todos.
- Restrinja `nvidia`, `nvidiactl` e `nvidia-uvm` com `NVreg_DeviceFileUID/GID/Mode`, regras udev e ACLs, para que somente o UID mapeado do contêiner possa abri-los.
- Coloque na lista de bloqueio módulos desnecessários, como `nvidia_drm`, `nvidia_modeset` e `nvidia_peermem`, em hosts de inferência headless.
- Pré-carregue somente os módulos necessários na inicialização, em vez de permitir que o runtime execute `modprobe` neles oportunisticamente durante a inicialização da inferência.

Exemplo:

```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```

Um ponto importante de revisão é **`/dev/nvidia-uvm`**. Mesmo que a workload não use explicitamente `cudaMallocManaged()`, runtimes recentes do CUDA ainda podem exigir `nvidia-uvm`. Como esse dispositivo é compartilhado e gerencia a memória virtual da GPU, trate-o como uma superfície de exposição de dados entre tenants. Se o backend de inferência oferecer suporte, um backend Vulkan pode ser uma alternativa interessante, pois talvez evite expor `nvidia-uvm` ao container.<sup>[[8]](#references)</sup>

### Confinamento LSM para workers de inferência

AppArmor/SELinux/seccomp devem ser usados como defesa em profundidade em torno do processo de inferência:<sup>[[8]](#references)</sup>

- Permita apenas as bibliotecas compartilhadas, os caminhos dos modelos, o diretório de sockets e os nós de dispositivos da GPU realmente necessários.
- Negue explicitamente recursos de alto risco, como `sys_admin`, `sys_module`, `sys_rawio` e `sys_ptrace`.
- Mantenha o diretório dos modelos somente para leitura e restrinja os caminhos graváveis aos diretórios de sockets/cache do runtime.
- Monitore os logs de negação, pois eles fornecem telemetria útil para detecção quando o servidor de modelos ou um payload de post-exploitation tenta escapar do comportamento esperado.

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

## Phantom Squatting: domínios alucinados por LLMs como vetor da cadeia de suprimentos de IA

Phantom squatting é o **equivalente de domínio/URL do slopsquatting**. Em vez de alucinar o nome de um pacote inexistente, o LLM alucina um **domínio de portal, API, webhook, faturamento, SSO, download ou suporte** plausível para uma marca real, e um atacante registra esse namespace antes que uma pessoa ou agente o use.<sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Isso é importante porque, em muitos fluxos de trabalho assistidos por IA, a saída do modelo é tratada como uma **dependência confiável**:
- Desenvolvedores colam o endpoint sugerido no código ou em integrações de CI/CD.
- Agentes de IA buscam documentação, esquemas, APKs, arquivos ZIP ou destinos de webhook automaticamente.
- Runbooks ou documentos gerados podem incorporar a URL falsa como se fosse oficial.

### Fluxo de ataque

1. **Investigue a superfície de alucinação**: faça perguntas específicas sobre a marca, relacionadas a fluxos de trabalho realistas, como portais de `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` ou `mobile app`.<sup>[[12]](#references)</sup>
2. **Normalize os candidatos**: resolva as URLs geradas, reduza as respostas NXDOMAIN ao domínio registrável principal e elimine duplicatas entre famílias de prompts. Os conjuntos de prompts devem permanecer diversificados, por exemplo, descartando quase duplicatas usando a **similaridade de Jaccard**.
3. **Priorize alucinações previsíveis**:
   - **Thermal Hallucination Persistence (THP)**: o mesmo domínio falso aparece em diferentes temperaturas, inclusive em temperaturas baixas, como `T=0.1`.
   - **Consenso entre modelos**: várias famílias de LLMs geram o mesmo domínio falso.
4. **Registre e weaponize** o domínio principal e, em seguida, hospede páginas de phishing, downloads falsos de APK/ZIP, coletores de credenciais, documentos maliciosos ou endpoints de API que coletam segredos/payloads de webhook. **Alucinações puramente no nível do domínio** são as mais fáceis de monetizar, pois o atacante controla todo o namespace; alucinações de subdomínio/caminho ainda podem ser exploradas quando o domínio principal normalizado não está registrado.
5. **Explore a janela de reputação zero**: domínios recém-registrados muitas vezes não têm histórico em listas de bloqueio, reputação de URL nem telemetria madura, então podem contornar controles até que as detecções se atualizem. Atacantes podem prolongar essa janela com respostas benignas exclusivas para crawlers, cloaking de redirecionamento, barreiras CAPTCHA ou preparação tardia de payloads.

### Por que é perigoso para agentes

Para uma vítima humana, o domínio falso geralmente ainda exige um clique e outra ação. Em um **fluxo de trabalho agentic**, o LLM pode ser tanto a **isca** quanto o **executor**: o agente recebe a URL alucinada, acessa-a, analisa a resposta e pode então vazar tokens, executar instruções, baixar uma dependência ou enviar dados envenenados para CI/CD sem qualquer revisão humana.<sup>[[12]](#references)</sup>

### Prompts práticos para atacantes

Prompts de alto rendimento geralmente parecem tarefas empresariais comuns, em vez de iscas explícitas de phishing:<sup>[[12]](#references)</sup>
- “Qual é a URL do sandbox de pagamentos para as integrações de `<brand>`?”
- “Qual endpoint de webhook devo usar para notificações de build de `<brand>`?”
- “Onde fica o portal de benefícios para funcionários / faturamento / SSO de `<brand>`?”
- “Forneça o download direto do APK para Android ou do cliente desktop de `<brand>`.”

### Inversão defensiva

Trate isso como um problema de monitoramento proativo de domínios, não apenas como um problema de prompt injection:<sup>[[12]](#references)</sup>
- Crie um **conjunto de prompts sobre marcas** e teste periodicamente os LLMs dos quais seus usuários/agentes dependem.
- Armazene as URLs alucinadas e acompanhe quais permanecem estáveis entre temperaturas/modelos.
- Acompanhe a **Adversarial Exploitation Window (AEW)**: o tempo entre a primeira alucinação e o registro pelo atacante. Uma AEW positiva significa que os defensores podem registrar preventivamente, criar um sinkhole ou bloquear antes da weaponization.
- Monitore transições de **NXDOMAIN → registrado** para os domínios principais.
- Após o registro, faça a triagem do registrador, data de criação, nameservers, proteção de privacidade, conteúdo da página, capturas de tela, status de página estacionada e similaridade com os ativos da marca.
- Adicione controles de política para que agentes/desenvolvedores **não confiem por padrão em domínios gerados por LLMs**: exija allowlists, validação de propriedade, verificações CT/RDAP ou aprovação humana antes do primeiro uso.

Isso se enquadra em várias categorias de risco de IA ao mesmo tempo: **ataque à cadeia de suprimentos de IA**, **saída insegura do modelo** e **ações não autorizadas** quando agentes consomem autonomamente a URL alucinada.

## References

- [1] [As 10 principais vulnerabilidades de Machine Learning da OWASP](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google SAIF (Secure AI Framework) – Riscos](https://saif.google/secure-ai-framework/risks)
- [3] [Matriz de ameaças MITRE ATLAS](https://atlas.mitre.org/)
- [4] [Unit 42 – Os riscos dos LLMs de assistente de código: conteúdo nocivo, uso indevido e fraude](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [5] [Sysdig – LLMjacking: credenciais de cloud roubadas usadas em novo ataque de IA](https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/)
- [6] [Visão geral do esquema LLMJacking – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [7] [oai-reverse-proxy (revenda de acesso roubado a LLMs)](https://gitgud.io/khanon/oai-reverse-proxy)
- [8] [Synacktiv - Análise detalhada da implantação de um servidor LLM local com poucos privilégios](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [9] [README do servidor llama.cpp](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [10] [Quadlets do Podman: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [11] [Especificação CNCF Container Device Interface (CDI)](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [12] [Unit 42 – Phantom Squatting: domínios alucinados por IA como vetor da cadeia de suprimentos de software](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [13] [Socket – Slopsquatting: como alucinações de IA estão alimentando uma nova classe de ataques à cadeia de suprimentos](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)
{{#include ../banners/hacktricks-training.md}}
