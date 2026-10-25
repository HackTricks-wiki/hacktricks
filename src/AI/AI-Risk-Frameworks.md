# Riscos de IA

{{#include ../banners/hacktricks-training.md}}

## Top 10 Vulnerabilidades de Machine Learning da OWASP

A OWASP identificou as 10 principais vulnerabilidades de machine learning que podem afetar sistemas de IA. Essas vulnerabilidades podem levar a vários problemas de segurança, incluindo data poisoning, model inversion e ataques adversariais. Entender essas vulnerabilidades é essencial para criar sistemas de IA seguros.

Para consultar uma lista atualizada e detalhada das 10 principais vulnerabilidades de machine learning, acesse o projeto [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).<sup>[[1]](#references)</sup>

- **Ataque de Manipulação de Entrada**: Um atacante adiciona pequenas alterações, muitas vezes invisíveis, aos **dados de entrada** para que o modelo tome a decisão errada.\
    *Exemplo*: Algumas manchas de tinta em uma placa de pare fazem um carro autônomo "enxergar" uma placa de limite de velocidade.

- **Ataque de Data Poisoning**: O **conjunto de treinamento** é deliberadamente contaminado com amostras ruins, ensinando regras prejudiciais ao modelo.\
*Exemplo*: Binários de malware são rotulados incorretamente como "benignos" em um corpus de treinamento de antivírus, permitindo que malwares semelhantes passem despercebidos mais tarde.

- **Ataque de Model Inversion**: Ao sondar as saídas, um atacante constrói um **modelo reverso** que reconstrói características sensíveis das entradas originais.\
*Exemplo*: Recriar a imagem de ressonância magnética de um paciente a partir das previsões de um modelo de detecção de câncer.

- **Ataque de Inferência de Associação**: O adversário testa se um **registro específico** foi usado durante o treinamento, identificando diferenças nos níveis de confiança.\
*Exemplo*: Confirmar que uma transação bancária de uma pessoa consta nos dados de treinamento de um modelo de detecção de fraude.

- **Roubo de Modelo**: Consultas repetidas permitem que um atacante aprenda os limites de decisão e **clone o comportamento do modelo** (e a propriedade intelectual).\
*Exemplo*: Coletar pares suficientes de perguntas e respostas de uma API de ML-as-a-Service para criar um modelo local quase equivalente.

- **Ataque à Cadeia de Suprimentos de IA**: Comprometer qualquer componente (dados, bibliotecas, pesos pré-treinados, CI/CD) no **pipeline de ML** para corromper os modelos subsequentes.\
*Exemplo*: Uma dependência contaminada em um model hub instala um modelo de análise de sentimentos com backdoor em vários aplicativos.

- **Ataque de Transfer Learning**: Uma lógica maliciosa é inserida em um **modelo pré-treinado** e sobrevive ao fine-tuning para a tarefa da vítima.\
*Exemplo*: Um modelo base de visão computacional com um gatilho oculto continua alterando rótulos após ser adaptado para imagens médicas.

- **Desvio do Modelo**: Dados sutilmente tendenciosos ou rotulados incorretamente **alteram as saídas do modelo** para favorecer os objetivos do atacante.\
*Exemplo*: Inserir e-mails de spam "limpos" rotulados como ham para que um filtro de spam permita a passagem de e-mails semelhantes no futuro.

- **Ataque à Integridade da Saída**: O atacante **altera as previsões do modelo em trânsito**, não o próprio modelo, enganando os sistemas subsequentes.\
*Exemplo*: Alterar o veredito "malicioso" de um classificador de malware para "benigno" antes que o estágio de quarentena do arquivo o receba.

- **Model Poisoning** --- Alterações diretas e direcionadas nos **parâmetros do modelo**, geralmente após obter acesso de gravação, para mudar o comportamento.\
*Exemplo*: Ajustar os pesos de um modelo de detecção de fraude em produção para que as transações de determinados cartões sejam sempre aprovadas.


## Riscos do Google SAIF

O [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) do Google descreve vários riscos associados a sistemas de IA:<sup>[[2]](#references)</sup>

- **Data Poisoning**: Agentes maliciosos alteram ou inserem dados de treinamento/ajuste para reduzir a precisão, implantar backdoors ou distorcer resultados, comprometendo a integridade do modelo em todo o ciclo de vida dos dados.

- **Dados de Treinamento Não Autorizados**: A ingestão de conjuntos de dados protegidos por direitos autorais, sensíveis ou não autorizados cria responsabilidades legais, éticas e de desempenho, pois o modelo aprende com dados que não tinha permissão para usar.

- **Adulteração da Origem do Modelo**: A manipulação por agentes da cadeia de suprimentos ou pessoas internas do código, das dependências ou dos pesos do modelo antes ou durante o treinamento pode inserir uma lógica oculta que persiste mesmo após o retreinamento.

- **Tratamento Excessivo de Dados**: Controles fracos de retenção e governança de dados levam os sistemas a armazenar ou processar mais dados pessoais do que o necessário, aumentando a exposição e os riscos de conformidade.

- **Exfiltração do Modelo**: Atacantes roubam arquivos/pesos do modelo, causando perda de propriedade intelectual e possibilitando serviços de imitação ou ataques subsequentes.

- **Adulteração da Implantação do Modelo**: Adversários modificam artefatos do modelo ou a infraestrutura de serving, fazendo com que o modelo em execução seja diferente da versão verificada e potencialmente alterando seu comportamento.

- **Negação de Serviço de ML**: Inundar APIs ou enviar entradas "sponge" pode esgotar recursos computacionais/energia e tirar o modelo do ar, emulando ataques DoS clássicos.

- **Engenharia Reversa do Modelo**: Ao coletar grandes quantidades de pares de entrada e saída, atacantes podem clonar ou destilar o modelo, alimentando produtos de imitação e ataques adversariais personalizados.

- **Componente Integrado Inseguro**: Plugins, agentes ou serviços upstream vulneráveis permitem que atacantes injetem código ou escalem privilégios no pipeline de IA.

- **Prompt Injection**: Criar prompts (direta ou indiretamente) para inserir instruções que sobreponham a intenção do sistema, fazendo o modelo executar comandos não pretendidos.

- **Evasão do Modelo**: Entradas cuidadosamente projetadas levam o modelo a classificar incorretamente, alucinar ou gerar conteúdo não permitido, comprometendo a segurança e a confiança.

- **Divulgação de Dados Sensíveis**: O modelo revela informações privadas ou confidenciais dos dados de treinamento ou do contexto do usuário, violando a privacidade e as regulamentações.

- **Dados Sensíveis Inferidos**: O modelo deduz atributos pessoais que nunca foram fornecidos, criando novos danos à privacidade por meio de inferências.

- **Saída Insegura do Modelo**: Respostas não sanitizadas transmitem código nocivo, desinformação ou conteúdo impróprio aos usuários ou a sistemas subsequentes.

- **Ações Não Autorizadas**: Agentes integrados de forma autônoma executam operações não pretendidas no mundo real (gravações de arquivos, chamadas de API, compras etc.) sem supervisão adequada do usuário.

## Matriz MITRE AI ATLAS

A [Matriz MITRE AI ATLAS](https://atlas.mitre.org/matrices/ATLAS) fornece uma estrutura abrangente para entender e mitigar riscos associados a sistemas de IA. Ela categoriza diversas técnicas de ataque e táticas que adversários podem usar contra modelos de IA, além de mostrar como usar sistemas de IA para realizar diferentes ataques.<sup>[[3]](#references)</sup>

## LLMJacking (Roubo de Tokens e Revenda de Acesso a LLMs Hospedados na Nuvem)

Atacantes roubam tokens de sessão ativos ou credenciais de API da nuvem e invocam LLMs pagos, hospedados na nuvem, sem autorização. O acesso costuma ser revendido por meio de proxies reversos que encaminham solicitações pela conta da vítima, por exemplo, implantações de "oai-reverse-proxy". As consequências incluem perdas financeiras, uso indevido do modelo fora das políticas e atribuição das atividades ao tenant da vítima.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

TTPs:
- Coletar tokens de máquinas de desenvolvedores ou navegadores infectados; roubar segredos de CI/CD; comprar cookies vazados.<sup>[[5]](#references)</sup>
- Configurar um proxy reverso que encaminhe solicitações ao provedor legítimo, ocultando a chave upstream e multiplexando muitos clientes.<sup>[[5]](#references)</sup><sup>[[7]](#references)</sup>
- Abusar de endpoints diretos do modelo base para contornar as proteções corporativas e os limites de taxa.<sup>[[4]](#references)</sup>

Mitigações:
- Vincular tokens à impressão digital do dispositivo, a intervalos de IP e à atestação do cliente; exigir expirações curtas e renovação com MFA.
- Limitar o escopo das chaves ao mínimo (sem acesso a ferramentas, somente leitura quando aplicável); alterná-las em caso de anomalia.
- Encerrar todo o tráfego no lado do servidor, por trás de um gateway de políticas que aplique filtros de segurança, cotas por rota e isolamento entre tenants.
- Monitorar padrões de uso incomuns (aumentos repentinos de gastos, regiões atípicas, strings UA) e revogar automaticamente sessões suspeitas.
- Preferir mTLS ou JWTs assinados emitidos pelo seu IdP em vez de chaves de API estáticas de longa duração.

## Reforço da segurança da inferência de LLMs auto-hospedados

Executar um servidor LLM local para dados confidenciais cria uma superfície de ataque diferente das APIs hospedadas na nuvem: endpoints de inferência/depuração podem leak prompts, a stack de serving geralmente expõe um proxy reverso e os nós de dispositivo GPU dão acesso a grandes superfícies de `ioctl()`. Se você estiver avaliando ou implantando um serviço de inferência on-prem, analise pelo menos os pontos a seguir.<sup>[[8]](#references)</sup>

### Vazamento de prompts por endpoints de depuração e monitoramento

Trate a API de inferência como um **serviço sensível multiusuário**. Rotas de depuração ou monitoramento podem expor o conteúdo dos prompts, o estado dos slots, metadados do modelo ou informações internas da fila. No `llama.cpp`, o endpoint `/slots` é especialmente sensível porque expõe o estado de cada slot e destina-se apenas à inspeção/gerenciamento de slots.<sup>[[8]](#references)</sup>

Para identificação por fingerprinting black-box e testes de runners de modelos expostos e serviços de IA relacionados, consulte [Exposed Self-Hosted AI Services](AI-Exposed-Self-Hosted-AI-Services.md).

- Coloque um proxy reverso na frente do servidor de inferência e **negue por padrão**.
- Permita apenas as combinações exatas de método HTTP + caminho necessárias para o cliente/UI.
- Desative endpoints de introspecção no próprio backend sempre que possível, por exemplo, com `llama-server --no-slots`.<sup>[[9]](#references)</sup>
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

### Contêineres rootless sem rede e sockets UNIX

Se o daemon de inferência aceitar conexões em um socket UNIX, prefira essa opção em vez de TCP e execute o contêiner **sem pilha de rede**:<sup>[[8]](#references)</sup>

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
- `--network none` remove a exposição TCP/IP de entrada/saída e evita auxiliares em modo de usuário que, de outra forma, os contêineres rootless precisariam.
- Um socket UNIX permite usar permissões/ACLs POSIX no caminho do socket como primeira camada de controle de acesso.
- `--userns=keep-id` e o Podman rootless reduzem o impacto de um escape do contêiner, pois o root do contêiner não é o root do host.
- Montagens de modelo somente para leitura reduzem a chance de adulteração do modelo de dentro do contêiner.

Em implantações persistentes, as mesmas restrições podem ser expressas como unidades Podman Quadlet. Se o acesso à GPU for delegado por meio da Container Device Interface, mantenha a especificação de dispositivo CDI o mais restrita possível, em vez de expor todos os nós de aceleradores.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>

### Minimização de nós de dispositivo da GPU

Para inferência com GPU, os arquivos `/dev/nvidia*` são superfícies de ataque locais de alto valor, pois expõem grandes handlers de driver `ioctl()` e caminhos potencialmente compartilhados de gerenciamento de memória da GPU.<sup>[[8]](#references)</sup>

- Não deixe `/dev/nvidia*` com permissão de escrita para todos.
- Restrinja `nvidia`, `nvidiactl` e `nvidia-uvm` com `NVreg_DeviceFileUID/GID/Mode`, regras udev e ACLs para que somente o UID mapeado do contêiner possa abri-los.
- Coloque na blacklist módulos desnecessários, como `nvidia_drm`, `nvidia_modeset` e `nvidia_peermem`, em hosts de inferência headless.
- Pré-carregue apenas os módulos necessários na inicialização, em vez de permitir que o runtime execute `modprobe` oportunisticamente durante a inicialização da inferência.

Exemplo:

```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```

Um ponto importante da revisão é **`/dev/nvidia-uvm`**. Mesmo que a carga de trabalho não use explicitamente `cudaMallocManaged()`, runtimes CUDA recentes ainda podem exigir `nvidia-uvm`. Como esse dispositivo é compartilhado e gerencia a memória virtual da GPU, trate-o como uma superfície de exposição de dados entre tenants. Se o backend de inferência oferecer suporte, um backend Vulkan pode ser uma alternativa interessante, pois talvez evite expor `nvidia-uvm` ao container.<sup>[[8]](#references)</sup>

### Confinamento LSM para workers de inferência

AppArmor/SELinux/seccomp devem ser usados como defesa em profundidade para o processo de inferência:<sup>[[8]](#references)</sup>

- Permita somente as bibliotecas compartilhadas, os caminhos dos modelos, o diretório de sockets e os nós de dispositivo da GPU realmente necessários.
- Negue explicitamente recursos de alto risco, como `sys_admin`, `sys_module`, `sys_rawio` e `sys_ptrace`.
- Mantenha o diretório do modelo somente para leitura e restrinja os caminhos graváveis apenas aos diretórios de sockets/cache do runtime.
- Monitore os logs de negação, pois eles fornecem telemetria útil para detecção quando o servidor do modelo ou um payload de pós-exploração tenta escapar do comportamento esperado.

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

## Phantom Squatting: domínios alucinados por LLMs como vetor de ataque à cadeia de suprimentos de IA

Phantom squatting é o **equivalente de domínio/URL do slopsquatting**. Em vez de alucinar o nome de um pacote inexistente, o LLM alucina um **domínio plausível de portal, API, webhook, cobrança, SSO, download ou suporte** de uma marca real, e um atacante registra esse namespace antes que uma pessoa ou um agente o use.<sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Isso importa porque, em muitos fluxos de trabalho assistidos por IA, a saída do modelo é tratada como uma **dependência confiável**:
- Desenvolvedores colam o endpoint sugerido no código ou em integrações de CI/CD.
- Agentes de IA buscam automaticamente documentação, schemas, APKs, ZIPs ou destinos de webhook.
- Runbooks ou documentos gerados podem incluir a URL falsa como se fosse oficial.

### Fluxo de ataque

1. **Investigue a superfície de alucinação**: faça perguntas específicas sobre uma marca, relacionadas a fluxos de trabalho realistas, como portais de `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` ou `mobile app`.<sup>[[12]](#references)</sup>
2. **Normalize os candidatos**: resolva as URLs geradas, reduza respostas NXDOMAIN ao domínio pai que pode ser registrado e remova duplicatas entre famílias de prompts. Os conjuntos de prompts devem continuar diversificados; por exemplo, descarte quase duplicatas usando **similaridade de Jaccard**.
3. **Priorize alucinações previsíveis**:
   - **Persistência Térmica da Alucinação (THP)**: o mesmo domínio falso aparece em diferentes temperaturas, inclusive em temperaturas baixas, como `T=0.1`.
   - **Consenso entre modelos**: várias famílias de LLMs geram o mesmo domínio falso.
4. **Registre e arme** o domínio pai e, em seguida, hospede páginas de phishing, downloads falsos de APK/ZIP, coletores de credenciais, documentos maliciosos ou endpoints de API que coletam segredos/payloads de webhook. **Alucinações apenas no nível do domínio** são as mais fáceis de monetizar, pois o atacante controla todo o namespace; alucinações de subdomínio/caminho ainda podem ser exploradas quando o domínio pai normalizado não está registrado.
5. **Explore a janela de reputação zero**: domínios recém-registrados geralmente não têm histórico em blocklists, reputação de URL ou telemetria consolidada, então podem contornar os controles até que as detecções sejam atualizadas. Atacantes podem prolongar essa janela usando respostas benignas apenas para crawlers, ocultação por redirecionamento, barreiras CAPTCHA ou preparação tardia do payload.

### Por que é perigoso para agentes

Para uma vítima humana, o domínio falso geralmente ainda exige um clique e outra ação. Em um **fluxo de trabalho agentivo**, o LLM pode ser tanto a **isca** quanto o **executor**: o agente recebe a URL alucinada, acessa-a, analisa a resposta e pode então vazar tokens, executar instruções, baixar uma dependência ou enviar dados envenenados para CI/CD sem qualquer revisão humana.<sup>[[12]](#references)</sup>

### Prompts práticos para atacantes

Prompts de alto rendimento geralmente parecem tarefas empresariais normais, e não iscas explícitas de phishing:<sup>[[12]](#references)</sup>
- “Qual é a URL do sandbox de pagamentos para as integrações de `<brand>`?”
- “Que endpoint de webhook devo usar para notificações de build de `<brand>`?”
- “Onde fica o portal de benefícios para funcionários / cobrança / SSO de `<brand>`?”
- “Forneça o link direto para baixar o APK Android ou o cliente para desktop de `<brand>`.”

### Inversão defensiva

Trate isso como um problema de monitoramento proativo de domínios, não apenas como um problema de prompt injection:<sup>[[12]](#references)</sup>
- Crie um **conjunto de prompts sobre marcas** e teste periodicamente os LLMs dos quais seus usuários/agentes dependem.
- Armazene as URLs alucinadas e acompanhe quais permanecem estáveis entre temperaturas/modelos.
- Acompanhe a **Janela de Exploração Adversarial (AEW)**: o intervalo entre a primeira alucinação e o registro do domínio pelo atacante. Uma AEW positiva significa que os defensores podem registrar preventivamente, criar um sinkhole ou bloquear antes da utilização maliciosa.
- Monitore transições de **NXDOMAIN → registrado** para os domínios pai.
- Após o registro, avalie o registrar, a data de criação, os servidores de nomes, a proteção de privacidade, o conteúdo da página, as capturas de tela, o status de página estacionada e a semelhança com os ativos da marca.
- Adicione controles de política para que agentes/desenvolvedores **não confiem por padrão em domínios gerados por LLMs**: exija listas de permissões, validação de propriedade, verificações de CT/RDAP ou aprovação humana antes do primeiro uso.

Isso se enquadra em várias categorias de risco de IA ao mesmo tempo: **ataque à cadeia de suprimentos de IA**, **saída insegura do modelo** e **ações não autorizadas** quando agentes consomem autonomamente a URL alucinada.

## References

- [1] [OWASP Top 10 de vulnerabilidades de machine learning](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google SAIF (Secure AI Framework) – Riscos](https://saif.google/secure-ai-framework/risks)
- [3] [Matriz de ameaças MITRE ATLAS](https://atlas.mitre.org/)
- [4] [Unit 42 – Os riscos dos LLMs assistentes de código: conteúdo nocivo, uso indevido e engano](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [5] [Sysdig – LLMjacking: credenciais de cloud roubadas usadas em novo ataque de IA](https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/)
- [6] [Visão geral do esquema de LLMJacking – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [7] [oai-reverse-proxy (revenda de acesso roubado a LLMs)](https://gitgud.io/khanon/oai-reverse-proxy)
- [8] [Synacktiv - Análise detalhada da implantação de um servidor LLM local com privilégios limitados](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [9] [README do servidor llama.cpp](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [10] [Quadlets do Podman: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [11] [Especificação da Container Device Interface (CDI) da CNCF](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [12] [Unit 42 – Phantom Squatting: domínios alucinados por IA como vetor de ataque à cadeia de suprimentos de software](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [13] [Socket – Slopsquatting: como as alucinações de IA estão impulsionando uma nova categoria de ataques à cadeia de suprimentos](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)
{{#include ../banners/hacktricks-training.md}}
