# Metodologia de segurança de agentes de IA

{{#include ../banners/hacktricks-training.md}}

Uma avaliação de agente deve seguir **a entrada controlada pelo atacante até um efeito observável externamente**. Jailbreaking, alterações de caracteres e divulgação do system prompt provam que um canal de raciocínio pode ser influenciado, mas a descoberta de alto impacto é a cadeia que leva a acesso a dados, uma ação não autorizada de ferramenta, um ponto de injeção downstream, persistência ou outro agente.<sup>[[2]](#references)</sup>

O [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) é útil para classificar a cobertura (sequestro de objetivos, uso indevido de ferramentas, abuso de privilégios, cadeia de suprimentos, execução de código, envenenamento de memória, confiança entre agentes, falhas em cascata, confiança humana e agentes descontrolados). Use essas classificações depois de construir um caminho de ataque de ponta a ponta, em vez de tratar o texto inesperado de um modelo como o fim do teste.<sup>[[1]](#references)[[2]](#references)</sup>

## Crie o mapa do alvo

Registre estas cinco dimensões para cada fluxo de trabalho do agente antes de criar payloads:<sup>[[2]](#references)</sup>

| Dimensão | O que enumerar | Pergunta de segurança |
|---|---|---|
| **Entrada não confiável** | Parâmetros de chat/API, URLs, documentos, e-mails, tickets, entradas de calendário, fragmentos recuperados, memória, resultados de ferramentas e mensagens de agentes pares | Onde um atacante pode inserir conteúdo que depois entre no contexto do modelo? |
| **Ferramentas** | Nomes e schemas das ferramentas, efeitos colaterais, execução automática, comportamento de confirmação e ferramentas carregadas dinamicamente | Quais chamadas leem segredos, gravam estado, enviam mensagens, excluem dados, executam código ou transferem valor? |
| **Autoridade** | Delegação do usuário, contas de serviço, tokens de API, duração das credenciais, escopo de tenant/recurso e alcance da rede | Como qual identidade cada chamada é executada, e a autorização é verificada novamente na fronteira da ferramenta? |
| **Processamento** | Construtores de consultas, shells, buscadores de URL, mecanismos de template, interpretadores, parsers, operações de arquivo e desserializadores | Onde os dados gerados pelo modelo se tornam sintaxe para outro interpretador? |
| **Saída** | Respostas, Markdown/HTML renderizado, links, buscas de imagens, webhooks, e-mails, arquivos, logs, relatórios, métricas e tráfego entre agentes pares | Qual canal observável pode transportar um segredo ou acionar uma solicitação secundária? |

Não reduza isso a uma lista de integrações anunciadas. Um artefato útil mapeia cada origem à posição exata do contexto que alcança, às ferramentas disponíveis naquele ponto, à credencial usada por cada ferramenta, ao interpretador downstream e a todas as rotas de saída. A mesma ferramenta pode ter baixo impacto com um token de leitura por usuário e ser crítica com uma credencial compartilhada de administrador.<sup>[[2]](#references)</sup>

## Reconhecimento

### Mapeie todos os caminhos de entrega e ingestão

Comece pela superfície de entrega (web, dispositivos móveis, API, e-mail, plataforma de chat, extensão de navegador) e intercepte o tráfego entre cliente e backend. Inspecione campos ocultos pela UI, parâmetros de busca/autocomplete/filtro, objetos de estado da conversa, tarefas de upload e indexação, respostas de ferramentas e tráfego de subagentes. Clientes exclusivos para dispositivos móveis podem exigir um emulador e instrumentação para contornar o certificate pinning antes que o schema real da solicitação fique visível.<sup>[[2]](#references)</sup>

Depois, mapeie a stack sob o modelo: framework de orquestração, montagem de prompt, armazenamentos de recuperação e memória, runtime (por exemplo, Python, container ou WASM), volumes montados, serviços do host, APIs internas, acessibilidade de metadados da cloud e redes vizinhas. Os padrões do framework são importantes, pois algumas “chamadas de ferramenta” são implementadas gerando ou avaliando código; o limite do runtime/sandbox determina se esse resultado permanece contido.<sup>[[2]](#references)</sup>

### Identifique o roteamento com probes não destrutivos

Compare uma solicitação dentro do escopo com várias solicitações não relacionadas, preservando a resposta completa, o código de status, a latência e o comportamento de streaming. Uma rejeição estável antes de qualquer raciocínio específico da tarefa pode indicar um gateway/classificador separado; uma recusa contextual sugere que a solicitação chegou ao modelo; uma resposta vazia ou puramente extrativa pode indicar busca por palavras-chave ou recuperação limitada. Trate isso como hipóteses e confirme reproduzindo o mesmo probe em campos de API e caminhos de ingestão alternativos.<sup>[[2]](#references)</sup>

O reconhecimento está concluído quando a avaliação consegue identificar a origem controlada pelo atacante mais precoce que altera o comportamento do agente **e** as ferramentas, identidades, interpretadores e saídas alcançáveis a partir dessa origem.<sup>[[2]](#references)</sup>

## Exploração: atravesse uma fronteira de confiança

Teste os canais, não apenas a formulação do prompt. Comece com injeção direta para determinar o que a porta de entrada visível bloqueia e, em seguida, repita uma intenção equivalente pelos caminhos menos visíveis abaixo:<sup>[[2]](#references)</sup>

- **Conteúdo indireto:** páginas, arquivos, e-mails, tickets, metadados, texto alternativo, comentários HTML, texto fora da tela ou caracteres de largura zero. Consulte [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) para técnicas de entrega de payload.
- **Recuperação e memória:** envenene conteúdo que será recuperado posteriormente ou estado que será recarregado em sessões futuras. Registre se a exclusão da origem original remove o comportamento.
- **Saída de ferramentas e agentes pares:** coloque o marcador em uma resposta de ferramenta ou mensagem entre agentes para testar se o tráfego interno ignora os filtros aplicados somente à entrada do usuário e à saída final.
- **Cadeia de suprimentos:** analise descritores de ferramentas, plugins, servidores conectados, skills, modelos e dependências como fontes de instruções confiáveis. Para testes específicos de MCP, consulte [MCP Servers](AI-MCP-Servers.md#mcp-vulns).
- **Aprovação humana:** compare a chamada estruturada real da ferramenta com o texto de aprovação gerado pelo modelo. Teste se a influência do atacante pode omitir o destino, o escopo, os objetos afetados ou os efeitos colaterais irreversíveis.

Use primeiro um marcador benigno e exclusivo. Preserve o artefato de origem, o contexto montado se for observável, a chamada de ferramenta selecionada, os dados de aprovação, a solicitação/resposta do backend e o estado final. Isso permite diferenciar influência de uma alegação alucinada de que uma ação ocorreu.<sup>[[2]](#references)</sup>

### Texto com aparência de política em um avaliador de risco de ferramentas

Um controle de ferramentas baseado em modelo pode receber texto controlado pelo atacante dentro de um contexto de classificação que, de resto, é útil. O `AutoModeMiddleware` experimental do LangChain, por exemplo, envia uma chamada de ferramenta proposta, seus argumentos, uma descrição opcional da ferramenta e até 30 mensagens recentes a um avaliador `is_risky` do TypeSafe. Ele bloqueia ferramentas configuradas quando a probabilidade Noul retornada é de pelo menos `0.5`; ferramentas não listadas não são classificadas por esse middleware.<sup>[[5]](#references)</sup> O TypeSafe também alerta que texto adversarial no estado pode influenciar uma classificação, mesmo quando o estado deveria ser tratado como dados.<sup>[[6]](#references)</sup>

Uma **política falsificada** é diferente de simplesmente alegar ser uma mensagem do sistema. Ela insere rótulos alternativos ou definições de risco em estado de menor confiança e induz o avaliador a usar essas definições em vez dos critérios definidos pelo desenvolvedor. No teste da Datadog, um `profile_description` editável pelo usuário era copiado para os argumentos da ferramenta junto com `can_edit:false`. O texto com aparência de política argumentava que uma tentativa de gravação era de baixo risco porque uma verificação de permissão separada a rejeitaria antes de qualquer alteração. Em 40 execuções, a pontuação média de `is_risky` caiu de `0.893` para `0.290`, enquanto uma comparação direta com falsificação de função teve média de `0.905`. A média abaixo de `0.5` não prova que todas as chamadas individuais passaram pelo controle, e o experimento **não** demonstrou uma gravação não autorizada concluída.<sup>[[7]](#references)</sup>

Ao testar essa fronteira, diferencie a decisão do classificador do resultado real da autorização da ferramenta. Verifique quais campos editáveis chegam ao avaliador, compare a mesma ação proposta com e sem texto com aparência de política e verifique o estado final de forma independente. Uma verificação de permissão separada ainda deve usar a autoridade do solicitante autenticado, não os direitos da conta de serviço do conector.<sup>[[7]](#references)</sup> Consulte [prompt-filter bypasses](AI-Prompts.md#prompt-waf-bypass) para outros modos de falha de classificadores; [LLM gateway trust boundaries](AI-LLM-Gateway-Security.md) aborda uma fronteira diferente de roteamento e credenciais.

### Isolamento do contexto de subagentes

Um subagente não-fork do Claude Agent SDK recebe seu próprio `AgentDefinition.prompt`, o prompt de delegação e as ferramentas disponíveis, mas não recebe o system prompt nem a conversa do agente pai. Se `tools` for omitido da definição, o subagente herda as ferramentas disponíveis para subagentes; o `CLAUDE.md` do projeto ainda pode ser carregado. Isso torna pouco confiável uma restrição de prompt aplicada apenas ao agente pai como fronteira, quando o filho pode usar as mesmas ferramentas de sistema de arquivos ou execução.<sup>[[4]](#references)</sup>

Teste a fronteira comparando uma solicitação direta que o agente pai recusa com a mesma tarefa delegada a um subagente nomeado. A NCC Group relata que uma enumeração de arquivos do sistema operacional recusada foi bem-sucedida quando reformulada para o filho como um inofensivo “mapa de layout”.<sup>[[3]](#references)</sup>

Inspecione as chamadas reais de ferramentas do filho e a lista efetiva de ferramentas permitidas, não apenas a resposta final do pai; confirme se o filho acessou arquivos que o pai não acessaria.<sup>[[4]](#references)</sup> Trata-se de uma falha de herança de guardrails, não de prova de escape de [Python sandbox](../generic-methodologies-and-resources/python/bypass-python-sandboxes/) ou de container.<sup>[[3]](#references)[[4]](#references)</sup>

### Agentes GUI móveis: instruções na tela e reatribuição de ações

Um agente GUI de telefone pode enviar cada captura de tela a um modelo cloud antes de escolher a próxima ação entre aplicativos. Para testar **injeção visual indireta**, insira texto controlado pelo atacante em um SMS, e-mail ou página que o agente inspecionará durante uma tarefa autorizada. Compare um prompt de tarefa direto com a mesma instrução visível apenas na captura de tela e, em seguida, inspecione a próxima ação e qualquer decisão sobre operações de alto risco. No assistente avaliado, `checkPrompt` no cliente filtrava o texto direto da tarefa, mas não aplicava uma filtragem equivalente ao conteúdo da captura de tela. Esta é uma variante móvel e entre aplicativos de [injeção por captura de tela em navegadores agentic](../generic-methodologies-and-resources/phishing-methodology/ai-agent-mode-phishing-abusing-hosted-agent-browsers.md), não uma forma de contornar a autenticação de componentes Android.<sup>[[9]](#references)</sup>

Um teste ilustrativo de efeito colateral usa um formulário controlado pelo atacante que solicita ao agente o preenchimento de campos sensíveis e, em seguida, pede que uma pessoa clique em “upload”, enquanto a página envia os campos preenchidos assim que eles mudam. A transferência para uma pessoa não pode proteger dados que já foram enviados pelo código da página; verifique o envio real em vez de tratar a narração do agente como prova. A fonte apresenta isso como um padrão possível, não como um comprometimento demonstrado de todos os assistentes.<sup>[[9]](#references)</sup>

**TOCTOU de GUI / reatribuição de ação** é um modo de falha distinto: o agente planeja uma entrada a partir de uma tela observada em `t0`, mas a UI em primeiro plano muda antes de a entrada ser injetada em `t1`.<sup>[[8]](#references)</sup> Uma captura de tela posterior em `t2` não pode desfazer uma ação já executada.<sup>[[9]](#references)</sup> Em um teste Android autorizado, o fluxo de trabalho reutilizável é:<sup>[[8]](#references)</sup>

1. Analise as coordenadas de tela do controle-alvo e renderize um controle benigno na mesma posição em um aplicativo controlado.
2. Mantenha esse aplicativo visível até que o agente o observe; em seguida, acione uma transição normal para primeiro plano durante o intervalo entre a observação e a ação.
3. Verifique se o toque planejado atinge o controle do novo aplicativo e confirme o estado resultante no aplicativo-alvo, em vez de confiar na narração do agente.

O estudo original sobre reatribuição de ações demonstra isso com um aplicativo que não possui permissões perigosas; também descreve a repetição da transição pelo loop de recuperação de tarefas do agente em fluxos com várias etapas.<sup>[[8]](#references)</sup>

**Não** presuma que a primitiva funcione sem alterações contra todos os assistentes. Na avaliação do Doubao, `OpClickUI` ignorava cliques se a Activity de nível superior mudasse e comparava capturas de tela quando `OpOpenApp` aparecia nas três etapas anteriores. Portanto, toques simples, pressionamentos longos e toques duplos ofereciam poucas oportunidades confiáveis para o atacante controlar o momento. `OpTypeText`, `OpSwipeUI` e `OpScrollWheelAction` não tinham proteções equivalentes, mas o relatório avaliou seu impacto prático como mais limitado.<sup>[[9]](#references)</sup>

## Execução: prove o impacto real

Há duas rotas distintas da influência ao impacto:<sup>[[2]](#references)</sup>

1. **Abuso de capacidade:** a ferramenta autorizada já realiza o objetivo. Exemplos incluem ler o registro de um tenant e gravá-lo em um relatório visível ao atacante, enviar e-mails, alterar registros, excluir um arquivo ou iniciar um pagamento. Não é necessário nenhum bug de software secundário.
2. **Exploração de ponto de entrada downstream:** a saída do modelo direcionada pelo atacante se torna sintaxe para outro componente. Analise consultas de banco de dados em busca de [SQL injection](../pentesting-web/sql-injection/README.md) ou [NoSQL injection](../pentesting-web/nosql-injection.md), wrappers de shell em busca de [command injection](../pentesting-web/command-injection.md), URLs escolhidas em busca de [SSRF](../pentesting-web/ssrf-server-side-request-forgery/README.md), operações de arquivo em busca de traversal, avaliadores de template/código em busca de RCE e parsers de objetos em busca de [unsafe deserialization](../pentesting-web/deserialization/README.md).

Para cada candidato, comprove esta cadeia:<sup>[[2]](#references)</sup>

```text
attacker-controlled source
  -> model/context influence
  -> selected tool and arguments
  -> effective identity/credential
  -> capability or vulnerable sink
  -> externally verified state change or data egress
```

Uma integração somente de leitura ainda pode ser explorada quando qualquer componente posterior puder publicar o que ela leu. Teste respostas comuns e canais de saída menos óbvios, como links controlados pelo atacante, recuperação automática de imagens, webhooks, logs, relatórios, contadores, notificações e mensagens para outros agentes.<sup>[[2]](#references)</sup>

## Ações sobre objetivos

Após confirmar uma ação, avalie todo o raio de impacto, em vez de parar no primeiro efeito visível:<sup>[[2]](#references)</sup>

- **Exfiltração:** segredos, registros de usuários, arquivos internos, dados de conversas ou conteúdo de prompt/contexto saem por um canal observável.
- **Ação não autorizada:** o agente usa capacidades legítimas de gravação para cumprir o objetivo do atacante.
- **Negação de serviço:** ferramentas destrutivas ou operações repetidas e caras afetam a integridade ou a disponibilidade.
- **Persistência:** memória envenenada, conteúdo indexado, estado confiável ou alterações em tempo de execução persistem após o fim da sessão ou a remoção da origem.
- **Propagação:** um peer confiável consome a mensagem ou o estado compartilhado do agente comprometido e repete a ação com suas próprias ferramentas e credenciais.

A gravidade deve considerar os dados acessíveis, o privilégio efetivo, a explorabilidade do sink, a saída de dados, a persistência e a propagação — não o quão surpreendente parece o texto do modelo.<sup>[[2]](#references)</sup>

## Controles a validar durante a avaliação

Filtros de prompt e um system prompt melhor podem aumentar o custo para o atacante, mas não devem ser tratados como limites de autorização. Valide os controles abaixo executando novamente a mesma cadeia por entrada direta, conteúdo indireto, memória, ferramentas e agentes peers:<sup>[[2]](#references)</sup>

- Uma camada determinística de políticas verifica o usuário autenticado, o tenant, o objeto, a ação e o destino em **toda invocação de ferramenta**; o modelo não pode fornecer nem substituir a identidade do chamador.
- As capacidades de leitura e gravação usam credenciais separadas, de privilégio mínimo e de curta duração; ferramentas de alto impacto são disponibilizadas just-in-time e nunca são executadas automaticamente com base em conteúdo ingerido.
- A saída de rede e os destinos internos são incluídos em allowlists independentemente das URLs selecionadas pelo modelo; o acesso em tempo de execução a endpoints de metadados, segredos montados e serviços adjacentes é bloqueado, a menos que seja necessário.
- A interface de aprovação é gerada a partir da solicitação estruturada canônica e mostra os argumentos exatos, a identidade, o destino, os objetos afetados e os efeitos colaterais — não um resumo em texto livre do modelo.
- O sucesso é verificado no sistema de destino ou no sistema de registro oficial. A narração do agente, uma solicitação de chamada de ferramenta ou um redirecionamento HTTP não comprovam a alteração de estado alegada.
- As entradas de memória e recuperação mantêm a proveniência e os rótulos de confiança, podem ser invalidadas e são reautorizadas quando usadas em uma ação posterior.
- As mensagens entre agentes são autenticadas e autorizadas como solicitações não confiáveis; a reputação de um peer ou seu cartão de agente não delega implicitamente as ferramentas do agente receptor.

Para cartões de agente A2A, fluxos de tarefas e sua superfície de ataque, consulte [A2A Protocol Security](AI-A2A-Protocol.md).

## References

- [1] [OWASP Top 10 para Aplicações Agentic de 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [2] [O guia do hacker para atacar agentes de IA](https://darkmarc.substack.com/p/the-hackers-guide-to-attacking-ai)
- [3] [Quão difícil é realmente tirar um agente de IA de seu sandbox?](https://www.nccgroup.com/research/how-hard-is-it-really-to-break-an-ai-agent-out-of-its-sandbox/)
- [4] [Subagentes no SDK](https://code.claude.com/docs/en/agent-sdk/subagents)
- [5] [Código-fonte do middleware TypeSafe Auto Mode do LangChain](https://github.com/langchain-ai/langchain/blob/master/libs/partners/typesafe/langchain_typesafe/experimental/middleware/auto_mode.py)
- [6] [Jaggedness do modelo TypeSafe AI Jev: conteúdo adversarial](https://docs.typesafe.ai/model-jaggedness/jev-1.13#adversarial-content)
- [7] [Jev como juiz: como uma política falsificada direciona Jev](https://securitylabs.datadoghq.com/articles/jev-as-a-judge-how-counterfeit-policy-steers-jev/)
- [8] [Manipulação sem permissões: podemos confiar em agentes de GUI baseados em grandes modelos multimodais?](https://arxiv.org/html/2601.12349v1)
- [9] [Quando um assistente de IA se torna parte da cadeia de ataque de um hacker | Análise de segurança do Doubao Phone](https://www.darknavy.org/blog/security_analysis_of_doubao_phone/)
{{#include ../banners/hacktricks-training.md}}
