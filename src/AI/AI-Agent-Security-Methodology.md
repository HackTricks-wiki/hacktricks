# Metodologia de Segurança de AI Agent

{{#include ../banners/hacktricks-training.md}}

Uma avaliação de agent deve seguir **da entrada controlada pelo atacante até um efeito observável externamente**. Jailbreaking, alterações de personagem e divulgação do system prompt demonstram que um canal de raciocínio pode ser influenciado, mas a descoberta de alto impacto é a cadeia que leva ao acesso a dados, a uma ação não autorizada de uma ferramenta, a um sink de injeção downstream, à persistência ou a outro agent.<sup>[[2]](#references)</sup>

O [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) é útil para rotular a cobertura (sequestro de objetivos, uso indevido de ferramentas, abuso de privilégios, cadeia de suprimentos, execução de código, envenenamento de memória, confiança entre agents, falhas em cascata, confiança humana e agents rogue). Use esses rótulos depois de construir um caminho de ataque de ponta a ponta, em vez de tratar um texto inesperado do modelo como o fim do teste.<sup>[[1]](#references)[[2]](#references)</sup>

## Criar o mapa do alvo

Registre estas cinco dimensões para cada workflow de agent antes de elaborar payloads:<sup>[[2]](#references)</sup>

| Dimensão | O que enumerar | Questão de segurança |
|---|---|---|
| **Entrada não confiável** | Parâmetros de Chat/API, URLs, documentos, email, tickets, entradas de calendário, trechos recuperados, memória, resultados de ferramentas e mensagens de agents pares | Onde um atacante pode inserir conteúdo que depois entre no contexto do modelo? |
| **Ferramentas** | Nomes e schemas das ferramentas, efeitos colaterais, execução automática, comportamento de confirmação e ferramentas carregadas dinamicamente | Quais chamadas leem segredos, alteram estado, enviam mensagens, excluem dados, executam código ou transferem valor? |
| **Autoridade** | Delegação do usuário, contas de serviço, API tokens, validade das credenciais, escopo de tenant/recurso e alcance de rede | Com qual identidade cada chamada é executada, e a autorização é repetida no limite da ferramenta? |
| **Processamento** | Construtores de queries, shells, buscadores de URL, engines de templates, interpretadores, parsers, operações de arquivos e desserializadores | Onde os dados gerados pelo modelo se tornam sintaxe para outro interpretador? |
| **Saída** | Respostas, Markdown/HTML renderizado, links, buscas de imagens, webhooks, email, arquivos, logs, relatórios, métricas e tráfego entre agents | Qual canal observável pode transportar um segredo ou acionar uma requisição secundária? |

Não reduza isso a uma lista de integrações anunciadas. Um artefato útil mapeia cada origem para a posição exata do contexto que alcança, as ferramentas disponíveis nesse ponto, a credencial usada por cada ferramenta, o interpretador downstream e todas as rotas de egress. A mesma ferramenta pode ter baixo impacto com um token de leitura por usuário e ser crítica com uma credencial compartilhada de administrador.<sup>[[2]](#references)</sup>

## Reconhecimento

### Mapear todos os caminhos de entrega e ingestão

Comece pela superfície de entrega (web, mobile, API, email, plataforma de chat, extensão de navegador) e faça proxy do tráfego entre cliente e backend. Inspecione campos ocultos pela UI, parâmetros de busca/autocomplete/filtro, objetos de estado da conversa, jobs de upload e indexação, respostas de ferramentas e tráfego de sub-agents. Clientes exclusivos para mobile podem exigir um emulador e instrumentação para contornar o certificate pinning antes que o schema real das requisições fique visível.<sup>[[2]](#references)</sup>

Em seguida, mapeie a stack abaixo do modelo: framework de orquestração, montagem de prompts, stores de retrieval e memória, runtime (por exemplo, Python, container ou WASM), volumes montados, serviços do host, APIs internas, acesso a cloud metadata e redes vizinhas. Os padrões do framework importam porque algumas “chamadas de ferramentas” são implementadas gerando ou avaliando código; o limite do runtime/sandbox determina se o resultado permanece contido.<sup>[[2]](#references)</sup>

### Identificar o roteamento com probes não destrutivos

Compare uma requisição dentro do escopo com várias requisições não relacionadas, preservando a resposta completa, o status code, a latência e o comportamento de streaming. Uma rejeição estável antes de qualquer raciocínio específico da tarefa pode indicar um gateway/classifier separado; uma recusa contextual sugere que a requisição chegou ao modelo; uma resposta vazia ou puramente extrativa pode indicar keyword search ou retrieval restrito. Trate essas observações como hipóteses e confirme-as reproduzindo o mesmo probe por campos alternativos da API e caminhos de ingestão.<sup>[[2]](#references)</sup>

O reconhecimento está concluído quando a avaliação consegue identificar a primeira origem controlada pelo atacante que altera o comportamento do agent **e** as ferramentas, identidades, interpretadores e saídas alcançáveis a partir dessa origem.<sup>[[2]](#references)</sup>

## Exploração: atravessar um limite de confiança

Teste os canais, não apenas a formulação do prompt. Comece com injeção direta para estabelecer o que a interface visível bloqueia e, em seguida, repita uma intenção equivalente pelos caminhos menos visíveis abaixo:<sup>[[2]](#references)</sup>

- **Conteúdo indireto:** páginas, arquivos, email, tickets, metadados, alt text, comentários HTML, texto fora da tela ou caracteres de largura zero. Consulte [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) para técnicas de entrega de payload.
- **Retrieval e memória:** envenene conteúdo que será recuperado depois ou estado que será recarregado em sessões futuras. Registre se a exclusão da origem original remove o comportamento.
- **Saída de ferramentas e agents pares:** coloque o marker em uma resposta de ferramenta ou mensagem entre agents para testar se o tráfego interno contorna filtros aplicados apenas à entrada do usuário e à saída final.
- **Cadeia de suprimentos:** avalie descritores de ferramentas, plugins, servidores conectados, skills, modelos e dependências como fontes de instruções confiáveis. Para testes específicos de MCP, consulte [MCP Servers](AI-MCP-Servers.md#mcp-vulns).
- **Aprovação humana:** compare a chamada estruturada real da ferramenta com o texto de aprovação gerado pelo modelo. Teste se a influência do atacante consegue omitir o destino, o escopo, os objetos afetados ou os efeitos colaterais irreversíveis.

Use primeiro um marker único e inofensivo. Preserve o artefato de origem, o contexto montado se estiver visível, a chamada de ferramenta selecionada, os dados de aprovação, a requisição/resposta do backend e o estado final. Isso permite distinguir influência de uma alegação alucinada de que uma ação ocorreu.<sup>[[2]](#references)</sup>

### Texto com aparência de política em um avaliador de risco de ferramentas

Um gate de ferramentas baseado em modelo pode receber texto controlado pelo atacante dentro de um contexto de classificação que, de resto, é útil. O `AutoModeMiddleware` experimental do LangChain, por exemplo, envia uma chamada de ferramenta proposta, seus argumentos, uma descrição opcional da ferramenta e até 30 mensagens recentes a um avaliador `is_risky` do TypeSafe. Ele bloqueia as ferramentas configuradas quando a probabilidade Noul retornada é pelo menos `0.5`; as ferramentas não listadas não são classificadas por esse middleware.<sup>[[5]](#references)</sup> O TypeSafe também alerta que texto adversarial no estado pode influenciar uma classificação, mesmo quando o estado deveria ser apenas dado.<sup>[[6]](#references)</sup>

Uma **política falsificada** é diferente de simplesmente afirmar ser uma mensagem do sistema. Ela insere rótulos alternativos ou definições de risco em um estado de menor confiança e induz o avaliador a usar essas definições em vez dos critérios definidos pelo developer. No teste da Datadog, um `profile_description` editável pelo usuário foi copiado para os argumentos da ferramenta junto com `can_edit:false`. O texto com aparência de política argumentava que uma tentativa de escrita era de baixo risco porque uma verificação de permissão separada a rejeitaria antes de qualquer alteração. Em 40 execuções, a média da pontuação `is_risky` caiu de `0.893` para `0.290`, enquanto uma comparação direta com falsificação de papel teve média de `0.905`. A média abaixo de `0.5` não prova que todas as chamadas individuais passaram pelo gate, e o experimento **não** demonstrou uma escrita não autorizada concluída.<sup>[[7]](#references)</sup>

Ao testar esse limite, diferencie o veredito do classifier do resultado real da autorização da ferramenta. Verifique quais campos editáveis chegam ao avaliador, compare a mesma ação proposta com e sem texto com aparência de política e verifique o estado final de forma independente. Uma verificação de permissão separada ainda deve usar a autoridade do solicitante autenticado, não os direitos da conta de serviço do connector.<sup>[[7]](#references)</sup> Consulte [prompt-filter bypasses](AI-Prompts.md#prompt-waf-bypass) para outros modos de falha de classifiers; [LLM gateway trust boundaries](AI-LLM-Gateway-Security.md) trata de um limite diferente de roteamento e credenciais.

### Isolamento de contexto de subagents

Um subagent do Claude Agent SDK que não usa fork recebe seu próprio `AgentDefinition.prompt`, o prompt de delegação e as ferramentas disponíveis, mas não o system prompt nem a conversa do parent. Se `tools` for omitido da definição, ele herda as ferramentas disponíveis para subagents; o `CLAUDE.md` do projeto ainda pode ser carregado. Isso torna uma restrição de prompt aplicada apenas ao parent um limite pouco confiável quando o child pode usar as mesmas ferramentas de sistema de arquivos ou execução.<sup>[[4]](#references)</sup>

Teste o limite comparando uma requisição direta recusada pelo parent com a mesma tarefa delegada a um subagent nomeado. A NCC Group relata que uma enumeração de arquivos do sistema operacional recusada foi bem-sucedida quando reformulada para um child como um inofensivo “mapa de layout”.<sup>[[3]](#references)</sup>

Inspecione as chamadas reais de ferramentas do child e sua allowlist efetiva de ferramentas, não apenas a resposta final do parent; confirme se o child acessou arquivos que o parent não acessaria.<sup>[[4]](#references)</sup> Trata-se de uma falha na herança de guardrails, não de prova de um [Python sandbox](../generic-methodologies-and-resources/python/bypass-python-sandboxes/) ou de escape de container.<sup>[[3]](#references)[[4]](#references)</sup>

## Execução: comprovar o impacto real

Há duas rotas distintas entre influência e impacto:<sup>[[2]](#references)</sup>

1. **Abuso de capacidade:** a ferramenta autorizada já executa o objetivo. Exemplos incluem ler o registro de um tenant e gravá-lo em um relatório visível ao atacante, enviar email, alterar registros, excluir um arquivo ou iniciar um pagamento. Não é necessário um bug de software secundário.
2. **Exploração de sink downstream:** a saída do modelo direcionada pelo atacante se torna sintaxe para outro componente. Analise queries de banco de dados em busca de [SQL injection](../pentesting-web/sql-injection/README.md) ou [NoSQL injection](../pentesting-web/nosql-injection.md), wrappers de shell em busca de [command injection](../pentesting-web/command-injection.md), URLs escolhidas em busca de [SSRF](../pentesting-web/ssrf-server-side-request-forgery/README.md), operações de arquivos em busca de traversal, avaliadores de templates/código em busca de RCE e parsers de objetos em busca de [unsafe deserialization](../pentesting-web/deserialization/README.md).

Para cada hipótese, comprove esta cadeia:<sup>[[2]](#references)</sup>

```text
attacker-controlled source
  -> model/context influence
  -> selected tool and arguments
  -> effective identity/credential
  -> capability or vulnerable sink
  -> externally verified state change or data egress
```

Uma integração somente leitura ainda pode ser explorada quando qualquer componente posterior pode publicar o que leu. Teste respostas comuns e canais de saída menos óbvios, como links controlados pelo atacante, recuperação automática de imagens, webhooks, logs, relatórios, contadores, notificações e mensagens para outros agentes.<sup>[[2]](#references)</sup>

## Ações sobre objetivos

Depois de confirmar uma ação, avalie todo o raio de impacto em vez de parar no primeiro efeito visível:<sup>[[2]](#references)</sup>

- **Exfiltração:** segredos, registros de usuários, arquivos internos, dados de conversas ou conteúdo de prompts/contexto saem por um canal observável.
- **Ação não autorizada:** o agente usa recursos legítimos de escrita para atingir o objetivo do atacante.
- **Negação de serviço:** ferramentas destrutivas ou operações caras repetidas afetam a integridade ou a disponibilidade.
- **Persistência:** memória envenenada, conteúdo indexado, estado confiável ou alterações de runtime persistem após o término da sessão ou a remoção da fonte original.
- **Propagação:** um peer confiável consome a mensagem ou o estado compartilhado do agente comprometido e repete a ação usando as próprias ferramentas e credenciais.

A severidade deve considerar os dados acessíveis, os privilégios efetivos, a explorabilidade do sink, o egress, a persistência e a propagação — não o quanto o texto do modelo parece surpreendente.<sup>[[2]](#references)</sup>

## Controles a validar durante a avaliação

Filtros de prompt e um system prompt melhor podem aumentar o custo para o atacante, mas não devem ser tratados como limites de autorização. Valide os controles abaixo reexecutando a mesma cadeia por meio de entrada direta, conteúdo indireto, memória, ferramentas e agentes peers:<sup>[[2]](#references)</sup>

- Uma camada determinística de políticas verifica o usuário autenticado, o tenant, o objeto, a ação e o destino em **cada invocação de ferramenta**; o modelo não pode fornecer nem substituir a identidade de quem fez a chamada.
- Os recursos de leitura e escrita usam credenciais separadas, de privilégio mínimo e de curta duração; ferramentas de alto impacto são disponibilizadas just-in-time e nunca são executadas automaticamente a partir de conteúdo ingerido.
- O egress de rede e os destinos internos são allowlisted independentemente das URLs escolhidas pelo modelo; o acesso do runtime a endpoints de metadados, segredos montados e serviços vizinhos é bloqueado, a menos que seja necessário.
- A interface de aprovação é gerada a partir da solicitação estruturada canônica e mostra os argumentos exatos, a identidade, o destino, os objetos afetados e os efeitos colaterais — não um resumo em texto livre gerado pelo modelo.
- O sucesso é verificado no sistema de destino ou no sistema de registro oficial. A descrição do agente, uma solicitação de chamada de ferramenta ou um redirecionamento HTTP não comprovam a alteração de estado alegada.
- As entradas de memória e recuperação mantêm a proveniência e os rótulos de confiança, podem ser invalidadas e são reautorizadas quando usadas em uma ação posterior.
- As mensagens entre agentes são autenticadas e autorizadas como solicitações não confiáveis; a reputação de um peer ou seu cartão de agente não delega implicitamente as ferramentas do agente receptor.

Para conferir cartões de agente A2A, fluxos de tarefas e sua superfície de ataque, consulte [Segurança do protocolo A2A](AI-A2A-Protocol.md).

## References

- [1] [OWASP Top 10 para Aplicações Agentic de 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [2] [O guia do hacker para atacar agentes de IA](https://darkmarc.substack.com/p/the-hackers-guide-to-attacking-ai)
- [3] [Quão difícil é realmente tirar um agente de IA de seu sandbox?](https://www.nccgroup.com/research/how-hard-is-it-really-to-break-an-ai-agent-out-of-its-sandbox/)
- [4] [Subagentes no SDK](https://code.claude.com/docs/en/agent-sdk/subagents)
- [5] [Código-fonte do middleware TypeSafe Auto Mode do LangChain](https://github.com/langchain-ai/langchain/blob/master/libs/partners/typesafe/langchain_typesafe/experimental/middleware/auto_mode.py)
- [6] [Irregularidade do modelo TypeSafe AI Jev: conteúdo adversarial](https://docs.typesafe.ai/model-jaggedness/jev-1.13#adversarial-content)
- [7] [Jev como juiz: como uma política falsificada direciona Jev](https://securitylabs.datadoghq.com/articles/jev-as-a-judge-how-counterfeit-policy-steers-jev/)
{{#include ../banners/hacktricks-training.md}}
