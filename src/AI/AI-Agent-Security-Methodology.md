# Metodologia de Segurança de AI Agent

{{#include ../banners/hacktricks-training.md}}

Uma avaliação de agent deve seguir **uma entrada controlada pelo atacante até um efeito observável externamente**. Jailbreaking, alterações de caractere e divulgação do system prompt demonstram que um canal de raciocínio pode ser influenciado, mas a descoberta de alto impacto é a cadeia que leva ao acesso a dados, a uma ação não autorizada de uma ferramenta, a um sink de injeção downstream, à persistência ou a outro agent.<sup>[[2]](#references)</sup>

O [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) é útil para identificar a cobertura (sequestro de objetivos, uso indevido de ferramentas, abuso de privilégios, cadeia de suprimentos, execução de código, envenenamento de memória, confiança entre agents, falhas em cascata, confiança humana e agents maliciosos). Use esses rótulos depois de construir um caminho de ataque de ponta a ponta, em vez de tratar um texto inesperado do modelo como o fim do teste.<sup>[[1]](#references)[[2]](#references)</sup>

## Mapeie o alvo

Registre estas cinco dimensões para cada fluxo de trabalho do agent antes de criar payloads:<sup>[[2]](#references)</sup>

| Dimensão | O que enumerar | Pergunta de segurança |
|---|---|---|
| **Entrada não confiável** | Parâmetros de Chat/API, URLs, documentos, e-mail, tickets, entradas de calendário, trechos recuperados, memória, resultados de ferramentas e mensagens de peer-agents | Onde um atacante pode inserir conteúdo que depois entra no contexto do modelo? |
| **Ferramentas** | Nomes e schemas de ferramentas, efeitos colaterais, execução automática, comportamento de confirmação e ferramentas carregadas dinamicamente | Quais chamadas leem secrets, gravam estado, enviam mensagens, excluem dados, executam código ou transferem valor? |
| **Autoridade** | Delegação do usuário, contas de serviço, API tokens, duração das credenciais, escopo de tenant/recurso e alcance da rede | Com qual identidade cada chamada é executada, e a autorização é verificada novamente no limite da ferramenta? |
| **Processamento** | Construtores de consultas, shells, buscadores de URL, engines de template, interpretadores, parsers, operações de arquivo e desserializadores | Onde os dados gerados pelo modelo se tornam sintaxe para outro interpretador? |
| **Saída** | Respostas, Markdown/HTML renderizado, links, buscas de imagem, webhooks, e-mail, arquivos, logs, relatórios, métricas e tráfego entre peer-agents | Qual canal observável pode transportar um secret ou acionar uma solicitação secundária? |

Não reduza isso a uma lista de integrações anunciadas. Um artefato útil mapeia cada origem à posição exata do contexto que ela alcança, às ferramentas disponíveis nesse ponto, à credencial usada por cada ferramenta, ao interpretador downstream e a todas as rotas de saída. A mesma ferramenta pode ter baixo impacto com um token de leitura por usuário e ser crítica com uma credencial de administrador compartilhada.<sup>[[2]](#references)</sup>

## Reconhecimento

### Mapeie cada caminho de entrega e ingestão

Comece pela superfície de entrega (web, mobile, API, e-mail, plataforma de chat, extensão de navegador) e faça proxy do tráfego entre cliente e backend. Inspecione campos ocultos pela UI, parâmetros de pesquisa/autocomplete/filtro, objetos de estado da conversa, tarefas de upload e indexação, respostas de ferramentas e tráfego de subagents. Clientes apenas para mobile podem exigir um emulador e instrumentação para contornar o certificate pinning antes que o schema real da solicitação fique visível.<sup>[[2]](#references)</sup>

Em seguida, mapeie a stack sob o modelo: framework de orquestração, montagem de prompt, armazenamentos de recuperação e memória, runtime (por exemplo, Python, container ou WASM), volumes montados, serviços do host, APIs internas, acessibilidade de metadados de cloud e redes vizinhas. Os padrões do framework importam porque algumas “chamadas de ferramenta” são implementadas gerando ou avaliando código; o limite do runtime/sandbox determina se o resultado fica contido.<sup>[[2]](#references)</sup>

### Identifique o roteamento com probes não destrutivos

Compare uma solicitação dentro do escopo com várias solicitações não relacionadas, preservando a resposta completa, o código de status, a latência e o comportamento de streaming. Uma rejeição estável antes de qualquer raciocínio específico da tarefa pode indicar um gateway/classificador separado; uma recusa contextual sugere que a solicitação chegou ao modelo; uma resposta vazia ou puramente extrativa pode indicar busca por palavra-chave ou recuperação limitada. Trate essas hipóteses como provisórias e confirme-as repetindo o mesmo probe por campos alternativos da API e caminhos de ingestão.<sup>[[2]](#references)</sup>

O reconhecimento está completo quando a avaliação consegue identificar a primeira origem controlada pelo atacante que altera o comportamento do agent **e** as ferramentas, identidades, interpretadores e saídas acessíveis a partir dessa origem.<sup>[[2]](#references)</sup>

## Exploração: atravesse um limite de confiança

Teste os canais, não apenas a formulação do prompt. Comece com injeção direta para determinar o que a entrada visível bloqueia e, em seguida, repita uma intenção equivalente pelos caminhos menos visíveis abaixo:<sup>[[2]](#references)</sup>

- **Conteúdo indireto:** páginas, arquivos, e-mail, tickets, metadados, alt text, comentários HTML, texto fora da tela ou caracteres de largura zero. Consulte [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) para técnicas de entrega de payload.
- **Recuperação e memória:** envenene conteúdo que será recuperado mais tarde ou estado que será recarregado em sessões futuras. Registre se a exclusão da origem original remove o comportamento.
- **Saída de ferramentas e peer-agents:** coloque o marcador em uma resposta de ferramenta ou mensagem entre agents para testar se o tráfego interno ignora filtros aplicados apenas à entrada do usuário e à saída final.
- **Cadeia de suprimentos:** analise descritores de ferramentas, plugins, servidores conectados, skills, modelos e dependências como fontes confiáveis de instruções. Para testes específicos de MCP, consulte [MCP Servers](AI-MCP-Servers.md#mcp-vulns).
- **Aprovação humana:** compare a chamada estruturada real da ferramenta com o texto de aprovação gerado pelo modelo. Teste se a influência do atacante pode omitir o destino, o escopo, os objetos afetados ou os efeitos colaterais irreversíveis.

Use primeiro um marcador exclusivo e benigno. Preserve o artefato de origem, o contexto montado, se observável, a chamada de ferramenta selecionada, os dados de aprovação, a solicitação/resposta do backend e o estado final. Isso diferencia influência de uma alegação alucinada de que uma ação ocorreu.<sup>[[2]](#references)</sup>

### Texto com aparência de política em um avaliador de risco de ferramenta

Um gate de ferramenta baseado em modelo pode receber texto controlado pelo atacante dentro de um contexto de classificação que, de outra forma, seria útil. O `AutoModeMiddleware` experimental do LangChain, por exemplo, envia uma chamada de ferramenta proposta, seus argumentos, uma descrição opcional da ferramenta e até 30 mensagens recentes a um avaliador TypeSafe `is_risky`. Ele bloqueia as ferramentas configuradas quando a probabilidade Noul retornada é pelo menos `0.5`; as ferramentas não listadas não são classificadas por esse middleware.<sup>[[5]](#references)</sup> TypeSafe também alerta que texto adversarial no estado pode influenciar uma classificação, mesmo quando o estado deveria ser tratado como dados.<sup>[[6]](#references)</sup>

Uma **política falsificada** é diferente de simplesmente alegar ser uma mensagem do sistema. Ela coloca rótulos alternativos ou definições de risco em um estado de menor confiança e incentiva o avaliador a usar essas definições no lugar dos critérios definidos pelo desenvolvedor. No teste da Datadog, um `profile_description` editável pelo usuário foi copiado para os argumentos da ferramenta junto com `can_edit:false`. O texto com aparência de política argumentava que uma tentativa de gravação era de baixo risco porque uma verificação de permissão separada a rejeitaria antes de qualquer alteração. Em 40 execuções, a pontuação média de `is_risky` caiu de `0.893` para `0.290`, enquanto uma comparação direta de falsificação de função teve média de `0.905`. A queda da média para menos de `0.5` não prova que todas as chamadas individuais passaram pelo gate, e o experimento **não** demonstrou uma gravação não autorizada concluída.<sup>[[7]](#references)</sup>

Ao testar esse limite, diferencie o veredito do classificador do resultado real da autorização da ferramenta. Verifique quais campos editáveis chegam ao avaliador, compare a mesma ação proposta com e sem texto com aparência de política e confirme o estado final de forma independente. Uma verificação de permissão separada ainda deve usar a autoridade do solicitante autenticado, e não os direitos da conta de serviço do conector.<sup>[[7]](#references)</sup> Consulte [prompt-filter bypasses](AI-Prompts.md#prompt-waf-bypass) para outros modos de falha de classificadores; [LLM gateway trust boundaries](AI-LLM-Gateway-Security.md) trata de um limite diferente de roteamento e credenciais.

### Isolamento de contexto de subagent

Um subagent não-fork do Claude Agent SDK recebe seu próprio `AgentDefinition.prompt`, o prompt de delegação e as ferramentas disponíveis, mas não o system prompt nem a conversa do parent. Se `tools` for omitido de sua definição, ele herda as ferramentas disponíveis para subagents; o `CLAUDE.md` do projeto ainda pode ser carregado. Isso torna uma restrição de prompt aplicada apenas ao parent um limite pouco confiável quando o child pode usar as mesmas ferramentas de sistema de arquivos ou execução.<sup>[[4]](#references)</sup>

Teste o limite comparando uma solicitação direta recusada pelo parent com a mesma tarefa delegada a um subagent nomeado. O NCC Group relata que uma enumeração de arquivos do sistema operacional recusada foi bem-sucedida quando reformulada para um child como um inofensivo "mapa de layout".<sup>[[3]](#references)</sup>

Inspecione as chamadas reais de ferramentas do child e sua allowlist efetiva de ferramentas, não apenas a resposta final do parent; confirme se o child acessou arquivos que o parent não acessaria.<sup>[[4]](#references)</sup> Isso é uma falha na herança de guardrails, não uma prova de [Python sandbox](../generic-methodologies-and-resources/python/bypass-python-sandboxes/) ou escape de container.<sup>[[3]](#references)[[4]](#references)</sup>

## Execução: comprove o impacto real

Há dois caminhos distintos da influência ao impacto:<sup>[[2]](#references)</sup>

1. **Abuso de capacidade:** a ferramenta autorizada já realiza o objetivo. Os exemplos incluem ler o registro de um tenant e gravá-lo em um relatório visível ao atacante, enviar e-mail, alterar registros, excluir um arquivo ou iniciar um pagamento. Não é necessário nenhum bug de software secundário.
2. **Exploração de sink downstream:** a saída do modelo direcionada pelo atacante se torna sintaxe para outro componente. Analise consultas a banco de dados em busca de [SQL injection](../pentesting-web/sql-injection/README.md) ou [NoSQL injection](../pentesting-web/nosql-injection.md), wrappers de shell em busca de [command injection](../pentesting-web/command-injection.md), URLs escolhidas em busca de [SSRF](../pentesting-web/ssrf-server-side-request-forgery/README.md), operações de arquivo em busca de traversal, avaliadores de template/código em busca de RCE e parsers de objetos em busca de [unsafe deserialization](../pentesting-web/deserialization/README.md).

Para cada possibilidade, comprove esta cadeia:<sup>[[2]](#references)</sup>

```text
attacker-controlled source
  -> model/context influence
  -> selected tool and arguments
  -> effective identity/credential
  -> capability or vulnerable sink
  -> externally verified state change or data egress
```

Uma integração somente de leitura ainda pode ser explorada quando qualquer componente posterior consegue publicar o que leu. Teste respostas comuns e formas de egress menos óbvias, como links controlados pelo atacante, carregamento automático de imagens, webhooks, logs, relatórios, contadores, notificações e mensagens para outros agentes.<sup>[[2]](#references)</sup>

## Ações sobre os objetivos

Depois de confirmar uma ação, avalie todo o raio de impacto em vez de parar no primeiro efeito visível:<sup>[[2]](#references)</sup>

- **Exfiltração:** segredos, registros de usuários, arquivos internos, dados de conversas ou conteúdo de prompt/contexto saem por um canal observável.
- **Ação não autorizada:** o agente usa recursos legítimos de escrita em prol do objetivo do atacante.
- **Negação de serviço:** ferramentas destrutivas ou operações dispendiosas repetidas afetam a integridade ou a disponibilidade.
- **Persistência:** memória envenenada, conteúdo indexado, estado confiável ou alterações no runtime persistem após o fim da sessão ou a remoção da origem.
- **Propagação:** um peer confiável consome a mensagem ou o estado compartilhado do agente comprometido e repete a ação usando suas próprias ferramentas e credenciais.

A gravidade deve levar em conta os dados acessíveis, o privilégio efetivo, a possibilidade de exploração do sink, o egress, a persistência e a propagação — não o quanto o texto do modelo parece surpreendente.<sup>[[2]](#references)</sup>

## Controles a validar durante a avaliação

Filtros de prompt e um system prompt melhor podem aumentar o custo para o atacante, mas não devem ser tratados como limites de autorização. Valide os controles abaixo repetindo a mesma cadeia por meio de entrada direta, conteúdo indireto, memória, ferramentas e agentes peer:<sup>[[2]](#references)</sup>

- Uma camada determinística de políticas verifica o usuário autenticado, o tenant, o objeto, a ação e o destino em **cada invocação de ferramenta**; o modelo não pode fornecer nem substituir a identidade do chamador.
- Os recursos de leitura e escrita usam credenciais separadas, com privilégio mínimo e validade curta; ferramentas de alto impacto são disponibilizadas just in time e nunca executadas automaticamente a partir de conteúdo ingerido.
- O egress de rede e os destinos internos são allowlisted independentemente das URLs selecionadas pelo modelo; o acesso do runtime a endpoints de metadados, segredos montados e serviços adjacentes é bloqueado, salvo quando necessário.
- A interface de aprovação é gerada a partir da solicitação estruturada canônica e mostra os argumentos exatos, a identidade, o destino, os objetos afetados e os efeitos colaterais — não um resumo em texto livre gerado pelo modelo.
- O sucesso é verificado no sistema de destino ou no sistema de registro oficial. A narração do agente, uma solicitação de chamada de ferramenta ou um redirecionamento HTTP não comprovam a alteração de estado alegada.
- As entradas de memória e recuperação mantêm a proveniência e os rótulos de confiança, podem ser invalidadas e são reautorizadas quando usadas em uma ação posterior.
- As mensagens entre agentes são autenticadas e autorizadas como solicitações não confiáveis; a reputação de um peer ou o cartão do agente não delega implicitamente as ferramentas do receptor.

## References

- [1] [OWASP Top 10 para Aplicações Agentic de 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [2] [O guia do hacker para atacar agentes de IA](https://darkmarc.substack.com/p/the-hackers-guide-to-attacking-ai)
- [3] [Quão difícil é realmente tirar um agente de IA de seu sandbox?](https://www.nccgroup.com/research/how-hard-is-it-really-to-break-an-ai-agent-out-of-its-sandbox/)
- [4] [Subagentes no SDK](https://code.claude.com/docs/en/agent-sdk/subagents)
- [5] [Código-fonte do middleware Auto Mode do TypeSafe LangChain](https://github.com/langchain-ai/langchain/blob/master/libs/partners/typesafe/langchain_typesafe/experimental/middleware/auto_mode.py)
- [6] [Jev model jaggedness da TypeSafe AI: conteúdo adversarial](https://docs.typesafe.ai/model-jaggedness/jev-1.13#adversarial-content)
- [7] [Jev como juiz: como uma política falsificada influencia Jev](https://securitylabs.datadoghq.com/articles/jev-as-a-judge-how-counterfeit-policy-steers-jev/)
{{#include ../banners/hacktricks-training.md}}
