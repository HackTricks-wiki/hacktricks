# Metodologia de Segurança de Agentes de IA

{{#include ../banners/hacktricks-training.md}}

Uma avaliação de agente deve seguir **a entrada controlada pelo atacante até um efeito observável externamente**. Jailbreaking, alterações de caractere e divulgação do system prompt comprovam que um canal de raciocínio pode ser influenciado, mas a descoberta de alto impacto é a cadeia que leva ao acesso a dados, a uma ação não autorizada de ferramenta, a um ponto de injeção posterior, à persistência ou a outro agente.<sup>[[2]](#references)</sup>

O [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) é útil para rotular a cobertura (goal hijacking, tool misuse, privilege abuse, supply chain, code execution, memory poisoning, inter-agent trust, cascading failures, human trust e rogue agents). Use esses rótulos após construir um caminho de ataque de ponta a ponta, em vez de tratar um texto inesperado do modelo como o fim do teste.<sup>[[1]](#references)[[2]](#references)</sup>

## Mapeie o alvo

Registre estas cinco dimensões para cada fluxo de trabalho do agente antes de criar payloads:<sup>[[2]](#references)</sup>

| Dimensão | O que enumerar | Questão de segurança |
|---|---|---|
| **Entrada não confiável** | Parâmetros de chat/API, URLs, documentos, e-mail, tickets, eventos de calendário, trechos recuperados, memória, resultados de ferramentas e mensagens de agentes pares | Onde um atacante pode inserir conteúdo que depois entra no contexto do modelo? |
| **Ferramentas** | Nomes e esquemas das ferramentas, efeitos colaterais, execução automática, comportamento de confirmação e ferramentas carregadas dinamicamente | Quais chamadas leem segredos, alteram estado, enviam mensagens, excluem dados, executam código ou transferem valor? |
| **Autoridade** | Delegação do usuário, contas de serviço, tokens de API, duração das credenciais, escopo de locatário/recurso e alcance da rede | Com qual identidade cada chamada é executada, e a autorização é verificada novamente no limite da ferramenta? |
| **Processamento** | Construtores de consultas, shells, buscadores de URL, mecanismos de template, interpretadores, analisadores, operações de arquivo e desserializadores | Onde os dados gerados pelo modelo se tornam sintaxe para outro interpretador? |
| **Saída** | Respostas, Markdown/HTML renderizado, links, busca de imagens, webhooks, e-mail, arquivos, logs, relatórios, métricas e tráfego entre agentes | Qual canal observável pode transportar um segredo ou acionar uma solicitação secundária? |

Não reduza isso a uma lista de integrações anunciadas. Um artefato útil mapeia cada origem à posição exata do contexto que ela alcança, às ferramentas disponíveis nesse ponto, à credencial usada por cada ferramenta, ao interpretador posterior e a todas as rotas de saída. A mesma ferramenta pode ter baixo impacto com um token de leitura por usuário e ser crítica com uma credencial compartilhada de administrador.<sup>[[2]](#references)</sup>

## Reconhecimento

### Mapeie todos os caminhos de entrega e ingestão

Comece pela superfície de entrega (web, dispositivo móvel, API, e-mail, plataforma de chat, extensão de navegador) e intercepte o tráfego entre cliente e backend. Inspecione campos ocultos pela interface, parâmetros de busca/autocomplete/filtro, objetos de estado da conversa, tarefas de upload e indexação, respostas de ferramentas e tráfego de subagentes. Clientes exclusivos para dispositivos móveis podem exigir um emulador e instrumentação para contornar o certificate pinning antes que o esquema real da solicitação fique visível.<sup>[[2]](#references)</sup>

Em seguida, mapeie a pilha abaixo do modelo: framework de orquestração, montagem do prompt, armazenamentos de recuperação e memória, runtime (por exemplo, Python, contêiner ou WASM), volumes montados, serviços do host, APIs internas, acessibilidade de metadados da cloud e redes adjacentes. Os padrões do framework importam porque algumas “chamadas de ferramenta” são implementadas gerando ou avaliando código; o limite do runtime/sandbox determina se o resultado permanece contido.<sup>[[2]](#references)</sup>

### Identifique o roteamento com sondas não destrutivas

Compare uma solicitação dentro do escopo com várias solicitações não relacionadas, preservando a resposta completa, o código de status, a latência e o comportamento de streaming. Uma rejeição consistente antes de qualquer raciocínio específico da tarefa pode indicar um gateway/classificador separado; uma recusa contextual sugere que a solicitação chegou ao modelo; uma resposta vazia ou puramente extrativa pode indicar busca por palavra-chave ou recuperação restrita. Trate essas observações como hipóteses e confirme-as reproduzindo a mesma sonda por campos alternativos da API e caminhos de ingestão.<sup>[[2]](#references)</sup>

O reconhecimento está concluído quando a avaliação consegue identificar a origem controlada pelo atacante mais antiga que altera o comportamento do agente **e** as ferramentas, identidades, os interpretadores e as saídas alcançáveis a partir dessa origem.<sup>[[2]](#references)</sup>

## Exploração: atravesse um limite de confiança

Teste os canais, não apenas a formulação do prompt. Comece com injeção direta para estabelecer o que a entrada visível bloqueia e, em seguida, repita uma intenção equivalente pelos caminhos menos visíveis abaixo:<sup>[[2]](#references)</sup>

- **Conteúdo indireto:** páginas, arquivos, e-mail, tickets, metadados, texto alternativo, comentários HTML, texto fora da tela ou caracteres de largura zero. Consulte [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) para técnicas de entrega de payloads.
- **Recuperação e memória:** envenene conteúdo que será recuperado posteriormente ou estado que será recarregado em sessões futuras. Registre se a exclusão da fonte original remove o comportamento.
- **Saída de ferramenta e agentes pares:** coloque o marcador em uma resposta de ferramenta ou mensagem entre agentes para testar se o tráfego interno contorna os filtros aplicados somente à entrada do usuário e à saída final.
- **Supply chain:** analise descritores de ferramentas, plugins, servidores conectados, skills, modelos e dependências como fontes de instruções confiáveis. Para testes específicos de MCP, consulte [MCP Servers](AI-MCP-Servers.md#mcp-vulns).
- **Aprovação humana:** compare a chamada estruturada real da ferramenta com o texto de aprovação gerado pelo modelo. Teste se a influência do atacante pode omitir o destino, o escopo, os objetos afetados ou os efeitos colaterais irreversíveis.

Use primeiro um marcador exclusivo e inofensivo. Preserve o artefato de origem, o contexto montado se for observável, a chamada de ferramenta selecionada, os dados de aprovação, a solicitação/resposta do backend e o estado final. Isso permite distinguir influência de uma alegação alucinada de que uma ação ocorreu.<sup>[[2]](#references)</sup>

## Execução: comprove o impacto real

Há duas rotas distintas da influência ao impacto:<sup>[[2]](#references)</sup>

1. **Abuso de capacidade:** a ferramenta autorizada já realiza o objetivo. Exemplos incluem ler o registro de um locatário e gravá-lo em um relatório visível ao atacante, enviar e-mail, alterar registros, excluir um arquivo ou iniciar um pagamento. Não é necessário nenhum bug de software secundário.
2. **Exploração de ponto de entrada posterior:** a saída do modelo direcionada pelo atacante se torna sintaxe para outro componente. Analise consultas de banco de dados em busca de [SQL injection](../pentesting-web/sql-injection/README.md) ou [NoSQL injection](../pentesting-web/nosql-injection.md), wrappers de shell em busca de [command injection](../pentesting-web/command-injection.md), URLs escolhidas em busca de [SSRF](../pentesting-web/ssrf-server-side-request-forgery/README.md), operações de arquivo em busca de traversal, avaliadores de template/código em busca de RCE e analisadores de objetos em busca de [unsafe deserialization](../pentesting-web/deserialization/README.md).

Para cada hipótese, comprove esta cadeia:<sup>[[2]](#references)</sup>

```text
attacker-controlled source
  -> model/context influence
  -> selected tool and arguments
  -> effective identity/credential
  -> capability or vulnerable sink
  -> externally verified state change or data egress
```

Uma integração somente leitura ainda pode ser explorada quando qualquer componente posterior consegue publicar o que ela leu. Teste respostas comuns e canais de egress menos óbvios, como links controlados pelo atacante, busca automática de imagens, webhooks, logs, relatórios, contadores, notificações e mensagens para outros agentes.<sup>[[2]](#references)</sup>

## Ações sobre objetivos

Após confirmar uma ação, avalie o raio de impacto completo em vez de parar no primeiro efeito visível:<sup>[[2]](#references)</sup>

- **Exfiltração:** segredos, registros de usuários, arquivos internos, dados de conversas ou conteúdo de prompt/contexto saem por um canal observável.
- **Ação não autorizada:** o agente usa recursos legítimos de escrita para atingir o objetivo do atacante.
- **Negação de serviço:** ferramentas destrutivas ou operações repetidas e dispendiosas afetam a integridade ou a disponibilidade.
- **Persistência:** memória envenenada, conteúdo indexado, estado confiável ou alterações no runtime permanecem após o fim da sessão ou a remoção da fonte original.
- **Propagação:** um peer confiável consome a mensagem ou o estado compartilhado do agente comprometido e repete a ação com as próprias ferramentas e credenciais.

A gravidade deve considerar os dados acessíveis, o privilégio efetivo, a explorabilidade do sink, o egress, a persistência e a propagação — não o quanto o texto do modelo parece surpreendente.<sup>[[2]](#references)</sup>

## Controles a validar durante a avaliação

Filtros de prompt e um system prompt melhor podem aumentar o custo para o atacante, mas não devem ser tratados como limites de autorização. Valide os controles abaixo executando novamente a mesma cadeia por meio de entrada direta, conteúdo indireto, memória, ferramentas e agentes peers:<sup>[[2]](#references)</sup>

- Uma camada de políticas determinística verifica o usuário autenticado, o tenant, o objeto, a ação e o destino em **cada invocação de ferramenta**; o modelo não pode fornecer nem substituir a identidade do solicitante.
- Os recursos de leitura e escrita usam credenciais separadas, de privilégio mínimo e de curta duração; ferramentas de alto impacto são disponibilizadas just-in-time e nunca são executadas automaticamente a partir de conteúdo ingerido.
- O egress de rede e os destinos internos são permitidos por allowlist, independentemente das URLs selecionadas pelo modelo; o acesso do runtime a endpoints de metadados, secrets montados e serviços vizinhos é bloqueado, salvo quando necessário.
- A interface de aprovação é gerada a partir da solicitação estruturada canônica e exibe os argumentos exatos, a identidade, o destino, os objetos afetados e os efeitos colaterais — não um resumo livre do modelo.
- O sucesso é verificado no sistema de destino ou no sistema de registro oficial. A narração do agente, uma solicitação de chamada de ferramenta ou um redirecionamento HTTP não comprovam a alteração de estado alegada.
- As entradas de memória e recuperação mantêm a proveniência e os rótulos de confiança, podem ser invalidadas e são reautorizadas quando usadas em uma ação posterior.
- As mensagens entre agentes são autenticadas e autorizadas como solicitações não confiáveis; a reputação de um peer ou seu cartão de agente não delega implicitamente as ferramentas do destinatário.

## References

- [1] [OWASP Top 10 para Aplicações Agentic de 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [2] [O guia do hacker para atacar agentes de IA](https://darkmarc.substack.com/p/the-hackers-guide-to-attacking-ai)
{{#include ../banners/hacktricks-training.md}}
