# Segurança do protocolo A2A (Agent2Agent)

{{#include ../banners/hacktricks-training.md}}

## O que é A2A

A2A (Agent2Agent) é um protocolo aberto que permite que um agente de IA descubra outro agente e lhe envie trabalho por HTTP. MCP conecta um agente a **ferramentas e dados**; A2A conecta um agente a **outros agentes**, que geralmente são serviços remotos pertencentes a outra equipe ou empresa. Um servidor A2A é uma API web com um agente LLM por trás, então os próprios objetos do protocolo (cartões de agente, tarefas, webhooks de notificação push, cartões estendidos) adicionam verificações específicas de autenticação, IDOR e SSRF a um teste de API comum.<sup>[[1]](#references)[[2]](#references)</sup>

Os principais componentes são:

- **Cartão do agente:** um documento JSON que descreve o agente: nome, descrição, habilidades, URL(s) de serviço, transportes compatíveis, recursos (streaming, notificações push, cartão estendido) e os `securitySchemes` que o cliente deve usar. Ele é publicado em `https://<host>/.well-known/agent-card.json`. Implantações mais antigas que seguem a especificação 0.2.x usam `/.well-known/agent.json`.<sup>[[1]](#references)[[3]](#references)</sup>
- **Tarefa:** a unidade de trabalho. Uma mensagem cria uma tarefa (com um `id` e um `contextId` gerados pelo servidor), e o cliente depois a lê, cancela ou assina para receber atualizações.<sup>[[1]](#references)</sup>
- **Transportes:** JSON-RPC 2.0 sobre HTTP (com SSE para streaming), gRPC e uma vinculação REST HTTP+JSON.<sup>[[1]](#references)</sup>
- **Autenticação:** as credenciais vão nos cabeçalhos HTTP (por exemplo, `Authorization: Bearer ...`), nunca dentro do payload JSON-RPC. O cartão do agente informa qual esquema é obrigatório.<sup>[[1]](#references)</sup>

Os nomes dos métodos mudaram entre as versões, então experimente os dois conjuntos:<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

| Operação | JSON-RPC 0.2/0.3 | JSON-RPC 1.0 | REST 1.0 |
| --- | --- | --- | --- |
| Enviar mensagem | `message/send` | `SendMessage` | `POST /message:send` |
| Enviar em streaming | `message/stream` | `SendStreamingMessage` | `POST /message:stream` |
| Obter tarefa | `tasks/get` | `GetTask` | `GET /tasks/{id}` |
| Listar tarefas | - | `ListTasks` | `GET /tasks` |
| Cancelar tarefa | `tasks/cancel` | `CancelTask` | `POST /tasks/{id}:cancel` |
| Configuração de notificação push | `tasks/pushNotificationConfig/set` | `CreateTaskPushNotificationConfig` | `POST /tasks/{id}/pushNotificationConfigs` |
| Cartão estendido | `agent/getAuthenticatedExtendedCard` (0.3); HTTP `GET agent/authenticatedExtendedCard` (0.2.5) | `GetExtendedAgentCard` | `GET /extendedAgentCard` |

A especificação 1.0 usa o cabeçalho `A2A-Version` (ou um parâmetro da solicitação) para selecionar a versão; solicitações sem ele são tratadas como 0.3.<sup>[[1]](#references)</sup>

## Descoberta

```bash
curl -s https://target/.well-known/agent-card.json | jq .
curl -s https://target/.well-known/agent.json | jq .
```

No cartão, anote:

- Cada `url` de serviço: na versão 1.0, elas ficam em `supportedInterfaces`, enquanto cartões mais antigos podem expor uma `url` de nível superior. Registre cada endpoint e transporte, incluindo nomes de host internos, URLs de staging e portas alternativas.<sup>[[1]](#references)[[7]](#references)</sup>
- `skills`: mostram o que o agente pode fazer e quais ferramentas ou dados estão por trás dele.
- `securitySchemes` / `security`: se estiverem vazios ou ausentes, provavelmente o agente foi projetado para ser chamado sem credenciais.
- `capabilities.pushNotifications` e `capabilities.extendedAgentCard` (na versão 0.3, `supportsAuthenticatedExtendedCard`).

A especificação diz que o cartão público não deve conter credenciais nem detalhes internos de implementação; portanto, URLs internas, chaves ou listas detalhadas de ferramentas em um cartão público já constituem uma descoberta.<sup>[[1]](#references)</sup>

### Colisão de nome de Agent Card em um host multiagente

O `name` de um cartão é um rótulo legível por humanos, não uma identidade de roteamento estável.<sup>[[1]](#references)[[5]](#references)</sup> Se um host registrar dois peers remotos distintos com o mesmo nome local, sua árvore de agentes, nome de ferramenta gerado, mapa de clientes ou rota do broker poderá enviar uma tarefa destinada ao peer confiável para o outro peer.<sup>[[5]](#references)</sup> Para isso, o peer controlado pelo atacante precisa ser admitido no **mesmo namespace de roteamento**; publicar um cartão duplicado na Internet, por si só, não basta.<sup>[[5]](#references)</sup>

Teste o caminho de **admissão até despacho** do host com dois peers controlados, URLs distintas e um marcador inofensivo:<sup>[[5]](#references)</sup>

1. Registre o cartão, a origem e o seletor local do peer confiável. Registre um segundo peer cujo cartão tenha o mesmo `name`, mas cuja URL aponte para um endpoint sob seu controle.
2. Acione a operação que seleciona o peer confiável pelo nome. Teste as duas ordens de registro e, se os nomes se tornarem identificadores de ferramentas, a normalização de nomes padrão do host. Capture qual endpoint recebe o marcador e qual agente retorna a resposta.
3. Altere apenas o nome do segundo cartão e repita. Uma solicitação que chega ao segundo endpoint somente no caso de colisão comprova o despacho para o peer errado. Verifique separadamente se algum contexto sensível ou credencial foi realmente anexado; a colisão de nomes, por si só, **não** comprova transferência de credenciais ou de autoridade sobre ferramentas.

Se o chamador usar um endpoint fixo, vinculado à origem, em vez de resolver um nome de cartão, este teste não se aplica.<sup>[[5]](#references)</sup> Para respostas subsequentes de peers maliciosos e o impacto de prompt-injection, consulte [AI Agent Security Methodology](AI-Agent-Security-Methodology.md#exploitation-cross-a-trust-boundary).

## Testando endpoints A2A

### Envio de tarefa sem autenticação

Envie uma mensagem mínima, sem credenciais, para cada `url` listada no cartão:

```bash
# 0.2 / 0.3 style
curl -s https://target/a2a -H 'Content-Type: application/json' -d '{
  "jsonrpc":"2.0","id":1,"method":"message/send",
  "params":{"message":{"role":"user","messageId":"6f1c2b9e-0000-4000-8000-000000000001",
            "parts":[{"kind":"text","text":"Reply only with the word PONG."}]}}}'

# 1.0 style
curl -s https://target/a2a -H 'Content-Type: application/json' -H 'A2A-Version: 1.0' -d '{
  "jsonrpc":"2.0","id":1,"method":"SendMessage",
  "params":{"message":{"role":"ROLE_USER","messageId":"6f1c2b9e-0000-4000-8000-000000000002",
            "parts":[{"text":"Reply only with the word PONG."}]}}}'
```

Um resultado `Task` ou `Message` com `PONG`, quando o card declara um esquema de segurança, significa que a autenticação não é aplicada no endpoint RPC (ela pode ser aplicada apenas na UI ou no card). Se o card não declarar nenhum esquema, verifique o que as skills do agent conseguem acessar: um agent sem autenticação que pode ler dados internos ou chamar tools equivale a uma API sem autenticação para essas tools.

### Task IDOR (`tasks/get`, `GetTask`, cancel, subscribe)

A spec exige que o servidor verifique, em cada solicitação, se o caller pode acessar a task e que limite `ListTasks` ao caller, mesmo quando nenhum filtro é fornecido.<sup>[[1]](#references)</sup> Teste com duas identidades (A e B):

1. Como A, crie uma task e salve seu `id` e `contextId`.
2. Como B (ou sem credenciais), chame `tasks/get` / `GetTask` com o `id` de A e, em seguida, `ListTasks` sem parâmetros.
3. Tente também cancelar e assinar a task de A, e enviar uma nova mensagem como B que inclua o `taskId` ou `contextId` de A (isso adicionaria o texto de B à conversa de A).

```json
{"jsonrpc":"2.0","id":2,"method":"tasks/get","params":{"id":"<task id of user A>","historyLength":10}}
```

Vulnerável: B recebe o histórico, os artefatos ou o status de A, ou pode alterar a tarefa de A. Seguro: um `TaskNotFoundError`, sem diferença entre “existe, mas não é sua” e “não existe”.<sup>[[1]](#references)</sup> Os IDs de tarefa costumam ser UUIDs, então procure-os em locais onde possam vazar (links compartilhados, logs, payloads de notificações push, mensagens de erro).

### SSRF em webhook de notificação push

Quando `capabilities.pushNotifications` é true, o cliente fornece ao agente uma URL de webhook, e o agente depois envia solicitações `POST` com atualizações da tarefa para essa URL. A especificação diz que os agentes devem rejeitar intervalos privados, localhost e endereços link-local, e usar listas de permissões.<sup>[[1]](#references)</sup> Crie uma tarefa, registre uma configuração de notificação push cuja `url` aponte para seu host OAST para confirmar as solicitações de saída e, então (somente se o escopo permitir), teste alvos internos como `http://127.0.0.1:<port>/` ou `http://169.254.169.254/`. Compare os erros e o tempo de resposta para mapear serviços internos. O agente também adiciona o cabeçalho de autenticação configurado a essas solicitações; portanto, verifique se ele não é enviado a um host escolhido pelo atacante quando você puder alterar a URL da configuração de outro usuário. Veja [SSRF](../pentesting-web/ssrf-server-side-request-forgery/).

### Partes de URL de arquivo como um segundo ponto de entrada de SSRF

O A2A 1.0 permite que uma mensagem ou um artefato inclua uma referência a arquivo como um `Part` com `url` (a versão 0.3 usa `kind: "file"` e `file.uri`).<sup>[[1]](#references)[[4]](#references)[[7]](#references)</sup> O protocolo transporta a referência; buscá-la é um comportamento da aplicação, não um requisito do SDK do A2A.<sup>[[6]](#references)</sup> Isso é separado da URL de callback de notificação push acima. Teste as duas direções: um arquivo fornecido pelo cliente e enviado a um servidor A2A, e uma URL de arquivo retornada por um peer de menor confiança a um orquestrador.<sup>[[1]](#references)[[6]](#references)</sup>

Para um endpoint JSON-RPC 1.0 autorizado, substitua a parte de texto normal por uma URL para um caminho OAST exclusivo e verifique **qual componente** faz a solicitação:<sup>[[1]](#references)[[7]](#references)</sup>

```bash
curl -s https://target/a2a -H 'Content-Type: application/json' -H 'A2A-Version: 1.0' -d '{
  "jsonrpc":"2.0","id":1,"method":"SendMessage",
  "params":{"message":{"role":"ROLE_USER",
    "messageId":"6f1c2b9e-0000-4000-8000-000000000003",
    "parts":[{"url":"https://oast.example/part-probe","filename":"probe.txt","mediaType":"text/plain"}]}}}'
```

Somente se o destinatário fizer a requisição, teste destinos internos dentro do escopo, redirecionamentos e alterações na resolução DNS usando o [workflow de SSRF](../pentesting-web/ssrf-server-side-request-forgery/). Um `Part` válido ou uma resposta de tarefa bem-sucedida, por si só, não comprova SSRF; confirme a requisição no destino e se o conteúdo obtido chega ao agente.<sup>[[6]](#references)</sup>

### Acesso ao cartão estendido do agente

`GetExtendedAgentCard` deve exigir autenticação e pode retornar mais habilidades e configurações do que o cartão público.<sup>[[1]](#references)</sup> Faça a chamada sem credenciais e com uma identidade de baixo privilégio e compare o resultado com o cartão público.

### Configuração de notificações push e vazamentos de credenciais em tarefas

As configurações de notificações push armazenam uma URL de webhook e as credenciais que o agente envia para ela. A especificação exige que cada operação de configuração de notificação push (criar, obter, listar, excluir) verifique se o chamador pode acessar a tarefa.<sup>[[1]](#references)</sup> Repita o teste com duas identidades descrito na [seção sobre IDOR de tarefas](#task-idor-tasksget-gettask-cancel-subscribe) nessas rotas. Uma configuração de outro usuário que possa ser lida vaza um token de webhook; se puder ser alterada, redireciona as atualizações de tarefas desse usuário para seu host.

Quando um agente precisa de autorização adicional durante uma tarefa, ele move a tarefa para `TASK_STATE_AUTH_REQUIRED`. O cliente pode providenciar a autorização out of band; a especificação diz que os agentes devem receber credenciais out of band, a menos que um mecanismo in-band tenha sido negociado. A troca in-band pode transmitir uma credencial por uma cadeia de agentes A2A e expô-la a todos os agentes dessa cadeia.<sup>[[1]](#references)</sup> Em um teste de orquestrador, verifique se uma credencial fornecida pelo usuário para um agente downstream aparece em mensagens, artefatos ou no histórico da tarefa que outros agentes (ou outros usuários por meio de IDOR de tarefas) possam ler.

Os campos do cartão do agente e os resultados das tarefas também são entradas não confiáveis para o agente que faz a chamada. Teste-os com as técnicas de injeção indireta de prompt em [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) e as verificações de confiança entre agentes em [AI Agent Security Methodology](AI-Agent-Security-Methodology.md).



## References

- [1] [Especificação do protocolo A2A](https://a2a-protocol.org/latest/specification/)
- [2] [Blog do Google Developers — Anúncio do protocolo Agent2Agent (A2A)](https://developers.googleblog.com/en/a2a-a-new-era-of-agent-interoperability/)
- [3] [Especificação A2A v0.2.5](https://github.com/a2aproject/A2A/blob/v0.2.5/docs/specification.md)
- [4] [Especificação A2A v0.3.0](https://github.com/a2aproject/A2A/blob/v0.3.0/docs/specification.md)
- [5] [Ataques de colisão de nomes de agentes em sistemas multiagentes](https://arxiv.org/abs/2609.27624)
- [6] [Guia de segurança do SDK A2A para .NET](https://github.com/a2aproject/a2a-dotnet/blob/main/docs/security.md)
- [7] [Guia de migração do A2A Python v1.0](https://github.com/a2aproject/a2a-python/blob/main/docs/migrations/v1_0/README.md)
{{#include ../banners/hacktricks-training.md}}
