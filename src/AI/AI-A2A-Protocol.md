# Segurança do protocolo A2A (Agent2Agent)

{{#include ../banners/hacktricks-training.md}}

## O que é A2A

A2A (Agent2Agent) é um protocolo aberto que permite que um agente de IA descubra outro agente e lhe envie tarefas por HTTP. MCP conecta um agente a **ferramentas e dados**; A2A conecta um agente a **outros agentes**, que geralmente são serviços remotos pertencentes a outra equipe ou empresa. Um servidor A2A é uma API web com um agente LLM por trás, então os próprios objetos do protocolo (agent cards, tasks, webhooks de push notifications, extended cards) exigem verificações específicas de autenticação, IDOR e SSRF, além das verificações de uma API comum.<sup>[[1]](#references)[[2]](#references)</sup>

Os principais componentes são:

- **Agent Card:** um documento JSON que descreve o agente: nome, descrição, skills, URL(s) do serviço, transports compatíveis, capabilities (streaming, push notifications, extended card) e os `securitySchemes` que o client deve usar. Ele é publicado em `https://<host>/.well-known/agent-card.json`. Deployments mais antigos que seguem a spec 0.2.x usam `/.well-known/agent.json`.<sup>[[1]](#references)[[3]](#references)</sup>
- **Task:** a unidade de trabalho. Uma mensagem cria uma task (com um `id` e um `contextId` gerados pelo servidor), e o client depois a consulta, cancela ou assina para receber atualizações.<sup>[[1]](#references)</sup>
- **Transports:** JSON-RPC 2.0 por HTTP (com SSE para streaming), gRPC e um binding REST HTTP+JSON.<sup>[[1]](#references)</sup>
- **Authentication:** as credenciais vão nos headers HTTP (por exemplo, `Authorization: Bearer ...`), nunca dentro do payload JSON-RPC. O agent card informa qual scheme é necessário.<sup>[[1]](#references)</sup>

Os nomes dos métodos mudaram entre versões, então tente ambos os conjuntos:<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

| Operação | JSON-RPC 0.2/0.3 | JSON-RPC 1.0 | REST 1.0 |
| --- | --- | --- | --- |
| Enviar mensagem | `message/send` | `SendMessage` | `POST /message:send` |
| Envio por streaming | `message/stream` | `SendStreamingMessage` | `POST /message:stream` |
| Obter task | `tasks/get` | `GetTask` | `GET /tasks/{id}` |
| Listar tasks | - | `ListTasks` | `GET /tasks` |
| Cancelar task | `tasks/cancel` | `CancelTask` | `POST /tasks/{id}:cancel` |
| Configuração de push notification | `tasks/pushNotificationConfig/set` | `CreateTaskPushNotificationConfig` | `POST /tasks/{id}/pushNotificationConfigs` |
| Extended card | `agent/getAuthenticatedExtendedCard` (0.3); HTTP `GET agent/authenticatedExtendedCard` (0.2.5) | `GetExtendedAgentCard` | `GET /extendedAgentCard` |

A spec 1.0 usa o header `A2A-Version` (ou um parâmetro da requisição) para selecionar a versão, e as requisições sem ele são tratadas como 0.3.<sup>[[1]](#references)</sup>

## Descoberta

```bash
curl -s https://target/.well-known/agent-card.json | jq .
curl -s https://target/.well-known/agent.json | jq .
```

No cartão, anote:

- Cada `url` de serviço (geralmente um hostname interno, uma URL de staging ou uma porta diferente da do site público).
- `skills`: mostram o que o agente pode fazer e quais ferramentas ou dados estão por trás dele.
- `securitySchemes` / `security`: se estiverem vazios ou ausentes, provavelmente o agente deve ser chamado sem credenciais.
- `capabilities.pushNotifications` e `capabilities.extendedAgentCard` (em 0.3, `supportsAuthenticatedExtendedCard`).

A especificação diz que o cartão público não deve conter credenciais nem detalhes internos de implementação. Portanto, URLs internas, chaves ou listas detalhadas de ferramentas em um cartão público já são um achado.<sup>[[1]](#references)</sup>

## Testando endpoints A2A

### Envio de tarefa sem autenticação

Envie uma mensagem mínima, sem credenciais, para cada `url` listado no cartão:

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

Um resultado `Task` ou `Message` com `PONG`, quando o card declara um esquema de segurança, significa que a autenticação não é aplicada no endpoint RPC (ela pode ser aplicada apenas na UI ou no card). Se o card não declarar nenhum esquema, verifique o que as skills do agent podem acessar: um agent não autenticado que pode ler dados internos ou chamar tools equivale a uma API não autenticada para essas tools.

### IDOR de tarefas (`tasks/get`, `GetTask`, cancelamento, inscrição)

A especificação exige que o servidor verifique, em cada solicitação, se o caller pode acessar a tarefa, e que limite `ListTasks` ao caller mesmo quando nenhum filtro é fornecido.<sup>[[1]](#references)</sup> Teste com duas identidades (A e B):

1. Como A, crie uma tarefa e salve seu `id` e `contextId`.
2. Como B (ou sem credenciais), chame `tasks/get` / `GetTask` com o `id` de A e, em seguida, `ListTasks` sem parâmetros.
3. Tente também cancelar e inscrever-se na tarefa de A, e envie uma nova mensagem como B que inclua o `taskId` ou o `contextId` de A (isso adicionaria o texto de B à conversa de A).

```json
{"jsonrpc":"2.0","id":2,"method":"tasks/get","params":{"id":"<task id of user A>","historyLength":10}}
```

Vulnerável: B recebe o histórico, os artefatos ou o status de A, ou pode alterar a tarefa de A. Seguro: um `TaskNotFoundError`, sem diferença entre “existe, mas não é sua” e “não existe”.<sup>[[1]](#references)</sup> Os IDs de tarefa costumam ser UUIDs, então procure-os em locais onde possam vazar (links compartilhados, logs, payloads de notificações push, mensagens de erro).

### SSRF em webhook de notificação push

Quando `capabilities.pushNotifications` é true, o cliente fornece ao agente uma URL de webhook, e o agente depois envia requisições `POST` com atualizações da tarefa para essa URL. A especificação diz que os agentes devem rejeitar intervalos privados, localhost e endereços link-local, e usar listas de permissões.<sup>[[1]](#references)</sup> Crie uma tarefa, registre uma configuração de notificação push cuja `url` aponte para seu host OAST para confirmar as requisições de saída e, em seguida (somente se o escopo permitir), para destinos internos como `http://127.0.0.1:<port>/` ou `http://169.254.169.254/`. Compare os erros e o tempo de resposta para mapear serviços internos. O agente também adiciona o cabeçalho de autenticação configurado a essas requisições, então verifique se ele não é enviado a um host escolhido por um invasor quando você puder alterar a URL da configuração de outro usuário. Consulte [SSRF](../pentesting-web/ssrf-server-side-request-forgery/).

### Acesso ao cartão estendido do agente

`GetExtendedAgentCard` deve exigir autenticação e pode retornar mais skills e configurações do que o cartão público.<sup>[[1]](#references)</sup> Chame-o sem credenciais e com uma identidade de baixo privilégio e compare o resultado com o cartão público.

### Configuração de notificação push e vazamentos de credenciais durante tarefas

As configurações de notificação push armazenam uma URL de webhook e as credenciais que o agente envia para ela. A especificação exige que toda operação de configuração de notificação push (criar, obter, listar, excluir) verifique se o chamador pode acessar a tarefa.<sup>[[1]](#references)</sup> Repita o teste com duas identidades da [seção sobre IDOR de tarefas](#task-idor-tasksget-gettask-cancel-subscribe) nessas rotas. Uma configuração de outro usuário que possa ser lida vaza um token de webhook; uma que possa ser alterada redireciona as atualizações da tarefa desse usuário para seu host.

Quando um agente precisa de autorização adicional durante uma tarefa, ele move a tarefa para `TASK_STATE_AUTH_REQUIRED`. O cliente pode providenciar a autorização fora de banda; a especificação diz que os agentes devem receber credenciais fora de banda, a menos que um mecanismo em banda tenha sido negociado. A troca em banda pode passar uma credencial por uma cadeia de agentes A2A e expô-la a todos os agentes dessa cadeia.<sup>[[1]](#references)</sup> Em um teste de orquestrador, verifique se uma credencial fornecida pelo usuário para um agente downstream aparece em mensagens, artefatos ou no histórico da tarefa que outros agentes (ou outros usuários, por meio de IDOR de tarefas) possam ler.

Os campos do cartão do agente e os resultados das tarefas também são entradas não confiáveis para o agente chamador. Teste-os com as técnicas de injeção indireta de prompt em [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) e as verificações de confiança entre agentes em [AI Agent Security Methodology](AI-Agent-Security-Methodology.md).

## References

- [1] [Especificação do protocolo A2A](https://a2a-protocol.org/latest/specification/)
- [2] [Blog dos Google Developers — Anúncio do protocolo Agent2Agent (A2A)](https://developers.googleblog.com/en/a2a-a-new-era-of-agent-interoperability/)
- [3] [Especificação A2A v0.2.5](https://github.com/a2aproject/A2A/blob/v0.2.5/docs/specification.md)
- [4] [Especificação A2A v0.3.0](https://github.com/a2aproject/A2A/blob/v0.3.0/docs/specification.md)
{{#include ../banners/hacktricks-training.md}}
