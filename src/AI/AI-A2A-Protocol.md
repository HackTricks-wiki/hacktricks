# Seguridad del protocolo A2A (Agent2Agent)

{{#include ../banners/hacktricks-training.md}}

## Qué es A2A

A2A (Agent2Agent) es un protocolo abierto que permite que un agente de IA descubra a otro agente y le asigne trabajo a través de HTTP. MCP conecta un agente con **herramientas y datos**; A2A conecta un agente con **otros agentes**, que suelen ser servicios remotos propiedad de otro equipo o empresa. Un servidor A2A es una API web con un agente LLM detrás, por lo que los propios objetos del protocolo (tarjetas de agente, tareas, webhooks de notificaciones push y tarjetas extendidas) añaden comprobaciones específicas de autenticación, IDOR y SSRF a una prueba normal de API.<sup>[[1]](#references)[[2]](#references)</sup>

Los componentes principales son:

- **Tarjeta de agente:** documento JSON que describe al agente: nombre, descripción, habilidades, URL(s) de servicio, transportes compatibles, capacidades (streaming, notificaciones push, tarjeta extendida) y los `securitySchemes` que debe usar el cliente. Se publica en `https://<host>/.well-known/agent-card.json`. Las implementaciones antiguas que siguen la especificación 0.2.x usan `/.well-known/agent.json`.<sup>[[1]](#references)[[3]](#references)</sup>
- **Tarea:** unidad de trabajo. Un mensaje crea una tarea (con un `id` y un `contextId` generados por el servidor), que el cliente puede leer, cancelar o a la que puede suscribirse más adelante.<sup>[[1]](#references)</sup>
- **Transportes:** JSON-RPC 2.0 sobre HTTP (con SSE para streaming), gRPC y un binding REST de HTTP+JSON.<sup>[[1]](#references)</sup>
- **Autenticación:** las credenciales van en los encabezados HTTP (por ejemplo, `Authorization: Bearer ...`), nunca dentro del payload JSON-RPC. La tarjeta de agente indica qué esquema se requiere.<sup>[[1]](#references)</sup>

Los nombres de los métodos cambiaron entre versiones, así que prueba ambos conjuntos:<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

| Operación | JSON-RPC 0.2/0.3 | JSON-RPC 1.0 | REST 1.0 |
| --- | --- | --- | --- |
| Enviar mensaje | `message/send` | `SendMessage` | `POST /message:send` |
| Envío con streaming | `message/stream` | `SendStreamingMessage` | `POST /message:stream` |
| Obtener tarea | `tasks/get` | `GetTask` | `GET /tasks/{id}` |
| Listar tareas | - | `ListTasks` | `GET /tasks` |
| Cancelar tarea | `tasks/cancel` | `CancelTask` | `POST /tasks/{id}:cancel` |
| Configuración de notificaciones push | `tasks/pushNotificationConfig/set` | `CreateTaskPushNotificationConfig` | `POST /tasks/{id}/pushNotificationConfigs` |
| Tarjeta extendida | `agent/getAuthenticatedExtendedCard` (0.3); HTTP `GET agent/authenticatedExtendedCard` (0.2.5) | `GetExtendedAgentCard` | `GET /extendedAgentCard` |

La especificación 1.0 usa el encabezado `A2A-Version` (o un parámetro de solicitud) para seleccionar la versión, y las solicitudes que no lo incluyen se tratan como 0.3.<sup>[[1]](#references)</sup>

## Descubrimiento

```bash
curl -s https://target/.well-known/agent-card.json | jq .
curl -s https://target/.well-known/agent.json | jq .
```

De la tarjeta, anota:

- Cada `url` del servicio (a menudo un hostname interno, una URL de staging o un puerto distinto al del sitio público).
- `skills`: muestran lo que puede hacer el agente y qué herramientas o datos hay detrás.
- `securitySchemes` / `security`: si están vacíos o no aparecen, probablemente se espera que se llame al agente sin credenciales.
- `capabilities.pushNotifications` y `capabilities.extendedAgentCard` (en 0.3, `supportsAuthenticatedExtendedCard`).

La especificación indica que la tarjeta pública no debe contener credenciales ni detalles de implementación interna, así que las URL internas, las claves o las listas detalladas de herramientas en una tarjeta pública ya constituyen un hallazgo.<sup>[[1]](#references)</sup>

## Pruebas de endpoints A2A

### Envío de tareas sin autenticación

Envía un mensaje mínimo, sin credenciales, a cada `url` que aparezca en la tarjeta:

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

Un resultado `Task` o `Message` con `PONG`, cuando la card declara un esquema de seguridad, significa que la autenticación no se aplica en el endpoint RPC (puede que solo se aplique en la UI o en la card). Si la card no declara ningún esquema, comprueba a qué pueden acceder las skills del agente: un agente sin autenticación que puede leer datos internos o llamar a herramientas equivale a una API sin autenticación para esas herramientas.

### Task IDOR (`tasks/get`, `GetTask`, cancel, subscribe)

La especificación exige que el servidor compruebe, en cada solicitud, que quien la realiza puede acceder a la tarea, y que limite `ListTasks` a quien la solicita, incluso cuando no se proporciona ningún filtro.<sup>[[1]](#references)</sup> Pruébalo con dos identidades (A y B):

1. Como A, crea una tarea y guarda su `id` y `contextId`.
2. Como B (o sin credenciales), llama a `tasks/get` / `GetTask` con el `id` de A y luego a `ListTasks` sin parámetros.
3. Prueba también a cancelar y suscribirte a la tarea de A, y envía un mensaje nuevo como B que incluya el `taskId` o `contextId` de A (esto añadiría el texto de B a la conversación de A).

```json
{"jsonrpc":"2.0","id":2,"method":"tasks/get","params":{"id":"<task id of user A>","historyLength":10}}
```

Vulnerable: B recibe el historial, los artefactos o el estado de A, o puede cambiar la tarea de A. Seguro: un `TaskNotFoundError`, sin diferencias entre «existe, pero no es tuyo» y «no existe».<sup>[[1]](#references)</sup> Los ID de tarea suelen ser UUID, así que búscalos en lugares donde puedan filtrarse (enlaces compartidos, registros, cargas útiles de notificaciones push, mensajes de error).

### SSRF en webhook de notificaciones push

Cuando `capabilities.pushNotifications` es true, el cliente proporciona al agente una URL de webhook, y luego el agente envía solicitudes `POST` con actualizaciones de tareas a esa URL. La especificación indica que los agentes deben rechazar rangos privados, localhost y direcciones link-local, y usar listas de permitidos.<sup>[[1]](#references)</sup> Crea una tarea, registra una configuración de notificaciones push cuya `url` apunte a tu host OAST para confirmar las solicitudes salientes y, después (solo si el alcance lo permite), prueba con destinos internos como `http://127.0.0.1:<port>/` o `http://169.254.169.254/`. Compara los errores y los tiempos de respuesta para identificar servicios internos. El agente también añade a estas solicitudes el encabezado de autenticación configurado, así que comprueba que no se envíe a un host elegido por un atacante cuando puedas cambiar la URL de la configuración de otro usuario. Consulta [SSRF](../pentesting-web/ssrf-server-side-request-forgery/).

### Acceso a la ficha extendida del agente

`GetExtendedAgentCard` debe requerir autenticación y puede devolver más habilidades y configuración que la ficha pública.<sup>[[1]](#references)</sup> Llámalo sin credenciales y con una identidad con pocos privilegios, y compara el resultado con la ficha pública.

### Fugas de credenciales en la configuración de notificaciones push y dentro de las tareas

Las configuraciones de notificaciones push almacenan una URL de webhook y las credenciales que el agente le envía. La especificación exige que todas las operaciones de configuración de notificaciones push (crear, obtener, listar, eliminar) verifiquen que quien realiza la solicitud puede acceder a la tarea.<sup>[[1]](#references)</sup> Repite la prueba con dos identidades de la [task IDOR section](#task-idor-tasksget-gettask-cancel-subscribe) en estas rutas. Una configuración de otro usuario que se pueda leer filtra un token de webhook; una que se pueda modificar redirige las actualizaciones de las tareas de ese usuario a tu host.

Cuando un agente necesita autorización adicional durante una tarea, la cambia a `TASK_STATE_AUTH_REQUIRED`. El cliente puede gestionar la autorización fuera de banda; la especificación indica que los agentes deben recibir las credenciales fuera de banda, salvo que se haya negociado un mecanismo dentro de banda. El intercambio dentro de banda puede pasar una credencial entre una cadena de agentes A2A y exponerla a todos los agentes de esa cadena.<sup>[[1]](#references)</sup> En una prueba de orquestador, comprueba si una credencial que el usuario proporciona para un agente posterior aparece en mensajes, artefactos o el historial de tareas que otros agentes (u otros usuarios mediante task IDOR) puedan leer.

Los campos de la ficha del agente y los resultados de las tareas también son entradas no confiables para el agente que realiza la llamada. Pruébalos con las técnicas de inyección indirecta de prompts de [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) y las comprobaciones de confianza entre agentes de [AI Agent Security Methodology](AI-Agent-Security-Methodology.md).

## References

- [1] [Especificación del protocolo A2A](https://a2a-protocol.org/latest/specification/)
- [2] [Blog de Google Developers — Anuncio del protocolo Agent2Agent (A2A)](https://developers.googleblog.com/en/a2a-a-new-era-of-agent-interoperability/)
- [3] [Especificación A2A v0.2.5](https://github.com/a2aproject/A2A/blob/v0.2.5/docs/specification.md)
- [4] [Especificación A2A v0.3.0](https://github.com/a2aproject/A2A/blob/v0.3.0/docs/specification.md)
{{#include ../banners/hacktricks-training.md}}
