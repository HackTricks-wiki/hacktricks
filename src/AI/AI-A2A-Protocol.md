# Seguridad del protocolo A2A (Agent2Agent)

{{#include ../banners/hacktricks-training.md}}

## Qué es A2A

A2A (Agent2Agent) es un protocolo abierto que permite que un agente de IA descubra a otro agente y le envíe trabajo mediante HTTP. MCP conecta un agente con **herramientas y datos**; A2A conecta un agente con **otros agentes**, que suelen ser servicios remotos propiedad de otro equipo o empresa. Un servidor A2A es una API web con un agente LLM detrás, por lo que los propios objetos del protocolo (tarjetas de agente, tareas, webhooks de notificaciones push y tarjetas extendidas) añaden comprobaciones específicas de autenticación, IDOR y SSRF a las pruebas habituales de API.<sup>[[1]](#references)[[2]](#references)</sup>

Los componentes principales son:

- **Agent Card:** un documento JSON que describe al agente: nombre, descripción, habilidades, URL(s) del servicio, transportes compatibles, capacidades (streaming, notificaciones push, tarjeta extendida) y los `securitySchemes` que debe usar el cliente. Se publica en `https://<host>/.well-known/agent-card.json`. Las implementaciones antiguas que siguen la especificación 0.2.x usan `/.well-known/agent.json`.<sup>[[1]](#references)[[3]](#references)</sup>
- **Task:** la unidad de trabajo. Un mensaje crea una tarea (con un `id` y un `contextId` generados por el servidor), y el cliente luego la consulta, cancela o se suscribe a ella.<sup>[[1]](#references)</sup>
- **Transportes:** JSON-RPC 2.0 sobre HTTP (con SSE para streaming), gRPC y un enlace REST HTTP+JSON.<sup>[[1]](#references)</sup>
- **Autenticación:** las credenciales van en los encabezados HTTP (por ejemplo, `Authorization: Bearer ...`), nunca dentro del payload JSON-RPC. La tarjeta del agente indica qué esquema se requiere.<sup>[[1]](#references)</sup>

Los nombres de los métodos cambiaron entre versiones, así que prueba ambos conjuntos:<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

| Operación | JSON-RPC 0.2/0.3 | JSON-RPC 1.0 | REST 1.0 |
| --- | --- | --- | --- |
| Enviar mensaje | `message/send` | `SendMessage` | `POST /message:send` |
| Envío en streaming | `message/stream` | `SendStreamingMessage` | `POST /message:stream` |
| Obtener tarea | `tasks/get` | `GetTask` | `GET /tasks/{id}` |
| Listar tareas | - | `ListTasks` | `GET /tasks` |
| Cancelar tarea | `tasks/cancel` | `CancelTask` | `POST /tasks/{id}:cancel` |
| Configuración de notificaciones push | `tasks/pushNotificationConfig/set` | `CreateTaskPushNotificationConfig` | `POST /tasks/{id}/pushNotificationConfigs` |
| Tarjeta extendida | `agent/getAuthenticatedExtendedCard` (0.3); HTTP `GET agent/authenticatedExtendedCard` (0.2.5) | `GetExtendedAgentCard` | `GET /extendedAgentCard` |

La especificación 1.0 usa el encabezado `A2A-Version` (o un parámetro de solicitud) para seleccionar la versión; las solicitudes que no lo incluyen se tratan como 0.3.<sup>[[1]](#references)</sup>

## Descubrimiento

```bash
curl -s https://target/.well-known/agent-card.json | jq .
curl -s https://target/.well-known/agent.json | jq .
```

En la tarjeta, anota:

- Cada `url` de servicio: en 1.0 aparecen en `supportedInterfaces`, mientras que las tarjetas antiguas pueden incluir un `url` de nivel superior. Registra cada endpoint y transporte, incluidos los nombres de host internos, las URL de staging y los puertos alternativos.<sup>[[1]](#references)[[7]](#references)</sup>
- `skills`: muestran lo que puede hacer el agente y qué herramientas o datos hay detrás.
- `securitySchemes` / `security`: si están vacíos o no aparecen, probablemente se espera que se invoque al agente sin credenciales.
- `capabilities.pushNotifications` y `capabilities.extendedAgentCard` (en 0.3, `supportsAuthenticatedExtendedCard`).

La especificación indica que la tarjeta pública no debe incluir credenciales ni detalles de implementación interna, por lo que las URL internas, las claves o las listas detalladas de herramientas en una tarjeta pública ya son un hallazgo.<sup>[[1]](#references)</sup>

### Colisión del nombre de Agent Card en un host multiagente

El `name` de una tarjeta es una etiqueta legible para las personas, no una identidad de enrutamiento estable.<sup>[[1]](#references)[[5]](#references)</sup> Si un host registra dos pares remotos distintos con el mismo nombre local, su árbol de agentes, el nombre de herramienta generado, el mapa de clientes o la ruta del broker pueden enviar una tarea destinada al par de confianza al otro par.<sup>[[5]](#references)</sup> Para que esto ocurra, el par controlado por el atacante debe admitirse en el **mismo espacio de nombres de enrutamiento**; publicar una tarjeta duplicada en Internet no basta.<sup>[[5]](#references)</sup>

Prueba la ruta de **admisión a despacho** del host con dos pares controlados, URL distintas y un marcador inocuo:<sup>[[5]](#references)</sup>

1. Registra la tarjeta, el origen y el selector local del par de confianza. Registra un segundo par cuya tarjeta tenga el mismo `name`, pero cuya URL apunte a un endpoint bajo tu control.
2. Activa la operación que selecciona el par de confianza por nombre. Prueba ambos órdenes de registro y, si los nombres se convierten en identificadores de herramientas, la normalización de nombres habitual del host. Captura qué endpoint recibe el marcador y qué agente devuelve la respuesta.
3. Cambia solo el nombre de la segunda tarjeta y repite la prueba. Si una solicitud llega al segundo endpoint únicamente cuando hay una colisión, queda demostrado el despacho al par equivocado. Comprueba por separado si se adjuntó algún contexto sensible o alguna credencial; la colisión de nombres por sí sola **no** demuestra la transferencia de credenciales ni de autoridad sobre herramientas.

Si el llamante se dirige a un endpoint fijo vinculado a un origen en vez de resolver el nombre de una tarjeta, esta prueba no aplica.<sup>[[5]](#references)</sup> Para analizar las respuestas posteriores del par malicioso y el impacto de la prompt injection, sigue [AI Agent Security Methodology](AI-Agent-Security-Methodology.md#exploitation-cross-a-trust-boundary).

## Pruebas de endpoints A2A

### Envío de tareas sin autenticación

Envía un mensaje mínimo sin credenciales a cada `url` que aparezca en la tarjeta:

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

Un resultado `Task` o `Message` con `PONG`, cuando la card declara un esquema de seguridad, significa que la autenticación no se aplica en el endpoint RPC (puede que solo se aplique en la UI o en la card). Si la card no declara ningún esquema, comprueba a qué puede acceder el agente mediante sus skills: un agente sin autenticar que puede leer datos internos o llamar a herramientas equivale a una API sin autenticar para esas herramientas.

### Task IDOR (`tasks/get`, `GetTask`, cancel, subscribe)

La especificación exige que el servidor compruebe, en cada solicitud, que quien la realiza puede acceder a la tarea, y que limite `ListTasks` a quien realiza la solicitud, incluso cuando no se proporciona ningún filtro.<sup>[[1]](#references)</sup> Pruébalo con dos identidades (A y B):

1. Como A, crea una tarea y guarda su `id` y `contextId`.
2. Como B (o sin credenciales), llama a `tasks/get` / `GetTask` con el `id` de A y, luego, a `ListTasks` sin parámetros.
3. Prueba también a cancelar y suscribirte a la tarea de A, y a enviar un mensaje nuevo como B que incluya el `taskId` o `contextId` de A (esto añadiría el texto de B a la conversación de A).

```json
{"jsonrpc":"2.0","id":2,"method":"tasks/get","params":{"id":"<task id of user A>","historyLength":10}}
```

Vulnerable: B recibe el historial, los artefactos o el estado de A, o puede cambiar la tarea de A. Secure: un `TaskNotFoundError`, sin diferencias entre «existe, pero no es tuyo» y «no existe».<sup>[[1]](#references)</sup> Los ID de tarea suelen ser UUID, así que búscalos en lugares donde se filtren (enlaces compartidos, registros, cargas útiles de notificaciones push, mensajes de error).

### SSRF en el webhook de notificaciones push

Cuando `capabilities.pushNotifications` es true, el cliente proporciona al agente una URL de webhook y, más tarde, el agente envía solicitudes `POST` con actualizaciones de tareas a esa URL. La especificación indica que los agentes deben rechazar rangos privados, localhost y direcciones link-local, y usar listas de permitidos.<sup>[[1]](#references)</sup> Crea una tarea, registra una configuración de notificaciones push cuya `url` apunte a tu host OAST para confirmar las solicitudes salientes y, después (solo si el alcance lo permite), apunta a destinos internos como `http://127.0.0.1:<port>/` o `http://169.254.169.254/`. Compara los errores y los tiempos para identificar los servicios internos. El agente también añade a estas solicitudes el encabezado de autenticación configurado, así que comprueba que no se envíe a un host elegido por un atacante cuando puedas cambiar la URL de la configuración de otro usuario. Consulta [SSRF](../pentesting-web/ssrf-server-side-request-forgery/).

### Partes con URL de archivo como segundo punto de entrada para SSRF

A2A 1.0 permite que un mensaje o artefacto contenga una referencia a un archivo como `Part` con `url` (0.3 usa `kind: "file"` y `file.uri`).<sup>[[1]](#references)[[4]](#references)[[7]](#references)</sup> El protocolo transporta la referencia; obtener el archivo es un comportamiento de la aplicación, no un requisito del SDK de A2A.<sup>[[6]](#references)</sup> Esto es independiente de la URL de callback de notificaciones push anterior. Prueba ambas direcciones: un archivo proporcionado por el cliente y enviado a un servidor A2A, y una URL de archivo devuelta por un par con menor nivel de confianza a un orquestador.<sup>[[1]](#references)[[6]](#references)</sup>

Para un endpoint JSON-RPC 1.0 autorizado, reemplaza la parte de texto normal por una URL a una ruta OAST única y comprueba **qué componente** realiza la solicitud:<sup>[[1]](#references)[[7]](#references)</sup>

```bash
curl -s https://target/a2a -H 'Content-Type: application/json' -H 'A2A-Version: 1.0' -d '{
  "jsonrpc":"2.0","id":1,"method":"SendMessage",
  "params":{"message":{"role":"ROLE_USER",
    "messageId":"6f1c2b9e-0000-4000-8000-000000000003",
    "parts":[{"url":"https://oast.example/part-probe","filename":"probe.txt","mediaType":"text/plain"}]}}}'
```

Solo si el destinatario lo desreferencia, prueba destinos internos dentro del alcance, redirecciones y cambios en la resolución DNS mediante el [flujo de trabajo de SSRF](../pentesting-web/ssrf-server-side-request-forgery/). Un `Part` válido o una respuesta exitosa de la tarea por sí solos no demuestran SSRF; confirma la solicitud en el destino y si el contenido obtenido llega al agente.<sup>[[6]](#references)</sup>

### Acceso a la tarjeta extendida del agente

`GetExtendedAgentCard` debe requerir autenticación y puede devolver más habilidades y configuración que la tarjeta pública.<sup>[[1]](#references)</sup> Llámalo sin credenciales y con una identidad de bajos privilegios, y compara el resultado con la tarjeta pública.

### Configuración de notificaciones push y filtraciones de credenciales durante las tareas

Las configuraciones de notificaciones push almacenan una URL de webhook y las credenciales que el agente le envía. La especificación exige que cada operación de configuración de notificaciones push (crear, obtener, listar, eliminar) verifique que el usuario que llama pueda acceder a la tarea.<sup>[[1]](#references)</sup> Repite en estas rutas la prueba con dos identidades de la [sección de IDOR de tareas](#task-idor-tasksget-gettask-cancel-subscribe). Una configuración de otro usuario que se pueda leer filtra un token de webhook, y una que se pueda modificar redirige las actualizaciones de las tareas de ese usuario a tu host.

Cuando un agente necesita autorización adicional durante una tarea, cambia la tarea a `TASK_STATE_AUTH_REQUIRED`. El cliente puede gestionar la autorización fuera de banda; la especificación indica que los agentes deben recibir las credenciales fuera de banda, salvo que se haya negociado un mecanismo dentro de banda. El intercambio dentro de banda puede pasar una credencial por una cadena de agentes A2A y exponerla a todos los agentes de esa cadena.<sup>[[1]](#references)</sup> En una prueba de orquestador, comprueba si una credencial que el usuario proporciona para un agente posterior aparece en mensajes, artefactos o el historial de tareas que otros agentes (u otros usuarios mediante IDOR de tareas) puedan leer.

Los campos de las tarjetas de agentes y los resultados de las tareas también son entradas no confiables para el agente que los recibe. Pruébalos con las técnicas de inyección indirecta de prompts de [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) y las comprobaciones de confianza entre agentes de [AI Agent Security Methodology](AI-Agent-Security-Methodology.md).



## References

- [1] [Especificación del protocolo A2A](https://a2a-protocol.org/latest/specification/)
- [2] [Blog de Google Developers — Anuncio del protocolo Agent2Agent (A2A)](https://developers.googleblog.com/en/a2a-a-new-era-of-agent-interoperability/)
- [3] [Especificación A2A v0.2.5](https://github.com/a2aproject/A2A/blob/v0.2.5/docs/specification.md)
- [4] [Especificación A2A v0.3.0](https://github.com/a2aproject/A2A/blob/v0.3.0/docs/specification.md)
- [5] [Ataques por colisión de nombres de agentes en sistemas multiagente](https://arxiv.org/abs/2609.27624)
- [6] [Guía de seguridad del SDK A2A .NET](https://github.com/a2aproject/a2a-dotnet/blob/main/docs/security.md)
- [7] [Guía de migración a A2A Python v1.0](https://github.com/a2aproject/a2a-python/blob/main/docs/migrations/v1_0/README.md)
{{#include ../banners/hacktricks-training.md}}
