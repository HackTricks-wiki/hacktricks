# Metodología de seguridad de AI Agent

{{#include ../banners/hacktricks-training.md}}

Una evaluación de agentes debe seguir **la entrada controlada por el atacante hasta un efecto observable externamente**. El jailbreaking, los cambios de carácter y la divulgación del system prompt demuestran que se puede influir en un canal de razonamiento, pero el hallazgo de alto impacto es la cadena que lleva al acceso a datos, a una acción no autorizada mediante una herramienta, a un punto de inyección posterior, a la persistencia o a otro agente.<sup>[[2]](#references)</sup>

El [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) es útil para etiquetar la cobertura (secuestro de objetivos, uso indebido de herramientas, abuso de privilegios, cadena de suministro, ejecución de código, envenenamiento de memoria, confianza entre agentes, fallos en cascada, confianza humana y agentes deshonestos). Usa esas etiquetas después de construir una ruta de ataque de extremo a extremo, en lugar de tratar un texto inesperado del modelo como el final de la prueba.<sup>[[1]](#references)[[2]](#references)</sup>

## Crear el mapa del objetivo

Registra estas cinco dimensiones para cada flujo de trabajo del agente antes de escribir payloads:<sup>[[2]](#references)</sup>

| Dimensión | Qué enumerar | Pregunta de seguridad |
|---|---|---|
| **Entrada no confiable** | Parámetros de chat/API, URL, documentos, correo electrónico, tickets, entradas de calendario, fragmentos recuperados, memoria, resultados de herramientas y mensajes de agentes pares | ¿Dónde puede colocar un atacante contenido que luego entre en el contexto del modelo? |
| **Herramientas** | Nombres y esquemas de herramientas, efectos secundarios, ejecución automática, comportamiento de confirmación y herramientas cargadas dinámicamente | ¿Qué llamadas leen secretos, escriben estado, envían mensajes, eliminan datos, ejecutan código o transfieren valor? |
| **Autoridad** | Delegación del usuario, cuentas de servicio, tokens de API, duración de las credenciales, ámbito de tenant/recurso y alcance de red | ¿Con qué identidad se ejecuta cada llamada y se vuelve a comprobar la autorización en el límite de la herramienta? |
| **Procesamiento** | Constructores de consultas, shells, recuperadores de URL, motores de plantillas, intérpretes, analizadores, operaciones con archivos y deserializadores | ¿Dónde se convierten los datos generados por el modelo en sintaxis para otro intérprete? |
| **Salida** | Respuestas, Markdown/HTML renderizado, enlaces, solicitudes de imágenes, webhooks, correo electrónico, archivos, registros, informes, métricas y tráfico entre agentes | ¿Qué canal observable puede transportar un secreto o activar una solicitud secundaria? |

No reduzcas esto a una lista de integraciones anunciadas. Un artefacto útil vincula cada origen con la posición exacta del contexto a la que llega, las herramientas disponibles en ese punto, la credencial que usa cada herramienta, el intérprete posterior y todas las rutas de salida. La misma herramienta puede tener un impacto bajo con un token de lectura por usuario y ser crítica con una credencial de administrador compartida.<sup>[[2]](#references)</sup>

## Reconocimiento

### Mapear todas las rutas de entrega e ingestión

Empieza por la superficie de entrega (web, móvil, API, correo electrónico, plataforma de chat, extensión del navegador) y captura el tráfico entre el cliente y el backend mediante un proxy. Inspecciona los campos ocultos por la interfaz, los parámetros de búsqueda/autocompletado/filtro, los objetos de estado de conversación, los trabajos de carga e indexación, las respuestas de herramientas y el tráfico de subagentes. Es posible que los clientes exclusivos para móviles requieran un emulador e instrumentación para eludir el certificate pinning antes de que el esquema real de solicitudes sea visible.<sup>[[2]](#references)</sup>

Luego, mapea la pila bajo el modelo: framework de orquestación, ensamblado de prompts, almacenes de recuperación y memoria, runtime (por ejemplo, Python, contenedor o WASM), volúmenes montados, servicios del host, API internas, accesibilidad de metadatos de cloud y redes vecinas. Los valores predeterminados del framework importan porque algunas “llamadas a herramientas” se implementan generando o evaluando código; el límite del runtime/sandbox determina si el resultado queda contenido.<sup>[[2]](#references)</sup>

### Identificar el enrutamiento con probes no destructivos

Compara una solicitud dentro del alcance con varias solicitudes no relacionadas, conservando la respuesta completa, el código de estado, la latencia y el comportamiento de streaming. Un rechazo estable antes de cualquier razonamiento específico de la tarea puede indicar un gateway/clasificador independiente; una negativa contextual sugiere que la solicitud llegó al modelo; una respuesta vacía o puramente extractiva puede indicar búsqueda por palabras clave o recuperación limitada. Trata estas observaciones como hipótesis y confírmalas reproduciendo el mismo probe mediante campos de API y rutas de ingestión alternativos.<sup>[[2]](#references)</sup>

El reconocimiento está completo cuando la evaluación puede identificar el origen controlado por el atacante más temprano que modifica el comportamiento del agente **y** las herramientas, identidades, intérpretes y salidas accesibles desde ese origen.<sup>[[2]](#references)</sup>

## Explotación: cruzar un límite de confianza

Prueba los canales, no solo la formulación del prompt. Empieza con una inyección directa para determinar qué bloquea la puerta de entrada visible y luego repite la misma intención por las rutas menos visibles que se indican a continuación:<sup>[[2]](#references)</sup>

- **Contenido indirecto:** páginas, archivos, correo electrónico, tickets, metadatos, texto alternativo, comentarios HTML, texto fuera de pantalla o caracteres de ancho cero. Consulta [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) para ver técnicas de entrega de payloads.
- **Recuperación y memoria:** envenena contenido que se recuperará más adelante o estado que se volverá a cargar en sesiones posteriores. Registra si eliminar el origen original hace que desaparezca el comportamiento.
- **Salida de herramientas y agentes pares:** coloca el marcador en una respuesta de herramienta o en un mensaje entre agentes para comprobar si el tráfico interno elude los filtros aplicados solo a la entrada del usuario y a la salida final.
- **Cadena de suministro:** revisa descriptores de herramientas, plugins, servidores conectados, skills, modelos y dependencias como fuentes de instrucciones confiables. Para pruebas específicas de MCP, consulta [MCP Servers](AI-MCP-Servers.md#mcp-vulns).
- **Aprobación humana:** compara la llamada estructurada real a la herramienta con el texto de aprobación generado por el modelo. Comprueba si la influencia del atacante puede omitir el destino, el ámbito, los objetos afectados o los efectos secundarios irreversibles.

Primero usa un marcador único e inocuo. Conserva el artefacto de origen, el contexto ensamblado si se puede observar, la llamada a herramienta seleccionada, los datos de aprobación, la solicitud/respuesta del backend y el estado final. Así se distingue la influencia de una afirmación alucinada de que se realizó una acción.<sup>[[2]](#references)</sup>

### Aislamiento del contexto de subagentes

Un subagente de Claude Agent SDK que no sea fork recibe su propio `AgentDefinition.prompt`, el prompt de delegación y las herramientas disponibles, pero no el system prompt ni la conversación del agente principal. Si se omite `tools` de su definición, hereda las herramientas disponibles para los subagentes; es posible que el proyecto también cargue `CLAUDE.md`. Esto hace que una restricción del prompt exclusiva del agente principal sea un límite poco fiable cuando el hijo puede usar las mismas herramientas de sistema de archivos o ejecución.<sup>[[4]](#references)</sup>

Prueba el límite comparando una solicitud directa que el agente principal rechaza con la misma tarea delegada a un subagente con nombre. NCC Group informa que una enumeración de archivos del sistema operativo rechazada tuvo éxito cuando se reformuló para un hijo como un inofensivo «mapa de distribución».<sup>[[3]](#references)</sup>

Inspecciona las llamadas reales a herramientas del hijo y su lista efectiva de herramientas permitidas, no solo la respuesta final del agente principal; confirma si el hijo accedió a archivos a los que el agente principal no habría accedido.<sup>[[4]](#references)</sup> Esto es un fallo en la herencia de guardrails, no una prueba de [Python sandbox](../generic-methodologies-and-resources/python/bypass-python-sandboxes/) ni de escape de contenedor.<sup>[[3]](#references)[[4]](#references)</sup>

## Ejecución: demostrar el impacto real

Hay dos rutas distintas desde la influencia hasta el impacto:<sup>[[2]](#references)</sup>

1. **Abuso de capacidades:** la herramienta autorizada ya realiza el objetivo. Por ejemplo, leer el registro de un tenant y escribirlo en un informe visible para el atacante, enviar correo electrónico, modificar registros, eliminar un archivo o iniciar un pago. No se requiere un fallo de software secundario.
2. **Explotación de puntos de entrada posteriores:** la salida del modelo controlada por el atacante se convierte en sintaxis para otro componente. Revisa las consultas a bases de datos para detectar [SQL injection](../pentesting-web/sql-injection/README.md) o [NoSQL injection](../pentesting-web/nosql-injection.md), los wrappers de shell para detectar [command injection](../pentesting-web/command-injection.md), las URL elegidas para detectar [SSRF](../pentesting-web/ssrf-server-side-request-forgery/README.md), las operaciones con archivos para detectar path traversal, los evaluadores de plantillas/código para detectar RCE y los analizadores de objetos para detectar [unsafe deserialization](../pentesting-web/deserialization/README.md).

Para cada candidato, demuestra esta cadena:<sup>[[2]](#references)</sup>

```text
attacker-controlled source
  -> model/context influence
  -> selected tool and arguments
  -> effective identity/credential
  -> capability or vulnerable sink
  -> externally verified state change or data egress
```

Una integración de solo lectura sigue siendo explotable si cualquier componente posterior puede publicar lo que leyó. Prueba las respuestas habituales y también vías de salida menos obvias, como enlaces controlados por el atacante, recuperación automática de imágenes, webhooks, registros, informes, contadores, notificaciones y mensajes a otros agentes.<sup>[[2]](#references)</sup>

## Acciones sobre los objetivos

Después de confirmar una acción, evalúa todo el radio de impacto en lugar de detenerte ante el primer efecto visible:<sup>[[2]](#references)</sup>

- **Exfiltración:** secretos, registros de usuarios, archivos internos, datos de conversaciones o contenido de prompts/contexto salen por un canal observable.
- **Acción no autorizada:** el agente usa capacidades legítimas de escritura para cumplir el objetivo del atacante.
- **Denegación de servicio:** herramientas destructivas u operaciones costosas repetidas afectan la integridad o la disponibilidad.
- **Persistencia:** memoria envenenada, contenido indexado, estado de confianza o cambios en el entorno de ejecución sobreviven a la sesión de origen o a la eliminación de la fuente.
- **Propagación:** un par de confianza consume el mensaje o estado compartido del agente comprometido y repite la acción con sus propias herramientas y credenciales.

La gravedad debe basarse en los datos a los que se puede acceder, los privilegios efectivos, la explotabilidad del destino, la salida de datos, la persistencia y la propagación, no en lo sorprendente que parezca el texto del modelo.<sup>[[2]](#references)</sup>

## Controles que validar durante la evaluación

Los filtros de prompts y un mejor prompt de sistema pueden aumentar el costo para el atacante, pero no deben tratarse como límites de autorización. Valida los controles siguientes volviendo a ejecutar la misma cadena mediante entrada directa, contenido indirecto, memoria, herramientas y agentes pares:<sup>[[2]](#references)</sup>

- Una capa de políticas determinista verifica el usuario autenticado, el tenant, el objeto, la acción y el destino en **cada invocación de herramienta**; el modelo no puede proporcionar ni sobrescribir la identidad del solicitante.
- Las capacidades de lectura y escritura usan credenciales separadas, con privilegios mínimos y de corta duración; las herramientas de alto impacto se habilitan justo a tiempo y nunca se ejecutan automáticamente a partir de contenido ingerido.
- La salida de red y los destinos internos se incluyen en listas de permitidos independientemente de las URL seleccionadas por el modelo; se bloquea el acceso del entorno de ejecución a endpoints de metadatos, secretos montados y servicios vecinos, salvo que sea necesario.
- La interfaz de aprobación se genera a partir de la solicitud estructurada canónica y muestra los argumentos exactos, la identidad, el destino, los objetos afectados y los efectos secundarios, no un resumen libre del modelo.
- El éxito se verifica en el sistema de destino o en el sistema de registro. La narración del agente, una solicitud de llamada a herramienta o una redirección HTTP no prueban que haya ocurrido el cambio de estado anunciado.
- Las entradas de memoria y recuperación conservan su procedencia y etiquetas de confianza, pueden invalidarse y se vuelven a autorizar cuando se usan para una acción posterior.
- Los mensajes entre agentes se autentican y autorizan como solicitudes no confiables; la reputación de un par o su tarjeta de agente no delega implícitamente las herramientas del receptor.

## References

- [1] [Los 10 principales riesgos de OWASP para aplicaciones agénticas de 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [2] [La guía del hacker para atacar agentes de IA](https://darkmarc.substack.com/p/the-hackers-guide-to-attacking-ai)
- [3] [¿Qué tan difícil es realmente sacar a un agente de IA de su sandbox?](https://www.nccgroup.com/research/how-hard-is-it-really-to-break-an-ai-agent-out-of-its-sandbox/)
- [4] [Subagentes en el SDK](https://code.claude.com/docs/en/agent-sdk/subagents)
{{#include ../banners/hacktricks-training.md}}
