# Metodología de seguridad de agentes de IA

{{#include ../banners/hacktricks-training.md}}

Una evaluación de agentes debe seguir **la entrada controlada por el atacante hasta un efecto observable externamente**. El jailbreaking, los cambios de carácter y la divulgación del system prompt demuestran que se puede influir en un canal de razonamiento, pero el hallazgo de mayor impacto es la cadena que conduce al acceso a datos, una acción no autorizada de una herramienta, un punto de inyección posterior, persistencia u otro agente.<sup>[[2]](#references)</sup>

El [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) resulta útil para etiquetar la cobertura (secuestro de objetivos, uso indebido de herramientas, abuso de privilegios, cadena de suministro, ejecución de código, envenenamiento de memoria, confianza entre agentes, fallos en cascada, confianza humana y agentes rogue). Usa esas etiquetas después de construir una ruta de ataque de extremo a extremo, en lugar de tratar el texto inesperado de un modelo como el final de la prueba.<sup>[[1]](#references)[[2]](#references)</sup>

## Crear el mapa del objetivo

Antes de escribir payloads, registra estas cinco dimensiones para cada flujo de trabajo del agente:<sup>[[2]](#references)</sup>

| Dimensión | Qué enumerar | Pregunta de seguridad |
|---|---|---|
| **Entrada no confiable** | Parámetros de chat/API, URL, documentos, correo electrónico, tickets, entradas del calendario, fragmentos recuperados, memoria, resultados de herramientas y mensajes de agentes pares | ¿Dónde puede colocar contenido un atacante para que después llegue al contexto del modelo? |
| **Herramientas** | Nombres y esquemas de herramientas, efectos secundarios, ejecución automática, comportamiento de confirmación y herramientas cargadas dinámicamente | ¿Qué llamadas leen secretos, escriben datos, envían mensajes, eliminan datos, ejecutan código o transfieren valor? |
| **Autoridad** | Delegación del usuario, cuentas de servicio, tokens de API, duración de las credenciales, ámbito de tenants/recursos y alcance de red | ¿Con qué identidad se ejecuta cada llamada y se vuelve a comprobar la autorización en el límite de la herramienta? |
| **Procesamiento** | Constructores de consultas, shells, URL fetchers, motores de plantillas, intérpretes, parsers, operaciones de archivos y deserializadores | ¿Dónde se convierten los datos generados por el modelo en sintaxis para otro intérprete? |
| **Salida** | Respuestas, Markdown/HTML renderizado, enlaces, solicitudes de imágenes, webhooks, correo electrónico, archivos, logs, informes, métricas y tráfico entre agentes | ¿Qué canal observable puede transportar un secreto o activar una solicitud secundaria? |

No lo reduzcas a una lista de integraciones anunciadas. Un artefacto útil relaciona cada fuente con la posición exacta del contexto a la que llega, las herramientas disponibles en ese punto, la credencial que usa cada herramienta, el intérprete posterior y todas las rutas de salida. La misma herramienta puede tener un impacto bajo con un token de lectura por usuario y ser crítica con una credencial compartida de administrador.<sup>[[2]](#references)</sup>

## Reconocimiento

### Mapear todas las rutas de entrega e ingesta

Empieza por la superficie de entrega (web, móvil, API, correo electrónico, plataforma de chat, extensión del navegador) e intercepta el tráfico entre el cliente y el backend. Inspecciona los campos ocultos por la interfaz, los parámetros de búsqueda/autocompletado/filtro, los objetos de estado de la conversación, los trabajos de carga e indexación, las respuestas de herramientas y el tráfico de subagentes. Los clientes exclusivos para móviles pueden requerir un emulador e instrumentación para eludir el certificate pinning antes de que el esquema real de las solicitudes quede visible.<sup>[[2]](#references)</sup>

Después, mapea la pila que hay bajo el modelo: framework de orquestación, ensamblado de prompts, almacenes de recuperación y memoria, runtime (por ejemplo, Python, contenedor o WASM), volúmenes montados, servicios del host, API internas, accesibilidad a los metadatos de la nube y redes vecinas. Los valores predeterminados del framework importan porque algunas “llamadas a herramientas” se implementan generando o evaluando código; el límite del runtime/sandbox determina si ese resultado queda contenido.<sup>[[2]](#references)</sup>

### Identificar el enrutamiento con probes no destructivos

Compara una solicitud dentro del alcance con varias solicitudes no relacionadas, conservando la respuesta completa, el código de estado, la latencia y el comportamiento de streaming. Un rechazo estable antes de cualquier razonamiento específico de la tarea puede indicar un gateway/clasificador independiente; una negativa contextual sugiere que la solicitud llegó al modelo; una respuesta vacía o puramente extractiva puede indicar búsqueda por palabras clave o recuperación limitada. Trátalos como hipótesis y confírmalas reproduciendo el mismo probe mediante campos de API y rutas de ingesta alternativos.<sup>[[2]](#references)</sup>

El reconocimiento está completo cuando la evaluación puede identificar la fuente controlada por el atacante más temprana que cambia el comportamiento del agente **y** las herramientas, identidades, intérpretes y salidas accesibles desde esa fuente.<sup>[[2]](#references)</sup>

## Explotación: cruzar un límite de confianza

Prueba los canales, no solo la redacción de los prompts. Empieza con inyección directa para establecer qué bloquea la puerta de entrada visible y luego repite una intención equivalente a través de las rutas menos visibles siguientes:<sup>[[2]](#references)</sup>

- **Contenido indirecto:** páginas, archivos, correo electrónico, tickets, metadatos, texto alternativo, comentarios HTML, texto fuera de pantalla o caracteres de ancho cero. Consulta [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) para ver técnicas de entrega de payloads.
- **Recuperación y memoria:** envenena contenido que se recuperará más adelante o estado que se volverá a cargar en sesiones posteriores. Registra si eliminar la fuente original elimina el comportamiento.
- **Resultados de herramientas y agentes pares:** coloca el marcador en la respuesta de una herramienta o en un mensaje entre agentes para comprobar si el tráfico interno elude los filtros que solo se aplican a la entrada del usuario y a la salida final.
- **Cadena de suministro:** revisa los descriptores de herramientas, plugins, servidores conectados, skills, modelos y dependencias como fuentes de instrucciones confiables. Para pruebas específicas de MCP, consulta [MCP Servers](AI-MCP-Servers.md#mcp-vulns).
- **Aprobación humana:** compara la llamada estructurada real a la herramienta con el texto de aprobación generado por el modelo. Comprueba si la influencia del atacante puede omitir el destino, el ámbito, los objetos afectados o los efectos secundarios irreversibles.

Usa primero un marcador benigno y único. Conserva el artefacto de origen, el contexto ensamblado si es observable, la llamada a la herramienta seleccionada, los datos de aprobación, la solicitud/respuesta del backend y el estado final. Así se distingue la influencia de una afirmación alucinada de que se realizó una acción.<sup>[[2]](#references)</sup>

### Texto con apariencia de política en un evaluador de riesgos de herramientas

Un control de herramientas basado en modelos puede recibir texto controlado por el atacante dentro de un contexto de clasificación que, por lo demás, es útil. Por ejemplo, el `AutoModeMiddleware` experimental de LangChain envía una llamada de herramienta propuesta, sus argumentos, una descripción opcional de la herramienta y hasta 30 mensajes recientes a un evaluador `is_risky` de TypeSafe. Bloquea las herramientas configuradas cuando la probabilidad Noul devuelta es al menos `0.5`; este middleware no clasifica las herramientas que no están en la lista.<sup>[[5]](#references)</sup> TypeSafe también advierte que el texto adversario en el estado puede influir en una clasificación, aunque se pretenda que el estado sea solo datos.<sup>[[6]](#references)</sup>

Una **política falsificada** es distinta de simplemente afirmar que se es un mensaje del sistema. Coloca etiquetas alternativas o definiciones de riesgo dentro de un estado de menor confianza e invita al evaluador a usar esas definiciones en lugar de los criterios definidos por el desarrollador. En la prueba de Datadog, se copió un `profile_description` editable por el usuario en los argumentos de la herramienta junto con `can_edit:false`. El texto con apariencia de política sostenía que un intento de escritura era de bajo riesgo porque una comprobación de permisos separada lo rechazaría antes de cualquier modificación. En 40 ejecuciones, la puntuación media de `is_risky` cayó de `0.893` a `0.290`, mientras que una comparación directa de suplantación de rol obtuvo una media de `0.905`. Que la media caiga por debajo de `0.5` no demuestra que todas las llamadas individuales superaran el control, y el experimento **no** demostró que se completara una escritura no autorizada.<sup>[[7]](#references)</sup>

Al probar este límite, distingue el veredicto del clasificador del resultado de autorización real de la herramienta. Comprueba qué campos editables llegan al evaluador, compara la misma acción propuesta con y sin texto con apariencia de política y verifica el estado final de forma independiente. Una comprobación de permisos separada debe seguir usando la autoridad del solicitante autenticado, no los derechos de la cuenta de servicio del conector.<sup>[[7]](#references)</sup> Consulta [prompt-filter bypasses](AI-Prompts.md#prompt-waf-bypass) para conocer otros modos de fallo de clasificadores; [LLM gateway trust boundaries](AI-LLM-Gateway-Security.md) se refiere a un límite distinto de enrutamiento y credenciales.

### Aislamiento del contexto de subagentes

Un subagente no bifurcado del Claude Agent SDK recibe su propio `AgentDefinition.prompt`, el prompt de delegación y las herramientas disponibles, pero no el system prompt ni la conversación del agente principal. Si se omite `tools` de su definición, hereda las herramientas disponibles para los subagentes; también puede cargarse el `CLAUDE.md` del proyecto. Esto hace que una restricción del prompt exclusiva del agente principal sea un límite poco fiable cuando el hijo puede usar las mismas herramientas de sistema de archivos o ejecución.<sup>[[4]](#references)</sup>

Prueba el límite comparando una solicitud directa que el agente principal rechaza con la misma tarea delegada a un subagente con nombre. NCC Group informa que una enumeración de archivos del sistema operativo que se había rechazado tuvo éxito cuando se reformuló para el agente hijo como un «mapa de distribución» inofensivo.<sup>[[3]](#references)</sup>

Inspecciona las llamadas reales a herramientas del hijo y su lista de herramientas permitidas efectiva, no solo la respuesta final del agente principal; confirma si el hijo accedió a archivos a los que el agente principal no accedería.<sup>[[4]](#references)</sup> Esto es un fallo de herencia de guardrails, no una prueba de [Python sandbox](../generic-methodologies-and-resources/python/bypass-python-sandboxes/) ni de escape de contenedor.<sup>[[3]](#references)[[4]](#references)</sup>

## Ejecución: demostrar el impacto real

Hay dos rutas distintas desde la influencia hasta el impacto:<sup>[[2]](#references)</sup>

1. **Abuso de capacidades:** la herramienta autorizada ya realiza el objetivo. Algunos ejemplos son leer el registro de un tenant y escribirlo en un informe visible para el atacante, enviar correo electrónico, modificar registros, eliminar un archivo o iniciar un pago. No se requiere un bug de software secundario.
2. **Explotación de puntos posteriores:** la salida del modelo controlada por el atacante se convierte en sintaxis para otro componente. Revisa las consultas a bases de datos en busca de [SQL injection](../pentesting-web/sql-injection/README.md) o [NoSQL injection](../pentesting-web/nosql-injection.md), los wrappers de shell en busca de [command injection](../pentesting-web/command-injection.md), las URL elegidas en busca de [SSRF](../pentesting-web/ssrf-server-side-request-forgery/README.md), las operaciones de archivos en busca de traversal, los evaluadores de plantillas/código en busca de RCE y los parsers de objetos en busca de [unsafe deserialization](../pentesting-web/deserialization/README.md).

Para cada posible caso, demuestra esta cadena:<sup>[[2]](#references)</sup>

```text
attacker-controlled source
  -> model/context influence
  -> selected tool and arguments
  -> effective identity/credential
  -> capability or vulnerable sink
  -> externally verified state change or data egress
```

Una integración de solo lectura sigue siendo explotable si cualquier componente posterior puede publicar lo que leyó. Prueba las respuestas habituales y también las vías de salida menos evidentes, como enlaces controlados por un atacante, la obtención automática de imágenes, webhooks, registros, informes, contadores, notificaciones y mensajes a otros agentes.<sup>[[2]](#references)</sup>

## Acciones sobre los objetivos

Tras confirmar una acción, evalúa todo el radio de impacto en lugar de detenerte en el primer efecto visible:<sup>[[2]](#references)</sup>

- **Exfiltración:** secretos, registros de usuarios, archivos internos, datos de conversaciones o contenido de prompts/contexto salen por un canal observable.
- **Acción no autorizada:** el agente usa capacidades legítimas de escritura para lograr el objetivo del atacante.
- **Denegación de servicio:** herramientas destructivas u operaciones costosas repetidas afectan la integridad o la disponibilidad.
- **Persistencia:** memoria envenenada, contenido indexado, estado de confianza o cambios en tiempo de ejecución persisten tras finalizar la sesión o eliminar la fuente que los originó.
- **Propagación:** un par de confianza consume el mensaje o estado compartido del agente comprometido y repite la acción con sus propias herramientas y credenciales.

La gravedad debe basarse en los datos accesibles, los privilegios efectivos, la explotabilidad del sink, el egress, la persistencia y la propagación, no en lo sorprendente que parezca el texto del modelo.<sup>[[2]](#references)</sup>

## Controles que se deben validar durante la evaluación

Los filtros de prompts y un mejor system prompt pueden elevar el coste para el atacante, pero no deben tratarse como límites de autorización. Valida los controles siguientes volviendo a ejecutar la misma cadena mediante entrada directa, contenido indirecto, memoria, herramientas y agentes pares:<sup>[[2]](#references)</sup>

- Una capa de políticas determinista verifica el usuario autenticado, el tenant, el objeto, la acción y el destino en **cada invocación de herramienta**; el modelo no puede proporcionar ni sobrescribir la identidad del usuario que realiza la solicitud.
- Las capacidades de lectura y escritura usan credenciales separadas, de mínimo privilegio y de corta duración; las herramientas de alto impacto se habilitan justo a tiempo y nunca se ejecutan automáticamente a partir de contenido ingerido.
- El egress de red y los destinos internos se incluyen en listas de permitidos independientemente de las URL seleccionadas por el modelo; se bloquea el acceso del entorno de ejecución a endpoints de metadatos, secretos montados y servicios vecinos, salvo que sea necesario.
- La interfaz de aprobación se genera a partir de la solicitud estructurada canónica y muestra los argumentos exactos, la identidad, el destino, los objetos afectados y los efectos secundarios, no un resumen en texto libre generado por el modelo.
- El éxito se verifica en el sistema de destino o en el sistema de registro. La narración del agente, una solicitud de llamada a herramienta o una redirección HTTP no prueban que se haya producido el cambio de estado indicado.
- Las entradas de memoria y recuperación conservan su procedencia y etiquetas de confianza, pueden invalidarse y se vuelven a autorizar cuando se usan para una acción posterior.
- Los mensajes entre agentes se autentican y autorizan como solicitudes no confiables; la reputación de un par o su tarjeta de agente no delega implícitamente las herramientas del receptor.

Para consultar las tarjetas de agente A2A, los flujos de tareas y su superficie de ataque, revisa [Seguridad del protocolo A2A](AI-A2A-Protocol.md).

## References

- [1] [OWASP Top 10 para aplicaciones agénticas de 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [2] [La guía del hacker para atacar agentes de IA](https://darkmarc.substack.com/p/the-hackers-guide-to-attacking-ai)
- [3] [¿Qué tan difícil es realmente sacar a un agente de IA de su sandbox?](https://www.nccgroup.com/research/how-hard-is-it-really-to-break-an-ai-agent-out-of-its-sandbox/)
- [4] [Subagentes en el SDK](https://code.claude.com/docs/en/agent-sdk/subagents)
- [5] [Código fuente del middleware Auto Mode de LangChain TypeSafe](https://github.com/langchain-ai/langchain/blob/master/libs/partners/typesafe/langchain_typesafe/experimental/middleware/auto_mode.py)
- [6] [Irregularidad del modelo Jev de TypeSafe AI: contenido adversarial](https://docs.typesafe.ai/model-jaggedness/jev-1.13#adversarial-content)
- [7] [Jev como juez: cómo una política falsificada dirige a Jev](https://securitylabs.datadoghq.com/articles/jev-as-a-judge-how-counterfeit-policy-steers-jev/)
{{#include ../banners/hacktricks-training.md}}
