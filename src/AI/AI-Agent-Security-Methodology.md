# Metodología de seguridad de agentes de IA

{{#include ../banners/hacktricks-training.md}}

Una evaluación de agentes debe seguir **la entrada controlada por un atacante hasta un efecto observable externamente**. El jailbreaking, los cambios de carácter y la divulgación del system prompt demuestran que se puede influir en un canal de razonamiento, pero el hallazgo de mayor impacto es la cadena que lleva al acceso a datos, a una acción no autorizada de una herramienta, a un punto de inyección posterior, a la persistencia o a otro agente.<sup>[[2]](#references)</sup>

El [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) resulta útil para etiquetar la cobertura (secuestro de objetivos, uso indebido de herramientas, abuso de privilegios, cadena de suministro, ejecución de código, envenenamiento de memoria, confianza entre agentes, fallos en cascada, confianza humana y agentes descontrolados). Usa esas etiquetas después de construir una ruta de ataque de extremo a extremo, en lugar de tratar un texto inesperado del modelo como el final de la prueba.<sup>[[1]](#references)[[2]](#references)</sup>

## Crear el mapa del objetivo

Registra estas cinco dimensiones para cada flujo de trabajo del agente antes de redactar payloads:<sup>[[2]](#references)</sup>

| Dimensión | Qué enumerar | Pregunta de seguridad |
|---|---|---|
| **Entrada no confiable** | Parámetros de chat/API, URL, documentos, correo electrónico, tickets, entradas del calendario, fragmentos recuperados, memoria, resultados de herramientas y mensajes de agentes pares | ¿Dónde puede un atacante colocar contenido que luego entre en el contexto del modelo? |
| **Herramientas** | Nombres y esquemas de herramientas, efectos secundarios, ejecución automática, comportamiento de confirmación y herramientas cargadas dinámicamente | ¿Qué llamadas leen secretos, escriben estado, envían mensajes, eliminan datos, ejecutan código o transfieren valor? |
| **Autoridad** | Delegación del usuario, cuentas de servicio, tokens de API, duración de las credenciales, ámbito del tenant/recurso y alcance de red | ¿Con qué identidad se ejecuta cada llamada y se vuelve a comprobar la autorización en el límite de la herramienta? |
| **Procesamiento** | Constructores de consultas, shells, recuperadores de URL, motores de plantillas, intérpretes, parsers, operaciones con archivos y deserializadores | ¿Dónde se convierten los datos generados por el modelo en sintaxis para otro intérprete? |
| **Salida** | Respuestas, Markdown/HTML renderizado, enlaces, carga de imágenes, webhooks, correo electrónico, archivos, registros, informes, métricas y tráfico entre agentes pares | ¿Qué canal observable puede transportar un secreto o activar una solicitud secundaria? |

No lo reduzcas a una lista de integraciones anunciadas. Un artefacto útil vincula cada origen con la posición exacta del contexto a la que llega, las herramientas disponibles en ese punto, las credenciales que usa cada herramienta, el intérprete posterior y todas las rutas de salida. La misma herramienta puede tener un impacto bajo con un token de lectura por usuario y ser crítica con una credencial compartida de administrador.<sup>[[2]](#references)</sup>

## Reconocimiento

### Mapear todas las rutas de entrega e ingesta

Empieza por la superficie de entrega (web, móvil, API, correo electrónico, plataforma de chat, extensión de navegador) y captura el tráfico entre el cliente y el backend con un proxy. Inspecciona los campos que la UI oculta, los parámetros de búsqueda/autocompletado/filtro, los objetos de estado de conversación, los trabajos de carga e indexación, las respuestas de herramientas y el tráfico de subagentes. Los clientes exclusivos para móviles pueden requerir un emulador e instrumentación para eludir el certificate pinning antes de que el esquema real de las solicitudes sea visible.<sup>[[2]](#references)</sup>

Después, mapea la infraestructura subyacente al modelo: framework de orquestación, ensamblado de prompts, almacenes de recuperación y memoria, runtime (por ejemplo, Python, contenedor o WASM), volúmenes montados, servicios del host, API internas, accesibilidad a metadatos cloud y redes adyacentes. Los valores predeterminados del framework importan porque algunas «llamadas a herramientas» se implementan generando o evaluando código; el límite del runtime/sandbox determina si el resultado queda contenido.<sup>[[2]](#references)</sup>

### Identificar el enrutamiento con probes no destructivos

Compara una solicitud dentro del alcance con varias solicitudes no relacionadas, conservando la respuesta completa, el código de estado, la latencia y el comportamiento de streaming. Un rechazo estable antes de cualquier razonamiento específico de la tarea puede indicar un gateway/clasificador separado; una negativa contextual sugiere que la solicitud llegó al modelo; una respuesta vacía o puramente extractiva puede indicar búsqueda por palabras clave o recuperación acotada. Trátalo como hipótesis y confírmalo reproduciendo el mismo probe a través de campos alternativos de la API y rutas de ingesta.<sup>[[2]](#references)</sup>

El reconocimiento termina cuando la evaluación puede identificar el origen controlado por el atacante más temprano que modifica el comportamiento del agente **y** las herramientas, identidades, intérpretes y salidas a las que se puede acceder desde ese origen.<sup>[[2]](#references)</sup>

## Explotación: cruzar un límite de confianza

Prueba los canales, no solo la redacción del prompt. Empieza con una inyección directa para establecer qué bloquea la entrada visible y luego repite una intención equivalente a través de las rutas menos visibles que se indican a continuación:<sup>[[2]](#references)</sup>

- **Contenido indirecto:** páginas, archivos, correo electrónico, tickets, metadatos, texto alternativo, comentarios HTML, texto fuera de pantalla o caracteres de ancho cero. Consulta [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) para ver técnicas de entrega de payloads.
- **Recuperación y memoria:** envenena contenido que se recuperará más adelante o estado que se volverá a cargar en sesiones posteriores. Registra si eliminar el origen original elimina el comportamiento.
- **Salida de herramientas y agentes pares:** coloca el marcador en la respuesta de una herramienta o en un mensaje entre agentes para probar si el tráfico interno elude los filtros aplicados solo a la entrada del usuario y a la salida final.
- **Cadena de suministro:** revisa los descriptores de herramientas, plugins, servidores conectados, skills, modelos y dependencias como fuentes de instrucciones confiables. Para pruebas específicas de MCP, consulta [MCP Servers](AI-MCP-Servers.md#mcp-vulns).
- **Aprobación humana:** compara la llamada estructurada real a la herramienta con el texto de aprobación generado por el modelo. Prueba si la influencia del atacante puede omitir el destino, el ámbito, los objetos afectados o los efectos secundarios irreversibles.

Usa primero un marcador único e inocuo. Conserva el artefacto de origen, el contexto ensamblado si es observable, la llamada a la herramienta seleccionada, los datos de aprobación, la solicitud/respuesta del backend y el estado final. Así se distingue la influencia de una afirmación alucinada de que se realizó una acción.<sup>[[2]](#references)</sup>

### Texto que imita políticas en un evaluador de riesgo de herramientas

Un filtro de herramientas basado en un modelo puede recibir texto controlado por un atacante dentro de un contexto de clasificación que, por lo demás, es útil. Por ejemplo, el `AutoModeMiddleware` experimental de LangChain envía a un evaluador `is_risky` de TypeSafe una llamada propuesta a una herramienta, sus argumentos, una descripción opcional de la herramienta y hasta 30 mensajes recientes. Bloquea las herramientas configuradas cuando la probabilidad Noul devuelta es igual o superior a `0.5`; este middleware no clasifica las herramientas que no están en la lista.<sup>[[5]](#references)</sup> TypeSafe también advierte que el texto adversarial en el estado puede influir en una clasificación, incluso cuando se pretende que el estado sean datos.<sup>[[6]](#references)</sup>

Una **política falsificada** es distinta de limitarse a afirmar que se es un mensaje del sistema. Coloca etiquetas alternativas o definiciones de riesgo en un estado de menor confianza e induce al evaluador a usar esas definiciones en vez de los criterios definidos por el desarrollador. En la prueba de Datadog, un `profile_description` editable por el usuario se copió en los argumentos de la herramienta junto con `can_edit:false`. Su texto, que imitaba una política, sostenía que un intento de escritura tenía poco riesgo porque una comprobación de permisos separada lo rechazaría antes de cualquier modificación. En 40 ejecuciones, la puntuación media de `is_risky` bajó de `0.893` a `0.290`, mientras que una comparación directa de suplantación de roles tuvo un promedio de `0.905`. Que la media caiga por debajo de `0.5` no demuestra que todas las llamadas individuales superaran el filtro, y el experimento **no** demostró que se completara una escritura no autorizada.<sup>[[7]](#references)</sup>

Al probar este límite, distingue el veredicto del clasificador del resultado de autorización real de la herramienta. Comprueba qué campos editables llegan al evaluador, compara la misma acción propuesta con y sin texto que imite una política y verifica el estado final de forma independiente. Una comprobación de permisos separada debe seguir usando la autoridad del solicitante autenticado, no los derechos de la cuenta de servicio del conector.<sup>[[7]](#references)</sup> Consulta [prompt-filter bypasses](AI-Prompts.md#prompt-waf-bypass) para ver otros modos de fallo del clasificador; [LLM gateway trust boundaries](AI-LLM-Gateway-Security.md) trata un límite distinto de enrutamiento y credenciales.

### Aislamiento del contexto de subagentes

Un subagente del Claude Agent SDK que no usa fork recibe su propio `AgentDefinition.prompt`, el prompt de delegación y sus herramientas disponibles, pero no el system prompt ni la conversación del agente principal. Si se omite `tools` en su definición, hereda las herramientas disponibles para los subagentes; es posible que también se cargue el `CLAUDE.md` del proyecto. Por eso, una restricción de prompt exclusiva del agente principal no es un límite fiable cuando el hijo puede usar las mismas herramientas de sistema de archivos o ejecución.<sup>[[4]](#references)</sup>

Prueba el límite comparando una solicitud directa que el agente principal rechaza con la misma tarea delegada a un subagente con nombre. NCC Group informa que una enumeración de archivos del sistema operativo que fue rechazada tuvo éxito cuando se reformuló para un hijo como un inofensivo «mapa de la estructura».<sup>[[3]](#references)</sup>

Inspecciona las llamadas reales a herramientas del hijo y su lista efectiva de herramientas permitidas, no solo la respuesta final del agente principal; confirma si el hijo accedió a archivos a los que el agente principal no accedería.<sup>[[4]](#references)</sup> Se trata de un fallo de herencia de guardrails, no de una prueba de [escape de Python sandbox](../generic-methodologies-and-resources/python/bypass-python-sandboxes/) ni de escape de contenedor.<sup>[[3]](#references)[[4]](#references)</sup>

### Agentes móviles con GUI: instrucciones en pantalla y reasignación de acciones

Un agente GUI de teléfono puede enviar cada captura de pantalla a un modelo cloud antes de elegir la siguiente acción entre aplicaciones. Para probar la **inyección visual indirecta**, coloca texto controlado por un atacante en un SMS, correo electrónico o página que el agente vaya a inspeccionar durante una tarea autorizada. Compara un prompt directo de la tarea con la misma instrucción visible solo en la captura y, después, inspecciona la siguiente acción y cualquier decisión sobre operaciones de alto riesgo. En el asistente evaluado, la comprobación del lado del cliente `checkPrompt` filtraba el texto directo de la tarea, pero no aplicaba un filtrado equivalente al contenido de las capturas de pantalla. Esta es una variante móvil y entre aplicaciones de la [inyección en capturas de pantalla de navegadores agénticos](../generic-methodologies-and-resources/phishing-methodology/ai-agent-mode-phishing-abusing-hosted-agent-browsers.md), no una forma de eludir la autenticación de componentes de Android.<sup>[[9]](#references)</sup>

Una prueba ilustrativa de efectos secundarios usa un formulario controlado por un atacante que pide al agente rellenar campos sensibles y luego solicita a una persona que haga clic en «upload», mientras la página envía los campos completados en cuanto cambian. La intervención humana no puede proteger los datos que el código de la página ya envió; verifica el envío real en lugar de considerar la narración del agente como prueba. La fuente presenta esto como un patrón posible, no como un compromiso demostrado de todos los asistentes.<sup>[[9]](#references)</sup>

**TOCTOU de GUI / reasignación de acciones** es un modo de fallo distinto: el agente planifica una entrada a partir de una pantalla observada en `t0`, pero la UI en primer plano cambia antes de que la entrada se inyecte en `t1`.<sup>[[8]](#references)</sup> Una captura posterior en `t2` no puede deshacer una acción ya realizada.<sup>[[9]](#references)</sup> En una prueba autorizada de Android, el flujo de trabajo reutilizable es:<sup>[[8]](#references)</sup>

1. Perfila las coordenadas en pantalla del control objetivo y muestra un control inocuo en la misma ubicación en una aplicación controlada.
2. Mantén visible ese elemento portador hasta que el agente lo observe; después, activa una transición normal en primer plano durante el intervalo entre la observación y la acción.
3. Comprueba si el toque planificado recae sobre el control de la nueva aplicación y verifica el estado resultante en la aplicación objetivo, en lugar de confiar en la narración del agente.

El estudio original sobre reasignación de acciones lo demuestra con una aplicación que no tiene permisos peligrosos; también describe repetir la transición mediante el bucle de recuperación de tareas del agente para flujos de varios pasos.<sup>[[8]](#references)</sup>

**No** des por hecho que la primitiva funciona igual con todos los asistentes. En la evaluación de Doubao, `OpClickUI` omitía los clics si cambiaba la Activity de nivel superior y comparaba capturas de pantalla cuando `OpOpenApp` aparecía en los tres pasos anteriores. Por tanto, los toques simples, las pulsaciones largas y los dobles toques ofrecían pocas oportunidades fiables para controlar el momento desde el lado del atacante. `OpTypeText`, `OpSwipeUI` y `OpScrollWheelAction` no tenían salvaguardas equivalentes, pero el informe consideró más limitado su impacto práctico.<sup>[[9]](#references)</sup>

## Ejecución: demostrar el impacto real

Hay dos rutas distintas desde la influencia hasta el impacto:<sup>[[2]](#references)</sup>

1. **Abuso de capacidades:** la herramienta autorizada ya realiza el objetivo. Algunos ejemplos son leer el registro de un tenant y escribirlo en un informe visible para el atacante, enviar correo electrónico, cambiar registros, eliminar un archivo o iniciar un pago. No se necesita ningún bug de software secundario.
2. **Explotación de un punto de entrada posterior:** la salida del modelo controlada por el atacante se convierte en sintaxis para otro componente. Revisa los querys de bases de datos para detectar [SQL injection](../pentesting-web/sql-injection/README.md) o [NoSQL injection](../pentesting-web/nosql-injection.md), los wrappers de shell para [command injection](../pentesting-web/command-injection.md), las URL elegidas para [SSRF](../pentesting-web/ssrf-server-side-request-forgery/README.md), las operaciones con archivos para path traversal, los evaluadores de plantillas/código para RCE y los parsers de objetos para [unsafe deserialization](../pentesting-web/deserialization/README.md).

Para cada caso candidato, demuestra esta cadena:<sup>[[2]](#references)</sup>

```text
attacker-controlled source
  -> model/context influence
  -> selected tool and arguments
  -> effective identity/credential
  -> capability or vulnerable sink
  -> externally verified state change or data egress
```

Una integración de solo lectura sigue siendo explotable si cualquier componente posterior puede publicar lo que ha leído. Prueba las respuestas habituales y también formas de egreso menos evidentes, como enlaces controlados por el atacante, recuperación automática de imágenes, webhooks, logs, informes, contadores, notificaciones y mensajes a otros agentes.<sup>[[2]](#references)</sup>

## Acciones sobre los objetivos

Tras confirmar una acción, evalúa todo el blast radius en lugar de detenerte ante el primer efecto visible:<sup>[[2]](#references)</sup>

- **Exfiltración:** secretos, registros de usuarios, archivos internos, datos de conversaciones o contenido del prompt/contexto salen por un canal observable.
- **Acción no autorizada:** el agente usa capacidades legítimas de escritura para cumplir el objetivo del atacante.
- **Denegación de servicio:** herramientas destructivas u operaciones costosas repetidas afectan la integridad o disponibilidad.
- **Persistencia:** la memoria envenenada, el contenido indexado, el estado de confianza o los cambios en runtime sobreviven a la sesión de origen o a la eliminación de la fuente.
- **Propagación:** un peer de confianza consume el mensaje o el estado compartido del agente comprometido y repite la acción con sus propias herramientas y credenciales.

La gravedad debe basarse en los datos accesibles, los privilegios efectivos, la explotabilidad del sink, el egreso, la persistencia y la propagación; no en lo sorprendente que parezca el texto del modelo.<sup>[[2]](#references)</sup>

## Controles que validar durante la evaluación

Los filtros de prompt y un mejor system prompt pueden aumentar el costo para el atacante, pero no deben considerarse límites de autorización. Valida los controles siguientes volviendo a ejecutar la misma cadena mediante entradas directas, contenido indirecto, memoria, herramientas y agentes peer:<sup>[[2]](#references)</sup>

- Una capa de políticas determinista comprueba el usuario autenticado, el tenant, el objeto, la acción y el destino en **cada invocación de herramienta**; el modelo no puede proporcionar ni sobrescribir la identidad del llamante.
- Las capacidades de lectura y escritura usan credenciales separadas, de mínimo privilegio y de corta duración; las herramientas de alto impacto se habilitan just in time y nunca se ejecutan automáticamente a partir del contenido ingerido.
- El egreso de red y los destinos internos se incluyen en listas de permitidos independientemente de las URL seleccionadas por el modelo; se bloquea el acceso desde runtime a los endpoints de metadatos, secretos montados y servicios vecinos, salvo que sea necesario.
- La interfaz de aprobación se genera a partir de la solicitud estructurada canónica y muestra los argumentos exactos, la identidad, el destino, los objetos afectados y los efectos secundarios, no un resumen libre del modelo.
- El éxito se verifica en el sistema de destino o en el sistema de registro. La narración del agente, una solicitud de llamada a herramienta o una redirección HTTP no demuestran que se haya producido el cambio de estado afirmado.
- Las entradas de memoria y recuperación conservan la procedencia y las etiquetas de confianza, pueden invalidarse y se vuelven a autorizar cuando se usan para una acción posterior.
- Los mensajes entre agentes se autentican y autorizan como solicitudes no confiables; la reputación de un peer o su ficha de agente no delega implícitamente las herramientas del receptor.

Para consultar las fichas de agente A2A, los flujos de tareas y su superficie de ataque, revisa [A2A Protocol Security](AI-A2A-Protocol.md).

## References

- [1] [OWASP Top 10 para aplicaciones agénticas de 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [2] [La guía del hacker para atacar agentes de IA](https://darkmarc.substack.com/p/the-hackers-guide-to-attacking-ai)
- [3] [¿Qué tan difícil es realmente sacar a un agente de IA de su sandbox?](https://www.nccgroup.com/research/how-hard-is-it-really-to-break-an-ai-agent-out-of-its-sandbox/)
- [4] [Subagentes en el SDK](https://code.claude.com/docs/en/agent-sdk/subagents)
- [5] [Código fuente del middleware LangChain TypeSafe Auto Mode](https://github.com/langchain-ai/langchain/blob/master/libs/partners/typesafe/langchain_typesafe/experimental/middleware/auto_mode.py)
- [6] [Irregularidades del modelo TypeSafe AI Jev: contenido adversarial](https://docs.typesafe.ai/model-jaggedness/jev-1.13#adversarial-content)
- [7] [Jev como juez: cómo una política falsa manipula a Jev](https://securitylabs.datadoghq.com/articles/jev-as-a-judge-how-counterfeit-policy-steers-jev/)
- [8] [Manipulación sin permisos: ¿podemos confiar en agentes GUI basados en modelos multimodales grandes?](https://arxiv.org/html/2601.12349v1)
- [9] [Cuando un asistente de IA pasa a formar parte de la cadena de ataque del hacker | Análisis de seguridad de Doubao Phone](https://www.darknavy.org/blog/security_analysis_of_doubao_phone/)
{{#include ../banners/hacktricks-training.md}}
