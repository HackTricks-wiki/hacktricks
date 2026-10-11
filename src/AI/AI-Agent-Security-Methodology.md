# Metodología de seguridad de agentes de IA

{{#include ../banners/hacktricks-training.md}}

Una evaluación de agentes debe seguir **la entrada controlada por el atacante hasta un efecto observable externamente**. El jailbreaking, los cambios de carácter y la divulgación del system prompt demuestran que se puede influir en un canal de razonamiento, pero el hallazgo de mayor impacto es la cadena que llega al acceso a datos, una acción no autorizada de una herramienta, un punto de inyección posterior, persistencia u otro agente.<sup>[[2]](#references)</sup>

El [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) resulta útil para etiquetar la cobertura (secuestro de objetivos, uso indebido de herramientas, abuso de privilegios, cadena de suministro, ejecución de código, envenenamiento de memoria, confianza entre agentes, fallos en cascada, confianza humana y agentes descontrolados). Usa esas etiquetas después de construir una ruta de ataque de extremo a extremo, en lugar de tratar el texto inesperado de un modelo como el final de la prueba.<sup>[[1]](#references)[[2]](#references)</sup>

## Crear el mapa del objetivo

Antes de escribir payloads, registra estas cinco dimensiones para cada flujo de trabajo del agente:<sup>[[2]](#references)</sup>

| Dimensión | Qué enumerar | Pregunta de seguridad |
|---|---|---|
| **Entrada no confiable** | Parámetros de chat/API, URL, documentos, correo electrónico, tickets, entradas del calendario, fragmentos recuperados, memoria, resultados de herramientas y mensajes de agentes pares | ¿Dónde puede colocar contenido un atacante para que después entre en el contexto del modelo? |
| **Herramientas** | Nombres y esquemas de herramientas, efectos secundarios, ejecución automática, comportamiento de confirmación y herramientas cargadas dinámicamente | ¿Qué llamadas leen secretos, escriben estado, envían mensajes, eliminan datos, ejecutan código o transfieren valor? |
| **Autoridad** | Delegación del usuario, cuentas de servicio, tokens de API, duración de las credenciales, ámbito de tenants/recursos y alcance de red | ¿Con qué identidad se ejecuta cada llamada y se vuelve a comprobar la autorización en el límite de la herramienta? |
| **Procesamiento** | Generadores de consultas, shells, recuperadores de URL, motores de plantillas, intérpretes, parsers, operaciones con archivos y deserializadores | ¿Dónde se convierte el dato generado por el modelo en sintaxis para otro intérprete? |
| **Salida** | Respuestas, Markdown/HTML renderizado, enlaces, recuperación de imágenes, webhooks, correo electrónico, archivos, registros, informes, métricas y tráfico entre agentes | ¿Qué canal observable puede transportar un secreto o activar una solicitud secundaria? |

No reduzcas esto a una lista de integraciones anunciadas. Un recurso útil relaciona cada fuente con la posición exacta del contexto a la que llega, las herramientas disponibles en ese punto, las credenciales que usa cada herramienta, el intérprete posterior y todas las rutas de salida. La misma herramienta puede tener un impacto bajo con un token de lectura por usuario y ser crítica con una credencial de administrador compartida.<sup>[[2]](#references)</sup>

## Reconocimiento

### Mapear todas las rutas de entrega e ingesta

Empieza por la superficie de entrega (web, móvil, API, correo electrónico, plataforma de chat, extensión del navegador) e intercepta el tráfico entre el cliente y el backend. Inspecciona los campos ocultos por la interfaz, los parámetros de búsqueda/autocompletado/filtro, los objetos de estado de conversación, las tareas de carga e indexación, las respuestas de herramientas y el tráfico de subagentes. Es posible que los clientes exclusivamente móviles requieran un emulador e instrumentación para eludir certificate pinning antes de que el esquema real de las solicitudes sea visible.<sup>[[2]](#references)</sup>

Después, mapea la infraestructura bajo el modelo: framework de orquestación, ensamblado de prompts, almacenes de recuperación y memoria, runtime (por ejemplo, Python, un contenedor o WASM), volúmenes montados, servicios del host, API internas, acceso a metadatos de cloud y redes vecinas. Los valores predeterminados del framework son importantes porque algunas “llamadas a herramientas” se implementan generando o evaluando código; el límite del runtime/sandbox determina si el resultado queda contenido.<sup>[[2]](#references)</sup>

### Identificar el enrutamiento mediante pruebas no destructivas

Compara una solicitud dentro del alcance con varias solicitudes no relacionadas, conservando la respuesta completa, el código de estado, la latencia y el comportamiento de streaming. Un rechazo estable antes de cualquier razonamiento específico de la tarea puede indicar una gateway/clasificador independiente; una negativa contextual sugiere que la solicitud llegó al modelo; una respuesta vacía o puramente extractiva puede indicar búsqueda por palabras clave o recuperación limitada. Trata estas observaciones como hipótesis y confírmalas reproduciendo la misma prueba mediante campos de API y rutas de ingesta alternativos.<sup>[[2]](#references)</sup>

El reconocimiento está completo cuando la evaluación puede identificar la primera fuente controlada por el atacante que modifica el comportamiento del agente **y** las herramientas, identidades, intérpretes y salidas accesibles desde esa fuente.<sup>[[2]](#references)</sup>

## Explotación: cruzar un límite de confianza

Prueba los canales, no solo la redacción del prompt. Empieza con inyección directa para determinar qué bloquea la puerta de entrada visible y luego repite una intención equivalente por las rutas menos visibles siguientes:<sup>[[2]](#references)</sup>

- **Contenido indirecto:** páginas, archivos, correo electrónico, tickets, metadatos, texto alt, comentarios HTML, texto fuera de pantalla o caracteres de ancho cero. Consulta [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) para ver técnicas de entrega de payloads.
- **Recuperación y memoria:** envenena contenido que se recuperará más adelante o estado que se volverá a cargar en sesiones posteriores. Registra si eliminar la fuente original hace que cese el comportamiento.
- **Resultados de herramientas y agentes pares:** coloca el marcador en la respuesta de una herramienta o en un mensaje entre agentes para comprobar si el tráfico interno elude los filtros aplicados solo a la entrada del usuario y a la salida final.
- **Cadena de suministro:** revisa los descriptores de herramientas, plugins, servidores conectados, skills, modelos y dependencias como fuentes de instrucciones confiables. Para pruebas específicas de MCP, consulta [MCP Servers](AI-MCP-Servers.md#mcp-vulns).
- **Aprobación humana:** compara la llamada estructurada real a la herramienta con el texto de aprobación generado por el modelo. Comprueba si la influencia del atacante puede omitir el destino, el alcance, los objetos afectados o los efectos secundarios irreversibles.

Usa primero un marcador único e inocuo. Conserva el artefacto de origen, el contexto ensamblado si es observable, la llamada a herramienta seleccionada, los datos de aprobación, la solicitud/respuesta del backend y el estado final. Así se distingue la influencia de una afirmación alucinada de que se realizó una acción.<sup>[[2]](#references)</sup>

## Ejecución: demostrar el impacto real

Hay dos rutas distintas desde la influencia hasta el impacto:<sup>[[2]](#references)</sup>

1. **Abuso de capacidades:** la herramienta autorizada ya realiza el objetivo. Algunos ejemplos son leer el registro de un tenant y escribirlo en un informe visible para el atacante, enviar correo electrónico, modificar registros, eliminar un archivo o iniciar un pago. No se necesita ningún bug de software secundario.
2. **Explotación de un punto posterior:** la salida del modelo manipulada por el atacante se convierte en sintaxis para otro componente. Revisa las consultas a bases de datos para detectar [SQL injection](../pentesting-web/sql-injection/README.md) o [NoSQL injection](../pentesting-web/nosql-injection.md), los wrappers de shell para detectar [command injection](../pentesting-web/command-injection.md), las URL elegidas para detectar [SSRF](../pentesting-web/ssrf-server-side-request-forgery/README.md), las operaciones con archivos para detectar traversal, los evaluadores de plantillas/código para detectar RCE y los parsers de objetos para detectar [unsafe deserialization](../pentesting-web/deserialization/README.md).

Para cada caso candidato, demuestra esta cadena:<sup>[[2]](#references)</sup>

```text
attacker-controlled source
  -> model/context influence
  -> selected tool and arguments
  -> effective identity/credential
  -> capability or vulnerable sink
  -> externally verified state change or data egress
```

Una integración de solo lectura sigue siendo explotable si cualquier componente posterior puede publicar lo que leyó. Prueba las respuestas habituales y vías de salida menos obvias, como enlaces controlados por el atacante, la recuperación automática de imágenes, webhooks, registros, informes, contadores, notificaciones y mensajes a otros agentes.<sup>[[2]](#references)</sup>

## Acciones sobre los objetivos

Tras confirmar una acción, evalúa todo el alcance del impacto en lugar de detenerte en el primer efecto visible:<sup>[[2]](#references)</sup>

- **Exfiltración:** secretos, registros de usuarios, archivos internos, datos de conversaciones o contenido del prompt/contexto salen por un canal observable.
- **Acción no autorizada:** el agente usa capacidades legítimas de escritura para cumplir el objetivo del atacante.
- **Denegación de servicio:** herramientas destructivas u operaciones costosas repetidas afectan la integridad o disponibilidad.
- **Persistencia:** la memoria envenenada, el contenido indexado, el estado de confianza o los cambios en tiempo de ejecución sobreviven a la sesión de origen o a la eliminación de la fuente.
- **Propagación:** un par de confianza consume el mensaje o el estado compartido del agente comprometido y repite la acción con sus propias herramientas y credenciales.

La gravedad debe basarse en los datos accesibles, los privilegios efectivos, la explotabilidad del sink, la salida de datos, la persistencia y la propagación, no en lo sorprendente que parezca el texto del modelo.<sup>[[2]](#references)</sup>

## Controles que validar durante la evaluación

Los filtros de prompt y un mejor system prompt pueden aumentar el costo para el atacante, pero no deben considerarse límites de autorización. Valida los controles siguientes volviendo a ejecutar la misma cadena mediante entrada directa, contenido indirecto, memoria, herramientas y agentes pares:<sup>[[2]](#references)</sup>

- Una capa de políticas determinista comprueba el usuario autenticado, el tenant, el objeto, la acción y el destino en **cada invocación de herramienta**; el modelo no puede proporcionar ni sobrescribir la identidad del solicitante.
- Las capacidades de lectura y escritura usan credenciales separadas, de privilegio mínimo y de corta duración; las herramientas de alto impacto solo se exponen cuando se necesitan y nunca se ejecutan automáticamente a partir de contenido ingerido.
- La salida de red y los destinos internos se incluyen en listas de permitidos independientemente de las URL seleccionadas por el modelo; se bloquea el acceso en tiempo de ejecución a endpoints de metadatos, secretos montados y servicios vecinos, salvo que sea necesario.
- La interfaz de aprobación se genera a partir de la solicitud estructurada canónica y muestra los argumentos exactos, la identidad, el destino, los objetos afectados y los efectos secundarios, no un resumen en texto libre del modelo.
- El éxito se verifica en el sistema de destino o en el sistema de registro. La narración del agente, una solicitud de llamada a herramienta o una redirección HTTP no prueban que se haya producido el cambio de estado alegado.
- Las entradas de memoria y recuperación conservan la procedencia y las etiquetas de confianza, se pueden invalidar y se vuelven a autorizar cuando se utilizan para una acción posterior.
- Los mensajes entre agentes se autentican y autorizan como solicitudes no confiables; la reputación de un par o su ficha de agente no delega implícitamente las herramientas del receptor.

## References

- [1] [Los 10 principales riesgos de OWASP para aplicaciones agentic en 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [2] [La guía del hacker para atacar agentes de IA](https://darkmarc.substack.com/p/the-hackers-guide-to-attacking-ai)
{{#include ../banners/hacktricks-training.md}}
