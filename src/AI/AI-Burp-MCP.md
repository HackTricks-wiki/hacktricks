# Burp MCP: revisión del tráfico asistida por LLM

{{#include ../banners/hacktricks-training.md}}

## Descripción general

La extensión **MCP Server** de Burp puede exponer el tráfico HTTP(S) interceptado a clientes LLM compatibles con MCP para que puedan **analizar solicitudes/respuestas reales** y detectar vulnerabilidades y redactar informes. Mantén Burp como fuente de verdad: usa análisis pasivo o repeticiones deliberadas de una sola variable en lugar de escaneos a ciegas.<sup>[[8]](#references)</sup>

## Arquitectura

- **Burp MCP Server (BApp)** escucha en `127.0.0.1:9876` de forma predeterminada y expone el tráfico interceptado mediante MCP.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- **MCP proxy JAR** conecta stdio (del lado del cliente) con el endpoint MCP SSE de Burp.
- **Proxy inverso local opcional** (Caddy) normaliza los encabezados para las comprobaciones estrictas del handshake MCP.
- **Clientes/backends**: Codex CLI (cloud), Gemini CLI (cloud) u Ollama (local).

## Configuración

### 1) Instalar Burp MCP Server

Instala **MCP Server** desde Burp BApp Store y verifica que esté escuchando en `127.0.0.1:9876`.<sup>[[1]](#references)[[2]](#references)</sup>

### 2) Extraer el proxy JAR

En la pestaña MCP Server, haz clic en **Extract server proxy jar** y guarda `mcp-proxy-all.jar`.<sup>[[7]](#references)</sup>

### 3) Configurar un cliente MCP (ejemplo con Codex)

Indica al cliente que use el proxy JAR y el endpoint SSE directo de Burp. El proxy incluido conecta stdio con SSE; no reemplaza el listener de Burp.<sup>[[7]](#references)</sup>

```toml
# ~/.codex/config.toml
[mcp_servers.burp]
command = "java"
args = ["-jar", "/absolute/path/to/mcp-proxy-all.jar", "--sse-url", "http://127.0.0.1:9876"]
```

El comando equivalente de Codex es:<sup>[[7]](#references)[[8]](#references)</sup>

```bash
codex mcp add burp -- /path/to/java -jar /path/to/mcp-proxy-all.jar \
  --sse-url http://127.0.0.1:9876
```

Luego ejecuta Codex y enumera las herramientas de MCP:

```bash
codex
# inside Codex: /mcp
```

### 4) Corregir la validación estricta de Origin/headers con Caddy (si es necesario)

Si el handshake de MCP falla debido a comprobaciones estrictas de `Origin` o a headers adicionales, usa un proxy inverso local para normalizar los headers (esto coincide con la solución alternativa para el problema de validación estricta de Burp MCP).<sup>[[1]](#references)[[3]](#references)</sup>

```bash
brew install caddy
mkdir -p ~/burp-mcp
cat >~/burp-mcp/Caddyfile <<'EOF'
:19876

reverse_proxy 127.0.0.1:9876 {
  # lock Host/Origin to the Burp listener
  header_up Host "127.0.0.1:9876"
  header_up Origin "http://127.0.0.1:9876"

  # strip client headers that trigger Burp's 403 during SSE init
  header_up -User-Agent
  header_up -Accept
  header_up -Accept-Encoding
  header_up -Connection
}
EOF
```

Inicia el proxy y el cliente, y cambia el `--sse-url` configurado a `http://127.0.0.1:19876` únicamente mientras uses este listener de Caddy:<sup>[[1]](#references)[[3]](#references)</sup>

```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```

### 5) Emparejar el estado del navegador con la evidencia del proxy (Playwright MCP)

Registra Playwright MCP para que su navegador use el proxy de Burp. Esto permite que el agente correlacione el estado del DOM y la accesibilidad renderizados con el historial HTTP exacto que los produjo.<sup>[[6]](#references)[[8]](#references)</sup>

```bash
codex mcp add playwright -- npx -y @playwright/mcp@latest \
  --proxy-server=http://127.0.0.1:8080 \
  --ignore-https-errors
```

Adapta la dirección del listener, reinicia Codex y usa `/mcp` para verificar ambas integraciones. El ejemplo desactiva los errores de certificado del navegador para que la interceptación HTTPS no se bloquee por el certificado generado localmente por Burp.<sup>[[6]](#references)[[8]](#references)</sup>

## Automatización del navegador compatible con proxy (OpenBurp)

La conexión MCP de Burp y la ruta del navegador interceptado son flujos de datos independientes. El servicio MCP expone las herramientas de Burp en `127.0.0.1:9876`, mientras que una instancia dedicada de Chromium envía su tráfico HTTP(S) a través del proxy de Burp en `127.0.0.1:8080`. Por tanto, las solicitudes generadas directamente por una herramienta MCP pueden no aparecer en **Proxy > HTTP history**; usa el navegador con proxy siempre que la solicitud o respuesta deba poder observarse, editarse o conservarse como evidencia.<sup>[[2]](#references)[[9]](#references)</sup>

Un cliente compatible con SSE puede registrar Burp directamente. En cambio, un cliente que solo admite stdio puede iniciar el JAR del proxy de PortSwigger. En ambos casos, registra un segundo MCP de control del navegador y configúralo para que use el Chromium integrado de Burp (`BURP_CHROMIUM` es una ruta a un ejecutable local):<sup>[[9]](#references)</sup>

```bash
# Claude Code: direct SSE plus a proxied browser
claude mcp add -s project -t sse burpsuite http://127.0.0.1:9876/
claude mcp add -s project -t stdio chrome-devtools -- chrome-devtools-mcp \
  --executablePath "$BURP_CHROMIUM" --proxy-server=http://127.0.0.1:8080 \
  --accept-insecure-certs --isolated

# Codex: SSE-to-stdio bridge plus a proxied browser
codex mcp add burp -- /path/to/java -jar /path/to/mcp-proxy-all.jar \
  --sse-url http://127.0.0.1:9876
codex mcp add burp-browser -- npx -y @playwright/mcp@latest \
  --executable-path "$BURP_CHROMIUM" --proxy-server=http://127.0.0.1:8080 \
  --ignore-https-errors --isolated
```

La flag TLS-bypass tolera los certificados generados por el proxy de interceptación, mientras que `--isolated` impide que la evaluación reutilice el perfil normal del navegador del operador. El aislamiento protege el estado del perfil, pero **no es un sandbox de seguridad**: el controlador aún puede acceder a las sesiones autenticadas abiertas en ese navegador de prueba, y Burp MCP puede exponer solicitudes, respuestas y configuración sensibles.<sup>[[9]](#references)</sup>

Prueba el listener SSE de forma independiente antes de depurar el puente del cliente:<sup>[[9]](#references)</sup>

```bash
curl -i --max-time 3 http://127.0.0.1:9876/
```

Un listener activo devuelve `Content-Type: text/event-stream`. Es normal que se produzca un timeout después de los encabezados, ya que una secuencia SSE permanece abierta para recibir eventos futuros. Si el cliente sigue fallando, confirma la ruta configurada en la extensión: PortSwigger indica que el endpoint puede ser la ruta raíz o `/sse`, según el cliente y la configuración de la extensión.<sup>[[9]](#references)[[7]](#references)</sup>

## Uso de distintos clientes

### Codex CLI

- Configura `~/.codex/config.toml` como se indicó arriba.
- Ejecuta `codex` y luego `/mcp` para verificar la lista de herramientas de Burp.

### Gemini CLI

El repositorio **burp-mcp-agents** proporciona helpers de lanzamiento:<sup>[[4]](#references)</sup>

```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```

### Ollama (local)

Usa el asistente de inicio proporcionado y selecciona un modelo local:

```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```

Ejemplos de modelos locales y necesidades aproximadas de VRAM:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## Reproducción y validación basadas en evidencia

No permitas que el agente trate una explicación plausible o una respuesta intermedia como prueba. Usa solicitudes y respuestas de Burp, así como el estado del navegador observado de forma independiente, para que cada prueba pueda refutarse.<sup>[[8]](#references)</sup>

1. Guarda un par de solicitud/respuesta de referencia e identifica el componente exacto controlado por el atacante.
2. Para comparar autorizaciones, captura el mismo flujo de trabajo de forma independiente con ambas cuentas antes de modificar identificadores, cookies o tokens.
3. Antes de reproducir una modificación, registra la hipótesis, la ubicación de la evidencia, la señal esperada y el resultado que la refutaría.
4. Modifica un componente a la vez, conserva el par resultante y etiqueta por separado las observaciones directas y las inferencias.
5. Registra cada candidato como `open`, `blocked`, `rejected` o `confirmed`; vuelve a examinarlo solo cuando nueva evidencia cambie el mecanismo o un requisito previo.
6. Confirma el control del atacante, la accesibilidad, la repetibilidad, la elusión de restricciones, el impacto y el estado final de la aplicación. Una redirección o una llamada exitosa a una herramienta no son pruebas si el cambio de estado alegado ocurre en una etapa posterior.

Mantén los detalles de explotación en la página de la técnica pertinente. Por ejemplo, los candidatos relacionados con mensajes del navegador corresponden a [PostMessage Vulnerabilities](../pentesting-web/postmessage-vulnerabilities/README.md), mientras que el comportamiento de selección de claves de tokens corresponde a [JWT Vulnerabilities](../pentesting-web/hacking-jwt-json-web-tokens.md).<sup>[[8]](#references)</sup>

Un registro compacto de hipótesis evita que agentes paralelos repitan la misma línea de investigación tentadora:<sup>[[8]](#references)</sup>

```yaml
status: open
hypothesis: "cross-account object access ignores ownership"
evidence: ["requests/user-a.txt", "requests/user-b.txt"]
next_test: "change only the object ID in user A's request"
expected_signal: "user B's object is returned"
falsifier: "server rejects it or returns only user A's object"
```

## Validación out-of-band dirigida con Burp MCP

Burp Suite Professional expone `generate_collaborator_payload` y `get_collaborator_interactions` mediante la extensión oficial de MCP. Combínalos con `get_proxy_http_history_regex` y una única repetición con `send_http1_request` para probar una posible solicitud de URL del lado del servidor sin escanear todo el objetivo. Es posible que Burp requiera aprobación por separado para leer el historial y enviar una solicitud.<sup>[[2]](#references)[[10]](#references)</sup>

1. Filtra el historial para encontrar una solicitud candidata que contenga una URL, por ejemplo, una que incluya `url=`, `webhook` o `callback`. Guarda la solicitud y la respuesta originales. La herramienta de historial acepta `regex`, `count` y `offset`; pagina los resultados en lugar de pedirle al modelo que inspeccione todas las entradas.<sup>[[10]](#references)</sup>
2. Genera un payload nuevo de Collaborator y conserva el **ID del payload** que devuelve. Repite la solicitud capturada al mismo host y puerto, cambiando únicamente la URL candidata por una URL HTTPS bajo ese dominio del payload. Para `send_http1_request`, pasa la solicitud HTTP/1.1 completa como `content`, junto con `targetHostname`, `targetPort` y `usesHttps`; los campos de destino identifican la **aplicación**, no el host de Collaborator.<sup>[[10]](#references)</sup>
3. Consulta periódicamente `get_collaborator_interactions` con ese ID del payload y correlaciona la hora de la interacción con la repetición. Una interacción HTTP confirma que se realizó una solicitud, mientras que una interacción DNS solo muestra que se resolvió el dominio, no que se completara una solicitud HTTP. Revisa el origen de la interacción y los encabezados de la solicitud para distinguir el tráfico saliente del servidor de la carga desde el navegador; luego repite la prueba con un payload nuevo para descartar tráfico no relacionado.<sup>[[10]](#references)[[11]](#references)</sup>

La herramienta de solicitudes de MCP devuelve directamente la respuesta y no necesariamente la añade al **Proxy > HTTP history**. Conserva el resultado de la solicitud y la respuesta, o usa el navegador con proxy o Repeater para obtener una evidencia respaldada por el historial. Para seleccionar payloads de SSRF y realizar pruebas posteriores, consulta el [capítulo de SSRF](../pentesting-web/ssrf-server-side-request-forgery/) en lugar de considerar una callback out-of-band como prueba de impacto en la red interna. Para probar el propio servidor MCP, consulta [pruebas de servidores MCP](AI-MCP-Servers.md#remote-mcp-server-testing-workflow).<sup>[[7]](#references)[[11]](#references)</sup>

## Conjunto de prompts para la revisión pasiva

El repo **burp-mcp-agents** incluye plantillas de prompts para el análisis de tráfico de Burp basado en evidencias:<sup>[[4]](#references)</sup>

- `passive_hunter.md`: detección pasiva amplia de vulnerabilidades.
- `idor_hunter.md`: discrepancias de IDOR/BOLA/objetos/tenants y autenticación.
- `auth_flow_mapper.md`: compara rutas autenticadas y no autenticadas.
- `ssrf_redirect_hunter.md`: candidatos a SSRF/open redirect a partir de parámetros de obtención de URL y cadenas de redirección.
- `logic_flaw_hunter.md`: fallos lógicos de varios pasos.
- `session_scope_hunter.md`: uso indebido del alcance/audiencia de tokens.
- `rate_limit_abuse_hunter.md`: brechas de limitación de solicitudes/abuso.
- `report_writer.md`: informes centrados en evidencias.

## Etiquetado opcional para atribución

Para etiquetar el tráfico de Burp/LLM en los logs, añade una reescritura de encabezado (proxy o Burp Match/Replace):<sup>[[1]](#references)</sup>

```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```

## Notas de seguridad

- Prefiere **modelos locales** cuando el tráfico contiene datos sensibles.
- Comparte solo la evidencia mínima necesaria para un hallazgo.
- Considera Burp la fuente de verdad; usa el modelo para **análisis e informes**, no para escanear.

## Burp AI Agent (triage asistido por IA + herramientas MCP)

**Burp AI Agent** es una extensión de Burp que combina LLM locales o en la nube con análisis pasivo/activo (62 clases de vulnerabilidades) y expone más de 53 herramientas MCP para que clientes MCP externos puedan orquestar Burp.<sup>[[5]](#references)</sup> Aspectos destacados:

- **Triage desde el menú contextual**: captura tráfico mediante Proxy, abre **Proxy > HTTP History**, haz clic derecho en una solicitud → **Extensions > Burp AI Agent > Analyze this request** para iniciar un chat de IA asociado a esa solicitud/respuesta.
- **Backends** (seleccionables por perfil):
  - HTTP local: **Ollama**, **LM Studio**.
  - HTTP remoto: endpoint **compatible con OpenAI** (URL base + nombre del modelo).
  - CLI en la nube: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` o `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (inicio de sesión específico del proveedor).
- **Perfiles del agente**: las plantillas de prompts se instalan automáticamente en `~/.burp-ai-agent/AGENTS/`; coloca archivos `*.md` adicionales ahí para agregar comportamientos personalizados de análisis/escaneo.
- **Servidor MCP**: actívalo en **Settings > MCP Server** para exponer operaciones de Burp a cualquier cliente MCP (más de 53 herramientas). Claude Desktop puede conectarse al servidor editando `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) o `%APPDATA%\Claude\claude_desktop_config.json` (Windows).
- **Controles de privacidad**: STRICT / BALANCED / OFF redactan datos sensibles de las solicitudes antes de enviarlos a modelos remotos; prefiere backends locales cuando manejes secretos.
- **Registro de auditoría**: registros JSONL con hash SHA-256 de integridad por entrada para una trazabilidad de las acciones de IA/MCP que evidencie manipulaciones.
- **Compilación/carga**: descarga el JAR de la versión o compílalo con Java 21:

```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```

Precauciones operativas: los backends en la nube pueden exfiltrar cookies de sesión/PII a menos que se aplique el modo de privacidad; la exposición de MCP permite la orquestación remota de Burp, así que restringe el acceso a agentes de confianza y supervisa el registro de auditoría con hash de integridad.



## References

- [1] [Integración de Burp MCP + Codex CLI y solución para el handshake de Caddy](https://pentestbook.six2dez.com/others/burp)
- [2] [BApp de Burp MCP Server](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [Problema de validación estricta de Origin/header en PortSwigger MCP server](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Agentes de Burp MCP (workflows, launchers, paquete de prompts)](https://github.com/six2dez/burp-mcp-agents)
- [5] [Agente de Burp AI](https://github.com/six2dez/burp-ai-agent)
- [6] [MCP de Microsoft Playwright](https://github.com/microsoft/playwright-mcp)
- [7] [PortSwigger Burp Suite MCP Server](https://github.com/PortSwigger/mcp-server)
- [8] [Cómo usar Codex para investigar Bug Bounty: explorar ampliamente, validar rigurosamente](https://www.yeswehack.com/learn-bug-bounty/llm-series-codex)
- [9] [OpenBurp: orquestación de Burp Suite para Claude Code y Codex](https://github.com/luispacheco22/OpenBurp)
- [10] [Implementaciones y parámetros de las herramientas de PortSwigger MCP Server](https://github.com/PortSwigger/mcp-server/blob/main/src/main/kotlin/net/portswigger/mcp/tools/Tools.kt)
- [11] [PortSwigger Web Security Academy - Vulnerabilidades SSRF ciegas](https://portswigger.net/web-security/ssrf/blind)
{{#include ../banners/hacktricks-training.md}}
