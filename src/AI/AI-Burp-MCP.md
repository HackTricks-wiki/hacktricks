# Burp MCP: revisión del tráfico asistida por LLM

{{#include ../banners/hacktricks-training.md}}

## Descripción general

La extensión **MCP Server** de Burp puede exponer tráfico HTTP(S) interceptado a clientes LLM compatibles con MCP, para que puedan **razonar sobre solicitudes/respuestas reales** con el fin de descubrir vulnerabilidades y redactar informes. Mantén Burp como fuente de verdad: utiliza análisis pasivo o repeticiones deliberadas cambiando una sola variable, en lugar de realizar escaneos a ciegas.<sup>[[8]](#references)</sup>

## Arquitectura

- **Burp MCP Server (BApp)** escucha en `127.0.0.1:9876` de forma predeterminada y expone el tráfico interceptado mediante MCP.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- **MCP proxy JAR** conecta stdio (lado del cliente) con el endpoint MCP SSE de Burp.
- **Proxy inverso local opcional** (Caddy) normaliza los headers para las comprobaciones estrictas del handshake de MCP.
- **Clientes/backends**: Codex CLI (cloud), Gemini CLI (cloud) u Ollama (local).

## Configuración

### 1) Instalar Burp MCP Server

Instala **MCP Server** desde Burp BApp Store y verifica que escucha en `127.0.0.1:9876`.<sup>[[1]](#references)[[2]](#references)</sup>

### 2) Extraer el proxy JAR

En la pestaña MCP Server, haz clic en **Extract server proxy jar** y guarda `mcp-proxy-all.jar`.<sup>[[7]](#references)</sup>

### 3) Configurar un cliente MCP (ejemplo con Codex)

Configura el cliente para utilizar el proxy JAR y el endpoint SSE directo de Burp. El proxy incluido es un puente de stdio a SSE; no sustituye al listener de Burp.<sup>[[7]](#references)</sup>
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
Luego ejecuta Codex y lista las herramientas de MCP:
```bash
codex
# inside Codex: /mcp
```
### 4) Corregir la validación estricta de Origin/headers con Caddy (si es necesario)

Si el handshake de MCP falla debido a comprobaciones estrictas de `Origin` o a headers adicionales, utiliza un proxy inverso local para normalizar los headers (esto coincide con la solución alternativa para el problema de validación estricta de Burp MCP).<sup>[[1]](#references)[[3]](#references)</sup>
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
Inicia el proxy y el cliente, y cambia el `--sse-url` configurado a `http://127.0.0.1:19876` solo mientras uses este listener de Caddy:<sup>[[1]](#references)[[3]](#references)</sup>
```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```
### 5) Vincular el estado del navegador con la evidencia del proxy (Playwright MCP)

Configura Playwright MCP para que su navegador use el proxy de Burp. Esto permite al agente correlacionar el estado renderizado del DOM y de accesibilidad con el historial HTTP exacto que lo generó.<sup>[[6]](#references)[[8]](#references)</sup>
```bash
codex mcp add playwright -- npx -y @playwright/mcp@latest \
--proxy-server=http://127.0.0.1:8080 \
--ignore-https-errors
```
Adapta la dirección del listener, reinicia Codex y usa `/mcp` para verificar ambas integraciones. El ejemplo deshabilita los errores de certificado del navegador para que la intercepción HTTPS no sea bloqueada por el certificado generado localmente por Burp.<sup>[[6]](#references)[[8]](#references)</sup>

## Usar distintos clientes

### Codex CLI

- Configura `~/.codex/config.toml` como se indicó anteriormente.
- Ejecuta `codex` y, después, `/mcp` para verificar la lista de herramientas de Burp.

### Gemini CLI

El repositorio **burp-mcp-agents** proporciona ayudantes de lanzamiento:<sup>[[4]](#references)</sup>
```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```
### Ollama (local)

Usa el helper de lanzamiento proporcionado y selecciona un modelo local:
```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```
Ejemplos de modelos locales y necesidades aproximadas de VRAM:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## Reproducción y validación basadas en evidencias

No permitas que el agente trate una explicación plausible o una respuesta intermedia como una prueba. Usa requests/responses de Burp y el estado del navegador observado de forma independiente para que cada prueba pueda falsarse.<sup>[[8]](#references)</sup>

1. Guarda un par de request/response de referencia e identifica el componente exacto controlado por el atacante.
2. Para las comparaciones de autorización, captura el mismo workflow de forma independiente con ambas cuentas antes de modificar identificadores, cookies o tokens.
3. Antes de reproducir una mutación, registra la hipótesis, la ubicación de la evidencia, la señal esperada y el resultado que la refutaría.
4. Modifica un componente cada vez, conserva el par resultante y etiqueta por separado las observaciones directas y las inferencias.
5. Registra cada candidato como `open`, `blocked`, `rejected` o `confirmed`; vuelve a revisarlo solo cuando nueva evidencia cambie el mecanismo o un prerrequisito.
6. Confirma el control del atacante, la alcanzabilidad, la repetibilidad, el bypass de restricciones, el impacto y el estado final de la aplicación. Una redirección o una llamada exitosa a una herramienta no es una prueba si el cambio de estado declarado ocurre downstream.

Mantén los detalles de explotación en la página de la técnica correspondiente. Por ejemplo, los candidatos relacionados con mensajes del navegador pertenecen a [PostMessage Vulnerabilities](../pentesting-web/postmessage-vulnerabilities/README.md), mientras que el comportamiento de selección de claves de tokens pertenece a [JWT Vulnerabilities](../pentesting-web/hacking-jwt-json-web-tokens.md).<sup>[[8]](#references)</sup>

Un registro compacto de hipótesis evita que los agentes paralelos repitan la misma rama atractiva:<sup>[[8]](#references)</sup>
```yaml
status: open
hypothesis: "cross-account object access ignores ownership"
evidence: ["requests/user-a.txt", "requests/user-b.txt"]
next_test: "change only the object ID in user A's request"
expected_signal: "user B's object is returned"
falsifier: "server rejects it or returns only user A's object"
```
## Paquete de prompts para revisión pasiva

El repo **burp-mcp-agents** incluye plantillas de prompts para el análisis basado en evidencias del tráfico de Burp:<sup>[[4]](#references)</sup>

- `passive_hunter.md`: detección pasiva amplia de vulnerabilidades.
- `idor_hunter.md`: IDOR/BOLA, objetos, desviaciones entre tenants y discrepancias de autenticación.
- `auth_flow_mapper.md`: comparación de rutas autenticadas y no autenticadas.
- `ssrf_redirect_hunter.md`: candidatos a SSRF/open-redirect a partir de parámetros de obtención de URL y cadenas de redirección.
- `logic_flaw_hunter.md`: fallos lógicos de varios pasos.
- `session_scope_hunter.md`: uso indebido de la audiencia o el scope de los tokens.
- `rate_limit_abuse_hunter.md`: deficiencias de throttling/abuso.
- `report_writer.md`: generación de informes centrados en evidencias.

## Etiquetado opcional de atribución

Para etiquetar el tráfico de Burp/LLM en los logs, añade una reescritura de header (proxy o Burp Match/Replace):<sup>[[1]](#references)</sup>
```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```
## Notas de seguridad

- Prefiere **modelos locales** cuando el tráfico contenga datos sensibles.
- Comparte únicamente la evidencia mínima necesaria para un hallazgo.
- Mantén Burp como fuente de verdad; utiliza el modelo para el **análisis y la generación de informes**, no para el scanning.

## Burp AI Agent (triage asistido por AI + herramientas MCP)

**Burp AI Agent** es una extensión de Burp que combina LLMs locales/cloud con análisis pasivo/activo (62 clases de vulnerabilidades) y expone más de 53 herramientas MCP para que clientes MCP externos puedan orquestar Burp.<sup>[[5]](#references)</sup> Aspectos destacados:

- **Triage desde el menú contextual**: captura tráfico mediante Proxy, abre **Proxy > HTTP History**, haz clic derecho en una request → **Extensions > Burp AI Agent > Analyze this request** para iniciar un chat de AI asociado a esa request/response.
- **Backends** (seleccionables por perfil):
- HTTP local: **Ollama**, **LM Studio**.
- HTTP remoto: endpoint compatible con **OpenAI** (URL base + nombre del modelo).
- CLIs cloud: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` o `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (login específico del proveedor).
- **Perfiles de agente**: las plantillas de prompts se instalan automáticamente en `~/.burp-ai-agent/AGENTS/`; añade archivos `*.md` adicionales allí para incorporar comportamientos personalizados de análisis/scanning.
- **Servidor MCP**: actívalo mediante **Settings > MCP Server** para exponer las operaciones de Burp a cualquier cliente MCP (más de 53 herramientas). Claude Desktop puede configurarse para apuntar al servidor editando `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) o `%APPDATA%\Claude\claude_desktop_config.json` (Windows).
- **Controles de privacidad**: STRICT / BALANCED / OFF redactan los datos sensibles de las requests antes de enviarlos a modelos remotos; prefiere backends locales al manejar secrets.
- **Registro de auditoría**: logs JSONL con hashing de integridad SHA-256 por entrada para proporcionar trazabilidad de las acciones de AI/MCP con evidencia de manipulación.
- **Compilación/carga**: descarga el JAR de release o compílalo con Java 21:
```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```
Precauciones operativas: los backends cloud pueden exfiltrar cookies de sesión/PII a menos que se fuerce el privacy mode; la exposición de MCP permite la orquestación remota de Burp, así que restringe el acceso a agentes de confianza y supervisa el audit log con hash de integridad.

## References

- [1] [Integración de Burp MCP + Codex CLI y solución del handshake de Caddy](https://pentestbook.six2dez.com/others/burp)
- [2] [BApp de Burp MCP Server](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [Problema de validación estricta de Origin/header en el servidor MCP de PortSwigger](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Agentes de Burp MCP (workflows, launchers, prompt pack)](https://github.com/six2dez/burp-mcp-agents)
- [5] [Agente de IA de Burp](https://github.com/six2dez/burp-ai-agent)
- [6] [Microsoft Playwright MCP](https://github.com/microsoft/playwright-mcp)
- [7] [Servidor MCP de PortSwigger Burp Suite](https://github.com/PortSwigger/mcp-server)
- [8] [Cómo usar Codex para la investigación de Bug Bounty: explorar ampliamente y validar rigurosamente](https://www.yeswehack.com/learn-bug-bounty/llm-series-codex)
{{#include ../banners/hacktricks-training.md}}
