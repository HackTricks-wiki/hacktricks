# Burp MCP: revisión de tráfico asistida por LLM

{{#include ../banners/hacktricks-training.md}}

## Descripción general

La extensión **MCP Server** de Burp puede exponer tráfico HTTP(S) interceptado a clientes LLM compatibles con MCP, permitiéndoles **razonar sobre solicitudes/respuestas reales** para el descubrimiento pasivo de vulnerabilidades y la redacción de informes. El objetivo es realizar una revisión basada en evidencias (sin fuzzing ni escaneos a ciegas), manteniendo Burp como fuente de verdad.

## Arquitectura

- **Burp MCP Server (BApp)** escucha en `127.0.0.1:9876` y expone el tráfico interceptado mediante MCP.<sup>[[1]](#references)[[2]](#references)</sup>
- **MCP proxy JAR** conecta stdio (lado del cliente) con el endpoint MCP SSE de Burp.
- **Reverse proxy local opcional** (Caddy) normaliza los headers para las comprobaciones estrictas del handshake de MCP.
- **Clientes/backends**: Codex CLI (cloud), Gemini CLI (cloud) u Ollama (local).

## Configuración

### 1) Instalar Burp MCP Server

Instala **MCP Server** desde la Burp BApp Store y verifica que esté escuchando en `127.0.0.1:9876`.<sup>[[1]](#references)[[2]](#references)</sup>

### 2) Extraer el proxy JAR

En la pestaña MCP Server, haz clic en **Extract server proxy jar** y guarda `mcp-proxy.jar`.

### 3) Configurar un cliente MCP (ejemplo con Codex)

Indica al cliente el proxy JAR y el endpoint SSE de Burp:
```toml
# ~/.codex/config.toml
[mcp_servers.burp]
command = "java"
args = ["-jar", "/absolute/path/to/mcp-proxy.jar", "--sse-url", "http://127.0.0.1:19876"]
```
Luego ejecuta Codex y lista las herramientas MCP:
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
Inicia el proxy y el cliente:
```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```
## Uso de diferentes clientes

### Codex CLI

- Configura `~/.codex/config.toml` como se indicó anteriormente.
- Ejecuta `codex` y, después, `/mcp` para verificar la lista de herramientas de Burp.

### Gemini CLI

El repositorio **burp-mcp-agents** proporciona helpers de lanzamiento:<sup>[[4]](#references)</sup>
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

## Prompt pack para revisión pasiva

El repo **burp-mcp-agents** incluye plantillas de prompts para el análisis basado en evidencias del tráfico de Burp:<sup>[[4]](#references)</sup>

- `passive_hunter.md`: detección pasiva amplia de vulnerabilidades.
- `idor_hunter.md`: IDOR/BOLA, desviaciones de object/tenant e incompatibilidades de auth.
- `auth_flow_mapper.md`: comparación de rutas autenticadas y no autenticadas.
- `ssrf_redirect_hunter.md`: candidatos a SSRF/open-redirect a partir de parámetros de URL fetch/cadenas de redirección.
- `logic_flaw_hunter.md`: fallos lógicos de varios pasos.
- `session_scope_hunter.md`: uso indebido de la audiencia/scope de tokens.
- `rate_limit_abuse_hunter.md`: deficiencias de throttling/abuse.
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
- Mantén Burp como la fuente de verdad; usa el modelo para el **análisis y la generación de informes**, no para el scanning.

## Burp AI Agent (triage asistido por AI + herramientas MCP)

**Burp AI Agent** es una extensión de Burp que combina LLMs locales/cloud con análisis pasivo/activo (62 clases de vulnerabilidades) y expone más de 53 herramientas MCP para que clientes MCP externos puedan orquestar Burp.<sup>[[5]](#references)</sup> Aspectos destacados:

- **Triage desde el menú contextual**: captura tráfico mediante Proxy, abre **Proxy > HTTP History**, haz clic derecho en una request → **Extensions > Burp AI Agent > Analyze this request** para iniciar un chat de AI vinculado a esa request/response.
- **Backends** (seleccionables por perfil):
- HTTP local: **Ollama**, **LM Studio**.
- HTTP remoto: endpoint compatible con **OpenAI** (base URL + nombre del modelo).
- CLIs cloud: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` o `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (login específico del proveedor).
- **Perfiles de Agent**: las plantillas de prompts se instalan automáticamente en `~/.burp-ai-agent/AGENTS/`; añade archivos `*.md` adicionales allí para incorporar comportamientos personalizados de análisis/scanning.
- **Servidor MCP**: actívalo mediante **Settings > MCP Server** para exponer las operaciones de Burp a cualquier cliente MCP (más de 53 herramientas). Claude Desktop puede apuntar al servidor editando `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) o `%APPDATA%\Claude\claude_desktop_config.json` (Windows).
- **Controles de privacidad**: STRICT / BALANCED / OFF redactan los datos sensibles de las requests antes de enviarlos a modelos remotos; prefiere backends locales al gestionar secretos.
- **Audit logging**: logs JSONL con hashing de integridad SHA-256 por entrada para proporcionar trazabilidad con evidencia de manipulación de las acciones de AI/MCP.
- **Build/load**: descarga el JAR de release o compílalo con Java 21:
```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```
Precauciones operativas: los backends cloud pueden exfiltrar cookies de sesión/PII a menos que se fuerce el modo de privacidad; la exposición de MCP concede orquestación remota de Burp, así que restringe el acceso a agentes de confianza y supervisa el audit log con hash de integridad.

## Referencias

- [1] [Integración de Burp MCP + Codex CLI y corrección del handshake de Caddy](https://pentestbook.six2dez.com/others/burp)
- [2] [BApp de Burp MCP Server](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [Problema de validación estricta de Origin/header en el servidor MCP de PortSwigger](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Agentes de Burp MCP (workflows, launchers, prompt pack)](https://github.com/six2dez/burp-mcp-agents)
- [5] [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)

{{#include ../banners/hacktricks-training.md}}
