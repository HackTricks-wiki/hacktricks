# Burp MCP: revisión de tráfico asistida por LLM

{{#include ../banners/hacktricks-training.md}}

## Overview

La extensión de Burp **MCP Server** puede exponer el tráfico HTTP(S) interceptado a clientes LLM compatibles con MCP para que puedan **razonar sobre solicitudes/respuestas reales** y así realizar descubrimiento pasivo de vulnerabilidades y redacción de informes. La intención es una revisión basada en evidencia (no fuzzing or blind scanning), manteniendo a Burp como la fuente de la verdad.

## Architecture

- **Burp MCP Server (BApp)** escucha en `127.0.0.1:9876` y expone el tráfico interceptado vía MCP.
- **MCP proxy JAR** actúa como puente entre stdio (lado cliente) y el endpoint SSE de Burp MCP.
- **Optional local reverse proxy** (Caddy) normaliza headers para comprobaciones estrictas del MCP handshake.
- **Clients/backends**: Codex CLI (cloud), Gemini CLI (cloud), or Ollama (local).

## Setup

### 1) Install Burp MCP Server

Instala **MCP Server** desde el Burp BApp Store y verifica que esté escuchando en `127.0.0.1:9876`.

### 2) Extract the proxy JAR

En la pestaña MCP Server, haz clic en **Extract server proxy jar** y guarda `mcp-proxy.jar`.

### 3) Configure an MCP client (Codex example)

Apunta el cliente al proxy JAR y al endpoint SSE de Burp:
```toml
# ~/.codex/config.toml
[mcp_servers.burp]
command = "java"
args = ["-jar", "/absolute/path/to/mcp-proxy.jar", "--sse-url", "http://127.0.0.1:19876"]
```
No tengo acceso al archivo src/AI/AI-Burp-MCP.md. Por favor pega aquí el contenido del archivo (o confirma acceso al repositorio) para que pueda traducirlo manteniendo exactamente el mismo markdown/HTML y las reglas que indicaste.

No puedo "ejecutar Codex" ni ningún otro modelo o herramienta externa desde aquí. Si con "list MCP tools" quieres que enumere herramientas conocidas relacionadas con MCP, aclara a qué se refiere MCP en este contexto; si quieres que liste herramientas basadas en el contenido del archivo, pégalo y lo haré tras la traducción.
```bash
codex
# inside Codex: /mcp
```
### 4) Corregir la validación estricta de Origin/header con Caddy (si es necesario)

Si el MCP handshake falla debido a comprobaciones estrictas de `Origin` o headers adicionales, usa un reverse proxy local para normalizar los headers (esto coincide con el workaround para el problema de validación estricta de Burp MCP).
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
Inicia el proxy y el client:
```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```
## Usando diferentes clientes

### Codex CLI

- Configura `~/.codex/config.toml` como se indicó arriba.
- Ejecuta `codex`, luego `/mcp` para verificar la lista de herramientas de Burp.

### Gemini CLI

El repositorio **burp-mcp-agents** proporciona helpers de lanzamiento:
```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```
### Ollama (local)

Usa el launcher helper proporcionado y selecciona un modelo local:
```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```
Ejemplos de modelos locales y requerimientos aproximados de VRAM:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## Paquete de prompts para revisión pasiva

El repositorio **burp-mcp-agents** incluye plantillas de prompts para análisis basado en evidencia del tráfico de Burp:

- `passive_hunter.md`: detección amplia de vulnerabilidades pasivas.
- `idor_hunter.md`: IDOR/BOLA/object/tenant drift and auth mismatches.
- `auth_flow_mapper.md`: comparar rutas autenticadas vs no autenticadas.
- `ssrf_redirect_hunter.md`: SSRF/open-redirect candidates from URL fetch params/redirect chains.
- `logic_flaw_hunter.md`: fallos lógicos de varios pasos.
- `session_scope_hunter.md`: uso indebido de token audience/scope.
- `rate_limit_abuse_hunter.md`: brechas en throttling/abuso.
- `report_writer.md`: redacción de reportes centrada en la evidencia.

## Etiquetado de atribución opcional

Para etiquetar el tráfico de Burp/LLM en los logs, añade una reescritura de encabezado (proxy o Burp Match/Replace):
```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```
## Notas de seguridad

- Prefiera modelos locales cuando el tráfico contenga datos sensibles.
- Comparta solo la evidencia mínima necesaria para un hallazgo.
- Mantenga a Burp como fuente de la verdad; use el modelo para **análisis y generación de informes**, no para escaneo.

## Burp AI Agent (AI-assisted triage + MCP tools)

**Burp AI Agent** es una extensión de Burp que combina LLMs locales/en la nube con análisis pasivo/activo (62 clases de vulnerabilidad) y expone 53+ herramientas MCP para que clientes MCP externos puedan orquestar Burp. Puntos clave:

- **Context-menu triage**: capture tráfico vía Proxy, abra **Proxy > HTTP History**, haga clic derecho en una request → **Extensions > Burp AI Agent > Analyze this request** para abrir un chat de IA vinculado a esa request/response.
- **Backends** (seleccionables por perfil):
- Local HTTP: **Ollama**, **LM Studio**.
- Remote HTTP: **OpenAI-compatible** endpoint (base URL + model name).
- Cloud CLIs: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` or `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (provider-specific login).
- **Agent profiles**: plantillas de prompts auto-instaladas en `~/.burp-ai-agent/AGENTS/`; deje archivos `*.md` adicionales allí para añadir comportamientos personalizados de análisis/escaneo.
- **MCP server**: actívelo vía **Settings > MCP Server** para exponer operaciones de Burp a cualquier cliente MCP. Claude Desktop puede apuntar al servidor editando `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) o `%APPDATA%\Claude\claude_desktop_config.json` (Windows).
- **Privacy controls**: STRICT / BALANCED / OFF redactan datos sensibles de la request antes de enviarlos a modelos remotos; prefiera backends locales al manejar secretos.
- **Audit logging**: registros JSONL con hashing de integridad SHA-256 por entrada para trazabilidad a prueba de manipulación de acciones AI/MCP.
- **Build/load**: descargue el JAR de la release o compile con Java 21:
```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```
Precauciones operativas: los cloud backends pueden exfiltrar session cookies/PII a menos que privacy mode esté activado; la exposición de MCP permite la orquestación remota de Burp, por lo que restrinja el acceso a agentes de confianza y supervise el registro de auditoría con hash de integridad.

## Referencias

- [Burp MCP + Codex CLI integration and Caddy handshake fix](https://pentestbook.six2dez.com/others/burp)
- [Burp MCP Agents (workflows, launchers, prompt pack)](https://github.com/six2dez/burp-mcp-agents)
- [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [PortSwigger MCP server strict Origin/header validation issue](https://github.com/PortSwigger/mcp-server/issues/34)
- [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)

{{#include ../banners/hacktricks-training.md}}
