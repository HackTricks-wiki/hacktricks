# Burp MCP: Revisión de tráfico asistida por LLM

{{#include ../banners/hacktricks-training.md}}

## Visión general

La extensión de Burp **MCP Server** puede exponer el tráfico HTTP(S) interceptado a clientes LLM compatibles con MCP para que puedan **razonar sobre solicitudes/respuestas reales** para el descubrimiento pasivo de vulnerabilidades y la redacción de informes. La intención es una revisión basada en evidencia (no fuzzing ni blind scanning), manteniendo a Burp como la fuente de la verdad.

## Arquitectura

- **Burp MCP Server (BApp)** escucha en `127.0.0.1:9876` y expone el tráfico interceptado vía MCP.
- **MCP proxy JAR** enlaza stdio (lado cliente) con el endpoint MCP SSE de Burp.
- **Proxy reverso local opcional** (Caddy) normaliza headers para comprobaciones estrictas del handshake MCP.
- **Clientes/backends**: Codex CLI (cloud), Gemini CLI (cloud), o Ollama (local).

## Configuración

### 1) Instalar Burp MCP Server

Instala **MCP Server** desde el Burp BApp Store y verifica que esté escuchando en `127.0.0.1:9876`.

### 2) Extraer el proxy JAR

En la pestaña MCP Server, haz clic en **Extract server proxy jar** y guarda `mcp-proxy.jar`.

### 3) Configurar un cliente MCP (ejemplo: Codex)

Apunta el cliente al proxy JAR y al endpoint SSE de Burp:
```toml
# ~/.codex/config.toml
[mcp_servers.burp]
command = "java"
args = ["-jar", "/absolute/path/to/mcp-proxy.jar", "--sse-url", "http://127.0.0.1:19876"]
```
No tengo el contenido de src/AI/AI-Burp-MCP.md. Por favor pega aquí el texto del archivo que quieres traducir.

Además, ¿qué entiendes por "run Codex"? ¿Quieres que use la API de OpenAI Codex, que simule salida de Codex, o que ejecute un script local? Indica también si quieres que, tras la traducción, liste las MCP tools encontradas dentro del mismo archivo.
```bash
codex
# inside Codex: /mcp
```
### 4) Corregir la validación estricta de `Origin`/header con Caddy (si es necesario)

Si el MCP handshake falla debido a comprobaciones estrictas de `Origin` o headers adicionales, utiliza un proxy inverso local para normalizar los headers (esto coincide con la solución alternativa para el problema de validación estricta de MCP en Burp).
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
## Usando diferentes clientes

### Codex CLI

- Configura `~/.codex/config.toml` como se indicó arriba.
- Ejecuta `codex`, luego `/mcp` para verificar la lista de Burp tools.

### Gemini CLI

El repositorio **burp-mcp-agents** proporciona launcher helpers:
```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```
### Ollama (local)

Usa el launcher helper provisto y selecciona un modelo local:
```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```
Ejemplos de modelos locales y necesidades aproximadas de VRAM:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## Pack de prompts para revisión pasiva

El repo **burp-mcp-agents** incluye plantillas de prompts para análisis orientado a evidencias del tráfico de Burp:

- `passive_hunter.md`: detección pasiva amplia de vulnerabilidades.
- `idor_hunter.md`: IDOR/BOLA/object/tenant drift y auth mismatches.
- `auth_flow_mapper.md`: comparar rutas autenticadas vs no autenticadas.
- `ssrf_redirect_hunter.md`: candidatos SSRF/open-redirect a partir de parámetros de fetch de URL/cadenas de redirección.
- `logic_flaw_hunter.md`: fallos lógicos de múltiples pasos.
- `session_scope_hunter.md`: uso indebido de token audience/scope.
- `rate_limit_abuse_hunter.md`: brechas en throttling/abuse.
- `report_writer.md`: redacción de reportes centrada en evidencias.

## Etiquetado de atribución opcional

Para etiquetar el tráfico Burp/LLM en logs, añade una reescritura de header (proxy o Burp Match/Replace):
```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```
## Notas de seguridad

- Prefiere **modelos locales** cuando el tráfico contenga datos sensibles.
- Comparte solo la evidencia mínima necesaria para un hallazgo.
- Mantén a Burp como la fuente de la verdad; usa el modelo para **análisis e informes**, no para escaneo.

## Referencias

- [Burp MCP + Codex CLI integration and Caddy handshake fix](https://pentestbook.six2dez.com/others/burp)
- [Burp MCP Agents (workflows, launchers, prompt pack)](https://github.com/six2dez/burp-mcp-agents)
- [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [PortSwigger MCP server strict Origin/header validation issue](https://github.com/PortSwigger/mcp-server/issues/34)

{{#include ../banners/hacktricks-training.md}}
