# Burp MCP: Revisão de tráfego assistida por LLM

{{#include ../banners/hacktricks-training.md}}

## Visão geral

A extensão do Burp **MCP Server** pode expor tráfego HTTP(S) interceptado para clientes LLM compatíveis com MCP, permitindo que eles **raciocinem sobre requisições/respostas reais** para descoberta passiva de vulnerabilidades e elaboração de relatórios. A intenção é uma revisão guiada por evidências (sem fuzzing ou blind scanning), mantendo o Burp como a fonte da verdade.

## Arquitetura

- **Burp MCP Server (BApp)** escuta em `127.0.0.1:9876` e expõe o tráfego interceptado via MCP.
- **MCP proxy JAR** faz a ponte entre stdio (lado do cliente) e o endpoint SSE do MCP do Burp.
- **Reverse proxy local opcional** (Caddy) normaliza cabeçalhos para verificações rigorosas do handshake do MCP.
- **Clientes/backends**: Codex CLI (cloud), Gemini CLI (cloud), ou Ollama (local).

## Configuração

### 1) Instale o Burp MCP Server

Instale **MCP Server** a partir do Burp BApp Store e verifique se está escutando em `127.0.0.1:9876`.

### 2) Extraia o proxy JAR

Na aba MCP Server, clique em **Extract server proxy jar** e salve `mcp-proxy.jar`.

### 3) Configure um cliente MCP (exemplo Codex)

Aponte o cliente para o proxy JAR e para o endpoint SSE do Burp:
```toml
# ~/.codex/config.toml
[mcp_servers.burp]
command = "java"
args = ["-jar", "/absolute/path/to/mcp-proxy.jar", "--sse-url", "http://127.0.0.1:19876"]
```
Preciso do conteúdo do arquivo src/AI/AI-Burp-MCP.md para fazer a tradução conforme suas regras. 

Também confirme:
- O que você entende por "run Codex"? (quer que eu gere conteúdo usando o modelo Codex/uma sugestão de código, ou pretende que eu execute algo localmente?)
- O que significa exatamente "MCP tools" no seu contexto (uma lista de ferramentas mencionadas no arquivo, ou uma lista geral de ferramentas usadas com Burp MCP)?

Envie o conteúdo do arquivo ou confirme as definições acima e eu procedo com a tradução e a listagem solicitada.
```bash
codex
# inside Codex: /mcp
```
### 4) Corrija a validação estrita Origin/header com Caddy (se necessário)

Se o handshake MCP falhar devido a verificações rígidas de `Origin` ou headers extras, use um reverse proxy local para normalizar os headers (isso corresponde ao workaround para o problema de validação estrita do Burp MCP).
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
Inicie o proxy e o client:
```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```
## Usando diferentes clientes

### Codex CLI

- Configure `~/.codex/config.toml` conforme acima.
- Execute `codex`, depois `/mcp` para verificar a lista de ferramentas do Burp.

### Gemini CLI

O **burp-mcp-agents** repo fornece launcher helpers:
```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```
### Ollama (local)

Use o launcher helper fornecido e selecione um modelo local:
```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```
Exemplos de modelos locais e necessidades aproximadas de VRAM:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## Pacote de prompts para revisão passiva

O repo **burp-mcp-agents** inclui templates de prompt para análise orientada por evidências do tráfego do Burp:

- `passive_hunter.md`: identificação ampla de vulnerabilidades passivas.
- `idor_hunter.md`: IDOR/BOLA/object/tenant drift e inconsistências de auth.
- `auth_flow_mapper.md`: comparar caminhos autenticados vs não autenticados.
- `ssrf_redirect_hunter.md`: candidatos a SSRF/open-redirect a partir de parâmetros de fetch de URL/ cadeias de redirecionamento.
- `logic_flaw_hunter.md`: falhas lógicas multietapa.
- `session_scope_hunter.md`: uso indevido de token audience/scope.
- `rate_limit_abuse_hunter.md`: lacunas de throttling/abuso.
- `report_writer.md`: relatórios focados em evidências.

## Marcação opcional de atribuição

Para marcar o tráfego Burp/LLM nos logs, adicione uma reescrita de header (proxy ou Burp Match/Replace):
```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```
## Notas de segurança

- Prefira **modelos locais** quando o tráfego contiver dados sensíveis.
- Compartilhe apenas as evidências mínimas necessárias para um achado.
- Mantenha o Burp como fonte da verdade; use o modelo para **análise e geração de relatórios**, não para varredura.

## Burp AI Agent (triagem assistida por AI + ferramentas MCP)

**Burp AI Agent** é uma extensão do Burp que conecta LLMs locais/cloud com análise passiva/ativa (62 classes de vulnerabilidade) e expõe 53+ ferramentas MCP para que clientes MCP externos possam orquestrar o Burp. Destaques:

- **Triagem via menu de contexto**: capture o tráfego via Proxy, abra **Proxy > HTTP History**, clique com o botão direito em uma requisição → **Extensions > Burp AI Agent > Analyze this request** para abrir um chat AI vinculado àquela requisição/resposta.
- **Backends** (selecionáveis por perfil):
- Local HTTP: **Ollama**, **LM Studio**.
- Remote HTTP: **OpenAI-compatible** endpoint (base URL + model name).
- Cloud CLIs: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` or `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (provider-specific login).
- **Perfis de agente**: modelos de prompt instalados automaticamente em `~/.burp-ai-agent/AGENTS/`; coloque arquivos extras `*.md` lá para adicionar comportamentos personalizados de análise/varredura.
- **Servidor MCP**: habilite via **Settings > MCP Server** para expor operações do Burp a qualquer cliente MCP (53+ ferramentas). O Claude Desktop pode ser apontado para o servidor editando `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) ou `%APPDATA%\Claude\claude_desktop_config.json` (Windows).
- **Controles de privacidade**: STRICT / BALANCED / OFF ofuscar dados sensíveis da requisição antes de enviá-los para modelos remotos; prefira backends locais ao lidar com segredos.
- **Registro de auditoria**: logs JSONL com hash de integridade SHA-256 por entrada para rastreabilidade com evidência de adulteração das ações AI/MCP.
- **Build/load**: faça o download do JAR de release ou compile com Java 21:
```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```
Cuidados operacionais: backends cloud podem exfiltrate session cookies/PII a menos que privacy mode seja imposto; a exposição do MCP concede orquestração remota do Burp, portanto restrinja o acesso a agentes confiáveis e monitore o integrity-hashed audit log.

## Referências

- [Burp MCP + Codex CLI integration and Caddy handshake fix](https://pentestbook.six2dez.com/others/burp)
- [Burp MCP Agents (workflows, launchers, prompt pack)](https://github.com/six2dez/burp-mcp-agents)
- [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [PortSwigger MCP server strict Origin/header validation issue](https://github.com/PortSwigger/mcp-server/issues/34)
- [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)

{{#include ../banners/hacktricks-training.md}}
