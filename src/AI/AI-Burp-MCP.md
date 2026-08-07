# Burp MCP: revisão de tráfego assistida por LLM

{{#include ../banners/hacktricks-training.md}}

## Visão geral

A extensão **MCP Server** do Burp pode expor tráfego HTTP(S) interceptado para clientes LLM compatíveis com MCP, permitindo que eles **raciocinem sobre requests/responses reais** para descoberta passiva de vulnerabilidades e elaboração de relatórios. A intenção é realizar uma revisão orientada por evidências (sem fuzzing ou scanning cego), mantendo o Burp como fonte de verdade.

## Arquitetura

- O **Burp MCP Server (BApp)** escuta em `127.0.0.1:9876` e expõe o tráfego interceptado via MCP.<sup>[[1]](#references)[[2]](#references)</sup>
- O **MCP proxy JAR** faz a ponte entre stdio (lado do cliente) e o endpoint MCP SSE do Burp.
- **Reverse proxy local opcional** (Caddy) normaliza headers para verificações rigorosas do handshake MCP.
- **Clientes/backends**: Codex CLI (cloud), Gemini CLI (cloud) ou Ollama (local).

## Configuração

### 1) Instalar o Burp MCP Server

Instale o **MCP Server** pela Burp BApp Store e verifique se ele está escutando em `127.0.0.1:9876`.<sup>[[1]](#references)[[2]](#references)</sup>

### 2) Extrair o proxy JAR

Na aba MCP Server, clique em **Extract server proxy jar** e salve `mcp-proxy.jar`.

### 3) Configurar um cliente MCP (exemplo com Codex)

Aponte o cliente para o proxy JAR e para o endpoint SSE do Burp:
```toml
# ~/.codex/config.toml
[mcp_servers.burp]
command = "java"
args = ["-jar", "/absolute/path/to/mcp-proxy.jar", "--sse-url", "http://127.0.0.1:19876"]
```
Em seguida, execute o Codex e liste as ferramentas MCP:
```bash
codex
# inside Codex: /mcp
```
### 4) Corrija a validação estrita de Origin/headers com Caddy (se necessário)

Se o handshake do MCP falhar devido a verificações estritas de `Origin` ou headers adicionais, use um proxy reverso local para normalizar os headers (isso corresponde à solução alternativa para o problema de validação estrita do Burp MCP).<sup>[[1]](#references)[[3]](#references)</sup>
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
Inicie o proxy e o cliente:
```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```
## Usando diferentes clientes

### Codex CLI

- Configure `~/.codex/config.toml` conforme descrito acima.
- Execute `codex` e, em seguida, `/mcp` para verificar a lista de ferramentas do Burp.

### Gemini CLI

O repositório **burp-mcp-agents** fornece auxiliares de inicialização:<sup>[[4]](#references)</sup>
```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```
### Ollama (local)

Use o helper de inicialização fornecido e selecione um modelo local:
```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```
Exemplos de modelos locais e necessidades aproximadas de VRAM:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## Prompt pack para revisão passiva

O repo **burp-mcp-agents** inclui templates de prompt para análise orientada por evidências do tráfego do Burp:<sup>[[4]](#references)</sup>

- `passive_hunter.md`: descoberta ampla de vulnerabilidades passivas.
- `idor_hunter.md`: IDOR/BOLA, divergências de object/tenant e incompatibilidades de auth.
- `auth_flow_mapper.md`: comparação entre caminhos autenticados e não autenticados.
- `ssrf_redirect_hunter.md`: candidatos a SSRF/open-redirect a partir de params de fetch de URL/cadeias de redirect.
- `logic_flaw_hunter.md`: falhas lógicas de múltiplas etapas.
- `session_scope_hunter.md`: uso indevido de audience/scope de tokens.
- `rate_limit_abuse_hunter.md`: falhas de throttling/abuso.
- `report_writer.md`: elaboração de relatórios focados em evidências.

## Tagging opcional de atribuição

Para marcar o tráfego do Burp/LLM nos logs, adicione um header rewrite (proxy ou Burp Match/Replace):<sup>[[1]](#references)</sup>
```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```
## Notas de segurança

- Prefira **modelos locais** quando o tráfego contiver dados sensíveis.
- Compartilhe apenas as evidências mínimas necessárias para um achado.
- Mantenha o Burp como fonte de verdade; use o modelo para **análise e geração de relatórios**, não para scanning.

## Burp AI Agent (triagem assistida por AI + ferramentas MCP)

**Burp AI Agent** é uma extensão do Burp que conecta LLMs locais/cloud à análise passiva/ativa (62 classes de vulnerabilidade) e expõe mais de 53 ferramentas MCP para que clientes MCP externos possam orquestrar o Burp.<sup>[[5]](#references)</sup> Destaques:

- **Triagem pelo menu de contexto**: capture tráfego via Proxy, abra **Proxy > HTTP History**, clique com o botão direito em uma requisição → **Extensions > Burp AI Agent > Analyze this request** para iniciar um chat de AI vinculado a essa requisição/resposta.
- **Backends** (selecionáveis por perfil):
- HTTP local: **Ollama**, **LM Studio**.
- HTTP remoto: endpoint compatível com **OpenAI** (URL base + nome do modelo).
- CLIs cloud: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` ou `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (login específico do provider).
- **Perfis de Agent**: templates de prompt instalados automaticamente em `~/.burp-ai-agent/AGENTS/`; adicione arquivos `*.md` extras nesse diretório para incluir comportamentos personalizados de análise/scanning.
- **Servidor MCP**: habilite via **Settings > MCP Server** para expor operações do Burp a qualquer cliente MCP (mais de 53 ferramentas). O Claude Desktop pode ser apontado para o servidor editando `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) ou `%APPDATA%\Claude\claude_desktop_config.json` (Windows).
- **Controles de privacidade**: STRICT / BALANCED / OFF redigem dados sensíveis das requisições antes de enviá-los a modelos remotos; prefira backends locais ao lidar com secrets.
- **Logging de auditoria**: logs JSONL com hashing de integridade SHA-256 por entrada para garantir rastreabilidade evidente de adulteração das ações de AI/MCP.
- **Build/load**: baixe o JAR da release ou faça o build com Java 21:
```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```
Cuidados operacionais: cloud backends podem exfiltrar session cookies/PII, a menos que o privacy mode seja aplicado; a exposição do MCP concede orquestração remota do Burp, portanto restrinja o acesso a agentes confiáveis e monitore o audit log com hash de integridade.

## Referências

- [1] [Integração do Burp MCP + Codex CLI e correção do handshake do Caddy](https://pentestbook.six2dez.com/others/burp)
- [2] [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [Problema de validação estrita de Origin/header no servidor MCP do PortSwigger](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Agentes do Burp MCP (workflows, launchers, prompt pack)](https://github.com/six2dez/burp-mcp-agents)
- [5] [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)

{{#include ../banners/hacktricks-training.md}}
