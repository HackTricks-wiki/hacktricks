# Burp MCP: Revisão de tráfego assistida por LLM

{{#include ../banners/hacktricks-training.md}}

## Visão geral

A extensão **MCP Server** do Burp pode expor tráfego HTTP(S) interceptado para clientes LLM compatíveis com MCP, permitindo que eles **analisem requests/responses reais** para descoberta passiva de vulnerabilidades e elaboração de relatórios. A intenção é uma revisão baseada em evidências (sem fuzzing ou blind scanning), mantendo o Burp como fonte de verdade.

## Arquitetura

- **Burp MCP Server (BApp)** escuta em `127.0.0.1:9876` e expõe o tráfego interceptado via MCP.
- **MCP proxy JAR** faz ponte entre stdio (lado cliente) e o endpoint SSE do MCP do Burp.
- **Optional local reverse proxy** (Caddy) normaliza cabeçalhos para verificações estritas do handshake MCP.
- **Clients/backends**: Codex CLI (cloud), Gemini CLI (cloud), or Ollama (local).

## Configuração

### 1) Instalar Burp MCP Server

Instale **MCP Server** a partir do Burp BApp Store e verifique que está escutando em `127.0.0.1:9876`.

### 2) Extrair o proxy JAR

Na aba MCP Server, clique em **Extract server proxy jar** e salve `mcp-proxy.jar`.

### 3) Configurar um cliente MCP (exemplo Codex)

Aponte o cliente para o proxy JAR e para o endpoint SSE do Burp:
```toml
# ~/.codex/config.toml
[mcp_servers.burp]
command = "java"
args = ["-jar", "/absolute/path/to/mcp-proxy.jar", "--sse-url", "http://127.0.0.1:19876"]
```
Preciso do conteúdo do arquivo src/AI/AI-Burp-MCP.md para fazer a tradução. Por favor cole aqui o conteúdo exato.

Além disso, confirme o que quer dizer com "run Codex": 
- quer que eu execute o modelo Codex (não tenho acesso para executar modelos externos), ou 
- deseja que eu simule/ gere a saída que o Codex produziria (posso gerar uma saída equivalente aqui)?

Depois que você mandar o arquivo e confirmar, eu:
1) traduzo o texto relevante para português mantendo exatamente a mesma sintaxe Markdown/HTML e sem traduzir código, nomes técnicos, links ou tags conforme suas instruções;  
2) gero a lista de MCP tools conforme o conteúdo (ou, se preferir, forneço uma lista típica de MCP tools usada com Burp/ambientes similares).
```bash
codex
# inside Codex: /mcp
```
### 4) Corrija validação rígida de Origin/header com Caddy (se necessário)

Se o MCP handshake falhar devido a verificações rígidas de `Origin` ou headers extras, use um reverse proxy local para normalizar headers (isso corresponde à solução alternativa para o problema de validação rígida do Burp MCP).
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

- Configure `~/.codex/config.toml` conforme acima.
- Execute `codex`, depois `/mcp` para verificar a lista de ferramentas do Burp.

### Gemini CLI

O repositório **burp-mcp-agents** fornece scripts auxiliares de lançamento:
```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```
### Ollama (local)

Use o helper launcher fornecido e selecione um modelo local:
```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```
Example local models and approximate VRAM needs:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## Pacote de prompts para revisão passiva

O repositório **burp-mcp-agents** inclui templates de prompt para análise orientada por evidências do tráfego do Burp:

- `passive_hunter.md`: detecção passiva ampla de vulnerabilidades.
- `idor_hunter.md`: IDOR/BOLA/object/tenant drift e incompatibilidades de auth.
- `auth_flow_mapper.md`: comparar caminhos autenticados vs não autenticados.
- `ssrf_redirect_hunter.md`: candidatos a SSRF/open-redirect a partir de parâmetros de URL de fetch/cadeias de redirecionamento.
- `logic_flaw_hunter.md`: falhas lógicas multi-etapa.
- `session_scope_hunter.md`: uso indevido de token audience/scope.
- `rate_limit_abuse_hunter.md`: lacunas de throttling/abuso.
- `report_writer.md`: relatórios com foco em evidências.

## Marcação de atribuição opcional

Para marcar o tráfego Burp/LLM nos logs, adicione uma reescrita de cabeçalho (proxy ou Burp Match/Replace):
```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```
## Notas de segurança

- Prefira **modelos locais** quando o tráfego contiver dados sensíveis.
- Compartilhe apenas as evidências mínimas necessárias para uma descoberta.
- Mantenha o Burp como a fonte da verdade; use o modelo para **análise e relatórios**, não para scanning.

## Referências

- [Burp MCP + Codex CLI integration and Caddy handshake fix](https://pentestbook.six2dez.com/others/burp)
- [Burp MCP Agents (workflows, launchers, prompt pack)](https://github.com/six2dez/burp-mcp-agents)
- [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [PortSwigger MCP server strict Origin/header validation issue](https://github.com/PortSwigger/mcp-server/issues/34)

{{#include ../banners/hacktricks-training.md}}
