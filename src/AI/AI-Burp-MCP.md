# Burp MCP: análise de tráfego assistida por LLM

{{#include ../banners/hacktricks-training.md}}

## Visão geral

A extensão **MCP Server** do Burp pode expor tráfego HTTP(S) interceptado a clientes LLM compatíveis com MCP, permitindo que eles **analisem requisições/respostas reais** para descoberta de vulnerabilidades e elaboração de relatórios. Mantenha o Burp como fonte de verdade: use análise passiva ou replays deliberados alterando uma variável por vez, em vez de realizar scanning às cegas.<sup>[[8]](#references)</sup>

## Arquitetura

- O **Burp MCP Server (BApp)** escuta em `127.0.0.1:9876` por padrão e expõe o tráfego interceptado via MCP.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- O **MCP proxy JAR** faz a ponte entre stdio (lado do cliente) e o endpoint MCP SSE do Burp.
- **Reverse proxy local opcional** (Caddy) normaliza os headers para verificações rigorosas do handshake do MCP.
- **Clientes/backends**: Codex CLI (cloud), Gemini CLI (cloud) ou Ollama (local).

## Configuração

### 1) Instalar o Burp MCP Server

Instale o **MCP Server** na Burp BApp Store e verifique se ele está escutando em `127.0.0.1:9876`.<sup>[[1]](#references)[[2]](#references)</sup>

### 2) Extrair o proxy JAR

Na aba MCP Server, clique em **Extract server proxy jar** e salve `mcp-proxy-all.jar`.<sup>[[7]](#references)</sup>

### 3) Configurar um cliente MCP (exemplo com Codex)

Aponte o cliente para o proxy JAR e para o endpoint SSE direto do Burp. O proxy empacotado é uma ponte de stdio para SSE; ele não substitui o listener do Burp.<sup>[[7]](#references)</sup>
```toml
# ~/.codex/config.toml
[mcp_servers.burp]
command = "java"
args = ["-jar", "/absolute/path/to/mcp-proxy-all.jar", "--sse-url", "http://127.0.0.1:9876"]
```
O comando Codex equivalente é:<sup>[[7]](#references)[[8]](#references)</sup>
```bash
codex mcp add burp -- /path/to/java -jar /path/to/mcp-proxy-all.jar \
--sse-url http://127.0.0.1:9876
```
Em seguida, execute o Codex e liste as ferramentas MCP:
```bash
codex
# inside Codex: /mcp
```
### 4) Corrija a validação rigorosa de Origin/headers com Caddy (se necessário)

Se o handshake do MCP falhar devido a verificações rigorosas de `Origin` ou a headers adicionais, use um proxy reverso local para normalizar os headers (isso corresponde à solução alternativa para o problema de validação rigorosa do Burp MCP).<sup>[[1]](#references)[[3]](#references)</sup>
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
Inicie o proxy e o cliente e altere o `--sse-url` configurado para `http://127.0.0.1:19876` somente ao usar este listener do Caddy:<sup>[[1]](#references)[[3]](#references)</sup>
```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```
### 5) Combine o estado do navegador com evidências do proxy (Playwright MCP)

Registre o Playwright MCP para que o navegador use o proxy do Burp. Isso permite que o agente correlacione o estado renderizado do DOM/acessibilidade com o histórico HTTP exato que o produziu.<sup>[[6]](#references)[[8]](#references)</sup>
```bash
codex mcp add playwright -- npx -y @playwright/mcp@latest \
--proxy-server=http://127.0.0.1:8080 \
--ignore-https-errors
```
Adapte o endereço do listener, reinicie o Codex e use `/mcp` para verificar ambas as integrações. O exemplo desativa os erros de certificado do browser para que a interceptação HTTPS não seja bloqueada pelo certificado gerado localmente pelo Burp.<sup>[[6]](#references)[[8]](#references)</sup>

## Usando clientes diferentes

### Codex CLI

- Configure `~/.codex/config.toml` conforme indicado acima.
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

## Replay e validação orientados por evidências

Não permita que o agent trate uma explicação plausível ou uma resposta intermediária como prova. Use requests/responses do Burp e o estado do browser observado independentemente para tornar cada teste falsificável.<sup>[[8]](#references)</sup>

1. Salve um par request/response de baseline e identifique o componente exato controlado pelo attacker.
2. Para comparações de autorização, capture o mesmo workflow independentemente em ambas as contas antes de alterar identificadores, cookies ou tokens.
3. Antes de reproduzir uma mutação, registre a hipótese, a localização da evidência, o sinal esperado e o resultado que a refutaria.
4. Altere um componente por vez, preserve o par resultante e rotule as observações diretas separadamente das inferências.
5. Acompanhe cada candidato como `open`, `blocked`, `rejected` ou `confirmed`; reavalie-o somente quando novas evidências alterarem o mecanismo ou um pré-requisito.
6. Confirme o controle pelo attacker, a alcançabilidade, a repetibilidade, o bypass de restrições, o impacto e o estado final da aplicação. Um redirect ou uma chamada de ferramenta bem-sucedida não é prova se a alteração de estado alegada ocorrer downstream.

Mantenha os detalhes da exploitation na página da técnica relevante. Por exemplo, candidatos relacionados a mensagens do browser pertencem a [PostMessage Vulnerabilities](../pentesting-web/postmessage-vulnerabilities/README.md), enquanto o comportamento de seleção de chaves de token pertence a [JWT Vulnerabilities](../pentesting-web/hacking-jwt-json-web-tokens.md).<sup>[[8]](#references)</sup>

Um registro compacto de hipóteses impede que agents paralelos repitam o mesmo caminho atraente:<sup>[[8]](#references)</sup>
```yaml
status: open
hypothesis: "cross-account object access ignores ownership"
evidence: ["requests/user-a.txt", "requests/user-b.txt"]
next_test: "change only the object ID in user A's request"
expected_signal: "user B's object is returned"
falsifier: "server rejects it or returns only user A's object"
```
## Pacote de prompts para revisão passiva

O repositório **burp-mcp-agents** inclui templates de prompt para análise orientada por evidências do tráfego do Burp:<sup>[[4]](#references)</sup>

- `passive_hunter.md`: identificação ampla de vulnerabilidades passivas.
- `idor_hunter.md`: IDOR/BOLA/desvios de objeto/tenant e incompatibilidades de autenticação.
- `auth_flow_mapper.md`: comparação entre caminhos autenticados e não autenticados.
- `ssrf_redirect_hunter.md`: candidatos a SSRF/open-redirect a partir de parâmetros de busca de URL/cadeias de redirecionamento.
- `logic_flaw_hunter.md`: falhas lógicas de várias etapas.
- `session_scope_hunter.md`: uso indevido de audience/scope de tokens.
- `rate_limit_abuse_hunter.md`: lacunas de throttling/abuso.
- `report_writer.md`: geração de relatórios com foco em evidências.

## Marcação opcional de atribuição

Para marcar o tráfego do Burp/LLM nos logs, adicione uma reescrita de header (proxy ou Burp Match/Replace):<sup>[[1]](#references)</sup>
```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```
## Notas de segurança

- Prefira **modelos locais** quando o tráfego contiver dados sensíveis.
- Compartilhe apenas o mínimo de evidências necessário para um finding.
- Mantenha o Burp como fonte de verdade; use o modelo para **análise e elaboração de relatórios**, não para scanning.

## Burp AI Agent (triagem assistida por AI + ferramentas MCP)

**Burp AI Agent** é uma extensão do Burp que combina LLMs locais/cloud com análise passiva/ativa (62 classes de vulnerabilidades) e expõe mais de 53 ferramentas MCP para que clientes MCP externos possam orquestrar o Burp.<sup>[[5]](#references)</sup> Destaques:

- **Triagem pelo menu de contexto**: capture tráfego via Proxy, abra **Proxy > HTTP History**, clique com o botão direito em uma requisição → **Extensions > Burp AI Agent > Analyze this request** para iniciar um chat de AI vinculado a essa requisição/resposta.
- **Backends** (selecionáveis por profile):
- HTTP local: **Ollama**, **LM Studio**.
- HTTP remoto: endpoint compatível com **OpenAI** (URL base + nome do modelo).
- CLIs de Cloud: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` ou `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (login específico do provider).
- **Agent profiles**: templates de prompt instalados automaticamente em `~/.burp-ai-agent/AGENTS/`; adicione arquivos `*.md` extras nesse diretório para incluir comportamentos personalizados de análise/scanning.
- **Servidor MCP**: habilite em **Settings > MCP Server** para expor operações do Burp a qualquer cliente MCP (mais de 53 ferramentas). O Claude Desktop pode ser apontado para o servidor editando `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) ou `%APPDATA%\Claude\claude_desktop_config.json` (Windows).
- **Controles de privacidade**: STRICT / BALANCED / OFF mascaram dados sensíveis das requisições antes de enviá-los para modelos remotos; prefira backends locais ao lidar com secrets.
- **Logs de auditoria**: logs JSONL com hashing de integridade SHA-256 por entrada para fornecer rastreabilidade à prova de adulteração das ações de AI/MCP.
- **Build/load**: baixe o JAR de release ou compile com Java 21:
```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```
Cautelas operacionais: cloud backends podem exfiltrar cookies de sessão/PII, a menos que o privacy mode seja aplicado; a exposição do MCP concede orquestração remota do Burp, portanto restrinja o acesso a agents confiáveis e monitore o audit log com hash de integridade.

## References

- [1] [Integração do Burp MCP + Codex CLI e correção do handshake do Caddy](https://pentestbook.six2dez.com/others/burp)
- [2] [BApp do Burp MCP Server](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [Problema de validação estrita de Origin/header no MCP server da PortSwigger](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Burp MCP Agents (workflows, launchers, pacote de prompts)](https://github.com/six2dez/burp-mcp-agents)
- [5] [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)
- [6] [Microsoft Playwright MCP](https://github.com/microsoft/playwright-mcp)
- [7] [PortSwigger Burp Suite MCP Server](https://github.com/PortSwigger/mcp-server)
- [8] [Como usar o Codex para pesquisa de Bug Bounty: explorar amplamente, validar rigorosamente](https://www.yeswehack.com/learn-bug-bounty/llm-series-codex)
{{#include ../banners/hacktricks-training.md}}
