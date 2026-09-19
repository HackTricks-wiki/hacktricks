# Burp MCP: revisão de tráfego assistida por LLM

{{#include ../banners/hacktricks-training.md}}

## Visão geral

A extensão **MCP Server** do Burp pode expor tráfego HTTP(S) interceptado a clientes LLM compatíveis com MCP, permitindo que eles **raciocinem sobre requests/responses reais** para descoberta de vulnerabilidades e elaboração de relatórios. Mantenha o Burp como fonte de verdade: use análise passiva ou replays deliberados alterando uma variável por vez, em vez de realizar scanning às cegas.<sup>[[8]](#references)</sup>

## Arquitetura

- O **Burp MCP Server (BApp)** escuta em `127.0.0.1:9876` por padrão e expõe o tráfego interceptado via MCP.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- O **MCP proxy JAR** conecta stdio (lado do cliente) ao endpoint MCP SSE do Burp.
- **Reverse proxy local opcional** (Caddy) normaliza headers para verificações rigorosas do handshake do MCP.
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
O comando equivalente do Codex é:<sup>[[7]](#references)[[8]](#references)</sup>
```bash
codex mcp add burp -- /path/to/java -jar /path/to/mcp-proxy-all.jar \
--sse-url http://127.0.0.1:9876
```
Em seguida, execute o Codex e liste as ferramentas MCP:
```bash
codex
# inside Codex: /mcp
```
### 4) Corrigir a validação estrita de Origin/cabeçalhos com Caddy (se necessário)

Se o handshake do MCP falhar devido a verificações estritas de `Origin` ou a cabeçalhos adicionais, use um proxy reverso local para normalizar os cabeçalhos (isso corresponde à solução alternativa para o problema de validação estrita do Burp MCP).<sup>[[1]](#references)[[3]](#references)</sup>
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
Inicie o proxy e o client e altere o `--sse-url` configurado para `http://127.0.0.1:19876` somente ao usar este listener do Caddy:<sup>[[1]](#references)[[3]](#references)</sup>
```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```
### 5) Associar o estado do navegador às evidências do proxy (Playwright MCP)

Registre o Playwright MCP para que seu navegador use o proxy do Burp. Isso permite que o agente correlacione o DOM renderizado/estado de acessibilidade com o histórico HTTP exato que o produziu.<sup>[[6]](#references)[[8]](#references)</sup>
```bash
codex mcp add playwright -- npx -y @playwright/mcp@latest \
--proxy-server=http://127.0.0.1:8080 \
--ignore-https-errors
```
Adapte o endereço do listener, reinicie o Codex e use `/mcp` para verificar ambas as integrações. O exemplo desativa os erros de certificado do navegador para que a interceptação HTTPS não seja bloqueada pelo certificado gerado localmente pelo Burp.<sup>[[6]](#references)[[8]](#references)</sup>

## Automação de navegador ciente de proxy (OpenBurp)

A conexão MCP do Burp e o caminho do navegador interceptado são fluxos de dados separados. O serviço MCP expõe as ferramentas do Burp em `127.0.0.1:9876`, enquanto uma instância dedicada do Chromium envia seu tráfego HTTP(S) pelo proxy do Burp em `127.0.0.1:8080`. Portanto, as solicitações geradas diretamente por uma ferramenta MCP podem não aparecer em **Proxy > HTTP history**; use o navegador com proxy sempre que a solicitação/resposta precisar ser observável, editável ou mantida como evidência.<sup>[[2]](#references)[[9]](#references)</sup>

Um cliente com suporte a SSE pode registrar o Burp diretamente. Um cliente que ofereça apenas stdio pode iniciar o proxy JAR da PortSwigger. Em ambos os casos, registre um segundo MCP de controle do navegador e aponte-o para o Chromium incorporado do Burp (`BURP_CHROMIUM` é um caminho para um executável local):<sup>[[9]](#references)</sup>
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
A flag de TLS-bypass tolera certificados gerados pelo proxy de interceptação, enquanto `--isolated` impede que o assessment reutilize o perfil normal do navegador do operador. O isolamento protege o estado do perfil, mas **não é um sandbox de segurança**: o controller ainda pode acessar sessões autenticadas abertas nesse navegador de teste, e o Burp MCP pode expor requests, responses e configurações sensíveis.<sup>[[9]](#references)</sup>

Teste o listener SSE de forma independente antes de depurar a bridge do cliente:<sup>[[9]](#references)</sup>
```bash
curl -i --max-time 3 http://127.0.0.1:9876/
```
Um listener saudável retorna `Content-Type: text/event-stream`. Um timeout após os headers é esperado porque um stream SSE permanece aberto para eventos futuros. Se o client ainda falhar, confirme a route configurada da extension: a PortSwigger observa que o endpoint pode ser o caminho raiz ou `/sse`, dependendo do client e da configuração da extension.<sup>[[9]](#references)[[7]](#references)</sup>

## Usando diferentes clients

### Codex CLI

- Configure `~/.codex/config.toml` conforme descrito acima.
- Execute `codex` e, em seguida, `/mcp` para verificar a lista de Burp tools.

### Gemini CLI

O repo **burp-mcp-agents** fornece launcher helpers:<sup>[[4]](#references)</sup>
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

Não permita que o agente trate uma explicação plausível ou uma resposta intermediária como prova. Use requests/responses do Burp e o estado do browser observado independentemente para tornar cada teste falseável.<sup>[[8]](#references)</sup>

1. Salve um par baseline de request/response e identifique o componente exato controlado pelo attacker.
2. Para comparações de autorização, capture o mesmo workflow independentemente em ambas as contas antes de alterar identifiers, cookies ou tokens.
3. Antes de reproduzir uma mutação, registre a hipótese, o local da evidência, o sinal esperado e o resultado que a refutaria.
4. Faça a mutação de um componente por vez, preserve o par resultante e rotule as observações diretas separadamente da inferência.
5. Acompanhe cada candidato como `open`, `blocked`, `rejected` ou `confirmed`; reavalie-o somente quando novas evidências alterarem o mecanismo ou um pré-requisito.
6. Confirme o controle pelo attacker, a reachability, a repeatability, o bypass de restrições, o impacto e o estado final da aplicação. Um redirect ou uma chamada de ferramenta bem-sucedida não é prova se a alteração de estado alegada ocorrer downstream.

Mantenha os detalhes de exploitation na página da técnica relevante. Por exemplo, candidatos de browser-message pertencem a [PostMessage Vulnerabilities](../pentesting-web/postmessage-vulnerabilities/README.md), enquanto o comportamento de seleção de chaves de tokens pertence a [JWT Vulnerabilities](../pentesting-web/hacking-jwt-json-web-tokens.md).<sup>[[8]](#references)</sup>

Um registro compacto de hipóteses impede que agentes paralelos repitam o mesmo caminho atraente:<sup>[[8]](#references)</sup>
```yaml
status: open
hypothesis: "cross-account object access ignores ownership"
evidence: ["requests/user-a.txt", "requests/user-b.txt"]
next_test: "change only the object ID in user A's request"
expected_signal: "user B's object is returned"
falsifier: "server rejects it or returns only user A's object"
```
## Pacote de prompts para revisão passiva

O repositório **burp-mcp-agents** inclui templates de prompt para análise de tráfego do Burp orientada por evidências:<sup>[[4]](#references)</sup>

- `passive_hunter.md`: identificação passiva ampla de vulnerabilidades.
- `idor_hunter.md`: IDOR/BOLA/desvios de objeto/tenant e incompatibilidades de autenticação.
- `auth_flow_mapper.md`: comparação entre caminhos autenticados e não autenticados.
- `ssrf_redirect_hunter.md`: candidatos a SSRF/open-redirect a partir de parâmetros de busca de URL/cadeias de redirecionamento.
- `logic_flaw_hunter.md`: falhas lógicas em múltiplas etapas.
- `session_scope_hunter.md`: uso indevido do audience/scope de tokens.
- `rate_limit_abuse_hunter.md`: lacunas de throttling/abuso.
- `report_writer.md`: geração de relatórios focados em evidências.

## Atribuição opcional de tags

Para marcar o tráfego do Burp/LLM nos logs, adicione uma reescrita de cabeçalho (proxy ou Burp Match/Replace):<sup>[[1]](#references)</sup>
```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```
## Notas de segurança

- Prefira **modelos locais** quando o tráfego contiver dados sensíveis.
- Compartilhe apenas as evidências mínimas necessárias para uma finding.
- Mantenha o Burp como fonte de verdade; use o modelo para **análise e geração de relatórios**, não para scanning.

## Burp AI Agent (triagem assistida por AI + ferramentas MCP)

**Burp AI Agent** é uma extensão do Burp que combina LLMs locais/cloud com análise passiva/ativa (62 classes de vulnerabilidade) e expõe mais de 53 ferramentas MCP para que clientes MCP externos possam orquestrar o Burp.<sup>[[5]](#references)</sup> Destaques:

- **Triagem pelo menu de contexto**: capture tráfego via Proxy, abra **Proxy > HTTP History**, clique com o botão direito em uma request → **Extensions > Burp AI Agent > Analyze this request** para iniciar um chat de AI vinculado a essa request/response.
- **Backends** (selecionáveis por profile):
- Local HTTP: **Ollama**, **LM Studio**.
- Remote HTTP: endpoint compatível com **OpenAI** (base URL + nome do modelo).
- Cloud CLIs: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` ou `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (login específico do provider).
- **Agent profiles**: templates de prompt instalados automaticamente em `~/.burp-ai-agent/AGENTS/`; adicione arquivos `*.md` extras nesse diretório para incluir comportamentos personalizados de análise/scanning.
- **MCP server**: habilite em **Settings > MCP Server** para expor operações do Burp a qualquer cliente MCP (mais de 53 ferramentas). O Claude Desktop pode ser apontado para o servidor editando `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) ou `%APPDATA%\Claude\claude_desktop_config.json` (Windows).
- **Controles de privacidade**: STRICT / BALANCED / OFF ocultam dados sensíveis das requests antes de enviá-los para modelos remotos; prefira backends locais ao lidar com secrets.
- **Audit logging**: logs JSONL com hash de integridade SHA-256 por entrada para garantir rastreabilidade à prova de adulteração das ações de AI/MCP.
- **Build/load**: baixe o JAR da release ou compile com Java 21:
```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```
Cautelas operacionais: os backends de cloud podem exfiltrar session cookies/PII, a menos que o privacy mode seja aplicado; a exposição do MCP concede orquestração remota do Burp, portanto restrinja o acesso a agentes confiáveis e monitore o audit log com hash de integridade.

## References

- [1] [Integração do Burp MCP + Codex CLI e correção do handshake do Caddy](https://pentestbook.six2dez.com/others/burp)
- [2] [BApp do Burp MCP Server](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [Problema de validação estrita de Origin/header no servidor MCP da PortSwigger](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Agentes do Burp MCP (workflows, launchers, prompt pack)](https://github.com/six2dez/burp-mcp-agents)
- [5] [Agente de IA do Burp](https://github.com/six2dez/burp-ai-agent)
- [6] [Microsoft Playwright MCP](https://github.com/microsoft/playwright-mcp)
- [7] [Servidor MCP do PortSwigger Burp Suite](https://github.com/PortSwigger/mcp-server)
- [8] [Como usar o Codex para pesquisa de Bug Bounty: explore amplamente, valide rigorosamente](https://www.yeswehack.com/learn-bug-bounty/llm-series-codex)
- [9] [OpenBurp: orquestração do Burp Suite para Claude Code e Codex](https://github.com/luispacheco22/OpenBurp)
{{#include ../banners/hacktricks-training.md}}
