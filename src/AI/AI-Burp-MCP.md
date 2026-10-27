# Burp MCP: revisão de tráfego assistida por LLM

{{#include ../banners/hacktricks-training.md}}

## Visão geral

A extensão **MCP Server** do Burp pode expor tráfego HTTP(S) interceptado a clientes LLM compatíveis com MCP, permitindo que eles **analisem requests/responses reais** para descobrir vulnerabilidades e elaborar relatórios. Mantenha o Burp como fonte de verdade: use análise passiva ou replays deliberados alterando uma variável por vez, em vez de fazer scanning às cegas.<sup>[[8]](#references)</sup>

## Arquitetura

- **Burp MCP Server (BApp)** escuta em `127.0.0.1:9876` por padrão e expõe o tráfego interceptado via MCP.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- **MCP proxy JAR** faz a ponte entre stdio (lado do cliente) e o endpoint MCP SSE do Burp.
- **Reverse proxy local opcional** (Caddy) normaliza headers para verificações rigorosas do handshake MCP.
- **Clientes/backends**: Codex CLI (cloud), Gemini CLI (cloud) ou Ollama (local).

## Configuração

### 1) Instalar o Burp MCP Server

Instale **MCP Server** da Burp BApp Store e verifique se está escutando em `127.0.0.1:9876`.<sup>[[1]](#references)[[2]](#references)</sup>

### 2) Extrair o proxy JAR

Na aba MCP Server, clique em **Extrair JAR do proxy do servidor** e salve `mcp-proxy-all.jar`.<sup>[[7]](#references)</sup>

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

### 4) Corrigir a validação rigorosa de Origin/cabeçalhos com Caddy (se necessário)

Se o handshake do MCP falhar devido a verificações rigorosas de `Origin` ou a cabeçalhos extras, use um proxy reverso local para normalizar os cabeçalhos (isso corresponde à solução alternativa para o problema de validação rigorosa do Burp MCP).<sup>[[1]](#references)[[3]](#references)</sup>

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

Configure o Playwright MCP para que o navegador use o proxy do Burp. Isso permite que o agente correlacione o estado renderizado do DOM e da acessibilidade com o histórico HTTP exato que o produziu.<sup>[[6]](#references)[[8]](#references)</sup>

```bash
codex mcp add playwright -- npx -y @playwright/mcp@latest \
  --proxy-server=http://127.0.0.1:8080 \
  --ignore-https-errors
```

Adapte o endereço do listener, reinicie o Codex e use `/mcp` para verificar as duas integrações. O exemplo desativa os erros de certificado do navegador para que a interceptação HTTPS não seja bloqueada pelo certificado gerado localmente pelo Burp.<sup>[[6]](#references)[[8]](#references)</sup>

## Automação de navegador com suporte a proxy (OpenBurp)

A conexão do Burp MCP e o fluxo de tráfego do navegador interceptado são fluxos de dados separados. O serviço MCP disponibiliza as ferramentas do Burp em `127.0.0.1:9876`, enquanto uma instância dedicada do Chromium envia o tráfego HTTP(S) pelo proxy do Burp em `127.0.0.1:8080`. Portanto, as solicitações geradas diretamente por uma ferramenta MCP podem não aparecer em **Proxy > HTTP history**; use o navegador com proxy sempre que a solicitação/resposta precisar ser observável, editável ou retida como evidência.<sup>[[2]](#references)[[9]](#references)</sup>

Um cliente com suporte a SSE pode registrar o Burp diretamente. Em vez disso, um cliente que só oferece suporte a stdio pode iniciar o JAR de proxy da PortSwigger. Em ambos os casos, registre um segundo MCP de controle do navegador e aponte-o para o Chromium integrado do Burp (`BURP_CHROMIUM` é um caminho para um executável local):<sup>[[9]](#references)</sup>

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

A flag `TLS-bypass` aceita certificados gerados pelo proxy de interceptação, enquanto `--isolated` impede que a avaliação reutilize o perfil normal do navegador do operador. O isolamento protege o estado do perfil, mas **não é um sandbox de segurança**: o controlador ainda pode acessar sessões autenticadas abertas nesse navegador de teste, e o Burp MCP pode expor requisições, respostas e configurações confidenciais.<sup>[[9]](#references)</sup>

Teste o listener SSE independentemente antes de depurar a ponte do cliente:<sup>[[9]](#references)</sup>

```bash
curl -i --max-time 3 http://127.0.0.1:9876/
```

Um listener em funcionamento retorna `Content-Type: text/event-stream`. É esperado que ocorra um timeout após os headers, pois um stream SSE permanece aberto para eventos futuros. Se o cliente ainda falhar, confirme a rota configurada para a extensão: a PortSwigger observa que o endpoint pode ser o caminho raiz ou `/sse`, dependendo do cliente e da configuração da extensão.<sup>[[9]](#references)[[7]](#references)</sup>

## Usando diferentes clientes

### Codex CLI

- Configure `~/.codex/config.toml` conforme acima.
- Execute `codex` e, em seguida, `/mcp` para verificar a lista de ferramentas do Burp.

### Gemini CLI

O repo **burp-mcp-agents** fornece auxiliares de inicialização:<sup>[[4]](#references)</sup>

```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```

### Ollama (local)

Use o launcher auxiliar fornecido e selecione um modelo local:

```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```

Exemplos de modelos locais e necessidades aproximadas de VRAM:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## Reprodução e validação baseadas em evidências

Não deixe o agente tratar uma explicação plausível ou uma resposta intermediária como prova. Use requisições/respostas do Burp e o estado do navegador observado de forma independente para tornar cada teste falsificável.<sup>[[8]](#references)</sup>

1. Salve um par de requisição/resposta de referência e identifique o componente exato controlado pelo atacante.
2. Para comparações de autorização, capture o mesmo fluxo de trabalho de forma independente nas duas contas antes de alterar identificadores, cookies ou tokens.
3. Antes de reproduzir uma alteração, registre a hipótese, o local da evidência, o sinal esperado e o resultado que a refutaria.
4. Altere um componente por vez, preserve o par resultante e identifique separadamente observações diretas e inferências.
5. Acompanhe cada candidato como `open`, `blocked`, `rejected` ou `confirmed`; reavalie-o somente quando novas evidências alterarem o mecanismo ou um pré-requisito.
6. Confirme o controle do atacante, a alcançabilidade, a repetibilidade, o bypass de restrições, o impacto e o estado final da aplicação. Um redirecionamento ou uma chamada de ferramenta bem-sucedida não é prova se a alteração de estado alegada ocorrer posteriormente.

Mantenha os detalhes de exploração na página da técnica relevante. Por exemplo, candidatos relacionados a mensagens do navegador pertencem a [PostMessage Vulnerabilities](../pentesting-web/postmessage-vulnerabilities/README.md), enquanto o comportamento de seleção de chave de token pertence a [JWT Vulnerabilities](../pentesting-web/hacking-jwt-json-web-tokens.md).<sup>[[8]](#references)</sup>

Um registro conciso de hipóteses evita que agentes em paralelo repitam o mesmo caminho atraente:<sup>[[8]](#references)</sup>

```yaml
status: open
hypothesis: "cross-account object access ignores ownership"
evidence: ["requests/user-a.txt", "requests/user-b.txt"]
next_test: "change only the object ID in user A's request"
expected_signal: "user B's object is returned"
falsifier: "server rejects it or returns only user A's object"
```

## Triagem de frames WebSocket com Burp MCP

A extensão oficial expõe `get_proxy_websocket_history_regex` para buscas somente de leitura e paginadas no histórico de WebSocket do Burp. Ela recebe `regex`, `count` e `offset`; ao contrário de `send_http1_request`, não envia um frame WebSocket. O Burp registra as mensagens nas duas direções mesmo quando Intercept está desativado, então filtre o histórico antes de fornecer ao modelo um pequeno conjunto de frames relevantes.<sup>[[10]](#references)[[12]](#references)[[13]](#references)</sup>

1. Execute a mesma ação baseada em WebSocket pelo navegador configurado para usar o proxy do Burp com duas contas de teste autenticadas independentemente. Mantenha juntos cada handshake de upgrade e seus cookies, o ID da conexão, a direção do frame e os frames de resposta; um evento do servidor para o cliente na conexão da primeira conta não comprova que a segunda conta o recebeu.
2. Pesquise em `get_proxy_websocket_history_regex` usando uma expressão restrita, como `(?i)(subscribe|room|tenant|objectId)`, `count: 20` e `offset: 0`. Avance o `offset` para inspecionar correspondências posteriores. Compare o identificador do objeto ou tópico no frame de saída com a resposta na **mesma conexão**.
3. Em **Proxy > WebSockets history**, envie o frame de saída candidato para o Repeater. Associe-o à conexão aberta adequada ou reconecte usando o handshake da segunda conta. Altere apenas o identificador do objeto/tópico e compare as mensagens do servidor e o estado da aplicação resultantes com ambas as linhas de base. A ferramenta de histórico do MCP não pode fazer esse replay; o WebSocket Repeater pode editar, reenviar e reconectar frames.

Para testes específicos de protocolo, como cross-site WebSocket hijacking e autorização de tópicos de broker, consulte [WebSocket Attacks](../pentesting-web/websocket-attacks.md). Não considere um upgrade aceito ou um echo no cliente como prova de que uma subscription protegida foi bem-sucedida.

## Validação out-of-band direcionada com Burp MCP

O Burp Suite Professional expõe `generate_collaborator_payload` e `get_collaborator_interactions` por meio da extensão oficial do MCP. Combine-os com `get_proxy_http_history_regex` e um único replay de `send_http1_request` para testar uma suspeita de busca de URL no servidor, sem varrer todo o alvo. O Burp pode exigir aprovações separadas para ler o histórico e enviar uma solicitação.<sup>[[2]](#references)[[10]](#references)</sup>

1. Filtre o histórico por uma solicitação candidata que contenha uma URL, como uma com `url=`, `webhook` ou `callback`. Salve a solicitação e a resposta originais. A ferramenta de histórico recebe `regex`, `count` e `offset`; use paginação em vez de pedir ao modelo que inspecione todas as entradas.<sup>[[10]](#references)</sup>
2. Gere um payload novo do Collaborator e guarde o **ID do payload** retornado. Reenvie a solicitação capturada para o mesmo host e porta, alterando apenas a URL candidata para uma URL HTTPS no domínio desse payload. Para `send_http1_request`, passe a solicitação HTTP/1.1 completa como `content`, além de `targetHostname`, `targetPort` e `usesHttps`; os campos de destino identificam a **aplicação**, não o host do Collaborator.<sup>[[10]](#references)</sup>
3. Consulte `get_collaborator_interactions` usando esse ID de payload e correlacione o horário da interação com o replay. Uma interação HTTP sustenta a hipótese de uma busca, enquanto apenas DNS demonstra resolução, não uma solicitação HTTP concluída. Verifique a origem da interação e os cabeçalhos da solicitação para distinguir tráfego de saída do servidor de carregamento no navegador; em seguida, repita com um payload novo para descartar tráfego não relacionado.<sup>[[10]](#references)[[11]](#references)</sup>

A ferramenta de solicitação do MCP retorna a resposta diretamente e pode não preencher **Proxy > HTTP history**. Preserve o resultado da solicitação/resposta ou use o navegador com proxy ou o Repeater para obter um artefato registrado no histórico. Para escolher payloads de SSRF e realizar testes adicionais, use o [capítulo de SSRF](../pentesting-web/ssrf-server-side-request-forgery/) em vez de tratar um callback out-of-band como prova de impacto na rede interna. Para testar o próprio servidor MCP, consulte [MCP server testing](AI-MCP-Servers.md#remote-mcp-server-testing-workflow).<sup>[[7]](#references)[[11]](#references)</sup>

## Conjunto de prompts para análise passiva

O repositório **burp-mcp-agents** inclui modelos de prompts para análise do tráfego do Burp baseada em evidências:<sup>[[4]](#references)</sup>

- `passive_hunter.md`: detecção passiva ampla de vulnerabilidades.
- `idor_hunter.md`: IDOR/BOLA, divergências de objeto/tenant e incompatibilidades de autenticação.
- `auth_flow_mapper.md`: comparação de caminhos autenticados e não autenticados.
- `ssrf_redirect_hunter.md`: candidatos a SSRF/open redirect em parâmetros de busca de URL/cadeias de redirecionamento.
- `logic_flaw_hunter.md`: falhas lógicas com várias etapas.
- `session_scope_hunter.md`: uso indevido de audience/scope de token.
- `rate_limit_abuse_hunter.md`: lacunas de throttling/abuso.
- `report_writer.md`: relatórios com foco em evidências.

## Marcação opcional para atribuição

Para marcar o tráfego do Burp/LLM nos logs, adicione uma reescrita de cabeçalho (proxy ou Burp Match/Replace):<sup>[[1]](#references)</sup>

```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```

## Observações de segurança

- Prefira **modelos locais** quando o tráfego contiver dados confidenciais.
- Compartilhe apenas as evidências mínimas necessárias para uma constatação.
- Mantenha o Burp como fonte da verdade; use o modelo para **análise e elaboração de relatórios**, não para fazer scans.

## Burp AI Agent (triagem assistida por IA + ferramentas MCP)

**Burp AI Agent** é uma extensão do Burp que combina LLMs locais/em nuvem com análise passiva/ativa (62 classes de vulnerabilidade) e expõe mais de 53 ferramentas MCP para que clientes MCP externos possam orquestrar o Burp.<sup>[[5]](#references)</sup> Destaques:

- **Triagem pelo menu de contexto**: capture tráfego via Proxy, abra **Proxy > HTTP History**, clique com o botão direito em uma solicitação → **Extensions > Burp AI Agent > Analyze this request** para iniciar um chat com IA associado a essa solicitação/resposta.
- **Backends** (selecionáveis por perfil):
  - HTTP local: **Ollama**, **LM Studio**.
  - HTTP remoto: endpoint **compatível com OpenAI** (URL base + nome do modelo).
  - CLIs na nuvem: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` ou `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (login específico do provedor).
- **Perfis de agente**: modelos de prompt instalados automaticamente em `~/.burp-ai-agent/AGENTS/`; adicione arquivos `*.md` extras nesse diretório para incluir comportamentos personalizados de análise/scanning.
- **Servidor MCP**: habilite em **Settings > MCP Server** para expor operações do Burp a qualquer cliente MCP (mais de 53 ferramentas). O Claude Desktop pode ser conectado ao servidor editando `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) ou `%APPDATA%\Claude\claude_desktop_config.json` (Windows).
- **Controles de privacidade**: STRICT / BALANCED / OFF ocultam dados confidenciais das solicitações antes de enviá-las a modelos remotos; prefira backends locais ao lidar com segredos.
- **Registro de auditoria**: logs JSONL com hash de integridade SHA-256 por entrada para rastreabilidade de ações de IA/MCP com evidência de adulteração.
- **Compilação/carregamento**: baixe o JAR da versão ou compile com Java 21:

```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```

Cuidados operacionais: backends na nuvem podem exfiltrar cookies de sessão/PII, a menos que o modo de privacidade seja aplicado; a exposição do MCP concede orquestração remota do Burp, portanto, restrinja o acesso a agentes confiáveis e monitore o log de auditoria com hash de integridade.



## References

- [1] [Integração do Burp MCP + Codex CLI e correção do handshake do Caddy](https://pentestbook.six2dez.com/others/burp)
- [2] [BApp do servidor Burp MCP](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [Problema de validação estrita de Origin/header no servidor MCP da PortSwigger](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Agentes Burp MCP (workflows, launchers, pacote de prompts)](https://github.com/six2dez/burp-mcp-agents)
- [5] [Agente de IA Burp](https://github.com/six2dez/burp-ai-agent)
- [6] [Microsoft Playwright MCP](https://github.com/microsoft/playwright-mcp)
- [7] [Servidor MCP do PortSwigger Burp Suite](https://github.com/PortSwigger/mcp-server)
- [8] [Como usar o Codex para pesquisa de Bug Bounty: explore amplamente, valide rigorosamente](https://www.yeswehack.com/learn-bug-bounty/llm-series-codex)
- [9] [OpenBurp: orquestração do Burp Suite para Claude Code e Codex](https://github.com/luispacheco22/OpenBurp)
- [10] [Implementações de ferramentas e parâmetros do servidor MCP da PortSwigger](https://github.com/PortSwigger/mcp-server/blob/main/src/main/kotlin/net/portswigger/mcp/tools/Tools.kt)
- [11] [PortSwigger Web Security Academy - Vulnerabilidades de SSRF cego](https://portswigger.net/web-security/ssrf/blind)
- [12] [PortSwigger - Histórico de WebSockets](https://portswigger.net/burp/documentation/desktop/tools/proxy/websockets-history)
- [13] [PortSwigger - Como trabalhar com mensagens WebSocket no Burp Repeater](https://portswigger.net/burp/documentation/desktop/tools/repeater/websocket-messages)
{{#include ../banners/hacktricks-training.md}}
