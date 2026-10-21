# Burp MCP: revisão de tráfego assistida por LLM

{{#include ../banners/hacktricks-training.md}}

## Visão geral

A extensão **MCP Server** do Burp pode expor tráfego HTTP(S) interceptado a clientes LLM compatíveis com MCP, permitindo que eles **analisem solicitações/respostas reais** para descobrir vulnerabilidades e redigir relatórios. Mantenha o Burp como fonte da verdade: use análise passiva ou replays deliberados de uma variável por vez, em vez de varreduras às cegas.<sup>[[8]](#references)</sup>

## Arquitetura

- O **Burp MCP Server (BApp)** escuta em `127.0.0.1:9876` por padrão e expõe tráfego interceptado via MCP.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- O **MCP proxy JAR** conecta stdio (lado do cliente) ao endpoint MCP SSE do Burp.
- **Proxy reverso local opcional** (Caddy) normaliza os cabeçalhos para verificações rigorosas do handshake MCP.
- **Clientes/backends**: Codex CLI (cloud), Gemini CLI (cloud) ou Ollama (local).

## Configuração

### 1) Instalar o Burp MCP Server

Instale o **MCP Server** na Burp BApp Store e verifique se ele está escutando em `127.0.0.1:9876`.<sup>[[1]](#references)[[2]](#references)</sup>

### 2) Extrair o proxy JAR

Na aba MCP Server, clique em **Extract server proxy jar** e salve `mcp-proxy-all.jar`.<sup>[[7]](#references)</sup>

### 3) Configurar um cliente MCP (exemplo com Codex)

Aponte o cliente para o proxy JAR e o endpoint SSE direto do Burp. O proxy empacotado é uma ponte de stdio para SSE; ele não substitui o listener do Burp.<sup>[[7]](#references)</sup>

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

### 5) Associe o estado do navegador às evidências do proxy (Playwright MCP)

Configure o Playwright MCP para que o navegador use o proxy do Burp. Isso permite que o agente correlacione o estado renderizado do DOM/acessibilidade com o histórico HTTP exato que o produziu.<sup>[[6]](#references)[[8]](#references)</sup>

```bash
codex mcp add playwright -- npx -y @playwright/mcp@latest \
  --proxy-server=http://127.0.0.1:8080 \
  --ignore-https-errors
```

Adapte o endereço do listener, reinicie o Codex e use `/mcp` para verificar as duas integrações. O exemplo desativa os erros de certificado do navegador para que a interceptação HTTPS não seja bloqueada pelo certificado gerado localmente pelo Burp.<sup>[[6]](#references)[[8]](#references)</sup>

## Automação de navegador com suporte a proxy (OpenBurp)

A conexão MCP do Burp e o tráfego do navegador interceptado são fluxos de dados separados. O serviço MCP expõe as ferramentas do Burp em `127.0.0.1:9876`, enquanto uma instância dedicada do Chromium envia seu tráfego HTTP(S) pelo proxy do Burp em `127.0.0.1:8080`. Portanto, as solicitações geradas diretamente por uma ferramenta MCP podem não aparecer em **Proxy > HTTP history**; use o navegador com proxy sempre que a solicitação/resposta precisar ser observável, editável ou mantida como evidência.<sup>[[2]](#references)[[9]](#references)</sup>

Um cliente com suporte a SSE pode registrar o Burp diretamente. Um cliente que só oferece suporte a stdio pode iniciar o JAR de proxy da PortSwigger. Em ambos os casos, registre um segundo MCP de controle do navegador e aponte-o para o Chromium integrado do Burp (`BURP_CHROMIUM` é um caminho local para o executável):<sup>[[9]](#references)</sup>

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

A flag de bypass de TLS aceita certificados gerados pelo proxy de interceptação, enquanto `--isolated` impede que a avaliação reutilize o perfil normal do navegador do operador. O isolamento protege o estado do perfil, mas **não é um sandbox de segurança**: o controlador ainda pode acessar sessões autenticadas abertas nesse navegador de teste, e o Burp MCP pode expor solicitações, respostas e configurações confidenciais.<sup>[[9]](#references)</sup>

Teste o listener SSE de forma independente antes de depurar a ponte do cliente:<sup>[[9]](#references)</sup>

```bash
curl -i --max-time 3 http://127.0.0.1:9876/
```

Um listener funcional retorna `Content-Type: text/event-stream`. Um timeout após os headers é esperado, pois um stream SSE permanece aberto para eventos futuros. Se o cliente ainda falhar, confirme a rota configurada da extensão: a PortSwigger informa que o endpoint pode ser o caminho raiz ou `/sse`, dependendo do cliente e da configuração da extensão.<sup>[[9]](#references)[[7]](#references)</sup>

## Usando diferentes clientes

### Codex CLI

- Configure `~/.codex/config.toml` como acima.
- Execute `codex` e, em seguida, `/mcp` para verificar a lista de ferramentas do Burp.

### Gemini CLI

O repositório **burp-mcp-agents** fornece auxiliares de inicialização:<sup>[[4]](#references)</sup>

```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```

### Ollama (local)

Use o auxiliar de inicialização fornecido e selecione um modelo local:

```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```

Exemplos de modelos locais e requisitos aproximados de VRAM:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## Reprodução e validação orientadas por evidências

Não deixe o agente tratar uma explicação plausível ou uma resposta intermediária como prova. Use solicitações/respostas do Burp e o estado do navegador observado de forma independente para tornar cada teste falsificável.<sup>[[8]](#references)</sup>

1. Salve um par de solicitação/resposta de referência e identifique o componente exato controlado pelo atacante.
2. Para comparações de autorização, capture o mesmo fluxo de trabalho de forma independente nas duas contas antes de modificar identificadores, cookies ou tokens.
3. Antes de reproduzir uma modificação, registre a hipótese, o local da evidência, o sinal esperado e o resultado que a refutaria.
4. Modifique um componente por vez, preserve o par resultante e identifique separadamente observações diretas e inferências.
5. Acompanhe cada candidato como `open`, `blocked`, `rejected` ou `confirmed`; reavalie-o somente quando novas evidências alterarem o mecanismo ou um pré-requisito.
6. Confirme o controle do atacante, a alcançabilidade, a repetibilidade, a ignorância de restrições, o impacto e o estado final da aplicação. Um redirecionamento ou uma chamada de ferramenta bem-sucedida não é prova se a alteração de estado alegada ocorrer em uma etapa posterior.

Mantenha os detalhes de exploração na página da técnica relevante. Por exemplo, candidatos relacionados a mensagens do navegador pertencem a [PostMessage Vulnerabilities](../pentesting-web/postmessage-vulnerabilities/README.md), enquanto o comportamento de seleção de chave de token pertence a [JWT Vulnerabilities](../pentesting-web/hacking-jwt-json-web-tokens.md).<sup>[[8]](#references)</sup>

Um registro compacto de hipóteses evita que agentes paralelos repitam o mesmo caminho atraente:<sup>[[8]](#references)</sup>

```yaml
status: open
hypothesis: "cross-account object access ignores ownership"
evidence: ["requests/user-a.txt", "requests/user-b.txt"]
next_test: "change only the object ID in user A's request"
expected_signal: "user B's object is returned"
falsifier: "server rejects it or returns only user A's object"
```

## Validação out-of-band direcionada com Burp MCP

O Burp Suite Professional expõe `generate_collaborator_payload` e `get_collaborator_interactions` por meio da extensão oficial de MCP. Combine-os com `get_proxy_http_history_regex` e uma única repetição de `send_http1_request` para testar uma suspeita de busca de URL no lado do servidor sem varrer todo o alvo. O Burp pode exigir aprovações separadas para ler o histórico e enviar uma solicitação.<sup>[[2]](#references)[[10]](#references)</sup>

1. Filtre o histórico em busca de uma solicitação candidata que contenha uma URL, como uma com `url=`, `webhook` ou `callback`. Salve a solicitação e a resposta originais. A ferramenta de histórico recebe `regex`, `count` e `offset`; percorra as páginas em vez de pedir ao modelo que inspecione todas as entradas.<sup>[[10]](#references)</sup>
2. Gere um payload novo do Collaborator e guarde o **payload ID** retornado. Repita a solicitação capturada para o mesmo host e porta, alterando apenas a URL candidata para uma URL HTTPS no domínio do payload. Para `send_http1_request`, passe a solicitação HTTP/1.1 completa como `content`, além de `targetHostname`, `targetPort` e `usesHttps`; os campos de destino identificam a **aplicação**, não o host do Collaborator.<sup>[[10]](#references)</sup>
3. Consulte `get_collaborator_interactions` usando esse payload ID e correlacione o horário da interação com a repetição. Uma interação HTTP confirma uma busca, enquanto apenas DNS indica resolução, mas não uma solicitação HTTP concluída. Verifique a origem da interação e os cabeçalhos da solicitação para distinguir o tráfego de saída do servidor do carregamento no navegador e, em seguida, repita com um payload novo para descartar tráfego não relacionado.<sup>[[10]](#references)[[11]](#references)</sup>

A ferramenta de solicitação do MCP retorna a resposta diretamente e pode não preencher **Proxy > HTTP history**. Guarde o resultado da solicitação/resposta ou use o navegador com proxy ou o Repeater para obter um artefato registrado no histórico. Para selecionar payloads de SSRF e fazer testes subsequentes, consulte o [capítulo de SSRF](../pentesting-web/ssrf-server-side-request-forgery/) em vez de tratar um callback out-of-band como prova de impacto na rede interna. Para testar o próprio servidor MCP, consulte [testes de servidores MCP](AI-MCP-Servers.md#remote-mcp-server-testing-workflow).<sup>[[7]](#references)[[11]](#references)</sup>

## Conjunto de prompts para análise passiva

O repositório **burp-mcp-agents** inclui modelos de prompts para análise do tráfego do Burp baseada em evidências:<sup>[[4]](#references)</sup>

- `passive_hunter.md`: identificação passiva ampla de vulnerabilidades.
- `idor_hunter.md`: IDOR/BOLA, desvios de objeto/tenant e incompatibilidades de autenticação.
- `auth_flow_mapper.md`: comparação de caminhos autenticados e não autenticados.
- `ssrf_redirect_hunter.md`: candidatos a SSRF/open redirect em parâmetros de busca de URL e cadeias de redirecionamento.
- `logic_flaw_hunter.md`: falhas lógicas com várias etapas.
- `session_scope_hunter.md`: uso indevido de audience/scope de tokens.
- `rate_limit_abuse_hunter.md`: lacunas de throttling/abuso.
- `report_writer.md`: relatórios focados em evidências.

## Marcação opcional de atribuição

Para marcar o tráfego do Burp/LLM nos logs, adicione uma reescrita de cabeçalho (proxy ou Burp Match/Replace):<sup>[[1]](#references)</sup>

```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```

## Notas de segurança

- Prefira **modelos locais** quando o tráfego contiver dados sensíveis.
- Compartilhe apenas as evidências mínimas necessárias para um achado.
- Mantenha o Burp como fonte confiável; use o modelo para **análise e geração de relatórios**, não para scanning.

## Burp AI Agent (triagem assistida por IA + ferramentas MCP)

**Burp AI Agent** é uma extensão do Burp que combina LLMs locais/na nuvem com análise passiva/ativa (62 classes de vulnerabilidade) e disponibiliza mais de 53 ferramentas MCP para que clientes MCP externos possam orquestrar o Burp.<sup>[[5]](#references)</sup> Destaques:

- **Triagem pelo menu de contexto**: capture o tráfego via Proxy, abra **Proxy > HTTP History**, clique com o botão direito em uma requisição → **Extensions > Burp AI Agent > Analyze this request** para iniciar um chat com IA vinculado a essa requisição/resposta.
- **Backends** (selecionáveis por perfil):
  - HTTP local: **Ollama**, **LM Studio**.
  - HTTP remoto: endpoint compatível com **OpenAI** (URL base + nome do modelo).
  - CLIs na nuvem: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` ou `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (login específico do provedor).
- **Perfis de agente**: modelos de prompt instalados automaticamente em `~/.burp-ai-agent/AGENTS/`; coloque arquivos `*.md` adicionais nesse diretório para adicionar comportamentos personalizados de análise/scanning.
- **Servidor MCP**: ative em **Settings > MCP Server** para disponibilizar operações do Burp a qualquer cliente MCP (mais de 53 ferramentas). O Claude Desktop pode ser configurado para usar o servidor editando `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) ou `%APPDATA%\Claude\claude_desktop_config.json` (Windows).
- **Controles de privacidade**: STRICT / BALANCED / OFF removem dados sensíveis das requisições antes de enviá-las a modelos remotos; prefira backends locais ao lidar com segredos.
- **Registro de auditoria**: logs JSONL com hash de integridade SHA-256 por entrada, para rastreabilidade das ações de IA/MCP com evidências de adulteração.
- **Compilação/carregamento**: baixe o JAR da versão ou compile com Java 21:

```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```

Cuidados operacionais: backends na nuvem podem exfiltrar cookies de sessão/PII, a menos que o modo de privacidade esteja ativado; a exposição do MCP permite a orquestração remota do Burp, portanto restrinja o acesso a agentes confiáveis e monitore o log de auditoria com hash de integridade.



## References

- [1] [Integração do Burp MCP + Codex CLI e correção do handshake do Caddy](https://pentestbook.six2dez.com/others/burp)
- [2] [BApp do Burp MCP Server](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [Problema de validação estrita de Origin/cabeçalho no servidor MCP do PortSwigger](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Agentes do Burp MCP (fluxos de trabalho, launchers, pacote de prompts)](https://github.com/six2dez/burp-mcp-agents)
- [5] [Agente de IA do Burp](https://github.com/six2dez/burp-ai-agent)
- [6] [Microsoft Playwright MCP](https://github.com/microsoft/playwright-mcp)
- [7] [PortSwigger Burp Suite MCP Server](https://github.com/PortSwigger/mcp-server)
- [8] [Como usar o Codex para pesquisa de Bug Bounty: explore amplamente, valide rigorosamente](https://www.yeswehack.com/learn-bug-bounty/llm-series-codex)
- [9] [OpenBurp: orquestração do Burp Suite para Claude Code e Codex](https://github.com/luispacheco22/OpenBurp)
- [10] [Implementações e parâmetros das ferramentas do PortSwigger MCP Server](https://github.com/PortSwigger/mcp-server/blob/main/src/main/kotlin/net/portswigger/mcp/tools/Tools.kt)
- [11] [PortSwigger Web Security Academy - vulnerabilidades de Blind SSRF](https://portswigger.net/web-security/ssrf/blind)
{{#include ../banners/hacktricks-training.md}}
