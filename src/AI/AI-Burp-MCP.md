# Burp MCP: LLM destekli trafik incelemesi

{{#include ../banners/hacktricks-training.md}}

## Genel Bakış

Burp'ın **MCP Server** eklentisi, ele geçirilen HTTP(S) trafiğini MCP uyumlu LLM istemcilerine sunarak güvenlik açığı keşfi ve rapor taslağı hazırlama amacıyla **gerçek istekler/yanıtlar** üzerinde akıl yürütmelerini sağlayabilir. Burp'ı doğruluk kaynağı olarak kullanın: körlemesine tarama yerine pasif analiz veya kasıtlı olarak tek değişkenli tekrar oynatmalar gerçekleştirin.<sup>[[8]](#references)</sup>

## Mimari

- **Burp MCP Server (BApp)** varsayılan olarak `127.0.0.1:9876` üzerinde dinler ve ele geçirilen trafiği MCP üzerinden sunar.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- **MCP proxy JAR**, stdio'yu (istemci tarafı) Burp'ın MCP SSE endpoint'ine bağlar.
- **İsteğe bağlı yerel reverse proxy** (Caddy), katı MCP handshake kontrolleri için header'ları normalize eder.
- **İstemciler/backend'ler**: Codex CLI (cloud), Gemini CLI (cloud) veya Ollama (local).

## Kurulum

### 1) Burp MCP Server'ı yükleyin

Burp BApp Store'dan **MCP Server**'ı yükleyin ve `127.0.0.1:9876` üzerinde dinlediğini doğrulayın.<sup>[[1]](#references)[[2]](#references)</sup>

### 2) Proxy JAR'ı çıkarın

MCP Server sekmesinde **Extract server proxy jar** seçeneğine tıklayın ve `mcp-proxy-all.jar` dosyasını kaydedin.<sup>[[7]](#references)</sup>

### 3) Bir MCP istemcisi yapılandırın (Codex örneği)

İstemciyi proxy JAR'a ve Burp'ın doğrudan SSE endpoint'ine yönlendirin. Paketlenmiş proxy, stdio'dan SSE'ye köprü görevi görür; Burp listener'ının yerini almaz.<sup>[[7]](#references)</sup>
```toml
# ~/.codex/config.toml
[mcp_servers.burp]
command = "java"
args = ["-jar", "/absolute/path/to/mcp-proxy-all.jar", "--sse-url", "http://127.0.0.1:9876"]
```
Eşdeğer Codex komutu şudur:<sup>[[7]](#references)[[8]](#references)</sup>
```bash
codex mcp add burp -- /path/to/java -jar /path/to/mcp-proxy-all.jar \
--sse-url http://127.0.0.1:9876
```
Ardından Codex'i çalıştırın ve MCP araçlarını listeleyin:
```bash
codex
# inside Codex: /mcp
```
### 4) Gerekirse Caddy ile katı Origin/header doğrulamasını düzeltme

MCP handshake işlemi katı `Origin` kontrolleri veya ek header'lar nedeniyle başarısız olursa, header'ları normalize etmek için yerel bir reverse proxy kullanın (bu, Burp MCP katı doğrulama sorunu için geçici çözümle aynıdır).<sup>[[1]](#references)[[3]](#references)</sup>
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
Proxy'yi ve istemciyi başlatın ve yapılandırılmış `--sse-url` değerini yalnızca bu Caddy listener'ını kullanırken `http://127.0.0.1:19876` olarak değiştirin:<sup>[[1]](#references)[[3]](#references)</sup>
```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```
### 5) Tarayıcı durumunu proxy kanıtıyla eşleştirin (Playwright MCP)

Playwright MCP'yi, tarayıcısı Burp proxy'sini kullanacak şekilde kaydedin. Bu, agent'ın oluşturulan DOM/erişilebilirlik durumunu, onu oluşturan kesin HTTP history ile ilişkilendirmesini sağlar.<sup>[[6]](#references)[[8]](#references)</sup>
```bash
codex mcp add playwright -- npx -y @playwright/mcp@latest \
--proxy-server=http://127.0.0.1:8080 \
--ignore-https-errors
```
Listener adresini uyarlayın, Codex'i yeniden başlatın ve her iki integration'ı doğrulamak için `/mcp` kullanın. Örnek, HTTPS interception işleminin Burp tarafından yerel olarak oluşturulan sertifika nedeniyle engellenmemesi için browser certificate errors seçeneğini devre dışı bırakır.<sup>[[6]](#references)[[8]](#references)</sup>

## Farklı istemcileri kullanma

### Codex CLI

- `~/.codex/config.toml` dosyasını yukarıdaki gibi yapılandırın.
- `codex` komutunu çalıştırın, ardından Burp tools listesini doğrulamak için `/mcp` kullanın.

### Gemini CLI

**burp-mcp-agents** repo'su launcher yardımcıları sağlar:<sup>[[4]](#references)</sup>
```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```
### Ollama (local)

Sağlanan launcher helper'ı kullanın ve bir local model seçin:
```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```
Örnek local modeller ve yaklaşık VRAM gereksinimleri:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## Kanıta dayalı replay ve doğrulama

Agent'ın makul bir açıklamayı veya ara yanıtı kanıt olarak değerlendirmesine izin vermeyin. Her testi falsifiable hale getirmek için Burp request/response verilerini ve bağımsız olarak gözlemlenen browser durumunu kullanın.<sup>[[8]](#references)</sup>

1. Bir baseline request/response çifti kaydedin ve saldırgan tarafından kontrol edilen bileşeni tam olarak belirleyin.
2. Authorization karşılaştırmaları için identifier'ları, cookie'leri veya token'ları değiştirmeden önce aynı workflow'u her iki account altında bağımsız olarak yakalayın.
3. Bir mutation'ı replay etmeden önce hypothesis'i, kanıtın konumunu, beklenen signal'i ve bunu çürütecek sonucu kaydedin.
4. Her seferinde tek bir bileşeni mutate edin, ortaya çıkan çifti koruyun ve direct observation'ları inference'dan ayrı olarak etiketleyin.
5. Her candidate'ı `open`, `blocked`, `rejected` veya `confirmed` olarak takip edin; yalnızca yeni kanıt mechanism'i veya bir prerequisite'ı değiştirdiğinde yeniden ele alın.
6. Attacker control'ü, reachability'yi, repeatability'yi, constraint bypass'ı, impact'i ve final application state'i doğrulayın. İddia edilen state change downstream ise redirect veya başarılı bir tool call kanıt değildir.

Exploitation ayrıntılarını ilgili technique page'de tutun. Örneğin browser-message candidate'ları [PostMessage Vulnerabilities](../pentesting-web/postmessage-vulnerabilities/README.md) altında, token key-selection behavior ise [JWT Vulnerabilities](../pentesting-web/hacking-jwt-json-web-tokens.md) altında yer alır.<sup>[[8]](#references)</sup>

Kısa bir hypothesis record, paralel agent'ların aynı ilgi çekici branch'i tekrarlamasını önler:<sup>[[8]](#references)</sup>
```yaml
status: open
hypothesis: "cross-account object access ignores ownership"
evidence: ["requests/user-a.txt", "requests/user-b.txt"]
next_test: "change only the object ID in user A's request"
expected_signal: "user B's object is returned"
falsifier: "server rejects it or returns only user A's object"
```
## Pasif inceleme için prompt paketi

**burp-mcp-agents** repo'su, kanıta dayalı Burp trafiği analizi için prompt şablonları içerir:<sup>[[4]](#references)</sup>

- `passive_hunter.md`: geniş kapsamlı pasif vulnerability tespiti.
- `idor_hunter.md`: IDOR/BOLA/object/tenant drift ve auth uyumsuzlukları.
- `auth_flow_mapper.md`: authenticated ve unauthenticated path'leri karşılaştırma.
- `ssrf_redirect_hunter.md`: URL fetch parametreleri ve redirect chain'lerinden SSRF/open-redirect adayları.
- `logic_flaw_hunter.md`: çok adımlı logic flaw'ları.
- `session_scope_hunter.md`: token audience/scope misuse.
- `rate_limit_abuse_hunter.md`: throttling/abuse açıkları.
- `report_writer.md`: kanıt odaklı raporlama.

## İsteğe bağlı attribution tagging

Log'larda Burp/LLM trafiğini etiketlemek için bir header rewrite ekleyin (proxy veya Burp Match/Replace):<sup>[[1]](#references)</sup>
```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```
## Güvenlik notları

- Traffic sensitive data içeriyorsa **local models** kullanmayı tercih edin.
- Bir finding için gereken minimum evidence'ı paylaşın.
- Burp'ü source of truth olarak tutun; modeli scanning için değil, **analysis and reporting** için kullanın.

## Burp AI Agent (AI-assisted triage + MCP tools)

**Burp AI Agent**, local/cloud LLM'leri passive/active analysis (62 vulnerability class) ile birleştiren ve harici MCP client'ların Burp'ü yönetebilmesi için 53+ MCP tool sunan bir Burp extension'dır.<sup>[[5]](#references)</sup> Öne çıkanlar:

- **Context-menu triage**: Proxy üzerinden traffic'i yakalayın, **Proxy > HTTP History**'yi açın, bir request'e sağ tıklayın → **Extensions > Burp AI Agent > Analyze this request** seçeneğine tıklayarak bu request/response'a bağlı bir AI chat başlatın.
- **Backends** (profile başına seçilebilir):
- Local HTTP: **Ollama**, **LM Studio**.
- Remote HTTP: **OpenAI-compatible** endpoint (base URL + model name).
- Cloud CLIs: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` veya `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (provider-specific login).
- **Agent profiles**: prompt template'leri `~/.burp-ai-agent/AGENTS/` altında otomatik olarak yüklenir; custom analysis/scanning davranışları eklemek için buraya ek `*.md` dosyaları bırakın.
- **MCP server**: Burp operation'larını herhangi bir MCP client'a (53+ tool) sunmak için **Settings > MCP Server** üzerinden etkinleştirin. Claude Desktop, `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) veya `%APPDATA%\Claude\claude_desktop_config.json` (Windows) düzenlenerek server'a yönlendirilebilir.
- **Privacy controls**: STRICT / BALANCED / OFF, remote model'lere gönderilmeden önce sensitive request data'yı redact eder; secrets işlerken local backend'leri tercih edin.
- **Audit logging**: AI/MCP action'larının tamper-evident traceability'si için her entry'ye ait SHA-256 integrity hashing içeren JSONL log'ları.
- **Build/load**: release JAR'ını indirin veya Java 21 ile build edin:
```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```
Operasyonel uyarılar: privacy mode zorunlu kılınmadığında cloud backend'leri session cookie'lerini/PII'yi exfiltrate edebilir; MCP exposure, Burp üzerinde remote orchestration yetkisi sağladığından erişimi trusted agent'larla sınırlandırın ve integrity-hashed audit log'un bütünlüğünü izleyin.

## References

- [1] [Burp MCP + Codex CLI entegrasyonu ve Caddy handshake düzeltmesi](https://pentestbook.six2dez.com/others/burp)
- [2] [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [PortSwigger MCP server strict Origin/header validation sorunu](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Burp MCP Agents (workflows, launchers, prompt pack)](https://github.com/six2dez/burp-mcp-agents)
- [5] [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)
- [6] [Microsoft Playwright MCP](https://github.com/microsoft/playwright-mcp)
- [7] [PortSwigger Burp Suite MCP Server](https://github.com/PortSwigger/mcp-server)
- [8] [Bug Bounty araştırması için Codex nasıl kullanılır: geniş kapsamlı keşfedin, titizlikle doğrulayın](https://www.yeswehack.com/learn-bug-bounty/llm-series-codex)
{{#include ../banners/hacktricks-training.md}}
