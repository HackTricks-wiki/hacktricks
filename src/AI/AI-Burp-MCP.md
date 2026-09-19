# Burp MCP: LLM destekli trafik incelemesi

{{#include ../banners/hacktricks-training.md}}

## Genel bakış

Burp'un **MCP Server** eklentisi, yakalanan HTTP(S) trafiğini MCP uyumlu LLM istemcilerine sunarak gerçek istekler/yanıtlar üzerinde **akıl yürütmelerini**, zafiyet keşfi ve rapor taslağı hazırlama işlemleri gerçekleştirmelerini sağlar. Burp'u doğruluk kaynağı olarak kullanın: körlemesine tarama yerine pasif analiz veya tek değişkenli kontrollü tekrar isteklerini tercih edin.<sup>[[8]](#references)</sup>

## Mimari

- **Burp MCP Server (BApp)** varsayılan olarak `127.0.0.1:9876` üzerinde dinler ve yakalanan trafiği MCP üzerinden sunar.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- **MCP proxy JAR**, stdio'yu (istemci tarafı) Burp'un MCP SSE endpoint'ine bağlar.
- **İsteğe bağlı yerel reverse proxy** (Caddy), katı MCP handshake kontrolleri için header'ları normalleştirir.
- **İstemciler/backend'ler**: Codex CLI (cloud), Gemini CLI (cloud) veya Ollama (local).

## Kurulum

### 1) Burp MCP Server'ı yükleyin

Burp BApp Store'dan **MCP Server**'ı yükleyin ve `127.0.0.1:9876` üzerinde dinlediğini doğrulayın.<sup>[[1]](#references)[[2]](#references)</sup>

### 2) Proxy JAR'ı çıkarın

MCP Server sekmesinde **Extract server proxy jar** seçeneğine tıklayın ve `mcp-proxy-all.jar` dosyasını kaydedin.<sup>[[7]](#references)</sup>

### 3) Bir MCP istemcisi yapılandırın (Codex örneği)

İstemciyi proxy JAR'a ve Burp'un doğrudan SSE endpoint'ine yönlendirin. Paketlenmiş proxy, stdio'dan SSE'ye bir köprü görevi görür; Burp listener'ının yerini almaz.<sup>[[7]](#references)</sup>
```toml
# ~/.codex/config.toml
[mcp_servers.burp]
command = "java"
args = ["-jar", "/absolute/path/to/mcp-proxy-all.jar", "--sse-url", "http://127.0.0.1:9876"]
```
Eşdeğer Codex komutu:<sup>[[7]](#references)[[8]](#references)</sup>
```bash
codex mcp add burp -- /path/to/java -jar /path/to/mcp-proxy-all.jar \
--sse-url http://127.0.0.1:9876
```
Ardından Codex'i çalıştırın ve MCP araçlarını listeleyin:
```bash
codex
# inside Codex: /mcp
```
### 4) Caddy ile katı Origin/header doğrulamasını düzeltme (gerekirse)

MCP handshake işlemi katı `Origin` kontrolleri veya ek header'lar nedeniyle başarısız olursa, header'ları normalleştirmek için yerel bir reverse proxy kullanın (bu, Burp MCP katı doğrulama sorunu için geçici çözümle aynıdır).<sup>[[1]](#references)[[3]](#references)</sup>
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
Proxy'yi ve client'ı başlatın ve yalnızca bu Caddy listener'ını kullanırken yapılandırılmış `--sse-url` değerini `http://127.0.0.1:19876` olarak değiştirin:<sup>[[1]](#references)[[3]](#references)</sup>
```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```
### 5) Tarayıcı durumunu proxy kanıtıyla eşleştirin (Playwright MCP)

Playwright MCP'yi, tarayıcısı Burp proxy'sini kullanacak şekilde kaydedin. Bu, agent'ın oluşturulan tam HTTP geçmişiyle işlenen DOM/erişilebilirlik durumunu ilişkilendirmesini sağlar.<sup>[[6]](#references)[[8]](#references)</sup>
```bash
codex mcp add playwright -- npx -y @playwright/mcp@latest \
--proxy-server=http://127.0.0.1:8080 \
--ignore-https-errors
```
Listener adresini uygun şekilde ayarlayın, Codex'i yeniden başlatın ve her iki entegrasyonu doğrulamak için `/mcp` komutunu kullanın. Örnek, HTTPS interception işleminin Burp tarafından yerel olarak oluşturulan sertifika nedeniyle engellenmemesi için browser sertifika hatalarını devre dışı bırakır.<sup>[[6]](#references)[[8]](#references)</sup>

## Proxy-aware browser automation (OpenBurp)

Burp MCP bağlantısı ile interception uygulanan browser yolu ayrı veri akışlarıdır. MCP service, Burp araçlarını `127.0.0.1:9876` üzerinde sunarken özel bir Chromium instance'ı HTTP(S) trafiğini `127.0.0.1:8080` üzerindeki Burp proxy'si üzerinden gönderir. Bu nedenle doğrudan bir MCP tool tarafından oluşturulan request'ler **Proxy > HTTP history** bölümünde görünmeyebilir; request/response'un gözlemlenmesi, düzenlenmesi veya kanıt olarak saklanması gerektiğinde proxy kullanan browser'ı kullanın.<sup>[[2]](#references)[[9]](#references)</sup>

SSE desteğine sahip bir client, Burp'u doğrudan kaydedebilir. Yalnızca stdio destekleyen bir client bunun yerine PortSwigger'ın proxy JAR'ını başlatabilir. Her iki durumda da ikinci bir browser-control MCP kaydedin ve bunu Burp'un embedded Chromium'una yönlendirin (`BURP_CHROMIUM` yerel bir executable path'tir):<sup>[[9]](#references)</sup>
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
TLS-bypass flag, interception proxy tarafından oluşturulan sertifikaları kabul eder; `--isolated` ise assessment işleminin operatörün normal browser profile'ını yeniden kullanmasını önler. Isolation, profile state'i korur ancak **security sandbox değildir**: controller, bu test browser'ında açılmış authenticated session'lara erişmeye devam edebilir ve Burp MCP, hassas request'leri, response'ları ve configuration'ı açığa çıkarabilir.<sup>[[9]](#references)</sup>

Client bridge'de hata ayıklamadan önce SSE listener'ı bağımsız olarak test edin:<sup>[[9]](#references)</sup>
```bash
curl -i --max-time 3 http://127.0.0.1:9876/
```
Sağlıklı bir listener `Content-Type: text/event-stream` döndürür. Header'ların ardından oluşan timeout beklenen bir durumdur; çünkü bir SSE stream gelecekteki event'ler için açık kalır. İstemci hâlâ başarısız oluyorsa extension'ın yapılandırılmış route'unu doğrulayın: PortSwigger, client ve extension yapılandırmasına bağlı olarak endpoint'in root path veya `/sse` olabileceğini belirtiyor.<sup>[[9]](#references)[[7]](#references)</sup>

## Farklı client'ları kullanma

### Codex CLI

- Yukarıdaki gibi `~/.codex/config.toml` dosyasını yapılandırın.
- `codex` komutunu çalıştırın, ardından Burp tools listesini doğrulamak için `/mcp` komutunu kullanın.

### Gemini CLI

**burp-mcp-agents** repo'su launcher helper'ları sağlar:<sup>[[4]](#references)</sup>
```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```
### Ollama (yerel)

Sağlanan launcher helper'ı kullanın ve bir yerel model seçin:
```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```
Örnek local modeller ve yaklaşık VRAM gereksinimleri:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## Kanıta dayalı replay ve doğrulama

Agent'ın makul bir açıklamayı veya ara yanıtı kanıt olarak değerlendirmesine izin vermeyin. Her testi yanlışlanabilir kılmak için Burp isteklerini/yanıtlarını ve bağımsız olarak gözlemlenen browser durumunu kullanın.<sup>[[8]](#references)</sup>

1. Bir baseline istek/yanıt çifti kaydedin ve attacker-controlled bileşeni tam olarak belirleyin.
2. Authorization karşılaştırmaları için identifier'ları, cookie'leri veya token'ları değiştirmeden önce aynı workflow'u her iki hesapla bağımsız olarak yakalayın.
3. Bir mutation'ı replay etmeden önce hipotezi, kanıt konumunu, beklenen sinyali ve hipotezi çürütecek sonucu kaydedin.
4. Her seferinde tek bir bileşeni mutate edin, ortaya çıkan çifti koruyun ve doğrudan gözlemleri inference'dan ayrı olarak etiketleyin.
5. Her adayı `open`, `blocked`, `rejected` veya `confirmed` olarak takip edin; yalnızca yeni kanıt mekanizmayı veya bir ön koşulu değiştirdiğinde yeniden değerlendirin.
6. Attacker control, reachability, repeatability, constraint bypass, impact ve final application state'i doğrulayın. İddia edilen state change sonraki aşamalara bağlıysa redirect veya başarılı bir tool call kanıt değildir.

Exploitation ayrıntılarını ilgili technique sayfasında tutun. Örneğin browser-message adayları [PostMessage Vulnerabilities](../pentesting-web/postmessage-vulnerabilities/README.md) içinde, token key-selection behavior ise [JWT Vulnerabilities](../pentesting-web/hacking-jwt-json-web-tokens.md) içinde yer almalıdır.<sup>[[8]](#references)</sup>

Kısa bir hipotez kaydı, paralel agent'ların aynı cazip dalı tekrarlamasını önler:<sup>[[8]](#references)</sup>
```yaml
status: open
hypothesis: "cross-account object access ignores ownership"
evidence: ["requests/user-a.txt", "requests/user-b.txt"]
next_test: "change only the object ID in user A's request"
expected_signal: "user B's object is returned"
falsifier: "server rejects it or returns only user A's object"
```
## Pasif inceleme için prompt paketi

**burp-mcp-agents** reposu, Burp trafiğinin kanıta dayalı analizi için prompt şablonları içerir:<sup>[[4]](#references)</sup>

- `passive_hunter.md`: geniş kapsamlı pasif güvenlik açığı tespiti.
- `idor_hunter.md`: IDOR/BOLA/object/tenant drift ve auth uyumsuzlukları.
- `auth_flow_mapper.md`: kimliği doğrulanmış ve doğrulanmamış yolları karşılaştırma.
- `ssrf_redirect_hunter.md`: URL fetch parametreleri ve redirect zincirlerinden SSRF/open-redirect adayları.
- `logic_flaw_hunter.md`: çok adımlı logic flaw'lar.
- `session_scope_hunter.md`: token audience/scope kötüye kullanımı.
- `rate_limit_abuse_hunter.md`: throttling/abuse açıkları.
- `report_writer.md`: kanıt odaklı raporlama.

## İsteğe bağlı attribution etiketleme

Burp/LLM trafiğini log'larda etiketlemek için bir header rewrite ekleyin (proxy veya Burp Match/Replace):<sup>[[1]](#references)</sup>
```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```
## Güvenlik notları

- Trafik hassas veriler içerdiğinde **local models** kullanmayı tercih edin.
- Bir bulgu için yalnızca gereken minimum kanıtı paylaşın.
- Burp'u doğruluk kaynağı olarak tutun; modeli scanning için değil, **analysis and reporting** için kullanın.

## Burp AI Agent (AI-assisted triage + MCP tools)

**Burp AI Agent**, local/cloud LLM'leri pasif/aktif analysis (62 vulnerability class) ile birleştiren ve harici MCP client'ların Burp'u yönetebilmesi için 53'ten fazla MCP tool sunan bir Burp extension'ıdır.<sup>[[5]](#references)</sup> Öne çıkanlar:

- **Context-menu triage**: Proxy üzerinden trafiği yakalayın, **Proxy > HTTP History** bölümünü açın, bir request'e sağ tıklayın → **Extensions > Burp AI Agent > Analyze this request** seçeneğine tıklayarak o request/response'a bağlı bir AI chat başlatın.
- **Backends** (profil başına seçilebilir):
- Local HTTP: **Ollama**, **LM Studio**.
- Remote HTTP: **OpenAI-compatible** endpoint (base URL + model name).
- Cloud CLIs: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` veya `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (provider-specific login).
- **Agent profiles**: prompt template'leri `~/.burp-ai-agent/AGENTS/` altında otomatik olarak yüklenir; özel analysis/scanning davranışları eklemek için buraya ek `*.md` dosyaları bırakın.
- **MCP server**: Burp operations'larını herhangi bir MCP client'a (53'ten fazla tool) sunmak için **Settings > MCP Server** üzerinden etkinleştirin. Claude Desktop, macOS'ta `~/Library/Application Support/Claude/claude_desktop_config.json` veya Windows'ta `%APPDATA%\Claude\claude_desktop_config.json` dosyası düzenlenerek server'a yönlendirilebilir.
- **Privacy controls**: STRICT / BALANCED / OFF, remote models'a gönderilmeden önce hassas request verilerini redakte eder; secret'larla çalışırken local backend'leri tercih edin.
- **Audit logging**: AI/MCP actions için kurcalamaya karşı kanıtlanabilir izlenebilirlik sağlayan, her giriş için SHA-256 integrity hashing içeren JSONL log'ları.
- **Build/load**: release JAR'ını indirin veya Java 21 ile build edin:
```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```
Operasyonel uyarılar: privacy mode uygulanmadığı sürece cloud backend'leri session cookie'lerini/PII'yi dışarı sızdırabilir; MCP'ye maruz bırakma, Burp'un uzaktan orchestration edilmesini sağlar; bu nedenle erişimi güvenilir agent'larla sınırlandırın ve bütünlük hash'i uygulanmış audit log'unu izleyin.

## References

- [1] [Burp MCP + Codex CLI entegrasyonu ve Caddy handshake düzeltmesi](https://pentestbook.six2dez.com/others/burp)
- [2] [Burp MCP Server BApp'i](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [PortSwigger MCP server strict Origin/header doğrulama sorunu](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Burp MCP Agents (iş akışları, launcher'lar, prompt paketi)](https://github.com/six2dez/burp-mcp-agents)
- [5] [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)
- [6] [Microsoft Playwright MCP](https://github.com/microsoft/playwright-mcp)
- [7] [PortSwigger Burp Suite MCP Server](https://github.com/PortSwigger/mcp-server)
- [8] [Bug Bounty araştırması için Codex nasıl kullanılır: kapsamlı keşfedin, titizlikle doğrulayın](https://www.yeswehack.com/learn-bug-bounty/llm-series-codex)
- [9] [OpenBurp: Claude Code ve Codex için Burp Suite orchestration'ı](https://github.com/luispacheco22/OpenBurp)
{{#include ../banners/hacktricks-training.md}}
