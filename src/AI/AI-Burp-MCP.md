# Burp MCP: LLM destekli trafik incelemesi

{{#include ../banners/hacktricks-training.md}}

## Genel Bakış

Burp'ün **MCP Server** eklentisi, ele geçirilen HTTP(S) trafiğini MCP destekli LLM istemcilerine sunarak güvenlik açığı keşfi ve rapor taslağı hazırlama amacıyla **gerçek istekler/yanıtlar üzerinde akıl yürütmelerini** sağlayabilir. Burp'ü tek doğruluk kaynağı olarak kullanın: kör tarama yapmak yerine pasif analiz veya tek değişkenli, bilinçli tekrarlar kullanın.<sup>[[8]](#references)</sup>

## Mimari

- **Burp MCP Server (BApp)** varsayılan olarak `127.0.0.1:9876` üzerinde dinler ve ele geçirilen trafiği MCP aracılığıyla sunar.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- **MCP proxy JAR**, stdio'yu (istemci tarafı) Burp'ün MCP SSE uç noktasına bağlar.
- **İsteğe bağlı yerel reverse proxy** (Caddy), katı MCP handshake kontrolleri için başlıkları standartlaştırır.
- **İstemciler/backend'ler**: Codex CLI (cloud), Gemini CLI (cloud) veya Ollama (local).

## Kurulum

### 1) Burp MCP Server'ı yükleyin

Burp BApp Store'dan **MCP Server**'ı yükleyin ve `127.0.0.1:9876` üzerinde dinlediğini doğrulayın.<sup>[[1]](#references)[[2]](#references)</sup>

### 2) Proxy JAR'ı çıkarın

MCP Server sekmesinde **Extract server proxy jar** seçeneğine tıklayın ve `mcp-proxy-all.jar` dosyasını kaydedin.<sup>[[7]](#references)</sup>

### 3) Bir MCP istemcisi yapılandırın (Codex örneği)

İstemciyi proxy JAR'a ve Burp'ün doğrudan SSE uç noktasına yönlendirin. Paketlenmiş proxy, stdio ile SSE arasında köprü görevi görür; Burp listener'ının yerini almaz.<sup>[[7]](#references)</sup>

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

Ardından Codex'i çalıştır ve MCP araçlarını listele:

```bash
codex
# inside Codex: /mcp
```

### 4) Caddy ile katı Origin/header doğrulamasını düzeltme (gerekirse)

Katı `Origin` kontrolleri veya ek header'lar nedeniyle MCP el sıkışması başarısız olursa, header'ları normalleştirmek için yerel bir reverse proxy kullanın (bu, Burp MCP katı doğrulama sorunu için geçici çözümle aynıdır).<sup>[[1]](#references)[[3]](#references)</sup>

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

Proxy'yi ve istemciyi başlatın; yapılandırılmış `--sse-url` değerini yalnızca şu Caddy dinleyicisini kullanırken `http://127.0.0.1:19876` olarak değiştirin:<sup>[[1]](#references)[[3]](#references)</sup>

```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```

### 5) Tarayıcı durumunu proxy kanıtlarıyla eşleştirin (Playwright MCP)

Playwright MCP'yi, tarayıcısı Burp'ın proxy'sini kullanacak şekilde kaydedin. Böylece ajan, render edilmiş DOM/erişilebilirlik durumunu bunu oluşturan tam HTTP geçmişiyle ilişkilendirebilir.<sup>[[6]](#references)[[8]](#references)</sup>

```bash
codex mcp add playwright -- npx -y @playwright/mcp@latest \
  --proxy-server=http://127.0.0.1:8080 \
  --ignore-https-errors
```

Listener adresini uyarlayın, Codex'i yeniden başlatın ve her iki entegrasyonu da doğrulamak için `/mcp` kullanın. Örnek, HTTPS interception işleminin Burp tarafından yerel olarak oluşturulan sertifika nedeniyle engellenmemesi için tarayıcının sertifika hatalarını devre dışı bırakır.<sup>[[6]](#references)[[8]](#references)</sup>

## Proxy kullanan tarayıcı otomasyonu (OpenBurp)

Burp MCP bağlantısı ile interception yapılan tarayıcı yolu ayrı veri akışlarıdır. MCP hizmeti Burp araçlarını `127.0.0.1:9876` adresinde sunarken, özel bir Chromium örneği HTTP(S) trafiğini Burp proxy'si üzerinden `127.0.0.1:8080` adresine gönderir. Bu nedenle doğrudan bir MCP aracı tarafından oluşturulan istekler **Proxy > HTTP history** bölümünde görünmeyebilir; isteğin/yanıtın gözlemlenmesi, düzenlenmesi veya kanıt olarak saklanması gerektiğinde proxy kullanan tarayıcıyı kullanın.<sup>[[2]](#references)[[9]](#references)</sup>

SSE desteği olan bir istemci Burp'u doğrudan kaydedebilir. Yalnızca stdio desteği olan bir istemci bunun yerine PortSwigger'ın proxy JAR'ını başlatabilir. Her iki durumda da ikinci bir tarayıcı denetim MCP'si kaydedin ve Burp'un gömülü Chromium'una yönlendirin (`BURP_CHROMIUM` yerel bir çalıştırılabilir dosya yoludur):<sup>[[9]](#references)</sup>

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

TLS-bypass flag, interception proxy tarafından oluşturulan sertifikaları kabul ederken, `--isolated` değerlendirme sırasında operatörün normal browser profile'ının yeniden kullanılmasını önler. Isolation, profile state'i korur ancak **bir security sandbox değildir**: controller, test browser'da açılan authenticated sessions'lara hâlâ erişebilir ve Burp MCP, hassas requests, responses ve configuration'ı açığa çıkarabilir.<sup>[[9]](#references)</sup>

Client bridge'de hata ayıklamadan önce SSE listener'ı bağımsız olarak test edin:<sup>[[9]](#references)</sup>

```bash
curl -i --max-time 3 http://127.0.0.1:9876/
```

Sağlıklı bir listener `Content-Type: text/event-stream` döndürür. Başlıklardan sonra zaman aşımı yaşanması beklenen bir durumdur; çünkü SSE stream'i gelecekteki event'ler için açık kalır. İstemci hâlâ başarısız oluyorsa extension'ın yapılandırılmış route'unu doğrulayın: PortSwigger, istemciye ve extension yapılandırmasına bağlı olarak endpoint'in root path veya `/sse` olabileceğini belirtiyor.<sup>[[9]](#references)[[7]](#references)</sup>

## Farklı istemcileri kullanma

### Codex CLI

- `~/.codex/config.toml` dosyasını yukarıdaki gibi yapılandırın.
- `codex` komutunu çalıştırın, ardından Burp tools listesini doğrulamak için `/mcp` komutunu çalıştırın.

### Gemini CLI

**burp-mcp-agents** repo'su launcher yardımcıları sağlar:<sup>[[4]](#references)</sup>

```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```

### Ollama (yerel)

Sağlanan başlatıcı yardımcısını kullanın ve yerel bir model seçin:

```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```

Örnek yerel modeller ve yaklaşık VRAM gereksinimleri:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## Kanıta dayalı yeniden oynatma ve doğrulama

Agent'ın makul görünen bir açıklamayı veya ara yanıtı kanıt olarak değerlendirmesine izin vermeyin. Her testi yanlışlanabilir kılmak için Burp isteklerini/yanıtlarını ve tarayıcıda bağımsız olarak gözlemlenen durumu kullanın.<sup>[[8]](#references)</sup>

1. Bir temel istek/yanıt çiftini kaydedin ve saldırganın kontrol ettiği bileşeni tam olarak belirleyin.
2. Yetkilendirme karşılaştırmaları için tanımlayıcıları, çerezleri veya token'ları değiştirmeden önce aynı iş akışını her iki hesapta da bağımsız olarak yakalayın.
3. Bir değişikliği yeniden oynatmadan önce hipotezi, kanıtın konumunu, beklenen sinyali ve hipotezi çürütecek sonucu kaydedin.
4. Her seferinde tek bir bileşeni değiştirin, ortaya çıkan çifti saklayın ve doğrudan gözlemleri çıkarımlardan ayrı olarak etiketleyin.
5. Her adayı `open`, `blocked`, `rejected` veya `confirmed` olarak takip edin; yalnızca yeni kanıt mekanizmayı veya bir ön koşulu değiştirdiğinde yeniden ele alın.
6. Saldırganın kontrolünü, erişilebilirliği, tekrarlanabilirliği, kısıtlamaların aşılmasını, etkiyi ve uygulamanın son durumunu doğrulayın. İddia edilen durum değişikliği sonraki bir aşamada gerçekleşiyorsa yönlendirme veya başarılı bir tool çağrısı kanıt değildir.

Exploitation ayrıntılarını ilgili teknik sayfasında tutun. Örneğin, tarayıcı mesajı adayları [PostMessage Vulnerabilities](../pentesting-web/postmessage-vulnerabilities/README.md) sayfasına, token key-selection davranışı ise [JWT Vulnerabilities](../pentesting-web/hacking-jwt-json-web-tokens.md) sayfasına aittir.<sup>[[8]](#references)</sup>

Kısa bir hipotez kaydı, paralel çalışan agent'ların aynı cazip dalı tekrar incelemesini önler:<sup>[[8]](#references)</sup>

```yaml
status: open
hypothesis: "cross-account object access ignores ownership"
evidence: ["requests/user-a.txt", "requests/user-b.txt"]
next_test: "change only the object ID in user A's request"
expected_signal: "user B's object is returned"
falsifier: "server rejects it or returns only user A's object"
```

## Burp MCP ile hedefli out-of-band doğrulama

Burp Suite Professional, resmi MCP eklentisi üzerinden `generate_collaborator_payload` ve `get_collaborator_interactions` sunar. Tüm hedefi taramadan şüpheli bir sunucu tarafı URL fetch işlemini test etmek için bunları `get_proxy_http_history_regex` ve tek bir `send_http1_request` replay işlemiyle birlikte kullanın. Burp, history'yi okumak ve request göndermek için ayrı ayrı onay isteyebilir.<sup>[[2]](#references)[[10]](#references)</sup>

1. `url=`, `webhook` veya `callback` içerenler gibi URL taşıyan olası bir request için history'yi filtreleyin. Orijinal request ve response'u kaydedin. History aracı `regex`, `count` ve `offset` parametrelerini alır; modelden her girdiyi incelemesini istemek yerine sayfalandırma kullanın.<sup>[[10]](#references)</sup>
2. Yeni bir Collaborator payload oluşturun ve döndürülen **payload ID** değerini saklayın. Yakalanan request'i aynı host ve porta replay edin; yalnızca olası URL'yi bu payload domain'i altındaki bir HTTPS URL'siyle değiştirin. `send_http1_request` için `content` olarak eksiksiz HTTP/1.1 request'ini ve ayrıca `targetHostname`, `targetPort` ve `usesHttps` değerlerini sağlayın; hedef alanları Collaborator host'unu değil, **uygulamayı** belirtir.<sup>[[10]](#references)</sup>
3. `get_collaborator_interactions` aracını bu payload ID ile sorgulayın ve interaction zamanını replay ile ilişkilendirin. HTTP interaction'ı fetch işlemini desteklerken yalnızca DNS görülmesi, çözümleme yapıldığını gösterir; tamamlanmış bir HTTP request yapıldığını göstermez. Sunucu egress'ini tarayıcı tarafındaki yüklemeden ayırmak için interaction kaynağını ve request header'larını kontrol edin; ardından ilgisiz trafiği elemek için yeni bir payload ile tekrarlayın.<sup>[[10]](#references)[[11]](#references)</sup>

MCP request aracı response'u doğrudan döndürür ve **Proxy > HTTP history** bölümüne eklemeyebilir. Request/response sonucunu saklayın veya history destekli bir kanıt için proxied browser ya da Repeater kullanın. SSRF payload seçimi ve takip testleri için out-of-band callback'i dahili ağ üzerindeki etkinin kanıtı olarak değerlendirmek yerine [SSRF bölümü](../pentesting-web/ssrf-server-side-request-forgery/)ne bakın. MCP server'ın kendisini test etmek için [MCP server testing](AI-MCP-Servers.md#remote-mcp-server-testing-workflow) bölümüne bakın.<sup>[[7]](#references)[[11]](#references)</sup>

## Pasif inceleme için prompt paketi

**burp-mcp-agents** reposu, Burp trafiğinin kanıta dayalı analizi için prompt şablonları içerir:<sup>[[4]](#references)</sup>

- `passive_hunter.md`: geniş kapsamlı pasif zafiyet tespiti.
- `idor_hunter.md`: IDOR/BOLA/object/tenant sapmaları ve auth uyumsuzlukları.
- `auth_flow_mapper.md`: authenticated ve unauthenticated yolları karşılaştırma.
- `ssrf_redirect_hunter.md`: URL fetch parametreleri/redirect zincirlerinden SSRF/open redirect adaylarını tespit etme.
- `logic_flaw_hunter.md`: çok adımlı logic flaw'lar.
- `session_scope_hunter.md`: token audience/scope kötüye kullanımı.
- `rate_limit_abuse_hunter.md`: throttling/abuse açıkları.
- `report_writer.md`: kanıta odaklı raporlama.

## İsteğe bağlı attribution etiketleme

Burp/LLM trafiğini log'larda etiketlemek için bir header rewrite ekleyin (proxy veya Burp Match/Replace):<sup>[[1]](#references)</sup>

```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```

## Güvenlik notları

- Trafik hassas veriler içerdiğinde **local models** kullanmayı tercih edin.
- Bir bulgu için yalnızca gereken minimum kanıtı paylaşın.
- Burp'ü doğruluk kaynağı olarak kullanın; modeli tarama için değil, **analiz ve raporlama** için kullanın.

## Burp AI Agent (AI destekli triyaj + MCP araçları)

**Burp AI Agent**, local/cloud LLM'leri pasif/aktif analizle (62 güvenlik açığı sınıfı) bir araya getiren ve harici MCP istemcilerinin Burp'ü yönetebilmesi için 53'ten fazla MCP aracı sunan bir Burp eklentisidir.<sup>[[5]](#references)</sup> Öne çıkanlar:

- **Bağlam menüsünden triyaj**: Proxy üzerinden trafiği yakalayın, **Proxy > HTTP History** bölümünü açın, bir isteğe sağ tıklayın → **Extensions > Burp AI Agent > Analyze this request** seçeneğine tıklayarak bu istek/yanıta bağlı bir AI sohbeti başlatın.
- **Arka uçlar** (profil başına seçilebilir):
  - Local HTTP: **Ollama**, **LM Studio**.
  - Remote HTTP: **OpenAI-compatible** uç nokta (base URL + model adı).
  - Cloud CLI'ları: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` veya `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (sağlayıcıya özgü login).
- **Agent profilleri**: prompt şablonları otomatik olarak `~/.burp-ai-agent/AGENTS/` dizinine yüklenir; özel analiz/tarama davranışları eklemek için buraya başka `*.md` dosyaları bırakın.
- **MCP server**: Burp işlemlerini herhangi bir MCP istemcisine sunmak için **Settings > MCP Server** üzerinden etkinleştirin (53'ten fazla araç). Claude Desktop'ı sunucuya yönlendirmek için `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) veya `%APPDATA%\Claude\claude_desktop_config.json` (Windows) dosyasını düzenleyin.
- **Gizlilik denetimleri**: STRICT / BALANCED / OFF ayarları, remote modellere gönderilmeden önce hassas istek verilerini redakte eder; sırlarla çalışırken local arka uçları tercih edin.
- **Denetim günlükleri**: AI/MCP işlemlerinin kurcalamaya karşı kanıt sağlayan izlenebilirliği için her kayıt için SHA-256 bütünlük hash'i içeren JSONL günlükleri.
- **Derleme/yükleme**: release JAR dosyasını indirin veya Java 21 ile derleyin:

```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```

Operasyonel uyarılar: privacy mode uygulanmadığı sürece cloud backend'ler session cookie'lerini/PII'yi dışarı sızdırabilir; MCP'ye erişim, Burp'ün uzaktan orkestrasyonuna olanak tanır. Bu nedenle erişimi güvenilir agent'larla sınırlandırın ve bütünlük hash'iyle korunan audit log'u izleyin.



## References

- [1] [Burp MCP + Codex CLI entegrasyonu ve Caddy handshake düzeltmesi](https://pentestbook.six2dez.com/others/burp)
- [2] [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [PortSwigger MCP server strict Origin/header doğrulama sorunu](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Burp MCP Agents (iş akışları, başlatıcılar, prompt paketi)](https://github.com/six2dez/burp-mcp-agents)
- [5] [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)
- [6] [Microsoft Playwright MCP](https://github.com/microsoft/playwright-mcp)
- [7] [PortSwigger Burp Suite MCP Server](https://github.com/PortSwigger/mcp-server)
- [8] [Bug Bounty araştırmalarında Codex nasıl kullanılır: geniş kapsamlı keşif, titiz doğrulama](https://www.yeswehack.com/learn-bug-bounty/llm-series-codex)
- [9] [OpenBurp: Claude Code ve Codex için Burp Suite orkestrasyonu](https://github.com/luispacheco22/OpenBurp)
- [10] [PortSwigger MCP Server araç uygulamaları ve parametreleri](https://github.com/PortSwigger/mcp-server/blob/main/src/main/kotlin/net/portswigger/mcp/tools/Tools.kt)
- [11] [PortSwigger Web Security Academy - Blind SSRF güvenlik açıkları](https://portswigger.net/web-security/ssrf/blind)
{{#include ../banners/hacktricks-training.md}}
