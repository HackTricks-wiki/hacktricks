# Burp MCP: LLM destekli trafik incelemesi

{{#include ../banners/hacktricks-training.md}}

## Genel Bakış

Burp'ın **MCP Server** eklentisi, ele geçirilen HTTP(S) trafiğini MCP destekli LLM istemcilerine sunarak güvenlik açıklarını keşfetmek ve rapor taslakları hazırlamak için **gerçek istekler/yanıtlar üzerinde akıl yürütmelerini** sağlayabilir. Gerçeğin kaynağı olarak Burp'ı kullanın: körlemesine tarama yapmak yerine pasif analiz veya tek değişkenli, bilinçli tekrarlar tercih edin.<sup>[[8]](#references)</sup>

## Mimari

- **Burp MCP Server (BApp)** varsayılan olarak `127.0.0.1:9876` adresini dinler ve ele geçirilen trafiği MCP üzerinden sunar.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- **MCP proxy JAR**, stdio'yu (istemci tarafı) Burp'ın MCP SSE uç noktasına bağlar.
- **İsteğe bağlı yerel reverse proxy** (Caddy), katı MCP handshake kontrolleri için header'ları standartlaştırır.
- **İstemciler/backend'ler**: Codex CLI (cloud), Gemini CLI (cloud) veya Ollama (yerel).

## Kurulum

### 1) Burp MCP Server'ı yükleyin

Burp BApp Store'dan **MCP Server**'ı yükleyin ve `127.0.0.1:9876` adresini dinlediğini doğrulayın.<sup>[[1]](#references)[[2]](#references)</sup>

### 2) Proxy JAR'ı çıkarın

MCP Server sekmesinde **Extract server proxy jar** seçeneğine tıklayın ve `mcp-proxy-all.jar` dosyasını kaydedin.<sup>[[7]](#references)</sup>

### 3) Bir MCP istemcisi yapılandırın (Codex örneği)

İstemciyi proxy JAR'a ve Burp'ın doğrudan SSE uç noktasına yönlendirin. Paketlenmiş proxy, stdio'dan SSE'ye köprü görevi görür; Burp listener'ının yerini almaz.<sup>[[7]](#references)</sup>

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

### 4) Gerekirse Caddy ile katı Origin/header doğrulamasını düzeltin

MCP handshake katı `Origin` kontrolleri veya ek header'lar nedeniyle başarısız olursa, header'ları normalize etmek için yerel bir reverse proxy kullanın (bu, Burp MCP katı doğrulama sorununa yönelik geçici çözümle aynıdır).<sup>[[1]](#references)[[3]](#references)</sup>

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

Proxy'yi ve client'ı başlatın ve yapılandırılmış `--sse-url` değerini yalnızca şu Caddy listener'ını kullanırken `http://127.0.0.1:19876` olarak değiştirin:<sup>[[1]](#references)[[3]](#references)</sup>

```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```

### 5) Tarayıcı durumunu proxy kanıtıyla eşleştirin (Playwright MCP)

Playwright MCP'yi, tarayıcısı Burp proxy'sini kullanacak şekilde yapılandırın. Böylece agent, oluşturulan DOM/erişilebilirlik durumunu buna yol açan tam HTTP geçmişiyle ilişkilendirebilir.<sup>[[6]](#references)[[8]](#references)</sup>

```bash
codex mcp add playwright -- npx -y @playwright/mcp@latest \
  --proxy-server=http://127.0.0.1:8080 \
  --ignore-https-errors
```

Dinleyici adresini uyarlayın, Codex'i yeniden başlatın ve her iki entegrasyonu da doğrulamak için `/mcp` kullanın. Örnek, HTTPS trafiğinin Burp tarafından yerel olarak oluşturulan sertifika nedeniyle engellenmemesi için tarayıcı sertifika hatalarını devre dışı bırakır.<sup>[[6]](#references)[[8]](#references)</sup>

## Proxy'yi kullanan tarayıcı otomasyonu (OpenBurp)

Burp MCP bağlantısı ile araya girilen tarayıcı yolu ayrı veri akışlarıdır. MCP hizmeti Burp araçlarını `127.0.0.1:9876` adresinde sunarken, özel bir Chromium örneği HTTP(S) trafiğini Burp'un `127.0.0.1:8080` adresindeki proxy'si üzerinden gönderir. Bu nedenle doğrudan bir MCP aracı tarafından oluşturulan istekler **Proxy > HTTP history** bölümünde görünmeyebilir; isteğin/yanıtın gözlemlenebilir, düzenlenebilir veya kanıt olarak saklanabilir olması gerekiyorsa proxy kullanan tarayıcıyı kullanın.<sup>[[2]](#references)[[9]](#references)</sup>

SSE desteği olan bir istemci Burp'u doğrudan kaydedebilir. Yalnızca stdio destekleyen bir istemci bunun yerine PortSwigger'ın proxy JAR dosyasını başlatabilir. Her iki durumda da ikinci bir tarayıcı denetimi MCP'si kaydedin ve bunu Burp'un gömülü Chromium'una yönlendirin (`BURP_CHROMIUM` yerel bir çalıştırılabilir dosya yoludur):<sup>[[9]](#references)</sup>

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

TLS-bypass flag, interception proxy tarafından oluşturulan sertifikaları kabul ederken `--isolated`, değerlendirmenin operatörün normal browser profilini yeniden kullanmasını önler. İzolasyon, profil durumunu korur ancak **bir güvenlik sandbox'ı değildir**: controller, bu test browser'ında açılan kimliği doğrulanmış oturumlara erişebilir ve Burp MCP hassas istekleri, yanıtları ve yapılandırmayı açığa çıkarabilir.<sup>[[9]](#references)</sup>

Client bridge'de hata ayıklamadan önce SSE listener'ı bağımsız olarak test edin:<sup>[[9]](#references)</sup>

```bash
curl -i --max-time 3 http://127.0.0.1:9876/
```

Sağlıklı bir listener `Content-Type: text/event-stream` döndürür. Başlıklardan sonra zaman aşımı oluşması beklenen bir durumdur; çünkü bir SSE stream gelecekteki event'ler için açık kalır. İstemci hâlâ başarısız oluyorsa extension'ın yapılandırılmış route'unu doğrulayın: PortSwigger, endpoint'in istemciye ve extension yapılandırmasına bağlı olarak kök path veya `/sse` olabileceğini belirtiyor.<sup>[[9]](#references)[[7]](#references)</sup>

## Farklı istemcileri kullanma

### Codex CLI

- `~/.codex/config.toml` dosyasını yukarıdaki gibi yapılandırın.
- `codex` komutunu çalıştırın, ardından Burp araçları listesini doğrulamak için `/mcp` komutunu kullanın.

### Gemini CLI

**burp-mcp-agents** repo'su başlatıcı yardımcıları sağlar:<sup>[[4]](#references)</sup>

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

## Kanıta dayalı replay ve doğrulama

Ajanın makul görünen bir açıklamayı veya ara yanıtı kanıt olarak değerlendirmesine izin vermeyin. Her testi yanlışlanabilir kılmak için Burp isteklerini/yanıtlarını ve bağımsız olarak gözlemlenen tarayıcı durumunu kullanın.<sup>[[8]](#references)</sup>

1. Bir temel istek/yanıt çiftini kaydedin ve saldırganın kontrolündeki bileşeni tam olarak belirleyin.
2. Yetkilendirme karşılaştırmaları için tanımlayıcıları, çerezleri veya token'ları değiştirmeden önce aynı iş akışını her iki hesapta da bağımsız olarak yakalayın.
3. Bir değişikliği replay etmeden önce hipotezi, kanıtın bulunduğu konumu, beklenen sinyali ve hipotezi çürütecek sonucu kaydedin.
4. Her seferinde tek bir bileşeni değiştirin, ortaya çıkan çifti koruyun ve doğrudan gözlemleri çıkarımlardan ayrı olarak etiketleyin.
5. Her adayı `open`, `blocked`, `rejected` veya `confirmed` olarak izleyin; adayı yalnızca yeni kanıt mekanizmayı veya ön koşullardan birini değiştirdiğinde yeniden ele alın.
6. Saldırganın kontrolünü, erişilebilirliği, tekrarlanabilirliği, kısıtlamanın aşılmasını, etkiyi ve uygulamanın son durumunu doğrulayın. İddia edilen durum değişikliği sonraki bir aşamada gerçekleşiyorsa, yönlendirme veya başarılı bir araç çağrısı kanıt sayılmaz.

Exploitation ayrıntılarını ilgili teknik sayfasında tutun. Örneğin, browser-message adayları [PostMessage Vulnerabilities](../pentesting-web/postmessage-vulnerabilities/README.md) sayfasına; token key-selection davranışı ise [JWT Vulnerabilities](../pentesting-web/hacking-jwt-json-web-tokens.md) sayfasına aittir.<sup>[[8]](#references)</sup>

Kısa bir hipotez kaydı, paralel çalışan ajanların aynı cazip yolu tekrar tekrar denemesini önler:<sup>[[8]](#references)</sup>

```yaml
status: open
hypothesis: "cross-account object access ignores ownership"
evidence: ["requests/user-a.txt", "requests/user-b.txt"]
next_test: "change only the object ID in user A's request"
expected_signal: "user B's object is returned"
falsifier: "server rejects it or returns only user A's object"
```

## Burp MCP ile WebSocket frame triyajı

Resmi extension, Burp'ın WebSocket history kayıtlarında salt okunur, sayfalandırılmış aramalar için `get_proxy_websocket_history_regex` aracını sunar. Araç `regex`, `count` ve `offset` değerlerini alır; `send_http1_request`'ten farklı olarak WebSocket frame göndermez. Intercept kapalıyken bile Burp her iki yöndeki mesajı kaydeder. Bu nedenle modele az sayıda ilgili frame sunmadan önce history kayıtlarını filtreleyin.<sup>[[10]](#references)[[12]](#references)[[13]](#references)</sup>

1. Burp proxy'sinden geçen tarayıcıda aynı WebSocket destekli eylemi, bağımsız olarak kimliği doğrulanmış iki test hesabıyla gerçekleştirin. Her upgrade handshake'i ve cookie'lerini, connection ID'yi, frame yönünü ve response frame'lerini birlikte tutun. İlk hesabın connection'ındaki server-to-client event, ikinci hesabın bunu aldığına kanıt değildir.
2. `get_proxy_websocket_history_regex` aracında `(?i)(subscribe|room|tenant|objectId)` gibi dar kapsamlı bir ifade, `count: 20` ve `offset: 0` ile arama yapın. Daha sonraki eşleşmeleri incelemek için `offset` değerini artırın. Giden frame'deki object veya topic identifier'ı, **aynı connection** üzerindeki response ile karşılaştırın.
3. **Proxy > WebSockets history** bölümünde aday giden frame'i Repeater'a gönderin. Frame'i uygun açık connection'a ekleyin veya ikinci hesabın handshake'iyle yeniden bağlanın. Yalnızca object/topic identifier'ı değiştirin ve ortaya çıkan server mesajlarını ve application state'i her iki baseline ile karşılaştırın. MCP history aracı bu replay işlemini yapamaz; WebSocket Repeater frame'leri düzenleyebilir, yeniden gönderebilir ve yeniden bağlanabilir.

Cross-site WebSocket hijacking ve broker topic authorization gibi protokole özgü testler için [WebSocket Attacks](../pentesting-web/websocket-attacks.md) bölümüne bakın. Başarılı bir upgrade'i veya client-side echo'yu, korumalı bir subscription'ın başarılı olduğuna kanıt olarak değerlendirmeyin.

## Burp MCP ile hedefli out-of-band doğrulama

Burp Suite Professional, resmi MCP extension üzerinden `generate_collaborator_payload` ve `get_collaborator_interactions` araçlarını sunar. Bunları `get_proxy_http_history_regex` ve tek bir `send_http1_request` replay'i ile birleştirerek tüm hedefi taramadan, şüpheli bir server-side URL fetch işlemini test edin. Burp, history'yi okuma ve request gönderme için ayrı onaylar gerektirebilir.<sup>[[2]](#references)[[10]](#references)</sup>

1. `url=`, `webhook` veya `callback` içerenler gibi URL taşıyan aday bir request için history'de filtreleme yapın. Orijinal request ve response'u kaydedin. History aracı `regex`, `count` ve `offset` değerlerini alır; modelden her girdiyi incelemesini istemek yerine sayfalandırma kullanın.<sup>[[10]](#references)</sup>
2. Yeni bir Collaborator payload oluşturun ve döndürülen **payload ID**'yi saklayın. Yakalanan request'i aynı host ve port'a replay edin; yalnızca aday URL'yi bu payload domain'i altında bir HTTPS URL'siyle değiştirin. `send_http1_request` için `content` olarak HTTP/1.1 request'in tamamını, ayrıca `targetHostname`, `targetPort` ve `usesHttps` değerlerini gönderin; hedef alanları Collaborator host'unu değil, **application**'ı belirtir.<sup>[[10]](#references)</sup>
3. Payload ID ile `get_collaborator_interactions` aracını sorgulayın ve etkileşim zamanını replay ile ilişkilendirin. Bir HTTP etkileşimi fetch işlemini destekler; yalnızca DNS görülmesi, çözümleme olduğunu gösterir ancak tamamlanmış bir HTTP request'ini kanıtlamaz. Server egress'i browser-side loading'den ayırt etmek için etkileşim kaynağını ve request header'larını inceleyin; ardından ilgisiz trafiği elemek için yeni bir payload ile tekrarlayın.<sup>[[10]](#references)[[11]](#references)</sup>

MCP request aracı response'u doğrudan döndürür; **Proxy > HTTP history**'yi doldurması gerekmez. Request/response sonucunu saklayın veya history'ye dayalı bir kanıt elde etmek için proxied browser ya da Repeater kullanın. SSRF payload seçimi ve devam testleri için, out-of-band callback'i dahili ağ üzerindeki etkiye kanıt saymak yerine [SSRF chapter](../pentesting-web/ssrf-server-side-request-forgery/) bölümüne bakın. MCP server'ın kendisini test etmek için [MCP server testing](AI-MCP-Servers.md#remote-mcp-server-testing-workflow) bölümüne bakın.<sup>[[7]](#references)[[11]](#references)</sup>

## Pasif inceleme için prompt paketi

**burp-mcp-agents** repo'su, Burp trafiğinin kanıta dayalı analizi için prompt şablonları içerir:<sup>[[4]](#references)</sup>

- `passive_hunter.md`: geniş kapsamlı pasif vulnerability tespiti.
- `idor_hunter.md`: IDOR/BOLA/object/tenant farklılıkları ve auth uyuşmazlıkları.
- `auth_flow_mapper.md`: kimliği doğrulanmış ve doğrulanmamış yolları karşılaştırma.
- `ssrf_redirect_hunter.md`: URL fetch parametrelerinden ve redirect zincirlerinden SSRF/open redirect adaylarını belirleme.
- `logic_flaw_hunter.md`: çok adımlı logic flaw'lar.
- `session_scope_hunter.md`: token audience/scope'un kötüye kullanımı.
- `rate_limit_abuse_hunter.md`: throttling/abuse açıkları.
- `report_writer.md`: kanıta odaklı raporlama.

## İsteğe bağlı ilişkilendirme etiketleme

Log'larda Burp/LLM trafiğini etiketlemek için bir header rewrite ekleyin (proxy veya Burp Match/Replace):<sup>[[1]](#references)</sup>

```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```

## Güvenlik notları

- Trafik hassas veriler içeriyorsa **local models** tercih edin.
- Bir bulgu için yalnızca gereken minimum kanıtı paylaşın.
- Burp'ü tek doğruluk kaynağı olarak tutun; modeli tarama için değil, **analiz ve raporlama** için kullanın.

## Burp AI Agent (AI destekli triage + MCP araçları)

**Burp AI Agent**, local/cloud LLM'leri pasif/aktif analizle (62 güvenlik açığı sınıfı) birleştiren ve harici MCP istemcilerinin Burp'ü yönetebilmesi için 53'ten fazla MCP aracı sunan bir Burp extension'dır.<sup>[[5]](#references)</sup> Öne çıkanlar:

- **Bağlam menüsünden triage**: Proxy üzerinden trafiği yakalayın, **Proxy > HTTP History**'yi açın, bir isteğe sağ tıklayın → **Extensions > Burp AI Agent > Analyze this request** seçeneğine tıklayarak ilgili istek/yanıta bağlı bir AI sohbeti başlatın.
- **Backends** (profile göre seçilebilir):
  - Local HTTP: **Ollama**, **LM Studio**.
  - Remote HTTP: **OpenAI-compatible** endpoint (base URL + model adı).
  - Cloud CLIs: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` veya `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (sağlayıcıya özel login).
- **Agent profilleri**: prompt şablonları otomatik olarak `~/.burp-ai-agent/AGENTS/` dizinine yüklenir; özel analiz/tarama davranışları eklemek için buraya başka `*.md` dosyaları bırakın.
- **MCP server**: Burp işlemlerini herhangi bir MCP istemcisine sunmak için **Settings > MCP Server** üzerinden etkinleştirin (53'ten fazla araç). Claude Desktop'ı sunucuya bağlamak için `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) veya `%APPDATA%\Claude\claude_desktop_config.json` (Windows) dosyasını düzenleyin.
- **Gizlilik kontrolleri**: STRICT / BALANCED / OFF, uzak modellere gönderilmeden önce hassas istek verilerini maskeler; gizli bilgilerle çalışırken local backends tercih edin.
- **Denetim günlükleri**: AI/MCP eylemlerinin değişiklik yapıldığını ortaya koyan izlenebilirliği için her kayıt için SHA-256 bütünlük hash'i içeren JSONL günlükleri.
- **Build/load**: release JAR'ını indirin veya Java 21 ile build edin:

```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```

Operasyonel uyarılar: gizlilik modu zorunlu tutulmazsa bulut arka uçları oturum çerezlerini/PII'yi sızdırabilir; MCP'ye erişim, Burp'ün uzaktan orkestrasyonuna izin verir. Bu nedenle erişimi güvenilir agent'larla sınırlandırın ve bütünlük hash'iyle korunan denetim günlüğünü izleyin.



## References

- [1] [Burp MCP + Codex CLI entegrasyonu ve Caddy handshake düzeltmesi](https://pentestbook.six2dez.com/others/burp)
- [2] [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [PortSwigger MCP server katı Origin/header doğrulama sorunu](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Burp MCP Agents (iş akışları, başlatıcılar, prompt paketi)](https://github.com/six2dez/burp-mcp-agents)
- [5] [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)
- [6] [Microsoft Playwright MCP](https://github.com/microsoft/playwright-mcp)
- [7] [PortSwigger Burp Suite MCP Server](https://github.com/PortSwigger/mcp-server)
- [8] [Bug Bounty araştırması için Codex nasıl kullanılır: geniş kapsamlı keşif, titiz doğrulama](https://www.yeswehack.com/learn-bug-bounty/llm-series-codex)
- [9] [OpenBurp: Claude Code ve Codex için Burp Suite orkestrasyonu](https://github.com/luispacheco22/OpenBurp)
- [10] [PortSwigger MCP Server araç uygulamaları ve parametreleri](https://github.com/PortSwigger/mcp-server/blob/main/src/main/kotlin/net/portswigger/mcp/tools/Tools.kt)
- [11] [PortSwigger Web Security Academy - Blind SSRF açıkları](https://portswigger.net/web-security/ssrf/blind)
- [12] [PortSwigger - WebSockets geçmişi](https://portswigger.net/burp/documentation/desktop/tools/proxy/websockets-history)
- [13] [PortSwigger - Burp Repeater'da WebSocket mesajlarıyla çalışma](https://portswigger.net/burp/documentation/desktop/tools/repeater/websocket-messages)
{{#include ../banners/hacktricks-training.md}}
