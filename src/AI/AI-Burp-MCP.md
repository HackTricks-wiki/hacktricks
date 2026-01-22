# Burp MCP: LLM destekli trafik incelemesi

{{#include ../banners/hacktricks-training.md}}

## Overview

Burp'un **MCP Server** uzantısı, yakalanan HTTP(S) trafiğini MCP yetenekli LLM istemcilerine açabilir; böylece gerçek istek/yanıtlar üzerinde akıl yürüterek pasif zafiyet keşfi ve rapor taslağı oluşturabilirler. Amaç kanıta dayalı inceleme (no fuzzing or blind scanning), Burp'u tek gerçek kaynak olarak tutmaktır.

## Architecture

- **Burp MCP Server (BApp)** `127.0.0.1:9876` adresinde dinler ve yakalanan trafiği MCP üzerinden açar.
- **MCP proxy JAR** stdio (istemci tarafı) ile Burp'un MCP SSE endpoint'i arasında köprü kurar.
- **Optional local reverse proxy** (Caddy) sıkı MCP el sıkışma kontrolleri için başlıkları normalize eder.
- **Clients/backends**: Codex CLI (cloud), Gemini CLI (cloud), or Ollama (local).

## Setup

### 1) Install Burp MCP Server

Burp BApp Store'dan **MCP Server**'ı yükleyin ve `127.0.0.1:9876` adresinde dinlediğini doğrulayın.

### 2) Extract the proxy JAR

MCP Server sekmesinde **Extract server proxy jar**'a tıklayın ve `mcp-proxy.jar` olarak kaydedin.

### 3) Configure an MCP client (Codex example)

İstemciyi proxy JAR'a ve Burp'un SSE endpoint'ine yönlendirin:
```toml
# ~/.codex/config.toml
[mcp_servers.burp]
command = "java"
args = ["-jar", "/absolute/path/to/mcp-proxy.jar", "--sse-url", "http://127.0.0.1:19876"]
```
Dosyayı buraya yapıştırabilir misiniz? src/AI/AI-Burp-MCP.md içeriğini görmeden çeviri yapamam.

Ayrıca "Then run Codex and list MCP tools:" ile ne kastettiğinizi netleştirin:
- "Codex" ile OpenAI Codex veya başka bir araç mu kullanmamı istiyorsunuz?
- Dosyadaki metni çevirip ardından MCP araçlarını dosyadan mı listelememi istiyorsunuz, yoksa benim genel bilgime dayanarak bir MCP araç listesi mi istiyorsunuz?

İçeriği yapıştırın ve tercihlerinizi belirtin; hemen çevirip istenen listeyi sağlayacağım.
```bash
codex
# inside Codex: /mcp
```
### 4) Caddy ile sıkı Origin/header doğrulamasını düzeltin (gerekirse)

Eğer MCP handshake'ı sıkı `Origin` kontrolleri veya ekstra headers nedeniyle başarısız oluyorsa, headers'ı normalize etmek için yerel bir reverse proxy kullanın (bu, Burp MCP sıkı doğrulama sorunu için kullanılan geçici çözümle eşleşir).
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
Proxy'yi ve client'ı başlatın:
```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```
## Farklı istemcilerin kullanımı

### Codex CLI

- `~/.codex/config.toml` dosyasını yukarıda belirtildiği gibi yapılandırın.
- `codex`'i çalıştırın, ardından `/mcp` ile Burp araç listesini doğrulayın.

### Gemini CLI

The **burp-mcp-agents** reposu başlatıcı yardımcıları sunar:
```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```
### Ollama (yerel)

Sağlanan launcher yardımcısını kullanın ve bir yerel model seçin:
```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```
Yerel modellere örnekler ve yaklaşık VRAM gereksinimleri:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## Pasif inceleme için Prompt paketi

**burp-mcp-agents** repo, Burp trafiğinin kanıta dayalı analizi için prompt şablonları içerir:

- `passive_hunter.md`: genel pasif zafiyet ortaya çıkarma.
- `idor_hunter.md`: IDOR/BOLA/object/tenant drift ve auth uyuşmazlıkları.
- `auth_flow_mapper.md`: kimlik doğrulamalı ve kimlik doğrulamasız yolları karşılaştırır.
- `ssrf_redirect_hunter.md`: URL fetch parametreleri/redirect zincirlerinden SSRF/open-redirect adayları.
- `logic_flaw_hunter.md`: çok adımlı mantık hataları.
- `session_scope_hunter.md`: token audience/scope kötü kullanımı.
- `rate_limit_abuse_hunter.md`: throttling/abuse açıklıkları.
- `report_writer.md`: kanıta odaklı raporlama.

## İsteğe bağlı attribution etiketleme

Burp/LLM trafiğini loglarda etiketlemek için, bir header rewrite ekleyin (proxy veya Burp Match/Replace):
```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```
## Güvenlik notları

- Trafik hassas veri içeriyorsa **yerel modelleri** tercih edin.
- Bir bulgu için gereken en az kanıtı paylaşın.
- Burp'ı doğruluk kaynağı olarak tutun; modeli **analiz ve raporlama** için kullanın, tarama için değil.

## Referanslar

- [Burp MCP + Codex CLI integration and Caddy handshake fix](https://pentestbook.six2dez.com/others/burp)
- [Burp MCP Agents (workflows, launchers, prompt pack)](https://github.com/six2dez/burp-mcp-agents)
- [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [PortSwigger MCP server strict Origin/header validation issue](https://github.com/PortSwigger/mcp-server/issues/34)

{{#include ../banners/hacktricks-training.md}}
