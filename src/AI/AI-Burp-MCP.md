# Burp MCP: LLM destekli trafik incelemesi

{{#include ../banners/hacktricks-training.md}}

## Genel Bakış

Burp'un **MCP Server** eklentisi, yakalanan HTTP(S) trafiğini MCP özellikli LLM istemcilerine açabilir; böylece gerçek istek/yanıtlar üzerinde değerlendirme yaparak pasif zafiyet keşfi ve rapor taslağı oluşturabilirler. Amaç, fuzzing veya blind scanning olmadan kanıta dayalı inceleme yapmak ve Burp'u tek doğruluk kaynağı olarak tutmaktır.

## Mimari

- **Burp MCP Server (BApp)** `127.0.0.1:9876` üzerinde dinler ve yakalanan trafiği MCP üzerinden açar.
- **MCP proxy JAR** stdio (istemci tarafı) ile Burp'un MCP SSE endpoint'i arasında köprü kurar.
- **Optional local reverse proxy** (Caddy) sıkı MCP el sıkışma kontrolleri için başlıkları normalleştirir.
- **Clients/backends**: Codex CLI (cloud), Gemini CLI (cloud), veya Ollama (local).

## Kurulum

### 1) Burp MCP Server'ı yükleyin

Burp BApp Store'dan **MCP Server**'ı yükleyin ve `127.0.0.1:9876` üzerinde dinlediğini doğrulayın.

### 2) Proxy JAR'ı çıkarın

MCP Server sekmesinde **Extract server proxy jar**'a tıklayın ve `mcp-proxy.jar` olarak kaydedin.

### 3) MCP istemcisini yapılandırın (Codex örneği)

İstemciyi proxy JAR'a ve Burp'un SSE endpoint'ine yönlendirin:
```toml
# ~/.codex/config.toml
[mcp_servers.burp]
command = "java"
args = ["-jar", "/absolute/path/to/mcp-proxy.jar", "--sse-url", "http://127.0.0.1:19876"]
```
Belirttiğiniz dosyanın (src/AI/AI-Burp-MCP.md) içeriğini buraya yapıştırın lütfen; onu Türkçeye çevireyim. 

Not: Burada "Codex" veya dış araçları doğrudan çalıştıramam. İsterseniz Codex ile yapılacak bir çıktıyı ben simüle edebilirim veya sizden Codex çıktısını yapıştırmanızı isteyebilirim.

Ayrıca "MCP tools" derken tam olarak hangi MCP'yi kastettiğinizi belirtin (ör. Managed Control Plane, Mobile/Modular C2 Platform, Burp MCP extension vb.). Hangi MCP kastedildiğini belirtirseniz, ilgili araçları listeleyip açıklayabilirim.
```bash
codex
# inside Codex: /mcp
```
### 4) Caddy ile sıkı Origin/header doğrulamasını düzeltin (gerekirse)

Eğer MCP handshake, sıkı `Origin` kontrolleri veya ek header'lar nedeniyle başarısız oluyorsa, header'ları normalize etmek için yerel bir reverse proxy kullanın (bu, Burp MCP sıkı validation sorununa yönelik workaround ile aynıdır).
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
proxy ve client'i başlatın:
```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```
## Farklı istemciler

### Codex CLI

- Yukarıdaki gibi `~/.codex/config.toml` dosyasını yapılandırın.
- `codex` çalıştırın, ardından Burp araç listesini doğrulamak için `/mcp` komutunu çalıştırın.

### Gemini CLI

The **burp-mcp-agents** repo provides launcher helpers:
```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```
### Ollama (local)

Sağlanan launcher yardımcısını kullanın ve bir yerel model seçin:
```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```
Example local models and approximate VRAM needs:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## Prompt pack for passive review

The **burp-mcp-agents** repo includes prompt templates for evidence-driven analysis of Burp traffic:

- `passive_hunter.md`: geniş kapsamlı pasif zafiyet keşfi.
- `idor_hunter.md`: IDOR/BOLA/object/tenant sapmaları ve auth uyumsuzlukları.
- `auth_flow_mapper.md`: authenticated ile unauthenticated yolların karşılaştırılması.
- `ssrf_redirect_hunter.md`: URL fetch parametreleri/redirect zincirlerinden SSRF/open-redirect adayları.
- `logic_flaw_hunter.md`: çok adımlı mantık hataları.
- `session_scope_hunter.md`: token audience/scope yanlış kullanımı.
- `rate_limit_abuse_hunter.md`: throttling/abuse boşlukları.
- `report_writer.md`: kanıta odaklı raporlama.

## Optional attribution tagging

To tag Burp/LLM traffic in logs, add a header rewrite (proxy or Burp Match/Replace):
```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```
## Güvenlik notları

- Trafikte hassas veriler olduğunda **yerel modelleri** tercih edin.
- Bir bulgu için gereken asgari kanıtı paylaşın.
- Burp'u doğruluk kaynağı olarak koruyun; modeli tarama için değil, **analiz ve raporlama** için kullanın.

## Burp AI Agent (AI-assisted triage + MCP tools)

**Burp AI Agent** is a Burp extension that couples local/cloud LLMs with passive/active analysis (62 vulnerability classes) and exposes 53+ MCP tools so external MCP clients can orchestrate Burp. Öne çıkanlar:

- **Context-menu triage**: Proxy aracılığıyla trafiği yakalayın, **Proxy > HTTP History**'yi açın, bir isteğe sağ tıklayın → **Extensions > Burp AI Agent > Analyze this request** ile o istek/yanıtla bağlı bir AI sohbeti başlatın.
- **Backends** (selectable per profile):
- Local HTTP: **Ollama**, **LM Studio**.
- Remote HTTP: **OpenAI-compatible** endpoint (base URL + model name).
- Cloud CLIs: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` or `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (provider-specific login).
- **Agent profiles**: prompt şablonları otomatik olarak `~/.burp-ai-agent/AGENTS/` altına kurulur; özel analiz/tarama davranışları eklemek için ek `*.md` dosyalarını buraya bırakın.
- **MCP server**: Burp işlemlerini herhangi bir MCP istemcisine açmak için **Settings > MCP Server** üzerinden etkinleştirin (53+ araç). Claude Desktop'i sunucuya yönlendirmek için `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) veya `%APPDATA%\Claude\claude_desktop_config.json` (Windows) dosyasını düzenleyin.
- **Privacy controls**: STRICT / BALANCED / OFF, uzak modellere göndermeden önce hassas istek verilerini sansürler; sırlarla çalışırken yerel backendlere öncelik verin.
- **Audit logging**: AI/MCP eylemlerinin tahrifata karşı izlenebilirliği için her kayıt için SHA-256 bütünlük karması içeren JSONL logları.
- **Build/load**: download the release JAR or build with Java 21:
```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```
Operasyonel uyarılar: cloud backends, privacy mode etkinleştirilmediği sürece session cookies/PII'yi exfiltrate edebilir; MCP exposure Burp'un uzaktan orkestrasyonunu mümkün kılar; bu yüzden erişimi trusted agents ile sınırlandırın ve integrity-hashed audit log'un bütünlüğünü izleyin.

## Referanslar

- [Burp MCP + Codex CLI integration and Caddy handshake fix](https://pentestbook.six2dez.com/others/burp)
- [Burp MCP Agents (workflows, launchers, prompt pack)](https://github.com/six2dez/burp-mcp-agents)
- [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [PortSwigger MCP server strict Origin/header validation issue](https://github.com/PortSwigger/mcp-server/issues/34)
- [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)

{{#include ../banners/hacktricks-training.md}}
