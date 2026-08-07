# Burp MCP: LLM destekli trafik incelemesi

{{#include ../banners/hacktricks-training.md}}

## Genel Bakış

Burp'ın **MCP Server** extension'ı, intercept edilen HTTP(S) trafiğini MCP destekli LLM istemcilerine sunarak bu istemcilerin **gerçek request/response'lar üzerinde akıl yürütmesini**, pasif vulnerability discovery ve report drafting işlemlerini gerçekleştirmesini sağlar. Amaç, Burp'ı doğruluk kaynağı olarak tutarak evidence-driven review gerçekleştirmektir (fuzzing veya blind scanning yoktur).

## Mimari

- **Burp MCP Server (BApp)** `127.0.0.1:9876` adresini dinler ve intercept edilen trafiği MCP üzerinden sunar.<sup>[[1]](#references)[[2]](#references)</sup>
- **MCP proxy JAR**, stdio'yu (client tarafı) Burp'ın MCP SSE endpoint'ine bağlar.
- **İsteğe bağlı local reverse proxy** (Caddy), strict MCP handshake kontrolleri için header'ları normalize eder.
- **Client/backend'ler**: Codex CLI (cloud), Gemini CLI (cloud) veya Ollama (local).

## Kurulum

### 1) Burp MCP Server'ı yükleme

Burp BApp Store'dan **MCP Server**'ı yükleyin ve `127.0.0.1:9876` adresini dinlediğini doğrulayın.<sup>[[1]](#references)[[2]](#references)</sup>

### 2) Proxy JAR'ı çıkarma

MCP Server sekmesinde **Extract server proxy jar** seçeneğine tıklayın ve `mcp-proxy.jar` olarak kaydedin.

### 3) Bir MCP client yapılandırma (Codex örneği)

Client'ı proxy JAR'a ve Burp'ın SSE endpoint'ine yönlendirin:
```toml
# ~/.codex/config.toml
[mcp_servers.burp]
command = "java"
args = ["-jar", "/absolute/path/to/mcp-proxy.jar", "--sse-url", "http://127.0.0.1:19876"]
```
Ardından Codex'i çalıştırın ve MCP araçlarını listeleyin:
```bash
codex
# inside Codex: /mcp
```
### 4) Gerekirse Caddy ile katı Origin/header validation sorununu düzeltme

MCP handshake, katı `Origin` kontrolleri veya ek header'lar nedeniyle başarısız olursa, header'ları normalize etmek için yerel bir reverse proxy kullanın (bu, Burp MCP strict validation sorunu için uygulanan workaround ile aynıdır).<sup>[[1]](#references)[[3]](#references)</sup>
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
## Farklı client'ları kullanma

### Codex CLI

- `~/.codex/config.toml` dosyasını yukarıdaki gibi yapılandırın.
- `codex` komutunu çalıştırın, ardından Burp araçları listesini doğrulamak için `/mcp` komutunu kullanın.

### Gemini CLI

**burp-mcp-agents** repo'su launcher yardımcıları sağlar:<sup>[[4]](#references)</sup>
```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```
### Ollama (yerel)

Sağlanan launcher helper'ı kullanın ve yerel bir model seçin:
```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```
Örnek local modeller ve yaklaşık VRAM gereksinimleri:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## Passive review için prompt paketi

**burp-mcp-agents** repo'su, Burp traffic için evidence-driven analysis prompt şablonları içerir:<sup>[[4]](#references)</sup>

- `passive_hunter.md`: kapsamlı passive vulnerability tespiti.
- `idor_hunter.md`: IDOR/BOLA/object/tenant drift ve auth uyumsuzlukları.
- `auth_flow_mapper.md`: authenticated ve unauthenticated path'leri karşılaştırır.
- `ssrf_redirect_hunter.md`: URL fetch parametreleri ve redirect chain'lerinden SSRF/open-redirect adayları.
- `logic_flaw_hunter.md`: çok adımlı logic flaw'lar.
- `session_scope_hunter.md`: token audience/scope kötüye kullanımı.
- `rate_limit_abuse_hunter.md`: throttling/abuse açıkları.
- `report_writer.md`: evidence-focused reporting.

## İsteğe bağlı attribution tagging

Log'larda Burp/LLM traffic'ini tag'lemek için bir header rewrite ekleyin (proxy veya Burp Match/Replace):<sup>[[1]](#references)</sup>
```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```
## Güvenlik notları

- Trafik hassas veriler içerdiğinde **local models** kullanmayı tercih edin.
- Bir bulgu için yalnızca gereken minimum kanıtı paylaşın.
- Burp'ü gerçek kaynak olarak tutun; modeli scanning için değil, **analysis and reporting** amacıyla kullanın.

## Burp AI Agent (AI destekli triage + MCP tools)

**Burp AI Agent**, local/cloud LLM'leri pasif/aktif analysis (62 zafiyet sınıfı) ile birleştiren ve harici MCP client'ların Burp'ü yönetebilmesi için 53+ MCP tools sunan bir Burp extension'dır.<sup>[[5]](#references)</sup> Öne çıkanlar:

- **Context-menu triage**: Proxy üzerinden trafiği yakalayın, **Proxy > HTTP History**'yi açın, bir request'e sağ tıklayın → **Extensions > Burp AI Agent > Analyze this request** seçeneğine tıklayarak bu request/response'a bağlı bir AI chat başlatın.
- **Backends** (profil başına seçilebilir):
- Local HTTP: **Ollama**, **LM Studio**.
- Remote HTTP: **OpenAI-compatible** endpoint (base URL + model name).
- Cloud CLIs: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` veya `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (provider-specific login).
- **Agent profiles**: prompt templates otomatik olarak `~/.burp-ai-agent/AGENTS/` altına yüklenir; özel analysis/scanning davranışları eklemek için buraya ilave `*.md` dosyaları bırakın.
- **MCP server**: Burp işlemlerini herhangi bir MCP client'a sunmak için **Settings > MCP Server** üzerinden etkinleştirin (53+ tools). Claude Desktop, macOS'ta `~/Library/Application Support/Claude/claude_desktop_config.json` veya Windows'ta `%APPDATA%\Claude\claude_desktop_config.json` dosyası düzenlenerek bu server'a yönlendirilebilir.
- **Privacy controls**: STRICT / BALANCED / OFF, remote models'a gönderilmeden önce hassas request verilerini redact eder; secret'larla çalışırken local backends kullanmayı tercih edin.
- **Audit logging**: AI/MCP işlemlerinin müdahale edildiğinin anlaşılmasını sağlayan izlenebilirlik için, her kayıt için SHA-256 integrity hashing içeren JSONL logları.
- **Build/load**: release JAR'ı indirin veya Java 21 ile build edin:
```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```
Operasyonel dikkat: cloud backends, privacy mode zorunlu kılınmadığı sürece session cookie'lerini/PII'yi exfiltrate edebilir; MCP exposure, Burp'un uzaktan orchestration'ını mümkün kılar. Bu nedenle erişimi trusted agents ile sınırlayın ve integrity-hashed audit log'un bütünlüğünü izleyin.

## Referanslar

- [1] [Burp MCP + Codex CLI entegrasyonu ve Caddy handshake düzeltmesi](https://pentestbook.six2dez.com/others/burp)
- [2] [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [PortSwigger MCP server strict Origin/header doğrulama sorunu](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Burp MCP Agents (workflows, launchers, prompt pack)](https://github.com/six2dez/burp-mcp-agents)
- [5] [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)

{{#include ../banners/hacktricks-training.md}}
