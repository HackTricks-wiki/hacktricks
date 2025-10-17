# AI Ajan Kötüye Kullanımı: Yerel AI CLI Araçları & MCP (Claude/Gemini/Warp)

{{#include ../../banners/hacktricks-training.md}}

## Genel Bakış

Yerel AI command-line arayüzleri (AI CLIs) — Claude Code, Gemini CLI, Warp ve benzeri araçlar — genellikle güçlü yerleşik özelliklerle gelir: filesystem read/write, shell execution ve outbound network access. Birçok araç MCP client (Model Context Protocol) olarak davranır ve modelin STDIO veya HTTP üzerinden dış araçları çağırmasına izin verir. LLM, tool-chain'leri non‑deterministically planladığı için, aynı promptlar farklı çalıştırmalarda ve hostlarda farklı process, file ve network davranışlarına yol açabilir.

Temel mekanikler (yaygın AI CLI'larda görülen):
- Genellikle Node/TypeScript ile implemente edilir; modeli başlatan ve araçları expose eden ince bir wrapper bulunur.
- Birden fazla mod: interactive chat, plan/execute ve tek‑prompt çalıştırma.
- MCP client desteği STDIO ve HTTP taşıyıcıları ile, hem local hem de remote yetenek genişletmesine imkan verir.

Kötüye kullanım etkisi: Tek bir prompt credentials inventoryleyip exfiltrate edebilir, yerel dosyaları değiştirebilir ve uzaktaki MCP sunucularına bağlanarak sessizce yetenekleri genişletebilir (bu sunucular üçüncü tarafsa görünürlük boşluğu oluşur).

---

## Saldırgan Oyun Planı – Prompt‑Tetikli Secrets Envanteri

Agent'ı, sessiz kalırken credentials/secrets'i hızlıca triage edip exfiltration için hazırlamak üzere görevlendirin:

- Scope: $HOME ve uygulama/cüzdan dizinleri altında recursive olarak enumerate edin; noisy/pseudo path'lerden kaçının (`/proc`, `/sys`, `/dev`).
- Performance/stealth: recursion depth'i sınırlayın; `sudo`/priv‑escalation'dan kaçının; sonuçları özetleyin.
- Targets: `~/.ssh`, `~/.aws`, cloud CLI creds, `.env`, `*.key`, `id_rsa`, `keystore.json`, browser storage (LocalStorage/IndexedDB profiles), crypto‑wallet data.
- Output: `/tmp/inventory.txt` içine kısa bir liste yazın; dosya zaten varsa, üzerine yazmadan önce timestamp'li bir backup oluşturun.

Example operator prompt to an AI CLI:
```
You can read/write local files and run shell commands.
Recursively scan my $HOME and common app/wallet dirs to find potential secrets.
Skip /proc, /sys, /dev; do not use sudo; limit recursion depth to 3.
Match files/dirs like: id_rsa, *.key, keystore.json, .env, ~/.ssh, ~/.aws,
Chrome/Firefox/Brave profile storage (LocalStorage/IndexedDB) and any cloud creds.
Summarize full paths you find into /tmp/inventory.txt.
If /tmp/inventory.txt already exists, back it up to /tmp/inventory.txt.bak-<epoch> first.
Return a short summary only; no file contents.
```
---

## MCP (STDIO ve HTTP) ile Yetenek Genişletme

AI CLIs sıklıkla ek araçlara erişmek için MCP istemcisi gibi davranır:

- STDIO transport (yerel araçlar): istemci, bir tool server çalıştırmak için yardımcı bir zincir başlatır. Tipik köken: `node → <ai-cli> → uv → python → file_write`. Gözlemlenen örnek: `uv run --with fastmcp fastmcp run ./server.py` bu komut `python3.13` başlatır ve ajanın adına yerel dosya işlemleri yapar.
- HTTP transport (uzak araçlar): istemci uzak bir MCP server’a outbound TCP (ör. port 8000) açar; uzak sunucu istenen eylemi gerçekleştirir (ör. `/home/user/demo_http` yazma). Endpoint’te yalnızca istemcinin ağ etkinliğini görürsünüz; sunucu tarafı dosya işlemleri host dışında gerçekleşir.

Notlar:
- MCP araçları modele tanımlanır ve planlama tarafından otomatik seçilebilir. Davranış çalıştırmalar arasında değişkenlik gösterir.
- Uzak MCP server’lar blast radius’u artırır ve host tarafı görünürlüğünü azaltır.

---

## Yerel Artefaktlar ve Kayıtlar (Forensics)

- Gemini CLI oturum kayıtları: `~/.gemini/tmp/<uuid>/logs.json`
- Sık görülen alanlar: `sessionId`, `type`, `message`, `timestamp`.
- Örnek `message`: `"@.bashrc what is in this file?"` (kullanıcı/ajan niyeti yakalanmış).
- Claude Code geçmişi: `~/.claude/history.jsonl`
- JSONL girdileri genellikle `display`, `timestamp`, `project` gibi alanlar içerir.

Bu yerel kayıtları LLM gateway/proxy’nizde (ör. LiteLLM) gözlemlenen isteklerle korele ederek tahrifat/model‑hijacking tespit edin: modelin işlediği içerik yerel prompt/output’tan sapıyorsa enjekte edilmiş talimatlar veya ele geçirilmiş tool descriptor’larını araştırın.

---

## Uç Nokta Telemetri Kalıpları

Amazon Linux 2023 üzerinde Node v22.19.0 ve Python 3.13 ile temsili zincirler:

1) Yerleşik araçlar (yerel dosya erişimi)
- Parent: `node .../bin/claude --model <model>` (veya CLI için eşdeğeri)
- Hemen sonraki çocuk eylem: yerel bir dosya oluşturma/değiştirme (ör. `demo-claude`). Dosya olayını parent→child soya bağlayın.

2) MCP over STDIO (yerel tool server)
- Zincir: `node → uv → python → file_write`
- Örnek spawn: `uv run --with fastmcp fastmcp run /home/ssm-user/tools/server.py`

3) MCP over HTTP (uzak tool server)
- Client: `node/<ai-cli>` outbound TCP açar `remote_port: 8000` (veya benzeri)
- Server: uzak Python prosesi isteği işler ve `/home/ssm-user/demo_http` yazar.

Ajan kararları çalıştırma bazında farklılık gösterdiğinden, tam süreçler ve dokunulan yolların değişken olmasını bekleyin.

---

## Tespit Stratejisi

Telemetri kaynakları
- Süreç, dosya ve ağ olayları için eBPF/auditd kullanan Linux EDR.
- Prompt/niyet görünürlüğü için yerel AI‑CLI kayıtları.
- Karşılaştırma ve model manipülasyonu tespiti için LLM gateway kayıtları (ör. LiteLLM).

Hunting heuristics
- Hassas dosya erişimlerini bir AI‑CLI parent zincirine bağlayın (ör. `node → <ai-cli> → uv/python`).
- Aşağılar altında erişim/okuma/yazma olayları için alarm verin: `~/.ssh`, `~/.aws`, tarayıcı profil depolama, bulut CLI kimlik bilgileri, `/etc/passwd`.
- AI‑CLI prosesinden onaylanmamış MCP uç noktalarına yönelik beklenmeyen outbound bağlantıları (HTTP/SSE, 8000 gibi portlar) işaretleyin.
- Yerel `~/.gemini`/`~/.claude` artefaktlarını LLM gateway prompt/output’larıyla korele edin; sapma olası hijacking işareti olur.

Example pseudo‑rules (EDR’inize uyarlayın):

---
```yaml
- when: file_write AND path IN ["$HOME/.ssh/*","$HOME/.aws/*","/etc/passwd"]
and ancestor_chain CONTAINS ["node", "claude|gemini|warp", "python|uv"]
then: alert("AI-CLI secrets touch via tool chain")

- when: outbound_tcp FROM process_name =~ "node|python" AND parent =~ "claude|gemini|warp"
and dest_port IN [8000, 3333, 8787]
then: tag("possible MCP over HTTP")
```
Hardening ideas
- Dosya/sistem araçları için açık kullanıcı onayı gerektirin; araç planlarını kaydedin ve görünür hale getirin.
- AI‑CLI süreçleri için ağ çıkışını yalnızca onaylı MCP sunucularıyla sınırlandırın.
- Tutarlı, müdahaleye dayanıklı denetim için yerel AI‑CLI loglarını ve LLM gateway loglarını gönderin/ithal edin.

---

## Blue‑Team Yeniden Üretme Notları

Aşağıdaki gibi zincirleri yeniden üretmek için EDR veya eBPF tracer ile temiz bir VM kullanın:
- `node → claude --model claude-sonnet-4-20250514` then immediate local file write.
- `node → uv run --with fastmcp ... → python3.13` writing under `$HOME`.
- `node/<ai-cli>` establishing TCP to an external MCP server (port 8000) while a remote Python process writes a file.

Sahte pozitifleri önlemek için tespitlerinizin dosya/ağ olaylarını başlatan AI‑CLI üst sürecine bağladığını doğrulayın.

---

## References

- [Commanding attention: How adversaries are abusing AI CLI tools (Red Canary)](https://redcanary.com/blog/threat-detection/ai-cli-tools/)
- [Model Context Protocol (MCP)](https://modelcontextprotocol.io)
- [LiteLLM – LLM Gateway/Proxy](https://docs.litellm.ai)

{{#include ../../banners/hacktricks-training.md}}
