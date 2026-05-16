# macOS Defensive Apps

{{#include ../../banners/hacktricks-training.md}}

## Firewalls

- [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html): Her süreç tarafından yapılan her bağlantıyı izler. Moda bağlı olarak (sessizce bağlantılara izin verme, sessizce bağlantıyı reddetme ve uyarı) yeni bir bağlantı kurulduğunda size her seferinde bir **uyarı gösterir**. Ayrıca tüm bu bilgileri görmek için çok güzel bir GUI’ye sahiptir.
- [**LuLu**](https://objective-see.org/products/lulu.html): Objective-See firewall. Bu, şüpheli bağlantılar için sizi uyaran temel bir firewall’dur (bir GUI’si vardır ama Little Snitch’inki kadar şık değildir).

## Persistence detection

- [**KnockKnock**](https://objective-see.org/products/knockknock.html): **malware could be persisting** olabileceği birkaç konumu arayan Objective-See uygulaması (tek seferlik bir araçtır, bir izleme servisi değildir).
- [**BlockBlock**](https://objective-see.org/products/blockblock.html): Persistence oluşturan süreçleri izleyerek KnockKnock gibi çalışır.

## Keyloggers detection

- [**ReiKey**](https://objective-see.org/products/reikey.html): Keyboard "event taps" kuran **keyloggers**’ı bulmak için Objective-See uygulaması

## Endpoint telemetry / execution control

- [**Santa**](https://santa.dev/): macOS için binary authorization ve monitoring sistemi. Kod çalışmadan önce **`exec`** event’lerini yetkilendirmek için bir **Endpoint Security** client kullanır; bu yüzden enterprise fleets içinde, yalnızca execution sonrası detection yerine **allowlisting/denylisting** odağında sık görülür.
- [**Mac Monitor**](https://github.com/redcanaryco/mac-monitor): Procmon-benzeri bir macOS dinamik analiz aracı. **Endpoint Security telemetry**’sini (process, file, interprocess, login ve XProtect ile ilgili event’ler) alır ve olgun bir ES tabanlı sensörün gerçekte neleri gözlemleyebildiğini anlamak için faydalıdır.
- [**ProcessMonitor / FileMonitor / DNSMonitor**](https://objective-see.org/products/utilities.html): **process**, **file** ve **DNS** telemetry’si için hafif Objective-See araçları. Modern macOS’ta **root**, **Terminal Full Disk Access** veya **System/Network Extension approval** gibi ek önkoşulları vardır. Daha fazla instrumentasyon fikri için [macOS app inspection/debugging hakkındaki bu diğer sayfaya](macos-apps-inspecting-debugging-and-fuzzing/README.md) bakın.

## Quick triage of defensive tooling

Çoğu modern macOS security ürünü, **System Extensions / Endpoint Security clients**, **launchd agents/daemons** ve **Full Disk Access** olan uygulamaların bir kombinasyonu olarak çalışır. Hızlı bir operator checklist:
```bash
# System / network extensions (EDRs, DNS filters, firewalls, VPNs)
systemextensionsctl list

# Legacy kernel agents on older boxes / upgraded fleets
kmutil showloaded 2>/dev/null | rg -i 'crowdstrike|carbon|sentinel|defender|sophos|eset|symantec|trellix|sentinelone'
# Older releases:
kextstat 2>/dev/null | rg -i 'crowdstrike|carbon|sentinel|defender|sophos|eset|symantec|trellix|sentinelone'

# Userland agents / helpers
launchctl print system | rg -i 'santa|lulu|little snitch|crowdstrike|sentinel|defender|jamf|sophos|eset|symantec'
launchctl print gui/$UID | rg -i 'santa|lulu|little snitch|crowdstrike|sentinel|defender|jamf|sophos|eset|symantec'

# Inspect code-signing and entitlements of a defensive app
codesign -dvv --entitlements :- /Applications/SomeAgent.app

# Check common TCC grants used by sensors / telemetry tools
for db in "$HOME/Library/Application Support/com.apple.TCC/TCC.db" "/Library/Application Support/com.apple.TCC/TCC.db"; do
[ -f "$db" ] || continue
echo "== $db =="
sqlite3 "$db" 'SELECT service,client,auth_value,last_modified FROM access WHERE service IN ("kTCCServiceSystemPolicyAllFiles","kTCCServiceEndpointSecurityClient") ORDER BY last_modified DESC;'
done
```
Eğer `systemextensionsctl list` bir sensor için **`[activated enabled]`** gösteriyorsa, bu genellikle extension’ın gerçekten aktif olduğunun en hızlı göstergesidir. **macOS 15 Sequoia ve sonrası**nda, MDM belirli security extensions’ları ayrıca **arayüzden kaldırılamaz** olarak işaretleyebilir; bu yüzden "System Settings’ten disable et" artık güvenli bir varsayım değildir. İç detaylar için bkz. [macOS System Extensions](mac-os-architecture/macos-system-extensions.md).

## Recent native telemetry defenders can consume

Son macOS sürümleri, daha önce tespit edilmesi zor olan bazı user-driven bypass’ları blue team’ler için çok daha görünür hale getirdi:

- **macOS 15+**: Endpoint Security clients, **`gatekeeper_user_override`** event’lerini alabilir; böylece manuel Gatekeeper bypass’ları merkezi olarak loglanabilir.
- **Mevcut macOS Endpoint Security tooling** ayrıca **XProtect malware detection** event’lerini ingest edebilir; bu da Apple’ın endpoint üzerinde zaten ne tespit ettiğini doğrulamayı kolaylaştırır.
- **macOS 15.4+**: Endpoint Security, **`tcc_modify`** ekler; bu da defenders’a sonunda **TCC grants/revokes** izlemek için desteklenen bir yol sağlar, TCC debug logs kazımak yerine.
```bash
# Gatekeeper user overrides
sudo eslogger gatekeeper_user_override

# XProtect detections
sudo eslogger xp_malware_detected

# macOS 15.4+
sudo eslogger tcc_modify
```
Bu, hem savunucular hem de self-assessment yapan red teamer'lar için kullanışlıdır: eğer hedef mature bir ES-based stack'e sahipse, **user-approved Gatekeeper / TCC bypass chains eskisinden çok daha görünür olabilir**. Bu korumalar hakkında arka plan için [Gatekeeper / Quarantine / XProtect](macos-security-protections/macos-gatekeeper.md) ve [TCC](macos-security-protections/macos-tcc/README.md) bakın.

## References

- [**Objective-See - TCCing is Believing! Apple finally adds TCC events to Endpoint Security!**](https://objective-see.org/blog/blog_0x7F.html)
- [**Red Canary - Introducing: Mac Monitor**](https://redcanary.com/blog/threat-detection/mac-monitor/)

{{#include ../../banners/hacktricks-training.md}}
