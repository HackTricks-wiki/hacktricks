# macOS Defensive Apps

{{#include ../../banners/hacktricks-training.md}}

## Firewalls

- [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html): Her process tarafından yapılan her bağlantıyı izler. Moda bağlı olarak (bağlantılara sessizce izin verme, bağlantıyı sessizce reddetme ve uyarı verme), her yeni bağlantı kurulduğunda **size bir uyarı gösterir**. Ayrıca tüm bu bilgileri görmek için oldukça kullanışlı bir GUI'ye sahiptir.
- [**LuLu**](https://objective-see.org/products/lulu.html): Objective-See firewall'ı. Şüpheli bağlantılar konusunda sizi uyaran temel bir firewall'dır (bir GUI'si vardır ancak Little Snitch'teki kadar gelişmiş değildir).

## Persistence detection

- [**KnockKnock**](https://objective-see.org/products/knockknock.html): **Malware'in persistence sağlayabileceği** çeşitli konumları arayan Objective-See uygulaması (monitoring service değil, tek seferlik çalışan bir araçtır).
- [**BlockBlock**](https://objective-see.org/products/blockblock.html): Persistence oluşturan process'leri izleyerek çalışan KnockKnock benzeri bir araçtır.

## Keyloggers detection

- [**ReiKey**](https://objective-see.org/products/reikey.html): Keyboard "event taps" yükleyen **keylogger**'ları bulmaya yarayan Objective-See uygulaması.

## Endpoint telemetry / execution control

- [**Santa**](https://santa.dev/): macOS için binary authorization ve monitoring system. Kod çalıştırılmadan önce **`exec`** event'lerini authorize etmek için bir **Endpoint Security** client kullanır; bu nedenle yalnızca post-execution detection yerine **allowlisting/denylisting** üzerine odaklanan enterprise fleet'lerde yaygın olarak kullanılır.
- [**Mac Monitor**](https://github.com/redcanaryco/mac-monitor): Procmon benzeri macOS dynamic analysis aracı. **Endpoint Security telemetry**'yi (process, file, interprocess, login ve XProtect ile ilgili event'ler) alır ve olgun, ES tabanlı bir sensor'ün gerçekte neleri gözlemleyebildiğini anlamak için kullanışlıdır.<sup>[[2]](#references)</sup>
- [**ProcessMonitor / FileMonitor / DNSMonitor**](https://objective-see.org/products/utilities.html): **process**, **file** ve **DNS** telemetry'si için kullanılan hafif Objective-See araçlarıdır. Modern macOS'ta **root**, **Terminal Full Disk Access** veya **System/Network Extension approval** gibi ek gereksinimleri vardır. Daha fazla instrumentation fikri için [macOS app inspection/debugging hakkındaki bu diğer sayfaya](macos-apps-inspecting-debugging-and-fuzzing/README.md) bakın.

## Defensive tooling için hızlı triage

Modern macOS security product'larının çoğu **System Extensions / Endpoint Security clients**, **launchd agents/daemons** ve **Full Disk Access** yetkisine sahip uygulamaların çeşitli kombinasyonları olarak çalışır. Hızlı bir operator checklist'i:
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
`systemextensionsctl list` çıktısı bir sensörü **`[activated enabled]`** olarak gösteriyorsa bu, extension'ın gerçekten etkin olduğunun genellikle en hızlı göstergesidir. **macOS 15 Sequoia ve sonraki sürümlerde** MDM, belirli security extension'larını **UI üzerinden kaldırılamaz** olarak da işaretleyebilir; bu nedenle "System Settings üzerinden devre dışı bırak" artık güvenli bir varsayım değildir. Dahili bileşenler için bkz. [macOS System Extensions](mac-os-architecture/macos-system-extensions.md).

## Defenders'ın kullanabileceği yeni native telemetry

Yeni macOS sürümleri, daha önce tespit edilmesi zor olan bazı kullanıcı kaynaklı bypass'ları blue teams için çok daha görünür hale getirdi:

- **macOS 15+**: Endpoint Security client'ları artık **`gatekeeper_user_override`** event'lerini alabilir; böylece manuel Gatekeeper bypass'ları merkezi olarak log'lanabilir.
- **Güncel macOS Endpoint Security tooling'i** artık **XProtect malware detection** event'lerini de alabilir; bu da Apple'ın endpoint üzerinde zaten ne tespit ettiğini doğrulamayı kolaylaştırır.
- **macOS 15.4+**: Endpoint Security, nihayet defenders'a TCC debug log'larını scrape etmek yerine **TCC grant/revoke** işlemlerini izlemek için desteklenen bir yöntem sunan **`tcc_modify`** özelliğini ekler.<sup>[[1]](#references)</sup>
```bash
# Gatekeeper user overrides
sudo eslogger gatekeeper_user_override

# XProtect detections
sudo eslogger xp_malware_detected

# macOS 15.4+
sudo eslogger tcc_modify
```
Bu, hem savunucular hem de öz değerlendirme yapan red teamer'lar için kullanışlıdır: hedefte olgun bir ES tabanlı stack varsa, **kullanıcı onaylı Gatekeeper / TCC bypass zincirleri eskisine göre çok daha görünür olabilir**. Bu korumalar hakkında arka plan bilgisi için [Gatekeeper / Quarantine / XProtect](macos-security-protections/macos-gatekeeper.md) ve [TCC](macos-security-protections/macos-tcc/README.md) bölümlerine bakın.

## Referanslar


- [1] [Objective-See - TCCing is Believing! Apple finally adds TCC events to Endpoint Security!](https://objective-see.org/blog/blog_0x7F.html)
- [2] [Red Canary - Introducing: Mac Monitor](https://redcanary.com/blog/threat-detection/mac-monitor/)

{{#include ../../banners/hacktricks-training.md}}
