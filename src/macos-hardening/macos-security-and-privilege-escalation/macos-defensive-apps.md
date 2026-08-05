# macOS Defensive Apps

{{#include ../../banners/hacktricks-training.md}}

## Firewalls

- [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html): Her process tarafından yapılan her bağlantıyı izler. Moda bağlı olarak (bağlantılara sessizce izin verme, bağlantıyı sessizce reddetme ve uyarma) her yeni bağlantı kurulduğunda **size bir uyarı gösterir**. Ayrıca tüm bu bilgileri görmek için oldukça kullanışlı bir GUI'ye sahiptir.
- [**LuLu**](https://objective-see.org/products/lulu.html): Objective-See firewall'ı. Şüpheli bağlantılar hakkında sizi uyaran temel bir firewall'dır (bir GUI'ye sahiptir ancak Little Snitch'teki kadar gelişmiş değildir).

## Persistence detection

- [**KnockKnock**](https://objective-see.org/products/knockknock.html): **Malware'in persistence sağlayabileceği** çeşitli konumları arayan Objective-See uygulaması (monitoring service değil, one-shot bir tool'dur).
- [**BlockBlock**](https://objective-see.org/products/blockblock.html): Persistence oluşturan process'leri monitoring ederek çalışan KnockKnock benzeri bir uygulama.

## Keyloggers detection

- [**ReiKey**](https://objective-see.org/products/reikey.html): Keyboard "event taps" yükleyen **keylogger'ları** bulmaya yarayan Objective-See uygulaması.

## Endpoint telemetry / execution control

- [**Santa**](https://santa.dev/): macOS için binary authorization ve monitoring system. Kod çalışmadan önce **`exec`** event'lerini authorize etmek için bir **Endpoint Security** client kullanır; bu nedenle yalnızca post-execution detection yerine **allowlisting/denylisting** üzerine odaklanan enterprise fleet'lerde yaygın olarak kullanılır.
- [**Mac Monitor**](https://github.com/redcanaryco/mac-monitor): Procmon benzeri macOS dynamic analysis tool'u. **Endpoint Security telemetry**'yi (process, file, interprocess, login ve XProtect-related event'leri) alır ve olgun bir ES-based sensor'ın gerçekte neleri gözlemleyebildiğini anlamak için kullanışlıdır.<sup>[2]</sup>
- [**ProcessMonitor / FileMonitor / DNSMonitor**](https://objective-see.org/products/utilities.html): **process**, **file** ve **DNS** telemetry için kullanılan lightweight Objective-See tool'larıdır. Modern macOS'ta **root**, **Terminal Full Disk Access** veya **System/Network Extension approval** gibi ek ön koşullara sahiptirler. Daha fazla instrumentation fikri için [macOS app inspection/debugging hakkındaki bu diğer sayfaya](macos-apps-inspecting-debugging-and-fuzzing/README.md) bakın.

## Defensive tooling için hızlı triage

Modern macOS security product'larının çoğu **System Extensions / Endpoint Security clients**, **launchd agents/daemons** ve **Full Disk Access** sahibi application'ların bir kombinasyonu olarak çalışır. Hızlı bir operator checklist'i:
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
`systemextensionsctl list` çıktısı bir sensörü **`[activated enabled]`** olarak gösteriyorsa bu genellikle extension'ın gerçekten çalışır durumda olduğunun en hızlı göstergesidir. **macOS 15 Sequoia ve sonraki sürümlerde** MDM, belirli security extension'larını **arayüzden kaldırılamaz** olarak da işaretleyebilir; bu nedenle "System Settings üzerinden devre dışı bırak" artık güvenli bir varsayım değildir. Dahili yapı için [macOS System Extensions](mac-os-architecture/macos-system-extensions.md) bölümüne bakın.

## Defenders'ın kullanabileceği yeni native telemetry

Yeni macOS sürümleri, daha önce tespit edilmesi zahmetli olan ve kullanıcı tarafından gerçekleştirilen bazı bypass'ları blue team'ler için çok daha gürültülü hâle getirdi:

- **macOS 15+**: Endpoint Security client'ları **`gatekeeper_user_override`** event'lerini alabilir; böylece manuel Gatekeeper bypass'ları merkezi olarak loglanabilir.
- **Güncel macOS Endpoint Security tooling'i** artık **XProtect malware detection** event'lerini de alabilir; bu sayede Apple'ın endpoint üzerinde zaten tespit ettiği durumları doğrulamak kolaylaşır.
- **macOS 15.4+**: Endpoint Security, nihayet defenders'a TCC debug log'larını taramak yerine **TCC grant/revoke** işlemlerini izlemek için desteklenen bir yöntem sunan **`tcc_modify`** özelliğini ekler.<sup>[1]</sup>
```bash
# Gatekeeper user overrides
sudo eslogger gatekeeper_user_override

# XProtect detections
sudo eslogger xp_malware_detected

# macOS 15.4+
sudo eslogger tcc_modify
```
Bu, hem savunmacılar hem de öz değerlendirme yapan red teamer'lar için faydalıdır: hedefte olgun bir ES tabanlı stack varsa, **kullanıcı onaylı Gatekeeper / TCC bypass zincirleri eskisinden çok daha görünür olabilir**. Bu korumalar hakkında arka plan bilgisi için [Gatekeeper / Quarantine / XProtect](macos-security-protections/macos-gatekeeper.md) ve [TCC](macos-security-protections/macos-tcc/README.md) bölümlerine bakın.

## Referanslar

- [1] [Objective-See - TCCing is Believing! Apple nihayet Endpoint Security'ye TCC event'leri ekliyor!](https://objective-see.org/blog/blog_0x7F.html)
- [2] [Red Canary - Tanıtım: Mac Monitor](https://redcanary.com/blog/threat-detection/mac-monitor/)

{{#include ../../banners/hacktricks-training.md}}
