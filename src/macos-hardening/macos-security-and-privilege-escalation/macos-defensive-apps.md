# macOS Defensive Apps

{{#include ../../banners/hacktricks-training.md}}

## Firewalls

- [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html): Він моніторить кожне з’єднання, створене кожним процесом. Залежно від режиму (silent allow connections, silent deny connection and alert) він **показуватиме вам alert** щоразу, коли встановлюється нове з’єднання. Також має дуже зручний GUI, щоб бачити всю цю інформацію.
- [**LuLu**](https://objective-see.org/products/lulu.html): Firewall від Objective-See. Це базовий firewall, який alert-итиме вас про suspicious connections (він має GUI, але він не такий fancy, як у Little Snitch).

## Persistence detection

- [**KnockKnock**](https://objective-see.org/products/knockknock.html): Application від Objective-See, яка шукатиме в кількох locations, де **malware could be persisting** (це однорозовий tool, не monitoring service).
- [**BlockBlock**](https://objective-see.org/products/blockblock.html): Як KnockKnock, але моніторить процеси, що генерують persistence.

## Keyloggers detection

- [**ReiKey**](https://objective-see.org/products/reikey.html): Application від Objective-See для пошуку **keyloggers**, які встановлюють keyboard "event taps"

## Endpoint telemetry / execution control

- [**Santa**](https://santa.dev/): Система binary authorization and monitoring для macOS. Вона використовує **Endpoint Security** client для авторизації подій **`exec`** перед запуском code, тому її часто використовують в enterprise fleets, зосереджених на **allowlisting/denylisting** замість лише post-execution detection.
- [**Mac Monitor**](https://github.com/redcanaryco/mac-monitor): Інструмент динамічного аналізу macOS, подібний до Procmon. Він ingests **Endpoint Security telemetry** (process, file, interprocess, login, і XProtect-related events) та корисний для розуміння, що насправді може спостерігати зрілий ES-based sensor.
- [**ProcessMonitor / FileMonitor / DNSMonitor**](https://objective-see.org/products/utilities.html): Легкі інструменти Objective-See для telemetry **process**, **file**, і **DNS**. На сучасному macOS вони мають додаткові prerequisites, такі як **root**, **Terminal Full Disk Access**, або **System/Network Extension approval**. Для інших ідей щодо instrumentation перегляньте [цю іншу сторінку про macOS app inspection/debugging and fuzzing](macos-apps-inspecting-debugging-and-fuzzing/README.md).

## Quick triage of defensive tooling

Більшість сучасних macOS security products працюють як певна комбінація **System Extensions / Endpoint Security clients**, **launchd agents/daemons**, і applications з **Full Disk Access**. Короткий checklist оператора:
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
Якщо `systemextensionsctl list` показує сенсор як **`[activated enabled]`**, це зазвичай найшвидший індикатор того, що extension насправді активний. На **macOS 15 Sequoia і новіших**, MDM також може позначати певні security extensions як **non-removable from the UI**, тож "disable it from System Settings" вже не є безпечною припущенням. Для внутрішньої інформації див. [macOS System Extensions](mac-os-architecture/macos-system-extensions.md).

## Recent native telemetry defenders can consume

Останні релізи macOS зробили деякі раніше складні для виявлення user-driven bypasses набагато помітнішими для blue teams:

- **macOS 15+**: Endpoint Security clients можуть отримувати події **`gatekeeper_user_override`**, тож manual Gatekeeper bypasses можна централізовано логувати.
- **Current macOS Endpoint Security tooling** також може інжестити події **XProtect malware detection**, що полегшує підтвердження того, що Apple вже виявила на endpoint.
- **macOS 15.4+**: Endpoint Security додає **`tcc_modify`**, що нарешті дає defenders підтримуваний спосіб моніторити **TCC grants/revokes** замість парсингу TCC debug logs.
```bash
# Gatekeeper user overrides
sudo eslogger gatekeeper_user_override

# XProtect detections
sudo eslogger xp_malware_detected

# macOS 15.4+
sudo eslogger tcc_modify
```
Це корисно як для захисників, так і для red teamer-ів, які проводять self-assessment: якщо ціль має mature ES-based stack, **user-approved Gatekeeper / TCC bypass chains можуть бути значно помітнішими, ніж раніше**. Для довідки щодо цих захистів дивіться [Gatekeeper / Quarantine / XProtect](macos-security-protections/macos-gatekeeper.md) і [TCC](macos-security-protections/macos-tcc/README.md).

## References

- [**Objective-See - TCCing is Believing! Apple finally adds TCC events to Endpoint Security!**](https://objective-see.org/blog/blog_0x7F.html)
- [**Red Canary - Introducing: Mac Monitor**](https://redcanary.com/blog/threat-detection/mac-monitor/)

{{#include ../../banners/hacktricks-training.md}}
