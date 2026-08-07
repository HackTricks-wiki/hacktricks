# Захисні застосунки macOS

{{#include ../../banners/hacktricks-training.md}}

## Firewalls

- [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html): Він відстежує кожне з'єднання, встановлене кожним процесом. Залежно від режиму (тихо дозволяти з'єднання, тихо блокувати з'єднання та сповіщати) він **показуватиме вам сповіщення** щоразу, коли встановлюється нове з'єднання. Також він має дуже зручний GUI для перегляду всієї цієї інформації.
- [**LuLu**](https://objective-see.org/products/lulu.html): Firewall від Objective-See. Це базовий firewall, який сповіщатиме вас про підозрілі з'єднання (він має GUI, але він не такий продуманий, як у Little Snitch).

## Виявлення persistence

- [**KnockKnock**](https://objective-see.org/products/knockknock.html): Застосунок Objective-See, який шукатиме в кількох місцях, де **може зберігатися malware** (це одноразовий інструмент, а не сервіс моніторингу).
- [**BlockBlock**](https://objective-see.org/products/blockblock.html): Подібний до KnockKnock, але здійснює моніторинг процесів, які створюють persistence.

## Виявлення keyloggers

- [**ReiKey**](https://objective-see.org/products/reikey.html): Застосунок Objective-See для пошуку **keyloggers**, які встановлюють keyboard "event taps"

## Endpoint telemetry / execution control

- [**Santa**](https://santa.dev/): Система binary authorization і моніторингу для macOS. Вона використовує клієнт **Endpoint Security** для авторизації подій **`exec`** до запуску коду, тому часто використовується в enterprise fleets, орієнтованих на **allowlisting/denylisting**, а не лише на post-execution detection.
- [**Mac Monitor**](https://github.com/redcanaryco/mac-monitor): Інструмент dynamic analysis для macOS, подібний до Procmon. Він отримує **Endpoint Security telemetry** (події, пов'язані з процесами, файлами, interprocess, login і XProtect) і допомагає зрозуміти, що саме може спостерігати зрілий сенсор на основі ES.<sup>[[2]](#references)</sup>
- [**ProcessMonitor / FileMonitor / DNSMonitor**](https://objective-see.org/products/utilities.html): Легковагові інструменти Objective-See для **process**, **file** і **DNS** telemetry. У сучасній macOS вони мають додаткові prerequisites, як-от **root**, **Terminal Full Disk Access** або схвалення **System/Network Extension**. Щоб отримати більше ідей щодо instrumentation, перегляньте [цю іншу сторінку про inspection/debugging застосунків macOS](macos-apps-inspecting-debugging-and-fuzzing/README.md).

## Швидкий triage захисних інструментів

Більшість сучасних security products для macOS працюють як певна комбінація **System Extensions / Endpoint Security clients**, **launchd agents/daemons** і застосунків із **Full Disk Access**. Короткий operator checklist:
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
Якщо `systemextensionsctl list` показує сенсор як **`[activated enabled]`**, це зазвичай найшвидший індикатор того, що extension справді активний. У **macOS 15 Sequoia і новіших версіях** MDM також може позначити певні security extensions як **non-removable from the UI**, тож припущення, що його можна «вимкнути в System Settings», більше не є безпечним. Детальніше про внутрішній механізм див. у [macOS System Extensions](mac-os-architecture/macos-system-extensions.md).

## Свіжі вбудовані дані телеметрії, які можуть використовувати захисники

У новіших релізах macOS деякі user-driven bypasses, які раніше було складно виявляти, стали значно помітнішими для blue teams:

- **macOS 15+**: клієнти Endpoint Security можуть отримувати події **`gatekeeper_user_override`**, тому ручні обходи Gatekeeper можна централізовано реєструвати.
- **Поточні інструменти macOS Endpoint Security** також можуть отримувати події **виявлення malware від XProtect**, що спрощує підтвердження того, що Apple вже виявила на endpoint.
- **macOS 15.4+**: Endpoint Security додає **`tcc_modify`**, що нарешті надає захисникам підтримуваний спосіб моніторити **TCC grants/revokes** замість збирання TCC debug logs.<sup>[[1]](#references)</sup>
```bash
# Gatekeeper user overrides
sudo eslogger gatekeeper_user_override

# XProtect detections
sudo eslogger xp_malware_detected

# macOS 15.4+
sudo eslogger tcc_modify
```
Це корисно як для defenders, так і для red teamers, які проводять self-assessment: якщо target має зрілий стек на базі ES, **ланцюжки обходу Gatekeeper / TCC, схвалені користувачем, можуть бути значно помітнішими, ніж раніше**. Додаткову інформацію про ці засоби захисту див. у розділах [Gatekeeper / Quarantine / XProtect](macos-security-protections/macos-gatekeeper.md) і [TCC](macos-security-protections/macos-tcc/README.md).

## References


- [1] [Objective-See - TCCing is Believing! Apple finally adds TCC events to Endpoint Security!](https://objective-see.org/blog/blog_0x7F.html)
- [2] [Red Canary - Introducing: Mac Monitor](https://redcanary.com/blog/threat-detection/mac-monitor/)

{{#include ../../banners/hacktricks-training.md}}
