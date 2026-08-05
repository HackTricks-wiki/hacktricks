# Захисні застосунки macOS

{{#include ../../banners/hacktricks-training.md}}

## Брандмауери

- [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html): Моніторить кожне з'єднання, встановлене кожним процесом. Залежно від режиму (тихо дозволяти з'єднання, тихо забороняти з'єднання та сповіщати) він **показуватиме вам сповіщення** щоразу, коли встановлюється нове з'єднання. Також має дуже зручний GUI для перегляду всієї цієї інформації.
- [**LuLu**](https://objective-see.org/products/lulu.html): брандмауер Objective-See. Це базовий брандмауер, який сповіщатиме вас про підозрілі з'єднання (він має GUI, але не такий вишуканий, як у Little Snitch).

## Виявлення persistence

- [**KnockKnock**](https://objective-see.org/products/knockknock.html): застосунок Objective-See, який шукатиме в різних місцях, де **може зберігатися malware** (це одноразовий інструмент, а не сервіс моніторингу).
- [**BlockBlock**](https://objective-see.org/products/blockblock.html): подібний до KnockKnock, але моніторить процеси, які створюють persistence.

## Виявлення keyloggers

- [**ReiKey**](https://objective-see.org/products/reikey.html): застосунок Objective-See для пошуку **keyloggers**, які встановлюють keyboard "event taps"

## Endpoint telemetry / контроль виконання

- [**Santa**](https://santa.dev/): система binary authorization і моніторингу для macOS. Вона використовує клієнт **Endpoint Security** для авторизації подій **`exec`** до запуску коду, тому часто застосовується в корпоративних середовищах, орієнтованих на **allowlisting/denylisting**, а не лише на виявлення після виконання.
- [**Mac Monitor**](https://github.com/redcanaryco/mac-monitor): інструмент динамічного аналізу macOS, подібний до Procmon. Він отримує **Endpoint Security telemetry** (події процесів, файлів, міжпроцесної взаємодії, входу в систему та пов'язані з XProtect) і корисний для розуміння того, що саме може спостерігати зрілий сенсор на базі ES.<sup>[[2]](#references)</sup>
- [**ProcessMonitor / FileMonitor / DNSMonitor**](https://objective-see.org/products/utilities.html): легковагові інструменти Objective-See для **process**, **file** і **DNS** telemetry. У сучасних версіях macOS вони мають додаткові передумови, як-от **root**, **Terminal Full Disk Access** або схвалення **System/Network Extension**. Щоб переглянути більше ідей щодо інструментування, ознайомтеся з [цією іншою сторінкою про перевірку/налагодження застосунків macOS](macos-apps-inspecting-debugging-and-fuzzing/README.md).

## Швидкий triage захисних інструментів

Більшість сучасних security-продуктів для macOS працюють як певна комбінація **System Extensions / клієнтів Endpoint Security**, **агентів/демонів launchd** і застосунків із **Full Disk Access**. Короткий checklist оператора:
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
Якщо `systemextensionsctl list` показує датчик як **`[activated enabled]`**, це зазвичай найшвидший індикатор того, що extension справді активний. У **macOS 15 Sequoia і новіших версіях** MDM також може позначати певні security extensions як **такі, що не видаляються через UI**, тому припущення «вимкнути його в System Settings» більше не є безпечним. Внутрішні деталі див. у [macOS System Extensions](mac-os-architecture/macos-system-extensions.md).

## Остання нативна телеметрія, доступна defenders

Останні релізи macOS зробили деякі раніше складні для виявлення user-driven bypasses значно помітнішими для blue teams:

- **macOS 15+**: клієнти Endpoint Security можуть отримувати події **`gatekeeper_user_override`**, тож ручні обходи Gatekeeper можна централізовано журналювати.
- **Сучасні інструменти macOS Endpoint Security** також можуть отримувати події **XProtect malware detection**, завдяки чому легше підтвердити, що Apple вже виявила на endpoint.
- **macOS 15.4+**: Endpoint Security додає **`tcc_modify`**, що нарешті надає defenders підтримуваний спосіб моніторити **надання/відкликання дозволів TCC**, замість отримання даних зі службових журналів TCC.<sup>[[1]](#references)</sup>
```bash
# Gatekeeper user overrides
sudo eslogger gatekeeper_user_override

# XProtect detections
sudo eslogger xp_malware_detected

# macOS 15.4+
sudo eslogger tcc_modify
```
Це корисно як для захисників, так і для red teamers, які проводять self-assessment: якщо ціль має зрілий стек на базі ES, **ланцюжки обходу Gatekeeper / TCC, схвалені користувачем, можуть бути значно помітнішими, ніж раніше**. Довідкову інформацію про ці засоби захисту див. у розділах [Gatekeeper / Quarantine / XProtect](macos-security-protections/macos-gatekeeper.md) і [TCC](macos-security-protections/macos-tcc/README.md).

## Посилання

- [1] [Objective-See - Вірити означає використовувати TCC! Apple нарешті додає події TCC до Endpoint Security!](https://objective-see.org/blog/blog_0x7F.html)
- [2] [Red Canary - Представляємо: Mac Monitor](https://redcanary.com/blog/threat-detection/mac-monitor/)

{{#include ../../banners/hacktricks-training.md}}
