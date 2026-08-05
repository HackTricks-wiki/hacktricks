# Захисні застосунки macOS

{{#include ../../banners/hacktricks-training.md}}

## Firewalls

- [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html): Він відстежує кожне з'єднання, яке встановлює кожен процес. Залежно від режиму (тихо дозволяти з'єднання, тихо забороняти з'єднання та сповіщати) він **показуватиме вам сповіщення** щоразу, коли встановлюється нове з'єднання. Також він має дуже зручний GUI для перегляду всієї цієї інформації.
- [**LuLu**](https://objective-see.org/products/lulu.html): Firewall від Objective-See. Це базовий firewall, який сповіщатиме вас про підозрілі з'єднання (він має GUI, але він не такий ефектний, як у Little Snitch).

## Виявлення Persistence

- [**KnockKnock**](https://objective-see.org/products/knockknock.html): Застосунок Objective-See, який перевіряє кілька місць, де **може зберігатися malware** (це одноразовий інструмент, а не сервіс моніторингу).
- [**BlockBlock**](https://objective-see.org/products/blockblock.html): Подібний до KnockKnock, але відстежує процеси, які створюють persistence.

## Виявлення Keyloggers

- [**ReiKey**](https://objective-see.org/products/reikey.html): Застосунок Objective-See для пошуку **keyloggers**, які встановлюють keyboard "event taps"

## Endpoint telemetry / контроль виконання

- [**Santa**](https://santa.dev/): Система авторизації та моніторингу бінарних файлів для macOS. Вона використовує клієнт **Endpoint Security** для авторизації подій **`exec`** до запуску коду, тому часто застосовується в enterprise-флотах, орієнтованих на **allowlisting/denylisting**, а не лише на виявлення після виконання.
- [**Mac Monitor**](https://github.com/redcanaryco/mac-monitor): Інструмент динамічного аналізу macOS, подібний до Procmon. Він отримує **телеметрію Endpoint Security** (події, пов'язані з процесами, файлами, міжпроцесною взаємодією, входом у систему та XProtect) і допомагає зрозуміти, що саме може спостерігати зрілий сенсор на основі ES.<sup>[2]</sup>
- [**ProcessMonitor / FileMonitor / DNSMonitor**](https://objective-see.org/products/utilities.html): Легкі інструменти Objective-See для збору телеметрії **процесів**, **файлів** і **DNS**. У сучасних версіях macOS вони мають додаткові вимоги, як-от **root**, **Terminal Full Disk Access** або схвалення **System/Network Extension**. Щоб дізнатися більше про ідеї інструментування, перегляньте [цю іншу сторінку про інспекцію, debugging і fuzzing застосунків macOS](macos-apps-inspecting-debugging-and-fuzzing/README.md).

## Швидке сортування захисних інструментів

Більшість сучасних продуктів безпеки для macOS працюють як певна комбінація **System Extensions / клієнтів Endpoint Security**, **агентів/демонів launchd** і застосунків із **Full Disk Access**. Короткий чекліст оператора:
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
Якщо `systemextensionsctl list` показує sensor як **`[activated enabled]`**, це зазвичай найшвидший показник того, що extension справді активний. У **macOS 15 Sequoia і новіших версіях** MDM також може позначати певні security extensions як **невидалювані через UI**, тому припущення, що його можна «вимкнути в System Settings», більше не є безпечним. Внутрішні подробиці див. у [macOS System Extensions](mac-os-architecture/macos-system-extensions.md).

## Нові native telemetry, доступні defenders

Нові версії macOS зробили деякі user-driven bypasses, які раніше було складно виявляти, значно помітнішими для blue teams:

- **macOS 15+**: клієнти Endpoint Security можуть отримувати події **`gatekeeper_user_override`**, тому ручні обходи Gatekeeper можна централізовано журналювати.
- **Сучасні macOS Endpoint Security tooling** також можуть отримувати події **XProtect malware detection**, що спрощує підтвердження того, що Apple вже виявила на endpoint.
- **macOS 15.4+**: Endpoint Security додає **`tcc_modify`**, що нарешті надає defenders підтримуваний спосіб моніторити **TCC grants/revokes** замість збирання TCC debug logs.<sup>[1]</sup>
```bash
# Gatekeeper user overrides
sudo eslogger gatekeeper_user_override

# XProtect detections
sudo eslogger xp_malware_detected

# macOS 15.4+
sudo eslogger tcc_modify
```
Це корисно як для захисників, так і для red teamers, які проводять самооцінювання: якщо ціль має зрілий стек на базі ES, **ланцюжки bypass Gatekeeper / TCC, схвалені користувачем, можуть бути значно помітнішими, ніж раніше**. Загальні відомості про ці механізми захисту наведено в розділах [Gatekeeper / Quarantine / XProtect](macos-security-protections/macos-gatekeeper.md) і [TCC](macos-security-protections/macos-tcc/README.md).

## Посилання

- [1] [Objective-See - TCCing is Believing! Apple finally adds TCC events to Endpoint Security!](https://objective-see.org/blog/blog_0x7F.html)
- [2] [Red Canary - Introducing: Mac Monitor](https://redcanary.com/blog/threat-detection/mac-monitor/)

{{#include ../../banners/hacktricks-training.md}}
