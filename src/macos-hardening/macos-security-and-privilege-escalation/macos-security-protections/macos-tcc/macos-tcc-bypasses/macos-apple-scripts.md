# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

Це scripting language, що використовується для автоматизації завдань, **взаємодіючи з remote processes**. Вона дає змогу досить легко **просити інші processes виконати певні дії**. **Malware** може зловживати цими можливостями, використовуючи функції, експортовані іншими processes.\
Наприклад, malware може **інжектити довільний JS code у відкриті сторінки browser**. Або **автоматично натискати** деякі allow permissions, запитані в користувача;<sup>[3]</sup>
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
Ось кілька прикладів: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
Більше інформації про malware, що використовує applescripts, можна знайти [**тут**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).

### Automation / нюанси TCC

Схвалення Apple Events є **спрямованими**: запит стосується пари **вихідний процес -> цільовий процес**. Після натискання користувачем **Allow** майбутні запити від того самого джерела до тієї самої цілі дозволяються, доки запис не буде скинуто. Під час тестування одноразового надання дозволу для `Terminal -> Finder` або `Terminal -> System Events` достатньо, щоб надалі повторно використовувати цей дозвіл без появи нового спливаючого вікна.<sup>[1]</sup>
```bash
# Remove previously granted Automation permissions from Terminal
tccutil reset AppleEvents com.apple.Terminal
```
Це особливо актуально, коли **ціллю** є **Finder**, оскільки Finder завжди має **Full Disk Access**, навіть якщо він не відображається в інтерфейсі FDA. Тому будь-який хост, який уже має **Automation** над Finder, можна використовувати як проксі AppleScript/JXA для доступу до файлів, захищених TCC.<sup>[1]</sup> Загальні payloads для Finder і System Events уже задокументовані [на головній сторінці TCC](../README.md) і [на сторінці Apple Events](../macos-apple-events.md).

### Сучасні наступальні методи

`/usr/bin/osascript` — лише найбільш помітна точка входу. AppleScript і JXA також можуть виконуватися з **Mach-O binaries** через **`NSAppleScript`** / **`OSAScript`**, що корисно як для ухилення від виявлення, так і для роботи всередині хоста, який уже має цікаві дозволи TCC.<sup>[2]</sup>
```bash
osascript -l JavaScript <<'EOF'
const app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("id > /tmp/jxa_id");
EOF
```
Якщо ви створюєте власний helper, який безпосередньо надсилає Apple Events, надання йому **реальної ідентичності застосунку** робить тестування та робочі операції значно надійнішими. На практиці це означає вбудовування `Info.plist` із `CFBundleIdentifier` і `NSAppleEventsUsageDescription`, підписування бінарного файлу та надання entitlement `com.apple.security.automation.apple-events`. Інакше запит Apple Events часто приписується **батьківському хосту** (наприклад, `Terminal`), або виконання `NSAppleScript` просто завершується з незрозумілими помилками `-1750` / `errOSASystemError`.<sup>[2]</sup>

Apple scripts можна легко "**скомпілювати**". Ці версії можна легко "**декомпілювати**" за допомогою `osadecompile`

Однак ці скрипти також можна **експортувати як "Read only"** (через опцію "Export..."):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
і в цьому випадку вміст не можна декомпілювати навіть за допомогою `osadecompile`

Однак існують інструменти, які можна використовувати для розуміння такого типу виконуваних файлів, [**ознайомтеся з цим дослідженням для отримання додаткової інформації**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)).<sup>[4]</sup> Інструмент [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) разом із [**aevt_decompile**](https://github.com/SentineLabs/aevt_decompile) буде дуже корисним для розуміння роботи скрипта.

## Посилання

- [1] [Обхід засобів захисту конфіденційності користувачів macOS TCC випадково та навмисно](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [2] [Як змусити AppleScript працювати в CLI-інструментах macOS: недокументовані аспекти](https://steipete.me/posts/2025/applescript-cli-macos-complete-guide)
- [3] [Як зловмисники використовують AppleScript для атак на macOS](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)
- [4] [FADE DEAD | Пригоди з реверсингом шкідливих AppleScripts, доступних лише для виконання](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)

{{#include ../../../../../banners/hacktricks-training.md}}
