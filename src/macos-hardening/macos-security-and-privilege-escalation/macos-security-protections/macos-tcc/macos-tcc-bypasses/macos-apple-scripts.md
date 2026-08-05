# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

Це scripting language, що використовується для автоматизації завдань, **взаємодіючи з remote processes**. Вона дає змогу досить легко **просити інші processes виконувати певні дії**. **Malware** може зловживати цими можливостями, використовуючи функції, експортовані іншими processes.\
Наприклад, malware може **інжектити довільний JS code у відкриті сторінки браузера**. Або **автоматично натискати** деякі дозволи, запити на надання яких показуються користувачеві;<sup>[[3]](#references)</sup>
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
Ось кілька прикладів: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
Більше інформації про malware, що використовує applescripts, можна знайти [**тут**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).

### Нюанси Automation / TCC

Схвалення Apple Events є **спрямованими**: запит стосується пари **source process -> target process**. Після натискання користувачем **Allow** майбутні запити від того самого source до того самого target дозволяються, доки запис не буде скинуто. Під час тестування одноразового надання дозволу для `Terminal -> Finder` або `Terminal -> System Events` достатньо, щоб надалі повторно використовувати цей дозвіл без появи нового вікна.<sup>[[1]](#references)</sup>
```bash
# Remove previously granted Automation permissions from Terminal
tccutil reset AppleEvents com.apple.Terminal
```
Це особливо актуально, коли **target** — **Finder**, оскільки Finder завжди має **Full Disk Access**, навіть якщо він не відображається у FDA UI. Тому будь-який host, який уже має Automation over Finder, можна використовувати як AppleScript/JXA proxy для доступу до TCC-protected файлів.<sup>[[1]](#references)</sup> Generic Finder і System Events payloads уже задокументовані на [main TCC page](../README.md) і на [Apple Events page](../macos-apple-events.md).

### Сучасний offensive tradecraft

`/usr/bin/osascript` — лише найпомітніша entry point. AppleScript і JXA також можуть виконуватися з **Mach-O binaries** через **`NSAppleScript`** / **`OSAScript`**, що корисно як для evasion, так і для роботи всередині host, який уже має цікаві TCC grants.<sup>[[2]](#references)</sup>
```bash
osascript -l JavaScript <<'EOF'
const app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("id > /tmp/jxa_id");
EOF
```
Якщо ви створюєте власний helper, який безпосередньо надсилає Apple Events, надання йому **реальної ідентичності застосунку** робить тестування та робочі операції значно надійнішими. На практиці це означає вбудовування `Info.plist` із `CFBundleIdentifier` і `NSAppleEventsUsageDescription`, підписування бінарного файлу та надання entitlement `com.apple.security.automation.apple-events`. Інакше запит Apple Events часто приписується **батьківському host** (наприклад, `Terminal`), або виконання `NSAppleScript` просто завершується з незрозумілими помилками `-1750` / `errOSASystemError`.<sup>[[2]](#references)</sup>

Apple scripts можна легко "**скомпілювати**". Ці версії можна легко "**декомпілювати**" за допомогою `osadecompile`

Однак ці scripts також можна **експортувати як "Read only"** (через опцію "Export..."):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
і в цьому випадку вміст не можна декомпілювати навіть за допомогою `osadecompile`

Однак усе ще існують деякі інструменти, які можна використовувати для розуміння такого типу виконуваних файлів, [**прочитайте це дослідження для отримання додаткової інформації**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)).<sup>[[4]](#references)</sup> Інструмент [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) разом із [**aevt_decompile**](https://github.com/SentineLabs/aevt_decompile) буде дуже корисним для розуміння роботи скрипта.

## Посилання

- [1] [Обхід захисту конфіденційності користувачів macOS TCC випадково та навмисно](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [2] [Як забезпечити роботу AppleScript в інструментах macOS CLI: недокументовані аспекти](https://steipete.me/posts/2025/applescript-cli-macos-complete-guide)
- [3] [Як зловмисники використовують AppleScript для атак на macOS](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)
- [4] [FADE DEAD | Пригоди реверсингу шкідливих AppleScript, доступних лише для запуску](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)

{{#include ../../../../../banners/hacktricks-training.md}}
