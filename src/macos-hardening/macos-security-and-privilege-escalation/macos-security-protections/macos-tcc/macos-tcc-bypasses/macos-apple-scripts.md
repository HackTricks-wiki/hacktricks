# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

Це мова сценаріїв, яка використовується для автоматизації завдань, **взаємодіючи з віддаленими процесами**. Вона дає змогу досить легко **запитувати інші процеси на виконання певних дій**. **Malware** може зловживати цими можливостями, щоб використовувати функції, експортовані іншими процесами.\
Наприклад, malware може **впроваджувати довільний JS-код у відкриті сторінки браузера** або **автоматично натискати** кнопки дозволу в запитах, показаних користувачу;<sup>[[3]](#references)</sup>
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
Ось кілька прикладів: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
Більше інформації про malware, що використовує applescripts, можна знайти **[тут](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)**.<sup>[[3]](#references)</sup>

### Automation / особливості TCC

Схвалення Apple Events є **спрямованими**: запит стосується пари **source process -> target process**. Після натискання користувачем **Allow** майбутні запити від того самого source до того самого target дозволяються, доки запис не буде скинуто. Під час тестування достатньо один раз надати дозвіл для `Terminal -> Finder` або `Terminal -> System Events`, щоб надалі повторно використовувати цей дозвіл без нового popup.<sup>[[1]](#references)</sup>
```bash
# Remove previously granted Automation permissions from Terminal
tccutil reset AppleEvents com.apple.Terminal
```
Це особливо актуально, коли **ціллю** є **Finder**, оскільки Finder завжди має **Full Disk Access**, навіть якщо він не відображається в інтерфейсі FDA. Тому будь-який host, який уже має Automation над Finder, можна використовувати як AppleScript/JXA proxy для доступу до файлів, захищених TCC.<sup>[[1]](#references)</sup> Загальні payloads для Finder і System Events уже задокументовані на [the main TCC page](../README.md) і на [the Apple Events page](../macos-apple-events.md).

### Сучасні offensive tradecraft

`/usr/bin/osascript` — лише найбільш помітна точка входу. AppleScript і JXA також можуть виконуватися з **Mach-O binaries** через **`NSAppleScript`** / **`OSAScript`**, що корисно як для evasion, так і для роботи всередині host, який уже має цікаві TCC grants.<sup>[[2]](#references)</sup>
```bash
osascript -l JavaScript <<'EOF'
const app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("id > /tmp/jxa_id");
EOF
```
Якщо ви створюєте custom helper, який надсилає Apple Events безпосередньо, надання йому **реальної ідентичності app** робить тестування й експлуатацію значно надійнішими. На практиці це означає вбудовування `Info.plist` із `CFBundleIdentifier` і `NSAppleEventsUsageDescription`, підписування binary та надання entitlement `com.apple.security.automation.apple-events`. Інакше запит Apple Events часто приписується **батьківському host** (наприклад, `Terminal`), або виконання `NSAppleScript` просто завершується з незрозумілими помилками `-1750` / `errOSASystemError`.<sup>[[2]](#references)</sup>

Apple scripts можна легко "**compiled**". Ці версії можна легко "**decompiled**" за допомогою `osadecompile`

Однак ці scripts також можна **експортувати як "Read only"** (через опцію "Export..."):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
і в цьому випадку вміст неможливо декомпілювати навіть за допомогою `osadecompile`

Однак все ще існують деякі інструменти, які можна використовувати для розуміння такого типу виконуваних файлів, [**прочитайте це дослідження для отримання додаткової інформації**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)).<sup>[[4]](#references)</sup> Інструмент [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) разом із [**aevt_decompile**](https://github.com/SentineLabs/aevt_decompile) буде дуже корисним для розуміння роботи скрипта.

## Посилання

- [1] [Обхід захисту конфіденційності користувачів macOS TCC випадково та навмисно](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [2] [Використання AppleScript в інструментах macOS CLI: недокументовані аспекти](https://steipete.me/posts/2025/applescript-cli-macos-complete-guide)
- [3] [Як зловмисники використовують AppleScript для атак на macOS](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)
- [4] [FADE DEAD | Пригоди з реверсингом шкідливих AppleScript, доступних лише для запуску](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)

{{#include ../../../../../banners/hacktricks-training.md}}
