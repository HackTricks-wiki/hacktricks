# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

AppleScript — це мова автоматизації, яка може надсилати Apple Events застосункам із підтримкою scripting. За наявності відповідних дозволів malware може inject JavaScript у вкладку браузера з підтримкою scripting або використовувати System Events/Accessibility для натискання діалогу дозволів. Apple Events і Accessibility — це окремі служби TCC, які зазвичай потребують відповідних підтверджень від користувача.<sup>[[3]](#references)</sup>
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
Репозиторій `abbeycode/AppleScripts` містить приклади автоматизації.<sup>[[7]](#references)</sup>\
Більше інформації про malware, що використовує applescripts, можна знайти [**тут**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).<sup>[[3]](#references)</sup>

### Автоматизація / особливості TCC

Схвалення Apple Events є **спрямованими**: запит стосується пари **вихідний процес -> цільовий процес**. Після натискання користувачем **Allow** майбутні запити від того самого вихідного процесу до тієї самої цілі дозволяються, доки запис не буде скинуто. Під час тестування одноразового надання дозволу для `Terminal -> Finder` або `Terminal -> System Events` достатньо, щоб повторно використовувати цей дозвіл пізніше без іншого спливного вікна.<sup>[[1]](#references)</sup>
```bash
# Remove previously granted Automation permissions from Terminal
tccutil reset AppleEvents com.apple.Terminal
```
Це особливо актуально, коли **ціллю** є **Finder**, оскільки Finder завжди має **Full Disk Access**, навіть якщо він не відображається в інтерфейсі FDA. Тому будь-який хост, який уже має **Automation** над Finder, можна використовувати як проксі AppleScript/JXA для доступу до файлів, захищених TCC.<sup>[[1]](#references)</sup> Загальні payloads для Finder і System Events уже описані на [головній сторінці TCC](../README.md) і на [сторінці Apple Events](../macos-apple-events.md).

### Сучасні наступальні техніки

`/usr/bin/osascript` є лише найбільш помітною точкою входу. AppleScript і JXA також можуть виконуватися з **Mach-O binaries** через **`NSAppleScript`** / **`OSAScript`**, що корисно як для обходу виявлення, так і для роботи всередині хоста, який уже має цікаві дозволи TCC.<sup>[[2]](#references)</sup>
```bash
osascript -l JavaScript <<'EOF'
const app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("id > /tmp/jxa_id");
EOF
```
Якщо ви створюєте власний helper, який надсилає Apple Events безпосередньо, надання йому **реальної ідентичності застосунку** робить тестування та роботу значно надійнішими. На практиці це означає вбудовування `Info.plist` із `CFBundleIdentifier` і `NSAppleEventsUsageDescription`, підписування binary та надання entitlement `com.apple.security.automation.apple-events`. В іншому разі запит Apple Events часто приписується **батьківському host** (наприклад, `Terminal`), або виконання `NSAppleScript` просто завершується незрозумілими помилками `-1750` / `errOSASystemError`.<sup>[[2]](#references)</sup>

AppleScripts можна зберігати у скомпільованому вигляді, а зазвичай декомпілювати за допомогою `osadecompile`.

Однак ці scripts також можна **експортувати як "Read only"** (через опцію "Export..."):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
У такому разі `osadecompile` відмовляється відновлювати звичайний source code, але bytecode і термінологію Apple Event усе ще можна аналізувати.

Дослідження SentinelOne щодо run-only описує, як відновити структуру попри це обмеження. `applescript-disassembler` і `aevt_decompile` допомагають перевіряти скомпільований script і дані Apple Event.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

## References

- [1] [Обхід засобів захисту macOS TCC для конфіденційності користувачів — випадково та навмисно](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [2] [Як забезпечити роботу AppleScript в інструментах macOS CLI: недокументовані частини](https://steipete.me/posts/2025/applescript-cli-macos-complete-guide)
- [3] [Як зловмисники використовують AppleScript для атак на macOS](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)
- [4] [FADE DEAD | Пригоди у reverse engineering шкідливих run-only AppleScripts](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)
- [5] [Jinmo/applescript-disassembler](https://github.com/Jinmo/applescript-disassembler)
- [6] [SentineLabs/aevt_decompile](https://github.com/SentineLabs/aevt_decompile)
- [7] [abbeycode/Приклади AppleScripts](https://github.com/abbeycode/AppleScripts)
{{#include ../../../../../banners/hacktricks-training.md}}
