# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

Це мова сценаріїв, що використовується для автоматизації завдань, **взаємодіючи з віддаленими процесами**. Вона дуже спрощує **звернення до інших процесів, щоб вони виконували певні дії**. **Malware** може зловживати цими можливостями, щоб використати функції, експортовані іншими процесами.\
Наприклад, malware може **впроваджувати довільний JS code у відкриті сторінки браузера**. Або **автоматично натискати** на деякі дозволи allow, які запитуються в користувача;
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
Here you have some examples: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
Знайдіть більше інформації про malware, що використовує applescripts, [**here**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).

### Automation / TCC quirks

Apple Events approvals are **directional**: prompt призначений для пари **source process -> target process**. Once the user clicks **Allow**, future requests from the same source to the same target are allowed until the entry is reset. During testing, granting `Terminal -> Finder` or `Terminal -> System Events` once is enough to reuse the permission later without another popup.
```bash
# Remove previously granted Automation permissions from Terminal
tccutil reset AppleEvents com.apple.Terminal
```
Це особливо актуально, коли **ціль** — **Finder**, тому що Finder завжди має **Full Disk Access**, навіть якщо він не відображається в UI FDA. Тому будь-який host, який уже має Automation над Finder, можна використовувати як AppleScript/JXA proxy для доступу до файлів, захищених TCC. Загальні payloads для Finder і System Events уже задокументовані в [the main TCC page](../README.md) та на [the Apple Events page](../macos-apple-events.md).

### Modern offensive tradecraft

`/usr/bin/osascript` — це лише найпомітніша точка входу. AppleScript і JXA також можуть виконуватися з **Mach-O binaries** через **`NSAppleScript`** / **`OSAScript`**, що корисно і для evasion, і для роботи всередині host, який уже має цікаві TCC grants.
```bash
osascript -l JavaScript <<'EOF'
const app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("id > /tmp/jxa_id");
EOF
```
Якщо ви будуєте custom helper, який надсилає Apple Events напряму, надання йому **real app identity** робить тестування та операції набагато надійнішими. На практиці це означає вбудовування `Info.plist` з `CFBundleIdentifier` і `NSAppleEventsUsageDescription`, підписування binary та надання entitlement `com.apple.security.automation.apple-events`. Інакше prompt для Apple Events часто приписується **parent host** (наприклад `Terminal`) або виконання `NSAppleScript` просто завершується з незрозумілими помилками `-1750` / `errOSASystemError`.

Apple scripts можуть легко бути "**compiled**". Ці версії можуть бути легко "**decompiled**" за допомогою `osadecompile`

Однак ці scripts також можуть бути **exported as "Read only"** (через опцію "Export..."):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
і в цьому випадку вміст не можна деcompile навіть за допомогою `osadecompile`

Однак, усе ще існують деякі tools, які можна використати, щоб зрозуміти цей тип executables, [**прочитайте це дослідження для отримання додаткової інформації**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)). Tool [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) разом із [**aevt_decompile**](https://github.com/SentineLabs/aevt_decompile) буде дуже корисний, щоб зрозуміти, як працює script.

## References

- [Bypassing macOS TCC User Privacy Protections by Accident and Design](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [Making AppleScript Work in macOS CLI Tools: The Undocumented Parts](https://steipete.me/posts/2025/applescript-cli-macos-complete-guide)

{{#include ../../../../../banners/hacktricks-training.md}}
