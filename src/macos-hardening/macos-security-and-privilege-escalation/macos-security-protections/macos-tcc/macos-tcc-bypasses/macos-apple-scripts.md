# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

Es ist eine Skriptsprache zur Aufgabenautomatisierung, die **mit entfernten Prozessen interagiert**. Sie macht es ziemlich einfach, **andere Prozesse zu bitten, bestimmte Aktionen auszuführen**. **Malware** kann diese Funktionen missbrauchen, um von anderen Prozessen exportierte Funktionen zu missbrauchen.\
Zum Beispiel könnte eine Malware **beliebigen JS-Code in geöffneten Browserseiten injizieren**. Oder **automatisch auf** einige der vom Benutzer angeforderten Berechtigungen klicken;
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
Hier findest du einige Beispiele: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
Weitere Infos über malware mit applescripts findest du [**hier**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).

### Automation / TCC quirks

Apple Events-Zulassungen sind **gerichtet**: Der Prompt gilt für ein **source process -> target process**-Paar. Sobald der Benutzer auf **Allow** klickt, sind zukünftige Anfragen vom selben source zum selben target erlaubt, bis der Eintrag zurückgesetzt wird. Beim Testen reicht es aus, `Terminal -> Finder` oder `Terminal -> System Events` einmal zu genehmigen, um die Berechtigung später ohne weiteres Popup erneut zu verwenden.
```bash
# Remove previously granted Automation permissions from Terminal
tccutil reset AppleEvents com.apple.Terminal
```
Dies ist besonders relevant, wenn das **target** **Finder** ist, weil Finder immer **Full Disk Access** hat, auch wenn es nicht in der FDA UI erscheint. Daher kann jeder Host, der bereits Automation über Finder hat, als AppleScript/JXA-Proxy verwendet werden, um auf TCC-geschützte Dateien zuzugreifen. Die generischen Finder- und System Events-Payloads sind bereits auf [the main TCC page](../README.md) und auf [the Apple Events page](../macos-apple-events.md) dokumentiert.

### Modern offensive tradecraft

`/usr/bin/osascript` ist nur der sichtbarste Einstiegspunkt. AppleScript und JXA können auch aus **Mach-O binaries** über **`NSAppleScript`** / **`OSAScript`** ausgeführt werden, was sowohl für Evasion als auch dafür nützlich ist, in einem Host zu leben, der bereits interessante TCC-Grants hat.
```bash
osascript -l JavaScript <<'EOF'
const app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("id > /tmp/jxa_id");
EOF
```
Wenn Sie einen benutzerdefinierten Helper bauen, der Apple Events direkt sendet, macht ihm eine **echte App-Identität** das Testen und den Betrieb deutlich zuverlässiger. In der Praxis bedeutet das, ein `Info.plist` mit `CFBundleIdentifier` und `NSAppleEventsUsageDescription` einzubetten, das Binary zu signieren und das `com.apple.security.automation.apple-events` Entitlement zu gewähren. Andernfalls wird der Apple-Events-Prompt häufig dem **Parent Host** zugeschrieben (zum Beispiel `Terminal`) oder die `NSAppleScript`-Ausführung schlägt einfach mit verwirrenden `-1750` / `errOSASystemError`-Fehlern fehl.

Apple scripts können leicht "**compiled**" werden. Diese Versionen können mit `osadecompile` leicht "**decompiled**" werden

Diese scripts können aber auch als **"Read only" exportiert** werden (über die Option "Export..."):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
und in diesem Fall kann der Inhalt nicht einmal mit `osadecompile` dekompiliert werden

Es gibt jedoch immer noch einige Tools, mit denen sich diese Art von Executables verstehen lässt, [**lies diese Forschung für mehr Infos**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)). Das Tool [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) mit [**aevt_decompile**](https://github.com/SentineLabs/aevt_decompile) ist sehr nützlich, um zu verstehen, wie das Script funktioniert.

## References

- [Bypassing macOS TCC User Privacy Protections by Accident and Design](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [Making AppleScript Work in macOS CLI Tools: The Undocumented Parts](https://steipete.me/posts/2025/applescript-cli-macos-complete-guide)

{{#include ../../../../../banners/hacktricks-training.md}}
