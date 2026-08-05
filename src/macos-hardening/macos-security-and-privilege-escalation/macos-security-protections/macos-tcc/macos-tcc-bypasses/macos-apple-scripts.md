# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

Es handelt sich um eine Skriptsprache zur Automatisierung von Aufgaben, die mit **remote processes** interagiert. Sie ermöglicht es sehr einfach, **andere Prozesse aufzufordern, bestimmte Aktionen auszuführen**. **Malware** kann diese Funktionen missbrauchen, um von anderen Prozessen exportierte Funktionen zu verwenden.\
Beispielsweise könnte eine Malware **beliebigen JS-Code in geöffneten Browser-Seiten injizieren**. Oder per **auto click** einige vom Benutzer angeforderte Berechtigungen zu erlauben;<sup>[[3]](#references)</sup>.
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
Hier finden Sie einige Beispiele: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
Weitere Informationen zu Malware, die AppleScripts verwendet, finden Sie [**hier**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).

### Automation / TCC-Eigenheiten

Apple Events-Genehmigungen sind **gerichtet**: Die Eingabeaufforderung gilt für ein Paar aus **Quellprozess -> Zielprozess**. Sobald der Benutzer auf **Allow** klickt, werden zukünftige Anfragen vom selben Quellprozess an dasselbe Ziel zugelassen, bis der Eintrag zurückgesetzt wird. Beim Testen reicht es aus, `Terminal -> Finder` oder `Terminal -> System Events` einmal zu genehmigen, um die Berechtigung später ohne ein weiteres Popup wiederzuverwenden.<sup>[[1]](#references)</sup>
```bash
# Remove previously granted Automation permissions from Terminal
tccutil reset AppleEvents com.apple.Terminal
```
Dies ist besonders relevant, wenn das **target** **Finder** ist, da Finder immer über **Full Disk Access** verfügt, selbst wenn es nicht in der FDA UI angezeigt wird. Daher kann jeder Host, der bereits über Automation für Finder verfügt, als AppleScript/JXA-Proxy verwendet werden, um auf durch TCC geschützte Dateien zuzugreifen.<sup>[[1]](#references)</sup> Die generischen Finder- und System Events-Payloads sind bereits [auf der Hauptseite zu TCC](../README.md) und [auf der Apple Events-Seite](../macos-apple-events.md) dokumentiert.

### Moderne offensive Tradecraft

`/usr/bin/osascript` ist lediglich der sichtbarste Einstiegspunkt. AppleScript und JXA können auch über **Mach-O-Binaries** mittels **`NSAppleScript`** / **`OSAScript`** ausgeführt werden, was sowohl für die Umgehung als auch dafür nützlich ist, innerhalb eines Hosts zu verbleiben, der bereits interessante TCC-Berechtigungen besitzt.<sup>[[2]](#references)</sup>
```bash
osascript -l JavaScript <<'EOF'
const app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("id > /tmp/jxa_id");
EOF
```
Wenn du einen benutzerdefinierten Helper erstellst, der Apple Events direkt sendet, macht eine **echte App-Identität** Tests und den Betrieb wesentlich zuverlässiger. In der Praxis bedeutet dies, eine `Info.plist` mit `CFBundleIdentifier` und `NSAppleEventsUsageDescription` einzubetten, die Binary zu signieren und das Entitlement `com.apple.security.automation.apple-events` zu gewähren. Andernfalls wird der Apple-Events-Prompt häufig dem **übergeordneten Host** (beispielsweise `Terminal`) zugeschrieben, oder die Ausführung von `NSAppleScript` schlägt mit verwirrenden Fehlern wie `-1750` / `errOSASystemError` fehl.<sup>[[2]](#references)</sup>

Apple scripts können leicht "**compiled**" werden. Diese Versionen können mit `osadecompile` leicht "**decompiled**" werden.

Diese Scripts können jedoch auch als **"Read only"** exportiert werden (über die Option "Export..."):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
und in diesem Fall kann der Inhalt selbst mit `osadecompile` nicht dekompiliert werden.

Es gibt jedoch weiterhin einige Tools, die verwendet werden können, um diese Art von Executables zu verstehen. [**Diese Recherche enthält weitere Informationen**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)).<sup>[[4]](#references)</sup> Das Tool [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) zusammen mit [**aevt_decompile**](https://github.com/SentineLabs/aevt_decompile) ist sehr hilfreich, um zu verstehen, wie das Script funktioniert.

## Referenzen

- [1] [Bypassing macOS TCC User Privacy Protections by Accident and Design](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [2] [Making AppleScript Work in macOS CLI Tools: The Undocumented Parts](https://steipete.me/posts/2025/applescript-cli-macos-complete-guide)
- [3] [How Offensive Actors Use AppleScript For Attacking macOS](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)
- [4] [FADE DEAD | Adventures in Reversing Malicious Run-Only AppleScripts](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)

{{#include ../../../../../banners/hacktricks-training.md}}
