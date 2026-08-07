# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

Es handelt sich um eine Skriptsprache zur Aufgabenautomatisierung, die mit **remote processes** interagiert. Sie macht es ziemlich einfach, **andere Prozesse aufzufordern, bestimmte Aktionen auszuführen**. **Malware** kann diese Funktionen missbrauchen, um von anderen Prozessen exportierte Funktionen zu missbrauchen.\
Beispielsweise könnte eine Malware **beliebigen JS-Code in geöffneten Browser-Seiten injizieren** oder angeforderte Berechtigungen automatisch anklicken, um die Benutzerbestätigung zu erteilen;<sup>[[3]](#references)</sup>
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
Hier finden Sie einige Beispiele: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
Weitere Informationen zu Malware, die AppleScripts verwendet, finden Sie [**hier**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).<sup>[[3]](#references)</sup>

### Automation- / TCC-Eigenheiten

Apple Events-Genehmigungen sind **gerichtet**: Die Abfrage gilt für ein Paar aus **Quellprozess -> Zielprozess**. Sobald der Benutzer auf **Allow** klickt, werden zukünftige Anfragen von derselben Quelle an dasselbe Ziel erlaubt, bis der Eintrag zurückgesetzt wird. Beim Testen reicht es aus, `Terminal -> Finder` oder `Terminal -> System Events` einmal zu erlauben, um die Berechtigung später ohne ein weiteres Popup erneut zu verwenden.<sup>[[1]](#references)</sup>
```bash
# Remove previously granted Automation permissions from Terminal
tccutil reset AppleEvents com.apple.Terminal
```
Dies ist besonders relevant, wenn das **target** **Finder** ist, da Finder immer über **Full Disk Access** verfügt, selbst wenn es nicht in der FDA UI angezeigt wird. Daher kann jeder Host, der bereits über **Automation** mit Finder verfügt, als AppleScript/JXA-Proxy für den Zugriff auf durch TCC geschützte Dateien verwendet werden.<sup>[[1]](#references)</sup> Die generischen Finder- und System-Events-Payloads sind bereits auf [der zentralen TCC-Seite](../README.md) und auf [der Apple-Events-Seite](../macos-apple-events.md) dokumentiert.

### Moderne offensive Tradecraft

`/usr/bin/osascript` ist nur der sichtbarste Einstiegspunkt. AppleScript und JXA können auch aus **Mach-O-Binaries** über **`NSAppleScript`** / **`OSAScript`** ausgeführt werden, was sowohl für Evasion als auch dafür nützlich ist, innerhalb eines Hosts zu agieren, der bereits interessante TCC-Berechtigungen besitzt.<sup>[[2]](#references)</sup>
```bash
osascript -l JavaScript <<'EOF'
const app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("id > /tmp/jxa_id");
EOF
```
Wenn du einen eigenen Helper erstellst, der Apple Events direkt sendet, macht eine **echte App-Identität** Tests und den Betrieb deutlich zuverlässiger. In der Praxis bedeutet dies, eine `Info.plist` mit `CFBundleIdentifier` und `NSAppleEventsUsageDescription` einzubetten, die Binary zu signieren und das Entitlement `com.apple.security.automation.apple-events` zu gewähren. Andernfalls wird die Apple-Events-Eingabeaufforderung häufig dem **übergeordneten Host** (zum Beispiel `Terminal`) zugeordnet, oder die Ausführung von `NSAppleScript` schlägt mit verwirrenden Fehlern wie `-1750` / `errOSASystemError` fehl.<sup>[[2]](#references)</sup>

Apple scripts können problemlos "**kompiliert**" werden. Diese Versionen können mit `osadecompile` einfach "**dekompiliert**" werden.

Diese Scripts können jedoch auch als **„Read only“** (über die Option „Export...“) **exportiert** werden:

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
und in diesem Fall kann der Inhalt nicht einmal mit `osadecompile` dekompiliert werden.

Es gibt jedoch weiterhin einige Tools, die zum Verständnis dieser Art von Executables verwendet werden können. [**Diese Recherche enthält weitere Informationen**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)).<sup>[[4]](#references)</sup> Das Tool [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) zusammen mit [**aevt_decompile**](https://github.com/SentineLabs/aevt_decompile) ist sehr hilfreich, um zu verstehen, wie das Script funktioniert.

## Referenzen

- [1] [Umgehung des macOS-TCC-Schutzes der Privatsphäre von Benutzern durch Zufall und Design](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [2] [AppleScript in macOS-CLI-Tools verwenden: Die undokumentierten Teile](https://steipete.me/posts/2025/applescript-cli-macos-complete-guide)
- [3] [Wie offensive Akteure AppleScript für Angriffe auf macOS verwenden](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)
- [4] [FADE DEAD | Abenteuer beim Reverse Engineering von bösartigen Run-Only-AppleScripts](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)

{{#include ../../../../../banners/hacktricks-training.md}}
