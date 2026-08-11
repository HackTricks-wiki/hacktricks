# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

AppleScript ist eine Automatisierungssprache, die Apple Events an skriptfähige Anwendungen senden kann. Mit den entsprechenden Berechtigungen kann Malware JavaScript in einen Tab eines skriptfähigen Browsers einschleusen oder System Events/Accessibility verwenden, um auf einen Berechtigungsdialog zu klicken. Apple Events und Accessibility sind unterschiedliche TCC-Dienste und erfordern im Allgemeinen jeweils die Zustimmung des Benutzers.<sup>[[3]](#references)</sup>
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
Das Repository `abbeycode/AppleScripts` enthält Beispiele für Automatisierung.<sup>[[7]](#references)</sup>\
Weitere Informationen zu Malware, die AppleScripts verwendet, finden Sie [**hier**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).<sup>[[3]](#references)</sup>

### Automatisierung / TCC-Eigenheiten

Genehmigungen für Apple Events sind **gerichtet**: Die Abfrage gilt für ein Paar aus **Quellprozess -> Zielprozess**. Sobald der Benutzer auf **Allow** klickt, werden zukünftige Anfragen von derselben Quelle an dasselbe Ziel erlaubt, bis der Eintrag zurückgesetzt wird. Beim Testen reicht es aus, `Terminal -> Finder` oder `Terminal -> System Events` einmal zu genehmigen, um die Berechtigung später ohne ein weiteres Popup wiederzuverwenden.<sup>[[1]](#references)</sup>
```bash
# Remove previously granted Automation permissions from Terminal
tccutil reset AppleEvents com.apple.Terminal
```
Dies ist besonders relevant, wenn der **Ziel** **Finder** ist, da Finder immer über **Full Disk Access** verfügt, auch wenn er nicht in der FDA UI erscheint. Daher kann jeder Host, der bereits über Automation für Finder verfügt, als AppleScript/JXA-Proxy verwendet werden, um auf TCC-geschützte Dateien zuzugreifen.<sup>[[1]](#references)</sup> Die generischen Finder- und System Events-Payloads sind bereits auf [der Hauptseite zu TCC](../README.md) und auf [der Apple Events-Seite](../macos-apple-events.md) dokumentiert.

### Moderne offensive tradecraft

`/usr/bin/osascript` ist nur der sichtbarste Einstiegspunkt. AppleScript und JXA können auch über **Mach-O-Binaries** mittels **`NSAppleScript`** / **`OSAScript`** ausgeführt werden, was sowohl für Evasion als auch dafür nützlich ist, innerhalb eines Hosts zu agieren, der bereits interessante TCC-Berechtigungen besitzt.<sup>[[2]](#references)</sup>
```bash
osascript -l JavaScript <<'EOF'
const app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("id > /tmp/jxa_id");
EOF
```
Wenn du einen eigenen Helper entwickelst, der Apple Events direkt sendet, macht eine **echte App-Identität** Tests und den Betrieb wesentlich zuverlässiger. In der Praxis bedeutet das, eine `Info.plist` mit `CFBundleIdentifier` und `NSAppleEventsUsageDescription` einzubetten, die Binärdatei zu signieren und das Entitlement `com.apple.security.automation.apple-events` zu gewähren. Andernfalls wird die Apple-Events-Abfrage häufig dem **übergeordneten Host** (z. B. `Terminal`) zugeschrieben, oder die Ausführung von `NSAppleScript` schlägt mit verwirrenden Fehlern wie `-1750` / `errOSASystemError` fehl.<sup>[[2]](#references)</sup>

AppleScripts können in kompilierter Form gespeichert und normalerweise mit `osadecompile` dekompiliert werden.

Diese Scripts können jedoch auch als **„Read only“** (über die Option „Export...“) **exportiert** werden:

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
In diesem Fall weigert sich `osadecompile`, den normalen Quelltext wiederherzustellen, aber der Bytecode und die Apple-Event-Terminologie können weiterhin analysiert werden.

SentinelOnes Forschung zu Run-Only-Scripts beschreibt, wie sich diese Einschränkung umgehen und dennoch die Struktur wiederherstellen lässt. `applescript-disassembler` und `aevt_decompile` helfen bei der Untersuchung des kompilierten Scripts und der Apple-Event-Daten.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

## References

- [1] [Umgehung des macOS-TCC-Schutzes der Privatsphäre von Benutzern durch Zufall und gezieltes Vorgehen](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [2] [AppleScript in macOS-CLI-Tools nutzen: Die undokumentierten Teile](https://steipete.me/posts/2025/applescript-cli-macos-complete-guide)
- [3] [Wie offensive Akteure AppleScript für Angriffe auf macOS nutzen](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)
- [4] [FADE DEAD | Abenteuer beim Reverse Engineering bösartiger Run-Only-AppleScripts](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)
- [5] [Jinmo/applescript-disassembler](https://github.com/Jinmo/applescript-disassembler)
- [6] [SentineLabs/aevt_decompile](https://github.com/SentineLabs/aevt_decompile)
- [7] [abbeycode/AppleScripts-Beispiele](https://github.com/abbeycode/AppleScripts)
{{#include ../../../../../banners/hacktricks-training.md}}
