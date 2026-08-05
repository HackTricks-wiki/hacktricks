# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

Dabei handelt es sich um eine scripting language zur Automatisierung von Aufgaben, die mit **remote processes** interagiert. Sie ermöglicht es ziemlich einfach, **andere processes aufzufordern, bestimmte Aktionen auszuführen**. **Malware** kann diese Funktionen missbrauchen, um von anderen processes exportierte Funktionen zu missbrauchen.\
Beispielsweise könnte eine Malware **beliebigen JS code in geöffneten Browserseiten injecten**. Oder **automatisch auf** bestimmte vom Benutzer angeforderte Berechtigungen klicken;<sup>[3]</sup>
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
Hier finden Sie einige Beispiele: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
Weitere Informationen zu Malware, die AppleScripts verwendet, finden Sie [**hier**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).

### Automation / TCC-Eigenheiten

Apple-Events-Genehmigungen sind **gerichtet**: Die Abfrage bezieht sich auf ein Paar aus **Quellprozess -> Zielprozess**. Sobald der Benutzer auf **Allow** klickt, werden zukünftige Anfragen von derselben Quelle an dasselbe Ziel erlaubt, bis der Eintrag zurückgesetzt wird. Beim Testen reicht es aus, `Terminal -> Finder` oder `Terminal -> System Events` einmal zu genehmigen, um die Berechtigung später erneut zu verwenden, ohne dass ein weiteres Popup angezeigt wird.<sup>[1]</sup>
```bash
# Remove previously granted Automation permissions from Terminal
tccutil reset AppleEvents com.apple.Terminal
```
Dies ist besonders relevant, wenn das **target** **Finder** ist, da Finder immer über **Full Disk Access** verfügt, auch wenn es nicht in der FDA UI erscheint. Daher kann jeder Host, der bereits über Automation mit Finder verfügt, als AppleScript/JXA-Proxy für den Zugriff auf TCC-geschützte Dateien verwendet werden.<sup>[1]</sup> Die generischen Finder- und System-Events-Payloads sind bereits auf [der zentralen TCC-Seite](../README.md) und auf [der Apple-Events-Seite](../macos-apple-events.md) dokumentiert.

### Moderne offensive tradecraft

`/usr/bin/osascript` ist nur der sichtbarste Einstiegspunkt. AppleScript und JXA können auch aus **Mach-O binaries** über **`NSAppleScript`** / **`OSAScript`** ausgeführt werden, was sowohl zur Umgehung als auch zur Ausführung innerhalb eines Hosts nützlich ist, der bereits interessante TCC-Berechtigungen besitzt.<sup>[2]</sup>
```bash
osascript -l JavaScript <<'EOF'
const app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("id > /tmp/jxa_id");
EOF
```
Wenn Sie einen benutzerdefinierten Helper erstellen, der Apple Events direkt sendet, macht eine **echte App-Identität** Tests und den Betrieb wesentlich zuverlässiger. In der Praxis bedeutet dies, eine `Info.plist` mit `CFBundleIdentifier` und `NSAppleEventsUsageDescription` einzubetten, die Binärdatei zu signieren und das Entitlement `com.apple.security.automation.apple-events` zu gewähren. Andernfalls wird der Apple-Events-Prompt häufig dem **übergeordneten Host** (z. B. `Terminal`) zugeordnet, oder die Ausführung von `NSAppleScript` schlägt mit verwirrenden Fehlern wie `-1750` / `errOSASystemError` fehl.<sup>[2]</sup>

AppleScript-Skripte können problemlos "**kompiliert**" werden. Diese Versionen können mit `osadecompile` problemlos "**dekompiliert**" werden.

Diese Skripte können jedoch auch als "**Nur lesen**" exportiert werden (über die Option "Exportieren..."):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
und in diesem Fall kann der Inhalt nicht einmal mit `osadecompile` dekompiliert werden

Es gibt jedoch weiterhin einige Tools, die verwendet werden können, um diese Art von Executables zu verstehen. [**Diese Recherche enthält weitere Informationen**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)).<sup>[4]</sup> Das Tool [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) zusammen mit [**aevt_decompile**](https://github.com/SentineLabs/aevt_decompile) ist sehr nützlich, um zu verstehen, wie das Script funktioniert.

## Referenzen

- [1] [Umgehung von macOS-TCC-User-Privacy-Schutzmaßnahmen durch Zufall und Design](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [2] [AppleScript in macOS-CLI-Tools verwenden: Die undokumentierten Teile](https://steipete.me/posts/2025/applescript-cli-macos-complete-guide)
- [3] [Wie offensive Akteure AppleScript für Angriffe auf macOS verwenden](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)
- [4] [FADE DEAD | Abenteuer beim Reversing bösartiger Run-Only-AppleScripts](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)

{{#include ../../../../../banners/hacktricks-training.md}}
