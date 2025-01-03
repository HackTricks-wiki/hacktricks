# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

Es ist eine Skriptsprache, die zur Automatisierung von Aufgaben **mit Remote-Prozessen interagiert**. Es macht es ziemlich einfach, **andere Prozesse zu bitten, einige Aktionen auszuführen**. **Malware** kann diese Funktionen missbrauchen, um Funktionen zu nutzen, die von anderen Prozessen exportiert werden.\
Zum Beispiel könnte eine Malware **willkürlichen JS-Code in geöffneten Browserseiten injizieren**. Oder **automatisch auf einige vom Benutzer angeforderte Berechtigungen klicken**;
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
Hier sind einige Beispiele: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
Finden Sie weitere Informationen über Malware, die AppleScripts verwendet, [**hier**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).

Apple-Skripte können leicht "**kompiliert**" werden. Diese Versionen können leicht "**dekompiliert**" werden mit `osadecompile`.

Diese Skripte können auch **als "Nur lesen" exportiert** werden (über die Option "Exportieren..."):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
und in diesem Fall kann der Inhalt selbst mit `osadecompile` nicht dekompiliert werden.

Es gibt jedoch immer noch einige Tools, die verwendet werden können, um diese Art von ausführbaren Dateien zu verstehen, [**lesen Sie diese Forschung für weitere Informationen**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)). Das Tool [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) mit [**aevt_decompile**](https://github.com/SentineLabs/aevt_decompile) wird sehr nützlich sein, um zu verstehen, wie das Skript funktioniert.

{{#include ../../../../../banners/hacktricks-training.md}}
