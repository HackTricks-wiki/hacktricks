# Cheat Engine

{{#include ../../banners/hacktricks-training.md}}

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) ist ein nützliches Programm, um herauszufinden, wo wichtige Werte im Speicher eines laufenden Spiels gespeichert sind, und sie zu ändern.\
Wenn du es herunterlädst und startest, wird dir ein **Tutorial** zur Verwendung des Tools angezeigt. Wenn du lernen möchtest, wie man das Tool verwendet, wird dringend empfohlen, es abzuschließen.<sup>[[3]](#references)</sup>

## Wonach suchst du?

![Cheat Engine - Wonach suchst du?: Wonach suchst du?](<../../images/image (762).png>)

Dieses Tool ist sehr nützlich, um herauszufinden, **wo ein bestimmter Wert** (normalerweise eine Zahl) **im Speicher** eines Programms **gespeichert ist**.\
**Normalerweise werden Zahlen** im **4bytes**-Format gespeichert, aber du kannst sie auch in den Formaten **double** oder **float** finden, oder du möchtest nach etwas **anderem als einer Zahl** suchen. Deshalb musst du sicherstellen, dass du auswählst, wonach du **suchen** möchtest:

![Cheat Engine - Wonach suchst du?: Normalerweise werden Zahlen im 4bytes-Format gespeichert, aber du kannst sie auch in den Formaten double oder float finden, oder du möchtest nach etwas...](<../../images/image (324).png>)

Du kannst außerdem verschiedene Arten von **Suchvorgängen** angeben:

![Cheat Engine - Wonach suchst du?: Du kannst außerdem verschiedene Arten von Suchvorgängen angeben](<../../images/image (311).png>)

Du kannst auch das Kontrollkästchen aktivieren, um **das Spiel während des Scannens des Speichers anzuhalten**:

![Cheat Engine - Wonach suchst du?: Du kannst auch das Kontrollkästchen aktivieren, um das Spiel während des Scannens des Speichers anzuhalten](<../../images/image (1052).png>)

### Hotkeys

Unter _**Edit --> Settings --> Hotkeys**_ kannst du verschiedene **Hotkeys** für unterschiedliche Zwecke festlegen, zum Beispiel zum **Anhalten** des **Spiels** (was besonders nützlich ist, wenn du irgendwann den Speicher scannen möchtest). Weitere Optionen sind verfügbar:

![Wonach suchst du? - Hotkeys: Unter Edit -- Settings -- Hotkeys kannst du verschiedene Hotkeys für unterschiedliche Zwecke festlegen, zum Beispiel zum Anhalten des Spiels (was besonders nützlich ist, wenn du irgendwann...](<../../images/image (864).png>)

## Ändern des Werts

Sobald du **gefunden** hast, wo sich der **gesuchte Wert** befindet (mehr dazu in den folgenden Schritten), kannst du ihn ändern, indem du doppelt darauf und anschließend doppelt auf seinen Wert klickst:

![Hotkeys - Ändern des Werts: Sobald du gefunden hast, wo sich der gesuchte Wert befindet (mehr dazu in den folgenden Schritten), kannst du ihn ändern, indem du doppelt darauf und anschließend doppelt...](<../../images/image (563).png>)

Aktiviere schließlich **das Kontrollkästchen**, damit die Änderung im Speicher durchgeführt wird:

![Hotkeys - Ändern des Werts: Aktiviere schließlich das Kontrollkästchen, damit die Änderung im Speicher durchgeführt wird](<../../images/image (385).png>)

Die **Änderung** am **Speicher** wird sofort **angewendet** (beachte, dass der Wert im Spiel **nicht aktualisiert wird**, solange das Spiel diesen Wert nicht erneut verwendet).

## Suchen des Werts

Nehmen wir an, dass es einen wichtigen Wert gibt (zum Beispiel die Lebenspunkte deines Benutzers), den du verbessern möchtest, und dass du diesen Wert im Speicher suchst.

### Über eine bekannte Änderung

Angenommen, du suchst nach dem Wert 100, führst du einen **Scan** nach diesem Wert durch und findest viele Treffer:

![Suchen des Werts - Über eine bekannte Änderung: Angenommen, du suchst nach dem Wert 100, führst du einen Scan nach diesem Wert durch und findest viele Treffer](<../../images/image (108).png>)

Dann tust du etwas, wodurch sich der **Wert ändert**, **hältst** das Spiel an und führst einen **weiteren Scan** durch:

![Suchen des Werts - Über eine bekannte Änderung: Dann tust du etwas, wodurch sich der Wert ändert, hältst das Spiel an und führst einen weiteren Scan durch](<../../images/image (684).png>)

Cheat Engine sucht nach den **Werten**, die **von 100 auf den neuen Wert geändert wurden**. Glückwunsch, du hast die **Adresse** des gesuchten Werts **gefunden** und kannst ihn nun ändern.\
_Wenn noch mehrere Werte vorhanden sind, ändere diesen Wert erneut und führe einen weiteren „next scan“ durch, um die Adressen zu filtern._

### Unbekannter Wert, bekannte Änderung

Wenn du in diesem Szenario den **Wert nicht kennst**, aber weißt, **wie du ihn ändern kannst** (und sogar um welchen Betrag), kannst du nach deiner Zahl suchen.

Beginne mit einem Scan des Typs „**Unknown initial value**“:

![Über eine bekannte Änderung - Unbekannter Wert, bekannte Änderung: Beginne mit einem Scan des Typs „Unknown initial value“](<../../images/image (890).png>)

Ändere anschließend den Wert, gib an, **wie** sich der **Wert** **geändert** hat (in meinem Fall wurde er um 1 verringert), und führe einen **weiteren Scan** durch:

![Über eine bekannte Änderung - Unbekannter Wert, bekannte Änderung: Ändere anschließend den Wert, gib an, wie sich der Wert geändert hat (in meinem Fall wurde er um 1 verringert), und führe einen weiteren Scan durch](<../../images/image (371).png>)

Dir werden **alle Werte angezeigt, die auf die ausgewählte Weise geändert wurden**:

![Über eine bekannte Änderung - Unbekannter Wert, bekannte Änderung: Dir werden alle Werte angezeigt, die auf die ausgewählte Weise geändert wurden](<../../images/image (569).png>)

Sobald du deinen Wert gefunden hast, kannst du ihn ändern.

Beachte, dass es **viele mögliche Änderungen** gibt und du diese **Schritte beliebig oft** durchführen kannst, um die Ergebnisse zu filtern:

![Über eine bekannte Änderung - Unbekannter Wert, bekannte Änderung: Beachte, dass es viele mögliche Änderungen gibt und du diese Schritte beliebig oft durchführen kannst, um die Ergebnisse zu filtern](<../../images/image (574).png>)

### Zufällige Speicheradresse - Den Code finden

Bisher haben wir gelernt, wie man eine Adresse findet, unter der ein Wert gespeichert ist. Es ist jedoch sehr wahrscheinlich, dass sich diese Adresse **bei verschiedenen Ausführungen des Spiels an unterschiedlichen Stellen im Speicher befindet**. Finden wir also heraus, wie wir diese Adresse immer finden können.

Finde mithilfe einiger der erwähnten Tricks die Adresse, unter der dein aktuelles Spiel den wichtigen Wert speichert. Klicke dann (du kannst das Spiel bei Bedarf anhalten) mit der **rechten Maustaste** auf die gefundene **Adresse** und wähle „**Find out what accesses this address**“ oder „**Find out what writes to this address**“:

![Unbekannter Wert, bekannte Änderung - Zufällige Speicheradresse - Den Code finden: Finde mithilfe einiger der erwähnten Tricks die Adresse, unter der dein aktuelles Spiel den wichtigen Wert speichert. Klicke dann...](<../../images/image (1067).png>)

Die **erste Option** ist nützlich, um herauszufinden, welche **Teile** des **Codes** diese **Adresse verwenden** (dies ist auch für andere Dinge nützlich, zum Beispiel um herauszufinden, **wo du den Code** des Spiels **ändern kannst**).\
Die **zweite Option** ist **spezifischer** und in diesem Fall hilfreicher, da wir herausfinden möchten, **von wo dieser Wert geschrieben wird**.

Nachdem du eine dieser Optionen ausgewählt hast, wird der **Debugger** an das Programm **angehängt** und ein neues **leeres Fenster** wird angezeigt. Spiele nun das **Spiel** und **ändere** diesen **Wert** (ohne das Spiel neu zu starten). Das **Fenster** sollte mit den **Adressen** gefüllt werden, die den **Wert ändern**:

![Unbekannter Wert, bekannte Änderung - Zufällige Speicheradresse - Den Code finden: Nachdem du eine dieser Optionen ausgewählt hast, wird der Debugger an das Programm angehängt und ein neues leeres Fenster...](<../../images/image (91).png>)

Da du nun die Adresse gefunden hast, die den Wert ändert, kannst du den **Code nach Belieben ändern** (Cheat Engine ermöglicht es, ihn sehr schnell durch NOPs zu ersetzen):

![Unbekannter Wert, bekannte Änderung - Zufällige Speicheradresse - Den Code finden: Da du nun die Adresse gefunden hast, die den Wert ändert, kannst du den Code nach Belieben ändern (Cheat Engine...](<../../images/image (1057).png>)

Du kannst ihn nun so ändern, dass der Code deine Zahl nicht beeinflusst oder sie immer positiv beeinflusst.

### Zufällige Speicheradresse - Den Pointer finden

Befolge die vorherigen Schritte und finde heraus, wo sich der gewünschte Wert befindet. Verwende anschließend „**Find out what writes to this address**“, um herauszufinden, welche Adresse diesen Wert schreibt, und doppelklicke darauf, um die Disassembly-Ansicht zu öffnen:

![Zufällige Speicheradresse - Den Code finden - Zufällige Speicheradresse - Den Pointer finden: Befolge die vorherigen Schritte und finde heraus, wo sich der gewünschte Wert befindet. Verwende anschließend „Find out...](<../../images/image (1039).png>)

Führe anschließend einen neuen Scan durch und **suche nach dem Hex-Wert zwischen „\[]“** (in diesem Fall dem Wert von $edx):

![Zufällige Speicheradresse - Den Code finden - Zufällige Speicheradresse - Den Pointer finden: Führe anschließend einen neuen Scan durch und suche nach dem Hex-Wert zwischen „ ()“ (in diesem Fall dem Wert von $edx)](<../../images/image (994).png>)

(_Wenn mehrere angezeigt werden, benötigst du normalerweise die Adresse mit dem kleinsten Wert._)\
Nun haben wir **den Pointer gefunden, der den für uns interessanten Wert ändern wird**.

Klicke auf „**Add Address Manually**“:

![Zufällige Speicheradresse - Den Code finden - Zufällige Speicheradresse - Den Pointer finden: Klicke auf „Add Address Manually“](<../../images/image (990).png>)

Klicke nun auf das Kontrollkästchen „Pointer“ und füge die gefundene Adresse in das Textfeld ein (in diesem Szenario war die gefundene Adresse im vorherigen Bild „Tutorial-i386.exe“+2426B0):

![Zufällige Speicheradresse - Den Code finden - Zufällige Speicheradresse - Den Pointer finden: Klicke nun auf das Kontrollkästchen „Pointer“ und füge die gefundene Adresse in das Textfeld ein (in diesem Szenario...](<../../images/image (392).png>)

(Beachte, dass die erste „Address“ automatisch anhand der eingegebenen Pointer-Adresse ausgefüllt wird.)

Klicke auf „OK“, woraufhin ein neuer Pointer erstellt wird:

![Zufällige Speicheradresse - Den Code finden - Zufällige Speicheradresse - Den Pointer finden: Klicke auf „OK“, woraufhin ein neuer Pointer erstellt wird](<../../images/image (308).png>)

Wenn du diesen Wert nun änderst, **änderst du den wichtigen Wert jedes Mal, selbst wenn sich die Speicheradresse, unter der sich der Wert befindet, ändert.**

### Code Injection

Code injection ist eine Technik, bei der du ein Codefragment in den Zielprozess injizierst und anschließend die Codeausführung so umleitest, dass sie durch deinen eigenen Code läuft (beispielsweise indem du dir Punkte gibst, anstatt sie abzuziehen).

Angenommen, du hast die Adresse gefunden, die 1 von den Lebenspunkten deines Spielers abzieht:

![Zufällige Speicheradresse - Den Pointer finden - Code Injection: Angenommen, du hast die Adresse gefunden, die 1 von den Lebenspunkten deines Spielers abzieht](<../../images/image (203).png>)

Klicke auf „Show disassembler“, um den **disassemblierten Code** anzuzeigen.\
Klicke anschließend auf **CTRL+a**, um das Fenster „Auto assemble“ zu öffnen, und wähle _**Template --> Code Injection**_ aus.

![Zufällige Speicheradresse - Den Pointer finden - Code Injection: Klicke anschließend auf CTRL+a, um das Fenster „Auto assemble“ zu öffnen, und wähle Template -- Code Injection aus](<../../images/image (902).png>)

Gib die **Adresse der Instruktion ein, die du ändern möchtest** (dies wird normalerweise automatisch ausgefüllt):

![Zufällige Speicheradresse - Den Pointer finden - Code Injection: Gib die Adresse der Instruktion ein, die du ändern möchtest (dies wird normalerweise automatisch ausgefüllt)](<../../images/image (744).png>)

Eine Vorlage wird generiert:

![Zufällige Speicheradresse - Den Pointer finden - Code Injection: Eine Vorlage wird generiert](<../../images/image (944).png>)

Füge nun deinen neuen Assembly-Code in den Abschnitt „**newmem**“ ein und entferne den Originalcode aus „**originalcode**“, wenn er nicht ausgeführt werden soll**.** In diesem Beispiel fügt der injizierte Code 2 Punkte hinzu, anstatt 1 abzuziehen:

![Zufällige Speicheradresse - Den Pointer finden - Code Injection: Füge nun deinen neuen Assembly-Code in den Abschnitt „newmem“ ein und entferne den Originalcode aus „originalcode“, wenn er...](<../../images/image (521).png>)

**Klicke auf „execute“ und so weiter, und dein Code sollte in das Programm injiziert werden, wodurch sich das Verhalten der Funktion ändert!**

## Erweiterte Funktionen in Cheat Engine 7.x (2023-2025)

Cheat Engine wurde seit Version 7.0 kontinuierlich weiterentwickelt. Dabei wurden mehrere praktische Verbesserungen und *offensive-reversing*-Funktionen hinzugefügt, die bei der Analyse moderner Software äußerst nützlich sind (und nicht nur bei Spielen!). Im Folgenden findest du einen **sehr kompakten Praxisleitfaden** zu den Ergänzungen, die du bei Red-Team-/CTF-Arbeiten wahrscheinlich am häufigsten verwenden wirst.<sup>[[1]](#references)</sup>

### Verbesserungen am Pointer Scanner 2
* `Pointers must end with specific offsets` und der neue **Deviation**-Regler (ab 7.4) reduzieren falsch-positive Ergebnisse beim erneuten Scannen nach einem Update erheblich. Verwende ihn zusammen mit dem Vergleich mehrerer Maps (`.PTR` → *Compare results with other saved pointer map*), um innerhalb weniger Minuten einen **einzigen robusten Basis-Pointer** zu erhalten.
* Shortcut zum Filtern vieler Einträge: Drücke nach dem ersten Scan `Ctrl+A → Space`, um alles zu markieren, und anschließend `Ctrl+I` (Invertieren), um Adressen abzuwählen, die den erneuten Scan nicht bestanden haben.

### Ultimap 3 – Intel-PT-Tracing
*Ab 7.5 wurde das alte Ultimap auf Basis von **Intel Processor-Trace (IPT)** neu implementiert.* Dadurch kannst du nun **jeden vom Ziel ausgeführten Branch** aufzeichnen, **ohne Single-Stepping** zu verwenden (nur im User-Mode; die meisten Anti-Debug-Gadgets werden dadurch nicht ausgelöst).
```
Memory View → Tools → Ultimap 3 → check «Intel PT»
Select number of buffers → Start
```
Stop the capture nach einigen Sekunden und **right-click → Save execution list to file**. Kombiniere Branch-Adressen mit einer Sitzung von `Find out what addresses this instruction accesses`, um Hotspots der Spiellogik mit hoher Zugriffshäufigkeit extrem schnell zu finden.

### 1-Byte-`jmp`- / Auto-Patch-Templates
Version 7.5 führte einen *one-byte* JMP-Stub (0xEB) ein, der einen SEH-Handler installiert und an der ursprünglichen Stelle ein INT3 platziert. Er wird automatisch generiert, wenn du **Auto Assembler → Template → Code Injection** für Instruktionen verwendest, die nicht mit einem 5-Byte-Relative-Jump gepatcht werden können. Dadurch werden „enge“ Hooks innerhalb gepackter oder größenbeschränkter Routinen möglich.

### Stealth auf Kernel-Ebene mit DBVM (AMD & Intel)
*DBVM* ist der integrierte Type-2-Hypervisor von CE. In aktuellen Builds wurde endlich **AMD-V/SVM-Support** hinzugefügt, sodass du `Driver → Load DBVM` auf Ryzen-/EPYC-Hosts ausführen kannst. DBVM ermöglicht dir:
1. Hardware-Breakpoints zu erstellen, die für Ring-3-/Anti-Debug-Prüfungen unsichtbar sind.
2. Pageable oder geschützte Kernel-Speicherbereiche zu lesen und zu schreiben, selbst wenn der User-Mode-Treiber deaktiviert ist.
3. VM-EXIT-less-Timing-Attack-Bypasses durchzuführen (z. B. `rdtsc` über den Hypervisor abzufragen).

**Tipp:** DBVM verweigert das Laden, wenn HVCI/Memory-Integrity unter Windows 11 aktiviert ist → deaktiviere es oder boote eine dedizierte VM-Host-Umgebung.

### Remote-/plattformübergreifendes Debugging mit **ceserver**
CE wird jetzt mit einer vollständigen Neufassung von *ceserver* ausgeliefert und kann sich über TCP mit **Linux-, Android-, macOS- und iOS-Targets** verbinden. Ein beliebter Fork integriert *Frida*, um dynamische Instrumentierung mit der CE-GUI zu kombinieren – ideal, wenn du Unity- oder Unreal-Spiele patchen musst, die auf einem Smartphone laufen:
```
# on the target (arm64)
./ceserver_arm64 &
# on the analyst workstation
adb forward tcp:52736 tcp:52736   # (or ssh tunnel)
Cheat Engine → "Network" icon → Host = localhost → Connect
```
Für die Frida bridge siehe `bb33bb/frida-ceserver` auf GitHub.<sup>[[2]](#references)</sup>

### Weitere erwähnenswerte Goodies
* **Patch Scanner** (MemView → Tools) – erkennt unerwartete Codeänderungen in ausführbaren Abschnitten; praktisch für Malware-Analyse.
* **Structure Dissector 2** – eine Adresse per Drag-and-drop verschieben → `Ctrl+D`, anschließend *Guess fields* auswählen, um C-Strukturen automatisch auszuwerten.
* **.NET & Mono Dissector** – verbesserte Unity-Spielunterstützung; Methoden direkt über die CE-Lua-Konsole aufrufen.
* **Big-Endian custom types** – Scan/Bearbeitung mit umgekehrter Byte-Reihenfolge (nützlich für Konsolenemulatoren und Netzwerkpaketpuffer).
* **Autosave & tabs** für AutoAssembler/Lua-Fenster sowie `reassemble()` zum Umschreiben mehrzeiliger Instruktionen.

### Installations- & OPSEC-Hinweise (2024-2025)
* Der offizielle Installer ist mit InnoSetup-**ad-offers** (`RAV` usw.) versehen. **Immer auf *Decline* klicken** *oder aus dem Quellcode kompilieren*, um PUPs zu vermeiden. AVs werden `cheatengine.exe` weiterhin als *HackTool* markieren, was zu erwarten ist.
* Moderne Anti-Cheat-Treiber (EAC/Battleye, ACE-BASE.sys, mhyprot2.sys) erkennen die Fensterklasse von CE auch dann, wenn sie umbenannt wurde. Die Reversing-Kopie **innerhalb einer entbehrlichen VM** oder nach dem Deaktivieren des Netzwerkspiels ausführen.
* Wenn du nur User-Mode-Zugriff benötigst, wähle **`Settings → Extra → Kernel mode debug = off`**, um das Laden des nicht signierten CE-Treibers zu vermeiden, der unter Windows 11 24H2 mit Secure-Boot einen BSOD verursachen kann.

---

## Referenzen

- [1] [Cheat Engine 7.5 release notes (GitHub)](https://github.com/cheat-engine/cheat-engine/releases/tag/7.5)
- [2] [frida-ceserver cross-platform bridge](https://github.com/bb33bb/frida-ceserver-Mac-and-IOS)
- [3] Cheat Engine tutorial, absolviere es, um den Einstieg in Cheat Engine zu lernen

{{#include ../../banners/hacktricks-training.md}}
