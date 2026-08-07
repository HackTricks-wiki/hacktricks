# Cheat Engine

{{#include ../../banners/hacktricks-training.md}}

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) ist ein nützliches Programm, um herauszufinden, wo wichtige Werte im Speicher eines laufenden Spiels gespeichert sind, und sie zu ändern.\
Wenn du es herunterlädst und ausführst, wird dir ein **Tutorial** zur Verwendung des Tools angezeigt. Wenn du lernen möchtest, wie man das Tool benutzt, wird dringend empfohlen, es abzuschließen.

## Wonach suchst du?

![Cheat Engine - Wonach suchst du?: Wonach suchst du?](<../../images/image (762).png>)

Dieses Tool ist sehr nützlich, um herauszufinden, **wo ein bestimmter Wert** (normalerweise eine Zahl) **im Speicher** eines Programms **gespeichert ist**.\
**Zahlen werden normalerweise** im Format **4bytes** gespeichert, aber du kannst sie auch in den Formaten **double** oder **float** finden. Außerdem möchtest du möglicherweise nach etwas **anderem als einer Zahl** suchen. Deshalb musst du sicherstellen, dass du auswählst, wonach du **suchen** möchtest:

![Cheat Engine - Wonach suchst du?: Zahlen werden normalerweise im Format 4bytes gespeichert, aber du kannst sie auch in den Formaten double oder float finden oder nach etwas anderem suchen...](<../../images/image (324).png>)

Du kannst auch verschiedene **Suchtypen** angeben:

![Cheat Engine - Wonach suchst du?: Du kannst auch verschiedene Suchtypen angeben](<../../images/image (311).png>)

Du kannst außerdem das Kontrollkästchen aktivieren, um **das Spiel während des Speicherscans anzuhalten**:

![Cheat Engine - Wonach suchst du?: Du kannst außerdem das Kontrollkästchen aktivieren, um das Spiel während des Speicherscans anzuhalten](<../../images/image (1052).png>)

### Hotkeys

Unter _**Edit --> Settings --> Hotkeys**_ kannst du verschiedene **Hotkeys** für unterschiedliche Zwecke festlegen, zum Beispiel zum **Anhalten** des **Spiels** (was besonders nützlich ist, wenn du zu einem bestimmten Zeitpunkt den Speicher scannen möchtest). Weitere Optionen sind verfügbar:

![Wonach suchst du? - Hotkeys: Unter Edit -- Settings -- Hotkeys kannst du verschiedene Hotkeys für unterschiedliche Zwecke festlegen, zum Beispiel zum Anhalten des Spiels (was besonders nützlich ist, wenn du zu einem bestimmten Zeitpunkt...](<../../images/image (864).png>)

## Ändern des Werts

Sobald du herausgefunden hast, wo sich der **gesuchte Wert** befindet (mehr dazu in den folgenden Schritten), kannst du ihn ändern, indem du doppelt darauf und anschließend doppelt auf seinen Wert klickst:

![Hotkeys - Ändern des Werts: Sobald du herausgefunden hast, wo sich der gesuchte Wert befindet (mehr dazu in den folgenden Schritten), kannst du ihn ändern, indem du doppelt darauf und anschließend doppelt...](<../../images/image (563).png>)

Aktiviere schließlich das **Kontrollkästchen**, damit die Änderung im Speicher vorgenommen wird:

![Hotkeys - Ändern des Werts: Aktiviere schließlich das Kontrollkästchen, damit die Änderung im Speicher vorgenommen wird](<../../images/image (385).png>)

Die **Änderung** im **Speicher** wird sofort **angewendet** (beachte, dass der Wert im Spiel erst aktualisiert wird, wenn das Spiel diesen Wert erneut verwendet).

## Nach dem Wert suchen

Nehmen wir an, dass es einen wichtigen Wert gibt (zum Beispiel die Lebenspunkte deines Benutzers), den du verbessern möchtest, und dass du diesen Wert im Speicher suchst.

### Über eine bekannte Änderung

Angenommen, du suchst nach dem Wert 100. Du **führst einen Scan** nach diesem Wert durch und erhältst viele Treffer:

![Nach dem Wert suchen - Über eine bekannte Änderung: Angenommen, du suchst nach dem Wert 100. Du führst einen Scan nach diesem Wert durch und erhältst viele Treffer](<../../images/image (108).png>)

Dann führst du eine Aktion aus, durch die sich der **Wert ändert**, hältst das **Spiel** an und führst einen **nächsten Scan** durch:

![Nach dem Wert suchen - Über eine bekannte Änderung: Dann führst du eine Aktion aus, durch die sich der Wert ändert, hältst das Spiel an und führst einen nächsten Scan durch](<../../images/image (684).png>)

Cheat Engine sucht nach den **Werten**, die sich **von 100 auf den neuen Wert geändert haben**. Glückwunsch, du hast die **Adresse** des gesuchten Werts gefunden und kannst ihn nun ändern.\
_Wenn noch mehrere Werte vorhanden sind, ändere diesen Wert erneut und führe einen weiteren „next scan“ durch, um die Adressen zu filtern._

### Unbekannter Wert, bekannte Änderung

Wenn du den **Wert** nicht kennst, aber weißt, **wie du ihn ändern kannst** (und sogar den Änderungswert kennst), kannst du nach deiner Zahl suchen.

Beginne mit einem Scan des Typs **„Unknown initial value“**:

![Über eine bekannte Änderung - Unbekannter Wert, bekannte Änderung: Beginne mit einem Scan des Typs „Unknown initial value“](<../../images/image (890).png>)

Ändere anschließend den Wert, gib an, **wie** sich der **Wert** **geändert hat** (in meinem Fall wurde er um 1 verringert) und führe einen **nächsten Scan** durch:

![Über eine bekannte Änderung - Unbekannter Wert, bekannte Änderung: Ändere anschließend den Wert, gib an, wie sich der Wert geändert hat (in meinem Fall wurde er um 1 verringert) und führe einen nächsten Scan durch](<../../images/image (371).png>)

Dir werden **alle Werte angezeigt, die auf die ausgewählte Weise geändert wurden**:

![Über eine bekannte Änderung - Unbekannter Wert, bekannte Änderung: Dir werden alle Werte angezeigt, die auf die ausgewählte Weise geändert wurden](<../../images/image (569).png>)

Sobald du deinen Wert gefunden hast, kannst du ihn ändern.

Beachte, dass es **zahlreiche mögliche Änderungen** gibt und du diese **Schritte beliebig oft** ausführen kannst, um die Ergebnisse zu filtern:

![Über eine bekannte Änderung - Unbekannter Wert, bekannte Änderung: Beachte, dass es zahlreiche mögliche Änderungen gibt und du diese Schritte beliebig oft ausführen kannst, um die Ergebnisse zu filtern](<../../images/image (574).png>)

### Zufällige Speicheradresse – Den Code finden

Bisher haben wir gelernt, wie man eine Adresse findet, an der ein Wert gespeichert ist. Es ist jedoch sehr wahrscheinlich, dass sich diese Adresse **bei verschiedenen Ausführungen des Spiels an unterschiedlichen Stellen im Speicher befindet**. Finden wir also heraus, wie wir diese Adresse immer finden können.

Finde mithilfe einiger der genannten Tricks die Adresse, an der dein aktuelles Spiel den wichtigen Wert speichert. Klicke anschließend (du kannst das Spiel bei Bedarf vorher anhalten) mit der **rechten Maustaste** auf die gefundene **Adresse** und wähle **„Find out what accesses this address“** oder **„Find out what writes to this address“**:

![Unbekannter Wert, bekannte Änderung – Zufällige Speicheradresse – Den Code finden: Finde mithilfe einiger der genannten Tricks die Adresse, an der dein aktuelles Spiel den wichtigen Wert speichert. Klicke anschließend...](<../../images/image (1067).png>)

Die **erste Option** ist nützlich, um herauszufinden, welche **Teile** des **Codes** diese **Adresse verwenden** (was auch für andere Dinge hilfreich ist, zum Beispiel um herauszufinden, **wo du den Code** des Spiels **ändern kannst**).\
Die **zweite Option** ist **spezifischer** und in diesem Fall hilfreicher, da wir herausfinden möchten, **von wo aus dieser Wert geschrieben wird**.

Nachdem du eine dieser Optionen ausgewählt hast, wird der **Debugger** an das Programm **angehängt** und ein neues **leeres Fenster** wird angezeigt. Spiele nun das **Spiel** und ändere diesen **Wert** (ohne das Spiel neu zu starten). Das **Fenster** sollte mit den **Adressen** gefüllt werden, die den **Wert ändern**:

![Unbekannter Wert, bekannte Änderung – Zufällige Speicheradresse – Den Code finden: Nachdem du eine dieser Optionen ausgewählt hast, wird der Debugger an das Programm angehängt und ein neues leeres Fenster...](<../../images/image (91).png>)

Da du nun die Adresse gefunden hast, die den Wert ändert, kannst du den **Code nach Belieben ändern** (Cheat Engine ermöglicht es, ihn sehr schnell durch NOPs zu ersetzen):

![Unbekannter Wert, bekannte Änderung – Zufällige Speicheradresse – Den Code finden: Da du nun die Adresse gefunden hast, die den Wert ändert, kannst du den Code nach Belieben ändern (Cheat Engine...](<../../images/image (1057).png>)

Du kannst ihn nun so ändern, dass der Code deine Zahl nicht beeinflusst oder sie immer auf positive Weise beeinflusst.

### Zufällige Speicheradresse – Den Pointer finden

Befolge die vorherigen Schritte und finde heraus, wo sich der gewünschte Wert befindet. Verwende anschließend **„Find out what writes to this address“**, um herauszufinden, welche Adresse diesen Wert schreibt, und doppelklicke darauf, um die Disassembly-Ansicht zu öffnen:

![Zufällige Speicheradresse – Den Code finden – Zufällige Speicheradresse – Den Pointer finden: Befolge die vorherigen Schritte und finde heraus, wo sich der gewünschte Wert befindet. Verwende anschließend „Find out...](<../../images/image (1039).png>)

Führe anschließend einen neuen Scan durch und **suche nach dem Hex-Wert zwischen „\[]“** (in diesem Fall dem Wert von $edx):

![Zufällige Speicheradresse – Den Code finden – Zufällige Speicheradresse – Den Pointer finden: Führe anschließend einen neuen Scan durch und suche nach dem Hex-Wert zwischen „ ()“ (in diesem Fall dem Wert von $edx)](<../../images/image (994).png>)

(_Wenn mehrere Treffer erscheinen, benötigst du normalerweise die Adresse mit dem kleinsten Wert._)\
Nun haben wir **den Pointer gefunden, der den für uns wichtigen Wert ändern wird**.

Klicke auf **„Add Address Manually“**:

![Zufällige Speicheradresse – Den Code finden – Zufällige Speicheradresse – Den Pointer finden: Klicke auf „Add Address Manually“](<../../images/image (990).png>)

Klicke nun auf das Kontrollkästchen **„Pointer“** und füge die gefundene Adresse in das Textfeld ein (in diesem Szenario war die gefundene Adresse im vorherigen Bild **„Tutorial-i386.exe“+2426B0**):

![Zufällige Speicheradresse – Den Code finden – Zufällige Speicheradresse – Den Pointer finden: Klicke nun auf das Kontrollkästchen „Pointer“ und füge die gefundene Adresse in das Textfeld ein (in diesem Szenario...](<../../images/image (392).png>)

(Beachte, dass die erste **„Address“** automatisch mit der von dir eingegebenen Pointer-Adresse ausgefüllt wird.)

Klicke auf „OK“, woraufhin ein neuer Pointer erstellt wird:

![Zufällige Speicheradresse – Den Code finden – Zufällige Speicheradresse – Den Pointer finden: Klicke auf „OK“, woraufhin ein neuer Pointer erstellt wird](<../../images/image (308).png>)

Wenn du diesen Wert nun änderst, **änderst du den wichtigen Wert jedes Mal, selbst wenn sich die Speicheradresse, an der sich der Wert befindet, ändert.**

### Code Injection

Code injection ist eine Technik, bei der du ein Stück Code in den Zielprozess injizierst und anschließend die Ausführung des Codes umleitest, sodass sie durch deinen eigenen Code läuft (zum Beispiel indem du dir Punkte gibst, anstatt sie abzuziehen).

Nehmen wir an, du hast die Adresse gefunden, die 1 von den Lebenspunkten deines Spielers abzieht:

![Zufällige Speicheradresse – Den Pointer finden – Code Injection: Nehmen wir an, du hast die Adresse gefunden, die 1 von den Lebenspunkten deines Spielers abzieht](<../../images/image (203).png>)

Klicke auf **„Show disassembler“**, um den **disassemblierten Code** anzuzeigen.\
Drücke anschließend **CTRL+a**, um das Fenster **„Auto assemble“** zu öffnen, und wähle _**Template --> Code Injection**_ aus:

![Zufällige Speicheradresse – Den Pointer finden – Code Injection: Drücke anschließend CTRL+a, um das Fenster Auto assemble zu öffnen, und wähle Template -- Code Injection aus](<../../images/image (902).png>)

Fülle die **Adresse der zu ändernden Instruktion** aus (dieses Feld wird normalerweise automatisch ausgefüllt):

![Zufällige Speicheradresse – Den Pointer finden – Code Injection: Fülle die Adresse der zu ändernden Instruktion aus (dieses Feld wird normalerweise automatisch ausgefüllt)](<../../images/image (744).png>)

Eine Vorlage wird erstellt:

![Zufällige Speicheradresse – Den Pointer finden – Code Injection: Eine Vorlage wird erstellt](<../../images/image (944).png>)

Füge deinen neuen Assembly-Code in den Abschnitt **„newmem“** ein und entferne den ursprünglichen Code aus **„originalcode“**, wenn er nicht ausgeführt werden soll**.** In diesem Beispiel fügt der injizierte Code 2 Punkte hinzu, anstatt 1 abzuziehen:

![Zufällige Speicheradresse – Den Pointer finden – Code Injection: Füge deinen neuen Assembly-Code in den Abschnitt „newmem“ ein und entferne den ursprünglichen Code aus „originalcode“, wenn er...](<../../images/image (521).png>)

**Klicke auf „execute“ und so weiter. Dein Code sollte anschließend in das Programm injiziert sein und das Verhalten der Funktion ändern!**

## Erweiterte Funktionen in Cheat Engine 7.x (2023–2025)

Cheat Engine wurde seit Version 7.0 kontinuierlich weiterentwickelt. Dabei wurden mehrere Quality-of-Life- und *offensive-reversing*-Funktionen hinzugefügt, die bei der Analyse moderner Software (und nicht nur von Spielen!) äußerst praktisch sind. Im Folgenden findest du einen **sehr kompakten Leitfaden** zu den Erweiterungen, die du bei Red-Team- und CTF-Arbeiten wahrscheinlich am häufigsten verwenden wirst.<sup>[[1]](#references)</sup>

### Verbesserungen am Pointer Scanner 2
* `Pointers must end with specific offsets` und der neue **Deviation**-Regler (ab 7.4) reduzieren False Positives beim erneuten Scannen nach einem Update erheblich. Verwende ihn zusammen mit dem Multi-Map-Vergleich (`.PTR` → *Compare results with other saved pointer map*), um in nur wenigen Minuten einen **einzigen robusten Base-Pointer** zu erhalten.
* Tastenkürzel für die Massenfilterung: Drücke nach dem ersten Scan `Ctrl+A → Space`, um alles zu markieren, und anschließend `Ctrl+I` (invertieren), um Adressen abzuwählen, die den erneuten Scan nicht bestanden haben.

### Ultimap 3 – Intel-PT-Tracing
*Ab 7.5 wurde das alte Ultimap auf Basis von **Intel Processor-Trace (IPT)** neu implementiert.* Dadurch kannst du nun **jeden Branch aufzeichnen**, den das Ziel ausführt, **ohne Single-Stepping** (nur im User-Mode; die meisten Anti-Debug-Gadgets werden dadurch nicht ausgelöst).
```
Memory View → Tools → Ultimap 3 → check «Intel PT»
Select number of buffers → Start
```
Nach einigen Sekunden beendest du die Aufzeichnung und wählst **right-click → Save execution list to file**. Kombiniere Branch-Adressen mit einer Sitzung von `Find out what addresses this instruction accesses`, um Hotspots der Spiellogik mit hoher Zugriffshäufigkeit extrem schnell zu finden.

### 1-Byte-`jmp`-/Auto-Patch-Templates
Version 7.5 führte einen *one-byte* JMP-Stub (0xEB) ein, der einen SEH-Handler installiert und am ursprünglichen Speicherort ein INT3 platziert. Er wird automatisch generiert, wenn du **Auto Assembler → Template → Code Injection** bei Instruktionen verwendest, die nicht mit einem 5-Byte-Relative-Jump gepatcht werden können. Dadurch werden „enge“ Hooks innerhalb gepackter oder größenbeschränkter Routinen möglich.<sup>[[1]](#references)</sup>

### Stealth auf Kernel-Ebene mit DBVM (AMD & Intel)
*DBVM* ist der integrierte Type-2-Hypervisor von CE. Neuere Builds bieten nun auch **AMD-V/SVM support**, sodass du `Driver → Load DBVM` auf Ryzen-/EPYC-Hosts ausführen kannst. DBVM ermöglicht dir:
1. Hardware-Breakpoints zu erstellen, die für Ring-3-/Anti-Debug-Prüfungen unsichtbar sind.
2. Pageable oder geschützte Kernel-Speicherbereiche zu lesen und zu schreiben, selbst wenn der User-Mode-Treiber deaktiviert ist.
3. VM-EXIT-less-Timing-Attack-Bypasses durchzuführen, beispielsweise `rdtsc` aus dem Hypervisor abzufragen.

**Tipp:** DBVM verweigert das Laden, wenn HVCI/Memory-Integrity unter Windows 11 aktiviert ist → deaktiviere die Funktion oder boote eine dedizierte VM-Host-Umgebung.

### Remote-/Cross-Platform-Debugging mit **ceserver**
CE wird nun mit einer vollständigen Neufassung von *ceserver* ausgeliefert und kann sich über TCP mit **Linux-, Android-, macOS- und iOS**-Targets verbinden. Ein beliebter Fork integriert *Frida*, um dynamische Instrumentierung mit der CE-GUI zu kombinieren – ideal, wenn du Unity- oder Unreal-Spiele patchen musst, die auf einem Smartphone laufen:
```
# on the target (arm64)
./ceserver_arm64 &
# on the analyst workstation
adb forward tcp:52736 tcp:52736   # (or ssh tunnel)
Cheat Engine → "Network" icon → Host = localhost → Connect
```
Für die Frida bridge siehe `bb33bb/frida-ceserver` auf GitHub.<sup>[[1]](#references)[[2]](#references)</sup>

### Weitere bemerkenswerte Extras
* **Patch Scanner** (MemView → Tools) – erkennt unerwartete Codeänderungen in ausführbaren Abschnitten; praktisch für Malware-Analyse.
* **Structure Dissector 2** – ziehe eine Adresse hinein → `Ctrl+D`, wähle dann *Guess fields*, um C-Strukturen automatisch auszuwerten.
* **.NET & Mono Dissector** – verbesserte Unity-Spielunterstützung; rufe Methoden direkt über die CE-Lua-Konsole auf.
* **Big-Endian custom types** – Scan/Bearbeitung mit umgekehrter Byte-Reihenfolge (nützlich für Konsolenemulatoren und Netzwerkpaketpuffer).
* **Autosave & tabs** für AutoAssembler/Lua-Fenster sowie `reassemble()` zum Umschreiben mehrzeiliger Instruktionen.<sup>[[1]](#references)</sup>

### Installations- und OPSEC-Hinweise (2024-2025)
* Der offizielle Installer ist mit **Werbeangeboten** von InnoSetup (`RAV` usw.) versehen. **Klicke immer auf *Decline*** *oder kompiliere aus dem Quellcode*, um PUPs zu vermeiden. AVs werden `cheatengine.exe` weiterhin als *HackTool* melden, was erwartet wird.
* Moderne Anti-Cheat-Treiber (EAC/Battleye, ACE-BASE.sys, mhyprot2.sys) erkennen die Fensterklasse von CE auch nach einer Umbenennung. Führe deine Reversing-Kopie **in einer verworfenen VM** oder nach der Deaktivierung des Netzwerkspiels aus.
* Wenn du nur User-Mode-Zugriff benötigst, wähle **`Settings → Extra → Kernel mode debug = off`**, um das Laden des unsignierten CE-Treibers zu vermeiden, der unter Windows 11 24H2 mit Secure Boot einen BSOD verursachen kann.

---

## Referenzen

- [1] [Cheat Engine 7.5 release notes (GitHub)](https://github.com/cheat-engine/cheat-engine/releases/tag/7.5)
- [2] [frida-ceserver cross-platform bridge](https://github.com/bb33bb/frida-ceserver-Mac-and-IOS)

{{#include ../../banners/hacktricks-training.md}}
