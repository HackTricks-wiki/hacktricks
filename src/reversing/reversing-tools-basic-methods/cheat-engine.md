# Cheat Engine

{{#include ../../banners/hacktricks-training.md}}

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) ist ein nützliches Programm, um herauszufinden, wo wichtige Werte im Speicher eines laufenden Spiels gespeichert sind und sie zu ändern.\
Wenn Sie es herunterladen und ausführen, wird Ihnen ein **Tutorial** zur Verwendung des Tools **präsentiert**. Wenn Sie lernen möchten, wie man das Tool verwendet, wird dringend empfohlen, es abzuschließen.

## Was suchen Sie?

![](<../../images/image (762).png>)

Dieses Tool ist sehr nützlich, um **herauszufinden, wo ein Wert** (normalerweise eine Zahl) **im Speicher** eines Programms **gespeichert ist**.\
**Normalerweise werden Zahlen** in **4 Bytes** gespeichert, aber Sie könnten sie auch in **double** oder **float** Formaten finden, oder Sie möchten nach etwas **anderem als einer Zahl** suchen. Aus diesem Grund müssen Sie sicherstellen, dass Sie **auswählen**, wonach Sie **suchen möchten**:

![](<../../images/image (324).png>)

Außerdem können Sie **verschiedene** Arten von **Suchen** angeben:

![](<../../images/image (311).png>)

Sie können auch das Kästchen ankreuzen, um **das Spiel während des Scannens des Speichers zu stoppen**:

![](<../../images/image (1052).png>)

### Hotkeys

In _**Bearbeiten --> Einstellungen --> Hotkeys**_ können Sie verschiedene **Hotkeys** für verschiedene Zwecke festlegen, wie z.B. **das Spiel zu stoppen** (was sehr nützlich ist, wenn Sie zu einem bestimmten Zeitpunkt den Speicher scannen möchten). Weitere Optionen sind verfügbar:

![](<../../images/image (864).png>)

## Den Wert ändern

Sobald Sie **gefunden** haben, wo der **Wert** ist, den Sie **suchen** (mehr dazu in den folgenden Schritten), können Sie ihn **ändern**, indem Sie doppelt darauf klicken und dann doppelt auf seinen Wert klicken:

![](<../../images/image (563).png>)

Und schließlich **das Kästchen markieren**, um die Änderung im Speicher vorzunehmen:

![](<../../images/image (385).png>)

Die **Änderung** im **Speicher** wird sofort **angewendet** (beachten Sie, dass der Wert **nicht im Spiel aktualisiert wird**, bis das Spiel diesen Wert nicht erneut verwendet).

## Den Wert suchen

Angenommen, es gibt einen wichtigen Wert (wie das Leben Ihres Benutzers), den Sie verbessern möchten, und Sie suchen nach diesem Wert im Speicher.

### Durch eine bekannte Änderung

Angenommen, Sie suchen nach dem Wert 100, Sie **führen einen Scan** durch, um nach diesem Wert zu suchen, und finden viele Übereinstimmungen:

![](<../../images/image (108).png>)

Dann tun Sie etwas, damit sich der **Wert ändert**, und Sie **stoppen** das Spiel und **führen** einen **nächsten Scan** durch:

![](<../../images/image (684).png>)

Cheat Engine wird nach den **Werten** suchen, die **von 100 auf den neuen Wert** gewechselt sind. Glückwunsch, Sie **haben** die **Adresse** des Wertes gefunden, den Sie gesucht haben, und können ihn jetzt ändern.\
_Wenn Sie immer noch mehrere Werte haben, ändern Sie diesen Wert erneut und führen Sie einen weiteren "nächsten Scan" durch, um die Adressen zu filtern._

### Unbekannter Wert, bekannte Änderung

In dem Szenario, dass Sie **den Wert nicht kennen**, aber wissen, **wie man ihn ändert** (und sogar den Wert der Änderung), können Sie nach Ihrer Zahl suchen.

Beginnen Sie also mit einem Scan des Typs "**Unbekannter Anfangswert**":

![](<../../images/image (890).png>)

Ändern Sie dann den Wert, geben Sie an, **wie** sich der **Wert** **geändert hat** (in meinem Fall wurde er um 1 verringert) und führen Sie einen **nächsten Scan** durch:

![](<../../images/image (371).png>)

Sie werden **alle Werte sehen, die auf die ausgewählte Weise geändert wurden**:

![](<../../images/image (569).png>)

Sobald Sie Ihren Wert gefunden haben, können Sie ihn ändern.

Beachten Sie, dass es **viele mögliche Änderungen** gibt und Sie diese **Schritte so oft wiederholen können, wie Sie möchten**, um die Ergebnisse zu filtern:

![](<../../images/image (574).png>)

### Zufällige Speicheradresse - Den Code finden

Bis jetzt haben wir gelernt, wie man eine Adresse findet, die einen Wert speichert, aber es ist sehr wahrscheinlich, dass in **verschiedenen Ausführungen des Spiels diese Adresse an verschiedenen Stellen im Speicher** ist. Lassen Sie uns also herausfinden, wie man diese Adresse immer findet.

Verwenden Sie einige der erwähnten Tricks, um die Adresse zu finden, an der Ihr aktuelles Spiel den wichtigen Wert speichert. Dann (stoppen Sie das Spiel, wenn Sie möchten) klicken Sie mit der **rechten Maustaste** auf die gefundene **Adresse** und wählen Sie "**Herausfinden, was auf diese Adresse zugreift**" oder "**Herausfinden, was in diese Adresse schreibt**":

![](<../../images/image (1067).png>)

Die **erste Option** ist nützlich, um zu wissen, welche **Teile** des **Codes** diese **Adresse** **verwenden** (was für mehr Dinge nützlich ist, wie z.B. **zu wissen, wo Sie den Code** des Spiels **ändern können**).\
Die **zweite Option** ist spezifischer und wird in diesem Fall hilfreicher sein, da wir daran interessiert sind, **von wo dieser Wert geschrieben wird**.

Sobald Sie eine dieser Optionen ausgewählt haben, wird der **Debugger** an das Programm **angehängt** und ein neues **leeres Fenster** erscheint. Jetzt **spielen** Sie das **Spiel** und **ändern** Sie diesen **Wert** (ohne das Spiel neu zu starten). Das **Fenster** sollte mit den **Adressen**, die den **Wert ändern**, **gefüllt** sein:

![](<../../images/image (91).png>)

Jetzt, da Sie die Adresse gefunden haben, die den Wert ändert, können Sie **den Code nach Belieben ändern** (Cheat Engine ermöglicht es Ihnen, ihn schnell in NOPs zu ändern):

![](<../../images/image (1057).png>)

So können Sie ihn jetzt so ändern, dass der Code Ihre Zahl nicht beeinflusst oder immer positiv beeinflusst.

### Zufällige Speicheradresse - Den Zeiger finden

Befolgen Sie die vorherigen Schritte, um herauszufinden, wo sich der Wert befindet, der Sie interessiert. Verwenden Sie dann "**Herausfinden, was in diese Adresse schreibt**", um herauszufinden, welche Adresse diesen Wert schreibt, und doppelklicken Sie darauf, um die Disassembly-Ansicht zu erhalten:

![](<../../images/image (1039).png>)

Führen Sie dann einen neuen Scan durch, **um den hexadezimalen Wert zwischen "\[]"** zu suchen (den Wert von $edx in diesem Fall):

![](<../../images/image (994).png>)

(_Wenn mehrere erscheinen, benötigen Sie normalerweise die kleinste Adresse_)\
Jetzt haben wir den **Zeiger gefunden, der den Wert ändert, an dem wir interessiert sind**.

Klicken Sie auf "**Adresse manuell hinzufügen**":

![](<../../images/image (990).png>)

Klicken Sie nun auf das Kontrollkästchen "Zeiger" und fügen Sie die gefundene Adresse im Textfeld hinzu (in diesem Szenario war die gefundene Adresse im vorherigen Bild "Tutorial-i386.exe"+2426B0):

![](<../../images/image (392).png>)

(Beachten Sie, dass die erste "Adresse" automatisch mit der Zeigeradresse, die Sie eingeben, ausgefüllt wird)

Klicken Sie auf OK und ein neuer Zeiger wird erstellt:

![](<../../images/image (308).png>)

Jetzt, jedes Mal, wenn Sie diesen Wert ändern, ändern Sie den **wichtigen Wert, auch wenn die Speicheradresse, an der der Wert gespeichert ist, unterschiedlich ist.**

### Code-Injektion

Code-Injektion ist eine Technik, bei der Sie ein Stück Code in den Zielprozess injizieren und dann die Ausführung des Codes so umleiten, dass sie durch Ihren eigenen geschriebenen Code geht (zum Beispiel, um Ihnen Punkte zu geben, anstatt sie abzuziehen).

Stellen Sie sich vor, Sie haben die Adresse gefunden, die 1 vom Leben Ihres Spielers abzieht:

![](<../../images/image (203).png>)

Klicken Sie auf "Disassembler anzeigen", um den **disassemblierten Code** zu erhalten.\
Klicken Sie dann auf **CTRL+a**, um das Auto-Assembly-Fenster aufzurufen, und wählen Sie _**Vorlage --> Code-Injektion**_

![](<../../images/image (902).png>)

Füllen Sie die **Adresse der Anweisung, die Sie ändern möchten** (dies wird normalerweise automatisch ausgefüllt):

![](<../../images/image (744).png>)

Eine Vorlage wird generiert:

![](<../../images/image (944).png>)

Fügen Sie Ihren neuen Assembly-Code in den Abschnitt "**newmem**" ein und entfernen Sie den ursprünglichen Code aus dem Abschnitt "**originalcode**", wenn Sie nicht möchten, dass er ausgeführt wird. In diesem Beispiel wird der injizierte Code 2 Punkte hinzufügen, anstatt 1 abzuziehen:

![](<../../images/image (521).png>)

**Klicken Sie auf Ausführen und so weiter, und Ihr Code sollte in das Programm injiziert werden, wodurch das Verhalten der Funktionalität geändert wird!**

## Erweiterte Funktionen in Cheat Engine 7.x (2023-2025)

Cheat Engine hat sich seit Version 7.0 weiterentwickelt, und mehrere Verbesserungen der Benutzerfreundlichkeit und *offensive-reversing* Funktionen wurden hinzugefügt, die beim Analysieren moderner Software (und nicht nur von Spielen!) äußerst nützlich sind. Im Folgenden finden Sie einen **sehr kompakten Feldführer** zu den Ergänzungen, die Sie höchstwahrscheinlich während der Red-Team/CTF-Arbeit verwenden werden.

### Verbesserungen des Pointer Scanners 2
* `Zeiger müssen mit spezifischen Offsets enden` und der neue **Deviation**-Schieberegler (≥7.4) reduziert erheblich falsch-positive Ergebnisse, wenn Sie nach einem Update erneut scannen. Verwenden Sie ihn zusammen mit dem Multi-Map-Vergleich (`.PTR` → *Ergebnisse mit anderen gespeicherten Zeigermaps vergleichen*), um in nur wenigen Minuten einen **einzigen widerstandsfähigen Basiszeiger** zu erhalten.
* Bulk-Filter-Shortcut: Nach dem ersten Scan drücken Sie `Ctrl+A → Leertaste`, um alles zu markieren, und dann `Ctrl+I` (invertieren), um Adressen abzuwählen, die den erneuten Scan nicht bestanden haben.

### Ultimap 3 – Intel PT-Tracking
*Ab Version 7.5 wurde das alte Ultimap auf **Intel Processor-Trace (IPT)** neu implementiert. Das bedeutet, dass Sie jetzt *jede* Verzweigung, die das Ziel nimmt, **ohne Einzelstepping** aufzeichnen können (nur im Benutzermodus, es wird die meisten Anti-Debug-Gadgets nicht auslösen).
```
Memory View → Tools → Ultimap 3 → check «Intel PT»
Select number of buffers → Start
```
Nach ein paar Sekunden stoppen Sie die Aufnahme und **rechte Maustaste → Ausführungsliste in Datei speichern**. Kombinieren Sie die Zweigadressen mit einer Sitzung „Finden Sie heraus, auf welche Adressen diese Anweisung zugreift“, um Hochfrequenz-Spiel-Logik-Hotspots extrem schnell zu lokalisieren.

### 1-Byte `jmp` / Auto-Patch-Vorlagen
Version 7.5 führte einen *ein-Byte* JMP Stub (0xEB) ein, der einen SEH-Handler installiert und ein INT3 an der ursprünglichen Stelle platziert. Er wird automatisch generiert, wenn Sie **Auto Assembler → Vorlage → Code-Injektion** bei Anweisungen verwenden, die nicht mit einem 5-Byte relativen Sprung gepatcht werden können. Dies ermöglicht „enge“ Hooks innerhalb von gepackten oder größenbeschränkten Routinen.

### Kernel-Level-Stealth mit DBVM (AMD & Intel)
*DBVM* ist der integrierte Type-2-Hypervisor von CE. Neuere Builds haben endlich **AMD-V/SVM-Unterstützung** hinzugefügt, sodass Sie `Driver → Load DBVM` auf Ryzen/EPYC-Hosts ausführen können. DBVM ermöglicht Ihnen:
1. Hardware-Breakpoints zu erstellen, die für Ring-3/Anti-Debug-Prüfungen unsichtbar sind.
2. Lese-/Schreibzugriff auf seitenfähige oder geschützte Kernel-Speicherbereiche, selbst wenn der Benutzermodus-Treiber deaktiviert ist.
3. VM-EXIT-freie Timing-Angriff-Umgehungen durchzuführen (z. B. `rdtsc` vom Hypervisor abfragen).

**Tipp:** DBVM weigert sich zu laden, wenn HVCI/Memory-Integrity unter Windows 11 aktiviert ist → schalten Sie es aus oder starten Sie einen dedizierten VM-Host.

### Remote / plattformübergreifendes Debugging mit **ceserver**
CE wird jetzt mit einer vollständigen Neuschreibung von *ceserver* ausgeliefert und kann über TCP mit **Linux, Android, macOS & iOS** Zielen verbunden werden. Ein beliebter Fork integriert *Frida*, um dynamische Instrumentierung mit der GUI von CE zu kombinieren – ideal, wenn Sie Unity- oder Unreal-Spiele auf einem Telefon patchen müssen:
```
# on the target (arm64)
./ceserver_arm64 &
# on the analyst workstation
adb forward tcp:52736 tcp:52736   # (or ssh tunnel)
Cheat Engine → "Network" icon → Host = localhost → Connect
```
Für die Frida-Brücke siehe `bb33bb/frida-ceserver` auf GitHub.

### Weitere bemerkenswerte Tools
* **Patch Scanner** (MemView → Tools) – erkennt unerwartete Codeänderungen in ausführbaren Abschnitten; nützlich für Malware-Analysen.
* **Structure Dissector 2** – drag-an-address → `Ctrl+D`, dann *Guess fields*, um C-Strukturen automatisch zu bewerten.
* **.NET & Mono Dissector** – verbesserte Unterstützung für Unity-Spiele; Methoden direkt aus der CE Lua-Konsole aufrufen.
* **Big-Endian benutzerdefinierte Typen** – umgekehrte Byte-Reihenfolge scannen/bearbeiten (nützlich für Konsolenemulatoren und Netzwerkpaketpuffer).
* **Autosave & Tabs** für AutoAssembler/Lua-Fenster, plus `reassemble()` für mehrzeilige Anweisungsumformulierung.

### Installations- & OPSEC-Hinweise (2024-2025)
* Der offizielle Installer ist mit InnoSetup **Werbeangeboten** (z.B. `RAV`) verpackt. **Immer auf *Ablehnen* klicken** *oder aus dem Quellcode kompilieren*, um PUPs zu vermeiden. AVs werden `cheatengine.exe` weiterhin als *HackTool* kennzeichnen, was zu erwarten ist.
* Moderne Anti-Cheat-Treiber (EAC/Battleye, ACE-BASE.sys, mhyprot2.sys) erkennen die Fensterklasse von CE, selbst wenn sie umbenannt wurde. Führen Sie Ihre Reverse-Engineering-Kopie **in einer Einweg-VM** oder nach Deaktivierung des Netzwerkspiels aus.
* Wenn Sie nur Zugriff im Benutzermodus benötigen, wählen Sie **`Settings → Extra → Kernel mode debug = off`**, um das Laden des nicht signierten Treibers von CE zu vermeiden, der auf Windows 11 24H2 Secure-Boot einen BSOD verursachen kann.

---

## **Referenzen**

- [Cheat Engine 7.5 Release-Notizen (GitHub)](https://github.com/cheat-engine/cheat-engine/releases/tag/7.5)
- [frida-ceserver plattformübergreifende Brücke](https://github.com/bb33bb/frida-ceserver-Mac-and-IOS)
- **Cheat Engine Tutorial, vervollständigen Sie es, um zu lernen, wie man mit Cheat Engine beginnt**

{{#include ../../banners/hacktricks-training.md}}
