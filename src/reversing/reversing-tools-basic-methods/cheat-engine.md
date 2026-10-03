# Cheat Engine

{{#include ../../banners/hacktricks-training.md}}

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) ist ein nützliches Programm, um herauszufinden, wo wichtige Werte im Speicher eines laufenden Spiels gespeichert sind, und sie zu ändern.\
Wenn du es herunterlädst und startest, wird dir ein **Tutorial** zur Verwendung des Tools angezeigt. Wenn du lernen möchtest, wie man das Tool verwendet, wird dringend empfohlen, es vollständig durchzuarbeiten.

## Wonach suchst du?

![Cheat Engine - Wonach suchst du?: Wonach suchst du?](<../../images/image (762).png>)

Dieses Tool ist sehr nützlich, um herauszufinden, **wo ein bestimmter Wert** (normalerweise eine Zahl) **im Speicher** eines Programms **gespeichert ist**.\
**Zahlen werden normalerweise** als **4bytes** gespeichert, aber du kannst sie auch in den Formaten **double** oder **float** finden oder nach etwas **anderem als einer Zahl** suchen. Deshalb musst du sicherstellen, dass du auswählst, wonach du **suchen** möchtest:

![Cheat Engine - Wonach suchst du?: Zahlen werden normalerweise als 4bytes gespeichert, aber du kannst sie auch in den Formaten double oder float finden oder nach etwas anderem als einer Zahl suchen...](<../../images/image (324).png>)

Du kannst auch **verschiedene** Arten von **Suchen** angeben:

![Cheat Engine - Wonach suchst du?: Du kannst auch verschiedene Arten von Suchen angeben](<../../images/image (311).png>)

Du kannst außerdem das Kästchen aktivieren, um **das Spiel während des Scans des Speichers anzuhalten**:

![Cheat Engine - Wonach suchst du?: Du kannst außerdem das Kästchen aktivieren, um das Spiel während des Scans des Speichers anzuhalten](<../../images/image (1052).png>)

### Hotkeys

Unter _**Edit --> Settings --> Hotkeys**_ kannst du verschiedene **Hotkeys** für unterschiedliche Zwecke festlegen, zum Beispiel zum **Anhalten** des **Spiels** (was besonders nützlich ist, wenn du irgendwann den Speicher scannen möchtest). Weitere Optionen sind verfügbar:

![Wonach suchst du? - Hotkeys: Unter Edit -- Settings -- Hotkeys kannst du verschiedene Hotkeys für unterschiedliche Zwecke festlegen, zum Beispiel zum Anhalten des Spiels (was besonders nützlich ist, wenn du irgendwann...](<../../images/image (864).png>)

## Ändern des Werts

Sobald du **gefunden** hast, wo sich der **gesuchte Wert** befindet (mehr dazu in den folgenden Schritten), kannst du ihn ändern, indem du doppelt darauf und anschließend doppelt auf seinen Wert klickst:

![Hotkeys - Ändern des Werts: Sobald du gefunden hast, wo sich der gesuchte Wert befindet (mehr dazu in den folgenden Schritten), kannst du ihn ändern, indem du doppelt darauf und anschließend doppelt...](<../../images/image (563).png>)

Und schließlich **das Kontrollkästchen aktivierst**, damit die Änderung im Speicher vorgenommen wird:

![Hotkeys - Ändern des Werts: Und schließlich das Kontrollkästchen aktivierst, damit die Änderung im Speicher vorgenommen wird](<../../images/image (385).png>)

Die **Änderung** am **Speicher** wird sofort **angewendet** (beachte, dass der Wert im Spiel erst aktualisiert wird, wenn das Spiel diesen Wert erneut verwendet).

## Suchen des Werts

Nehmen wir an, dass es einen wichtigen Wert gibt (zum Beispiel die Lebenspunkte deines Spielers), den du erhöhen möchtest, und dass du diesen Wert im Speicher suchst.

### Über eine bekannte Änderung

Angenommen, du suchst nach dem Wert 100, führst du einen **Scan** nach diesem Wert durch und erhältst viele Treffer:

![Suchen des Werts - Über eine bekannte Änderung: Angenommen, du suchst nach dem Wert 100, führst du einen Scan nach diesem Wert durch und erhältst viele Treffer](<../../images/image (108).png>)

Dann tust du etwas, wodurch sich der **Wert ändert**, **hältst** das Spiel an und führst einen **nächsten Scan** durch:

![Suchen des Werts - Über eine bekannte Änderung: Dann tust du etwas, wodurch sich der Wert ändert, hältst das Spiel an und führst einen nächsten Scan durch](<../../images/image (684).png>)

Cheat Engine sucht nach den **Werten**, die **von 100 auf den neuen Wert geändert wurden**. Glückwunsch, du hast die **Adresse** des gesuchten Werts **gefunden** und kannst ihn nun ändern.\
_Wenn noch mehrere Werte vorhanden sind, ändere diesen Wert erneut und führe einen weiteren „next scan“ durch, um die Adressen zu filtern._

### Unbekannter Wert, bekannte Änderung

Wenn du in diesem Szenario den **Wert nicht kennst**, aber weißt, **wie du ihn ändern kannst** (und sogar den Betrag der Änderung kennst), kannst du nach deiner Zahl suchen.

Beginne mit einem Scan des Typs **„Unknown initial value“**:

![Über eine bekannte Änderung - Unbekannter Wert, bekannte Änderung: Beginne mit einem Scan des Typs „Unknown initial value“](<../../images/image (890).png>)

Ändere anschließend den Wert, gib an, **wie** sich der **Wert** geändert hat (in meinem Fall wurde er um 1 verringert), und führe einen **nächsten Scan** durch:

![Über eine bekannte Änderung - Unbekannter Wert, bekannte Änderung: Ändere anschließend den Wert, gib an, wie sich der Wert geändert hat (in meinem Fall wurde er um 1 verringert), und führe einen nächsten Scan durch](<../../images/image (371).png>)

Dir werden **alle Werte angezeigt, die auf die ausgewählte Weise geändert wurden**:

![Über eine bekannte Änderung - Unbekannter Wert, bekannte Änderung: Dir werden alle Werte angezeigt, die auf die ausgewählte Weise geändert wurden](<../../images/image (569).png>)

Sobald du deinen Wert gefunden hast, kannst du ihn ändern.

Beachte, dass es **viele mögliche Änderungen** gibt und du diese **Schritte beliebig oft** durchführen kannst, um die Ergebnisse zu filtern:

![Über eine bekannte Änderung - Unbekannter Wert, bekannte Änderung: Beachte, dass es viele mögliche Änderungen gibt und du diese Schritte beliebig oft durchführen kannst, um die Ergebnisse zu filtern](<../../images/image (574).png>)

### Zufällige Speicheradresse – Den Code finden

Bisher haben wir gelernt, wie man eine Adresse findet, die einen Wert speichert. Es ist jedoch sehr wahrscheinlich, dass sich diese Adresse **bei verschiedenen Ausführungen des Spiels an unterschiedlichen Stellen im Speicher befindet**. Finden wir also heraus, wie wir diese Adresse immer finden können.

Finde mithilfe einiger der genannten Tricks die Adresse, an der dein aktuelles Spiel den wichtigen Wert speichert. Klicke dann (du kannst das Spiel vorher anhalten, wenn du möchtest) mit der **rechten Maustaste** auf die gefundene **Adresse** und wähle **„Find out what accesses this address“** oder **„Find out what writes to this address“**:

![Unbekannter Wert, bekannte Änderung - Zufällige Speicheradresse – Den Code finden: Finde mithilfe einiger der genannten Tricks die Adresse, an der dein aktuelles Spiel den wichtigen Wert speichert. Klicke dann...](<../../images/image (1067).png>)

Die **erste Option** ist nützlich, um zu erfahren, welche **Teile** des **Codes** diese **Adresse verwenden** (was auch für andere Dinge nützlich ist, zum Beispiel um herauszufinden, **wo du den Code** des Spiels **ändern kannst**).\
Die **zweite Option** ist **spezifischer** und in diesem Fall hilfreicher, da wir wissen möchten, **von wo aus dieser Wert geschrieben wird**.

Nachdem du eine dieser Optionen ausgewählt hast, wird der **Debugger** an das Programm **angehängt** und ein neues **leeres Fenster** angezeigt. **Spiele** nun das **Spiel** und **ändere** diesen **Wert** (ohne das Spiel neu zu starten). Das **Fenster** sollte mit den **Adressen** gefüllt werden, die den **Wert ändern**:

![Unbekannter Wert, bekannte Änderung - Zufällige Speicheradresse – Den Code finden: Nachdem du eine dieser Optionen ausgewählt hast, wird der Debugger an das Programm angehängt und ein neues leeres Fenster...](<../../images/image (91).png>)

Nachdem du die Adresse gefunden hast, die den Wert ändert, kannst du den **Code nach deinen Wünschen ändern** (Cheat Engine ermöglicht es, ihn sehr schnell durch NOPs zu ersetzen):

![Unbekannter Wert, bekannte Änderung - Zufällige Speicheradresse – Den Code finden: Nachdem du die Adresse gefunden hast, die den Wert ändert, kannst du den Code nach deinen Wünschen ändern (Cheat Engine...](<../../images/image (1057).png>)

Du kannst ihn nun so ändern, dass der Code deine Zahl nicht beeinflusst oder sie immer positiv beeinflusst.

### Zufällige Speicheradresse – Den Pointer finden

Befolge die vorherigen Schritte und finde heraus, wo sich der gewünschte Wert befindet. Verwende anschließend **„Find out what writes to this address“**, um herauszufinden, welche Adresse diesen Wert schreibt, und doppelklicke darauf, um die Disassembly-Ansicht zu öffnen:

![Zufällige Speicheradresse – Den Code finden - Zufällige Speicheradresse – Den Pointer finden: Befolge die vorherigen Schritte und finde heraus, wo sich der gewünschte Wert befindet. Verwende anschließend „Find out...](<../../images/image (1039).png>)

Führe anschließend einen neuen Scan durch und **suche nach dem Hex-Wert zwischen „\[]“** (in diesem Fall der Wert von $edx):

![Zufällige Speicheradresse – Den Code finden - Zufällige Speicheradresse – Den Pointer finden: Führe anschließend einen neuen Scan durch und suche nach dem Hex-Wert zwischen „ ()“ (in diesem Fall der Wert von $edx)](<../../images/image (994).png>)

(_Wenn mehrere angezeigt werden, benötigst du normalerweise die Adresse mit dem kleinsten Wert_)\
Nun haben wir den **Pointer gefunden, der den für uns wichtigen Wert ändern wird**.

Klicke auf **„Add Address Manually“**:

![Zufällige Speicheradresse – Den Code finden - Zufällige Speicheradresse – Den Pointer finden: Klicke auf „Add Address Manually“](<../../images/image (990).png>)

Klicke nun auf das Kontrollkästchen „Pointer“ und füge die gefundene Adresse in das Textfeld ein (in diesem Szenario war die gefundene Adresse im vorherigen Bild „Tutorial-i386.exe“+2426B0):

![Zufällige Speicheradresse – Den Code finden - Zufällige Speicheradresse – Den Pointer finden: Klicke nun auf das Kontrollkästchen „Pointer“ und füge die gefundene Adresse in das Textfeld ein (in diesem Szenario...](<../../images/image (392).png>)

(Beachte, dass die erste „Address“ automatisch mit der von dir eingegebenen Pointer-Adresse gefüllt wird.)

Klicke auf „OK“, woraufhin ein neuer Pointer erstellt wird:

![Zufällige Speicheradresse – Den Code finden - Zufällige Speicheradresse – Den Pointer finden: Klicke auf „OK“, woraufhin ein neuer Pointer erstellt wird](<../../images/image (308).png>)

Wenn du diesen Wert nun änderst, **änderst du jedes Mal den wichtigen Wert, selbst wenn sich die Speicheradresse, an der sich der Wert befindet, ändert.**

### Code Injection

Code injection ist eine Technik, bei der du ein Stück Code in den Zielprozess injizierst und anschließend die Codeausführung umleitest, sodass sie durch deinen eigenen Code läuft (zum Beispiel indem du dir Punkte gibst, anstatt sie abzuziehen).

Stell dir vor, du hast die Adresse gefunden, die 1 von den Lebenspunkten deines Spielers abzieht:

![Zufällige Speicheradresse – Den Pointer finden - Code Injection: Stell dir vor, du hast die Adresse gefunden, die 1 von den Lebenspunkten deines Spielers abzieht](<../../images/image (203).png>)

Klicke auf „Show disassembler“, um den **disassemblierten Code** anzuzeigen.\
Klicke anschließend auf **CTRL+a**, um das Fenster „Auto assemble“ zu öffnen, und wähle _**Template --> Code Injection**_ aus.

![Zufällige Speicheradresse – Den Pointer finden - Code Injection: Klicke anschließend auf CTRL+a, um das Fenster „Auto assemble“ zu öffnen, und wähle Template -- Code Injection aus](<../../images/image (902).png>)

Trage die **Adresse der Anweisung ein, die du ändern möchtest** (dies geschieht normalerweise automatisch):

![Zufällige Speicheradresse – Den Pointer finden - Code Injection: Trage die Adresse der Anweisung ein, die du ändern möchtest (dies geschieht normalerweise automatisch)](<../../images/image (744).png>)

Eine Vorlage wird generiert:

![Zufällige Speicheradresse – Den Pointer finden - Code Injection: Eine Vorlage wird generiert](<../../images/image (944).png>)

Füge nun deinen neuen Assembly-Code in den Abschnitt **„newmem“** ein und entferne den ursprünglichen Code aus **„originalcode“**, wenn er nicht ausgeführt werden soll**.** In diesem Beispiel fügt der injizierte Code 2 Punkte hinzu, anstatt 1 abzuziehen:

![Zufällige Speicheradresse – Den Pointer finden - Code Injection: Füge nun deinen neuen Assembly-Code in den Abschnitt „newmem“ ein und entferne den ursprünglichen Code aus „originalcode“, wenn er...](<../../images/image (521).png>)

**Klicke auf „execute and so on“, und dein Code sollte in das Programm injiziert werden, wodurch das Verhalten der Funktion geändert wird!**

## Relocation-safe code injection mit AOB signatures

Ein Script, das `game.exe+123456` hookt, kann nach ASLR oder einem Software-Update nicht mehr funktionieren. Eine **Array of Bytes (AOB) signature** findet die Anweisung anhand des umgebenden Maschinencodes. Verwende `aobscanmodule`, um die Suche auf ein Modul zu beschränken. Die Signatur muss lang genug sein, damit genau ein Treffer zurückgegeben wird. Verwende Wildcards für Relocation-Bytes, Adressen und andere Bytes, die sich ändern können. Verwende keine Wildcards für die gesamte Anweisung, die du wiederherstellen musst.<sup>[[4]](#references)</sup>

Wähle in der Memory View die Anweisung aus und verwende **Tools → Auto Assemble → Template → AOB Injection**. Der generierte Block `[DISABLE]` ist wichtig. Er muss jedes überschriebenen Byte wiederherstellen und die Allokation freigeben.<sup>[[4]](#references)</sup>

<details>
<summary>Minimales x64-AOB-Injection-Skelett</summary>
```asm
[ENABLE]
aobscanmodule(INJECT,game.exe,F3 0F 11 83 A0 00 00 00 48 8B)
alloc(newmem,1024,INJECT)
label(return)
registersymbol(INJECT)
newmem:
movss [rbx+000000A0],xmm0
jmp return
INJECT:
jmp newmem
nop
nop
nop
return:
[DISABLE]
INJECT:
db F3 0F 11 83 A0 00 00 00
unregistersymbol(INJECT)
dealloc(newmem)
```
</details>

Bevor du das Script aktivierst, überprüfe diese Punkte:

1. Das AOB liefert **eine** Adresse. Füge auf beiden Seiten stabile Instructions hinzu, falls es mehrere liefert.
2. Der Sprung ersetzt vollständige Instructions. Teile niemals eine Instruction.
3. Die zugewiesene Code-Cave ist vom generierten Sprung aus erreichbar. Unter x64 kann ein 14-Byte-Sprung erforderlich sein, wenn die Zuweisung zu weit entfernt ist.
4. Der injizierte Code bewahrt Register, Flags und Stack-Alignment, die die ursprüngliche Funktion erwartet.
5. Der Disable-Block stellt die exakt ursprünglichen Bytes wieder her. Teste Enable und Disable mehrmals, bevor du die Tabelle speicherst.

## Zuverlässiger Pointer-Workflow

Ein in einem Durchlauf gefundener Pointer ist nur ein Kandidat. Erstelle Pointer-Maps in mehreren frischen Ausführungen und führe den Rescan gegen alle durch. Starte das Ziel zwischen den Captures neu, damit sich ASLR und Heap-Zuweisungen ändern. Bevorzuge Pfade, deren Basis ein Modul oder ein anderes stabiles Symbol ist. Verwirf Pfade, die nur mit einem bestimmten Save, Level oder einer bestimmten Objektinstanz funktionieren.

Der Filter **the pointer must end with specific offsets** und seine Abweichungsoption können nützliche Pfade behalten, wenn sich ein benachbartes Feld zwischen Builds verschiebt. Release 7.5 fügte diese Abweichungssteuerung ebenfalls hinzu. Sie ist ein Filter und kein Beweis dafür, dass eine Pointer-Kette stabil ist.<sup>[[1]](#references)</sup>

Wenn sich eine Struktur zu häufig verschiebt, um Pointer Scanning zu verwenden, hooke die Instruction, die auf sie zugreift. Erfasse den Live-Objekt-Pointer aus einem Register in ein zugewiesenes Symbol. Dies ist häufig zuverlässiger für Entity-Listen und Managed Objects.

## Code tracen statt Werte zu scannen

Verwende **Find out what writes to this address**, wenn der Wert direkt verändert wird. Verwende **Find out what accesses this address**, wenn du das zugehörige Objekt benötigst oder wenn der Write über kopierte Daten erfolgt. Löse im Ziel nur eine Aktion aus. Vergleiche anschließend die Trefferanzahl und den Registerzustand.

**Ultimap 2** verwendet Intel Processor Trace auf unterstützten Intel-CPUs. Es zeichnet den ausgeführten Control Flow mit weniger Unterbrechungen auf, als beim schrittweisen Ausführen jeder Instruction entstehen würden. Filtere nach Code, der während der interessanten Aktion ausgeführt wurde, und entferne Code, der auch während eines Idle-Captures ausgeführt wurde. Intel PT ist kein Stealth-Feature. Das Ziel kann Tracing, Timing-Änderungen oder Cheat Engine selbst weiterhin erkennen.<sup>[[1]](#references)</sup>

Cheat Engine 7.5 fügte außerdem eine von Windows bereitgestellte Intel-PT-Schnittstelle hinzu. Der ältere, auf DBVM basierende Ultimap-Modus und der Intel-PT-Modus haben unterschiedliche Hardware- und OS-Anforderungen. Gehe nicht davon aus, dass eine DBVM-fähige CPU Intel PT unterstützt.<sup>[[1]](#references)</sup>

## Auswahl von Debugger und Breakpoint

Wähle den am wenigsten invasiven Debugger, der funktioniert:

- **Windows debugger** ist einfach, erzeugt aber normale Debug-Events. Anti-Debugging-Checks können ihn erkennen.
- **VEH debugger** verarbeitet Breakpoints über einen vectored exception handler. Er umgeht einige grundlegende Debugger-Checks, ist aber nicht unsichtbar.
- **Hardware breakpoints** patchen die Instruction-Bytes nicht, aber x86/x64 stellt nur eine geringe Anzahl an Debug-Register-Slots bereit.
- **Software breakpoints** ersetzen ein Byte durch `INT3`. Sie sind leicht zu erkennen und können mit Integrity-Checks kollidieren.
- **DBVM debugger** verlagert einige Operationen unter das Guest-OS. Er verfügt über deutlich mehr Privilegien und kann bei einer Fehlkonfiguration den Host zum Absturz bringen.

Cheat Engine 7.5 kann einen auf einem Exception Handler basierenden Ein-Byte-Sprung und `INT3` verwenden, wenn nicht genug Platz für einen normalen relativen Sprung vorhanden ist. Behandle ihn wie einen Software-Breakpoint. Überprüfe den Exception-Flow und gehe nicht davon aus, dass er Anti-Tamper-Checks umgeht.<sup>[[1]](#references)</sup>

DBVM ist ein Hypervisor und kein allgemeiner Unsichtbarkeitsschalter. Verwende ihn nur in einer wegwerfbaren Laborumgebung. Setze seine Control-Schnittstelle keinem nicht vertrauenswürdigen Code aus. Kernel-Anti-Cheat- und Endpoint-Produkte können den Driver, den Hypervisor-Status oder den veränderten Speicher weiterhin erkennen.

## Managed Runtimes und aktuelle 7.6/7.7-Features

Bei Mono-, IL2CPP-, .NET- und Java-Zielen solltest du, sofern verfügbar, Runtime-Metadaten gegenüber Blindscans bevorzugen. Öffne **Mono → Activate mono features** oder das entsprechende Runtime-Informationsfenster. Ermittle zuerst die Klasse, das Feld oder die Methode. Verwende anschließend die native Disassembly, wenn die Managed-Methode JIT-kompiliert wird.

Die 7.6-Reihe fügte `AOBSCANEX` für Signaturen hinzu, die ausschließlich ausführbaren Speicher durchsuchen, außerdem eine `gdbserver`-Debugger-Schnittstelle, die Untersuchung von Java-Metadaten, eine schnellere IL2CPP-Aufzählung und eine Pointer-Scan-Option, die das obere Pointer-Byte ignoriert, das beim ARM Memory Tagging verwendet wird. Die 7.7-Reihe fügte native Linux-Builds, `HOOK`/`UNHOOK`, `aobscanfunction`, eine bessere Suche nach generischen Mono-Methoden, eine verbesserte PDB-Structure-Unterstützung und eine grundlegende Structure-Dissection für Unreal Engine hinzu.<sup>[[3]](#references)</sup>

Diese Ergänzungen ermöglichen einen nützlichen Workflow:

1. Löse eine Managed-Methode oder ein statisches Feld aus den Metadaten auf.
2. Trace oder disassembliere den nativen Code, der für diese Methode erzeugt wurde.
3. Verwende `AOBSCANEX` oder `aobscanfunction`, um eine stabile ausführbare Signatur zu finden.
4. Erzeuge einen reversiblen Hook. Bewahre die ursprünglichen Instructions auf und validiere den Disable-Pfad.
5. Überprüfe die Signatur nach jedem Update des Ziels erneut. Ein erfolgreicher Match garantiert nicht, dass die umgebende Logik weiterhin dieselbe Bedeutung hat.

## Remote-Ziele mit `ceserver`

`ceserver` stellt der Cheat-Engine-GUI Prozessaufzählung, Speicherzugriff und Debugging zur Verfügung. Offizielle Builds unterstützen Linux und Android. Führe die passende Architektur auf dem Ziel aus und verbinde dich über den Tab **Network**. Unter Android verhindert das Weiterleiten des Standard-Ports, dass dieser im Netzwerk offengelegt wird:<sup>[[3]](#references)</sup>
```bash
adb push ceserver_arm64 /data/local/tmp/ceserver
adb shell 'su -c "chmod 700 /data/local/tmp/ceserver && /data/local/tmp/ceserver"'
adb forward tcp:52736 tcp:52736
```
Die Drittanbieter-Bridge `frida-ceserver` kann eine mit Cheat Engine kompatible Schnittstelle für iOS-Ziele bereitstellen. Sie ist nicht der offizielle `ceserver`, und die unterstützten Operationen können abweichen.<sup>[[2]](#references)</sup>

Gehe davon aus, dass das Protokoll Zugriff auf Debugger-Ebene gewährt. Binde es an Loopback oder platziere es hinter einem SSH/ADB-Tunnel. Setze TCP 52736 niemals einem nicht vertrauenswürdigen Netzwerk aus. Stoppe den Server, sobald die Sitzung beendet ist.

## Betriebssicherheit

Verbinde dich nur mit Software, die dir gehört oder deren Test du autorisiert durchführen darfst. Führe Cheat Engine nicht neben einem Online-Spiel oder einem Produktionsendpunkt aus. Speicherschreibvorgänge, injizierter Code, Treiber und DBVM können das Ziel zum Absturz bringen oder beschädigen.<sup>[[3]](#references)</sup>

Lade Builds von der offiziellen Website herunter oder kompiliere den veröffentlichten Quellcode. Sicherheitsprodukte klassifizieren Memory-Editoren, Debugger und deren Treiber häufig als Hack-Tools. Deaktiviere den Host-Schutz nicht global. Verwende eine dedizierte VM oder einen Labor-Host und überprüfe das Artefakt, bevor du es ausführst.<sup>[[3]](#references)</sup>



## References

- [1] [Veröffentlichungshinweise zu Cheat Engine 7.5](https://github.com/cheat-engine/cheat-engine/releases/tag/7.5)
- [2] [frida-ceserver-Bridge für Remote-Ziele](https://github.com/gmh5225/frida-ceserver)
- [3] [Offizielle Veröffentlichungsnachrichten zu Cheat Engine](https://www.cheatengine.org/)
- [4] [Cheat Engine Wiki: Auto Assembler AOBs](https://wiki.cheatengine.org/index.php?title=Tutorials:AOBs)
{{#include ../../banners/hacktricks-training.md}}
