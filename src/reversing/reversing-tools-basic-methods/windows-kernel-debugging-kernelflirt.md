# Windows-Kernel-Debugging mit KernelFlirt

{{#include ../../banners/hacktricks-training.md}}

KernelFlirt ist ein Windows-x64-Debugger für kontrollierte Reverse-Engineering-Labs. Eine hostseitige WPF-UI oder `KfConsole.exe` sendet Befehle an `KfRelay.exe` in einer test-signierten Windows-VM. Das Relay übersetzt sie in `DeviceIoControl`-Anfragen an `KernelFlirt.sys`, das Speicher-, Register-, Breakpoint-, Ausführungskontroll- und Kernelmodul-Operationen bereitstellt. Der Treiber modifiziert außerdem den Kernel-Debugging-Pfad mit einem `KdpStub`/`KdTrap`-Inline-Hook. Verwende ihn daher nur in einer entbehrlichen VM.<sup>[[1]](#references)</sup>

```text
Host UI / KfConsole
        |
        | TCP 31337 (CMD + debug-event channels)
        v
KfRelay.exe -- DeviceIoControl/IOCTL --> KernelFlirt.sys
        ^
        |
KfLoader.exe -- SCM load/unload/status
```

Der Relay ist eine privilegierte Debugging-Grenze und kein gewöhnlicher Remote-Dienst. Betreibe TCP `31337` in einem isolierten Host-only-Netzwerk und setze den test-signierten Treiber oder Relay niemals einem nicht vertrauenswürdigen Netzwerk aus.<sup>[[1]](#references)</sup>

Verwandte Windows-Exploitationstechniken:

{{#ref}}
../../binary-exploitation/windows-exploiting-basic-guide-oscp-lvl.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/arbitrary-kernel-rw-token-theft.md
{{#endref}}

## Laboreinrichtung und erster Halt

Für Builds sind Windows 10/11 x64, Visual Studio 2022 mit C++, WDK 10.0.26100.0 oder höher und .NET 9 erforderlich. Lade den Treiber und Relay innerhalb der VM und stelle dann vom Host aus eine Verbindung her. Die UI kann eine Remote-EXE oder -SYS öffnen, und die Ansicht **Kernel Modules** kann Breakpoints in bereits geladenen Treibern setzen.<sup>[[1]](#references)</sup>

```bat
:: VM
KfLoader.exe load
KfLoader.exe status
KfRelay.exe

:: Host
KernelFlirt.exe
:: Connect -> <VM-IP>
```

Verwende `KfLoader.exe unload`, wenn das Lab beendet ist. Die Konsole unterstützt eine unverbundene REPL, direkten Zugriff auf lokale Geräte und Relay-Zugriff; nur der Relay-Modus implementiert den unten beschriebenen deterministischen `open`-Workflow.<sup>[[2]](#references)</sup>

```bat
KfConsole.exe
KfConsole.exe local
KfConsole.exe 10.100.102.6
KfConsole.exe 10.100.102.6:31337
```

Ein minimaler Konsolen-Workflow ist:<sup>[[2]](#references)</sup>

```text
connect 10.100.102.6:31337
open C:\Temp\target.exe
bp ntdll!NtCreateFile if rcx != 0
g
u rip 8
dq rsp 8
r
detach
```

Adressen sind Ausdrücke. Reine Zahlen sind hexadezimal, und Ausdrücke können Register, Arithmetik, Dereferenzierungen wie `[rsp]` und Symbole wie `ntdll!NtCreateFile` verwenden. Symbol-Breakpoints sollten erst hinzugefügt werden, nachdem `open` oder `attach` die Module aufgelistet und ihre PDBs geladen hat.<sup>[[2]](#references)</sup>

## Deterministisches Abfangen des Einstiegspunkts mit `EB FE`

Relay-seitiges `open` erstellt das Ziel im angehaltenen Zustand, speichert die ersten Bytes des Einstiegspunkts, schreibt `EB FE`, setzt den Ausführungsthread fort und fragt wiederholt ab, bis sein Instruction Pointer diese Adresse erreicht. `EB FE` ist ein Zwei-Byte-Kurzbefehl, der zu sich selbst zurückspringt. Dadurch wird die Ausführung abgefangen, ohne auf die Zustellung einer User-Mode-Debug-Ausnahme angewiesen zu sein. Anschließend stellt das Relay die Originalbytes wieder her und hält das Ziel an seinem Einstiegspunkt an.<sup>[[2]](#references)</sup>

Dieses Muster ist auch nützlich, wenn ein früher Loader-Pfad beobachtet werden muss, bevor die normale Debugger-Einrichtung abgeschlossen ist.<sup>[[2]](#references)</sup>

1. Erstelle den Prozess im angehaltenen Zustand und ermittle nach dem Mapping des Images seinen tatsächlichen Einstiegspunkt.
2. Speichere die Originalbytes des Einstiegspunkts und ersetze sie durch die Zwei-Byte-Endlosschleife.
3. Setze den Ausführungsthread fort und frage seinen Instruction Pointer wiederholt ab, bis er die gepatchte Adresse erreicht.
4. Halte das Ziel an und stelle die exakten Originalbytes wieder her, bevor die Analyse fortgesetzt wird.

Die Technik ist bewusst invasiv. Wenn der Debugger oder das Relay vor der Wiederherstellung beendet wird, kann das Ziel in einer Endlosschleife hängen bleiben. Der lokale Modus von KernelFlirt bietet kein relay-seitiges Patching des Einstiegspunkts. Starte den Prozess manuell und verwende stattdessen `attach <pid>`.<sup>[[2]](#references)</sup>

## Die passende Breakpoint-Methode auswählen

KernelFlirt bietet mehrere Breakpoint-Mechanismen mit unterschiedlichen Nebenwirkungen. Mit den folgenden Befehlen kann ein Analyst zwischen den Methoden wechseln, wenn gepackter Code sich selbst umschreibt, ausführbare Seiten schreibgeschützt sind oder Software-Breakpoint-Bytes auf Integrität geprüft werden.<sup>[[1]](#references)[[2]](#references)</sup>

| Methode | Befehl | Mechanismus und Einsatz |
| --- | --- | --- |
| Software | `bp <expr>` | MDL-gestütztes `INT3`; kann RX-`.text`-Seiten instrumentieren |
| Bedingte Software | `bp <expr> if <condition>` | Wird bei jedem Treffer ausgewertet und setzt die Ausführung bei falschem Ergebnis still fort |
| Hardware-Ausführung | `ba e1 <expr>` | Verwendet eines der Register DR0-DR3, ohne Codebytes zu ändern |
| Hardware-Daten | `ba w4 <expr>` / `ba r8 <expr>` | Überwacht Schreibzugriffe oder Lese-/Schreibzugriffe auf 1, 2, 4 oder 8 Bytes |
| Guard Page | `bm <expr> [size]` | Verwendet `PAGE_GUARD` für einen Breakpoint auf einem Speicherbereich |
| Temporär | `g <expr>`, `p` oder `o` | Hilfs-Breakpoint für „Run to Address“, Step Over und Step Out |

Mit `bl` kannst du Software-, Hardware-, Speicher- und temporäre Einträge unterscheiden und mit `bc <address|handle|all>` entfernen. Hardware-Slots sind knapp und gelten über den Zustand der Debug-Register. Guard Pages decken einen größeren Bereich ab, lösen aber auch bei nicht zusammenhängenden Zugriffen auf dieselbe Seite aus.

## Single-Step bei nativem x64 und WoW64

Native x64-Single-Steps setzen über `IOCTL_KF_SINGLE_STEP` das Trap-Flag des Prozessors. Step Over dekodiert die aktuelle Instruktion und setzt temporäre Breakpoints an ihren möglichen Folgeadressen. Step Out liest die Rücksprungadresse vom Anfang des aktuellen Stacks. Bei einem Funktionsprolog kann diese Stack-Annahme falsch sein; verwende daher vorzugsweise einen bekannten internen Breakpoint.<sup>[[2]](#references)</sup>

Der `KdTrap`-Hook fängt 32-Bit-Ausnahmen nicht auf dieselbe Weise ab. Bei WoW64-Zielen dekodiert der Debugger die Instruktion mit Iced, schreibt `EB FE` an die berechnete nächste `EIP` und fragt die Instruction Pointer der Threads wiederholt ab. Daher ist `g <address>` für WoW64 nicht verfügbar, und ein einfaches `g` blockiert die Konsole, bis ein Breakpoint erreicht wird. Setze zuerst einen erreichbaren Breakpoint und vermeide eine unbegrenzte Ausführung, da `Ctrl+C` die Konsole beendet, statt die Abfrage abzubrechen.<sup>[[2]](#references)</sup>

## Analyse mit Unterstützung von Speicher, Registern und Symbolen

Die Konsole kann einen symbolischen Halt mit Speicherinspektion und einem kontrollierten Patch kombinieren. Suchaufrufe akzeptieren Byte-Wildcards, ASCII oder UTF-16 und sind auf 4 MB sowie höchstens 256 gemeldete Treffer begrenzt. Die Befehle für Allokierung und Schutzattribute werden den Allocate-, Free- und Protect-IOCTLs des Treibers zugeordnet.<sup>[[2]](#references)</sup>

```text
s 7ff700000000 100000 48 8b ?? c3
s 7ff700000000 100000 "MZ"
d rip 40
r rax
r rip=module!Function+5
e rip 90 90
.alloc 1000 rwx
.protect <addr> 1000 rx
.free <addr>
```

Das Laden von PDBs liest das PE-Debugverzeichnis jedes Remote-Moduls aus, extrahiert dessen RSDS-Kennung, sucht über DbgHelp/SymSrv nach der passenden PDB und überprüft, ob sie als PDB geladen wurde. Lege private PDBs neben dem Ziel auf der Relay-Maschine ab oder füge ihr Verzeichnis auf dem Host zu `_NT_SYMBOL_PATH` hinzu.<sup>[[2]](#references)</sup>

## Kernel-gestützte Änderungen am Anti-Debug-Status

Der Kernel-Zugriff ermöglicht es dem Debugger, Indikatoren zu entfernen, die ein User-Mode-Debugger nicht zuverlässig verbergen kann. Nimm jeweils nur eine Änderung vor, überprüfe den entsprechenden Ziel-Check und setze den zugehörigen Hook zurück, bevor du die Sitzung beendest.<sup>[[2]](#references)</sup>

```text
!peb
ad clr_debug_port
ad clr_thread_hide
ad ntqsi on
ad spoof on
stats
ad spoof off
ad ntqsi off
```

- `clr_debug_port` löscht `EPROCESS.DebugPort`.
- `clr_thread_hide` entfernt `HideFromDebugger` aus den Ziel-Threads.
- `ntqsi on` fälscht die Klasse `0x23` (`SystemKernelDebuggerInformation`) von `NtQuerySystemInformation`.
- `spoof on` sorgt dafür, dass Lesezugriffe im User-Mode auf `KUSER_SHARED_DATA.KdDebuggerEnabled` den Wert false sehen, während der für den Trap-Mechanismus erforderliche Kernelzustand erhalten bleibt.
- `stats` überprüft die Hook-Zähler und den aufgezeichneten Zustand von `KiDebugRoutine`, `KdpStub` und `KdTrap`.

Diese Vorgänge verändern Prozess- und Kernelzustände. Ein Absturz, ein veralteter Inline-Hook, ein falscher Struktur-Offset oder eine nicht abgeschlossene Wiederherstellung von Patches können die VM destabilisieren. Deshalb sind Snapshots und eine isolierte Test-Signing-Umgebung zwingend erforderlich.<sup>[[1]](#references)</sup>

## References

- [1] [KernelFlirt-Repository und Hauptdokumentation](https://github.com/AkaTorich/KernelFlirt)
- [2] [KernelFlirt-Konsolenreferenz](https://github.com/AkaTorich/KernelFlirt/blob/main/docs/cli.md)
{{#include ../../banners/hacktricks-training.md}}
