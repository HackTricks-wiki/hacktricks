# Virtualisierte Payload-Ausführung und Umgehung durch benutzerdefinierte VMs

{{#include ../banners/hacktricks-training.md}}

Payload-Virtualisierung kompiliert offensive Logik in einen Gastbefehlssatz und führt sie mit einem nativen Interpreter aus. Anders als bei einem Packer, der die ursprünglichen nativen Instruktionen letztendlich im Speicher offenlegen muss, kann eine virtualisierte Payload die geschützte Logik während ihrer gesamten Laufzeit als Bytecode behalten. Dadurch entfällt dieses spezifische Entpackungsfenster, **nicht** jedoch hostseitig sichtbares Verhalten wie Syscalls, Netzwerkaktivität oder die VM-zu-nativ-Aufrufgrenze.<sup>[[2]](#references)[[3]](#references)</sup>

## WebAssembly-Rehosting zur Umgehung statischer Analysen

Anstatt ein Tool in Go mit zahlreichen Signaturen zu bearbeiten, kann es als `wasip1`-Gast kompiliert und in einen separaten nativen Loader eingebettet werden. Der Gast wird gegen einen gepatchten GOROOT erstellt, in dem nicht unterstützte Operationen wie `net.Dial`, `net.Listen`, `os/exec` und `os.Pipe` über `//go:wasmimport` weitergeleitet werden; ein Wazero-Hostmodul implementiert dann Sockets, Prozessoperationen, Win32-Aufrufe und macOS-Framework-Aufrufe. So bleibt die Verwendung der Go-API des ursprünglichen Projekts erhalten, während der Großteil seiner Logik in ein verschlüsseltes WASM-Modul verlagert wird, das statische PE-Tools möglicherweise nicht verstehen.<sup>[[4]](#references)</sup>

### Linearen Speicher mit nativen APIs überbrücken

Ein Gastzeiger ist ein 32-Bit-Offset in den linearen WASM-Speicher und keine virtuelle Hostadresse. Vor einem nativen Aufruf kann die Bridge ein Argument nur dann übersetzen, wenn es als lokaler Zeiger markiert ist und im Bereich `0x10000 <= value < wasmMemorySize` liegt; das Ergebnis ist `wasmMemoryBase + value`. Die untere Grenze verhindert, dass kleine Handles, Flags und `nil` umgeschrieben werden. Pro API generierte Masken auf Basis von `win32metadata` unterscheiden echte Zeiger von Handles, Größen und Adressen in Remote-Prozessen; für ungenaue oder mehrdeutige Metadaten gibt es Overrides.<sup>[[4]](#references)</sup>

Native APIs können über Gast-Ausgabepuffer auch Hostzeiger zurückgeben. Eine Spiegeltabelle kann solchen Objekten Darstellungen im Gastspeicher zuweisen und eine umgekehrte Zuordnung zur ursprünglichen Hostadresse beibehalten. COM erfordert das Spiegeln sowohl des Interfaces als auch seiner VTable: Datenzeiger können verfolgt und gespiegelt werden, während ausführbare Zeiger in `MEM_IMAGE`-Bereichen undurchsichtige Tokens bleiben müssen, da WASM keine nativen Instruktionen ausführen kann. Dieses Modell unterstützt Host-zu-Gast-Callback-APIs wie `EnumWindows` oder `SetWindowsHookEx` nicht direkt.<sup>[[4]](#references)</sup>

### WASM-VM-Polymorphie pro Build

Runtime und Payload können bei jedem Build gemeinsam transformiert werden: Die Opcode-zu-Handler-Tabelle wird umgeordnet, jeder Gast-Opcode auf die neue Zuordnung umgeschrieben, Abschnittskennungen werden randomisiert, die standardmäßige `\0asm`-Magic wird durch einen buildspezifischen Marker ersetzt und die Magic des Runtime-Caches wird geändert. Derselbe Quellcode ergibt dadurch byteweise unterschiedliche Module, und gewöhnliche WASM-Tools können die Payload erst analysieren, wenn der Analyst die benutzerdefinierte Zuordnung und das Framing aus dem Host-Loader rekonstruiert hat.<sup>[[4]](#references)</sup>

Beginne beim Reverse Engineering mit dem nativen Host, statt nur nach `\0asm` zu suchen: Ermittle den kompilierten Marker, den Modul-Entschlüsselungspfad, die Opcode-Dispatch-Tabelle und die `env`-Hostfunktionsregistrierungen. Rekonstruiere anschließend ein Standardmodul oder instrumentiere die Importgrenze. Die Bridge bleibt ein nützlicher Verhaltens-Kontrollpunkt, da Aufrufe für Netzwerkkommunikation, Prozesserstellung, Registry-Zugriff, dynamisches Laden und generische Win32-Dispatches über sie laufen, selbst wenn sich der eingebettete Bytecode von Build zu Build ändert.<sup>[[4]](#references)</sup>

### Tarnung der äußeren Go-Executable

Wird nur der Gast geändert, bleibt der Loader weiterhin erkennbar. Die demonstrierten Transformationen fügen dichte Symbolprofile aus legitimen Go-Projekten in `gopclntab` ein, rotieren durch eine kleine plausible Auswahl an DLL-Imports und variieren die PE-`VERSIONINFO`- sowie Authenticode-Identitätszeichenfolgen. Diese Transformationen zielen auf statische und Machine-Learning-Merkmale des Containers ab; sie entfernen nicht das Runtime-Verhalten, das durch die Host-Shims sichtbar wird.<sup>[[4]](#references)</sup>

## Ausführungsmodell

Ein kompakter virtualisierter Loader kann die Ausführung in folgende Ebenen aufteilen.<sup>[[3]](#references)</sup>

1. Freestanding-C-Code, BOF-Quellcode oder Runtime-Bibliotheken über LLVM in eine benutzerdefinierte Bytecode-ISA kompilieren.
2. Einen kleinen nativen Interpreter starten und eine buildspezifische Opcode-Zuordnung initialisieren.
3. Den PE-Linker-Loader selbst als Bytecode ausführen: Header parsen, Sections abbilden, Relocations anwenden, Imports auflösen und die IAT befüllen.
4. Aufrufe zwischen Gastkomponenten innerhalb des Interpreters halten. Ziele außerhalb des Bytecode-Bereichs, etwa importierte DLL-Funktionen, über einen nativen Host-Call-Thunk weiterleiten.
5. Unterstützende Funktionen wie HTTP-Framing, TLS und Teile der C-Runtime hinter dieselbe Interpretationsgrenze verlagern.

Dieses Modell vermeidet es, für jedes Plugin einen separaten nativen Codebereich zuzuweisen, und verhindert, dass die ursprüngliche Payload als erkennbarer x86-64-Instruktionsstrom erscheint. Es bildet weiterhin eine Evasion-/Obfuskationsgrenze und keine Sicherheitsgrenze: Der native Interpreter und alle externen Effekte bleiben beobachtbar.<sup>[[2]](#references)[[3]](#references)</sup>

## Host-Bridge mit gemeinsamem Speicher

Eine isolierte VM stellt Zeiger als Offsets in einen Gastpuffer dar, weshalb bei jedem Übergang zu einer Host-API Zeiger übersetzt und Ausgabeparameter speziell behandelt werden müssen. Eine VM mit gemeinsamem Speicher macht Gastadressen stattdessen zu gültigen Adressen im Hostprozess. Lese- und Schreibvorgänge können daher mit Operationen im Stil von `memcpy` erfolgen, und ein Zeiger, den ein natives Allokations-ECALL zurückgibt, kann direkt vom Bytecode dereferenziert werden. RISC-Y Business hat gezeigt, dass dieses Design die Bridge auf das Ermitteln des PEB und das Ausführen beliebiger Host-Aufrufe reduzieren kann.<sup>[[1]](#references)</sup>

Für Windows x64 kann die virtuelle Registerdatei die ABI nachbilden: Die ersten vier Integer- oder Zeigerargumente kommen in `RCX`, `RDX`, `R8` und `R9`; weitere Argumente und der Shadow Space liegen auf dem Stack. Löst sich ein virtueller `CALL` außerhalb des Bytecode-Bereichs auf, organisiert ein universeller Thunk diesen Zustand für einen nativen Aufruf und kopiert den Rückgabewert zurück in die VM. So sind IAT-Aufrufe, Heap-Allokationen und Socket-Operationen ohne Zeigerkorrekturen möglich.<sup>[[2]](#references)[[3]](#references)</sup>

Der Nachteil ist der vollständige Verlust der Isolation. Beschädigungen des Gast-Speichers können den Host direkt beeinträchtigen, native Callees können Gastzeiger speichern oder verändern, und der Interpreter muss Bytecode als vollständig vertrauenswürdig behandeln. Native-zu-VM-Callbacks benötigen ebenfalls eine Rück-Bridge; eine VM, die nur ausgehende Aufrufe unterstützt, kann Callback-basierte APIs wie `EnumWindows` nicht direkt bedienen.<sup>[[1]](#references)[[3]](#references)</sup>

## ISA-Polymorphie pro Build

Eine benutzerdefinierte ISA mit fester Instruktionsbreite vereinfacht Decodierung, Dispatch, Relocation und die Zuordnung virtueller Register. Centurion verwendet ein 18 Byte langes, von x86-64 inspiriertes Instruktionsformat. Damit wird eine geringere Codedichte gegen vorhersehbares Parsing eingetauscht; zugleich bleibt ein möglicher Weg offen, bestehende x86-64-Artefakte in Bytecode umzuwandeln.<sup>[[3]](#references)</sup>

Wird die Opcode-zu-Handler-Zuordnung für jeden Build randomisiert, erzeugt identische Gastlogik unterschiedliche Bytefolgen. Die Verschlüsselung der Zuordnungstabelle und ihre Wiederherstellung erst zur Laufzeit beseitigen zusätzlich ein stabiles Opcode-Wörterbuch auf dem Datenträger. Das erschwert feste Signaturen und wiederverwendbare Disassemblierungsregeln, ändert aber nicht automatisch den nativen Dispatcher, die Tabellen-Entschlüsselungsroutine oder die Host-Call-Grenze.<sup>[[3]](#references)</sup>

## Die Ausführungsumgebung in die VM verlagern

Der Hostprozess kann auf Speicher-, Syscall- und Socket-Primitiven reduziert werden, während Freestanding-Bibliotheken innerhalb der VM höherwertige Funktionen bereitstellen. Beispielsweise können FreeRTOS coreHTTP HTTP-Framing und mbedTLS TLS implementieren, ohne WinHTTP oder eine TLS-API des Betriebssystems aufzurufen. Raw Sockets über `afd.sys` oder eine ähnliche Schnittstelle bilden dann die schmale native Netzwerkgrenze.<sup>[[3]](#references)</sup>

Dieses **Bring Your Own Execution Environment (BYOEE)**-Design kann auch PE-Laden, Runtime-Unterstützung und ein In-Memory-Dateisystem hinter den Interpreter verlagern. Es reduziert erkennbare native Implementierungen, beseitigt aber keine Telemetrie: Raw-Socket-Operationen bleiben sichtbar, und Umgebungen, die explizite Proxys oder TLS-Interception erfordern, können die Netzwerkkonzeption unbrauchbar machen.<sup>[[3]](#references)</sup>

## Selektive native Beschleunigung

Die Interpretation jeder Instruktion ist bei Kryptografie mit Public-Key-Verfahren besonders teuer. Eine praktische Aufteilung verwendet die `MBEDTLS_ALT`-Hooks von mbedTLS als Soft-Coprozessor-Schnittstelle: TLS-Zustand, Zertifikats-Parsing, Aushandlung, Speicherverwaltung und den übergeordneten Bignum-Code im Bytecode behalten, die rechenintensiven Kernel aus `bignum_core.c` aber über native ECALLs ausführen. Im Centurion-Prototyp blieben `bignum.c`, `bignum_mod.c` und `bignum_mod_raw.c` virtualisiert, während die inneren Schleifen nativ liefen. Dadurch verkürzte sich ein ECDHE-Handshake von Minuten auf Sekunden.<sup>[[3]](#references)</sup>

Gestalte Beschleuniger optional, damit Payloads, die TLS nicht benötigen, auf die zusätzlichen nativen Einstiegspunkte verzichten können. Dieses Muster lässt sich auf jede Interpreter-Workload übertragen: Zuerst profilieren, dann das kleinstmögliche native Primitiv verfügbar machen, statt ein ganzes Subsystem aus der VM zu verlagern.<sup>[[3]](#references)</sup>

Centurion validierte die gesamte Kette mit einer TLS-1.2-Bind-Shell: Der Bytecode-Loader bildete das PE ab, Socket-Aufrufe liefen über den universellen Thunk, mbedTLS verarbeitete das Protokoll innerhalb der VM und native ECALLs beschleunigten die ECDHE-Arithmetik. Der etwa 18 KB große native Interpreter unterstützte so einen verschlüsselten Command-Kanal, ohne die Payload als nativen x86-64-Code zu materialisieren.<sup>[[3]](#references)</sup>

## Ankerpunkte für Reverse Engineering und Erkennung

Die folgenden praktischen Analyse-Ankerpunkte lassen sich aus der Architektur ableiten: Virtualisierung verändert, wo Analysten Verhalten beobachten, beseitigt das Verhalten selbst jedoch nicht.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

- Den Fetch-/Decode-/Dispatch-Loop, den virtuellen Programmzähler, die Registerdatei und die wiederholte Verarbeitung von Instruktionen fester Breite identifizieren.
- Die Opcode-Tabelle nach ihrer Entschlüsselung zur Laufzeit sichern und Handler-Adressen semantischen Operationen zuordnen, statt verschlüsselten Bytecode auf dem Datenträger abzugleichen.
- Am universellen Thunk oder ECALL-Dispatcher anhalten, um das native Ziel, virtuelle Argumentregister, Stack-Argumente und den Rückgabewert zu erfassen.
- PEB-Zugriffe, Export-Auflösung, PE-Header-Parsing, Relocation-Schreibvorgänge und das Befüllen der IAT verfolgen, selbst wenn die Loader-Implementierung selbst Bytecode ist.
- Socket-Erstellung und `afd.sys`-Datenverkehr mit dem Fehlen erwarteter WinHTTP- oder nativer TLS-Aufrufe korrelieren; fehlende High-Level-Imports sind ein Hinweis, aber kein Beweis für gutartiges Verhalten.
- Native Arithmetik-Beschleuniger als semantische Kontrollpunkte behandeln: Ihre Aufrufer können Aktivitäten wie Schlüsselaustausch und Zertifikatsvalidierung offenbaren, während die umgebende TLS-Zustandsmaschine virtualisiert bleibt.

Analyse-Workflows, die beim Dispatcher statt beim ursprünglichen Kontrollflussgraphen ansetzen, finden sich in den [Anleitungen zur Malware-Analyse und Virtualisierung von Packern](../generic-methodologies-and-resources/basic-forensic-methodology/malware-analysis.md#virtualizing-packers-and-no-labels-obfuscation).

## Betriebliche Einschränkungen

Virtualisierung verursacht Interpretations-Overhead, erhöht die Komplexität von Toolchain und ABI und löst keine verhaltensbasierte Erkennung. Gemeinsamer Speicher ist konstruktionsbedingt unsicher, Raw-Socket-Netzwerkkommunikation kann hinter verpflichtenden Proxys scheitern, und Callback-intensive Win32-APIs erfordern Native-zu-VM-Trampolines. Auch der Interpreter, die Syscall-Bridge und native Beschleuniger bleiben eine herkömmliche native Angriffsfläche, die Verteidiger signieren oder instrumentieren können.<sup>[[2]](#references)[[3]](#references)</sup>

## Verwandte Seiten

Zur Analyse von VMProtect-3.x-Packing siehe [emuliertes Unpacking und Import-Reparatur](../generic-methodologies-and-resources/basic-forensic-methodology/malware-analysis.md#vmprotect-3x-emulated-unpacking-and-import-repair).

{{#ref}}
../reversing/common-api-used-in-malware.md
{{#endref}}

{{#ref}}
../generic-hacking/reverse-shells/README.md
{{#endref}}

## References

- [1] [RISC-Y Business: Aufbau einer RISC-V-Virtual Machine zur Payload-Obfuskation](https://secret.club/2023/12/24/riscy-business.html)
- [2] [Fox-IT: Red Teaming im Zeitalter von EDR — Evasion durch Malware-Virtualisierung](https://blog.fox-it.com/2024/09/25/red-teaming-in-the-age-of-edr-evasion-of-endpoint-detection-through-malware-virtualisation/)
- [3] [Praetorian: Centurion — Die eigene Ausführungsumgebung mitbringen](https://praetorian.com/blog/virtualized-loader-centurion/)
- [4] [Praetorian - Enter the WasmForge: Sliver zu WebAssembly kompilieren](https://praetorian.com/blog/wasmforge-sliver-webassembly)
{{#include ../banners/hacktricks-training.md}}
