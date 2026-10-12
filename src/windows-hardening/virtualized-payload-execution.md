# Virtualized Payload Execution und Custom-VM-Evasion

{{#include ../banners/hacktricks-training.md}}

Payload-Virtualisierung kompiliert offensive Logik in einen Guest-Instruktionssatz und führt sie mit einem nativen Interpreter aus. Anders als bei einem Packer, der die ursprünglichen nativen Instruktionen irgendwann im Speicher offenlegen muss, kann ein virtualized Payload die geschützte Logik während seiner gesamten Laufzeit als Bytecode behalten. Dadurch entfällt dieses spezifische Unpacking-Zeitfenster, hostseitig sichtbares Verhalten wie Syscalls, Netzwerkaktivität oder die VM-zu-Native-Aufrufgrenze wird dadurch jedoch **nicht** verborgen.<sup>[[2]](#references)[[3]](#references)</sup>

## Ausführungsmodell

Ein kompakter virtualisierter Loader kann die Ausführung in folgende Schichten aufteilen.<sup>[[3]](#references)</sup>

1. Freestanding C, BOF-Quellcode oder Runtime-Bibliotheken über LLVM in eine benutzerdefinierte Bytecode-ISA kompilieren.
2. Einen kleinen nativen Interpreter starten und ein buildspezifisches Opcode-Mapping initialisieren.
3. Den PE-Linker-Loader selbst als Bytecode ausführen: Header parsen, Sections mappen, Relocations anwenden, Imports auflösen und die IAT befüllen.
4. Guest-zu-Guest-Aufrufe innerhalb des Interpreters halten. Ziele außerhalb des Bytecode-Bereichs, etwa importierte DLL-Funktionen, über einen nativen Host-Call-Thunk aufrufen.
5. Unterstützende Funktionen wie HTTP-Framing, TLS und Teile der C-Runtime hinter dieselbe Interpretationsgrenze verschieben.

Dieses Modell vermeidet die Zuweisung eines separaten nativen Codebereichs für jedes Plugin und verhindert, dass der ursprüngliche Payload als erkennbarer x86-64-Instruktionsstrom erscheint. Es bildet weiterhin eine Evasion-/Obfuscation-Grenze und keine Sicherheitsgrenze: Der native Interpreter und alle externen Effekte bleiben beobachtbar.<sup>[[2]](#references)[[3]](#references)</sup>

## Shared-Memory-Host-Bridge

Eine isolierte VM stellt Zeiger als Offsets in einen Guest-Puffer dar. Daher erfordert jeder Übergang zu einer Host-API die Übersetzung von Zeigern und eine spezielle Behandlung von Ausgabeparametern. Eine Shared-Memory-VM macht Guest-Adressen dagegen zu gültigen Adressen im Host-Prozess. Lese- und Schreibzugriffe können somit `memcpy`-ähnliche Operationen verwenden, und ein von einem nativen Allocation-ECALL zurückgegebener Zeiger kann direkt vom Bytecode dereferenziert werden. RISC-Y Business zeigte, dass sich die Bridge mit diesem Design auf das Abrufen des PEB und das Ausführen beliebiger Host-Aufrufe reduzieren lässt.<sup>[[1]](#references)</sup>

Unter Windows x64 kann das virtuelle Registerfile die ABI widerspiegeln: Die ersten vier Integer- oder Zeigerargumente werden in `RCX`, `RDX`, `R8` und `R9` abgelegt, spätere Argumente und der Shadow Space auf dem Stack. Wenn ein virtueller `CALL` außerhalb des Bytecode-Bereichs aufgelöst wird, überträgt ein universeller Thunk diesen Zustand in einen nativen Aufruf und kopiert den Rückgabewert zurück in die VM. So sind IAT-Aufrufe, Heap-Allokationen und Socket-Operationen ohne Zeigerkorrekturen möglich.<sup>[[2]](#references)[[3]](#references)</sup>

Der Nachteil ist der vollständige Verlust der Isolation. Speicherbeschädigungen im Guest können sich direkt auf den Host auswirken, native Callees können Guest-Zeiger behalten oder verändern, und der Interpreter muss Bytecode als vollständig vertrauenswürdig behandeln. Auch Native-zu-VM-Callbacks benötigen eine Rückwärts-Bridge; eine VM, die nur ausgehende Aufrufe unterstützt, kann callbackbasierte APIs wie `EnumWindows` nicht direkt bedienen.<sup>[[1]](#references)[[3]](#references)</sup>

## Polymorphismus der ISA pro Build

Eine ISA mit fester Instruktionsbreite vereinfacht Decoding, Dispatch, Relocations und das Mapping virtueller Register. Centurion verwendet ein 18 Byte großes, von x86-64 inspiriertes Instruktionsformat. Dabei wird eine geringere Codedichte zugunsten vorhersehbaren Parsings in Kauf genommen; zugleich bleibt ein möglicher Weg offen, vorhandene x86-64-Artefakte in Bytecode zu übersetzen.<sup>[[3]](#references)</sup>

Wird das Opcode-zu-Handler-Mapping für jeden Build randomisiert, erzeugt identische Guest-Logik unterschiedliche Bytefolgen. Eine Verschlüsselung der Mapping-Tabelle und deren Wiederherstellung erst zur Laufzeit beseitigen zusätzlich ein stabiles Opcode-Wörterbuch auf dem Datenträger. Das erschwert feste Signaturen und wiederverwendbare Disassemblierungsregeln, ändert aber nicht automatisch den nativen Dispatcher, die Tabellenentschlüsselungsroutine oder die Host-Call-Grenze.<sup>[[3]](#references)</sup>

## Die Ausführungsumgebung in die VM verlagern

Der Host-Prozess kann auf Speicher-, Syscall- und Socket-Primitiven reduziert werden, während Freestanding-Bibliotheken innerhalb der VM höherwertige Funktionen bereitstellen. So kann beispielsweise FreeRTOS coreHTTP das HTTP-Framing und mbedTLS TLS implementieren, ohne WinHTTP oder eine TLS-API des Betriebssystems aufzurufen. Raw Sockets über `afd.sys` oder eine ähnliche Schnittstelle bilden dann die schmale native Netzwerkgrenze.<sup>[[3]](#references)</sup>

Dieses **Bring Your Own Execution Environment (BYOEE)**-Design kann auch PE-Laden, Runtime-Unterstützung und ein In-Memory-Dateisystem hinter den Interpreter verlagern. Es reduziert erkennbare native Implementierungen, beseitigt aber keine Telemetrie: Raw-Socket-Operationen bleiben sichtbar, und Umgebungen, die explizite Proxys oder TLS-Interception voraussetzen, können verhindern, dass das Netzwerkdesign funktioniert.<sup>[[3]](#references)</sup>

## Selektive native Beschleunigung

Die Interpretation jeder Instruktion ist besonders bei Public-Key-Kryptografie kostspielig. Ein praktischer Ansatz nutzt die `MBEDTLS_ALT`-Hooks von mbedTLS als Software-Coprozessor-Schnittstelle: TLS-Zustand, Zertifikatsparsing, Aushandlung, Allokation und den höherwertigen Bignum-Code in Bytecode belassen, die rechenintensiven Arithmetikkernels aus `bignum_core.c` jedoch über native ECALLs aufrufen. Im Centurion-Prototyp blieben `bignum.c`, `bignum_mod.c` und `bignum_mod_raw.c` virtualisiert, während die inneren Schleifen nativ ausgeführt wurden. Dadurch sank die Dauer eines ECDHE-Handshakes von Minuten auf Sekunden.<sup>[[3]](#references)</sup>

Beschleuniger sollten optional sein, damit Payloads, die TLS nicht benötigen, auf zusätzliche native Einstiegspunkte verzichten können. Dieses Muster lässt sich auf jede Interpreter-Workload übertragen: zuerst profilieren, dann das kleinstmögliche native Primitive bereitstellen, statt ein ganzes Subsystem aus der VM herauszuverlagern.<sup>[[3]](#references)</sup>

Centurion validierte die gesamte Kette mit einer TLS-1.2-Bind-Shell: Der Bytecode-Loader lud das PE, Socket-Aufrufe liefen über den universellen Thunk, mbedTLS verarbeitete das Protokoll innerhalb der VM und native ECALLs beschleunigten die ECDHE-Arithmetik. Der etwa 18 KB große native Interpreter unterstützte damit einen verschlüsselten Command-Kanal, ohne den Payload als nativen x86-64-Code zu materialisieren.<sup>[[3]](#references)</sup>

## Anhaltspunkte für Reverse Engineering und Detection

Die folgenden praktischen Analyseansatzpunkte lassen sich aus der Architektur ableiten: Virtualisierung verändert, wo Analysten Verhalten beobachten, beseitigt das Verhalten selbst jedoch nicht.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

- Den Fetch-/Decode-/Dispatch-Loop, den virtuellen Programmzähler, das Registerfile und die wiederholte Verarbeitung von Instruktionen mit fester Breite identifizieren.
- Die Opcode-Tabelle nach ihrer Laufzeitentschlüsselung auslesen und Handler-Adressen semantischen Operationen zuordnen, anstatt verschlüsselte Bytecode-Dateien auf dem Datenträger abzugleichen.
- Am universellen Thunk oder am ECALL-Dispatcher anhalten, um das native Ziel, virtuelle Argumentregister, Stack-Argumente und den Rückgabewert aufzuzeichnen.
- PEB-Zugriffe, die Auflösung von Exports, das Parsen von PE-Headern, Relocation-Schreibzugriffe und das Befüllen der IAT nachverfolgen, selbst wenn der Loader selbst als Bytecode implementiert ist.
- Socket-Erstellung und `afd.sys`-Traffic mit dem Fehlen erwarteter WinHTTP- oder nativer TLS-Aufrufe korrelieren; fehlende höherwertige Imports sind ein Hinweis, aber kein Beweis für harmloses Verhalten.
- Native Arithmetikbeschleuniger als semantische Engpässe betrachten: Ihre Aufrufer können Aktivitäten beim Schlüsselaustausch und bei der Zertifikatsvalidierung offenlegen, während die umgebende TLS-Zustandsmaschine virtualisiert bleibt.

Für Analyse-Workflows, die beim Dispatcher statt beim ursprünglichen Kontrollflussgraphen ansetzen, siehe die [Anleitung zur Malware-Analyse für virtualisierte Packer](../generic-methodologies-and-resources/basic-forensic-methodology/malware-analysis.md#virtualizing-packers-and-no-labels-obfuscation).

## Operative Einschränkungen

Virtualisierung verursacht Interpretations-Overhead, erhöht die Komplexität von Toolchain und ABI und löst keine verhaltensbasierte Detection. Shared Memory ist konstruktionsbedingt unsicher, Raw-Socket-Netzwerkverkehr kann hinter obligatorischen Proxys scheitern, und callbackintensive Win32-APIs erfordern Native-zu-VM-Trampolines. Auch der Interpreter, die Syscall-Bridge und native Beschleuniger hinterlassen weiterhin einen herkömmlichen nativen Footprint, den Defender signieren oder instrumentieren können.<sup>[[2]](#references)[[3]](#references)</sup>

## Verwandte Seiten

{{#ref}}
../reversing/common-api-used-in-malware.md
{{#endref}}

{{#ref}}
../generic-hacking/reverse-shells/README.md
{{#endref}}

## References

- [1] [RISC-Y Business: Entwicklung einer RISC-V-Virtual Machine zur Payload-Obfuscation](https://secret.club/2023/12/24/riscy-business.html)
- [2] [Fox-IT: Red Teaming im Zeitalter von EDR — Evasion durch Malware-Virtualisierung](https://blog.fox-it.com/2024/09/25/red-teaming-in-the-age-of-edr-evasion-of-endpoint-detection-through-malware-virtualisation/)
- [3] [Praetorian: Centurion — Die eigene Ausführungsumgebung mitbringen](https://praetorian.com/blog/virtualized-loader-centurion/)
{{#include ../banners/hacktricks-training.md}}
