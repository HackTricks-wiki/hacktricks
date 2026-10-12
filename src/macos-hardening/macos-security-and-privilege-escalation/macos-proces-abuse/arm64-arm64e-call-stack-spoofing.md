# ARM64/ARM64e Call-Stack Spoofing

{{#include ../../../banners/hacktricks-training.md}}

## Warum metadata-driven Unwinding gefälscht werden kann

Manche macOS-Sicherheitstools delegieren die Erfassung von Thread-Stacks an `/usr/sbin/spindump` oder vertrauen anderweitig einem konventionellen metadata-driven Unwinder. Ein Implantat kann diese Vertrauensgrenze ausnutzen, indem es ABI-korrekte synthetische Records auf seinem Stack platziert. Dadurch scheint es, als sei eine sensible API über vom Angreifer ausgewählte Funktionen in dyld und geladenen Apple-Frameworks aufgerufen worden, statt aus nicht hinterlegtem Implantat-Code. Dabei handelt es sich um Telemetrie-Täuschung, nicht um eine Änderung an der ausführbaren Datei oder ihren Unwind-Metadaten.<sup>[[1]](#references)</sup>

Unter [macOS stackshots and `spindump`](../macos-apps-inspecting-debugging-and-fuzzing/#stackshot--microstackshots) findest du den Kontext zur Erfassung.

Ein Unwinder kann nicht nachweisen, dass ein Compiler-generiertes Prolog einen Record erstellt hat. Er verwendet wiederholt den aktuellen `PC`, um eine Mach-O-Rezeptur auszuwählen, wendet diese auf `SP`, `x29`, `x30`, den Stack-Speicher und alle deklarierten nichtflüchtigen Register an und verwendet den wiederhergestellten Caller-`PC`, um die nächste Rezeptur auszuwählen. Wenn vom Angreifer kontrollierter Speicher jede ausgewählte Rezeptur erfüllt, kann die resultierende Kette strukturell gültig und symbolisierbar sein, obwohl diese Aufrufe nie stattgefunden haben.<sup>[[1]](#references)</sup>

## ARM64-Frame-Zustand

Die [ARM64 assembly overview](../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md) behandelt die Registerrollen und die Calling Convention. Bei einem konventionellen Frame, der mit `stp x29, x30, [sp, #-16]!` und anschließend `mov x29, sp` erstellt wird, ist die Canonical Frame Address (CFA), die den `SP` des Aufrufers beim Eintritt darstellt, `FP+0x10`:<sup>[[1]](#references)[[4]](#references)</sup>

```text
higher addresses
FP + 0x10   caller SP / CFA
FP + 0x08   saved LR / caller PC
FP + 0x00   previous FP
FP - 0x08   saved x19 (when declared)
FP - 0x10   saved x20 (when declared)
lower addresses
```

Frame-Records bilden über `[FP]` eine verkettete Liste, aber dieser Liste blind zu folgen reicht nicht aus: Leaf-Funktionen können frameless sein, Tail Calls können logische Übergänge entfernen, und ungewöhnliche Layouts verwenden DWARF CFI. Die vom aktuellen Address ausgewählte Recipe bestimmt, ob der Unwinder die FP-Kette überhaupt ausliest.<sup>[[1]](#references)[[4]](#references)</sup>

## Auswählen einer Mach-O-Unwind-Recipe

Final verknüpfte Images speichern Compact-Unwind-Daten in `__TEXT,__unwind_info`. Der Section-Header verweist auf einen First-Level-Funktionsindex; jeder Indexbereich verweist auf eine reguläre (`kind=2`) oder komprimierte (`kind=3`) Second-Level-Seite. Layouts, die Compact Unwind nicht beschreiben kann, verwenden ein FDE und Call-Frame-Instructions in `__eh_frame`.<sup>[[1]](#references)[[2]](#references)</sup>

Für jede mögliche Runtime-PC-Adresse:<sup>[[1]](#references)[[2]](#references)</sup>

1. PAC-Bits von ARM64e für die Suche entfernen oder normalisieren.
2. Das geladene Mach-O finden, dessen ausführbarer `__TEXT`-Bereich die Adresse enthält.
3. `functionOffset = normalizedPC - loadedImageBase` berechnen und negative Ergebnisse oder Werte über `UINT32_MAX` ablehnen.
4. Den First-Level-Bereich auswählen, für den `index[i].functionOffset <= functionOffset < index[i+1].functionOffset` gilt.
5. Die referenzierte Second-Level-Seite parsen, den nächsten Eintrag auswählen, dessen Startoffset den Offset nicht überschreitet, und sicherstellen, dass die Adresse unter dem nächsten Eintrag oder dem Ende des First-Level-Bereichs liegt.
6. Diesen Eintrag dekodieren und exakt den darin beschriebenen Zustand konstruieren.

Stammt eine Adresse aus einem gespeicherten LR, kann die Suche `PC-1` verwenden, damit eine Adresse direkt nach einem Call im abgedeckten Bereich des Callers bleibt. Dies ändert die Recipe-Auswahl, nicht aber einen Stack-Offset.<sup>[[1]](#references)</sup>

Ein Parser muss jeden Header und jedes Array auf Grenzen prüfen, Section-Version `1` voraussetzen, den abschließenden First-Level-Sentinel berücksichtigen, einen Second-Level-Page-Offset von null zurückweisen und zwischen regulären und komprimierten Seiten unterscheiden. Bei einer regulären Seite ist `entryPageOffset` relativ zum Anfang dieser Seite, während der First-Level-Page-Offset relativ zum Anfang von `__unwind_info` ist.<sup>[[1]](#references)[[2]](#references)</sup>

Der übergeordnete Modus ist `encoding & 0x0F000000`. Die aktuellen LLVM-Definitionen umfassen die folgenden Modi; ein Parser sollte nicht jeden Wert außer DWARF als klassischen Frame behandeln:<sup>[[1]](#references)[[2]](#references)</sup>

| Modus | Wert | Caller-Wiederherstellung |
| --- | --- | --- |
| Keine Compact-Unwind-Recipe | `0x00000000` | Anhalten oder einen unabhängigen Fallback verwenden. |
| Frameless | `0x02000000` | Die codierte Stack-Größe zum aktuellen `SP` addieren; die Caller-PC-Adresse ist das live LR. |
| DWARF | `0x03000000` | Das durch die unteren 24 Bits identifizierte FDE/CFI ausführen. |
| Frame | `0x04000000` | Den konventionellen `x29`-Frame-Record auslesen. |
| arm64e-Frame mit authentifiziertem LR-Bereich | `0x05000000` | `UNWIND_ARM64_MODE_FRAME_PAUTH_LR` behandeln; sein Offset-Feld lokalisiert `pacibsppc` innerhalb des abgedeckten Bereichs. |

Für den Frameless-Modus gilt `stackSize = ((encoding & 0x00FFF000) >> 12) * 16`. Beim Frame-Modus geben die fünf unteren Bits zusammenhängende gespeicherte GPR-Paare von `x19/x20` bis `x27/x28` an; die Bits `0x100-0x800` geben in ähnlicher Weise `d8-d15`-Paare an. Diese gespeicherten Register sind möglicherweise nicht erforderlich, um die nächste PC-Adresse zu finden, aber ein glaubwürdiger virtueller Caller-Zustand muss jedes Feld enthalten, das der Consumer wiederherstellt.<sup>[[1]](#references)[[2]](#references)</sup>

## Konstruieren synthetischer Records im Frame-Modus

Bei der Konstruktion wird der Unwinder rückwärts ausgeführt, statt den Stack nach wertsähnlichen Adressen zu durchsuchen:<sup>[[1]](#references)</sup>

1. Eine echte ausführbare PC-Adresse in einem aktuell geladenen Image auswählen.
2. Die Recipe dekodieren, die diese genaue PC- oder Call-Site-Adresse abdeckt.
3. Einen synthetischen Record mit der erforderlichen Ausrichtung und CFA-Beziehung zuweisen.
4. Den nächsten synthetischen FP bei `[FP]`, die gespeicherte Caller-PC-Adresse dieses Frames bei `[FP+8]` und alle durch die Encoding deklarierten GPR/FPR-Saves unterhalb von FP speichern.
5. Mehrere Records verketten und den ersten Record in das live `x29` eintragen.
6. Das live LR und den API-Rückgabepfad so einrichten, dass das Unwinding in die ausgewählte Kette eintritt und die Ausführung dennoch sicher wiederhergestellt werden kann.

`0x04000001` bedeutet beispielsweise Frame-Modus plus das `x19/x20`-Paar. Die entsprechende Zustandstransformation und der erforderliche Speicherinhalt sind:<sup>[[1]](#references)[[2]](#references)</sup>

```text
[FP - 0x10] = caller x20
[FP - 0x08] = caller x19
[FP + 0x00] = caller FP
[FP + 0x08] = caller PC
caller SP    = FP + 0x10
```

Eine legitim wirkende Adresse reicht daher nicht aus. Jeder wiederhergestellte PC wird zum Schlüssel für die nächste Suche. Wenn auch nur eine Adresse nicht mit dem gefälschten Layout übereinstimmend codiert ist, wird die Kette unterbrochen oder der Consumer rekonstruiert einen inkonsistenten Registerzustand.<sup>[[1]](#references)</sup>

## ARM64e-PAC-Anforderungen

PAC speichert einen schlüsselabhängigen Integritätswert in ansonsten ungenutzten Pointer-Bits; die Adresse wird dadurch nicht verschlüsselt. Clangs arm64e-Schema für Rücksprungadressen verwendet den Instruktionsschlüssel B und den Stack-Pointer beim Eintritt in die Funktion als Diskriminator. Bei einem konventionellen Stack-Frame ist dieser Eintritts-`SP` der CFA, sodass die gespeicherte LR an `[FP+8]` an `FP+0x10` gebunden ist.<sup>[[1]](#references)[[3]](#references)</sup>

```text
modifier = syntheticFP + 0x10
signedLR = PACIB(rawReturnPC, modifier)

# Authentication must recover the original PC:
AUTIB(signedLR, modifier) == rawReturnPC
```

Jeder synthetische LR muss unabhängig signiert werden, da das Verschieben eines bereits signierten LR in einen Frame mit einem anderen CFA den Discriminator ändert und die Authentifizierung fehlschlagen lässt. `ptrauth_strip()` eignet sich zur Adressnormalisierung und Symbolsuche, stellt aber **keine** Authentizität sicher; jeder tatsächliche Return oder authentifizierte indirekte Branch muss den Schlüssel und Modifier verwenden, die für genau diesen Übergang erwartet werden.<sup>[[1]](#references)[[3]](#references)</sup>

Eine typische arm64e-Funktion ohne Blattstatus signiert den LR vor dem Speichern und authentifiziert ihn nach dem Wiederherstellen des Entry-SP:<sup>[[1]](#references)[[3]](#references)</sup>

```asm
pacibsp
stp x29, x30, [sp, #-16]!
mov x29, sp
; function body
ldp x29, x30, [sp], #16
retab
```

## Trampoline und Restore Bridge

Synthetische Records müssen lediglich den Unwinder zufriedenstellen; sie enthalten keinen vollständigen Ausführungskontext. Eine Rückkehr von der sensiblen API direkt zu den gefälschten Aufrufern würde normalerweise einen Absturz verursachen. Das praktische Design platziert daher unmittelbar unter der API einen Gadget-Frame: Die API kehrt zu ausführbarem Code in einem geladenen Framework zurück, und dieses Gadget verzweigt über ein kontrolliertes callee-saved Register zu einer Restore Bridge im Implant.<sup>[[1]](#references)</sup>

Ein geeignetes Gadget bewahrt LR und überträgt die Ausführung über ein kontrolliertes Register, zum Beispiel mit einer passenden `br`-, `braa`- oder `brab`-Sequenz. Die Restore Bridge muss die ursprünglichen Werte von `x19-x30` und `SP` wiederherstellen, bevor die Implant-Ausführung fortgesetzt wird. Auf arm64e benötigt jeder authentifizierte Return oder Branch im Pfad von der API zum Gadget, vom Gadget zur Bridge und von der Bridge zum Implant einen Pointer, der mit dem von dieser Instruktion verwendeten Key und Discriminator signiert ist.<sup>[[1]](#references)</sup>

```text
implant -> synthetic state -> sensitive API
                              |
                              v
                     signed gadget in image
                              |
                              v
                 restore x19-x30 and original SP
                              |
                              v
                           implant
```

Das Ergebnis ist ein schwerwiegendes Versagen der Vertrauensgrenze bei stackbasierten Erkennungen: Eine Chain kann ausschließlich gemappte, symbolisierbare PCs aus Apple-Frameworks enthalten und dennoch keinen tatsächlichen Kontrollfluss darstellen. Die Unwind-Ausgabe sollte daher durch unabhängige Belege zur Herkunft des ausführbaren Speichers des Threads und zu den tatsächlichen Übergängen rund um die sensible API bestätigt werden, statt sie als Ausführungsspur zu behandeln.<sup>[[1]](#references)</sup>

## References

- [1] [MDSec - ARM64-Stack-Interna und -Verschleierung auf Apple Silicon](https://mdsec.co.uk/2026/08/arm64-stack-internals-and-obfuscation-on-apple-silicon/)
- [2] [LLVM - Definitionen der Mach-O-Compact-Unwind-Kodierung](https://github.com/llvm/llvm-project/blob/main/libunwind/include/mach-o/compact_unwind_encoding.h)
- [3] [Clang - Zeigerauthentifizierung](https://clang.llvm.org/docs/PointerAuthentication.html)
- [4] [Arm - Prozeduraufrufstandard für die 64-Bit-Arm-Architektur](https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst)
{{#include ../../../banners/hacktricks-training.md}}
