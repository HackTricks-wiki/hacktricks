# macOS xpc_connection_get_audit_token Attack

{{#include ../../../../../../banners/hacktricks-training.md}}

**Za više informacija pogledajte originalni post:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). Ovo je sažetak:

## Mach Messages Basic Info

Ako ne znate šta su Mach poruke, počnite da proveravate ovu stranicu:

{{#ref}}
../../
{{#endref}}

Za sada zapamtite da ([definicija odavde](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):\
Mach poruke se šalju preko _mach porta_, koji je **kanal komunikacije sa jednim prijemnikom i više pošiljalaca** ugrađen u mach kernel. **Više procesa može slati poruke** na mach port, ali u bilo kojem trenutku **samo jedan proces može čitati sa njega**. Baš kao i deskriptori datoteka i soketi, mach portovi se dodeljuju i upravljaju od strane kernela, a procesi vide samo ceo broj, koji mogu koristiti da označe kernelu koji od svojih mach portova žele da koriste.

## XPC Connection

Ako ne znate kako se uspostavlja XPC veza, proverite:

{{#ref}}
../
{{#endref}}

## Vuln Summary

Ono što je zanimljivo za vas da znate je da je **XPC-ova apstrakcija veza jedan-na-jedan**, ali se zasniva na tehnologiji koja **može imati više pošiljalaca, tako da:**

- Mach portovi su jedini prijemnik, **više pošiljalaca**.
- Audit token XPC veze je audit token **kopiran iz najnovije primljene poruke**.
- Dobijanje **audit token-a** XPC veze je ključno za mnoge **provere bezbednosti**.

Iako prethodna situacija zvuči obećavajuće, postoje neki scenariji gde to neće izazvati probleme ([odavde](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):

- Audit tokeni se često koriste za proveru autorizacije da bi se odlučilo da li da se prihvati veza. Kako se to dešava koristeći poruku na servisnom portu, **veza još nije uspostavljena**. Više poruka na ovom portu će se samo obraditi kao dodatni zahtevi za vezu. Dakle, sve **provere pre prihvatanja veze nisu ranjive** (to takođe znači da unutar `-listener:shouldAcceptNewConnection:` audit token nije ugrožen). Stoga **tražimo XPC veze koje verifikuju specifične akcije**.
- XPC rukovaoci događajima se obrađuju sinhrono. To znači da rukovalac događajem za jednu poruku mora biti završen pre nego što se pozove za sledeću, čak i na konkurentnim redovima za raspodelu. Dakle, unutar **XPC rukovaoca događajem audit token ne može biti prepisan** drugim normalnim (ne-odgovor!) porukama.

Dve različite metode koje bi mogle biti ranjive:

1. Variant1:
- **Eksploit** **se povezuje** na servis **A** i servis **B**
- Servis **B** može pozvati **privilegovanu funkcionalnost** u servisu A koju korisnik ne može
- Servis **A** poziva **`xpc_connection_get_audit_token`** dok _**nije**_ unutar **rukovaoca događajem** za vezu u **`dispatch_async`**.
- Tako bi **druga** poruka mogla **prepisati Audit Token** jer se šalje asinhrono van rukovaoca događajem.
- Eksploit prosleđuje **servisu B pravo SLANJA servisu A**.
- Tako će svc **B** zapravo **slati** **poruke** servisu **A**.
- **Eksploit** pokušava da **pozove** **privilegovanu akciju.** U RC svc **A** **proverava** autorizaciju ove **akcije** dok **svc B prepisuje Audit token** (dajući eksploitu pristup da pozove privilegovanu akciju).
2. Variant 2:
- Servis **B** može pozvati **privilegovanu funkcionalnost** u servisu A koju korisnik ne može
- Eksploit se povezuje sa **servisom A** koji **šalje** eksploitu **poruku očekujući odgovor** na specifičnom **portu za odgovor**.
- Eksploit šalje **servisu** B poruku prosleđujući **taj port za odgovor**.
- Kada servis **B odgovara**, on **šalje poruku servisu A**, **dok** **eksploit** šalje drugačiju **poruku servisu A** pokušavajući da **dođe do privilegovane funkcionalnosti** i očekujući da će odgovor servisa B prepisati Audit token u savršenom trenutku (Race Condition).

## Variant 1: calling xpc_connection_get_audit_token outside of an event handler <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Scenario:

- Dva mach servisa **`A`** i **`B`** na koja se možemo povezati (na osnovu sandbox profila i provere autorizacije pre prihvatanja veze).
- _**A**_ mora imati **proveru autorizacije** za specifičnu akciju koju **`B`** može proći (ali naša aplikacija ne može).
- Na primer, ako B ima neka **prava** ili radi kao **root**, to bi mu moglo omogućiti da zatraži od A da izvrši privilegovanu akciju.
- Za ovu proveru autorizacije, **`A`** dobija audit token asinhrono, na primer pozivajući `xpc_connection_get_audit_token` iz **`dispatch_async`**.

> [!CAUTION]
> U ovom slučaju, napadač bi mogao izazvati **Race Condition** praveći **eksploit** koji **traži od A da izvrši akciju** nekoliko puta dok **B šalje poruke `A`**. Kada je RC **uspešan**, **audit token** **B** će biti kopiran u memoriji **dok** se zahtev našeg **eksploita** obrađuje od strane A, dajući mu **pristup privilegovanoj akciji koju je samo B mogao zatražiti**.

Ovo se dogodilo sa **`A`** kao `smd` i **`B`** kao `diagnosticd`. Funkcija [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) iz smb može se koristiti za instalaciju novog privilegovanog pomoćnog alata (kao **root**). Ako **proces koji radi kao root kontaktira** **smd**, neće se izvršiti druge provere.

Stoga, servis **B** je **`diagnosticd`** jer radi kao **root** i može se koristiti za **praćenje** procesa, tako da kada praćenje počne, on će **slati više poruka u sekundi.**

Da bi se izvršio napad:

1. Inicirajte **vezu** sa servisom nazvanim `smd` koristeći standardni XPC protokol.
2. Formirajte sekundarnu **vezu** sa `diagnosticd`. Suprotno normalnoj proceduri, umesto da kreirate i šaljete dva nova mach porta, pravo slanja klijentskog porta se zamenjuje duplikatom **prava slanja** povezanog sa `smd` vezom.
3. Kao rezultat, XPC poruke mogu biti poslati `diagnosticd`, ali odgovori od `diagnosticd` se preusmeravaju na `smd`. Za `smd`, izgleda kao da poruke od korisnika i `diagnosticd` potiču iz iste veze.

![Image depicting the exploit process](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. Sledeći korak uključuje davanje instrukcija `diagnosticd` da započne praćenje odabranog procesa (potencijalno korisnikovog). Paralelno, poplava rutinskih 1004 poruka se šalje `smd`. Cilj ovde je instalirati alat sa povišenim privilegijama.
5. Ova akcija pokreće trku unutar funkcije `handle_bless`. Vreme je ključno: poziv funkcije `xpc_connection_get_pid` mora vratiti PID korisnikovog procesa (jer se privilegovani alat nalazi u korisničkom paketu aplikacije). Međutim, funkcija `xpc_connection_get_audit_token`, posebno unutar podrutine `connection_is_authorized`, mora se pozivati na audit token koji pripada `diagnosticd`.

## Variant 2: reply forwarding

U XPC (Cross-Process Communication) okruženju, iako rukovaoci događajima ne izvršavaju se konkurentno, obrada odgovarajućih poruka ima jedinstveno ponašanje. Konkretno, postoje dve različite metode za slanje poruka koje očekuju odgovor:

1. **`xpc_connection_send_message_with_reply`**: Ovde se XPC poruka prima i obrađuje na određenoj redi.
2. **`xpc_connection_send_message_with_reply_sync`**: Suprotno tome, u ovoj metodi, XPC poruka se prima i obrađuje na trenutnoj redi za raspodelu.

Ova razlika je ključna jer omogućava mogućnost da **paketi odgovora budu obrađeni konkurentno sa izvršenjem XPC rukovaoca događajem**. Imajte na umu da, iako `_xpc_connection_set_creds` implementira zaključavanje kako bi se zaštitilo od delimičnog prepisivanja audit token-a, ova zaštita se ne proširuje na ceo objekat veze. Kao rezultat, to stvara ranjivost gde audit token može biti zamenjen tokom intervala između obrade paketa i izvršenja njegovog rukovaoca događajem.

Da bi se iskoristila ova ranjivost, potrebna je sledeća postavka:

- Dva mach servisa, nazvana **`A`** i **`B`**, oba od kojih mogu uspostaviti vezu.
- Servis **`A`** treba da uključuje proveru autorizacije za specifičnu akciju koju samo **`B`** može izvršiti (korisnička aplikacija ne može).
- Servis **`A`** treba da pošalje poruku koja očekuje odgovor.
- Korisnik može poslati poruku **`B`** na koju će on odgovoriti.

Proces eksploatacije uključuje sledeće korake:

1. Sačekajte da servis **`A`** pošalje poruku koja očekuje odgovor.
2. Umesto da direktno odgovara **`A`**, port za odgovor se otima i koristi za slanje poruke servisu **`B`**.
3. Nakon toga, šalje se poruka koja uključuje zabranjenu akciju, uz očekivanje da će biti obrađena konkurentno sa odgovorom od **`B`**.

Ispod je vizuelna reprezentacija opisane napadnute situacije:

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../images/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../images/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Discovery Problems

- **Teškoće u pronalaženju instanci**: Pretraživanje instanci korišćenja `xpc_connection_get_audit_token` bilo je izazovno, kako statički tako i dinamički.
- **Metodologija**: Frida je korišćena za povezivanje funkcije `xpc_connection_get_audit_token`, filtrirajući pozive koji ne potiču iz rukovaoca događajem. Međutim, ova metoda je bila ograničena na povezani proces i zahtevala je aktivnu upotrebu.
- **Analiza alata**: Alati poput IDA/Ghidra korišćeni su za ispitivanje dostupnih mach servisa, ali je proces bio vremenski zahtevan, otežan pozivima koji uključuju dyld deljenu keš memoriju.
- **Ograničenja skriptiranja**: Pokušaji skriptiranja analize za pozive `xpc_connection_get_audit_token` iz `dispatch_async` blokova bili su ometeni složenostima u analizi blokova i interakcijama sa dyld deljenom keš memorijom.

## The fix <a href="#the-fix" id="the-fix"></a>

- **Prijavljeni problemi**: Izveštaj je podnet Apple-u koji detaljno opisuje opšte i specifične probleme pronađene unutar `smd`.
- **Apple-ov odgovor**: Apple je rešio problem u `smd` zamenom `xpc_connection_get_audit_token` sa `xpc_dictionary_get_audit_token`.
- **Priroda popravke**: Funkcija `xpc_dictionary_get_audit_token` se smatra sigurnom jer direktno preuzima audit token iz mach poruke vezane za primljenu XPC poruku. Međutim, nije deo javnog API-ja, slično kao `xpc_connection_get_audit_token`.
- **Odsustvo šire popravke**: Ostaje nejasno zašto Apple nije implementirao sveobuhvatniju popravku, kao što je odbacivanje poruka koje se ne poklapaju sa sačuvanim audit token-om veze. Mogućnost legitimnih promena audit token-a u određenim scenarijima (npr. korišćenje `setuid`) može biti faktor.
- **Trenutni status**: Problem i dalje postoji u iOS 17 i macOS 14, predstavljajući izazov za one koji žele da ga identifikuju i razumeju.

{{#include ../../../../../../banners/hacktricks-training.md}}
