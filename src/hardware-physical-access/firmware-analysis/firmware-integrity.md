# Integritet firmware-a

{{#include ../../banners/hacktricks-training.md}}

Kada ovlašćena procena otkrije slabu ili nepostojeću proveru potpisa firmware-a, izmenjena slika firmware-a može da pokaže uticaj na integritet. Sledeći laboratorijski postupak dodaje bind shell, uz zadržavanje originalnih koraka ekstrakcije, emulacije i ponovnog pakovanja.<sup>[[2]](#references)[[3]](#references)</sup>

1. Firmware se može izdvojiti pomoću firmware-mod-kit (FMK).
2. Treba utvrditi arhitekturu i endianness ciljnog firmware-a.
3. Za to okruženje može se napraviti cross compiler pomoću Buildroot-a ili drugih odgovarajućih metoda.
4. Backdoor se može napraviti pomoću cross compiler-a.
5. Backdoor se može kopirati u /usr/bin direktorijum izdvojenog firmware-a.
6. Odgovarajući QEMU binary može se kopirati u rootfs izdvojenog firmware-a.
7. Backdoor se može emulirati pomoću chroot-a i QEMU-a.
8. Backdoor-u se može pristupiti pomoću netcat-a.
9. QEMU binary treba ukloniti iz rootfs-a izdvojenog firmware-a.
10. Izmenjeni firmware može se ponovo upakovati pomoću FMK-a.
11. Firmware sa backdoor-om može se testirati emulacijom pomoću firmware analysis toolkit (FAT), a zatim povezivanjem na IP adresu i port ciljnog backdoor-a pomoću netcat-a.

Ako je root shell već dobijen dinamičkom analizom, manipulacijom bootloader-a ili testiranjem hardverske bezbednosti, mogu se izvršiti unapred kompajlirani testni binary-ji, kao što su implants ili reverse shells. Metasploit-ov `msfvenom` može da generiše payload specifičan za arhitekturu za ovaj postupak validacije:<sup>[[4]](#references)</sup>

1. Treba utvrditi arhitekturu i endianness ciljnog firmware-a.
2. Msfvenom se može koristiti za navođenje ciljnog payload-a, IP adrese host-a napadača, broja porta za slušanje, tipa fajla, arhitekture, platforme i izlaznog fajla.
3. Payload se može preneti na kompromitovani uređaj, a zatim proveriti da li ima dozvole za izvršavanje.
4. Metasploit se može pripremiti za obradu dolaznih zahteva pokretanjem msfconsole-a i konfigurisanjem postavki u skladu sa payload-om.
5. Meterpreter reverse shell se može izvršiti na kompromitovanom uređaju.

## Neautentifikovani transportni mostovi ka privilegovanim protokolima za ažuriranje

Česta greška u dizajnu ugrađenih sistema jeste izlaganje **istog internog komandnog protokola preko više transportnih kanala**, uz sprovođenje autentifikacije samo na jednom od njih. Na primer, USB može zahtevati challenge-response, dok BLE jednostavno prosleđuje neautentifikovane **GATT writes** istom privilegovanom handler-u za ažuriranje firmware-a.<sup>[[1]](#references)</sup>

Tipičan ofanzivni postupak:

1. Nabrojati BLE GATT bazu podataka i identifikovati karakteristike u koje zvanična mobilna aplikacija može da upisuje.
2. Presresti saobraćaj aplikacije i potražiti **magic bytes / opcodes** koji odgovaraju žičanom protokolu.
3. Ponoviti privilegovane komande preko BLE-a **bez uparivanja** i proveriti da li osetljive operacije i dalje funkcionišu.
4. Ako su dostupni opcodes za nadogradnju firmware-a, upis konfiguracije, debug ili fabričko testiranje, tretirati BLE kao **admin port dostupan putem radija**.

Brze provere:

```bash
# Enumerate services/characteristics
ble.enum <MAC>

# Replay a sniffed command
ble.write <MAC> <UUID> <HEX_DATA>

# gatttool equivalent
# gatttool -b <MAC> --char-write-req -a <HANDLE> -n <HEX_DATA>
```

Stvari koje treba proveriti tokom RE-a:

- Da li BLE zahteva **pairing/bonding** ili samo običnu konekciju?
- Da li se svi transporti usmeravaju ka istoj internoj tabeli dispatcher-a?
- Da li se privilegovani opcode-ovi različito filtriraju preko USB-a / BLE-a / UART-a / Wi-Fi-ja?
- Može li mobilna aplikacija daljinski da pokrene firmware update, recovery ili diagnostic handlere?

## Firmware kontejneri zaštićeni samo kontrolnom sumom i dalje sadrže firmware pod kontrolom napadača

Firmware kontejner zaštićen samo **neključevanom kontrolnom sumom** (CRC32, SHA-256, MD5 itd.) omogućava otkrivanje oštećenja, **ne i proveru autentičnosti**. Ako napadač može da dođe do rutine za update, može da izmeni image, ponovo izračuna kontrolnu sumu i flešuje proizvoljan kod.<sup>[[1]](#references)</sup>

Znaci za uzbunu tokom RE-a:

- Update kod proverava samo završni blok kontrolne sume, kao što su `CHK2`, `CRC` ili `SHA256`.
- Nema provere potpisa niti root of trust za secure boot.
- Ne koristi se MAC / HMAC vezan za uređaj niti autentifikovano šifrovanje.
- Recovery mode prihvata isti format image-a bez provere autentičnosti.

Praktični tok provere:

1. Izdvojite firmware kontejner i identifikujte bootloader, glavni firmware i metapodatke za proveru integriteta.
2. Izmenite bezazleni string ili baner u image-u.
3. Ponovo izračunajte kontrolnu sumu tačno onako kako to očekuje updater.
4. Ponovo flešujte image uobičajenim putem za update.
5. Pri pokretanju proverite da li je izmena vidljiva kako biste dokazali da je moguće zameniti firmware proizvoljnim kodom.

Ako ovo funkcioniše preko daljinski dostupnog transporta, kao što su BLE/Wi-Fi, ranjivost se praktično svodi na **neautentifikovanu OTA zamenu firmware-a**.

## Fragmentirano stanje update-a i upisivi metapodaci integriteta

Updater može da proveri potpisano firmware zaglavlje tokom instalacije, ali pri pokretanju i dalje da proverava image samo pomoću sačuvanog hash-a integriteta. Na uređaju Cypherock X1, Bootloader je pozivao odvojene Firewall zadatke za proveru zaglavlja i smeštanje verzije/veličine u RAM, čuvanje firmware potpisa u RAM-u, proveru upisanog image-a i, na kraju, heširanje image-a u trajni Primary Bootloader Data. Sam potpis nije trajno čuvan. Ovi zadaci mogli su da se pozivaju nezavisno, umesto da sprovode jednu autentifikovanu transakciju nadogradnje.<sup>[[5]](#references)</sup>

Uz izvršavanje koda na MCU-u i pristup za upis u Flash, opisani napad je prepisao aplikacioni image, promenio vrednosti verzije/veličine u Bootloader RAM-u koji Firewall deli sa njim, a zatim pozvao završni zadatak za metapodatke da sačuva hash zlonamernog image-a i vrati uobičajeno stanje pokretanja. Provera integriteta pri uobičajenom pokretanju prihvatila je taj hash bez ponovne provere potpisa. Kada analizirate sličan updater, pratite **koja komponenta može da pozove svaki zadatak**, gde se čuvaju proverene vrednosti i da li odluka pri pokretanju autentifikuje *isti image* čiji se hash čuva. Ovo je uži slučaj od formata image-a zaštićenog samo kontrolnom sumom: provera potpisa je postojala, ali prelaz stanja nije bio povezan s njom.<sup>[[5]](#references)</sup>

## Potpisi secure element-a nad merenjima firmware-a kojima se ne može verovati

Secure element ne potvrđuje pokrenuti kod samo time što potpiše hash koji mu dostavi taj kod. Na istom wallet-u, secure element je potpisivao serijski broj uređaja, a zatim XOR cloud nonce-a i firmware hash-a dostavljenog preko MCU-a. Kompromitovani firmware mogao je da dostavi očekivani hash za potpisivanje, a da istovremeno pokreće druge bajtove. Prateći klijent je takođe slao verziju firmware-a u cloud, pa se poređenje očekivanog hash-a kod verifikatora i dalje oslanjalo na merenje koje potiče od MCU-a, umesto na nezavisno očitavanje Flash-a.<sup>[[5]](#references)</sup>

Rezultat na strani uređaja predstavljao je zasebnu granicu poverenja: cloud je proveravao uređaj, ali uređaj nije proveravao autentičnost cloud-ove odluke. Izmenjeni klijent mogao je da prijavi lokalni uspeh izmenjenom uređaju. Posebno testirajte poreklo merenja i autentifikaciju odgovora; važeći potpis secure element-a i ekran sa porukom o uspehu ne dokazuju sami po sebi da je instalirana aplikacija autentična.<sup>[[5]](#references)</sup>

Za otkrivanje zaštićenog koda koje je omogućilo analizu ovog updater-a, pogledajte [Preuzimanje firmware-a pomoću Firewall copy-task-a](index.html#disclosing-protected-code-through-a-firewall-copy-task).<sup>[[5]](#references)</sup>

## Pretvaranje pouzdane USB periferije u BadUSB ponovnim flešovanjem firmware-a

Kada host već veruje ciljnom uređaju preko USB-a, zlonamernom firmware-u možda neće biti potrebno da implementira potpuno nov USB stack. Često je mnogo lakše iskoristiti postojeću podršku za **HID**.<sup>[[1]](#references)</sup>

Koristan pristup:

1. Proverite da li se uređaj već enumeriše kao **HID Consumer Control** / media / vendor HID interfejs.
2. Pronađite postojeći **HID report descriptor** u firmware-u.
3. Dodajte ili zamenite unose deskriptora kako bi uređaj oglašavao i mogućnost rada kao **keyboard**.
4. Ponovo iskoristite postojeće firmware rutine koje već šalju HID izveštaje, umesto da pišete novu implementaciju transporta.
5. Ubacite izveštaje o pritisku i otpuštanju tastera da biste otkucali komande na host-u.

Tako kompromitovanje firmware-a postaje **kompromitovanje host-a**, jer će PC verovati perifernom uređaju sa ponovo flešovanim firmware-om kao legitimnoj tastaturi.

### Minimalna kontrolna lista za procenu

- Da li `dmesg`, Device Manager ili USB deskriptori prikazuju postojeći HID interfejs?
- Ima li slobodnog prostora u blizini report descriptor-a ili postoji tabela deskriptora čije se lokacije mogu promeniti?
- Mogu li se postojeće rutine za slanje media-control izveštaja ponovo iskoristiti za izveštaje tastature?
- Da li host automatski prihvata novi interfejs tastature nakon ponovnog flešovanja?

## Pouzdano izvršavanje payload-a u RTOS firmware-u

Umesto ubacivanja krhkih trampoline-a u nasumične putanje koda, potražite **postojeće RTOS zadatke** koji se ne koriste ili imaju mali uticaj tokom uobičajenog rada.<sup>[[1]](#references)</sup>

Zašto je ovo korisno:

- Scheduler prirodno pokreće vaš payload pri boot-u.
- Izbegavate kvarenje kritičnog toka izvršavanja.
- Kod odloženog izvršavanja payload-ovi ređe izazivaju watchdog reset nego kada se pokreću unutar USB/network handler-a osetljivog na kašnjenje.

Dobri ciljevi su diagnostic, factory-test, telemetry ili coprocessor service zadaci koji deluju neaktivno tokom uobičajene upotrebe.

## Brzo testiranje exploita: prenamenite bezazlene protocol handler-e

Kada je moguće menjati firmware, brz način da ubrzate RE jeste da prepišete bezazleni command handler (na primer **echo/debug opcode**) prilagođenim primitivama za **čitanje / upis / izvršavanje memorije**. Tako izbegavate ponovno flešovanje za svaki eksperiment, a posebno je korisno kada uređaj podržava izmenjeni handler preko brzog žičnog transporta.<sup>[[1]](#references)</sup>

Koristite ovo za:

- Proveru scatter-loaded memorijskih mapa
- Pregled stanja heap-a/task-ova uživo
- Testiranje manjih payload-ova pre nego što ih upišete u flash
- Bezbedno pronalaženje function pointer-a, string-ova i descriptor tabela

## References

- [1] [Pwnd Blaster: Hacking your PC using your speaker without ever touching it](https://blog.nns.ee/2026/06/03/katana-badusb/)
- [2] [firmware-mod-kit](https://github.com/rampageX/firmware-mod-kit)
- [3] [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit)
- [4] [Metasploit - How to use `msfvenom`](https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html)
- [5] [How And Why We Hacked Cypherock Hardware Wallet: The Full Story](https://www.darknavy.org/blog/how_and_why_we_hacked_cypherock_hardware_wallet_the_full_story/)
{{#include ../../banners/hacktricks-training.md}}
