# Integritet firmware-a

{{#include ../../banners/hacktricks-training.md}}

Kada ovlašćena procena otkrije slabu ili nepostojeću verifikaciju potpisa firmware-a, modifikovana firmware slika može demonstrirati uticaj na integritet. Sledeći lab workflow dodaje bind shell uz zadržavanje originalnih koraka ekstrakcije, emulacije i ponovnog pakovanja.<sup>[[2]](#references)[[3]](#references)</sup>

1. Firmware se može ekstraktovati pomoću firmware-mod-kit-a (FMK).
2. Potrebno je identifikovati arhitekturu i endianness ciljnog firmware-a.
3. Cross compiler se može izgraditi pomoću Buildroot-a ili drugih odgovarajućih metoda za dato okruženje.
4. Backdoor se može izgraditi pomoću cross compiler-a.
5. Backdoor se može kopirati u /usr/bin direktorijum ekstraktovanog firmware-a.
6. Odgovarajući QEMU binary se može kopirati u rootfs ekstraktovanog firmware-a.
7. Backdoor se može emulirati pomoću chroot-a i QEMU-a.
8. Backdoor-u se može pristupiti pomoću netcat-a.
9. QEMU binary treba ukloniti iz rootfs-a ekstraktovanog firmware-a.
10. Modifikovani firmware se može ponovo zapakovati pomoću FMK-a.
11. Backdoored firmware se može testirati emulacijom pomoću firmware analysis toolkit-a (FAT) i povezivanjem na IP adresu i port ciljnog backdoor-a pomoću netcat-a.

Ako je root shell već dobijen kroz dinamičku analizu, manipulaciju bootloader-a ili hardware security testing, precompiled test binaries kao što su implants ili reverse shells mogu se izvršiti. Metasploit-ov `msfvenom` može generisati payload specifičan za arhitekturu za ovaj validation workflow:<sup>[[4]](#references)</sup>

1. Potrebno je identifikovati arhitekturu i endianness ciljnog firmware-a.
2. Msfvenom se može koristiti za navođenje ciljnog payload-a, IP adrese attacker host-a, broja listening port-a, filetype-a, arhitekture, platforme i izlaznog fajla.
3. Payload se može preneti na kompromitovani uređaj i potrebno je proveriti da li ima dozvole za izvršavanje.
4. Metasploit se može pripremiti za obradu dolaznih zahteva pokretanjem msfconsole-a i konfigurisanjem podešavanja u skladu sa payload-om.
5. Meterpreter reverse shell se može izvršiti na kompromitovanom uređaju.

## Neautentifikovani transportni mostovi ka privilegovanim update protokolima

Česta greška u dizajnu embedded sistema jeste izlaganje **istog internog command protokola preko više transporta**, uz sprovođenje autentifikacije samo na jednom od njih. Na primer, USB može zahtevati challenge-response, dok BLE jednostavno prosleđuje neautentifikovane **GATT writes** istom privilegovanom handler-u za update firmware-a.<sup>[[1]](#references)</sup>

Tipičan offensive workflow:

1. Enumerisati BLE GATT bazu i identifikovati writable characteristics koje koristi zvanična mobilna aplikacija.
2. Snimiti saobraćaj aplikacije i potražiti **magic bytes / opcodes** koji odgovaraju wired protokolu.
3. Replay-ovati privilegovane komande preko BLE-a **bez pairing-a** i proveriti da li osetljive operacije i dalje funkcionišu.
4. Ako su firmware upgrade, config write, debug ili factory-test opcodes dostupni, tretirati BLE kao **radio-reachable admin port**.

Brze provere:
```bash
# Enumerate services/characteristics
ble.enum <MAC>

# Replay a sniffed command
ble.write <MAC> <UUID> <HEX_DATA>

# gatttool equivalent
# gatttool -b <MAC> --char-write-req -a <HANDLE> -n <HEX_DATA>
```
Stvari koje treba proveriti tokom reverse engineering-a:

- Da li BLE zahteva **pairing/bonding** ili samo običnu konekciju?
- Da li se svi transporti prosleđuju istoj internoj dispatcher tabeli?
- Da li se privilegovani opcodes filtriraju drugačije preko USB / BLE / UART / Wi-Fi?
- Da li mobilna aplikacija može daljinski da aktivira firmware update, recovery ili dijagnostičke handlere?

## Firmware kontejneri koji koriste samo checksum i dalje sadrže firmware pod kontrolom napadača

Firmware kontejner zaštićen samo **unkeyed checksum** vrednošću (CRC32, SHA-256, MD5 itd.) omogućava detekciju oštećenja, **ali ne i autentičnost**. Ako napadač može da dođe do update rutine, može da izmeni image, ponovo izračuna checksum i flash-uje proizvoljan code.<sup>[[1]](#references)</sup>

Indikatori tokom RE:

- Update code proverava samo završni checksum blob, kao što su `CHK2`, `CRC` ili `SHA256`.
- Ne postoji signature verification niti secure-boot root of trust.
- Ne koristi se device-bound MAC / HMAC / authenticated encryption.
- Recovery mode prihvata isti unauthenticated image format.

Praktičan tok validacije:

1. Extract-ujte firmware container i identifikujte bootloader, glavni firmware i integrity metadata.
2. Izmenite bezopasan string ili banner u image-u.
3. Ponovo izračunajte checksum tačno onako kako updater očekuje.
4. Reflash-ujte image kroz normalan update path.
5. Potvrdite izmenu pri boot-u kako biste dokazali proizvoljnu zamenu firmware-a.

Ako ovo funkcioniše preko daljinski dostupnog transporta, kao što su BLE/Wi-Fi, bug je efektivno **unauthenticated OTA firmware replacement**.

## Pretvaranje pouzdanog USB peripheral uređaja u BadUSB putem firmware reflashing-a

Kada host već veruje target uređaju preko USB-a, malicious firmware možda ne mora da implementira potpuno novi USB stack. Mnogo jednostavniji pivot često je **reuse postojeće HID podrške**.<sup>[[1]](#references)</sup>

Korisni obrazac:

1. Proverite da li se uređaj već enumeriše kao **HID Consumer Control** / media / vendor HID interface.
2. Pronađite postojeći **HID report descriptor** u firmware-u.
3. Dodajte ili zamenite descriptor entries tako da uređaj oglašava i **keyboard** capability.
4. Ponovo upotrebite postojeće firmware rutine koje već šalju HID reports, umesto pisanja nove transport implementacije.
5. Inject-ujte key press + key release reports kako biste kucali komande na hostu.

Ovo pretvara kompromitovanje firmware-a u **host compromise**, jer će PC verovati reflashed peripheral uređaju kao legitimnoj tastaturi.

### Minimalna assessment checklist-a

- Da li `dmesg`, Device Manager ili USB descriptors prikazuju postojeći HID interface?
- Da li postoji slobodan prostor u blizini report descriptor-a ili relocatable descriptor table?
- Da li postojeće media-control send rutine mogu ponovo da se upotrebe za keyboard reports?
- Da li host automatski prihvata novi keyboard interface nakon reflashing-a?

## Pouzdano izvršavanje payload-a unutar RTOS firmware-a

Umesto ubacivanja fragilnih trampoline-a u nasumične code paths, potražite **postojeće RTOS tasks** koji se ne koriste ili imaju mali uticaj tokom normalnog rada.<sup>[[1]](#references)</sup>

Zašto je ovo korisno:

- Scheduler prirodno pokreće vaš payload tokom boot-a.
- Izbegavate korumpiranje kritičnog control flow-a.
- Odloženi payload-i imaju manju verovatnoću da aktiviraju watchdog reset nego kada se izvršavaju unutar latency-sensitive USB/network handler-a.

Dobre mete su diagnostic, factory-test, telemetry ili coprocessor service tasks koji deluju neaktivno tokom normalne upotrebe.

## Brza exploit iteracija: ponovna upotreba benign protocol handler-a

Kada je patching firmware-a moguć, kompaktan način za ubrzavanje RE procesa jeste prepisivanje bezopasnog command handler-a (na primer **echo/debug opcode**) prilagođenim **memory read / write / execute** primitives. Ovo izbegava potpuno reflashing-ovanje pri svakom eksperimentu i naročito je korisno kada uređaj podržava izmenjeni handler preko brzog wired transport-a.<sup>[[1]](#references)</sup>

Koristite ovo za:

- Verifikaciju scatter-loaded memory mapa
- Live pregled heap/task state-a
- Testiranje malih payload-a pre njihovog upisivanja u flash
- Bezbedno pronalaženje function pointer-a, string-ova i descriptor table-ova

## References

- [1] [Pwnd Blaster: Hakovanje vašeg PC-ja pomoću zvučnika, bez njegovog dodirivanja](https://blog.nns.ee/2026/06/03/katana-badusb/)
- [2] [firmware-mod-kit](https://github.com/rampageX/firmware-mod-kit)
- [3] [Toolkit za analizu firmware-a](https://github.com/attify/firmware-analysis-toolkit)
- [4] [Metasploit - Kako koristiti `msfvenom`](https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html)
{{#include ../../banners/hacktricks-training.md}}
