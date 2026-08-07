# Integritet firmware-a

{{#include ../../banners/hacktricks-training.md}}

**Custom firmware i/ili kompajlirani binaries mogu se otpremiti radi iskorišćavanja propusta u proveri integriteta ili potpisa**. Za kompajliranje bind shell backdoor-a mogu se pratiti sledeći koraci:

1. Firmware se može izdvojiti pomoću firmware-mod-kit-a (FMK).
2. Potrebno je identifikovati arhitekturu i endianness ciljnog firmware-a.
3. Cross compiler se može izgraditi pomoću Buildroot-a ili drugih odgovarajućih metoda za dato okruženje.
4. Backdoor se može izgraditi pomoću cross compiler-a.
5. Backdoor se može kopirati u /usr/bin direktorijum izdvojenog firmware-a.
6. Odgovarajući QEMU binary može se kopirati u rootfs izdvojenog firmware-a.
7. Backdoor se može emulirati pomoću chroot-a i QEMU-a.
8. Backdoor-u se može pristupiti pomoću netcat-a.
9. QEMU binary treba ukloniti iz rootfs-a izdvojenog firmware-a.
10. Izmenjeni firmware se može ponovo zapakovati pomoću FMK-a.
11. Backdoored firmware se može testirati emulacijom pomoću firmware analysis toolkit-a (FAT) i povezivanjem na IP adresu i port ciljnog backdoor-a pomoću netcat-a.

Ako je root shell već dobijen putem dinamičke analize, manipulacije bootloader-om ili testiranja hardverske bezbednosti, mogu se izvršiti unapred kompajlirani zlonamerni binaries, kao što su implants ili reverse shells. Automatizovani payload/implant alati, poput Metasploit framework-a i alata 'msfvenom', mogu se iskoristiti pomoću sledećih koraka:

1. Potrebno je identifikovati arhitekturu i endianness ciljnog firmware-a.
2. Msfvenom se može koristiti za definisanje ciljnog payload-a, IP adrese hosta napadača, broja porta za osluškivanje, tipa fajla, arhitekture, platforme i izlaznog fajla.
3. Payload se može preneti na kompromitovani uređaj i potrebno je proveriti da ima dozvole za izvršavanje.
4. Metasploit se može pripremiti za obradu dolaznih zahteva pokretanjem msfconsole-a i konfigurisanjem podešavanja u skladu sa payload-om.
5. Meterpreter reverse shell se može izvršiti na kompromitovanom uređaju.

## Neautentifikovani transportni mostovi ka privilegovanim update protokolima

Česta greška u dizajnu embedded sistema jeste izlaganje **istog internog command protokola preko više transporta**, uz sprovođenje autentifikacije samo na jednom od njih. Na primer, USB može zahtevati challenge-response, dok BLE jednostavno prosleđuje neautentifikovane **GATT writes** istom privilegovanom firmware-update handler-u.<sup>[[1]](#references)</sup>

Tipičan offensive workflow:

1. Enumerisati BLE GATT bazu podataka i identifikovati writable characteristics koje koristi zvanična mobilna aplikacija.
2. Snimiti saobraćaj aplikacije i potražiti **magic bytes / opcodes** koji odgovaraju wired protokolu.
3. Reprodukovati privilegovane komande preko BLE-a **bez pairing-a** i proveriti da li osetljive operacije i dalje funkcionišu.
4. Ako su firmware upgrade, config write, debug ili factory-test opcodes dostupni, BLE treba tretirati kao **radio-reachable admin port**.

Brze provere:
```bash
# Enumerate services/characteristics
ble.enum <MAC>

# Replay a sniffed command
ble.write <MAC> <UUID> <HEX_DATA>

# gatttool equivalent
# gatttool -b <MAC> --char-write-req -a <HANDLE> -n <HEX_DATA>
```
Stvari koje treba proveriti tokom reverse engineeringa:

- Da li BLE zahteva **pairing/bonding** ili samo običnu konekciju?
- Da li se svi transporti prosleđuju istoj internoj dispatcher tabeli?
- Da li se privilegovani opcodes različito filtriraju na USB / BLE / UART / Wi-Fi?
- Da li mobilna aplikacija može daljinski da pokrene firmware update, recovery ili diagnostic handlere?

## Checksum-only firmware containers are still attacker-controlled firmware

Firmware container zaštićen samo **unkeyed checksum-om** (CRC32, SHA-256, MD5 itd.) omogućava detekciju oštećenja, **ne autentičnost**. Ako attacker može da dođe do update rutine, može da izmeni image, ponovo izračuna checksum i flash-uje proizvoljan kod.<sup>[[1]](#references)</sup>

Red flags tokom RE:

- Update kod validira samo završni checksum blob kao što su `CHK2`, `CRC` ili `SHA256`.
- Ne postoji provera potpisa niti secure-boot root of trust.
- Ne koristi se device-bound MAC / HMAC / authenticated encryption.
- Recovery mode prihvata isti unauthenticated image format.

Praktičan tok validacije:

1. Extract-ujte firmware container i identifikujte bootloader, glavni firmware i integrity metadata.
2. Izmenite bezopasan string ili banner u image-u.
3. Ponovo izračunajte checksum tačno onako kako updater očekuje.
4. Reflash-ujte image kroz uobičajeni update path.
5. Potvrdite izmenu pri boot-u da biste dokazali proizvoljnu zamenu firmware-a.

Ako ovo funkcioniše preko daljinski dostupnog transporta kao što su BLE/Wi-Fi, bug je praktično **unauthenticated OTA firmware replacement**.

## Turning a trusted USB peripheral into BadUSB via firmware reflashing

Kada host već veruje ciljnom uređaju preko USB-a, malicious firmware često ne mora da implementira potpuno novi USB stack. Mnogo lakši pivot obično je **reuse postojeće HID podrške**.<sup>[[1]](#references)</sup>

Korisni obrazac:

1. Proverite da li se uređaj već enumeriše kao **HID Consumer Control** / media / vendor HID interface.
2. Pronađite postojeći **HID report descriptor** u firmware-u.
3. Dodajte ili zamenite descriptor entries tako da uređaj oglašava i **keyboard** capability.
4. Ponovo iskoristite postojeće firmware rutine koje već šalju HID reports, umesto pisanja nove transport implementacije.
5. Inject-ujte key press + key release reports da biste kucali komande na hostu.

Ovo pretvara kompromitovanje firmware-a u **host compromise**, jer će PC verovati reflash-ovanoj periferiji kao legitimnoj tastaturi.

### Minimal assessment checklist

- Da li `dmesg`, Device Manager ili USB descriptors prikazuju postojeći HID interface?
- Da li postoji slobodan prostor u blizini report descriptor-a ili relocatable descriptor table?
- Da li postojeće media-control send rutine mogu ponovo da se koriste za keyboard reports?
- Da li host automatski prihvata novi keyboard interface nakon reflashing-a?

## Reliable payload execution inside RTOS firmware

Umesto ubacivanja fragilnih trampoline-a u nasumične code paths, potražite **postojeće RTOS taskove** koji se ne koriste ili imaju mali uticaj tokom normalnog rada.<sup>[[1]](#references)</sup>

Zašto je ovo korisno:

- Scheduler prirodno pokreće vaš payload tokom boot-a.
- Izbegavate korumpiranje kritičnog control flow-a.
- Delayed payload-i ređe aktiviraju watchdog reset nego kada se izvršavaju unutar latency-sensitive USB/network handler-a.

Dobri targets su diagnostic, factory-test, telemetry ili coprocessor service taskovi koji deluju dormant tokom uobičajene upotrebe.

## Fast exploit iteration: repurpose benign protocol handlers

Kada je patching firmware-a moguć, kompaktan način za ubrzavanje RE-a jeste da bezopasan command handler (na primer **echo/debug opcode**) zamenite prilagođenim **memory read / write / execute** primitivama. Ovo izbegava potpuno reflashing-ovanje pri svakom eksperimentu i naročito je korisno kada uređaj podržava izmenjeni handler preko brzog wired transporta.<sup>[[1]](#references)</sup>

Koristite ovo za:

- Verifikaciju scatter-loaded memory mapa
- Live pregled heap/task stanja
- Testiranje malih payload-a pre njihovog upisivanja u flash
- Bezbedno pronalaženje function pointer-a, stringova i descriptor tabela

## Reference

- [1] [Pwnd Blaster: Hacking your PC using your speaker without ever touching it](https://blog.nns.ee/2026/06/03/katana-badusb/)

{{#include ../../banners/hacktricks-training.md}}
