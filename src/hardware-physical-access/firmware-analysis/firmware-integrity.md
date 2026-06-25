# Firmware Integrity

{{#include ../../banners/hacktricks-training.md}}

**Custom firmware i/ili compiled binaries mogu da se uploaduju da bi se iskoristile flaws u integrity ili signature verification.** Sledeći koraci mogu da se prate za backdoor bind shell kompajlaciju:

1. Firmware može da se ekstrahuje koristeći firmware-mod-kit (FMK).
2. Arhitektura target firmware-a i endianness treba da se identifikuju.
3. Cross compiler može da se izgradi koristeći Buildroot ili druge odgovarajuće metode za environment.
4. Backdoor može da se izgradi koristeći cross compiler.
5. Backdoor može da se kopira u /usr/bin direktorijum ekstrahovanog firmware-a.
6. Odgovarajući QEMU binary može da se kopira u rootfs ekstrahovanog firmware-a.
7. Backdoor može da se emulira koristeći chroot i QEMU.
8. Backdoor može da se pristupi preko netcat.
9. QEMU binary treba da se ukloni iz rootfs-a ekstrahovanog firmware-a.
10. Modifikovani firmware može da se ponovo spakuje koristeći FMK.
11. Firmware sa backdoor-om može da se testira emulacijom pomoću firmware analysis toolkit (FAT) i povezivanjem na target backdoor IP i port koristeći netcat.

Ako je root shell već dobijen kroz dynamic analysis, bootloader manipulation, ili hardware security testing, unapred kompajlirani malicious binaries kao što su implants ili reverse shells mogu da se izvrše. Automated payload/implant alati kao što su Metasploit framework i 'msfvenom' mogu da se iskoriste koristeći sledeće korake:

1. Arhitektura target firmware-a i endianness treba da se identifikuju.
2. Msfvenom može da se koristi da se specificiraju target payload, attacker host IP, listening port number, filetype, architecture, platform, i output file.
3. Payload može da se prenese na compromised device i da se obezbedi da ima execution permissions.
4. Metasploit može da se pripremi da rukuje incoming requests pokretanjem msfconsole i konfigurisanjem settings prema payload-u.
5. meterpreter reverse shell može da se izvrši na compromised device.

## Unauthenticated transport bridges to privileged update protocols

Uobičajena embedded design greška je izlaganje **istog internog command protocol-a preko više transporta**, ali enforceovanje authentication samo na jednom od njih. Na primer, USB može da zahteva challenge-response dok BLE jednostavno prosleđuje unauthenticated **GATT writes** u isti privileged firmware-update handler.

Tipičan offensive workflow:

1. Enumeriši BLE GATT database i identifikuj writable characteristics koje koristi official mobile app.
2. Sniffuj app traffic i traži **magic bytes / opcodes** koji se poklapaju sa wired protocol-om.
3. Reprodukuj privileged commands preko BLE **bez pairing-a** i proveri da li sensitive operations i dalje rade.
4. Ako su firmware upgrade, config write, debug, ili factory-test opcodes dostupni, tretiraj BLE kao **radio-reachable admin port**.

Quick checks:
```bash
# Enumerate services/characteristics
ble.enum <MAC>

# Replay a sniffed command
ble.write <MAC> <UUID> <HEX_DATA>

# gatttool equivalent
# gatttool -b <MAC> --char-write-req -a <HANDLE> -n <HEX_DATA>
```
Stvari koje treba proveriti tokom reversing-a:

- Da li BLE zahteva **pairing/bonding** ili je dovoljna obična konekcija?
- Da li su svi transporti usmereni na istu internu dispatcher tabelu?
- Da li se privilegovani opcodes filtriraju drugačije na USB / BLE / UART / Wi-Fi?
- Može li mobile app daljinski da pokrene firmware update, recovery ili diagnostic handlere?

## Firmware kontejneri sa samo checksum-om su i dalje attacker-controlled firmware

Firmware kontejner zaštićen samo **nekeyed checksum-om** (CRC32, SHA-256, MD5, itd.) obezbeđuje detekciju korupcije, **ne i autenticity**. Ako napadač može da dođe do update rutine, može da izmeni image, ponovo izračuna checksum i flešuje proizvoljan kod.

Crvene zastavice tokom RE:

- Update kod validira samo završni checksum blob kao što je `CHK2`, `CRC` ili `SHA256`.
- Nema signature verification niti secure-boot root of trust.
- Ne koristi se device-bound MAC / HMAC / authenticated encryption.
- Recovery mode prihvata isti neautentifikovani image format.

Praktični tok validacije:

1. Ekstrahuj firmware container i identifikuj bootloader, glavni firmware i integrity metadata.
2. Izmeni bezopasnu string vrednost ili banner u image-u.
3. Ponovo izračunaj checksum tačno kako updater očekuje.
4. Ponovo flešuj image kroz normalan update path.
5. Potvrdi izmenu pri boot-u da bi dokazao proizvoljnu zamenu firmware-a.

Ako ovo radi preko remotelly reachable transport-a kao što je BLE/Wi-Fi, bug je efektivno **unauthenticated OTA firmware replacement**.

## Pretvaranje trusted USB peripheral-a u BadUSB putem firmware reflashing-a

Kada je ciljni uređaj već trusted od strane host-a preko USB-a, malicious firmware možda ne mora da implementira potpuno novi USB stack. Mnogo lakši pivot je često da se **ponovo iskoristi postojeća HID podrška**.

Koristan pattern:

1. Proveri da li se uređaj već enumeriše kao **HID Consumer Control** / media / vendor HID interface.
2. Lociraj postojeći **HID report descriptor** u firmware-u.
3. Dodaj ili zameni descriptor entry-je tako da uređaj takođe reklamira **keyboard** capability.
4. Ponovo iskoristi postojeće firmware rutine koje već šalju HID reports umesto pisanja nove transport implementacije.
5. Ubaci key press + key release reports da ukucaš komande na host-u.

Ovo pretvara compromise firmware-a u **host compromise** zato što će PC verovati reflashed peripheral-u kao legitimnoj tastaturi.

### Minimalna checklist-a za procenu

- Da li `dmesg`, Device Manager ili USB descriptors pokazuju postojeći HID interface?
- Da li ima slobodnog prostora blizu report descriptor-a ili relocatable descriptor tabele?
- Da li se postojeće media-control send rutine mogu ponovo iskoristiti za keyboard reports?
- Da li host automatski prihvata novi keyboard interface posle reflashing-a?

## Pouzdano izvršavanje payload-a unutar RTOS firmware-a

Umesto ubacivanja krhkih trampolines u nasumične code path-ove, potraži **postojeće RTOS tasks** koje su neiskorišćene ili imaju mali uticaj tokom normalnog rada.

Zašto je ovo korisno:

- Scheduler prirodno pokreće tvoj payload tokom boot-a.
- Izbegavaš kvarenje kritičnog control flow-a.
- Odloženi payload-i će manje verovatno izazvati watchdog resets nego kada se izvršavaju unutar latency-sensitive USB/network handler-a.

Dobri targeti su diagnostic, factory-test, telemetry ili coprocessor service tasks koje deluju dormant tokom normalne upotrebe.

## Brza iteracija exploit-a: ponovna upotreba benignih protocol handler-a

Kada je firmware patching moguć, kompaktan način da se ubrza RE je da se pregazi bezopasan command handler (na primer **echo/debug opcode**) custom **memory read / write / execute** primitivama. Ovo izbegava potpuno reflashing za svaki eksperiment i posebno je korisno kada uređaj podržava modifikovani handler preko brzog wired transport-a.

Koristi ovo za:

- Verifikaciju scatter-loaded memory map-a
- Pregled heap/task stanja uživo
- Testiranje malih payload-ova pre nego što ih upišeš u flash
- Bezbedno vraćanje function pointers, strings i descriptor tables

## Reference

- [Pwnd Blaster: Hacking your PC using your speaker without ever touching it](https://blog.nns.ee/2026/06/03/katana-badusb/)

{{#include ../../banners/hacktricks-training.md}}
