# macOS Launch/Environment Constraints & Trust Cache

{{#include ../../../banners/hacktricks-training.md}}

## Osnovne informacije

Launch constraints u macOS-u uvedeni su radi poboljšanja bezbednosti tako što **regulišu kako, ko i odakle može da pokrene proces**. Uvedeni u macOS Ventura, pružaju okvir koji kategorizuje **svaki sistemski binary u zasebne kategorije constraints**, definisane unutar **trust cache-a**, liste koja sadrži sistemske binary-je i njihove odgovarajuće hash vrednosti. Ovi constraints se primenjuju na svaki izvršni binary u sistemu i obuhvataju skup **pravila** koja određuju zahteve za **pokretanje određenog binary-ja**. Pravila obuhvataju self constraints, koje binary mora da ispuni, parent constraints, koje mora da ispuni njegov parent process, i responsible constraints, kojih se moraju pridržavati drugi relevantni entiteti.<sup>[[1]](#references)[[4]](#references)</sup>

Mehanizam se proširuje i na third-party aplikacije kroz **Environment Constraints**, počevši od macOS Sonoma, što developer-ima omogućava da zaštite svoje aplikacije navođenjem **skupa ključeva i vrednosti za environment constraints.**<sup>[[5]](#references)</sup>

**Launch environment i library constraints** definišete u constraint dictionary-jima koje ili čuvate u **`launchd` property list fajlovima**, ili u **zasebnim property list** fajlovima koje koristite prilikom code signing-a.<sup>[[5]](#references)</sup>

Postoje 4 tipa constraints:

- **Self Constraints**: Constraints koji se primenjuju na **pokrenuti** binary.
- **Parent Process**: Constraints koji se primenjuju na **parent process** procesa (na primer **`launchd`** koji pokreće XP service)
- **Responsible Constraints**: Constraints koji se primenjuju na **process koji poziva service** u XPC komunikaciji
- **Library load constraints**: Library load constraints koristite za selektivno opisivanje koda koji može biti učitan

Kada proces pokuša da pokrene drugi proces — pozivanjem `execve(_:_:_:)` ili `posix_spawn(_:_:_:_:_:_:)` — operativni sistem proverava da **izvršni** fajl **ispunjava sopstveni self constraint**. Takođe proverava da izvršni fajl **parent process-a** **ispunjava parent constraint** izvršnog fajla i da izvršni fajl **responsible process-a** **ispunjava responsible process constraint** izvršnog fajla. Ako bilo koji od ovih launch constraints nije ispunjen, operativni sistem ne pokreće program.

Ako prilikom učitavanja library-ja bilo koji deo **library constraint-a nije tačan**, vaš proces **ne učitava** library.

## LC kategorije

LC se sastoji od **činjenica** i **logičkih operacija** (and, or..) koje kombinuju činjenice.

[**Činjenice koje LC može da koristi su dokumentovane**](https://developer.apple.com/documentation/security/defining_launch_environment_and_library_constraints). Na primer:

- is-init-proc: Boolean vrednost koja pokazuje da li executable mora biti initialization process operativnog sistema (`launchd`).
- is-sip-protected: Boolean vrednost koja pokazuje da li executable mora biti fajl zaštićen funkcijom System Integrity Protection (SIP).
- `on-authorized-authapfs-volume:` Boolean vrednost koja pokazuje da li je operativni sistem učitao executable sa autorizovanog, autentifikovanog APFS volume-a.
- `on-authorized-authapfs-volume`: Boolean vrednost koja pokazuje da li je operativni sistem učitao executable sa autorizovanog, autentifikovanog APFS volume-a.
- Cryptexes volume
- `on-system-volume:` Boolean vrednost koja pokazuje da li je operativni sistem učitao executable sa trenutno pokrenutog system volume-a.
- Unutar /System...
- ...

Kada se Apple binary potpiše, **dodeljuje mu LC kategoriju** unutar **trust cache-a**.

- **iOS 16 LC kategorije** su [**reversed i dokumentovane ovde**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056).<sup>[[6]](#references)</sup>
- Aktuelne **LC kategorije (macOS 14** - Somona) su reversed, a njihovi [**opisi se mogu pronaći ovde**](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53).<sup>[[7]](#references)</sup>

Na primer, kategorija 1 je:<sup>[[7]](#references)</sup>
```
Category 1:
Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
Parent Constraint: is-init-proc
```
- `(on-authorized-authapfs-volume || on-system-volume)`: Mora biti na System ili Cryptexes volume.
- `launch-type == 1`: Mora biti system service (plist u LaunchDaemons).
- `validation-category == 1`: Izvršna datoteka operativnog sistema.
- `is-init-proc`: Launchd

### Reversing LC Categories

Više informacija o tome možete pronaći [**ovde**](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints), ali suštinski, one su definisane u **AMFI (AppleMobileFileIntegrity)**, tako da je potrebno preuzeti Kernel Development Kit da biste dobili **KEXT**. Simboli koji počinju sa **`kConstraintCategory`** su **interesantni**. Njihovim izdvajanjem dobićete DER (ASN.1) kodirani tok koji ćete morati da dekodirate pomoću [ASN.1 Decoder](https://holtstrom.com/michael/tools/asn1decoder.php) ili python-asn1 biblioteke i njene `dump.py` skripte, [andrivet/python-asn1](https://github.com/andrivet/python-asn1/tree/master), što će vam dati razumljiviji string.<sup>[[3]](#references)[[8]](#references)</sup>

## Environment Constraints

Ovo su Launch Constraints postavljeni i konfigurisani u **third party applications**. Developer može da izabere **facts** i **logical operands** koje će koristiti u svojoj aplikaciji kako bi ograničio pristup samoj aplikaciji.

Moguće je izlistati Environment Constraints aplikacije pomoću:
```bash
codesign -d -vvvv app.app
```
## Trust Caches

U **macOS-u** postoji nekoliko trust cache-ova:

- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4`**
- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**
- **`/System/Library/Security/OSLaunchPolicyData`**

A u iOS-u se, po svemu sudeći, nalazi na lokaciji **`/usr/standalone/firmware/FUD/StaticTrustCache.img4`**.

> [!WARNING]
> Na macOS-u koji radi na Apple Silicon uređajima, ako se Apple signed binary ne nalazi u trust cache-u, AMFI će odbiti da ga učita.

### Enumerisanje Trust Caches

Prethodno navedene trust cache datoteke su u formatu **IMG4** i **IM4P**, pri čemu je IM4P payload sekcija IMG4 formata.

Možete koristiti [**pyimg4**](https://github.com/m1stadev/PyIMG4) za ekstrakciju payloada iz baza:
```bash
# Installation
python3 -m pip install pyimg4

# Extract payloads data
cp /System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4 /tmp
pyimg4 img4 extract -i /tmp/BaseSystemTrustCache.img4 -p /tmp/BaseSystemTrustCache.im4p
pyimg4 im4p extract -i /tmp/BaseSystemTrustCache.im4p -o /tmp/BaseSystemTrustCache.data

cp /System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4 /tmp
pyimg4 img4 extract -i /tmp/StaticTrustCache.img4 -p /tmp/StaticTrustCache.im4p
pyimg4 im4p extract -i /tmp/StaticTrustCache.im4p -o /tmp/StaticTrustCache.data

pyimg4 im4p extract -i /System/Library/Security/OSLaunchPolicyData -o /tmp/OSLaunchPolicyData.data
```
(Druga opcija je korišćenje alata [**img4tool**](https://github.com/tihmstar/img4tool), koji će raditi čak i na M1 uređajima iako je izdanje staro, kao i na x86_64 ako ga instalirate na odgovarajuće lokacije).

Sada možete koristiti alat [**trustcache**](https://github.com/CRKatri/trustcache) da dobijete informacije u čitljivom formatu:
```bash
# Install
wget https://github.com/CRKatri/trustcache/releases/download/v2.0/trustcache_macos_arm64
sudo mv ./trustcache_macos_arm64 /usr/local/bin/trustcache
xattr -rc /usr/local/bin/trustcache
chmod +x /usr/local/bin/trustcache

# Run
trustcache info /tmp/OSLaunchPolicyData.data | head
trustcache info /tmp/StaticTrustCache.data | head
trustcache info /tmp/BaseSystemTrustCache.data | head

version = 2
uuid = 35EB5284-FD1E-4A5A-9EFB-4F79402BA6C0
entry count = 969
0065fc3204c9f0765049b82022e4aa5b44f3a9c8 [none] [2] [1]
00aab02b28f99a5da9b267910177c09a9bf488a2 [none] [2] [1]
0186a480beeee93050c6c4699520706729b63eff [none] [2] [2]
0191be4c08426793ff3658ee59138e70441fc98a [none] [2] [3]
01b57a71112235fc6241194058cea5c2c7be3eb1 [none] [2] [2]
01e6934cb8833314ea29640c3f633d740fc187f2 [none] [2] [2]
020bf8c388deaef2740d98223f3d2238b08bab56 [none] [2] [3]
```
Trust cache prati sledeću strukturu, tako da je **LC category 4. kolona**
```c
struct trust_cache_entry2 {
uint8_t cdhash[CS_CDHASH_LEN];
uint8_t hash_type;
uint8_t flags;
uint8_t constraintCategory;
uint8_t reserved0;
} __attribute__((__packed__));
```
Zatim biste mogli da koristite skriptu kao što je [**ova**](https://gist.github.com/xpn/66dc3597acd48a4c31f5f77c3cc62f30) za izdvajanje podataka.

Iz tih podataka možete proveriti aplikacije sa **vrednošću launch constraints od `0`**, odnosno one koje nisu ograničene (pogledajte [**ovde**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056) šta svaka vrednost predstavlja).<sup>[[6]](#references)</sup>

## Mitigacije napada

Launch Constraints bi ublažio nekoliko starih napada tako što bi **obezbedio da proces ne bude izvršen u neočekivanim uslovima:** na primer, sa neočekivanih lokacija ili pozivanjem od strane neočekivanog nadređenog procesa (ako bi samo launchd trebalo da ga pokreće).

Pored toga, Launch Constraints takođe **ublažava downgrade napade.**

Međutim, oni **ne ublažavaju uobičajene XPC** zloupotrebe, **Electron** code injections ili **dylib injections** bez library validation-a (osim ako su poznati team IDs koji mogu da učitavaju biblioteke).<sup>[[3]](#references)</sup>

### XPC Daemon Protection

U izdanju Sonoma, značajna stavka je **konfiguracija odgovornosti** XPC servisa daemon-a. XPC servis je odgovoran za sebe, za razliku od povezivanja klijenta koji je odgovoran. Ovo je dokumentovano u feedback izveštaju FB13206884. Ovakva postavka može delovati neispravno, jer omogućava određene interakcije sa XPC servisom:

- **Pokretanje XPC servisa**: Ako se pretpostavi da je ovo bug, ova postavka ne dozvoljava pokretanje XPC servisa putem attacker koda.
- **Povezivanje sa aktivnim servisom**: Ako XPC servis već radi (moguće je da ga je aktivirala njegova originalna aplikacija), ne postoje prepreke za povezivanje sa njim.

Iako bi implementiranje ograničenja na XPC servisu moglo biti korisno tako što bi **sužavalo vremenski prozor za potencijalne napade**, ono ne rešava primarni problem. Bezbednost XPC servisa u osnovi zahteva **efikasnu validaciju klijenta koji se povezuje**. To ostaje jedini način za jačanje bezbednosti servisa. Takođe, vredi napomenuti da je pomenuta konfiguracija odgovornosti trenutno operativna, što možda nije u skladu sa predviđenim dizajnom.<sup>[[3]](#references)</sup>

### Electron Protection

Čak i ako je zahtevano da aplikaciju mora da **otvori LaunchService** (u parents constraints). To se može postići korišćenjem **`open`** (koji može da postavi env promenljive) ili korišćenjem **Launch Services API-ja** (gde se env promenljive mogu navesti).<sup>[[3]](#references)</sup>

### CVE-2025-43253 - Overriding the built-in constraints at spawn time

Launch constraints (zvanično **lightweight code requirements**, *LWCR*) primenjuje **AMFI MAC policy**. `posix_spawn` omogućava pozivaocu da prosledi proizvoljan blob MAC policy-ju putem **`posix_spawnattr_setmacpolicyinfo_np()`**, a AMFI je tim putem prihvatao LWCR dictionary koji je dostavio pozivalac. Greška je bila u tome što su **constraints koje je dostavio attacker zamenjivale ugrađene constraints binarnog fajla**, umesto da se proveravaju zajedno sa njima:

- Napraviti minimalni (čak i prazan) launch-constraints dictionary.
- Postaviti **constraint category na `127`**, vrednost koju AMFI dozvoljava u spawn attributes, ali je **ne primenjuje** — umesto blokiranja izvršavanja, samo beleži `Launch Constraint Violation (not enforcing)`.
- Proslediti ga putem spawn attributes; proces se zatim pokreće u kontekstu koji bi njegove stvarne self/parent constraints zabranile.

Nakon ispravke, proveravaju se **i** ugrađene **i** prosleđene constraints, tako da prosleđeni dictionary više ne može da oslabi ugrađene constraints.<sup>[[2]](#references)</sup>

> [!TIP]
> Ovo je opšti obrazac koji treba tražiti prilikom auditovanja primene constraints: API koji omogućava da nepouzdan unos *dostavi* policy obično je zanimljiv kada policy engine tretira dostavljenu vrednost kao zamenu, a ne kao dodatni zahtev.

## Reference

- [1] [Objective by the Sea #OBTS v6.0 Day 2 (Live-Stream)](https://youtu.be/f1HA5QhLQ7Y?t=24146)
- [2] [CVE-2025-43253: Bypassing Launch Constraints on macOS (wts.dev)](https://wts.dev/posts/bypassing-launch-constraints/)
- [3] [Dubinska analiza Launch and Environment Constraints - theevilbit](https://theevilbit.github.io/posts/launch_constraints_deep_dive/)
- [4] [Zašto se system app ili command tool ne pokreće? Launch constraints i trust caches - The Eclectic Light Company](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
- [5] [Zaštitite Mac aplikaciju pomoću environment constraints - WWDC23](https://developer.apple.com/videos/play/wwdc2023/10266/)
- [6] [Opis Launch Constraints uvedenih u iOS 16 (LinusHenze gist)](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)
- [7] [macOS Sonoma (14) Launch Constraints (theevilbit gist)](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53)
- [8] [Beyond the good ol` LaunchAgents - about it in here](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints)

{{#include ../../../banners/hacktricks-training.md}}
