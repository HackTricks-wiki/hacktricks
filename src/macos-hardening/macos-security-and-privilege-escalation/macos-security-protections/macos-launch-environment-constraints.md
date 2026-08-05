# Ograničenja pokretanja/okruženja u macOS-u i Trust Cache

{{#include ../../../banners/hacktricks-training.md}}

## Osnovne informacije

Ograničenja pokretanja u macOS-u uvedena su radi poboljšanja bezbednosti kroz **regulisanje načina, osobe i mesta sa kog proces može biti pokrenut**. Uvedena u macOS Ventura, ona pružaju okvir koji kategorizuje **svaki sistemski binarni fajl u zasebne kategorije ograničenja**, definisane unutar **trust cache-a**, liste koja sadrži sistemske binarne fajlove i njihove odgovarajuće hash vrednosti. Ova ograničenja obuhvataju svaki izvršni binarni fajl u sistemu i uključuju skup **pravila** koja određuju zahteve za **pokretanje određenog binarnog fajla**. Pravila obuhvataju self constraints koje binarni fajl mora da ispuni, parent constraints koje mora da ispuni njegov parent proces i responsible constraints kojih moraju da se pridržavaju drugi relevantni entiteti.

Ovaj mehanizam se, počevši od macOS Sonoma, proširuje i na aplikacije trećih strana kroz **Environment Constraints**, što developerima omogućava da zaštite svoje aplikacije navođenjem **skupa ključeva i vrednosti za ograničenja okruženja.**

**launch environment and library constraints** definišete u constraint rečnicima koje ili čuvate u **`launchd` property list fajlovima**, ili u **zasebnim property list** fajlovima koje koristite prilikom code signing-a.

Postoje 4 vrste ograničenja:

- **Self Constraints**: Ograničenja koja se primenjuju na **pokrenuti** binarni fajl.
- **Parent Process**: Ograničenja koja se primenjuju na **parent procesa** (na primer **`launchd`** koji pokreće XP service)
- **Responsible Constraints**: Ograničenja koja se primenjuju na **proces koji poziva service** u XPC komunikaciji
- **Library load constraints**: Library load constraints koristite za selektivno opisivanje koda koji može biti učitan

Kada proces pokuša da pokrene drugi proces — pozivanjem `execve(_:_:_:)` ili `posix_spawn(_:_:_:_:_:_:)` — operativni sistem proverava da li **izvršni** fajl **ispunjava sopstveni self constraint**. Takođe proverava da li izvršni fajl **parent** **procesa** ispunjava **parent constraint** izvršnog fajla i da li izvršni fajl **responsible** **procesa** ispunjava responsible process constraint izvršnog fajla. Ako bilo koje od ovih launch constraints nije ispunjeno, operativni sistem ne pokreće program.

Ako pri učitavanju library-ja bilo koji deo **library constraint-a nije ispunjen**, vaš proces **ne učitava** library.

## LC Categories

Jedan LC se sastoji od **činjenica** i **logičkih operacija** (and, or..) koje kombinuju činjenice.

[**Činjenice koje jedan LC može da koristi dokumentovane su ovde**](https://developer.apple.com/documentation/security/defining_launch_environment_and_library_constraints). Na primer:

- is-init-proc: Boolean vrednost koja označava da li izvršni fajl mora biti initialization proces operativnog sistema (`launchd`).
- is-sip-protected: Boolean vrednost koja označava da li izvršni fajl mora biti fajl zaštićen pomoću System Integrity Protection (SIP).
- `on-authorized-authapfs-volume:` Boolean vrednost koja označava da li je operativni sistem učitao izvršni fajl sa autorizovanog, autentifikovanog APFS volume-a.
- `on-authorized-authapfs-volume`: Boolean vrednost koja označava da li je operativni sistem učitao izvršni fajl sa autorizovanog, autentifikovanog APFS volume-a.
- Cryptexes volume
- `on-system-volume:` Boolean vrednost koja označava da li je operativni sistem učitao izvršni fajl sa trenutno pokrenutog system volume-a.
- Unutar /System...
- ...

Kada se Apple binarni fajl potpiše, **dodeljuje mu LC kategoriju** unutar **trust cache-a**.

- **iOS 16 LC categories** su [**reverzovane i dokumentovane ovde**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056).<sup>[[6]](#references)</sup>
- Aktuelne **LC categories (macOS 14** - Somona) su reverzovane, a njihovi [**opisi se mogu pronaći ovde**](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53).<sup>[[7]](#references)</sup>

Na primer, Category 1 je:<sup>[[7]](#references)</sup>
```
Category 1:
Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
Parent Constraint: is-init-proc
```
- `(on-authorized-authapfs-volume || on-system-volume)`: Mora biti na System ili Cryptexes volumenu.
- `launch-type == 1`: Mora biti system service (plist u LaunchDaemons).
- `validation-category == 1`: Izvršna datoteka operativnog sistema.
- `is-init-proc`: Launchd

### Obrnuti inženjering LC kategorija

Više informacija o tome možete pronaći [**ovde**](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints), ali u osnovi, one su definisane u **AMFI (AppleMobileFileIntegrity)**, tako da morate preuzeti Kernel Development Kit da biste dobili **KEXT**. Simboli koji počinju sa **`kConstraintCategory`** su **interesantni**. Njihovim izdvajanjem dobićete DER (ASN.1) kodirani tok koji ćete morati da dekodirate pomoću [ASN.1 Decoder](https://holtstrom.com/michael/tools/asn1decoder.php) ili python-asn1 biblioteke i njene `dump.py` skripte, [andrivet/python-asn1](https://github.com/andrivet/python-asn1/tree/master), što će vam dati razumljiviji string.<sup>[[3]](#references)</sup>

## Ograničenja okruženja

Ovo su Launch Constraints podešena u **third party aplikacijama**. Developer može da izabere **facts** i **logičke operande** koje će koristiti u svojoj aplikaciji kako bi ograničio pristup samoj aplikaciji.

Environment Constraints aplikacije moguće je nabrojati pomoću:
```bash
codesign -d -vvvv app.app
```
## Trust Caches

U **macOS** postoji nekoliko trust cache-ova:

- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4`**
- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**
- **`/System/Library/Security/OSLaunchPolicyData`**

U iOS-u se trust cache nalazi na putanji **`/usr/standalone/firmware/FUD/StaticTrustCache.img4`**.

> [!WARNING]
> Na macOS-u koji radi na Apple Silicon uređajima, ako se Apple-potpisana binarna datoteka ne nalazi u trust cache-u, AMFI će odbiti da je učita.

### Enumerisanje Trust Caches

Prethodno navedene trust cache datoteke su u formatima **IMG4** i **IM4P**, pri čemu je IM4P odeljak sa payload-om IMG4 formata.

Možete koristiti [**pyimg4**](https://github.com/m1stadev/PyIMG4) za ekstrakciju payload-a iz baza podataka:
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
(Druga opcija je korišćenje alata [**img4tool**](https://github.com/tihmstar/img4tool), koji će raditi čak i na M1, iako je izdanje staro, kao i na x86_64 ako ga instalirate na odgovarajuće lokacije).

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
Zatim možete koristiti skriptu kao što je [**ova**](https://gist.github.com/xpn/66dc3597acd48a4c31f5f77c3cc62f30) za ekstrakciju podataka.

Iz tih podataka možete proveriti aplikacije sa **vrednošću launch constraints `0`**, odnosno one koje nisu ograničene ([**proverite ovde**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056) šta svaka vrednost predstavlja).<sup>[[6]](#references)</sup>

## Ublažavanje napada

Launch Constraints bi ublažile nekoliko starih napada tako što bi **osigurale da se proces ne izvršava u neočekivanim uslovima:** na primer, sa neočekivanih lokacija ili kada ga pozove neočekivani parent proces (ako bi samo launchd trebalo da ga pokreće).

Pored toga, Launch Constraints takođe **ublažavaju downgrade napade.**

Međutim, one **ne ublažavaju uobičajene XPC** zloupotrebe, **Electron** code injection napade niti **dylib injection** napade bez library validation-a (osim ako su poznati team IDs koji mogu da učitavaju biblioteke).<sup>[[3]](#references)</sup>

### XPC Daemon Protection

U Sonoma izdanju, značajna stavka je **responsibility konfiguracija** XPC service-a za daemon. XPC service je odgovoran za sebe, za razliku od connecting client-a koji je odgovoran. Ovo je dokumentovano u feedback report-u FB13206884. Ovakvo podešavanje može izgledati pogrešno, jer omogućava određene interakcije sa XPC service-om:

- **Pokretanje XPC Service-a**: Ako se ovo smatra bug-om, ovakvo podešavanje ne dozvoljava pokretanje XPC service-a kroz attacker code.
- **Povezivanje sa aktivnim Service-om**: Ako je XPC service već pokrenut (moguće aktiviran od strane originalne aplikacije), ne postoje prepreke za povezivanje sa njim.

Iako implementiranje constraints na XPC service-u može biti korisno za **smanjivanje vremenskog prozora za potencijalne napade**, ono ne rešava primarni problem. Bezbednost XPC service-a se suštinski može obezbediti samo **efikasnom validacijom connecting client-a**. Ovo ostaje jedini način za jačanje bezbednosti service-a. Takođe je važno napomenuti da je navedena responsibility konfiguracija trenutno operativna, što možda nije u skladu sa predviđenim dizajnom.<sup>[[3]](#references)</sup>

### Electron Protection

Čak i ako je zahtev da aplikaciju mora da **otvori LaunchService** (u parents constraints). Ovo se može postići korišćenjem **`open`** (koji može da postavi env variables) ili korišćenjem **Launch Services API-ja** (gde se env variables mogu navesti).<sup>[[3]](#references)</sup>

### CVE-2025-43253 - Overriding the built-in constraints at spawn time

Launch constraints (zvanično **lightweight code requirements**, *LWCR*) sprovodi **AMFI MAC policy**. `posix_spawn` omogućava caller-u da prosledi proizvoljan blob MAC policy-ju kroz **`posix_spawnattr_setmacpolicyinfo_np()`**, a AMFI je prihvatao LWCR dictionary koji je caller prosledio tim putem. Bug se sastojao u tome što su **constraints koje je prosledio attacker zamenjivale ugrađene constraints binarnog fajla**, umesto da se proveravaju zajedno sa njima:

- Napraviti minimalni (čak i prazan) launch-constraints dictionary.
- Postaviti **constraint category na `127`**, vrednost koju AMFI dozvoljava u spawn attributes, ali je **ne sprovodi** — samo beleži `Launch Constraint Violation (not enforcing)` umesto da blokira izvršavanje.
- Proslediti ga kroz spawn attributes, nakon čega se proces pokreće u kontekstu koji bi njegove stvarne self/parent constraints zabranile.

Nakon ispravke, proveravaju se **i ugrađene i prosleđene constraints**, tako da prosleđeni dictionary više ne može da oslabi ugrađene constraints.<sup>[[2]](#references)</sup>

> [!TIP]
> Ovo je opšti obrazac koji treba tražiti prilikom auditovanja sprovođenja constraints: API koji omogućava nepouzdanom input-u da *prosledi* policy obično je zanimljiv kada policy engine tretira prosleđenu vrednost kao zamenu, a ne kao dodatni zahtev.

## Reference

- [1] [Objective by the Sea #OBTS v6.0 Day 2 (Live-Stream)](https://youtu.be/f1HA5QhLQ7Y?t=24146)
- [2] [CVE-2025-43253: Bypassing Launch Constraints on macOS (wts.dev)](https://wts.dev/posts/bypassing-launch-constraints/)
- [3] [Launch and Environment Constraints Deep Dive - theevilbit](https://theevilbit.github.io/posts/launch_constraints_deep_dive/)
- [4] [Why won't a system app or command tool run? Launch constraints and trust caches - The Eclectic Light Company](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
- [5] [Protect your Mac app with environment constraints - WWDC23](https://developer.apple.com/videos/play/wwdc2023/10266/)
- [6] [Description of the Launch Constraints introduced in iOS 16 (LinusHenze gist)](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)
- [7] [macOS Sonoma (14) Launch Constraints (theevilbit gist)](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53)

{{#include ../../../banners/hacktricks-training.md}}
