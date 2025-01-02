# macOS Launch/Environment Constraints & Trust Cache

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

Launch constraints in macOS were introduced to enhance security by **regulating how, who, and from where a process can be initiated**. Initiated in macOS Ventura, they provide a framework that categorizes **each system binary into distinct constraint categories**, which are defined within the **trust cache**, a list containing system binaries and their respective hashes​. These constraints extend to every executable binary within the system, entailing a set of **rules** delineating the requirements for **launching a particular binary**. The rules encompass self constraints that a binary must satisfy, parent constraints required to be met by its parent process, and responsible constraints to be adhered to by other relevant entities​.

The mechanism extends to third-party apps through **Environment Constraints**, beginning from macOS Sonoma, allowing developers to protect their apps by specifying a **set of keys and values for environment constraints.**

You define **launch environment and library constraints** in constraint dictionaries that you either save in **`launchd` property list files**, or in **separate property list** files that you use in code signing.

There are 4 types of constraints:

- **Self Constraints**: Ograničenja primenjena na **pokrenuti** binarni fajl.
- **Parent Process**: Ograničenja primenjena na **roditeljski proces** (na primer **`launchd`** koji pokreće XP servis)
- **Responsible Constraints**: Ograničenja primenjena na **proces koji poziva servis** u XPC komunikaciji
- **Library load constraints**: Koristite ograničenja učitavanja biblioteka da selektivno opišete kod koji može biti učitan

So when a process tries to launch another process — by calling `execve(_:_:_:)` or `posix_spawn(_:_:_:_:_:_:)` — the operating system checks that the **executable** file **satisfies** its **own self constraint**. It also checks that the **parent** **process’s** executable **satisfies** the executable’s **parent constraint**, and that the **responsible** **process’s** executable **satisfies the executable’s responsible process constraint**. If any of these launch constraints aren’t satisfied, the operating system doesn’t run the program.

If when loading a library any part of the **library constraint isn’t true**, your process **doesn’t load** the library.

## LC Categories

A LC as composed by **facts** and **logical operations** (and, or..) that combines facts.

The[ **facts that a LC can use are documented**](https://developer.apple.com/documentation/security/defining_launch_environment_and_library_constraints). For example:

- is-init-proc: A Boolean value that indicates whether the executable must be the operating system’s initialization process (`launchd`).
- is-sip-protected: A Boolean value that indicates whether the executable must be a file protected by System Integrity Protection (SIP).
- `on-authorized-authapfs-volume:` A Boolean value that indicates whether the operating system loaded the executable from an authorized, authenticated APFS volume.
- `on-authorized-authapfs-volume`: A Boolean value that indicates whether the operating system loaded the executable from an authorized, authenticated APFS volume.
- Cryptexes volume
- `on-system-volume:`A Boolean value that indicates whether the operating system loaded the executable from the currently-booted system volume.
- Inside /System...
- ...

When an Apple binary is signed it **assigns it to a LC category** inside the **trust cache**.

- **iOS 16 LC categories** were [**reversed and documented in here**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056).
- Current **LC categories (macOS 14** - Somona) have been reversed and their [**descriptions can be found here**](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53).

For example Category 1 is:
```
Category 1:
Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
Parent Constraint: is-init-proc
```
- `(on-authorized-authapfs-volume || on-system-volume)`: Mora biti u System ili Cryptexes volumenu.
- `launch-type == 1`: Mora biti sistemska usluga (plist u LaunchDaemons).
- `validation-category == 1`: Izvršna datoteka operativnog sistema.
- `is-init-proc`: Launchd

### Reversing LC Categories

Imate više informacija [**o tome ovde**](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints), ali u suštini, one su definisane u **AMFI (AppleMobileFileIntegrity)**, tako da treba da preuzmete Kernel Development Kit da biste dobili **KEXT**. Simboli koji počinju sa **`kConstraintCategory`** su **zanimljivi**. Ekstrakcijom njih dobićete DER (ASN.1) kodirani tok koji ćete morati da dekodirate sa [ASN.1 Decoder](https://holtstrom.com/michael/tools/asn1decoder.php) ili python-asn1 bibliotekom i njenim `dump.py` skriptom, [andrivet/python-asn1](https://github.com/andrivet/python-asn1/tree/master) koja će vam dati razumljiviji string.

## Environment Constraints

Ovo su Launch Constraints postavljeni u **aplikacijama trećih strana**. Razvijač može odabrati **činjenice** i **logičke operatore koje će koristiti** u svojoj aplikaciji da bi ograničio pristup sebi.

Moguće je enumerisati Environment Constraints aplikacije sa:
```bash
codesign -d -vvvv app.app
```
## Trust Caches

U **macOS** postoji nekoliko trust cache-a:

- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4`**
- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**
- **`/System/Library/Security/OSLaunchPolicyData`**

A u iOS izgleda da se nalazi u **`/usr/standalone/firmware/FUD/StaticTrustCache.img4`**.

> [!WARNING]
> Na macOS-u koji radi na Apple Silicon uređajima, ako Apple potpisani binarni fajl nije u trust cache-u, AMFI će odbiti da ga učita.

### Enumerating Trust Caches

Prethodni trust cache fajlovi su u formatu **IMG4** i **IM4P**, pri čemu je IM4P deo sa payload-om formata IMG4.

Možete koristiti [**pyimg4**](https://github.com/m1stadev/PyIMG4) za ekstrakciju payload-a iz baza:
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
(Druga opcija bi mogla biti korišćenje alata [**img4tool**](https://github.com/tihmstar/img4tool), koji će raditi čak i na M1, čak i ako je verzija stara, i za x86_64 ako ga instalirate na pravim mestima).

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
Keš poverenja prati sledeću strukturu, tako da je **LC kategorija 4. kolona**
```c
struct trust_cache_entry2 {
uint8_t cdhash[CS_CDHASH_LEN];
uint8_t hash_type;
uint8_t flags;
uint8_t constraintCategory;
uint8_t reserved0;
} __attribute__((__packed__));
```
Zatim, možete koristiti skriptu kao što je [**ova**](https://gist.github.com/xpn/66dc3597acd48a4c31f5f77c3cc62f30) za ekstrakciju podataka.

Na osnovu tih podataka možete proveriti aplikacije sa **vrednošću launch constraints `0`**, koje su one koje nisu ograničene ([**proverite ovde**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056) šta svaka vrednost predstavlja).

## Mitigacije napada

Launch Constrains bi umanjili nekoliko starih napada **osiguravajući da proces neće biti izvršen u neočekivanim uslovima:** Na primer, iz neočekivanih lokacija ili da bude pozvan od neočekivanog roditeljskog procesa (ako samo launchd treba da ga pokrene).

Pored toga, Launch Constraints takođe **umanjuju napade na smanjenje nivoa sigurnosti.**

Međutim, oni **ne umanjuju uobičajene XPC** zloupotrebe, **Electron** injekcije koda ili **dylib injekcije** bez validacije biblioteka (osim ako su ID-ovi timova koji mogu učitati biblioteke poznati).

### XPC Daemon Zaštita

U Sonoma izdanju, značajna tačka je **konfiguracija odgovornosti** XPC servisnog daemona. XPC servis je odgovoran za sebe, za razliku od povezane klijentske aplikacije koja je odgovorna. Ovo je dokumentovano u izveštaju o povratnim informacijama FB13206884. Ova postavka može izgledati kao greška, jer omogućava određene interakcije sa XPC servisom:

- **Pokretanje XPC Servisa**: Ako se smatra greškom, ova postavka ne dozvoljava pokretanje XPC servisa putem koda napadača.
- **Povezivanje sa Aktivnim Servisom**: Ako je XPC servis već pokrenut (moguće aktiviran njegovom originalnom aplikacijom), nema prepreka za povezivanje sa njim.

Iako implementacija ograničenja na XPC servis može biti korisna **sužavanjem prozora za potencijalne napade**, to ne rešava primarnu zabrinutost. Osiguranje sigurnosti XPC servisa fundamentalno zahteva **efikasnu validaciju povezane klijentske aplikacije**. Ovo ostaje jedini način da se ojača sigurnost servisa. Takođe, vredi napomenuti da je pomenuta konfiguracija odgovornosti trenutno operativna, što možda nije u skladu sa predviđenim dizajnom.

### Electron Zaštita

Čak i ako je potrebno da aplikacija bude **otvorena putem LaunchService** (u roditeljskim ograničenjima). To se može postići korišćenjem **`open`** (koji može postaviti env varijable) ili korišćenjem **Launch Services API** (gde se mogu naznačiti env varijable).

## Reference

- [https://youtu.be/f1HA5QhLQ7Y?t=24146](https://youtu.be/f1HA5QhLQ7Y?t=24146)
- [https://theevilbit.github.io/posts/launch_constraints_deep_dive/](https://theevilbit.github.io/posts/launch_constraints_deep_dive/)
- [https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
- [https://developer.apple.com/videos/play/wwdc2023/10266/](https://developer.apple.com/videos/play/wwdc2023/10266/)

{{#include ../../../banners/hacktricks-training.md}}
