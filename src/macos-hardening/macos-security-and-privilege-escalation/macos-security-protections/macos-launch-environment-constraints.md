# macOS Launch/Environment Constraints & Trust Cache

{{#include ../../../banners/hacktricks-training.md}}

## Osnovne informacije

Launch constraints u macOS-u uvedeni su radi unapređenja bezbednosti, tako što **regulišu kako, ko i odakle može da pokrene proces**. Uvedeni u macOS Ventura, pružaju okvir koji **svaki sistemski binarijarni fajl svrstava u posebne kategorije ograničenja**, definisane unutar **trust cache-a**, liste koja sadrži sistemske binarijarne fajlove i njihove odgovarajuće hash vrednosti​. Ova ograničenja se primenjuju na svaki izvršni binarijarni fajl u sistemu i obuhvataju skup **pravila** koja određuju zahteve za **pokretanje određenog binarnarnog fajla**. Pravila obuhvataju self constraints koje binarni fajl mora da ispuni, parent constraints koje mora da ispuni njegov nadređeni proces i responsible constraints kojih moraju da se pridržavaju drugi relevantni entiteti​.

Ovaj mehanizam se, počev od macOS Sonoma, proširuje i na aplikacije trećih strana kroz **Environment Constraints**, omogućavajući developerima da zaštite svoje aplikacije navođenjem **skupa ključeva i vrednosti za environment constraints.**

**Launch environment and library constraints** definišete u constraint dictionaries koje čuvate u **`launchd` property list fajlovima** ili u **zasebnim property list** fajlovima koje koristite prilikom code signing-a.

Postoje 4 vrste ograničenja:

- **Self Constraints**: Ograničenja koja se primenjuju na **pokrenuti** binarni fajl.
- **Parent Process**: Ograničenja koja se primenjuju na **nadređeni proces** (na primer **`launchd`** koji pokreće XP servis)
- **Responsible Constraints**: Ograničenja koja se primenjuju na **proces koji poziva servis** u XPC komunikaciji
- **Library load constraints**: Library load constraints koristite za selektivno opisivanje koda koji može da se učita

Kada proces pokuša da pokrene drugi proces — pozivanjem `execve(_:_:_:)` ili `posix_spawn(_:_:_:_:_:_:)` — operativni sistem proverava da li **izvršni** fajl ispunjava svoj **sopstveni self constraint**. Takođe proverava da li izvršni fajl **nadređenog** **procesa** ispunjava **parent constraint** izvršnog fajla i da li izvršni fajl **responsible** **procesa** ispunjava **responsible process constraint** izvršnog fajla. Ako bilo koje od ovih launch constraints nije ispunjeno, operativni sistem ne pokreće program.

Ako prilikom učitavanja biblioteke bilo koji deo **library constraint-a nije ispunjen**, vaš proces **ne učitava** biblioteku.

## LC kategorije

LC se sastoji od **činjenica** i **logičkih operacija** (and, or..) koje kombinuju činjenice.

[ **Činjenice koje LC može da koristi dokumentovane su ovde**](https://developer.apple.com/documentation/security/defining_launch_environment_and_library_constraints). Na primer:

- is-init-proc: Boolean vrednost koja pokazuje da li izvršni fajl mora da bude proces za inicijalizaciju operativnog sistema (`launchd`).
- is-sip-protected: Boolean vrednost koja pokazuje da li izvršni fajl mora da bude fajl zaštićen funkcijom System Integrity Protection (SIP).
- `on-authorized-authapfs-volume:` Boolean vrednost koja pokazuje da li je operativni sistem učitao izvršni fajl sa autorizovanog, autentifikovanog APFS volumena.
- `on-authorized-authapfs-volume`: Boolean vrednost koja pokazuje da li je operativni sistem učitao izvršni fajl sa autorizovanog, autentifikovanog APFS volumena.
- Cryptexes volume
- `on-system-volume:`Boolean vrednost koja pokazuje da li je operativni sistem učitao izvršni fajl sa trenutno pokrenutog sistemskog volumena.
- Unutar /System...
- ...

Kada se Apple binarni fajl potpiše, **dodeljuje mu se kategorija LC-a** unutar **trust cache-a**.

- **iOS 16 LC kategorije** su [**reverse-engineer-ovane i dokumentovane ovde**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056).<sup>[6]</sup>
- Aktuelne **LC kategorije (macOS 14** - Somona) su reverse-engineer-ovane, a njihovi [**opisi se mogu pronaći ovde**](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53).<sup>[7]</sup>

Na primer, kategorija 1 je:<sup>[7]</sup>
```
Category 1:
Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
Parent Constraint: is-init-proc
```
- `(on-authorized-authapfs-volume || on-system-volume)`: Mora biti u System ili Cryptexes volume.
- `launch-type == 1`: Mora biti system service (plist u LaunchDaemons).
- `validation-category == 1`: Izvršna datoteka operativnog sistema.
- `is-init-proc`: Launchd

### Reversing LC Categories

Više informacija o tome možete pronaći [**ovde**](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints), ali ukratko, one su definisane u **AMFI (AppleMobileFileIntegrity)**, tako da morate preuzeti Kernel Development Kit da biste dobili **KEXT**. Simboli koji počinju sa **`kConstraintCategory`** su oni koji su **interesantni**. Njihovim ekstraktovanjem dobićete DER (ASN.1) kodirani tok koji ćete morati da dekodirate pomoću [ASN.1 Decoder](https://holtstrom.com/michael/tools/asn1decoder.php) ili python-asn1 biblioteke i njene `dump.py` skripte, [andrivet/python-asn1](https://github.com/andrivet/python-asn1/tree/master), što će vam dati razumljiviji string.<sup>[3]</sup>

## Ograničenja okruženja

Ovo su Launch Constraints podešeni u **third party applications**. Developer može da izabere **facts** i **logical operands** koje će koristiti u svojoj aplikaciji kako bi ograničio pristup samoj aplikaciji.

Moguće je izlistati Environment Constraints aplikacije pomoću:
```bash
codesign -d -vvvv app.app
```
## Trust Caches

U **macOS** postoji nekoliko trust cache-ova:

- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4`**
- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**
- **`/System/Library/Security/OSLaunchPolicyData`**

A na iOS-u se, po svemu sudeći, nalazi u **`/usr/standalone/firmware/FUD/StaticTrustCache.img4`**.

> [!WARNING]
> Na macOS-u koji radi na Apple Silicon uređajima, ako se Apple signed binary ne nalazi u trust cache-u, AMFI će odbiti da ga učita.

### Enumerisanje Trust Caches

Prethodni trust cache fajlovi su u formatima **IMG4** i **IM4P**, pri čemu je IM4P payload sekcija IMG4 formata.

Možete koristiti [**pyimg4**](https://github.com/m1stadev/PyIMG4) za izdvajanje payload-a iz baza podataka:
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

Sada možete koristiti alat [**trustcache**](https://github.com/CRKatri/trustcache) da biste dobili informacije u čitljivom formatu:
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
Trust cache prati sledeću strukturu, tako da je **LC kategorija 4. kolona**
```c
struct trust_cache_entry2 {
uint8_t cdhash[CS_CDHASH_LEN];
uint8_t hash_type;
uint8_t flags;
uint8_t constraintCategory;
uint8_t reserved0;
} __attribute__((__packed__));
```
Zatim možete koristiti skriptu kao što je [**ova**](https://gist.github.com/xpn/66dc3597acd48a4c31f5f77c3cc62f30) za izdvajanje podataka.

Na osnovu tih podataka možete proveriti aplikacije sa **vrednošću launch constraints `0`**, odnosno one koje nisu ograničene ([**proverite ovde**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056) šta svaka vrednost predstavlja).<sup>[6]</sup>

## Ublažavanje napada

Launch Constraints bi ublažio nekoliko starih napada tako što bi **osigurao da se proces ne izvršava u neočekivanim uslovima:** na primer, sa neočekivanih lokacija ili pozvan od strane neočekivanog nadređenog procesa (ako bi samo launchd trebalo da ga pokreće).

Pored toga, Launch Constraints takođe **ublažava downgrade napade.**

Međutim, oni **ne ublažavaju uobičajene XPC** zloupotrebe, **Electron** code injections ili **dylib injections** bez library validation (osim ako su poznati team IDs koji mogu da učitavaju biblioteke).<sup>[3]</sup>

### XPC Daemon Protection

U izdanju Sonoma, važna stavka je **konfiguracija odgovornosti** XPC service-a daemon-a. XPC service je odgovoran sam za sebe, za razliku od connecting client-a koji je odgovoran. Ovo je dokumentovano u feedback report-u FB13206884. Ova postavka može delovati manjkavo, jer omogućava određene interakcije sa XPC service-om:

- **Pokretanje XPC Service-a**: Ako se ovo smatra bug-om, ova postavka ne dozvoljava pokretanje XPC service-a pomoću attacker code-a.
- **Povezivanje sa aktivnim service-om**: Ako XPC service već radi (moguće je da ga je aktivirala njegova originalna aplikacija), ne postoje prepreke za povezivanje sa njim.

Iako bi implementiranje constraints-a na XPC service-u moglo biti korisno za **smanjivanje prostora za potencijalne napade**, ono ne rešava primarni problem. Obezbeđivanje sigurnosti XPC service-a u osnovi zahteva **efikasnu validaciju connecting client-a**. To ostaje jedini način za jačanje sigurnosti service-a. Takođe je važno napomenuti da je navedena konfiguracija odgovornosti trenutno operativna, što možda nije u skladu sa predviđenim dizajnom.<sup>[3]</sup>

### Electron Protection

Čak i ako je zahtev da aplikaciju mora da **otvori LaunchService** (u parents constraints). Ovo se može postići pomoću **`open`** (koji može da postavi env variables) ili korišćenjem **Launch Services API-ja** (gde se env variables mogu navesti).<sup>[3]</sup>

### CVE-2025-43253 - Zaobilaženje ugrađenih constraints-a tokom spawn-a

Launch constraints (zvanično **lightweight code requirements**, *LWCR*) sprovodi **AMFI MAC policy**. `posix_spawn` omogućava caller-u da prosledi proizvoljan blob MAC policy-ju putem **`posix_spawnattr_setmacpolicyinfo_np()`**, a AMFI je tim putem prihvatao LWCR dictionary koji je prosledio caller. Bug se sastojao u tome što su **constraints-i koje je prosledio attacker zamenjivali ugrađene constraints-e binary-ja**, umesto da se proveravaju dodatno uz njih:

- Napraviti minimalan (čak i prazan) launch-constraints dictionary.
- Postaviti **constraint category na `127`**, vrednost koju AMFI dozvoljava u spawn attributes, ali je **ne sprovodi** — umesto blokiranja izvršavanja, samo beleži `Launch Constraint Violation (not enforcing)`.
- Proslediti ga kroz spawn attributes; proces se tada pokreće u kontekstu koji bi njegovi stvarni self/parent constraints-i zabranili.

Nakon ispravke, proveravaju se **i ugrađeni i prosleđeni constraints-i**, tako da prosleđeni dictionary više ne može da oslabi ugrađeni.<sup>[2]</sup>

> [!TIP]
> Ovo je opšti obrazac koji treba tražiti prilikom provere sprovođenja constraints-a: API koji omogućava da nepouzdan input *prosledi* policy obično je zanimljiv kada policy engine tretira prosleđenu vrednost kao zamenu, a ne kao dodatni zahtev.

## Reference

- [1] [Objective by the Sea #OBTS v6.0 Day 2 (Live-Stream)](https://youtu.be/f1HA5QhLQ7Y?t=24146)
- [2] [CVE-2025-43253: Zaobilaženje Launch Constraints-a na macOS-u (wts.dev)](https://wts.dev/posts/bypassing-launch-constraints/)
- [3] [Detaljna analiza Launch and Environment Constraints-a - theevilbit](https://theevilbit.github.io/posts/launch_constraints_deep_dive/)
- [4] [Zašto se system app ili command tool ne pokreće? Launch constraints i trust caches - The Eclectic Light Company](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
- [5] [Zaštitite svoju Mac aplikaciju pomoću environment constraints-a - WWDC23](https://developer.apple.com/videos/play/wwdc2023/10266/)
- [6] [Opis Launch Constraints-a uvedenih u iOS 16 (LinusHenze gist)](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)
- [7] [macOS Sonoma (14) Launch Constraints (theevilbit gist)](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53)

{{#include ../../../banners/hacktricks-training.md}}
