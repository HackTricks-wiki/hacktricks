# macOS ograničenja pokretanja/okruženja i Trust Cache

{{#include ../../../banners/hacktricks-training.md}}

## Osnovne informacije

Ograničenja pokretanja u macOS-u uvedena su radi unapređenja bezbednosti tako što **uređuju kako, ko i odakle može da pokrene proces**. Uvedena u macOS Ventura, pružaju okvir koji **svaki sistemski binarni fajl svrstava u posebne kategorije ograničenja**, definisane unutar **trust cache-a** — liste sistemskih binarnih fajlova i njihovih hash vrednosti. Ova ograničenja važe za svaki izvršni binarni fajl u sistemu i obuhvataju skup **pravila** koja definišu uslove za **pokretanje određenog binarnog fajla**. Pravila obuhvataju ograničenja samog binarnog fajla koja on mora da ispuni, ograničenja roditeljskog procesa koja njegov roditeljski proces mora da ispuni i ograničenja odgovornog procesa kojih se moraju pridržavati drugi relevantni entiteti.<sup>[[1]](#references)[[4]](#references)</sup>

Od macOS Sonoma mehanizam obuhvata i aplikacije trećih strana kroz **Environment Constraints**, što programerima omogućava da zaštite svoje aplikacije navođenjem **skupa ključeva i vrednosti za ograničenja okruženja.**<sup>[[5]](#references)</sup>

**Ograničenja okruženja pri pokretanju i ograničenja biblioteka** definišu se u rečnicima ograničenja, koje možete sačuvati u **`launchd` datotekama property lista** ili u **zasebnim datotekama property lista** koje koristite pri potpisivanju koda.<sup>[[5]](#references)</sup>

Postoje 4 vrste ograničenja:

- **Self Constraints**: Ograničenja koja se primenjuju na **pokrenuti** binarni fajl.
- **Parent Process**: Ograničenja koja se primenjuju na **roditeljski proces** (na primer, **`launchd`** koji pokreće XPC servis)
- **Responsible Constraints**: Ograničenja koja se primenjuju na **proces koji poziva servis** u XPC komunikaciji
- **Library load constraints**: Ograničenja učitavanja biblioteka koriste se za selektivno opisivanje koda koji može da se učita

Kada proces pokuša da pokrene drugi proces — pozivom `execve(_:_:_:)` ili `posix_spawn(_:_:_:_:_:_:)` — operativni sistem proverava da li **izvršna** datoteka **ispunjava** svoje **sopstveno Self Constraint ograničenje**. Takođe proverava da li izvršna datoteka **roditeljskog procesa** **ispunjava** **Parent Constraint ograničenje** izvršne datoteke i da li izvršna datoteka **odgovornog procesa** **ispunjava Responsible Process Constraint ograničenje izvršne datoteke**. Ako bilo koje od ovih ograničenja pokretanja nije ispunjeno, operativni sistem ne pokreće program.

Ako pri učitavanju biblioteke bilo koji deo **ograničenja biblioteke nije ispunjen**, vaš proces **ne učitava** biblioteku.

## LC kategorije

LC se sastoji od **činjenica** i **logičkih operacija** (and, or..) koje kombinuju činjenice.

[**Dokumentovane su činjenice koje LC može da koristi**](https://developer.apple.com/documentation/security/defining_launch_environment_and_library_constraints). Na primer:

- is-init-proc: Bulova vrednost koja označava da li izvršni fajl mora biti proces za inicijalizaciju operativnog sistema (`launchd`).
- is-sip-protected: Bulova vrednost koja označava da li izvršni fajl mora biti datoteka zaštićena funkcijom System Integrity Protection (SIP).
- `on-authorized-authapfs-volume:` Bulova vrednost koja označava da li je operativni sistem učitao izvršni fajl sa autorizovanog, autentifikovanog APFS volumena.
- `on-authorized-authapfs-volume`: Bulova vrednost koja označava da li je operativni sistem učitao izvršni fajl sa autorizovanog, autentifikovanog APFS volumena.
  - Cryptexes volume
- `on-system-volume:`Bulova vrednost koja označava da li je operativni sistem učitao izvršni fajl sa trenutno pokrenutog sistemskog volumena.
  - Unutar /System...
- ...

Kada se Apple binarni fajl potpiše, **dodeljuje mu LC kategoriju** unutar **trust cache-a**.

- **LC kategorije za iOS 16** su [**obrnuto analizirane i dokumentovane ovde**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056).<sup>[[6]](#references)</sup>
- Aktuelne **LC kategorije (macOS 14** - Somona) su obrnuto analizirane, a njihove [**opise možete pronaći ovde**](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53).<sup>[[7]](#references)</sup>

Na primer, kategorija 1 je:<sup>[[7]](#references)</sup>

```
Category 1:
        Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
        Parent Constraint: is-init-proc
```

- `(on-authorized-authapfs-volume || on-system-volume)`: Mora da bude na System ili Cryptexes volume-u.
- `launch-type == 1`: Mora da bude sistemska usluga (plist u LaunchDaemons).
- `validation-category == 1`: Izvršna datoteka operativnog sistema.
- `is-init-proc`: Launchd

### Reverzni inženjering LC kategorija

Više informacija možete pronaći [**ovde**](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints), ali ukratko, one su definisane u **AMFI (AppleMobileFileIntegrity)**, pa morate da preuzmete Kernel Development Kit da biste dobili **KEXT**. Simboli koji počinju sa **`kConstraintCategory`** su **zanimljivi**. Kada ih izdvojite, dobićete DER (ASN.1) kodiran tok koji ćete morati da dekodirate pomoću [ASN.1 Decoder](https://holtstrom.com/michael/tools/asn1decoder.php) ili python-asn1 biblioteke i njene skripte `dump.py`, [andrivet/python-asn1](https://github.com/andrivet/python-asn1/tree/master), koja će vam dati razumljiviji string.<sup>[[3]](#references)[[8]](#references)</sup>

## Ograničenja okruženja

Ovo su Launch Constraints podešena u **aplikacijama trećih strana**. Programer može da izabere **činjenice** i **logičke operande koje će koristiti** u svojoj aplikaciji da bi ograničio pristup njoj.

Moguće je izlistati Environment Constraints neke aplikacije pomoću:

```bash
codesign -d -vvvv app.app
```

## Keševi poverenja

U **macOS** postoji nekoliko keševa poverenja:

- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4`**
- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**
- **`/System/Library/Security/OSLaunchPolicyData`**

A u iOS-u se čini da se nalazi u **`/usr/standalone/firmware/FUD/StaticTrustCache.img4`**.

> [!WARNING]
> Na macOS-u koji radi na uređajima sa Apple Silicon čipovima, ako se binarna datoteka koju je potpisao Apple ne nalazi u kešu poverenja, AMFI će odbiti da je učita.

### Enumerisanje keševa poverenja

Prethodne datoteke keša poverenja su u formatu **IMG4** i **IM4P**, pri čemu je IM4P odeljak sa sadržajem formata IMG4.

Možete da koristite [**pyimg4**](https://github.com/m1stadev/PyIMG4) da biste izdvojili sadržaj baza podataka:

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

(Druga opcija može biti korišćenje alata [**img4tool**](https://github.com/tihmstar/img4tool), koji će raditi čak i na M1, iako je izdanje staro i namenjeno za x86_64, ako ga instalirate na odgovarajuće lokacije).

Sada možete da koristite alat [**trustcache**](https://github.com/CRKatri/trustcache) da biste dobili informacije u čitljivom formatu:

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

Zatim biste mogli da upotrebite skriptu kao što je [**ova**](https://gist.github.com/xpn/66dc3597acd48a4c31f5f77c3cc62f30) da izdvojite podatke.

Na osnovu tih podataka možete da proverite aplikacije koje imaju **vrednost launch constraints `0`** — one nisu ograničene ([**ovde**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056) možete proveriti značenje svake vrednosti).<sup>[[6]](#references)</sup>

## Ublažavanje napada

Launch Constraints bi ublažio nekoliko starih napada tako što bi **osigurao da se proces ne izvršava u neočekivanim uslovima**: na primer, sa neočekivanih lokacija ili kada ga pokrene neočekivani nadređeni proces (ako bi trebalo da ga pokreće samo launchd).

Pored toga, Launch Constraints **ublažava i downgrade napade**.

Međutim, **ne ublažava uobičajene zloupotrebe XPC-a**, ubacivanje koda u **Electron** niti **dylib injections** bez library validation (osim ako nisu poznati team ID-jevi kojima je dozvoljeno učitavanje biblioteka).<sup>[[3]](#references)</sup>

### Zaštita XPC demona

U izdanju Sonoma, značajna stavka je **konfiguracija odgovornosti** XPC servisa demona. Za XPC servis odgovoran je sam servis, a ne klijent koji se povezuje. Ovo je dokumentovano u izveštaju o povratnim informacijama FB13206884. Ovo podešavanje može delovati manjkavo jer omogućava određene interakcije sa XPC servisom:

- **Pokretanje XPC servisa**: Ako se ovo smatra greškom, podešavanje ne dozvoljava pokretanje XPC servisa pomoću koda napadača.
- **Povezivanje sa aktivnim servisom**: Ako je XPC servis već pokrenut (možda ga je aktivirala njegova originalna aplikacija), nema prepreka za povezivanje sa njim.

Uvođenje ograničenja za XPC servis moglo bi biti korisno jer bi **sužilo vremenski prozor za potencijalne napade**, ali ne rešava osnovni problem. Da bi XPC servis bio bezbedan, neophodno je **efikasno proveravati klijenta koji se povezuje**. To je jedini način da se ojača bezbednost servisa. Takođe, vredi napomenuti da je pomenuta konfiguracija odgovornosti trenutno aktivna, što možda nije u skladu sa predviđenim dizajnom.<sup>[[3]](#references)</sup>

### Zaštita Electron-a

Čak i ako je neophodno da aplikaciju **otvori LaunchService** (u ograničenjima nadređenog procesa), to se može postići pomoću **`open`** (koji može da postavi env varijable) ili pomoću **Launch Services API-ja** (u kom se mogu navesti env varijable).<sup>[[3]](#references)</sup>

Opšti opis mehanizma MACF koji stoji iza atributa pokretanja specifičnih za pravila potražite u odeljku [Atributi pokretanja specifični za pravila u MACF-u](macos-macf-mandatory-access-control-framework.md#policy-specific-spawn-attributes-as-a-macf-input).

### CVE-2025-43253 - Zaobilaženje ugrađenih ograničenja tokom pokretanja procesa

Launch constraints (zvanično **lightweight code requirements**, *LWCR*) sprovodi **AMFI MAC policy**. `posix_spawn` omogućava pozivaocu da prosledi proizvoljan blob MAC policy-ju pomoću **`posix_spawnattr_setmacpolicyinfo_np()`**, a AMFI je preko tog mehanizma prihvatao LWCR dictionary koji je dostavio pozivalac. Greška je bila u tome što su **ograničenja koja je dostavio napadač zamenjivala ugrađena ograničenja binarne datoteke**, umesto da se proveravaju uz njih:

- Napravite minimalan (čak i prazan) launch-constraints dictionary.
- Postavite **kategoriju ograničenja na `127`**, vrednost koju AMFI dozvoljava u spawn atributima, ali je **ne sprovodi** — umesto da blokira izvršavanje, samo beleži `Launch Constraint Violation (not enforcing)`.
- Prosledite je putem spawn atributa; proces će se pokrenuti u kontekstu koji bi njegova stvarna ograničenja za sebe/nadređeni proces zabranila.

Nakon ispravke, proveravaju se **i ugrađena i dostavljena ograničenja**, pa dostavljeni dictionary više ne može da oslabi ugrađena ograničenja.<sup>[[2]](#references)</sup>

> [!TIP]
> Ovo je opšti obrazac na koji treba obratiti pažnju pri proveri sprovođenja ograničenja: API koji omogućava da nepouzdan ulaz *dostavi* pravilo često je zanimljiv kada mehanizam za sprovođenje pravila tretira dostavljenu vrednost kao zamenu, a ne kao dodatni uslov.



## References

- [1] [Objective by the Sea #OBTS v6.0, 2. dan (prenos uživo)](https://youtu.be/f1HA5QhLQ7Y?t=24146)
- [2] [CVE-2025-43253: Zaobilaženje Launch Constraints na macOS-u (wts.dev)](https://wts.dev/posts/bypassing-launch-constraints/)
- [3] [Detaljan pregled Launch and Environment Constraints - theevilbit](https://theevilbit.github.io/posts/launch_constraints_deep_dive/)
- [4] [Zašto se sistemska aplikacija ili komandni alat ne pokreće? Launch constraints i trust caches - The Eclectic Light Company](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
- [5] [Zaštitite svoju Mac aplikaciju pomoću environment constraints - WWDC23](https://developer.apple.com/videos/play/wwdc2023/10266/)
- [6] [Opis Launch Constraints uvedenih u iOS 16 (LinusHenze gist)](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)
- [7] [Launch Constraints u macOS Sonoma (14) (theevilbit gist)](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53)
- [8] [Više od dobrih starih LaunchAgents - više o tome ovde](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints)
{{#include ../../../banners/hacktricks-training.md}}
