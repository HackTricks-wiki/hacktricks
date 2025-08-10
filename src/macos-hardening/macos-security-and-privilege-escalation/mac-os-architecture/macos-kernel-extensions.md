# macOS Kernel Extensions & Debugging

{{#include ../../../banners/hacktricks-training.md}}

## Osnovne informacije

Kernel ekstenzije (Kexts) su **paketi** sa **`.kext`** ekstenzijom koji se **učitavaju direktno u macOS kernel prostor**, pružajući dodatnu funkcionalnost glavnom operativnom sistemu.

### Status deprecacije & DriverKit / Sistem ekstenzije
Počevši od **macOS Catalina (10.15)**, Apple je označio većinu nasleđenih KPI-a kao *deprecated* i uveo **Sistem ekstenzije & DriverKit** okvire koji rade u **user-space**. Od **macOS Big Sur (11)**, operativni sistem će *odbiti da učita* treće strane kextove koji se oslanjaju na deprecated KPI-e osim ako je mašina pokrenuta u **Reduced Security** režimu. Na Apple Silicon-u, omogućavanje kextova dodatno zahteva od korisnika da:

1. Ponovo pokrene u **Recovery** → *Startup Security Utility*.
2. Izabere **Reduced Security** i označi **“Allow user management of kernel extensions from identified developers”**.
3. Ponovo pokrene i odobri kext iz **System Settings → Privacy & Security**.

Upravljački programi napisani sa DriverKit/Sistem ekstenzijama dramatično **smanjuju površinu napada** jer se rušenja ili oštećenje memorije ograničavaju na proces u sandbox-u umesto na kernel prostor.

> 📝 Od macOS Sequoia (15) Apple je potpuno uklonio nekoliko nasleđenih mrežnih i USB KPI-a – jedino rešenje koje je kompatibilno unapred za prodavce je migracija na Sistem ekstenzije.

### Zahtevi

Očigledno, ovo je toliko moćno da je **komplikovano učitati kernel ekstenziju**. Ovo su **zahtevi** koje kernel ekstenzija mora ispuniti da bi bila učitana:

- Kada se **ulazi u režim oporavka**, kernel **ekstenzije moraju biti dozvoljene** za učitavanje:

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- Kernel ekstenzija mora biti **potpisana sa sertifikatom za potpisivanje kernel koda**, koji može biti **dodeljen samo od strane Apple-a**. Ko će detaljno pregledati kompaniju i razloge zašto je to potrebno.
- Kernel ekstenzija takođe mora biti **notarizovana**, Apple će moći da je proveri na malver.
- Zatim, **root** korisnik je taj koji može **učitati kernel ekstenziju** i datoteke unutar paketa moraju **pripadati root-u**.
- Tokom procesa učitavanja, paket mora biti pripremljen na **zaštićenoj lokaciji koja nije root**: `/Library/StagedExtensions` (zahteva `com.apple.rootless.storage.KernelExtensionManagement` dozvolu).
- Na kraju, kada se pokuša učitati, korisnik će [**dobiti zahtev za potvrdu**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) i, ako bude prihvaćen, računar mora biti **ponovo pokrenut** da bi se učitao.

### Proces učitavanja

U Catalini je to izgledalo ovako: Zanimljivo je napomenuti da se **proceso verifikacije** dešava u **userland-u**. Međutim, samo aplikacije sa **`com.apple.private.security.kext-management`** dozvolom mogu **zatražiti od kernela da učita ekstenziju**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli **pokreće** **proceso verifikacije** za učitavanje ekstenzije
- Razgovaraće sa **`kextd`** slanjem putem **Mach servisa**.
2. **`kextd`** će proveriti nekoliko stvari, kao što su **potpis**
- Razgovaraće sa **`syspolicyd`** da **proveri** da li se ekstenzija može **učitati**.
3. **`syspolicyd`** će **pitati** **korisnika** ako ekstenzija nije prethodno učitana.
- **`syspolicyd`** će prijaviti rezultat **`kextd`**
4. **`kextd`** će konačno moći da **kaže kernelu da učita** ekstenziju

Ako **`kextd`** nije dostupan, **`kextutil`** može izvršiti iste provere.

### Enumeracija & upravljanje (učitani kextovi)

`kextstat` je bio istorijski alat, ali je **deprecated** u nedavnim macOS izdanjima. Moderna interfejs je **`kmutil`**:
```bash
# List every extension currently linked in the kernel, sorted by load address
sudo kmutil showloaded --sort

# Show only third-party / auxiliary collections
sudo kmutil showloaded --collection aux

# Unload a specific bundle
sudo kmutil unload -b com.example.mykext
```
Stariji sintaksis je još uvek dostupan za referencu:
```bash
# (Deprecated) Get loaded kernel extensions
kextstat

# (Deprecated) Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
`kmutil inspect` se takođe može iskoristiti za **izvlačenje sadržaja Kernel Collection (KC)** ili verifikaciju da kext rešava sve zavisnosti simbola:
```bash
# List fileset entries contained in the boot KC
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Check undefined symbols of a 3rd party kext before loading
kmutil libraries -p /Library/Extensions/FancyUSB.kext --undef-symbols
```
## Kernelcache

> [!CAUTION]
> Iako se očekuje da su kernel ekstenzije u `/System/Library/Extensions/`, ako odete u ovu fasciklu **nećete pronaći nijedan binarni fajl**. To je zbog **kernelcache** i da biste obrnuli jedan `.kext` potrebno je da pronađete način da ga dobijete.

**Kernelcache** je **prekompajlirana i prelinkovana verzija XNU kernela**, zajedno sa esencijalnim uređajnim **drajverima** i **kernel ekstenzijama**. Čuva se u **komprimovanom** formatu i dekompresuje se u memoriju tokom procesa pokretanja. Kernelcache olakšava **brže vreme pokretanja** tako što ima verziju kernela i ključnih drajvera spremnu za rad, smanjujući vreme i resurse koji bi inače bili potrošeni na dinamičko učitavanje i povezivanje ovih komponenti prilikom pokretanja.

### Lokalni Kernelcache

U iOS-u se nalazi u **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`**, u macOS-u ga možete pronaći sa: **`find / -name "kernelcache" 2>/dev/null`** \
U mom slučaju u macOS-u pronašao sam ga u:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

#### IMG4

IMG4 format fajla je kontejnerski format koji koristi Apple u svojim iOS i macOS uređajima za sigurno **čuvanje i verifikaciju firmware** komponenti (kao što je **kernelcache**). IMG4 format uključuje zaglavlje i nekoliko oznaka koje obuhvataju različite delove podataka uključujući stvarni payload (kao što je kernel ili bootloader), potpis i skup manifest svojstava. Format podržava kriptografsku verifikaciju, omogućavajući uređaju da potvrdi autentičnost i integritet firmware komponente pre nego što je izvrši.

Obično se sastoji od sledećih komponenti:

- **Payload (IM4P)**:
- Često komprimovan (LZFSE4, LZSS, …)
- Opcionalno enkriptovan
- **Manifest (IM4M)**:
- Sadrži potpis
- Dodatni rečnik Ključ/Vrednost
- **Restore Info (IM4R)**:
- Takođe poznat kao APNonce
- Sprečava ponavljanje nekih ažuriranja
- OPCIONALNO: Obično se ovo ne nalazi

Dekompresujte Kernelcache:
```bash
# img4tool (https://github.com/tihmstar/img4tool)
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# pyimg4 (https://github.com/m1stadev/PyIMG4)
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
### Preuzimanje

- [**KernelDebugKit Github**](https://github.com/dortania/KdkSupportPkg/releases)

Na [https://github.com/dortania/KdkSupportPkg/releases](https://github.com/dortania/KdkSupportPkg/releases) možete pronaći sve kernel debug kitove. Možete ga preuzeti, montirati, otvoriti sa alatom [Suspicious Package](https://www.mothersruin.com/software/SuspiciousPackage/get.html), pristupiti **`.kext`** folderu i **izvući ga**.

Proverite ga na simbole sa:
```bash
nm -a ~/Downloads/Sandbox.kext/Contents/MacOS/Sandbox | wc -l
```
- [**theapplewiki.com**](https://theapplewiki.com/wiki/Firmware/Mac/14.x)**,** [**ipsw.me**](https://ipsw.me/)**,** [**theiphonewiki.com**](https://www.theiphonewiki.com/)

Ponekad Apple objavljuje **kernelcache** sa **symbolima**. Možete preuzeti neke firmvere sa simbolima prateći linkove na tim stranicama. Firmveri će sadržati **kernelcache** među ostalim datotekama.

Da biste **izvukli** datoteke, počnite tako što ćete promeniti ekstenziju sa `.ipsw` na `.zip` i **raspakovati** je.

Nakon vađenja firmvera dobićete datoteku poput: **`kernelcache.release.iphone14`**. U **IMG4** formatu, možete izvući zanimljive informacije pomoću:

[**pyimg4**](https://github.com/m1stadev/PyIMG4)**:**
```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
[**img4tool**](https://github.com/tihmstar/img4tool)**:**
```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
### Inspekcija kernelcache-a

Proverite da li kernelcache ima simbole sa
```bash
nm -a kernelcache.release.iphone14.e | wc -l
```
Sa ovim možemo sada **izvući sve ekstenzije** ili **onu koja vas interesuje:**
```bash
# List all extensions
kextex -l kernelcache.release.iphone14.e
## Extract com.apple.security.sandbox
kextex -e com.apple.security.sandbox kernelcache.release.iphone14.e

# Extract all
kextex_all kernelcache.release.iphone14.e

# Check the extension for symbols
nm -a binaries/com.apple.security.sandbox | wc -l
```
## Nedavne ranjivosti i tehnike eksploatacije

| Godina | CVE | Sažetak |
|--------|-----|---------|
| 2024   | **CVE-2024-44243** | Logička greška u **`storagekitd`** omogućila je *root* napadaču da registruje zloćudni paket datotečnog sistema koji je na kraju učitao **nepotpisani kext**, **zaobilazeći zaštitu integriteta sistema (SIP)** i omogućavajući postojane rootkitove. Ispravljeno u macOS 14.2 / 15.2.   |
| 2021   | **CVE-2021-30892** (*Shrootless*) | Instalacioni demon sa ovlašćenjem `com.apple.rootless.install` mogao je biti zloupotrebljen za izvršavanje proizvoljnih post-instalacionih skripti, onemogućavanje SIP-a i učitavanje proizvoljnih kextova.  |

**Zaključci za red-timove**

1. **Tražite ovlašćene demone (`codesign -dvv /path/bin | grep entitlements`) koji interaguju sa Disk Arbitration, Installer ili Kext Management.**
2. **Zloupotreba SIP zaobilaženja gotovo uvek omogućava učitavanje kexta → izvršavanje koda u kernelu**.

**Defanzivni saveti**

*Zadržite SIP uključen*, pratite `kmutil load`/`kmutil create -n aux` pozive koji dolaze iz ne-Apple binarnih datoteka i obaveštavajte o bilo kojem pisanju u `/Library/Extensions`. Događaji Endpoint Security `ES_EVENT_TYPE_NOTIFY_KEXTLOAD` pružaju skoro real-time uvid.

## Debagovanje macOS kernela i kextova

Preporučeni radni tok Apple-a je da se izgradi **Kernel Debug Kit (KDK)** koji odgovara trenutnoj verziji i zatim se poveže **LLDB** preko **KDP (Kernel Debugging Protocol)** mrežne sesije.

### Jednokratno lokalno debagovanje panike
```bash
# Create a symbolication bundle for the latest panic
sudo kdpwrit dump latest.kcdata
kmutil analyze-panic latest.kcdata -o ~/panic_report.txt
```
### Live remote debugging from another Mac

1. Preuzmite + instalirajte tačnu **KDK** verziju za ciljni uređaj.
2. Povežite ciljni Mac i host Mac sa **USB-C ili Thunderbolt kablom**.
3. Na **ciljnom**:
```bash
sudo nvram boot-args="debug=0x100 kdp_match_name=macbook-target"
reboot
```
4. Na **hostu**:
```bash
lldb
(lldb) kdp-remote "udp://macbook-target"
(lldb) bt  # get backtrace in kernel context
```
### Priključivanje LLDB na određeni učitani kext
```bash
# Identify load address of the kext
ADDR=$(kmutil showloaded --bundle-identifier com.example.driver | awk '{print $4}')

# Attach
sudo lldb -n kernel_task -o "target modules load --file /Library/Extensions/Example.kext/Contents/MacOS/Example --slide $ADDR"
```
> ℹ️  KDP samo izlaže **samo za čitanje** interfejs. Za dinamičku instrumentaciju biće potrebno da zakrpite binarni fajl na disku, iskoristite **hooking funkcija jezgra** (npr. `mach_override`) ili migrirate drajver na **hipervizor** za potpuni read/write.

## References

- DriverKit Security – Apple Platform Security Guide
- Microsoft Security Blog – *Analyzing CVE-2024-44243 SIP bypass*

{{#include ../../../banners/hacktricks-training.md}}
