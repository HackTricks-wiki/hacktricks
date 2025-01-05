# macOS Kernel Extensions & Debugging

{{#include ../../../banners/hacktricks-training.md}}

## Osnovne informacije

Kernel ekstenzije (Kexts) su **paketi** sa **`.kext`** ekstenzijom koji se **učitavaju direktno u macOS kernel prostor**, pružajući dodatnu funkcionalnost glavnom operativnom sistemu.

### Zahtevi

Očigledno, ovo je toliko moćno da je **komplikovano učitati kernel ekstenziju**. Ovo su **zahtevi** koje kernel ekstenzija mora ispuniti da bi bila učitana:

- Kada **uđete u režim oporavka**, kernel **ekstenzije moraju biti dozvoljene** za učitavanje:

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- Kernel ekstenzija mora biti **potpisana sa sertifikatom za potpisivanje kernel koda**, koji može biti **dodeljen samo od strane Apple-a**. Ko će detaljno pregledati kompaniju i razloge zašto je to potrebno.
- Kernel ekstenzija takođe mora biti **notarizovana**, Apple će moći da je proveri na malver.
- Zatim, **root** korisnik je taj koji može **učitati kernel ekstenziju** i datoteke unutar paketa moraju **pripadati root-u**.
- Tokom procesa učitavanja, paket mora biti pripremljen na **zaštićenoj lokaciji koja nije root**: `/Library/StagedExtensions` (zahteva `com.apple.rootless.storage.KernelExtensionManagement` dozvolu).
- Na kraju, kada pokušate da je učitate, korisnik će [**dobiti zahtev za potvrdu**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) i, ako bude prihvaćen, računar mora biti **ponovo pokrenut** da bi se učitala.

### Proces učitavanja

U Catalini je to izgledalo ovako: Zanimljivo je napomenuti da se **proverava** proces dešava u **userland-u**. Međutim, samo aplikacije sa **`com.apple.private.security.kext-management`** dozvolom mogu **zatražiti od kernela da učita ekstenziju**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli **pokreće** **proveru** za učitavanje ekstenzije
- Razgovaraće sa **`kextd`** slanjem putem **Mach servisa**.
2. **`kextd`** će proveriti nekoliko stvari, kao što je **potpis**
- Razgovaraće sa **`syspolicyd`** da **proveri** da li se ekstenzija može **učitati**.
3. **`syspolicyd`** će **pitati** **korisnika** ako ekstenzija nije prethodno učitana.
- **`syspolicyd`** će izvestiti rezultat **`kextd`**
4. **`kextd`** će konačno moći da **kaže kernelu da učita** ekstenziju

Ako **`kextd`** nije dostupan, **`kextutil`** može izvršiti iste provere.

### Enumeracija (učitane kexts)
```bash
# Get loaded kernel extensions
kextstat

# Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
## Kernelcache

> [!CAUTION]
> Iako se očekuje da su kernel ekstenzije u `/System/Library/Extensions/`, ako odete u ovu fasciklu **nećete pronaći nijedan binarni** fajl. To je zbog **kernelcache** i da biste obrnuli jedan `.kext` morate pronaći način da ga dobijete.

**Kernelcache** je **prekompajlirana i prelinkovana verzija XNU kernela**, zajedno sa esencijalnim uređajnim **drajverima** i **kernel ekstenzijama**. Čuva se u **kompresovanom** formatu i dekompresuje se u memoriju tokom procesa pokretanja. Kernelcache olakšava **brže vreme pokretanja** tako što ima verziju kernela i ključnih drajvera spremnu za rad, smanjujući vreme i resurse koji bi inače bili potrošeni na dinamičko učitavanje i linkovanje ovih komponenti prilikom pokretanja.

### Lokalni Kernelcache

U iOS-u se nalazi u **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`**, u macOS-u ga možete pronaći sa: **`find / -name "kernelcache" 2>/dev/null`** \
U mom slučaju u macOS-u pronašao sam ga u:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

#### IMG4

IMG4 format fajla je kontejnerski format koji koristi Apple u svojim iOS i macOS uređajima za sigurno **čuvanje i verifikaciju firmware** komponenti (kao što je **kernelcache**). IMG4 format uključuje zaglavlje i nekoliko oznaka koje enkapsuliraju različite delove podataka uključujući stvarni payload (kao što je kernel ili bootloader), potpis i skup manifest svojstava. Format podržava kriptografsku verifikaciju, omogućavajući uređaju da potvrdi autentičnost i integritet firmware komponente pre nego što je izvrši.

Obično se sastoji od sledećih komponenti:

- **Payload (IM4P)**:
- Često kompresovan (LZFSE4, LZSS, …)
- Opcionalno enkriptovan
- **Manifest (IM4M)**:
- Sadrži potpis
- Dodatni ključ/vrednost rečnik
- **Restore Info (IM4R)**:
- Takođe poznat kao APNonce
- Sprečava ponavljanje nekih ažuriranja
- OPCIONALNO: Obično se ovo ne nalazi

Dekompresujte Kernelcache:
```bash
# img4tool (https://github.com/tihmstar/img4tool
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# pyimg4 (https://github.com/m1stadev/PyIMG4)
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
### Preuzimanje

- [**KernelDebugKit Github**](https://github.com/dortania/KdkSupportPkg/releases)

Na [https://github.com/dortania/KdkSupportPkg/releases](https://github.com/dortania/KdkSupportPkg/releases) je moguće pronaći sve kernel debug kitove. Možete ga preuzeti, montirati, otvoriti sa alatom [Suspicious Package](https://www.mothersruin.com/software/SuspiciousPackage/get.html), pristupiti **`.kext`** folderu i **izvući ga**.

Proverite ga za simbole sa:
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
### Inspecting kernelcache

Proverite da li kernelcache ima simbole sa
```bash
nm -a kernelcache.release.iphone14.e | wc -l
```
Sa ovim možemo sada **izvući sve ekstenzije** ili **onu koja vas zanima:**
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
## Debugging

## Referencije

- [https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/](https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/)
- [https://www.youtube.com/watch?v=hGKOskSiaQo](https://www.youtube.com/watch?v=hGKOskSiaQo)

{{#include ../../../banners/hacktricks-training.md}}
