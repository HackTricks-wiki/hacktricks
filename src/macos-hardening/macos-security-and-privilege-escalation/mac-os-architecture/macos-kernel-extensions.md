# macOS Kernel Extensions & Kernelcaches

{{#include ../../../banners/hacktricks-training.md}}

## Osnovne informacije

Kernel extensions (Kexts) su **paketi** sa ekstenzijom **`.kext`** koji se **učitavaju direktno u prostor macOS kernela**, pružajući dodatnu funkcionalnost glavnom operativnom sistemu.

### Status deprecated funkcionalnosti i DriverKit / System Extensions
Počevši od **macOS Catalina (10.15)**, Apple je većinu legacy KPI-jeva označio kao *deprecated* i uveo **System Extensions & DriverKit** framework-e koji se izvršavaju u **user-space-u**. Od **macOS Big Sur (11)**, operativni sistem će *odbiti da učita* third-party kexts koji se oslanjaju na deprecated KPI-jeve, osim ako je računar pokrenut u režimu **Reduced Security**. Na Apple Silicon uređajima, omogućavanje kexts dodatno zahteva da korisnik:

1. Ponovo pokrene računar u **Recovery** režim → *Startup Security Utility*.
2. Izabere **Reduced Security** i označi **„Allow user management of kernel extensions from identified developers“**.
3. Ponovo pokrene računar i odobri kext u **System Settings → Privacy & Security**.

User-land driver-i napisani pomoću DriverKit/System Extensions značajno **smanjuju attack surface**, jer su crash-evi ili memory corruption ograničeni na sandboxed proces, umesto na kernel space.<sup>[[1]](#references)</sup>

> 📝 Počevši od macOS Sequoia (15), Apple je u potpunosti uklonio nekoliko legacy networking i USB KPI-jeva – jedino rešenje kompatibilno sa budućim verzijama za vendore jeste migracija na System Extensions.

### Zahtevi

Očigledno, ovo je toliko moćno da je **učitavanje kernel extension-a komplikovano**. Ovo su **zahtevi** koje kernel extension mora da ispuni da bi bila učitana:

- Prilikom **ulaska u recovery mode**, mora biti dozvoljeno učitavanje kernel **extensions**:

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- Kernel extension mora biti **potpisana kernel code signing sertifikatom**, koji može da **dodeli samo Apple**. Apple će detaljno proveriti kompaniju i razloge zbog kojih je sertifikat potreban.
- Kernel extension takođe mora biti **notarized**; Apple će moći da proveri da li sadrži malware.
- Zatim, **root** korisnik može da **učita kernel extension**, a fajlovi unutar paketa moraju **pripadati root-u**.
- Tokom procesa upload-a, paket mora biti pripremljen na **zaštićenoj lokaciji koja nije root**: `/Library/StagedExtensions` (zahteva `com.apple.rootless.storage.KernelExtensionManagement` grant).
- Na kraju, prilikom pokušaja učitavanja, korisnik će [**dobiti zahtev za potvrdu**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html), a ako ga prihvati, računar mora biti **restartovan** da bi se extension učitao.

### Proces učitavanja

U Catalina verziji proces je izgledao ovako: Zanimljivo je primetiti da se proces **verifikacije** odvija u **userland-u**. Međutim, samo aplikacije sa **`com.apple.private.security.kext-management`** grant-om mogu **zahtevati od kernela da učita extension**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli **pokreće** proces **verifikacije** za učitavanje extension-a
- Komunicira sa **`kextd`** slanjem zahteva putem **Mach service-a**.
2. **`kextd`** proverava nekoliko stvari, kao što je **signature**
- Komunicira sa **`syspolicyd`** da bi **proverio** da li extension može biti **učitan**.
3. **`syspolicyd`** će **prikazati upit** **korisniku** ako extension prethodno nije bio učitan.
- **`syspolicyd`** će prijaviti rezultat procesu **`kextd`**
4. **`kextd`** će konačno moći da **naloži kernelu da učita** extension

Ako **`kextd`** nije dostupan, **`kextutil`** može da izvrši iste provere.

### Enumeracija i upravljanje (učitanim kexts)

`kextstat` je bio istorijski alat, ali je **deprecated** u novijim verzijama macOS-a. Moderni interfejs je **`kmutil`**:
```bash
# List every extension currently linked in the kernel, sorted by load address
sudo kmutil showloaded --sort

# Show only third-party / auxiliary collections
sudo kmutil showloaded --collection aux

# Unload a specific bundle
sudo kmutil unload -b com.example.mykext
```
Starija sintaksa je i dalje dostupna za referencu:
```bash
# (Deprecated) Get loaded kernel extensions
kextstat

# (Deprecated) Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
`kmutil inspect` se takođe može iskoristiti za **dump sadržaja Kernel Collection (KC)** ili za proveru da li kext razrešava sve zavisnosti simbola:
```bash
# List fileset entries contained in the boot KC
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Check undefined symbols of a 3rd party kext before loading
kmutil libraries -p /Library/Extensions/FancyUSB.kext --undef-symbols
```
## Kernelcache

> [!CAUTION]
> Iako se očekuje da se kernel extensions nalaze u `/System/Library/Extensions/`, ako otvorite ovaj folder, **nećete pronaći nijedan binary**. To je zbog **kernelcache-a**, a da biste reverse-ovali jedan `.kext`, morate pronaći način da ga pribavite.

**Kernelcache** je **pre-compiled i pre-linked verzija XNU kernela**, zajedno sa osnovnim device **drivers** i **kernel extensions**. Čuva se u **compressed** formatu i dekompresuje se u memoriju tokom boot-up procesa. Kernelcache omogućava **brže bootovanje** tako što obezbeđuje spremnu verziju kernela i ključnih driver-a, čime se smanjuju vreme i resursi koji bi inače bili potrebni za dinamičko učitavanje i povezivanje ovih komponenti tokom boot-a.

Glavne prednosti kernelcache-a su **brzina učitavanja** i činjenica da su svi moduli prelinked (nema prepreke pri učitavanju). Nakon što su svi moduli prelinked, KXLD može biti uklonjen iz memorije, pa **XNU ne može da učita nove KEXT-ove.**

> [!TIP]
> Alat [https://github.com/dhinakg/aeota](https://github.com/dhinakg/aeota) dekriptuje Apple-ove AEA (Apple Encrypted Archive / AEA asset) kontejnere — encrypted container format koji Apple koristi za OTA assets i neke IPSW delove — i može da generiše osnovni .dmg/asset archive koji zatim možete extract-ovati pomoću priloženih aastuff alata.


### Local Kerlnelcache

U iOS-u se nalazi na lokaciji **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`**, a u macOS-u možete ga pronaći pomoću: **`find / -name "kernelcache" 2>/dev/null`** \
U mom slučaju, u macOS-u sam ga pronašao na:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

Pronađite ovde i [**kernelcache verzije 14 sa symbols**](https://x.com/tihmstar/status/1295814618242318337?lang=en).

#### IMG4 / BVX2 (LZFSE) compressed

IMG4 file format je container format koji Apple koristi na svojim iOS i macOS uređajima za bezbedno **čuvanje i verifikaciju firmware** komponenti (kao što je **kernelcache**). IMG4 format uključuje header i nekoliko tagova koji enkapsuliraju različite delove podataka, uključujući stvarni payload (kao što su kernel ili bootloader), signature i skup manifest properties. Format podržava cryptographic verification, što uređaju omogućava da potvrdi autentičnost i integritet firmware komponente pre njenog izvršavanja.

Obično se sastoji od sledećih komponenti:

- **Payload (IM4P)**:
- Često compressed (LZFSE4, LZSS, …)
- Opciono encrypted
- **Manifest (IM4M)**:
- Sadrži Signature
- Dodatni Key/Value dictionary
- **Restore Info (IM4R)**:
- Poznat i kao APNonce
- Sprečava replay nekih update-a
- OPTIONAL: Obično se ne nalazi

Dekompresujte Kernelcache:
```bash
# img4tool (https://github.com/tihmstar/img4tool)
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# pyimg4 (https://github.com/m1stadev/PyIMG4)
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# imjtool (https://newandroidbook.com/tools/imjtool.html)
imjtool _img_name_ [extract]

# disarm (you can use it directly on the IMG4 file) - [https://newandroidbook.com/tools/disarm.html](https://newandroidbook.com/tools/disarm.html)
disarm -L kernelcache.release.v57 # From unzip ipsw

# disamer (extract specific parts, e.g. filesets) - [https://newandroidbook.com/tools/disarm.html](https://newandroidbook.com/tools/disarm.html)
disarm -e filesets kernelcache.release.d23
```
#### Disarm simboli za kernel

**`Disarm`** omogućava simboličko označavanje funkcija iz kernelcache-a pomoću matchers-a. Ovi matchers-i su samo jednostavna pravila obrazaca (tekstualne linije) koja govore alatu disarm kako da prepozna i automatski simbolički označi funkcije, argumente i panic/log stringove unutar binarne datoteke.

Dakle, navodite string koji funkcija koristi, a disarm će ga pronaći i **simbolički označiti**.

Neke `xnu.matchers` možete pronaći na [https://newosxbook.com/tools/disarm.html](https://newosxbook.com/tools/disarm.html), u odeljku **`Matchers`**. Takođe možete kreirati sopstvene matchers-e.
```bash
# Go to /tmp/extracted where disarm extracted the filesets
disarm -e filesets kernelcache.release.d23 # Always extract to /tmp/extracted
cd /tmp/extracted
JMATCHERS=xnu.matchers disarm --analyze kernel.rebuilt  # Note that xnu.matchers is actually a file with the matchers
```
### Preuzimanje

**IPSW (iPhone/iPad Software)** je Apple format paketa firmware-a koji se koristi za vraćanje uređaja, ažuriranja i kompletne firmware pakete. Između ostalog, sadrži **kernelcache**.

- [**KernelDebugKit Github**](https://github.com/dortania/KdkSupportPkg/releases)

Na adresi [https://github.com/dortania/KdkSupportPkg/releases](https://github.com/dortania/KdkSupportPkg/releases) moguće je pronaći sve kernel debug kit-ove. Možete ga preuzeti, montirati, otvoriti pomoću alata [Suspicious Package](https://www.mothersruin.com/software/SuspiciousPackage/get.html), pristupiti folderu **`.kext`** i **ekstrahovati ga**.

Proverite da li sadrži simbole pomoću:
```bash
nm -a ~/Downloads/Sandbox.kext/Contents/MacOS/Sandbox | wc -l
```
- [**theapplewiki.com**](https://theapplewiki.com/wiki/Firmware/Mac/14.x)**,** [**ipsw.me**](https://ipsw.me/)**,** [**theiphonewiki.com**](https://www.theiphonewiki.com/)

Apple ponekad objavljuje **kernelcache** sa **symbols**. Neke firmware-e sa symbols možete preuzeti prateći linkove na tim stranicama. Firmware-i će, između ostalih datoteka, sadržati i **kernelcache**.

Da biste **extract** kernel cache, možete uraditi sledeće:
```bash
# Install ipsw tool
brew install blacktop/tap/ipsw

# Extract only the kernelcache from the IPSW
ipsw extract --kernel /path/to/YourFirmware.ipsw -o out/

# You should get something like:
#   out/Firmware/kernelcache.release.iPhoneXX
#   or an IMG4 payload: out/Firmware/kernelcache.release.iPhoneXX.im4p

# If you get an IMG4 payload:
ipsw img4 im4p extract out/Firmware/kernelcache*.im4p -o kcache.raw
```
Druga opcija za **extract** fajlova počinje promenom ekstenzije sa `.ipsw` na `.zip` i **unzip**ovanjem.

Nakon **extract**ovanja firmware-a dobićete fajl poput: **`kernelcache.release.iphone14`**. On je u **IMG4** formatu, a zanimljive informacije možete **extract**ovati pomoću:

[**pyimg4**](https://github.com/m1stadev/PyIMG4)**:**
```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
[**img4tool**](https://github.com/tihmstar/img4tool)**:**
```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```

```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
[**img4tool**](https://github.com/tihmstar/img4tool)**:**
```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
### Provera kernelcache

Proverite da li kernelcache ima simbole pomoću
```bash
nm -a kernelcache.release.iphone14.e | wc -l
```
Ovim sada možemo da **izdvojimo sve ekstenzije** ili **onu za koju smo zainteresovani:**
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
|------|-----|---------|
| 2024 | **CVE-2024-44243** | Logički propust u **`storagekitd`** omogućio je *root* napadaču da registruje zlonamerni file-system bundle koji je na kraju učitao **unsigned kext**, **zaobilazeći System Integrity Protection (SIP)** i omogućavajući trajne rootkit-e. Ispravljeno u macOS 14.2 / 15.2. <sup>[[2]](#references)</sup>  |
| 2021 | **CVE-2021-30892** (*Shrootless*) | Installation daemon sa entitlement-om `com.apple.rootless.install` mogao je biti zloupotrebljen za izvršavanje proizvoljnih post-install skripti, onemogućavanje SIP-a i učitavanje proizvoljnih kext-ova. <sup>[[3]](#references)</sup> |

**Zaključci za red-teamere**

1. **Potražite entitled daemon-e (`codesign -dvv /path/bin | grep entitlements`) koji komuniciraju sa Disk Arbitration, Installer ili Kext Management.**
2. **Zloupotreba SIP bypass-a gotovo uvek omogućava učitavanje kext-a → izvršavanje koda u kernelu**.

**Saveti za odbranu**

*Ostavite SIP uključen*, pratite `kmutil load`/`kmutil create -n aux` pozive koji potiču od non-Apple binarnih datoteka i generišite upozorenje na svaki upis u `/Library/Extensions`. Endpoint Security događaji `ES_EVENT_TYPE_NOTIFY_KEXTLOAD` pružaju gotovo real-time vidljivost.

## Debugging macOS kernela i kext-ova

Apple-ov preporučeni workflow je da izgradite **Kernel Debug Kit (KDK)** koji odgovara pokrenutom build-u, a zatim se povežete sa **LLDB** preko mrežne sesije **KDP (Kernel Debugging Protocol)**.

### Jednokratni lokalni debugging panic-a
```bash
# Create a symbolication bundle for the latest panic
sudo kdpwrit dump latest.kcdata
kmutil analyze-panic latest.kcdata -o ~/panic_report.txt
```
### Udaljeno debugging uživo sa drugog Mac računara

1. Preuzmite i instalirajte tačnu verziju **KDK**-a za ciljnu mašinu.
2. Povežite ciljni Mac i host Mac pomoću **USB-C ili Thunderbolt kabla**.
3. Na **ciljnom Mac računaru**:
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
### Povezivanje LLDB-a sa određenim učitanim kext-om
```bash
# Identify load address of the kext
ADDR=$(kmutil showloaded --bundle-identifier com.example.driver | awk '{print $4}')

# Attach
sudo lldb -n kernel_task -o "target modules load --file /Library/Extensions/Example.kext/Contents/MacOS/Example --slide $ADDR"
```
> ℹ️  KDP izlaže samo **read-only** interfejs. Za dinamičku instrumentaciju moraćete da zakrpite binarni fajl na disku, iskoristite **kernel function hooking** (npr. `mach_override`) ili migrirate driver u **hypervisor** radi potpunog read/write pristupa.

## Reference

- [1] [DriverKit security for macOS - Apple Platform Security Guide](https://support.apple.com/guide/security/driverkit-security-seca48c92d43/web)
- [2] [Analyzing CVE-2024-44243, a macOS System Integrity Protection bypass through kernel extensions - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [3] [Microsoft finds new macOS vulnerability, Shrootless, that could bypass System Integrity Protection - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)

{{#include ../../../banners/hacktricks-training.md}}
