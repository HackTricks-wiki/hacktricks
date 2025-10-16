# macOS Kernel ekstenzije & Kernelcaches

{{#include ../../../banners/hacktricks-training.md}}

## Osnovne informacije

Kernel ekstenzije (Kexts) su **paketi** sa ekstenzijom **`.kext`** koji se **učitavaju direktno u macOS kernel prostor**, pružajući dodatnu funkcionalnost glavnom operativnom sistemu.

### Status zastarelosti & DriverKit / System Extensions
Počevši od **macOS Catalina (10.15)** Apple je većinu legacy KPI označio kao *deprecated* i uveo okvire **System Extensions & DriverKit** koji rade u **korisničkom prostoru**. Od **macOS Big Sur (11)** operativni sistem će *odbiti da učita* third-party kexts koji zavise od zastarelih KPIs osim ako je mašina pokrenuta u režimu **Reduced Security**. Na Apple Silicon platformi, omogućavanje kextova dodatno zahteva od korisnika da:

1. Reboot-uje u **Recovery** → *Startup Security Utility*.
2. Izabere **Reduced Security** i označi **“Allow user management of kernel extensions from identified developers”**.
3. Ponovo pokrene i odobri kext iz **System Settings → Privacy & Security**.

User-land drajveri napisani sa DriverKit/System Extensions dramatično **smanjuju attack surface** jer su padovi ili korupcija memorije ograničeni na sandboxovan proces umesto na kernel prostor.

> 📝 Od macOS Sequoia (15) Apple je u potpunosti uklonio nekoliko legacy networking i USB KPIs – jedino forward-compatible rešenje za dobavljače je da migriraju na System Extensions.

### Zahtevi

Očigledno, ovo je toliko moćno da je **komplikovano učitati kernel ekstenziju**. Ovo su **zahtevi** koje kernel ekstenzija mora ispuniti da bi bila učitana:

- Kada se **ulazi u recovery mode**, kernel **ekstenzije moraju biti dozvoljene** za učitavanje:

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- Kernel ekstenzija mora biti **potpisana kernel code signing sertifikatom**, koji može izdati samo **Apple**. Apple će detaljno pregledati kompaniju i razloge zašto je sertifikat potreban.
- Kernel ekstenzija takođe mora biti **notarized**, Apple će moći da je proveri na malware.
- Zatim, korisnik **root** je taj koji može **učitati kernel ekstenziju** i fajlovi unutar paketa moraju **pripadati root-u**.
- Tokom procesa otpremanja, paket mora biti pripremljen u **zaštićenoj lokaciji koja nije root**: `/Library/StagedExtensions` (zahteva `com.apple.rootless.storage.KernelExtensionManagement` grant).
- Na kraju, prilikom pokušaja učitavanja, korisnik će [**dobiti zahtev za potvrdu**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) i, ako prihvati, računar mora biti **restartovan** da bi se ekstenzija učitala.

### Proces učitavanja

U Catalina je to izgledalo ovako: Zanimljivo je napomenuti da se proces **verifikacije** odvija u **userland-u**. Međutim, samo aplikacije sa **`com.apple.private.security.kext-management`** grant-om mogu **zahtevati kernel da učita ekstenziju**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli **pokreće** proces **verifikacije** za učitavanje ekstenzije
- Komunicira sa **`kextd`** koristeći **Mach service**.
2. **`kextd`** će proveriti nekoliko stvari, kao što je **potpis**
- Komunicira sa **`syspolicyd`** da **proveri** da li ekstenzija može da bude **učitana**.
3. **`syspolicyd`** će **zatražiti potvrdu** od **korisnika** ako ekstenzija ranije nije bila učitana.
- **`syspolicyd`** će izvestiti rezultat nazad **`kextd`**
4. **`kextd`** će konačno moći da **naredi kernelu da učita** ekstenziju

Ako **`kextd`** nije dostupan, **`kextutil`** može izvršiti iste provere.

### Enumeracija i upravljanje (učitanim kextovima)

`kextstat` je bio istorijski alat, ali je **zastareo** u novijim macOS izdanjima. Moderni interfejs je **`kmutil`**:
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
`kmutil inspect` se takođe može iskoristiti za **dump the contents of a Kernel Collection (KC)** ili za proveru da li kext rešava sve zavisnosti simbola:
```bash
# List fileset entries contained in the boot KC
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Check undefined symbols of a 3rd party kext before loading
kmutil libraries -p /Library/Extensions/FancyUSB.kext --undef-symbols
```
## Kernelcache

> [!CAUTION]
> Iako se kernel ekstenzije očekuju u `/System/Library/Extensions/`, ako odete u ovaj folder **nećete naći nijedan binarni fajl**. To je zbog **kernelcache**-a i da biste reverzovali jednu `.kext` morate pronaći način da je nabavite.

The **kernelcache** je **pre-compiled and pre-linked version of the XNU kernel**, zajedno sa bitnim uređajnim **drivers** i **kernel extensions**. Skladišti se u **compressed** formatu i dekompresuje se u memoriju tokom procesa boot-up. Kernelcache omogućava **brže vreme podizanja sistema** tako što sadrži spremnu verziju kernela i ključne drajvere, smanjujući vreme i resurse koji bi se inače trošili na dinamičko učitavanje i linkovanje ovih komponenti pri podizanju sistema.

Glavne prednosti kernelcache-a su **speed of loading** i to što su svi moduli prelinked (nema zastoja pri učitavanju). I kada su svi moduli prelinkedovani, KXLD se može ukloniti iz memorije tako da **XNU cannot load new KEXTs.**

> [!TIP]
> The [https://github.com/dhinakg/aeota](https://github.com/dhinakg/aeota) tool decrypts Apple’s AEA (Apple Encrypted Archive / AEA asset) containers — šifrovani format kontejnera koji Apple koristi za OTA assets i neke delove IPSW — i može proizvesti odgovarajući .dmg/asset arhiv koji možete potom izvaditi pomoću priloženih aastuff alata.


### Lokalni Kernelcache

U iOS-u se nalazi u **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`**, u macOS-u ga možete naći sa: **`find / -name "kernelcache" 2>/dev/null`** \
U mom slučaju na macOS-u ga pronašao sam u:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

Find also here the [**kernelcache of version 14 with symbols**](https://x.com/tihmstar/status/1295814618242318337?lang=en).

#### IMG4 / BVX2 (LZFSE) compressed

IMG4 file format je kontejnerski format koji Apple koristi na svojim iOS i macOS uređajima za bezbedno **storing and verifying firmware** komponenti (kao što je **kernelcache**). IMG4 format uključuje zaglavlje i nekoliko tagova koji enkapsuliraju različite delove podataka uključujući stvarni payload (kao kernel ili bootloader), potpis i skup manifest svojstava. Format podržava kriptografsku verifikaciju, omogućavajući uređaju da potvrdi autentičnost i integritet firmware komponente pre nego što je izvrši.

Obično se sastoji od sledećih komponenti:

- **Payload (IM4P)**:
- Često kompresovan (LZFSE4, LZSS, …)
- Opcionalno enkriptovan
- **Manifest (IM4M)**:
- Sadrži Signature
- Dodatni Key/Value dictionary
- **Restore Info (IM4R)**:
- Takođe poznato kao APNonce
- Sprečava replay nekih ažuriranja
- OPTIONAL: Obično se ne nalazi

Decompress the Kernelcache:
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

**`Disarm`** omogućava da symbolicate funkcije iz kernelcache-a koristeći matchere. Ti matcheri su samo jednostavna pravila šablona (tekstualne linije) koja govore disarm-u kako da prepozna & auto-symbolicate funkcije, argumente i panic/log stringove unutar binarnog fajla.

Dakle, u suštini označite string koji funkcija koristi i disarm će ga pronaći i **symbolicate it**.
```bash
You can find some `xnu.matchers` in [https://newosxbook.com/tools/disarm.html](https://newosxbook.com/tools/disarm.html) in the **`Matchers`** section. You can also create your own matchers.

```bash
# Idi u /tmp/extracted gde je disarm izvukao filesets
disarm -e filesets kernelcache.release.d23 # Always extract to /tmp/extracted
cd /tmp/extracted
JMATCHERS=xnu.matchers disarm --analyze kernel.rebuilt  # Note that xnu.matchers is actually a file with the matchers
```

### Download

An **IPSW (iPhone/iPad Software)** is Apple’s firmware package format used for device restores, updates, and full firmware bundles. Among other things, it contains the **kernelcache**.

- [**KernelDebugKit Github**](https://github.com/dortania/KdkSupportPkg/releases)

In [https://github.com/dortania/KdkSupportPkg/releases](https://github.com/dortania/KdkSupportPkg/releases) it's possible to find all the kernel debug kits. You can download it, mount it, open it with [Suspicious Package](https://www.mothersruin.com/software/SuspiciousPackage/get.html) tool, access the **`.kext`** folder and **extract it**.

Check it for symbols with:

```bash
nm -a ~/Downloads/Sandbox.kext/Contents/MacOS/Sandbox | wc -l
```

- [**theapplewiki.com**](https://theapplewiki.com/wiki/Firmware/Mac/14.x)**,** [**ipsw.me**](https://ipsw.me/)**,** [**theiphonewiki.com**](https://www.theiphonewiki.com/)

Sometime Apple releases **kernelcache** with **symbols**. You can download some firmwares with symbols by following links on those pages. The firmwares will contain the **kernelcache** among other files.

To **extract** the kernel cache you can do:

```bash
# Instalirajte ipsw alat
brew install blacktop/tap/ipsw

# Izvucite samo kernelcache iz IPSW-a
ipsw extract --kernel /path/to/YourFirmware.ipsw -o out/

# Treba da dobijete nešto ovako:
#   out/Firmware/kernelcache.release.iPhoneXX
#   ili IMG4 payload: out/Firmware/kernelcache.release.iPhoneXX.im4p

# Ako dobijete IMG4 payload:
ipsw img4 im4p extract out/Firmware/kernelcache*.im4p -o kcache.raw
```

Another option to **extract** the files start by changing the extension from `.ipsw` to `.zip` and **unzip** it.

After extracting the firmware you will get a file like: **`kernelcache.release.iphone14`**. It's in **IMG4** format, you can extract the interesting info with:

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

### Inspecting kernelcache

Check if the kernelcache has symbols with

```bash
nm -a kernelcache.release.iphone14.e | wc -l
```

With this we can now **extract all the extensions** or the **one you are interested in:**

```bash
# Lista svih ekstenzija
kextex -l kernelcache.release.iphone14.e
## Ekstrahuj com.apple.security.sandbox
kextex -e com.apple.security.sandbox kernelcache.release.iphone14.e

# Ekstrahuj sve
kextex_all kernelcache.release.iphone14.e

# Proveri ekstenziju za simbole
nm -a binaries/com.apple.security.sandbox | wc -l
```


## Recent vulnerabilities & exploitation techniques

| Year | CVE | Summary |
|------|-----|---------|
| 2024 | **CVE-2024-44243** | Logic flaw in **`storagekitd`** allowed a *root* attacker to register a malicious file-system bundle that ultimately loaded an **unsigned kext**, **bypassing System Integrity Protection (SIP)** and enabling persistent rootkits. Patched in macOS 14.2 / 15.2.   |
| 2021 | **CVE-2021-30892** (*Shrootless*) | Installation daemon with the entitlement `com.apple.rootless.install` could be abused to execute arbitrary post-install scripts, disable SIP and load arbitrary kexts.  |

**Take-aways for red-teamers**

1. **Look for entitled daemons (`codesign -dvv /path/bin | grep entitlements`) that interact with Disk Arbitration, Installer or Kext Management.**
2. **Abusing SIP bypasses almost always grants the ability to load a kext → kernel code execution**.

**Defensive tips**

*Keep SIP enabled*, monitor for `kmutil load`/`kmutil create -n aux` invocations coming from non-Apple binaries and alert on any write to `/Library/Extensions`. Endpoint Security events `ES_EVENT_TYPE_NOTIFY_KEXTLOAD` provide near real-time visibility.

## Debugging macOS kernel & kexts

Apple’s recommended workflow is to build a **Kernel Debug Kit (KDK)** that matches the running build and then attach **LLDB** over a **KDP (Kernel Debugging Protocol)** network session.

### One-shot local debug of a panic

```bash
# Kreirajte bundle za simbolikaciju za najnoviji kernel panic
sudo kdpwrit dump latest.kcdata
kmutil analyze-panic latest.kcdata -o ~/panic_report.txt
```

### Live remote debugging from another Mac

1. Download + install the exact **KDK** version for the target machine.
2. Connect the target Mac and the host Mac with a **USB-C or Thunderbolt cable**.
3. On the **target**:

```bash
sudo nvram boot-args="debug=0x100 kdp_match_name=macbook-target"
reboot
```

4. On the **host**:

```bash
lldb
(lldb) kdp-remote "udp://macbook-target"
(lldb) bt  # dohvati backtrace u kernel kontekstu
```

### Attaching LLDB to a specific loaded kext

```bash
# Identifikujte adresu učitavanja kext-a
ADDR=$(kmutil showloaded --bundle-identifier com.example.driver | awk '{print $4}')

# Prikači se
sudo lldb -n kernel_task -o "target modules load --file /Library/Extensions/Example.kext/Contents/MacOS/Example --slide $ADDR"
```

> ℹ️  KDP only exposes a **read-only** interface. For dynamic instrumentation you will need to patch the binary on-disk, leverage **kernel function hooking** (e.g. `mach_override`) or migrate the driver to a **hypervisor** for full read/write.

## References

- DriverKit Security – Apple Platform Security Guide
- Microsoft Security Blog – *Analyzing CVE-2024-44243 SIP bypass*

{{#include ../../../banners/hacktricks-training.md}}
