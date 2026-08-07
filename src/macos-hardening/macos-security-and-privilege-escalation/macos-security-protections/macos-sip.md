# macOS SIP

{{#include ../../../banners/hacktricks-training.md}}

## **Osnovne informacije**

**System Integrity Protection (SIP)** u macOS-u je mehanizam osmišljen da spreči čak i najprivilegovanije korisnike da izvrše neovlašćene izmene ključnih sistemskih fascikli. Ova funkcija igra ključnu ulogu u očuvanju integriteta sistema tako što ograničava radnje poput dodavanja, menjanja ili brisanja datoteka u zaštićenim oblastima. Primarne fascikle koje SIP štiti uključuju:

- **/System**
- **/bin**
- **/sbin**
- **/usr**

Pravila koja određuju ponašanje SIP-a definisana su u konfiguracionoj datoteci koja se nalazi na putanji **`/System/Library/Sandbox/rootless.conf`**. U ovoj datoteci putanje kojima prethodi zvezdica (\*) označene su kao izuzeci od inače strogih SIP ograničenja.

Razmotrite primer u nastavku:
```javascript
/usr
* /usr/libexec/cups
* /usr/local
* /usr/share/man
```
Ovaj isečak ukazuje na to da, iako SIP uglavnom štiti direktorijum **`/usr`**, postoje određeni poddirektorijumi (`/usr/libexec/cups`, `/usr/local` i `/usr/share/man`) u kojima su izmene dozvoljene, što je označeno zvezdicom (\*) ispred njihovih putanja.

Da biste proverili da li je direktorijum ili datoteka zaštićena funkcijom SIP, možete koristiti komandu **`ls -lOd`** da proverite prisustvo oznake **`restricted`** ili **`sunlnk`**. Na primer:
```bash
ls -lOd /usr/libexec/cups
drwxr-xr-x  11 root  wheel  sunlnk 352 May 13 00:29 /usr/libexec/cups
```
U ovom slučaju, zastavica **`sunlnk`** označava da direktorijum `/usr/libexec/cups` **ne može biti obrisan**, iako se datoteke unutar njega mogu kreirati, menjati ili brisati.

S druge strane:
```bash
ls -lOd /usr/libexec
drwxr-xr-x  338 root  wheel  restricted 10816 May 13 00:29 /usr/libexec
```
Ovde **`restricted`** zastavica označava da je direktorijum `/usr/libexec` zaštićen pomoću SIP-a. U direktorijumu zaštićenom pomoću SIP-a nije moguće kreirati, menjati ili brisati datoteke.

Pored toga, ako datoteka sadrži prošireni **atribut** **`com.apple.rootless`**, ta datoteka će takođe biti **zaštićena pomoću SIP-a**.

> [!TIP]
> Imajte na umu da **Sandbox** hook **`hook_vnode_check_setextattr`** sprečava svaki pokušaj izmene proširenog atributa **`com.apple.rootless`.**

**SIP takođe ograničava druge root radnje**, kao što su:

- Učitavanje nepouzdanih kernel ekstenzija
- Dobijanje task-portova za procese koje je potpisao Apple
- Izmena NVRAM promenljivih
- Omogućavanje kernel debugging-a

Opcije se čuvaju u nvram promenljivoj kao bitflag (`csr-active-config` na Intel-u, dok se `lp-sip0` učitava iz pokrenutog Device Tree-a za ARM). Zastavice možete pronaći u izvornom kodu XNU-a, u datoteci `csr.sh`:

<figure><img src="../../../images/image (1192).png" alt=""><figcaption></figcaption></figure>

### Status SIP-a

Možete proveriti da li je SIP omogućen na vašem sistemu pomoću sledeće komande:
```bash
csrutil status
```
Ako je potrebno da onemogućite SIP, morate ponovo pokrenuti računar u recovery mode-u (pritiskom na Command+R tokom pokretanja), a zatim izvršiti sledeću komandu:
```bash
csrutil disable
```
Ako želite da SIP ostane omogućen, ali da uklonite debugging zaštite, to možete učiniti pomoću:
```bash
csrutil enable --without debug
```
### Ostala ograničenja

- **Onemogućava učitavanje unsigned kernel extensions** (kexts), čime se osigurava da samo verified extensions mogu da komuniciraju sa system kernel.
- **Sprečava debugging** macOS system processes, štiteći osnovne system components od unauthorized access i modification.
- **Onemogućava tools** poput dtrace da inspectuju system processes, dodatno štiteći integritet rada sistema.

[**Learn more about SIP info in this talk**](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)**.**<sup>[[1]](#references)</sup>

### **SIP related Entitlements**

- `com.apple.rootless.xpc.bootstrap`: Control launchd
- `com.apple.rootless.install[.heritable]`: Access file system
- `com.apple.rootless.kext-management`: `kext_request`
- `com.apple.rootless.datavault.controller`: Manage UF_DATAVAULT
- `com.apple.rootless.xpc.bootstrap`: XPC setup capabilities
- `com.apple.rootless.xpc.effective-root`: Root via launchd XPC
- `com.apple.rootless.restricted-block-devices`: Access to raw block devices
- `com.apple.rootless.internal.installer-equivalent`: Unfettered filesystem access
- `com.apple.rootless.restricted-nvram-variables[.heritable]`: Full access to NVRAM
- `com.apple.rootless.storage.label`: Modify files restricted by com.apple.rootless xattr with the corresponding label
- `com.apple.rootless.volume.VM.label`: Maintain VM swap on volume

## SIP Bypasses

Bypassing SIP omogućava attackeru da:

- **Access User Data**: Čita sensitive user data poput mailova, messages i Safari history iz svih user accounts.
- **TCC Bypass**: Direktno manipuliše TCC (Transparency, Consent, and Control) bazom podataka kako bi dobio unauthorized access web kameri, microphoneu i drugim resources.
- **Establish Persistence**: Postavi malware na SIP-protected locations, čineći ga otpornim na removal, čak i uz root privileges. Ovo takođe uključuje potencijal za tampering sa Malware Removal Tool (MRT).
- **Load Kernel Extensions**: Iako postoje dodatne safeguards, bypassing SIP pojednostavljuje proces učitavanja unsigned kernel extensions.

### Installer Packages

**Installer packages potpisani Apple certificateom** mogu da zaobiđu njegove protections. To znači da će čak i packages potpisani od strane standard developers biti blokirani ako pokušaju da modifikuju SIP-protected directories.

### Inexistent SIP file

Jedna potencijalna loophole je da, ako je file naveden u **`rootless.conf`, ali trenutno ne postoji**, može biti kreiran. Malware bi mogao da ovo iskoristi za **establish persistence** na sistemu. Na primer, malicious program bi mogao da kreira .plist file u `/System/Library/LaunchDaemons` ako je naveden u `rootless.conf`, ali nije prisutan.

### com.apple.rootless.install.heritable

> [!CAUTION]
> Entitlement **`com.apple.rootless.install.heritable`** omogućava bypass SIP-a

#### [CVE-2019-8561](https://objective-see.org/blog/blog_0x42.html) <a href="#cve" id="cve"></a>

Otkriveno je da je bilo moguće **zameniti installer package nakon što je sistem verifikovao njegov code** signature, nakon čega bi sistem instalirao malicious package umesto originalnog. Pošto je ove radnje izvršavao **`system_installd`**, to je omogućavalo bypass SIP-a.<sup>[[2]](#references)</sup>

#### [CVE-2020–9854](https://objective-see.org/blog/blog_0x4D.html) <a href="#cve-unauthd-chain" id="cve-unauthd-chain"></a>

Ako je package instaliran sa mounted imagea ili external drivea, **installer** bi **izvršio** binary iz **tog file systema** (umesto iz SIP protected location), čime bi **`system_installd`** izvršio arbitrary binary.<sup>[[3]](#references)</sup>

#### CVE-2021-30892 - Shrootless

[**Researchers from this blog post**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/) otkrili su vulnerability u macOS-ovom System Integrity Protection (SIP) mehanizmu, nazvanu „Shrootless“ vulnerability. Ova vulnerability se fokusira na **`system_installd`** daemon, koji ima entitlement **`com.apple.rootless.install.heritable`**, što omogućava svim njegovim child processes da zaobiđu SIP-ova file system restrictions.<sup>[[4]](#references)</sup>

**`system_installd`** daemon će instalirati packages koje je potpisao **Apple**.

Researchers su otkrili da tokom instalacije Apple-signed packagea (.pkg file), **`system_installd`** **pokreće** sve **post-install** scripts uključene u package. Ovi scripts se izvršavaju pomoću default shell-a, **`zsh`**, koji automatski **pokreće** commands iz filea **`/etc/zshenv`**, ako on postoji, čak i u non-interactive modeu. Ovo ponašanje mogli su da iskoriste attackers: kreiranjem malicious `/etc/zshenv` filea i čekanjem da **`system_installd` pozove `zsh`**, mogli su da izvrše arbitrary operations na uređaju.<sup>[[4]](#references)</sup>

Pored toga, otkriveno je da je **`/etc/zshenv` mogao da se koristi kao general attack technique**, a ne samo za SIP bypass. Svaki user profile ima `~/.zshenv` file, koji se ponaša na isti način kao `/etc/zshenv`, ali ne zahteva root permissions. Ovaj file mogao je da se koristi kao persistence mechanism, koji se aktivira svaki put kada se `zsh` pokrene, ili kao elevation of privilege mechanism. Ako admin user elevira na root pomoću `sudo -s` ili `sudo <command>`, `~/.zshenv` file bi se aktivirao i efektivno omogućio elevation na root.<sup>[[4]](#references)</sup>

#### [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)

U [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/) otkriveno je da je isti **`system_installd`** process i dalje mogao da se abuseuje, jer je stavljao **post-install script u folder sa random imenom, zaštićen SIP-om, unutar `/tmp`**. Problem je u tome što **`/tmp` sam po sebi nije zaštićen SIP-om**, pa je bilo moguće **mountovati** **virtual image na njega**, nakon čega bi **installer** tamo stavio **post-install script**, **unmountovao** virtual image, **ponovo kreirao** sve **foldere** i **dodao** **post-installation** script sa **payloadom** koji treba izvršiti.<sup>[[5]](#references)</sup>

#### [fsck_cs utility](https://www.theregister.com/2016/03/30/apple_os_x_rootless/)

Identifikovana je vulnerability u kojoj je **`fsck_cs`** bio naveden na pogrešan trag i nateran da korumpira ključni file, zbog svoje sposobnosti da prati **symbolic links**. Konkretno, attackers su kreirali link sa _`/dev/diskX`_ ka fileu `/System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist`. Izvršavanje **`fsck_cs`** nad _`/dev/diskX`_ dovodilo je do korupcije `Info.plist` filea. Integritet ovog filea od ključne je važnosti za operativni sistemski SIP (System Integrity Protection), koji kontroliše učitavanje kernel extensions. Nakon korupcije, SIP-ova sposobnost upravljanja kernel exclusions bila je ugrožena.<sup>[[6]](#references)</sup>

Commands za exploitovanje ove vulnerability su:
```bash
ln -s /System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist /dev/diskX
fsck_cs /dev/diskX 1>&-
touch /Library/Extensions/
reboot
```
Iskorišćavanje ove ranjivosti ima ozbiljne posledice. Datoteka `Info.plist`, koja je obično zadužena za upravljanje dozvolama za kernel extensions, postaje neefikasna. To uključuje nemogućnost stavljanja određenih extensions na blacklistu, kao što je `AppleHWAccess.kext`. Posledično, pošto je kontrolni mehanizam SIP-a van funkcije, ovaj extension može da se učita, čime se dobija neovlašćen pristup za čitanje i upis u RAM sistema.<sup>[[6]](#references)</sup>

#### [Montiranje preko SIP zaštićenih fascikli](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)

Bilo je moguće montirati novi file system preko **SIP zaštićenih fascikli radi zaobilaženja zaštite**.<sup>[[1]](#references)</sup>
```bash
mkdir evil
# Add contento to the folder
hdiutil create -srcfolder evil evil.dmg
hdiutil attach -mountpoint /System/Library/Snadbox/ evil.dmg
```
#### [Upgrader bypass (2016)](https://objective-see.org/blog/blog_0x14.html)

Sistem je podešen da se pokrene sa ugrađene slike instalacionog diska unutar aplikacije `Install macOS Sierra.app` radi nadogradnje operativnog sistema, koristeći uslužni program `bless`. Korišćena komanda je sledeća:<sup>[[7]](#references)</sup>
```bash
/usr/sbin/bless -setBoot -folder /Volumes/Macintosh HD/macOS Install Data -bootefi /Volumes/Macintosh HD/macOS Install Data/boot.efi -options config="\macOS Install Data\com.apple.Boot" -label macOS Installer
```
Bezbednost ovog procesa može biti kompromitovana ako napadač izmeni upgrade image (`InstallESD.dmg`) pre bootovanja. Strategija podrazumeva zamenu dynamic loader-a (dyld) zlonamernom verzijom (`libBaseIA.dylib`). Ova zamena dovodi do izvršavanja napadačevog koda kada se pokrene installer.<sup>[[7]](#references)</sup>

Napadačev kod dobija kontrolu tokom procesa upgrade-a, iskorišćavajući poverenje sistema u installer. Napad se izvodi izmenom image-a `InstallESD.dmg` putem method swizzling-a, posebno ciljanjem metode `extractBootBits`. To omogućava ubacivanje zlonamernog koda pre upotrebe disk image-a.<sup>[[7]](#references)</sup>

Pored toga, unutar `InstallESD.dmg` nalazi se `BaseSystem.dmg`, koji služi kao root file system upgrade koda. Ubacivanje dynamic library-ja u njega omogućava zlonamernom kodu da radi unutar procesa sposobnog da menja fajlove na nivou OS-a, čime se potencijal za kompromitovanje sistema značajno povećava.<sup>[[7]](#references)</sup>

#### [systemmigrationd (2023)](https://www.youtube.com/watch?v=zxZesAN-TEk)

U ovom predavanju sa konferencije [**DEF CON 31**](https://www.youtube.com/watch?v=zxZesAN-TEk) prikazano je kako **`systemmigrationd`** (koji može da zaobiđe SIP) izvršava **bash** i **perl** script, koji se mogu zloupotrebiti putem env varijabli **`BASH_ENV`** i **`PERL5OPT`**.<sup>[[8]](#references)</sup>

#### CVE-2023-42860 <a href="#cve-a-detailed-look" id="cve-a-detailed-look"></a>

Kao što je [**detaljno opisano u ovom blog postu**](https://blog.kandji.io/apple-mitigates-vulnerabilities-installer-scripts), `postinstall` script iz `InstallAssistant.pkg` paketa omogućavao je izvršavanje:<sup>[[9]](#references)</sup>
```bash
/usr/bin/chflags -h norestricted "${SHARED_SUPPORT_PATH}/SharedSupport.dmg"
```
i bilo je moguće kreirati simboličku vezu u `${SHARED_SUPPORT_PATH}/SharedSupport.dmg` koja bi korisniku omogućila da **ukloni ograničenja za bilo koju datoteku, zaobilazeći SIP zaštitu**.<sup>[[9]](#references)</sup>

### **com.apple.rootless.install**

> [!CAUTION]
> Entitlement **`com.apple.rootless.install`** omogućava zaobilaženje SIP-a

Poznato je da entitlement `com.apple.rootless.install` omogućava zaobilaženje System Integrity Protection-a (SIP) na macOS-u. Ovo je posebno pomenuto u vezi sa [**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/).<sup>[[10]](#references)</sup>

U ovom konkretnom slučaju, sistemski XPC servis koji se nalazi na `/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc` poseduje ovaj entitlement. To povezanom procesu omogućava da zaobiđe SIP ograničenja. Pored toga, ovaj servis ima metod koji omogućava premeštanje datoteka bez primene bilo kakvih bezbednosnih mera.<sup>[[10]](#references)</sup>

## Zapečaćeni sistemski snapshot-i

Zapečaćeni sistemski snapshot-i su funkcija koju je Apple uveo u **macOS Big Sur (macOS 11)** kao deo svog mehanizma **System Integrity Protection (SIP)**, kako bi obezbedio dodatni sloj bezbednosti i stabilnosti sistema. Oni su u suštini verzije sistemskog volumena koje su samo za čitanje.

Detaljniji pregled:

1. **Nepromenljivi sistem**: Zapečaćeni sistemski snapshot-i čine macOS sistemski volumen „nepromenljivim“, što znači da se ne može menjati. Ovo sprečava neovlašćene ili slučajne izmene sistema koje bi mogle ugroziti bezbednost ili stabilnost sistema.
2. **Ažuriranja sistemskog softvera**: Kada instalirate macOS ažuriranja ili nadogradnje, macOS kreira novi sistemski snapshot. macOS startup volumen zatim koristi **APFS (Apple File System)** za prebacivanje na ovaj novi snapshot. Ceo proces primene ažuriranja postaje bezbedniji i pouzdaniji, jer sistem uvek može da se vrati na prethodni snapshot ako tokom ažuriranja nešto pođe po zlu.
3. **Razdvajanje podataka**: U kombinaciji sa konceptom razdvajanja Data i System volumena, uvedenim u macOS Catalina, funkcija zapečaćenog sistemskog snapshot-a obezbeđuje da se svi vaši podaci i podešavanja čuvaju na zasebnom "**Data**" volumenu. Ovo razdvajanje čini vaše podatke nezavisnim od sistema, što pojednostavljuje proces ažuriranja sistema i poboljšava bezbednost sistema.

Imajte na umu da macOS automatski upravlja ovim snapshot-ima i da oni ne zauzimaju dodatni prostor na disku, zahvaljujući mogućnostima deljenja prostora sistema APFS. Takođe je važno napomenuti da se ovi snapshot-i razlikuju od **Time Machine snapshot-a**, koji predstavljaju korisniku dostupne rezervne kopije celog sistema.

### Provera snapshot-a

Komanda **`diskutil apfs list`** prikazuje **detalje APFS volumena** i njihov raspored:

<pre><code>+-- Container disk3 966B902E-EDBA-4775-B743-CF97A0556A13
|   ====================================================
|   APFS Container Reference:     disk3
|   Size (Capacity Ceiling):      494384795648 B (494.4 GB)
|   Capacity In Use By Volumes:   219214536704 B (219.2 GB) (44.3% used)
|   Capacity Not Allocated:       275170258944 B (275.2 GB) (55.7% free)
|   |
|   +-< Physical Store disk0s2 86D4B7EC-6FA5-4042-93A7-D3766A222EBE
|   |   -----------------------------------------------------------
|   |   APFS Physical Store Disk:   disk0s2
|   |   Size:                       494384795648 B (494.4 GB)
|   |
|   +-> Volume disk3s1 7A27E734-880F-4D91-A703-FB55861D49B7
|   |   ---------------------------------------------------
<strong>|   |   APFS Volume Disk (Role):   disk3s1 (System)
</strong>|   |   Name:                      Macintosh HD (Case-insensitive)
<strong>|   |   Mount Point:               /System/Volumes/Update/mnt1
</strong>|   |   Capacity Consumed:         12819210240 B (12.8 GB)
|   |   Sealed:                    Broken
|   |   FileVault:                 Yes (Unlocked)
|   |   Encrypted:                 No
|   |   |
|   |   Snapshot:                  FAA23E0C-791C-43FF-B0E7-0E1C0810AC61
|   |   Snapshot Disk:             disk3s1s1
<strong>|   |   Snapshot Mount Point:      /
</strong><strong>|   |   Snapshot Sealed:           Yes
</strong>[...]
+-> Volume disk3s5 281959B7-07A1-4940-BDDF-6419360F3327
|   ---------------------------------------------------
|   APFS Volume Disk (Role):   disk3s5 (Data)
|   Name:                      Macintosh HD - Data (Case-insensitive)
<strong>    |   Mount Point:               /System/Volumes/Data
</strong><strong>    |   Capacity Consumed:         412071784448 B (412.1 GB)
</strong>    |   Sealed:                    No
|   FileVault:                 Yes (Unlocked)
</code></pre>

U prethodnom izlazu moguće je videti da se **lokacije dostupne korisniku** montiraju pod `/System/Volumes/Data`.

Pored toga, **snapshot macOS sistemskog volumena** montiran je u `/` i **zapečaćen** je (kriptografski potpisan od strane OS-a). Dakle, ako se SIP zaobiđe i on se izmeni, **OS se više neće pokrenuti**.

Takođe je moguće **proveriti da li je seal omogućen** pokretanjem:
```bash
csrutil authenticated-root status
Authenticated Root status: enabled
```
Štaviše, disk snapshot-a je takođe montiran kao **samo za čitanje**:
```bash
mount
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
```
## Reference

- [1] [SyScan360 - Stefan Esser - OS X El Capitan potapa S\H/IP](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)
- [2] [CVE-2019-8561 - Objective-See Blog](https://objective-see.org/blog/blog_0x42.html)
- [3] [CVE-2020–9854: „Unauthd“ (three) logic bugs ftw! - Objective-See Blog](https://objective-see.org/blog/blog_0x4D.html)
- [4] [Microsoft pronalazi novu macOS ranjivost, Shrootless, koja može zaobići System Integrity Protection](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)
- [5] [Technical Analysis: CVE-2022-22583 - Perception Point](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)
- [6] [Apple-ova fruitless rootless bezbednost probijena kodom koji staje u jedan tweet - The Register](https://www.theregister.com/2016/03/30/apple_os_x_rootless/)
- [7] [\[0day\] Zaobilaženje Apple-ovog System Integrity Protection - Objective-See Blog](https://objective-see.org/blog/blog_0x14.html)
- [8] [DEF CON 31 - Kako dobiti migrenu - Unique SIP Bypass on MacOS - Or, Pearse, Bohra](https://www.youtube.com/watch?v=zxZesAN-TEk)
- [9] [Apple ublažava ranjivosti u Installer Scripts - Kandji Blog](https://blog.kandji.io/apple-mitigates-vulnerabilities-installer-scripts)
- [10] [CVE-2022-26712: POC za SIP-Bypass može da stane čak i u tweet](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/)

{{#include ../../../banners/hacktricks-training.md}}
