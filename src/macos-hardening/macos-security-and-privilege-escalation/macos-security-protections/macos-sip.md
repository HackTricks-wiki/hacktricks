# macOS SIP

{{#include ../../../banners/hacktricks-training.md}}

## **Osnovne informacije**

**System Integrity Protection (SIP)** u macOS-u je mehanizam osmišljen da spreči čak i najprivilegovanije korisnike da izvršavaju neovlašćene izmene u ključnim sistemskim fasciklama. Ova funkcija ima ključnu ulogu u očuvanju integriteta sistema tako što ograničava radnje poput dodavanja, menjanja ili brisanja fajlova u zaštićenim oblastima. Glavne fascikle koje SIP štiti uključuju:

- **/System**
- **/bin**
- **/sbin**
- **/usr**

Pravila koja određuju ponašanje SIP-a definisana su u konfiguracionom fajlu koji se nalazi na putanji **`/System/Library/Sandbox/rootless.conf`**. U ovom fajlu putanje kojima prethodi zvezdica (\*) označavaju izuzetke od inače strogih SIP ograničenja.

Razmotrite primer u nastavku:
```javascript
/usr
* /usr/libexec/cups
* /usr/local
* /usr/share/man
```
Ovaj isečak ukazuje na to da, iako SIP uglavnom štiti direktorijum **`/usr`**, postoje određeni poddirektorijumi (`/usr/libexec/cups`, `/usr/local` i `/usr/share/man`) u kojima su izmene dozvoljene, što je označeno zvezdicom (\*) ispred njihovih putanja.

Da biste proverili da li je direktorijum ili datoteka zaštićena funkcijom SIP, možete koristiti komandu **`ls -lOd`** i proveriti prisustvo oznake **`restricted`** ili **`sunlnk`**. Na primer:
```bash
ls -lOd /usr/libexec/cups
drwxr-xr-x  11 root  wheel  sunlnk 352 May 13 00:29 /usr/libexec/cups
```
U ovom slučaju, zastavica **`sunlnk`** označava da direktorijum `/usr/libexec/cups` **ne može biti obrisan**, iako datoteke unutar njega mogu biti kreirane, menjane ili brisane.

S druge strane:
```bash
ls -lOd /usr/libexec
drwxr-xr-x  338 root  wheel  restricted 10816 May 13 00:29 /usr/libexec
```
Ovde oznaka **`restricted`** ukazuje na to da je direktorijum `/usr/libexec` zaštićen pomoću SIP-a. U direktorijumu zaštićenom SIP-om nije moguće kreirati, menjati niti brisati datoteke.

Pored toga, ako datoteka sadrži prošireni **attribute** **`com.apple.rootless`**, ta datoteka će takođe biti **zaštićena SIP-om**.

> [!TIP]
> Imajte na umu da **Sandbox** hook **`hook_vnode_check_setextattr`** sprečava svaki pokušaj izmene proširenog atributa **`com.apple.rootless`.**

**SIP takođe ograničava druge root radnje**, kao što su:

- Učitavanje nepouzdanih kernel ekstenzija
- Dobijanje task-portova za procese koje je potpisao Apple
- Menjanje NVRAM promenljivih
- Omogućavanje kernel debugging-a

Opcije se održavaju u nvram promenljivoj kao bitflag (`csr-active-config` na Intel-u, dok se `lp-sip0` čita iz pokrenutog Device Tree-a na ARM-u). Flag-ove možete pronaći u XNU izvornom kodu u datoteci `csr.sh`:

<figure><img src="../../../images/image (1192).png" alt=""><figcaption></figcaption></figure>

### Status SIP-a

Da biste proverili da li je SIP omogućen na vašem sistemu, upotrebite sledeću komandu:
```bash
csrutil status
```
Ako je potrebno da onemogućite SIP, morate ponovo pokrenuti računar u recovery mode-u (pritiskom na Command+R tokom pokretanja), a zatim izvršiti sledeću komandu:
```bash
csrutil disable
```
Ako želite da zadržite SIP omogućenim, ali uklonite debugging zaštite, to možete učiniti pomoću:
```bash
csrutil enable --without debug
```
### Ostala ograničenja

- **Onemogućava učitavanje nepotpisanih kernel extensions** (kexts), čime se osigurava da samo verifikovane ekstenzije mogu da komuniciraju sa sistemskim kernelom.
- **Sprečava debugging** macOS sistemskih procesa, štiteći osnovne sistemske komponente od neovlašćenog pristupa i izmena.
- **Onemogućava alatima** kao što je dtrace da pregledaju sistemske procese, dodatno štiteći integritet rada sistema.

[**Saznajte više o SIP informacijama u ovom predavanju**](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)**.**<sup>[[1]](#references)</sup>

### **Entitlements povezani sa SIP-om**

- `com.apple.rootless.xpc.bootstrap`: Kontrola launchd-a
- `com.apple.rootless.install[.heritable]`: Pristup file systemu
- `com.apple.rootless.kext-management`: `kext_request`
- `com.apple.rootless.datavault.controller`: Upravljanje UF_DATAVAULT
- `com.apple.rootless.xpc.bootstrap`: Mogućnosti XPC podešavanja
- `com.apple.rootless.xpc.effective-root`: Root putem launchd XPC-a
- `com.apple.rootless.restricted-block-devices`: Pristup sirovim block uređajima
- `com.apple.rootless.internal.installer-equivalent`: Neograničen pristup file systemu
- `com.apple.rootless.restricted-nvram-variables[.heritable]`: Potpun pristup NVRAM-u
- `com.apple.rootless.storage.label`: Izmena fajlova ograničenih pomoću com.apple.rootless xattr-a sa odgovarajućom oznakom
- `com.apple.rootless.volume.VM.label`: Održavanje VM swap-a na volume-u

## SIP Bypasses

Zaobilaženje SIP-a napadaču omogućava da:

- **Pristupi korisničkim podacima**: Čita osetljive korisničke podatke, kao što su pošta, poruke i Safari istorija sa svih korisničkih naloga.
- **TCC Bypass**: Direktno manipuliše TCC (Transparency, Consent, and Control) bazom podataka kako bi dodelio neovlašćen pristup web kameri, mikrofonu i drugim resursima.
- **Uspostavi persistence**: Postavi malware na lokacije zaštićene SIP-om, čime se otežava njegovo uklanjanje, čak i uz root privilegije. Ovo takođe uključuje mogućnost neovlašćenih izmena Malware Removal Tool-a (MRT).
- **Učita Kernel Extensions**: Iako postoje dodatne zaštite, zaobilaženje SIP-a pojednostavljuje proces učitavanja nepotpisanih kernel extensions.

### Installer Packages

**Installer packages potpisani Apple sertifikatom** mogu da zaobiđu njegove zaštite. To znači da će čak i packages potpisani od strane standardnih developera biti blokirani ako pokušaju da izmene direktorijume zaštićene SIP-om.

### Nepostojeći SIP fajl

Jedna potencijalna slabost je to što, ako je fajl naveden u **`rootless.conf`, ali trenutno ne postoji**, može biti kreiran. Malware bi ovo mogao da iskoristi za **uspostavljanje persistence** na sistemu. Na primer, maliciozni program mogao bi da kreira .plist fajl u `/System/Library/LaunchDaemons` ako je on naveden u `rootless.conf`, ali ne postoji.

### com.apple.rootless.install.heritable

> [!CAUTION]
> Entitlement **`com.apple.rootless.install.heritable`** omogućava zaobilaženje SIP-a

#### [CVE-2019-8561](https://objective-see.org/blog/blog_0x42.html) <a href="#cve" id="cve"></a>

Otkriveno je da je bilo moguće **zameniti installer package nakon što je sistem verifikovao njegov code** potpis, nakon čega bi sistem instalirao maliciozni package umesto originalnog. Pošto je ove radnje izvršavao **`system_installd`**, to je omogućavalo zaobilaženje SIP-a.<sup>[[2]](#references)</sup>

#### [CVE-2020–9854](https://objective-see.org/blog/blog_0x4D.html) <a href="#cve-unauthd-chain" id="cve-unauthd-chain"></a>

Ako je package instaliran sa mounted image-a ili spoljnog diska, **installer** bi **izvršavao** binary sa **tog file systema** (umesto sa lokacije zaštićene SIP-om), omogućavajući da **`system_installd`** izvrši proizvoljni binary.<sup>[[3]](#references)</sup>

#### CVE-2021-30892 - Shrootless

[**Istraživači iz ovog blog posta**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/) otkrili su ranjivost u mehanizmu macOS System Integrity Protection (SIP), nazvanu ranjivost „Shrootless“. Ova ranjivost se odnosi na daemon **`system_installd`**, koji poseduje entitlement **`com.apple.rootless.install.heritable`**, što omogućava svakom njegovom child procesu da zaobiđe SIP ograničenja file systema.<sup>[[4]](#references)</sup>

Daemon **`system_installd`** instalira packages koje je potpisao **Apple**.

Istraživači su otkrili da tokom instalacije Apple-potpisanog package-a (.pkg fajla), **`system_installd`** **pokreće** sve **post-install** skripte uključene u package. Ove skripte izvršava podrazumevani shell, **`zsh`**, koji automatski **pokreće** komande iz fajla **`/etc/zshenv`**, ako on postoji, čak i u non-interactive režimu. Napadači bi mogli da iskoriste ovo ponašanje tako što bi kreirali maliciozni fajl `/etc/zshenv` i sačekali da **`system_installd` pozove `zsh`**, čime bi mogli da izvrše proizvoljne operacije na uređaju.<sup>[[4]](#references)</sup>

Pored toga, otkriveno je da se **`/etc/zshenv` može koristiti kao opšta attack tehnika**, a ne samo za SIP bypass. Svaki korisnički profil ima fajl `~/.zshenv`, koji se ponaša na isti način kao `/etc/zshenv`, ali ne zahteva root permissions. Ovaj fajl može da se koristi kao persistence mehanizam, koji se aktivira svaki put kada se `zsh` pokrene, ili kao mehanizam za privilege escalation. Ako admin korisnik dobije root putem `sudo -s` ili `sudo <command>`, fajl `~/.zshenv` bi se aktivirao i efektivno omogućio root privilegije.<sup>[[4]](#references)</sup>

#### [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)

U [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/) otkriveno je da je isti proces **`system_installd`** i dalje mogao da bude zloupotrebljen, jer je stavljao **post-install script u folder sa nasumičnim imenom, zaštićen SIP-om, unutar `/tmp`**. Problem je u tome što **sam `/tmp` nije zaštićen SIP-om**, pa je bilo moguće **mountovati** **virtual image na njega**, nakon čega bi **installer** tamo smestio **post-install script**, **unmountovao** virtual image, **ponovo kreirao** sve **foldere** i **dodao** **post-installation** script sa **payloadom** za izvršavanje.<sup>[[5]](#references)</sup>

#### [fsck_cs utility](https://www.theregister.com/2016/03/30/apple_os_x_rootless/)

Identifikovana je ranjivost u kojoj je **`fsck_cs`** naveden na pogrešan trag i naveđen da korumpira ključni fajl, zbog mogućnosti praćenja **symbolic links**. Napadači su konkretno kreirali link sa _`/dev/diskX`_ ka fajlu `/System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist`. Izvršavanje **`fsck_cs`** nad _`/dev/diskX`_ dovelo je do korupcije fajla `Info.plist`. Integritet ovog fajla je ključan za SIP (System Integrity Protection) operativnog sistema, koji kontroliše učitavanje kernel extensions. Nakon korupcije, sposobnost SIP-a da upravlja izuzecima kernel extensions bila je ugrožena.<sup>[[6]](#references)</sup>

Komande za iskorišćavanje ove ranjivosti su:
```bash
ln -s /System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist /dev/diskX
fsck_cs /dev/diskX 1>&-
touch /Library/Extensions/
reboot
```
Eksploatacija ove ranjivosti ima ozbiljne posledice. Datoteka `Info.plist`, koja je obično zadužena za upravljanje dozvolama za kernel extensions, postaje neefikasna. To uključuje nemogućnost stavljanja određenih extensions na blacklistu, kao što je `AppleHWAccess.kext`. Shodno tome, pošto je SIP-ov kontrolni mehanizam van funkcije, ovaj extension može da se učita, čime se dobija neovlašćen pristup za čitanje i upis u sistemsku RAM memoriju.<sup>[[6]](#references)</sup>

#### [Montiranje preko foldera zaštićenih SIP-om](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)

Bilo je moguće montirati novi fajl sistem preko **foldera zaštićenih SIP-om radi zaobilaženja zaštite**.<sup>[[1]](#references)</sup>
```bash
mkdir evil
# Add contento to the folder
hdiutil create -srcfolder evil evil.dmg
hdiutil attach -mountpoint /System/Library/Snadbox/ evil.dmg
```
#### [Upgrader bypass (2016)](https://objective-see.org/blog/blog_0x14.html)

Sistem je podešen da se pokrene sa ugrađene slike instalacionog diska unutar aplikacije `Install macOS Sierra.app` kako bi nadogradio OS, koristeći uslužni program `bless`. Korišćena komanda je sledeća:<sup>[[7]](#references)</sup>
```bash
/usr/sbin/bless -setBoot -folder /Volumes/Macintosh HD/macOS Install Data -bootefi /Volumes/Macintosh HD/macOS Install Data/boot.efi -options config="\macOS Install Data\com.apple.Boot" -label macOS Installer
```
Bezbednost ovog procesa može biti ugrožena ako napadač izmeni upgrade image (`InstallESD.dmg`) pre bootovanja. Strategija podrazumeva zamenu dynamic loader-a (dyld) zlonamernom verzijom (`libBaseIA.dylib`). Ova zamena dovodi do izvršavanja koda napadača kada se pokrene installer.<sup>[[7]](#references)</sup>

Kod napadača dobija kontrolu tokom upgrade procesa, iskorišćavajući poverenje sistema u installer. Napad se izvršava izmenom `InstallESD.dmg` image-a putem method swizzling-a, posebno ciljanjem metode `extractBootBits`. Ovo omogućava ubacivanje zlonamernog koda pre nego što se disk image upotrebi.<sup>[[7]](#references)</sup>

Pored toga, unutar `InstallESD.dmg` nalazi se `BaseSystem.dmg`, koji služi kao root file system upgrade koda. Ubacivanje dynamic library-ja u njega omogućava zlonamernom kodu da radi unutar procesa sposobnog da menja fajlove na nivou OS-a, što značajno povećava potencijal za kompromitovanje sistema.<sup>[[7]](#references)</sup>

#### [systemmigrationd (2023)](https://www.youtube.com/watch?v=zxZesAN-TEk)

U ovom predavanju sa konferencije [**DEF CON 31**](https://www.youtube.com/watch?v=zxZesAN-TEk) prikazano je kako **`systemmigrationd`** (koji može da zaobiđe SIP) izvršava **bash** i **perl** script-e, koji se mogu zloupotrebiti putem env varijabli **`BASH_ENV`** i **`PERL5OPT`**.<sup>[[8]](#references)</sup>

#### CVE-2023-42860 <a href="#cve-a-detailed-look" id="cve-a-detailed-look"></a>

Kao što je [**detaljno opisano u ovom blog postu**](https://blog.kandji.io/apple-mitigates-vulnerabilities-installer-scripts), `postinstall` script iz paketa `InstallAssistant.pkg` omogućavao je izvršavanje:<sup>[[9]](#references)</sup>
```bash
/usr/bin/chflags -h norestricted "${SHARED_SUPPORT_PATH}/SharedSupport.dmg"
```
i bilo je moguće kreirati simboličku vezu u `${SHARED_SUPPORT_PATH}/SharedSupport.dmg`, koja bi korisniku omogućila da **ukloni ograničenja sa bilo koje datoteke, zaobilazeći SIP zaštitu**.<sup>[[9]](#references)</sup>

### **com.apple.rootless.install**

> [!CAUTION]
> Entitlement **`com.apple.rootless.install`** omogućava zaobilaženje SIP-a

Poznato je da entitlement `com.apple.rootless.install` omogućava zaobilaženje System Integrity Protection-a (SIP) na macOS-u. Ovo je naročito pomenuto u vezi sa [**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/).<sup>[[10]](#references)</sup>

U ovom konkretnom slučaju, sistemski XPC servis koji se nalazi na putanji `/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc` poseduje ovaj entitlement. To povezanom procesu omogućava zaobilaženje SIP ograničenja. Pored toga, ovaj servis pruža metod koji dozvoljava premeštanje datoteka bez primene bilo kakvih bezbednosnih mera.<sup>[[10]](#references)</sup>

## Zapečaćeni sistemski snapshot-i

Zapečaćeni sistemski snapshot-i su funkcija koju je Apple uveo u **macOS Big Sur (macOS 11)** kao deo mehanizma **System Integrity Protection (SIP)**, kako bi obezbedio dodatni sloj bezbednosti i stabilnosti sistema. Oni su u suštini verzije sistemskog volumena koje su samo za čitanje.

Detaljniji pregled:

1. **Nepromjenjiv sistem**: Zapečaćeni sistemski snapshot-i čine macOS sistemski volumen „nepromenljivim“, što znači da se ne može izmeniti. Ovo sprečava neovlašćene ili slučajne promene sistema koje bi mogle ugroziti bezbednost ili stabilnost sistema.
2. **Ažuriranja sistemskog softvera**: Kada instalirate macOS ažuriranja ili nadogradnje, macOS kreira novi sistemski snapshot. macOS startup volumen zatim koristi **APFS (Apple File System)** da pređe na ovaj novi snapshot. Ceo proces primene ažuriranja postaje bezbedniji i pouzdaniji, jer sistem uvek može da se vrati na prethodni snapshot ako tokom ažuriranja nešto pođe po zlu.
3. **Razdvajanje podataka**: Zajedno sa konceptom razdvajanja Data i System volumena, uvedenim u macOS Catalina, funkcija zapečaćenog sistemskog snapshot-a obezbeđuje da se svi vaši podaci i podešavanja čuvaju na zasebnom "**Data**" volumenu. Ovo razdvajanje čini vaše podatke nezavisnim od sistema, što pojednostavljuje proces ažuriranja sistema i poboljšava bezbednost sistema.

Imajte na umu da macOS automatski upravlja ovim snapshot-ima i da oni ne zauzimaju dodatni prostor na disku, zahvaljujući mogućnostima deljenja prostora koje pruža APFS. Takođe je važno napomenuti da se ovi snapshot-i razlikuju od **Time Machine snapshot-a**, koji predstavljaju rezervne kopije celog sistema dostupne korisniku.

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
|   |   Encrypted:               No
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

U prethodnom izlazu moguće je videti da su **lokacije dostupne korisniku** montirane pod `/System/Volumes/Data`.

Pored toga, **snapshot macOS sistemskog volumena** montiran je u `/` i **zapečaćen** je (kriptografski potpisan od strane OS-a). Dakle, ako se SIP zaobiđe i izvrše izmene na njemu, **OS se više neće pokrenuti**.

Takođe je moguće **proveriti da li je pečat omogućen** pokretanjem:
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

- [1] [SyScan360 - Stefan Esser - OS X El Capitan sinking the S\H/IP](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)
- [2] [CVE-2019-8561 - Objective-See Blog](https://objective-see.org/blog/blog_0x42.html)
- [3] [CVE-2020–9854: "Unauthd" (three) logic bugs ftw! - Objective-See Blog](https://objective-see.org/blog/blog_0x4D.html)
- [4] [Microsoft pronalazi novu macOS ranjivost, Shrootless, koja bi mogla zaobići System Integrity Protection](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)
- [5] [Technical Analysis: CVE-2022-22583 - Perception Point](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)
- [6] [Apple-ova rootless bezbednost bez ploda probijena kodom koji staje u jedan tweet - The Register](https://www.theregister.com/2016/03/30/apple_os_x_rootless/)
- [7] [\[0day\] Zaobilaženje Apple-ovog System Integrity Protection-a - Objective-See Blog](https://objective-see.org/blog/blog_0x14.html)
- [8] [DEF CON 31 - Getting a Migraine - Unique SIP Bypass on MacOS - Or, Pearse, Bohra](https://www.youtube.com/watch?v=zxZesAN-TEk)
- [9] [Apple ublažava ranjivosti u Installer Scripts - Kandji Blog](https://blog.kandji.io/apple-mitigates-vulnerabilities-installer-scripts)
- [10] [CVE-2022-26712: POC za SIP-Bypass se čak može objaviti u tweet-u](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/)

{{#include ../../../banners/hacktricks-training.md}}
