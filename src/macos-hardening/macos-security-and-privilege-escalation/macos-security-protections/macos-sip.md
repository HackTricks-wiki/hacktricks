# macOS SIP

{{#include ../../../banners/hacktricks-training.md}}

## **Osnovne informacije**

**System Integrity Protection (SIP)** u macOS-u je mehanizam osmišljen da spreči čak i najprivilegovanije korisnike da izvrše neovlašćene izmene ključnih sistemskih fascikli. Ova funkcija ima ključnu ulogu u očuvanju integriteta sistema tako što ograničava radnje poput dodavanja, izmene ili brisanja datoteka u zaštićenim oblastima. Glavne fascikle zaštićene pomoću SIP-a uključuju:

- **/System**
- **/bin**
- **/sbin**
- **/usr**

Pravila koja određuju ponašanje SIP-a definisana su u konfiguracionoj datoteci koja se nalazi na putanji **`/System/Library/Sandbox/rootless.conf`**. U ovoj datoteci putanje sa prefiksom zvezdice (\*) označene su kao izuzeci od inače strogih SIP ograničenja.

Pogledajte primer u nastavku:
```javascript
/usr
* /usr/libexec/cups
* /usr/local
* /usr/share/man
```
Ovaj odlomak ukazuje na to da, iako SIP uglavnom štiti direktorijum **`/usr`**, postoje određeni poddirektorijumi (`/usr/libexec/cups`, `/usr/local` i `/usr/share/man`) u kojima su izmene dozvoljene, što je označeno zvezdicom (\*) ispred njihovih putanja.

Da biste proverili da li je direktorijum ili datoteka zaštićena SIP-om, možete koristiti komandu **`ls -lOd`** da proverite prisustvo zastavice **`restricted`** ili **`sunlnk`**. Na primer:
```bash
ls -lOd /usr/libexec/cups
drwxr-xr-x  11 root  wheel  sunlnk 352 May 13 00:29 /usr/libexec/cups
```
U ovom slučaju, oznaka **`sunlnk`** označava da sam direktorijum `/usr/libexec/cups` **ne može da se obriše**, iako se datoteke unutar njega mogu kreirati, menjati ili brisati.

S druge strane:
```bash
ls -lOd /usr/libexec
drwxr-xr-x  338 root  wheel  restricted 10816 May 13 00:29 /usr/libexec
```
Ovde zastavica **`restricted`** označava da je direktorijum `/usr/libexec` zaštićen pomoću SIP-a. U direktorijumu zaštićenom pomoću SIP-a nije moguće kreirati, menjati ili brisati datoteke.

Pored toga, ako datoteka sadrži prošireni **atribut** **`com.apple.rootless`**, ta datoteka će takođe biti **zaštićena pomoću SIP-a**.

> [!TIP]
> Imajte na umu da **Sandbox** hook **`hook_vnode_check_setextattr`** sprečava svaki pokušaj izmene proširenog atributa **`com.apple.rootless`.**

**SIP takođe ograničava druge root radnje**, kao što su:

- Učitavanje nepouzdanih kernel ekstenzija
- Dobijanje task-portova za procese potpisane od strane kompanije Apple
- Izmena NVRAM promenljivih
- Omogućavanje kernel debugging-a

Opcije se održavaju u nvram promenljivoj kao bitflag (`csr-active-config` na Intel-u, dok se `lp-sip0` čita iz pokrenutog Device Tree-a na ARM-u). Zastavice možete pronaći u izvornom kodu XNU-a, u datoteci `csr.sh`:

<figure><img src="../../../images/image (1192).png" alt=""><figcaption></figcaption></figure>

### Status SIP-a

Možete proveriti da li je SIP omogućen na vašem sistemu pomoću sledeće komande:
```bash
csrutil status
```
Ako je potrebno da onemogućite SIP, morate ponovo pokrenuti računar u recovery mode (pritiskom na Command+R tokom pokretanja), a zatim izvršiti sledeću komandu:
```bash
csrutil disable
```
Ako želite da SIP ostane omogućen, ali da uklonite debugging zaštite, to možete učiniti pomoću:
```bash
csrutil enable --without debug
```
### Ostala ograničenja

- **Onemogućava učitavanje nepotpisanih kernel ekstenzija** (kexts), čime se obezbeđuje da samo verifikovane ekstenzije stupaju u interakciju sa sistemskim kernelom.
- **Sprečava debugging** macOS sistemskih procesa, štiteći osnovne sistemske komponente od neovlašćenog pristupa i izmena.
- **Onemogućava alatima** kao što je dtrace da analiziraju sistemske procese, dodatno štiteći integritet rada sistema.

[**Saznajte više o SIP informacijama u ovom predavanju**](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)**.**<sup>[1]</sup>

### **Entitlements povezani sa SIP-om**

- `com.apple.rootless.xpc.bootstrap`: Kontrola launchd-a
- `com.apple.rootless.install[.heritable]`: Pristup sistemu datoteka
- `com.apple.rootless.kext-management`: `kext_request`
- `com.apple.rootless.datavault.controller`: Upravljanje UF_DATAVAULT-om
- `com.apple.rootless.xpc.bootstrap`: Mogućnosti XPC podešavanja
- `com.apple.rootless.xpc.effective-root`: Root putem launchd XPC-a
- `com.apple.rootless.restricted-block-devices`: Pristup sirovim blok uređajima
- `com.apple.rootless.internal.installer-equivalent`: Neograničen pristup sistemu datoteka
- `com.apple.rootless.restricted-nvram-variables[.heritable]`: Potpun pristup NVRAM-u
- `com.apple.rootless.storage.label`: Izmena datoteka ograničenih pomoću com.apple.rootless xattr-a sa odgovarajućom oznakom
- `com.apple.rootless.volume.VM.label`: Održavanje VM swap-a na volumenu

## SIP Bypasses

Zaobilaženje SIP-a omogućava napadaču da:

- **Pristupi korisničkim podacima**: Čita osetljive korisničke podatke, kao što su pošta, poruke i Safari istorija, sa svih korisničkih naloga.
- **TCC Bypass**: Direktno menja TCC (Transparency, Consent, and Control) bazu podataka kako bi dodelio neovlašćen pristup web kameri, mikrofonu i drugim resursima.
- **Uspostavi Persistence**: Postavi malware na lokacije zaštićene SIP-om, čineći ga otpornim na uklanjanje, čak i uz root privilegije. Ovo uključuje i mogućnost menjanja Malware Removal Tool-a (MRT).
- **Učita Kernel Extensions**: Iako postoje dodatne zaštite, zaobilaženje SIP-a pojednostavljuje učitavanje nepotpisanih kernel ekstenzija.

### Instalacioni paketi

**Instalacioni paketi potpisani Apple sertifikatom** mogu zaobići njegove zaštite. To znači da će čak i paketi potpisani od strane standardnih developera biti blokirani ako pokušaju da izmene direktorijume zaštićene SIP-om.

### Neegzistentna SIP datoteka

Jedna potencijalna ranjivost postoji ako je datoteka navedena u **`rootless.conf`, ali trenutno ne postoji** — tada može biti kreirana. Malware bi ovo mogao da iskoristi za **uspostavljanje persistence-a** na sistemu. Na primer, zlonamerni program mogao bi da kreira .plist datoteku u `/System/Library/LaunchDaemons` ako je navedena u `rootless.conf`, ali nije prisutna.

### com.apple.rootless.install.heritable

> [!CAUTION]
> Entitlement **`com.apple.rootless.install.heritable`** omogućava zaobilaženje SIP-a

#### [CVE-2019-8561](https://objective-see.org/blog/blog_0x42.html) <a href="#cve" id="cve"></a>

Otkriveno je da je bilo moguće **zameniti instalacioni paket nakon što je sistem verifikovao njegov code** potpis, nakon čega bi sistem instalirao zlonamerni paket umesto originalnog. Pošto je ove radnje obavljao **`system_installd`**, to je omogućavalo zaobilaženje SIP-a.<sup>[2]</sup>

#### [CVE-2020–9854](https://objective-see.org/blog/blog_0x4D.html) <a href="#cve-unauthd-chain" id="cve-unauthd-chain"></a>

Ako je paket instaliran sa montirane slike ili eksternog diska, **installer** bi **izvršio** binarni fajl sa **tog sistema datoteka** (umesto sa lokacije zaštićene SIP-om), čime bi **`system_installd`** izvršio proizvoljni binarni fajl.<sup>[3]</sup>

#### CVE-2021-30892 - Shrootless

[**Istraživači iz ovog blog posta**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/) otkrili su ranjivost u mehanizmu System Integrity Protection (SIP) sistema macOS, nazvanu ranjivost „Shrootless“. Ova ranjivost je povezana sa daemon-om **`system_installd`**, koji poseduje entitlement **`com.apple.rootless.install.heritable`**, što omogućava svim njegovim child procesima da zaobiđu ograničenja sistema datoteka koje nameće SIP.<sup>[4]</sup>

Daemon **`system_installd`** instalira pakete koje je potpisao **Apple**.

Istraživači su otkrili da tokom instalacije Apple-potpisanog paketa (.pkg datoteke), **`system_installd`** **pokreće** sve **post-install** skripte uključene u paket. Ove skripte izvršava podrazumevani shell, **`zsh`**, koji automatski **pokreće** komande iz datoteke **`/etc/zshenv`**, ako ona postoji, čak i u non-interactive režimu. Napadači bi mogli da iskoriste ovo ponašanje tako što bi kreirali zlonamernu datoteku `/etc/zshenv` i sačekali da **`system_installd` pozove `zsh`**, čime bi mogli da izvrše proizvoljne radnje na uređaju.<sup>[4]</sup>

Pored toga, otkriveno je da se **`/etc/zshenv` može koristiti kao opšta attack tehnika**, a ne samo za SIP bypass. Svaki korisnički profil ima datoteku `~/.zshenv`, koja se ponaša isto kao `/etc/zshenv`, ali ne zahteva root dozvole. Ova datoteka može da se koristi kao persistence mehanizam, koji se aktivira svaki put kada se pokrene `zsh`, ili kao mehanizam za elevation of privilege. Ako admin korisnik dobije root koristeći `sudo -s` ili `sudo <command>`, datoteka `~/.zshenv` bi se aktivirala i praktično omogućila elevation do root-a.<sup>[4]</sup>

#### [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)

U tekstu o [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/) otkriveno je da je isti proces **`system_installd`** i dalje mogao da bude zloupotrebljen, jer je **post-install skriptu smeštao u nasumično imenovani direktorijum zaštićen SIP-om unutar `/tmp`**. Međutim, sam **`/tmp` nije zaštićen SIP-om**, pa je bilo moguće **montirati** **virtuelnu sliku na njega**. Zatim bi **installer** tamo smestio **post-install skriptu**, **demontirao** virtuelnu sliku, **ponovo kreirao** sve **direktorijume** i **dodao** **post-install** skriptu sa **payload-om** koji treba izvršiti.<sup>[5]</sup>

#### [fsck_cs utility](https://www.theregister.com/2016/03/30/apple_os_x_rootless/)

Identifikovana je ranjivost u kojoj je **`fsck_cs`** bio naveden na pogrešan trag i nateran da ošteti ključnu datoteku, zbog mogućnosti praćenja **symbolic linkova**. Konkretno, napadači su kreirali link od _`/dev/diskX`_ do datoteke `/System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist`. Izvršavanje **`fsck_cs`** nad _`/dev/diskX`_ dovodilo je do oštećenja `Info.plist` datoteke. Integritet ove datoteke je od ključne važnosti za SIP (System Integrity Protection) operativnog sistema, koji kontroliše učitavanje kernel ekstenzija. Kada se ošteti, SIP-ova mogućnost upravljanja izuzecima kernela biva ugrožena.<sup>[6]</sup>

Komande za iskorišćavanje ove ranjivosti su:
```bash
ln -s /System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist /dev/diskX
fsck_cs /dev/diskX 1>&-
touch /Library/Extensions/
reboot
```
Eksploatacija ove ranjivosti ima ozbiljne posledice. Datoteka `Info.plist`, koja je obično zadužena za upravljanje dozvolama za kernel ekstenzije, postaje neefikasna. To uključuje nemogućnost stavljanja određenih ekstenzija, kao što je `AppleHWAccess.kext`, na blacklistu. Shodno tome, pošto je SIP-ov mehanizam kontrole van funkcije, ova ekstenzija može da se učita, čime se dobija neovlašćen pristup za čitanje i upis u sistemski RAM.<sup>[6]</sup>

#### [Montiranje preko foldera zaštićenih SIP-om](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)

Bilo je moguće montirati novi file system preko **foldera zaštićenih SIP-om kako bi se zaobišla zaštita**.<sup>[1]</sup>
```bash
mkdir evil
# Add contento to the folder
hdiutil create -srcfolder evil evil.dmg
hdiutil attach -mountpoint /System/Library/Snadbox/ evil.dmg
```
#### [Zaobilaženje Upgrader-a (2016)](https://objective-see.org/blog/blog_0x14.html)

Sistem je podešen da se pokrene sa ugrađenog instalacionog disk image-a unutar aplikacije `Install macOS Sierra.app` kako bi nadogradio OS, koristeći uslužni program `bless`. Korišćena komanda je sledeća:<sup>[7]</sup>
```bash
/usr/sbin/bless -setBoot -folder /Volumes/Macintosh HD/macOS Install Data -bootefi /Volumes/Macintosh HD/macOS Install Data/boot.efi -options config="\macOS Install Data\com.apple.Boot" -label macOS Installer
```
Bezbednost ovog procesa može biti ugrožena ako napadač izmeni upgrade image (`InstallESD.dmg`) pre pokretanja. Strategija podrazumeva zamenu dynamic loader-a (dyld) zlonamernom verzijom (`libBaseIA.dylib`). Ova zamena dovodi do izvršavanja napadačevog koda kada se pokrene installer.<sup>[7]</sup>

Napadačev kod preuzima kontrolu tokom procesa upgrade-a, iskorišćavajući poverenje sistema u installer. Napad se sprovodi izmenom image-a `InstallESD.dmg` pomoću method swizzling-a, posebno ciljanjem metode `extractBootBits`. Ovo omogućava ubacivanje zlonamernog koda pre upotrebe disk image-a.<sup>[7]</sup>

Pored toga, unutar `InstallESD.dmg` nalazi se `BaseSystem.dmg`, koji služi kao root file system upgrade koda. Ubacivanje dynamic library-ja u njega omogućava zlonamernom kodu da radi unutar procesa koji može da menja fajlove na nivou OS-a, čime se značajno povećava mogućnost kompromitovanja sistema.<sup>[7]</sup>

#### [systemmigrationd (2023)](https://www.youtube.com/watch?v=zxZesAN-TEk)

U ovom predavanju sa konferencije [**DEF CON 31**](https://www.youtube.com/watch?v=zxZesAN-TEk) prikazano je kako **`systemmigrationd`** (koji može da zaobiđe SIP) izvršava **bash** i **perl** script-e, što se može zloupotrebiti pomoću env promenljivih **`BASH_ENV`** i **`PERL5OPT`**.<sup>[8]</sup>

#### CVE-2023-42860 <a href="#cve-a-detailed-look" id="cve-a-detailed-look"></a>

Kao što je [**detaljno opisano u ovom blog postu**](https://blog.kandji.io/apple-mitigates-vulnerabilities-installer-scripts), `postinstall` script iz paketa `InstallAssistant.pkg` mogao je da se izvršava:<sup>[9]</sup>
```bash
/usr/bin/chflags -h norestricted "${SHARED_SUPPORT_PATH}/SharedSupport.dmg"
```
i bilo je moguće kreirati symlink u `${SHARED_SUPPORT_PATH}/SharedSupport.dmg`, što bi korisniku omogućilo da **ukloni ograničenja za bilo koju datoteku i zaobiđe SIP zaštitu**.<sup>[9]</sup>

### **com.apple.rootless.install**

> [!CAUTION]
> Entitlement **`com.apple.rootless.install`** omogućava zaobilaženje SIP-a

Poznato je da entitlement `com.apple.rootless.install` omogućava zaobilaženje System Integrity Protection (SIP) na macOS-u. Ovo je posebno pomenuto u vezi sa [**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/).<sup>[10]</sup>

U ovom konkretnom slučaju, sistemski XPC servis koji se nalazi na `/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc` poseduje ovaj entitlement. To povezanom procesu omogućava zaobilaženje SIP ograničenja. Pored toga, ovaj servis sadrži metod koji omogućava premeštanje datoteka bez primene bilo kakvih bezbednosnih mera.<sup>[10]</sup>

## Zapečaćeni sistemski snapshotovi

Zapečaćeni sistemski snapshotovi su funkcija koju je Apple uveo u **macOS Big Sur (macOS 11)** kao deo mehanizma **System Integrity Protection (SIP)**, kako bi obezbedio dodatni sloj bezbednosti i stabilnosti sistema. Oni su u suštini verzije sistemskog volumena samo za čitanje.

Detaljniji pregled:

1. **Nepromeljiv sistem**: Zapečaćeni sistemski snapshotovi čine macOS sistemski volumen „nepromenjivim“, što znači da se ne može izmeniti. Time se sprečavaju neovlašćene ili slučajne promene sistema koje bi mogle ugroziti bezbednost ili stabilnost sistema.
2. **Ažuriranja sistemskog softvera**: Kada instalirate macOS ažuriranja ili nadogradnje, macOS kreira novi sistemski snapshot. macOS startup volumen zatim koristi **APFS (Apple File System)** da pređe na ovaj novi snapshot. Ceo proces primene ažuriranja postaje bezbedniji i pouzdaniji, jer sistem uvek može da se vrati na prethodni snapshot ako tokom ažuriranja nešto pođe po zlu.
3. **Razdvajanje podataka**: U kombinaciji sa konceptom razdvajanja Data i System volumena, uvedenim u macOS Catalina, funkcija zapečaćenih sistemskih snapshotova obezbeđuje da se svi vaši podaci i podešavanja čuvaju na zasebnom "**Data**" volumenu. Ovo razdvajanje čini vaše podatke nezavisnim od sistema, što pojednostavljuje proces ažuriranja sistema i poboljšava bezbednost sistema.

Imajte na umu da macOS automatski upravlja ovim snapshotovima i da oni ne zauzimaju dodatni prostor na disku, zahvaljujući mogućnostima deljenja prostora koje pruža APFS. Takođe je važno napomenuti da se ovi snapshotovi razlikuju od **Time Machine snapshotova**, koji predstavljaju korisniku dostupne rezervne kopije celog sistema.

### Provera snapshotova

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

U prethodnom izlazu moguće je videti da su **lokacije dostupne korisniku** montirane pod `/System/Volumes/Data`.

Pored toga, **snapshot macOS System volumena** montiran je u `/` i **zapečaćen** (kriptografski potpisan od strane OS-a). Dakle, ako se SIP zaobiđe i on izmeni, **OS se više neće pokrenuti**.

Takođe je moguće **proveriti da li je seal omogućen** pokretanjem:
```bash
csrutil authenticated-root status
Authenticated Root status: enabled
```
Štaviše, disk sa snapshotom je takođe montiran kao **samo za čitanje**:
```bash
mount
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
```
## Reference

- [1] [SyScan360 - Stefan Esser - OS X El Capitan potapa S\H/IP](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)
- [2] [CVE-2019-8561 - Objective-See Blog](https://objective-see.org/blog/blog_0x42.html)
- [3] [CVE-2020–9854: „Unauthd“ (tri) logičke greške ftw! - Objective-See Blog](https://objective-see.org/blog/blog_0x4D.html)
- [4] [Microsoft pronalazi novu macOS ranjivost, Shrootless, koja može zaobići System Integrity Protection](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)
- [5] [Technical Analysis: CVE-2022-22583 - Perception Point](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)
- [6] [Apple-ova fruitless rootless bezbednost probijena kodom koji staje u jedan tweet - The Register](https://www.theregister.com/2016/03/30/apple_os_x_rootless/)
- [7] [\[0day\] Zaobilaženje Apple-ovog System Integrity Protection-a - Objective-See Blog](https://objective-see.org/blog/blog_0x14.html)
- [8] [DEF CON 31 - Getting a Migraine - Unique SIP Bypass on MacOS - Or, Pearse, Bohra](https://www.youtube.com/watch?v=zxZesAN-TEk)
- [9] [Apple ublažava ranjivosti u Installer skriptama - Kandji Blog](https://blog.kandji.io/apple-mitigates-vulnerabilities-installer-scripts)
- [10] [CVE-2022-26712: POC za SIP-Bypass može da stane i u tweet](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/)

{{#include ../../../banners/hacktricks-training.md}}
