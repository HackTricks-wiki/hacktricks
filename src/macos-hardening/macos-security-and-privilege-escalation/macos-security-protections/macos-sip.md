# macOS SIP

{{#include ../../../banners/hacktricks-training.md}}

## **Osnovne Informacije**

**System Integrity Protection (SIP)** u macOS-u je mehanizam dizajniran da spreči čak i najprivilegovanije korisnike da vrše neovlašćene promene u ključnim sistemskim folderima. Ova funkcija igra ključnu ulogu u održavanju integriteta sistema ograničavanjem radnji kao što su dodavanje, modifikovanje ili brisanje datoteka u zaštićenim oblastima. Glavni folderi zaštićeni SIP-om uključuju:

- **/System**
- **/bin**
- **/sbin**
- **/usr**

Pravila koja upravljaju ponašanjem SIP-a definisana su u konfiguracionom fajlu koji se nalazi na **`/System/Library/Sandbox/rootless.conf`**. Unutar ovog fajla, putevi koji su označeni zvezdicom (\*) se smatraju izuzecima od inače strogih SIP ograničenja.

Razmotrite primer ispod:
```javascript
/usr
* /usr/libexec/cups
* /usr/local
* /usr/share/man
```
Ovaj deo implicira da, iako SIP generalno obezbeđuje **`/usr`** direktorijum, postoje specifične poddirektorijume (`/usr/libexec/cups`, `/usr/local`, i `/usr/share/man`) gde su modifikacije dozvoljene, što je naznačeno zvezdicom (\*) koja prethodi njihovim putanjama.

Da biste proverili da li je direktorijum ili fajl zaštićen SIP-om, možete koristiti komandu **`ls -lOd`** da proverite prisustvo **`restricted`** ili **`sunlnk`** oznake. Na primer:
```bash
ls -lOd /usr/libexec/cups
drwxr-xr-x  11 root  wheel  sunlnk 352 May 13 00:29 /usr/libexec/cups
```
U ovom slučaju, **`sunlnk`** zastavica označava da se direktorijum `/usr/libexec/cups` **ne može obrisati**, iako se unutar njega mogu kreirati, modifikovati ili brisati datoteke.

S druge strane:
```bash
ls -lOd /usr/libexec
drwxr-xr-x  338 root  wheel  restricted 10816 May 13 00:29 /usr/libexec
```
Ovde, **`restricted`** zastavica označava da je direktorijum `/usr/libexec` zaštićen SIP-om. U direktorijumu zaštićenom SIP-om, datoteke ne mogu biti kreirane, modifikovane ili obrisane.

Pored toga, ako datoteka sadrži atribut **`com.apple.rootless`** prošireni **atribut**, ta datoteka će takođe biti **zaštićena SIP-om**.

> [!TIP]
> Imajte na umu da **Sandbox** hook **`hook_vnode_check_setextattr`** sprečava bilo kakav pokušaj modifikacije proširenog atributa **`com.apple.rootless`.**

**SIP takođe ograničava druge root akcije** kao što su:

- Učitavanje nepouzdanih kernel ekstenzija
- Dobijanje task-portova za Apple-potpisane procese
- Modifikovanje NVRAM varijabli
- Omogućavanje kernel debagovanja

Opcije se čuvaju u nvram varijabli kao bitflag (`csr-active-config` na Intel-u i `lp-sip0` se čita iz pokrenutog Device Tree-a za ARM). Možete pronaći zastavice u XNU izvor kodu u `csr.sh`:

<figure><img src="../../../images/image (1192).png" alt=""><figcaption></figcaption></figure>

### SIP Status

Možete proveriti da li je SIP omogućen na vašem sistemu pomoću sledeće komande:
```bash
csrutil status
```
Ako treba da onemogućite SIP, morate restartovati računar u režimu oporavka (pritiskom na Command+R tokom pokretanja), a zatim izvršiti sledeću komandu:
```bash
csrutil disable
```
Ako želite da zadržite SIP uključen, ali da uklonite zaštite od debagovanja, to možete učiniti sa:
```bash
csrutil enable --without debug
```
### Ostala Ograničenja

- **Onemogućava učitavanje nepodpisanih kernel ekstenzija** (kexts), osiguravajući da samo verifikovane ekstenzije komuniciraju sa sistemskim kernelom.
- **Sprječava debagovanje** macOS sistemskih procesa, štiteći osnovne sistemske komponente od neovlašćenog pristupa i modifikacije.
- **Inhibira alate** poput dtrace da ispituju sistemske procese, dodatno štiteći integritet rada sistema.

[**Saznajte više o SIP informacijama u ovom predavanju**](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)**.**

### **SIP povezane Dozvole**

- `com.apple.rootless.xpc.bootstrap`: Kontrola launchd
- `com.apple.rootless.install[.heritable]`: Pristup datotečnom sistemu
- `com.apple.rootless.kext-management`: `kext_request`
- `com.apple.rootless.datavault.controller`: Upravljanje UF_DATAVAULT
- `com.apple.rootless.xpc.bootstrap`: XPC postavke sposobnosti
- `com.apple.rootless.xpc.effective-root`: Root preko launchd XPC
- `com.apple.rootless.restricted-block-devices`: Pristup sirovim blok uređajima
- `com.apple.rootless.internal.installer-equivalent`: Neograničen pristup datotečnom sistemu
- `com.apple.rootless.restricted-nvram-variables[.heritable]`: Potpuni pristup NVRAM-u
- `com.apple.rootless.storage.label`: Modifikovanje datoteka ograničenih od strane com.apple.rootless xattr sa odgovarajućom oznakom
- `com.apple.rootless.volume.VM.label`: Održavanje VM swap na volumenu

## SIP Obilaženja

Obilaženje SIP omogućava napadaču da:

- **Pristupi korisničkim podacima**: Čita osetljive korisničke podatke poput maila, poruka i Safari istorije sa svih korisničkih naloga.
- **TCC Obilaženje**: Direktno manipuliše TCC (Transparentnost, Saglasnost i Kontrola) bazom podataka kako bi omogućio neovlašćen pristup kameri, mikrofonu i drugim resursima.
- **Uspostavi postojanost**: Postavi malver na SIP-om zaštićenim lokacijama, čineći ga otpornim na uklanjanje, čak i od strane root privilegija. Ovo takođe uključuje potencijal za manipulaciju Alatom za uklanjanje malvera (MRT).
- **Učita kernel ekstenzije**: Iako postoje dodatne zaštite, obilaženje SIP pojednostavljuje proces učitavanja nepodpisanih kernel ekstenzija.

### Instalacijski Paketi

**Instalacijski paketi potpisani Apple-ovim sertifikatom** mogu zaobići njegove zaštite. To znači da će čak i paketi potpisani od strane standardnih developera biti blokirani ako pokušaju da modifikuju SIP-om zaštićene direktorijume.

### Nepostojeći SIP fajl

Jedna potencijalna rupa je da ako je fajl naveden u **`rootless.conf` ali trenutno ne postoji**, može biti kreiran. Malver bi mogao iskoristiti ovo da **uspostavi postojanost** na sistemu. Na primer, zlonameran program bi mogao kreirati .plist fajl u `/System/Library/LaunchDaemons` ako je naveden u `rootless.conf` ali nije prisutan.

### com.apple.rootless.install.heritable

> [!CAUTION]
> Dozvola **`com.apple.rootless.install.heritable`** omogućava zaobilaženje SIP-a

#### [CVE-2019-8561](https://objective-see.org/blog/blog_0x42.html) <a href="#cve" id="cve"></a>

Otkriveno je da je moguće **zamijeniti instalacijski paket nakon što je sistem verifikovao njegov kod** potpis i tada bi sistem instalirao zlonamerni paket umesto originalnog. Kako su ove radnje izvršene od strane **`system_installd`**, to bi omogućilo zaobilaženje SIP-a.

#### [CVE-2020–9854](https://objective-see.org/blog/blog_0x4D.html) <a href="#cve-unauthd-chain" id="cve-unauthd-chain"></a>

Ako je paket instaliran sa montirane slike ili spoljnog diska, **instalater** bi **izvršio** binarni fajl iz **tog datotečnog sistema** (umesto iz SIP-om zaštićene lokacije), čineći da **`system_installd`** izvrši proizvoljni binarni fajl.

#### CVE-2021-30892 - Shrootless

[**Istraživači iz ovog blog posta**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/) otkrili su ranjivost u SIP mehanizmu macOS-a, nazvanu 'Shrootless' ranjivost. Ova ranjivost se fokusira na **`system_installd`** demon, koji ima dozvolu, **`com.apple.rootless.install.heritable`**, koja omogućava bilo kojem od njegovih podprocesa da zaobiđe SIP-ove restrikcije datotečnog sistema.

**`system_installd`** demon će instalirati pakete koji su potpisani od strane **Apple-a**.

Istraživači su otkrili da tokom instalacije paketa potpisanog od Apple-a (.pkg fajl), **`system_installd`** **izvršava** sve **post-install** skripte uključene u paket. Ove skripte se izvršavaju od strane podrazumevanog shella, **`zsh`**, koji automatski **izvršava** komande iz **`/etc/zshenv`** fajla, ako postoji, čak i u neinteraktivnom režimu. Ovo ponašanje bi mogli iskoristiti napadači: kreiranjem zlonamernog `/etc/zshenv` fajla i čekanjem da **`system_installd` pozove `zsh`**, mogli bi izvršiti proizvoljne operacije na uređaju.

Pored toga, otkriveno je da se **`/etc/zshenv` može koristiti kao opšta napadačka tehnika**, ne samo za zaobilaženje SIP-a. Svaki korisnički profil ima `~/.zshenv` fajl, koji se ponaša na isti način kao `/etc/zshenv` ali ne zahteva root privilegije. Ovaj fajl bi mogao biti korišćen kao mehanizam postojanosti, aktivirajući se svaki put kada `zsh` startuje, ili kao mehanizam za podizanje privilegija. Ako admin korisnik podigne privilegije na root koristeći `sudo -s` ili `sudo <komanda>`, `~/.zshenv` fajl bi bio aktiviran, efektivno podižući na root.

#### [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)

U [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/) otkriveno je da se isti **`system_installd`** proces još uvek može zloupotrebiti jer je stavljajući **post-install skriptu unutar nasumično imenovane fascikle zaštićene SIP-om unutar `/tmp`**. Stvar je u tome da **`/tmp` sam po sebi nije zaštićen SIP-om**, tako da je bilo moguće **montirati** **virtuelnu sliku na njega**, zatim bi **instalater** stavio **post-install skriptu** unutra, **odmontirao** virtuelnu sliku, **ponovo kreirao** sve **fascikle** i **dodao** **post instalacionu** skriptu sa **payload-om** za izvršavanje.

#### [fsck_cs utility](https://www.theregister.com/2016/03/30/apple_os_x_rootless/)

Identifikovana je ranjivost gde je **`fsck_cs`** bio zavaravan da korumpira ključni fajl, zbog svoje sposobnosti da prati **simboličke linkove**. Konkretno, napadači su kreirali link sa _`/dev/diskX`_ na fajl `/System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist`. Izvršavanje **`fsck_cs`** na _`/dev/diskX`_ dovelo je do korupcije `Info.plist`. Integritet ovog fajla je vitalan za SIP (System Integrity Protection) operativnog sistema, koji kontroliše učitavanje kernel ekstenzija. Kada je korumpiran, SIP-ova sposobnost da upravlja isključenjima kernela je kompromitovana.

Komande za iskorišćavanje ove ranjivosti su:
```bash
ln -s /System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist /dev/diskX
fsck_cs /dev/diskX 1>&-
touch /Library/Extensions/
reboot
```
Eksploatacija ove ranjivosti ima ozbiljne posledice. Datoteka `Info.plist`, koja je obično odgovorna za upravljanje dozvolama za kernel ekstenzije, postaje neefikasna. To uključuje nemogućnost da se stavi na crnu listu određene ekstenzije, kao što je `AppleHWAccess.kext`. Kao rezultat toga, sa SIP-ovim kontrolnim mehanizmom van funkcije, ova ekstenzija može biti učitana, omogućavajući neovlašćen pristup za čitanje i pisanje RAM-u sistema.

#### [Mount over SIP protected folders](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)

Bilo je moguće montirati novi fajl sistem preko **SIP zaštićenih foldera kako bi se zaobišla zaštita**.
```bash
mkdir evil
# Add contento to the folder
hdiutil create -srcfolder evil evil.dmg
hdiutil attach -mountpoint /System/Library/Snadbox/ evil.dmg
```
#### [Upgrader bypass (2016)](https://objective-see.org/blog/blog_0x14.html)

Sistem je podešen da se pokrene sa ugrađenog instalacionog diska unutar `Install macOS Sierra.app` za nadogradnju operativnog sistema, koristeći `bless` alat. Komanda koja se koristi je sledeća:
```bash
/usr/sbin/bless -setBoot -folder /Volumes/Macintosh HD/macOS Install Data -bootefi /Volumes/Macintosh HD/macOS Install Data/boot.efi -options config="\macOS Install Data\com.apple.Boot" -label macOS Installer
```
Bezbednost ovog procesa može biti kompromitovana ako napadač izmeni sliku za nadogradnju (`InstallESD.dmg`) pre pokretanja. Strategija uključuje zamenu dinamičkog učitavača (dyld) sa zloćudnom verzijom (`libBaseIA.dylib`). Ova zamena rezultira izvršavanjem napadačevog koda kada se instalater pokrene.

Napadačev kod preuzima kontrolu tokom procesa nadogradnje, koristeći poverenje sistema u instalater. Napad se nastavlja izmenom slike `InstallESD.dmg` putem metode swizzling, posebno ciljanjem na metodu `extractBootBits`. Ovo omogućava injekciju zloćudnog koda pre nego što se slika diska upotrebi.

Štaviše, unutar `InstallESD.dmg`, postoji `BaseSystem.dmg`, koja služi kao korenski fajl sistem nadogradnje. Injekcija dinamičke biblioteke u ovo omogućava zloćudnom kodu da funkcioniše unutar procesa sposobnog za izmenu OS nivoa fajlova, značajno povećavajući potencijal za kompromitovanje sistema.

#### [systemmigrationd (2023)](https://www.youtube.com/watch?v=zxZesAN-TEk)

U ovom govoru sa [**DEF CON 31**](https://www.youtube.com/watch?v=zxZesAN-TEk), prikazano je kako **`systemmigrationd`** (koji može zaobići SIP) izvršava **bash** i **perl** skriptu, koja može biti zloupotrebljena putem env varijabli **`BASH_ENV`** i **`PERL5OPT`**.

#### CVE-2023-42860 <a href="#cve-a-detailed-look" id="cve-a-detailed-look"></a>

Kao što je [**detaljno opisano u ovom blog postu**](https://blog.kandji.io/apple-mitigates-vulnerabilities-installer-scripts), `postinstall` skripta iz `InstallAssistant.pkg` paketa je omogućila izvršavanje:
```bash
/usr/bin/chflags -h norestricted "${SHARED_SUPPORT_PATH}/SharedSupport.dmg"
```
i bilo je moguće kreirati symlink u `${SHARED_SUPPORT_PATH}/SharedSupport.dmg` koji bi omogućio korisniku da **ukloni ograničenja sa bilo kog fajla, zaobilazeći SIP zaštitu**.

### **com.apple.rootless.install**

> [!CAUTION]
> Ovlašćenje **`com.apple.rootless.install`** omogućava zaobilaženje SIP-a

Ovlašćenje `com.apple.rootless.install` je poznato po tome što zaobilazi zaštitu integriteta sistema (SIP) na macOS-u. Ovo je posebno pomenuto u vezi sa [**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/).

U ovom specifičnom slučaju, XPC servis sistema smešten na `/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc` poseduje ovo ovlašćenje. Ovo omogućava povezanim procesima da zaobiđu SIP ograničenja. Pored toga, ovaj servis posebno predstavlja metodu koja omogućava premestanje fajlova bez primene bilo kakvih bezbednosnih mera.

## Zapečaćene sistemske snimke

Zapečaćene sistemske snimke su funkcija koju je Apple uveo u **macOS Big Sur (macOS 11)** kao deo svog mehanizma **zaštite integriteta sistema (SIP)** kako bi pružio dodatni sloj bezbednosti i stabilnosti sistema. One su u suštini verzije sistemskog volumena koje su samo za čitanje.

Evo detaljnijeg pregleda:

1. **Nepromenljiv sistem**: Zapečaćene sistemske snimke čine macOS sistemski volumen "nepromenljivim", što znači da ne može biti modifikovan. Ovo sprečava bilo kakve neovlašćene ili slučajne promene na sistemu koje bi mogle ugroziti bezbednost ili stabilnost sistema.
2. **Ažuriranja sistemskog softvera**: Kada instalirate ažuriranja ili nadogradnje za macOS, macOS kreira novu sistemsku snimku. Zatim, macOS startni volumen koristi **APFS (Apple File System)** da pređe na ovu novu snimku. Ceo proces primene ažuriranja postaje sigurniji i pouzdaniji jer se sistem uvek može vratiti na prethodnu snimku ako nešto pođe po zlu tokom ažuriranja.
3. **Separacija podataka**: U skladu sa konceptom separacije podataka i sistemskog volumena uvedenim u macOS Catalina, funkcija zapečaćenih sistemskih snimaka osigurava da su svi vaši podaci i podešavanja smešteni na odvojenom "**Data**" volumenu. Ova separacija čini vaše podatke nezavisnim od sistema, što pojednostavljuje proces ažuriranja sistema i poboljšava bezbednost sistema.

Zapamtite da ove snimke automatski upravlja macOS i ne zauzimaju dodatni prostor na vašem disku, zahvaljujući mogućnostima deljenja prostora APFS-a. Takođe je važno napomenuti da su ove snimke različite od **Time Machine snimaka**, koje su korisnički dostupne sigurnosne kopije celog sistema.

### Proverite snimke

Komanda **`diskutil apfs list`** prikazuje **detalje APFS volumena** i njihov raspored:

<pre><code>+-- Container disk3 966B902E-EDBA-4775-B743-CF97A0556A13
|   ====================================================
|   APFS Container Reference:     disk3
|   Size (Capacity Ceiling):      494384795648 B (494.4 GB)
|   Capacity In Use By Volumes:   219214536704 B (219.2 GB) (44.3% used)
|   Capacity Not Allocated:       275170258944 B (275.2 GB) (55.7% free)
|   |
|   +-&#x3C; Physical Store disk0s2 86D4B7EC-6FA5-4042-93A7-D3766A222EBE
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

U prethodnom izlazu je moguće videti da su **lokacije dostupne korisnicima** montirane pod `/System/Volumes/Data`.

Pored toga, **macOS sistemska snimka volumena** je montirana u `/` i ona je **zapečaćena** (kriptografski potpisana od strane OS-a). Dakle, ako se SIP zaobiđe i modifikuje, **OS više neće moći da se pokrene**.

Takođe je moguće **proveriti da li je pečat omogućen** pokretanjem:
```bash
csrutil authenticated-root status
Authenticated Root status: enabled
```
Pored toga, snapshot disk je takođe montiran kao **samo za čitanje**:
```bash
mount
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
```
{{#include ../../../banners/hacktricks-training.md}}
