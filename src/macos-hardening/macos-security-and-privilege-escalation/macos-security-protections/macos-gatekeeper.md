# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}

## Gatekeeper

**Gatekeeper** je bezbednosna funkcija razvijena za Mac operativne sisteme, dizajnirana da osigura da korisnici **pokreću samo pouzdan softver** na svojim sistemima. Funkcioniše tako što **verifikuje softver** koji korisnik preuzima i pokušava da otvori iz **izvora van App Store-a**, kao što su aplikacija, dodatak ili instalacioni paket.

Ključni mehanizam Gatekeeper-a leži u njegovom **procesu verifikacije**. Proverava da li je preuzeti softver **potpisan od strane priznatog programera**, osiguravajući autentičnost softvera. Pored toga, utvrđuje da li je softver **notarisan od strane Apple-a**, potvrđujući da je bez poznatog zlonamernog sadržaja i da nije menjan nakon notarizacije.

Dodatno, Gatekeeper pojačava kontrolu i bezbednost korisnika tako što **traži od korisnika da odobri otvaranje** preuzetog softvera prvi put. Ova zaštita pomaže u sprečavanju korisnika da nenamerno pokrenu potencijalno štetan izvršni kod koji su možda zamislili kao bezopasan podatkovni fajl.

### Potpisi Aplikacija

Potpisi aplikacija, takođe poznati kao potpisi koda, su ključna komponenta Apple-ove bezbednosne infrastrukture. Koriste se za **verifikaciju identiteta autora softvera** (programera) i za osiguranje da kod nije menjan od poslednjeg potpisivanja.

Evo kako to funkcioniše:

1. **Potpisivanje Aplikacije:** Kada je programer spreman da distribuira svoju aplikaciju, on **potpisuje aplikaciju koristeći privatni ključ**. Ovaj privatni ključ je povezan sa **sertifikatom koji Apple izdaje programeru** kada se prijavi u Apple Developer Program. Proces potpisivanja uključuje kreiranje kriptografskog haša svih delova aplikacije i enkriptovanje ovog haša privatnim ključem programera.
2. **Distribucija Aplikacije:** Potpisana aplikacija se zatim distribuira korisnicima zajedno sa sertifikatom programera, koji sadrži odgovarajući javni ključ.
3. **Verifikacija Aplikacije:** Kada korisnik preuzme i pokuša da pokrene aplikaciju, njihov Mac operativni sistem koristi javni ključ iz sertifikata programera da dekriptuje haš. Zatim ponovo izračunava haš na osnovu trenutnog stanja aplikacije i upoređuje ga sa dekripovanim hašem. Ako se poklapaju, to znači da **aplikacija nije modifikovana** od kada ju je programer potpisao, i sistem dozvoljava pokretanje aplikacije.

Potpisi aplikacija su esencijalni deo Apple-ove Gatekeeper tehnologije. Kada korisnik pokuša da **otvori aplikaciju preuzetu sa interneta**, Gatekeeper verifikuje potpis aplikacije. Ako je potpisana sertifikatom koji je Apple izdao poznatom programeru i kod nije menjan, Gatekeeper dozvoljava pokretanje aplikacije. U suprotnom, blokira aplikaciju i obaveštava korisnika.

Počevši od macOS Catalina, **Gatekeeper takođe proverava da li je aplikacija notarizovana** od strane Apple-a, dodajući dodatni sloj bezbednosti. Proces notarizacije proverava aplikaciju na poznate bezbednosne probleme i zlonamerni kod, i ako ovi provere prođu, Apple dodaje tiket aplikaciji koji Gatekeeper može da verifikuje.

#### Proveri Potpise

Kada proveravate neki **uzorak zlonamernog softvera**, uvek treba da **proverite potpis** binarnog fajla jer **programer** koji ga je potpisao može već biti **povezan** sa **zlonamernim softverom.**
```bash
# Get signer
codesign -vv -d /bin/ls 2>&1 | grep -E "Authority|TeamIdentifier"

# Check if the app’s contents have been modified
codesign --verify --verbose /Applications/Safari.app

# Get entitlements from the binary
codesign -d --entitlements :- /System/Applications/Automator.app # Check the TCC perms

# Check if the signature is valid
spctl --assess --verbose /Applications/Safari.app

# Sign a binary
codesign -s <cert-name-keychain> toolsdemo
```
### Notarizacija

Apple-ov proces notarizacije služi kao dodatna zaštita za korisnike od potencijalno štetnog softvera. Uključuje **razvojnu osobu koja podnosi svoju aplikaciju na ispitivanje** od strane **Apple-ove Notarizacione Usluge**, što se ne sme mešati sa Pregledom Aplikacija. Ova usluga je **automatski sistem** koji pažljivo ispituje podneti softver na prisustvo **malicioznog sadržaja** i bilo kakvih potencijalnih problema sa potpisivanjem koda.

Ako softver **prođe** ovu inspekciju bez podizanja bilo kakvih zabrinutosti, Notarizaciona Usluga generiše notarizacionu kartu. Razvojna osoba je zatim obavezna da **priključi ovu kartu svom softveru**, proces poznat kao 'stapling.' Pored toga, notarizaciona karta se takođe objavljuje online gde joj Gatekeeper, Apple-ova bezbednosna tehnologija, može pristupiti.

Prilikom prve instalacije ili izvršavanja softvera od strane korisnika, postojanje notarizacione karte - bilo da je priključena izvršnom fajlu ili pronađena online - **obaveštava Gatekeeper da je softver notarizovan od strane Apple-a**. Kao rezultat toga, Gatekeeper prikazuje opisnu poruku u dijalogu za inicijalno pokretanje, ukazujući da je softver prošao provere za maliciozni sadržaj od strane Apple-a. Ovaj proces tako poboljšava poverenje korisnika u bezbednost softvera koji instaliraju ili pokreću na svojim sistemima.

### spctl & syspolicyd

> [!CAUTION]
> Imajte na umu da od verzije Sequoia, **`spctl`** više ne dozvoljava modifikaciju konfiguracije Gatekeeper-a.

**`spctl`** je CLI alat za enumeraciju i interakciju sa Gatekeeper-om (sa `syspolicyd` demonima putem XPC poruka). Na primer, moguće je videti **status** GateKeeper-a sa:
```bash
# Check the status
spctl --status
```
> [!CAUTION]
> Imajte na umu da se provere potpisa GateKeeper-a vrše samo za **datoteke sa atributom Quarantine**, a ne za svaku datoteku.

GateKeeper će proveriti da li se prema **postavkama i potpisu** može izvršiti binarni fajl:

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`** je glavni daemon odgovoran za sprovođenje Gatekeeper-a. Održava bazu podataka smeštenu u `/var/db/SystemPolicy` i moguće je pronaći kod koji podržava [bazu podataka ovde](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp) i [SQL šablon ovde](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql). Imajte na umu da baza podataka nije ograničena SIP-om i da je moguće pisati u nju kao root, a baza podataka `/var/db/.SystemPolicy-default` se koristi kao originalna rezervna kopija u slučaju da se druga ošteti.

Pored toga, paketi **`/var/db/gke.bundle`** i **`/var/db/gkopaque.bundle`** sadrže datoteke sa pravilima koja se ubacuju u bazu podataka. Možete proveriti ovu bazu podataka kao root sa:
```bash
# Open database
sqlite3 /var/db/SystemPolicy

# Get allowed rules
SELECT requirement,allow,disabled,label from authority where label != 'GKE' and disabled=0;
requirement|allow|disabled|label
anchor apple generic and certificate 1[subject.CN] = "Apple Software Update Certification Authority"|1|0|Apple Installer
anchor apple|1|0|Apple System
anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] exists|1|0|Mac App Store
anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and (certificate leaf[field.1.2.840.113635.100.6.1.14] or certificate leaf[field.1.2.840.113635.100.6.1.13]) and notarized|1|0|Notarized Developer ID
[...]
```
**`syspolicyd`** takođe izlaže XPC server sa različitim operacijama kao što su `assess`, `update`, `record` i `cancel` koje su takođe dostupne koristeći **`Security.framework`'s `SecAssessment*`** API-je, a **`spctl`** zapravo komunicira sa **`syspolicyd`** putem XPC.

Obratite pažnju kako je prvo pravilo završilo sa "**App Store**" a drugo sa "**Developer ID**" i da je u prethodnoj slici bilo **omogućeno izvršavanje aplikacija iz App Store-a i od identifikovanih developera**.\
Ako **izmenite** tu postavku na App Store, pravila "**Notarized Developer ID" će nestati**.

Takođe postoji hiljade pravila **tipa GKE**:
```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```
Ovo su heševi koji dolaze iz:

- `/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`
- `/var/db/gke.bundle/Contents/Resources/gk.db`
- `/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`

Ili možete navesti prethodne informacije sa:
```bash
sudo spctl --list
```
Opcije **`--master-disable`** i **`--global-disable`** za **`spctl`** će potpuno **onemogućiti** ove provere potpisa:
```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```
Kada je potpuno omogućeno, pojaviće se nova opcija:

<figure><img src="../../../images/image (1151).png" alt=""><figcaption></figcaption></figure>

Moguće je **proveriti da li će aplikacija biti dozvoljena od strane GateKeeper-a** sa:
```bash
spctl --assess -v /Applications/App.app
```
Moguće je dodati nova pravila u GateKeeper da bi se omogućila izvršavanje određenih aplikacija sa:
```bash
# Check if allowed - nop
spctl --assess -v /Applications/App.app
/Applications/App.app: rejected
source=no usable signature

# Add a label and allow this label in GateKeeper
sudo spctl --add --label "whitelist" /Applications/App.app
sudo spctl --enable --label "whitelist"

# Check again - yep
spctl --assess -v /Applications/App.app
/Applications/App.app: accepted
```
Regarding **kernel extensions**, the folder `/var/db/SystemPolicyConfiguration` contains files with lists of kexts allowed to be loaded. Moreover, `spctl` has the entitlement `com.apple.private.iokit.nvram-csr` because it's capable of adding new pre-approved kernel extensions which need to be saved also in NVRAM in a `kext-allowed-teams` key.

#### Управљање Gatekeeper-ом на macOS 15 (Sequoia) и касније

Starting in macOS 15 Sequoia, end users can no longer toggle Gatekeeper policy from `spctl`. Management is performed via System Settings or by deploying an MDM configuration profile with the `com.apple.systempolicy.control` payload. Example profile snippet to allow App Store and identified developers (but not "Anywhere"):
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>PayloadContent</key>
<array>
<dict>
<key>PayloadType</key>
<string>com.apple.systempolicy.control</string>
<key>PayloadVersion</key>
<integer>1</integer>
<key>PayloadIdentifier</key>
<string>com.example.gatekeeper</string>
<key>EnableAssessment</key>
<true/>
<key>AllowIdentifiedDevelopers</key>
<true/>
</dict>
</array>
<key>PayloadType</key>
<string>Configuration</string>
<key>PayloadIdentifier</key>
<string>com.example.profile.gatekeeper</string>
<key>PayloadUUID</key>
<string>00000000-0000-0000-0000-000000000000</string>
<key>PayloadVersion</key>
<integer>1</integer>
<key>PayloadDisplayName</key>
<string>Gatekeeper</string>
</dict>
</plist>
```
### Quarantine Files

Upon **downloading** an application or file, specific macOS **applications** such as web browsers or email clients **attach an extended file attribute**, commonly known as the "**quarantine flag**," to the downloaded file. This attribute acts as a security measure to **mark the file** as coming from an untrusted source (the internet), and potentially carrying risks. However, not all applications attach this attribute, for instance, common BitTorrent client software usually bypasses this process.

**Prisutnost quarantine flag-a signalizira macOS-ovu Gatekeeper sigurnosnu funkciju kada korisnik pokuša da izvrši datoteku**.

In the case where the **quarantine flag is not present** (as with files downloaded via some BitTorrent clients), Gatekeeper's **checks may not be performed**. Thus, users should exercise caution when opening files downloaded from less secure or unknown sources.

> [!NOTE] > **Proveravanje** **validnosti** potpisa koda je **resursno intenzivan** proces koji uključuje generisanje kriptografskih **hash-ova** koda i svih njegovih pratećih resursa. Furthermore, checking certificate validity involves doing an **online check** to Apple's servers to see if it has been revoked after it was issued. For these reasons, a full code signature and notarization check is **impractical to run every time an app is launched**.
>
> Therefore, these checks are **only run when executing apps with the quarantined attribute.**

> [!WARNING]
> This attribute must be **set by the application creating/downloading** the file.
>
> However, files that are sandboxed will have this attribute set to every file they create. And non sandboxed apps can set it themselves, or specify the [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) key in the **Info.plist** which will make the system set the `com.apple.quarantine` extended attribute on the files created,

Moreover, all files created by a process calling **`qtn_proc_apply_to_self`** are quarantined. Or the API **`qtn_file_apply_to_path`** adds the quarantine attribute to a specified file path.

It's possible to **check it's status and enable/disable** (root required) with:
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
Možete takođe **proveriti da li datoteka ima prošireni atribut karantina** sa:
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
Proverite **vrednost** **proširenih** **atributa** i pronađite aplikaciju koja je napisala atribut karantina sa:
```bash
xattr -l portada.png
com.apple.macl:
00000000  03 00 53 DA 55 1B AE 4C 4E 88 9D CA B7 5C 50 F3  |..S.U..LN.....P.|
00000010  16 94 03 00 27 63 64 97 98 FB 4F 02 84 F3 D0 DB  |....'cd...O.....|
00000020  89 53 C3 FC 03 00 27 63 64 97 98 FB 4F 02 84 F3  |.S....'cd...O...|
00000030  D0 DB 89 53 C3 FC 00 00 00 00 00 00 00 00 00 00  |...S............|
00000040  00 00 00 00 00 00 00 00                          |........|
00000048
com.apple.quarantine: 00C1;607842eb;Brave;F643CD5F-6071-46AB-83AB-390BA944DEC5
# 00c1 -- It has been allowed to eexcute this file (QTN_FLAG_USER_APPROVED = 0x0040)
# 607842eb -- Timestamp
# Brave -- App
# F643CD5F-6071-46AB-83AB-390BA944DEC5 -- UID assigned to the file downloaded
```
Zapravo, proces "može postaviti zastavice karantina na datoteke koje kreira" (već sam pokušao da primenim USER_APPROVED zastavicu na kreiranoj datoteci, ali se neće primeniti):

<details>

<summary>Izvorni kod primene zastavica karantina</summary>
```c
#include <stdio.h>
#include <stdlib.h>

enum qtn_flags {
QTN_FLAG_DOWNLOAD = 0x0001,
QTN_FLAG_SANDBOX = 0x0002,
QTN_FLAG_HARD = 0x0004,
QTN_FLAG_USER_APPROVED = 0x0040,
};

#define qtn_proc_alloc _qtn_proc_alloc
#define qtn_proc_apply_to_self _qtn_proc_apply_to_self
#define qtn_proc_free _qtn_proc_free
#define qtn_proc_init _qtn_proc_init
#define qtn_proc_init_with_self _qtn_proc_init_with_self
#define qtn_proc_set_flags _qtn_proc_set_flags
#define qtn_file_alloc _qtn_file_alloc
#define qtn_file_init_with_path _qtn_file_init_with_path
#define qtn_file_free _qtn_file_free
#define qtn_file_apply_to_path _qtn_file_apply_to_path
#define qtn_file_set_flags _qtn_file_set_flags
#define qtn_file_get_flags _qtn_file_get_flags
#define qtn_proc_set_identifier _qtn_proc_set_identifier

typedef struct _qtn_proc *qtn_proc_t;
typedef struct _qtn_file *qtn_file_t;

int qtn_proc_apply_to_self(qtn_proc_t);
void qtn_proc_init(qtn_proc_t);
int qtn_proc_init_with_self(qtn_proc_t);
int qtn_proc_set_flags(qtn_proc_t, uint32_t flags);
qtn_proc_t qtn_proc_alloc();
void qtn_proc_free(qtn_proc_t);
qtn_file_t qtn_file_alloc(void);
void qtn_file_free(qtn_file_t qf);
int qtn_file_set_flags(qtn_file_t qf, uint32_t flags);
uint32_t qtn_file_get_flags(qtn_file_t qf);
int qtn_file_apply_to_path(qtn_file_t qf, const char *path);
int qtn_file_init_with_path(qtn_file_t qf, const char *path);
int qtn_proc_set_identifier(qtn_proc_t qp, const char* bundleid);

int main() {

qtn_proc_t qp = qtn_proc_alloc();
qtn_proc_set_identifier(qp, "xyz.hacktricks.qa");
qtn_proc_set_flags(qp, QTN_FLAG_DOWNLOAD | QTN_FLAG_USER_APPROVED);
qtn_proc_apply_to_self(qp);
qtn_proc_free(qp);

FILE *fp;
fp = fopen("thisisquarantined.txt", "w+");
fprintf(fp, "Hello Quarantine\n");
fclose(fp);

return 0;

}
```
</details>

I **uklonite** taj atribut sa:
```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```
I pronađite sve zaražene datoteke sa:
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
Quarantine informacije se takođe čuvaju u centralnoj bazi podataka koju upravlja LaunchServices u **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**, što omogućava GUI-ju da dobije podatke o poreklu datoteka. Štaviše, ovo može biti prepisano od strane aplikacija koje bi mogle biti zainteresovane da sakriju svoje poreklo. Takođe, ovo se može uraditi putem LaunchServices APIS.

#### **libquarantine.dylib**

Ova biblioteka izvozi nekoliko funkcija koje omogućavaju manipulaciju poljima proširenih atributa.

`qtn_file_*` API-ji se bave politikama karantina datoteka, dok se `qtn_proc_*` API-ji primenjuju na procese (datoteke koje kreira proces). Neizvođene `__qtn_syscall_quarantine*` funkcije su one koje primenjuju politike koje pozivaju `mac_syscall` sa "Quarantine" kao prvim argumentom, što šalje zahteve ka `Quarantine.kext`.

#### **Quarantine.kext**

Kernel ekstenzija je dostupna samo kroz **kernel cache na sistemu**; međutim, _možete_ preuzeti **Kernel Debug Kit sa** [**https://developer.apple.com/**](https://developer.apple.com/), koji će sadržati simboličku verziju ekstenzije.

Ova Kext će uhvatiti putem MACF nekoliko poziva kako bi uhvatila sve događaje životnog ciklusa datoteka: Kreiranje, otvaranje, preimenovanje, hard-linkovanje... čak i `setxattr` da spreči postavljanje `com.apple.quarantine` proširenog atributa.

Takođe koristi nekoliko MIB-ova:

- `security.mac.qtn.sandbox_enforce`: Sprovodi karantin zajedno sa Sandbox-om
- `security.mac.qtn.user_approved_exec`: Karantinske procese mogu izvršavati samo odobrene datoteke

#### Provenance xattr (Ventura i kasnije)

macOS 13 Ventura je uveo poseban mehanizam porekla koji se popunjava prvi put kada je karantinskoj aplikaciji dozvoljeno da se pokrene. Dva artefakta se kreiraju:

- `com.apple.provenance` xattr u `.app` bundle direktorijumu (fiksna veličina binarne vrednosti koja sadrži primarni ključ i oznake).
- Red u `provenance_tracking` tabeli unutar ExecPolicy baze podataka na `/var/db/SystemPolicyConfiguration/ExecPolicy/` koji čuva cdhash aplikacije i metapodatke.

Praktična upotreba:
```bash
# Inspect provenance xattr (if present)
xattr -p com.apple.provenance /Applications/Some.app | hexdump -C

# Observe Gatekeeper/provenance events in real time
log stream --style syslog --predicate 'process == "syspolicyd"'

# Retrieve historical Gatekeeper decisions for a specific bundle
log show --last 2d --style syslog --predicate 'process == "syspolicyd" && eventMessage CONTAINS[cd] "GK scan"'
```
### XProtect

XProtect je ugrađena **anti-malware** funkcija u macOS-u. XProtect **proverava svaku aplikaciju kada se prvi put pokrene ili izmeni u odnosu na svoju bazu podataka** poznatih malware-a i nesigurnih tipova datoteka. Kada preuzmete datoteku putem određenih aplikacija, kao što su Safari, Mail ili Messages, XProtect automatski skenira datoteku. Ako se podudara sa bilo kojim poznatim malware-om u svojoj bazi podataka, XProtect će **sprečiti pokretanje datoteke** i obavestiti vas o pretnji.

Baza podataka XProtect-a se **redovno ažurira** od strane Apple-a sa novim definicijama malware-a, a ova ažuriranja se automatski preuzimaju i instaliraju na vašem Mac-u. To osigurava da je XProtect uvek ažuriran sa najnovijim poznatim pretnjama.

Međutim, vredi napomenuti da **XProtect nije rešenje za antivirus sa punim funkcijama**. Proverava samo specifičnu listu poznatih pretnji i ne vrši skeniranje pri pristupu kao većina antivirusnog softvera.

Možete dobiti informacije o najnovijem XProtect ažuriranju pokretanjem:
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
XProtect se nalazi na. SIP zaštićenoj lokaciji na **/Library/Apple/System/Library/CoreServices/XProtect.bundle** i unutar paketa možete pronaći informacije koje XProtect koristi:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Omogućava kodu sa tim cdhash-ovima da koristi legacijske privilegije.
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: Lista dodataka i ekstenzija koje nisu dozvoljene za učitavanje putem BundleID i TeamID ili koje označavaju minimalnu verziju.
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Yara pravila za otkrivanje malvera.
- **`XProtect.bundle/Contents/Resources/gk.db`**: SQLite3 baza podataka sa hešovima blokiranih aplikacija i TeamID-ima.

Napomena da postoji još jedna aplikacija u **`/Library/Apple/System/Library/CoreServices/XProtect.app`** koja je povezana sa XProtect-om, a koja nije uključena u proces Gatekeeper-a.

> XProtect Remediator: Na modernom macOS-u, Apple isporučuje skenerе na zahtev (XProtect Remediator) koji se periodično pokreću putem launchd-a kako bi otkrili i remedijirali porodice malvera. Ove skeniranja možete posmatrati u ujedinjenim logovima:
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### Nije Gatekeeper

> [!CAUTION]
> Napomena da Gatekeeper **nije izvršen svaki put** kada izvršite aplikaciju, samo _**AppleMobileFileIntegrity**_ (AMFI) će **verifikovati potpise izvršnog koda** kada izvršite aplikaciju koja je već izvršena i verifikovana od strane Gatekeeper-a.

Stoga, ranije je bilo moguće izvršiti aplikaciju da je kešira sa Gatekeeper-om, a zatim **modifikovati neizvršne datoteke aplikacije** (kao što su Electron asar ili NIB datoteke) i ako nisu bile postavljene druge zaštite, aplikacija bi bila **izvršena** sa **malicioznim** dodacima.

Međutim, sada to nije moguće jer macOS **sprečava modifikaciju datoteka** unutar paketa aplikacija. Dakle, ako pokušate napad [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md), otkrićete da više nije moguće zloupotrebiti ga jer nakon izvršavanja aplikacije da je keširate sa Gatekeeper-om, nećete moći da modifikujete paket. I ako promenite, na primer, ime direktorijuma Contents u NotCon (kako je naznačeno u eksploitu), a zatim izvršite glavni binarni fajl aplikacije da je keširate sa Gatekeeper-om, to će izazvati grešku i neće se izvršiti.

## Obilaženje Gatekeeper-a

Svaki način za obilaženje Gatekeeper-a (uspeti da naterate korisnika da preuzme nešto i izvrši to kada bi Gatekeeper trebao da to onemogući) smatra se ranjivošću u macOS-u. Ovo su neki CVE-ovi dodeljeni tehnikama koje su omogućile obilaženje Gatekeeper-a u prošlosti:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Primećeno je da ako se **Archive Utility** koristi za ekstrakciju, datoteke sa **putanjama dužim od 886 karaktera** ne dobijaju proširenu atribut com.apple.quarantine. Ova situacija nenamerno omogućava tim datotekama da **obiđu Gatekeeper-ove** sigurnosne provere.

Proverite [**originalni izveštaj**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) za više informacija.

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Kada se aplikacija kreira pomoću **Automator-a**, informacije o tome šta joj je potrebno za izvršavanje su unutar `application.app/Contents/document.wflow`, a ne u izvršnom fajlu. Izvršni fajl je samo generički Automator binarni fajl nazvan **Automator Application Stub**.

Stoga, mogli biste napraviti `application.app/Contents/MacOS/Automator\ Application\ Stub` **da pokazuje simboličku vezu na drugi Automator Application Stub unutar sistema** i izvršiće ono što je unutar `document.wflow` (vaš skript) **bez aktiviranja Gatekeeper-a** jer stvarni izvršni fajl nema quarantine xattr.

Primer očekivane lokacije: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Proverite [**originalni izveštaj**](https://ronmasas.com/posts/bypass-macos-gatekeeper) za više informacija.

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

U ovom obilaženju, zip fajl je kreiran sa aplikacijom koja počinje da kompresuje iz `application.app/Contents` umesto iz `application.app`. Stoga, **quarantine attr** je primenjen na sve **datoteke iz `application.app/Contents`** ali **ne na `application.app`**, što je Gatekeeper proveravao, tako da je Gatekeeper bio obilažen jer kada je `application.app` aktiviran, **nije imao atribut karantina.**
```bash
zip -r test.app/Contents test.zip
```
Proverite [**originalni izveštaj**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) za više informacija.

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Čak i ako su komponenti različiti, eksploatacija ove ranjivosti je veoma slična prethodnoj. U ovom slučaju, generisaćemo Apple Archive iz **`application.app/Contents`** tako da **`application.app` neće dobiti atribut karantina** kada ga dekompresuje **Archive Utility**.
```bash
aa archive -d test.app/Contents -o test.app.aar
```
Proverite [**originalni izveštaj**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) za više informacija.

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

ACL **`writeextattr`** može se koristiti da spreči bilo koga da upisuje atribut u datoteku:
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
Pored toga, **AppleDouble** format datoteka kopira datoteku uključujući njene ACE.

U [**izvornom kodu**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) moguće je videti da će ACL tekstualna reprezentacija smeštena unutar xattr pod nazivom **`com.apple.acl.text`** biti postavljena kao ACL u dekompresovanoj datoteci. Dakle, ako ste kompresovali aplikaciju u zip datoteku sa **AppleDouble** formatom datoteke sa ACL-om koji sprečava da se drugi xattrs upisuju u nju... xattr karantina nije postavljen u aplikaciju:
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
Proverite [**originalni izveštaj**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) za više informacija.

Imajte na umu da se ovo takođe može iskoristiti sa AppleArchives:
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

Otkriveno je da **Google Chrome nije postavljao atribut karantina** za preuzete datoteke zbog nekih unutrašnjih problema sa macOS-om.

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDouble formati datoteka čuvaju atribute datoteke u posebnoj datoteci koja počinje sa `._`, što pomaže u kopiranju atributa datoteka **između macOS mašina**. Međutim, primećeno je da nakon dekompresije AppleDouble datoteke, datoteka koja počinje sa `._` **nije dobila atribut karantina**.
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you downloaded the resulting test.aar and decompress it, the file test/._a won't have a quarantitne attribute
```
Mogućnost kreiranja datoteke koja neće imati postavljen atribut karantina omogućila je **obići Gatekeeper.** Trik je bio **napraviti DMG datoteku aplikacije** koristeći AppleDouble nazivnu konvenciju (početi je sa `._`) i kreirati **vidljivu datoteku kao simboličku vezu ka ovoj skrivenoj** datoteci bez atributa karantina.\
Kada se **dmg datoteka izvrši**, pošto nema atribut karantina, ona će **obići Gatekeeper.**
```bash
# Create an app bundle with the backdoor an call it app.app

echo "[+] creating disk image with app"
hdiutil create -srcfolder app.app app.dmg

echo "[+] creating directory and files"
mkdir
mkdir -p s/app
cp app.dmg s/app/._app.dmg
ln -s ._app.dmg s/app/app.dmg

echo "[+] compressing files"
aa archive -d s/ -o app.aar
```
### [CVE-2023-41067]

Zaobilaženje Gatekeeper-a koje je ispravljeno u macOS Sonoma 14.0 omogućilo je pokretanje kreiranih aplikacija bez upozorenja. Detalji su javno objavljeni nakon zakrpe, a problem je aktivno iskorišćen u prirodi pre ispravke. Osigurajte da je instaliran Sonoma 14.0 ili noviji.

### [CVE-2024-27853]

Zaobilaženje Gatekeeper-a u macOS 14.4 (objavljeno mart 2024) proizašlo iz `libarchive` obrade zlonamernih ZIP-ova omogućilo je aplikacijama da izbegnu procenu. Ažurirajte na 14.4 ili noviji gde je Apple rešio problem.

### Treće strane dekompresori koji pogrešno propagiraju karantin (2023–2024)

Nekoliko ranjivosti u popularnim alatima za ekstrakciju (npr. The Unarchiver) uzrokovalo je da datoteke ekstrahovane iz arhiva ne sadrže `com.apple.quarantine` xattr, omogućavajući prilike za zaobilaženje Gatekeeper-a. Uvek se oslanjajte na macOS Archive Utility ili ispravljene alate prilikom testiranja, i proverite xattrs nakon ekstrakcije.

### uchg (iz ove [prezentacije](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

- Kreirajte direktorijum koji sadrži aplikaciju.
- Dodajte uchg aplikaciji.
- Kompresujte aplikaciju u tar.gz datoteku.
- Pošaljite tar.gz datoteku žrtvi.
- Žrtva otvara tar.gz datoteku i pokreće aplikaciju.
- Gatekeeper ne proverava aplikaciju.

### Sprečavanje xattr karantina

U ".app" paketu, ako xattr karantina nije dodat, prilikom izvršavanja **Gatekeeper neće biti aktiviran**.


## Reference

- Apple Platform Security: O bezbednosnom sadržaju macOS Sonoma 14.4 (uključuje CVE-2024-27853) – [https://support.apple.com/en-us/HT214084](https://support.apple.com/en-us/HT214084)
- Eclectic Light: Kako macOS sada prati poreklo aplikacija – [https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)

{{#include ../../../banners/hacktricks-training.md}}
