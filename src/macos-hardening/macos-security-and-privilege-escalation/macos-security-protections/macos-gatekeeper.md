# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

**Gatekeeper** je bezbednosna funkcija razvijena za Mac operativne sisteme, namenjena da osigura da korisnici **pokreću samo pouzdan softver** na svojim sistemima. Ona funkcioniše tako što **verifikuje softver** koji korisnik preuzme i pokuša da otvori iz **izvora van App Store**, kao što su aplikacija, plug-in, ili instalacioni paket.

Ključni mehanizam Gatekeeper leži u njegovom procesu **verifikacije**. On proverava da li je preuzeti softver **potpisan od strane prepoznatog developera**, čime se osigurava autentičnost softvera. Dodatno, utvrđuje da li je softver **notarised by Apple**, potvrđujući da ne sadrži poznati maliciozni sadržaj i da nije izmenjen nakon notarizacije.

Pored toga, Gatekeeper pojačava kontrolu i bezbednost korisnika tako što **zahteva od korisnika da odobre otvaranje** preuzetog softvera pri prvom pokretanju. Ova mera pomaže da se spreči da korisnici nenamerno pokreću potencijalno štetan izvršni kod koji su mogli pobrkati sa bezopasnom data datotekom.

### Application Signatures

Application signatures, poznati i kao code signatures, predstavljaju ključnu komponentu Apple-ove sigurnosne infrastrukture. Koriste se da **verifikuju identitet autora softvera** (developera) i da osiguraju da kod nije bio izmenjen od kada je poslednji put potpisan.

Evo kako to funkcioniše:

1. **Signing the Application:** Kada je developer spreman da distribuira svoju aplikaciju, on je **potpisuje koristeći privatni ključ**. Taj privatni ključ je povezan sa **sertifikatom koji Apple izdaje developeru** kada se prijavi u Apple Developer Program. Proces potpisivanja uključuje kreiranje kriptografskog heša svih delova aplikacije i enkriptovanje tog heša developerovim privatnim ključem.
2. **Distributing the Application:** Potpisana aplikacija se zatim distribuira korisnicima zajedno sa developerovim sertifikatom, koji sadrži odgovarajući javni ključ.
3. **Verifying the Application:** Kada korisnik preuzme i pokuša da pokrene aplikaciju, njegov Mac operativni sistem koristi javni ključ iz developerovog sertifikata da dešifruje heš. Zatim ponovo izračunava heš na osnovu trenutnog stanja aplikacije i upoređuje ga sa dešifrovanim hešem. Ako se poklapaju, to znači da **aplikacija nije izmenjena** od kada ju je developer potpisao, i sistem dozvoljava njeno pokretanje.

Potpisi aplikacija su suštinski deo Apple-ove Gatekeeper tehnologije. Kada korisnik pokuša da **otvori aplikaciju preuzetu sa interneta**, Gatekeeper verifikuje potpis aplikacije. Ako je aplikacija potpisana sertifikatom koji je Apple izdao poznatom developeru i kod nije bio izmenjen, Gatekeeper dozvoljava pokretanje aplikacije. U suprotnom, blokira aplikaciju i upozorava korisnika.

Počevši od macOS Catalina, **Gatekeeper also checks whether the application has been notarized** by Apple, dodajući dodatni sloj bezbednosti. Proces notarizacije proverava aplikaciju na poznate sigurnosne probleme i maliciozni kod, i ako te provere prođu, Apple dodaje ticket aplikaciji koji Gatekeeper može verifikovati.

#### Check Signatures

Kada proveravate neki **malware sample** uvek treba da **check the signature** binarnog fajla, jer se može desiti da je **developer** koji ga je potpisao već povezan sa **malware.**
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

Proces notarizacije kompanije Apple služi kao dodatna mera zaštite kako bi se korisnici zaštitili od potencijalno štetnog softvera. To podrazumeva **da programer podnosi svoju aplikaciju na pregled** kod **Apple's Notary Service**, što se ne bi trebalo brkati sa App Review. Ova usluga je **automatizovan sistem** koji detaljno pregleda poslat softver u potrazi za **zlonamernim sadržajem** i eventualnim problemima sa potpisivanjem koda.

Ako softver **prođe** ovu proveru bez podizanja sumnji, Notary Service generiše tiket za notarizaciju. Programer potom mora da **priloži ovaj tiket uz svoj softver**, proces poznat kao 'stapling'. Nadalje, tiket za notarizaciju se takođe objavljuje online gde mu Gatekeeper, Apple-ova bezbednosna tehnologija, može pristupiti.

Prilikom prvog instaliranja ili pokretanja softvera od strane korisnika, postojanje tiketa za notarizaciju — bilo da je 'stapled' na izvršnom fajlu ili dostupno online — **obaveštava Gatekeeper da je softver notarizovao Apple**. Kao rezultat, Gatekeeper prikazuje opisnu poruku u dijalogu pri prvom pokretanju, koja ukazuje da je softver prošao provere na zlonamerni sadržaj od strane Apple-a. Ovaj proces povećava poverenje korisnika u bezbednost softvera koji instaliraju ili pokreću na svojim sistemima.

### spctl & syspolicyd

> [!CAUTION]
> Imajte na umu da od Sequoia verzije, **`spctl`** više ne dozvoljava izmenu Gatekeeper konfiguracije.

**`spctl`** je CLI alat za ispitivanje i interakciju sa Gatekeeper-om (putem `syspolicyd` daemona preko XPC poruka). Na primer, moguće je videti **stanje** GateKeeper-a pomoću:
```bash
# Check the status
spctl --status
```
> [!CAUTION]
> Imajte na umu da se GateKeeper proveravanja potpisa vrše samo za **datoteke sa atributom Quarantine**, ne za svaki fajl.

GateKeeper će proveriti da li prema **podešavanjima & potpisu** binarni fajl može da se izvrši:

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`** je glavni daemon zadužen za sprovođenje GateKeeper-a. Održava bazu podataka lociranu u `/var/db/SystemPolicy` i moguće je pronaći kod koji podržava the [database here](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp) i the [SQL template here](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql). Imajte na umu da baza podataka nije ograničena od strane SIP i da je upisiva od strane root-a, a baza `/var/db/.SystemPolicy-default` se koristi kao originalna rezervna kopija u slučaju da se druga pokvari.

Moreover, the bundles **`/var/db/gke.bundle`** and **`/var/db/gkopaque.bundle`** contains files with rules that are inserted in the database. You can check this database as root with:
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
**`syspolicyd`** такође излаже XPC сервер са различитим операцијама као што су `assess`, `update`, `record` и `cancel` које су такође доступне коришћењем **`Security.framework`'s `SecAssessment*`** API-ja и **`spctl`** заправо комуницира са **`syspolicyd`** преко XPC.

Обратите пажњу како је прво правило завршавало са "**App Store**" а друго са "**Developer ID**" и да је на претходној слици било **омогућено извршавање апликација из App Store и идентификованих developera**.\
Ако ту поставку **измените** на App Store, "**Notarized Developer ID" правила ће нестати**.

Постоје и хиљаде правила типа **type GKE** :
```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```
Ovo su heševi koji potiču iz:

- `/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`
- `/var/db/gke.bundle/Contents/Resources/gk.db`
- `/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`

Ili možete ispisati prethodne informacije pomoću:
```bash
sudo spctl --list
```
Opcije **`--master-disable`** i **`--global-disable`** alata **`spctl`** će potpuno **onemogućiti** ove provere potpisa:
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

Moguće je **proveriti da li će App biti dozvoljen od GateKeeper-a** pomoću:
```bash
spctl --assess -v /Applications/App.app
```
Moguće je dodati nova pravila u GateKeeper da bi se omogućilo izvršavanje određenih aplikacija pomoću:
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
Što se tiče **kernel extensions**, folder `/var/db/SystemPolicyConfiguration` sadrži fajlove sa listama kext-ova koji su dozvoljeni za učitavanje. Pored toga, `spctl` ima entitlement `com.apple.private.iokit.nvram-csr` jer je sposoban da doda nova unapred odobrena kernel proširenja koja takođe moraju biti sačuvana u NVRAM-u u ključu `kext-allowed-teams`.

#### Managing Gatekeeper on macOS 15 (Sequoia) and later

- Dugogodišnji Finder **Ctrl+Open / Right‑click → Open** bypass je uklonjen; korisnici moraju eksplicitno dozvoliti blokiranu aplikaciju iz **System Settings → Privacy & Security → Open Anyway** nakon prvog dijaloga o blokadi.
- `spctl --master-disable/--global-disable` više nisu podržani; `spctl` je efektivno samo za čitanje za procenu i upravljanje oznakama dok se sprovođenje politike konfiguriše preko UI ili MDM.

Počevši od macOS 15 Sequoia, krajnji korisnici više ne mogu menjati Gatekeeper politiku preko `spctl`. Upravljanje se vrši putem System Settings ili raspoređivanjem MDM konfiguracionog profila sa `com.apple.systempolicy.control` payload-om. Primer isječka profila da bi se dozvolio App Store i identified developers (ali ne "Anywhere"): 

<details>
<summary>MDM profile to allow App Store and identified developers</summary>
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
</details>

### Fajlovi u karantinu

Prilikom **preuzimanja** aplikacije ili fajla, određene macOS **aplikacije** kao što su web pregledači ili klijenti elektronske pošte **dodaju prošireni atribut fajla**, poznat kao "**quarantine flag**", preuzetom fajlu. Ovaj atribut služi kao bezbednosna mera da **označi fajl** kao da potiče iz nepouzdanog izvora (internet) i potencijalno nosi rizike. Međutim, ne sve aplikacije dodaju ovaj atribut; na primer, uobičajeni BitTorrent klijenti obično zaobilaze ovaj proces.

**Prisutnost quarantine flag označava Gatekeeper bezbednosnu funkciju macOS-a kada korisnik pokuša da izvrši fajl.**

U slučaju kada **quarantine flag nije prisutan** (kao kod fajlova preuzetih preko nekih BitTorrent klijenata), Gatekeeper-ove **provere možda neće biti izvršene**. Stoga bi korisnici trebalo da budu oprezni pri otvaranju fajlova preuzetih sa manje bezbednih ili nepoznatih izvora.

> [!NOTE] > **Provera** **validnosti** potpisa koda je proces koji zahteva mnogo resursa i uključuje generisanje kriptografskih **hash-ova** koda i svih njegovih uvezanih resursa. Dalje, provera validnosti sertifikata uključuje obavljanje **onlajn provere** prema Apple-ovim serverima da bi se utvrdilo da li je sertifikat opozvan nakon izdavanja. Iz tih razloga, puna provera potpisa koda i notarizacije je **nepraktična za pokretanje pri svakom pokretanju aplikacije**.
>
> Stoga se ove provere **pokreću samo kada se izvršavaju aplikacije sa quarantined attribute.**

> [!WARNING]
> Ovaj atribut mora biti **postavljen od strane aplikacije koja kreira/preuzima** fajl.
>
> Međutim, fajlovi koje kreira sandboxovan proces će imati ovaj atribut postavljen za svaki fajl koji kreiraju. A aplikacije koje nisu sandboxovane mogu ga same postaviti, ili navesti ključ [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) u **Info.plist** koji će naterati sistem da postavi prošireni atribut `com.apple.quarantine` na kreiranim fajlovima,

Štaviše, svi fajlovi koje kreira proces koji poziva **`qtn_proc_apply_to_self`** su stavljeni u karantin. Ili API **`qtn_file_apply_to_path`** dodaje atribut karantina na određenu putanju fajla.

Moguće je **proveriti njegov status i omogućiti/onemogućiti** (zahteva root) pomoću:
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
Takođe možete **proveriti da li fajl ima prošireni atribut karantine** pomoću:
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
Proveri **vrednost** **proširenih** **atributa** i saznaj koja aplikacija je postavila quarantine atribut pomoću:
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
Zapravo, proces "može postaviti quarantine flags na fajlove koje kreira" (već sam pokušao da primenim USER_APPROVED flag u kreiranom fajlu, ali se neće primeniti):

<details>

<summary>Izvorni kod za primenu quarantine flags</summary>
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

I **uklonite** taj atribut pomoću:
```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```
I pronađi sve datoteke u karantinu pomoću:
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
Quarantine information is also stored in a central database managed by LaunchServices in **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`** which allows the GUI to obtain data about the file origins. Moreover this can be overwritten by applications which might be interested in hiding its origins. Moreover, this can be done from LaunchServices APIS.

#### **libquarantine.dylib**

This library exports several functions that allow to manipulate the extended attribute fields.

The `qtn_file_*` APIs deal with file quarantine policies, the `qtn_proc_*` APIs are applied to processes (files created by the process). The unexported `__qtn_syscall_quarantine*` functions are the ones that applies the policies which calls `mac_syscall` with "Quarantine" as first argument which sends the requests to `Quarantine.kext`.

#### **Quarantine.kext**

The kernel extension is only available through the **kernel cache on the system**; however, you _can_ download the **Kernel Debug Kit from** [**https://developer.apple.com/**](https://developer.apple.com/), which will contain a symbolicated version of the extension.

This Kext will hook via MACF several calls in order to traps all file lifecycle events: Creation, opening, renaming, hard-linkning... even `setxattr` to prevent it from setting the `com.apple.quarantine` extended attribute.

It also uses a couple of MIBs:

- `security.mac.qtn.sandbox_enforce`: Enforce quarantine along Sandbox
- `security.mac.qtn.user_approved_exec`: Querantined procs can only execute approved files

#### Provenance xattr (Ventura and later)

macOS 13 Ventura introduced a separate provenance mechanism which is populated the first time a quarantined app is allowed to run. Two artefacts are created:

- The `com.apple.provenance` xattr on the `.app` bundle directory (fixed-size binary value containing a primary key and flags).
- A row in the `provenance_tracking` table inside the ExecPolicy database at `/var/db/SystemPolicyConfiguration/ExecPolicy/` storing the app’s cdhash and metadata.

Practical usage:
```bash
# Inspect provenance xattr (if present)
xattr -p com.apple.provenance /Applications/Some.app | hexdump -C

# Observe Gatekeeper/provenance events in real time
log stream --style syslog --predicate 'process == "syspolicyd"'

# Retrieve historical Gatekeeper decisions for a specific bundle
log show --last 2d --style syslog --predicate 'process == "syspolicyd" && eventMessage CONTAINS[cd] "GK scan"'
```
### XProtect

XProtect je ugrađena **anti-malware** funkcija u macOS-u. XProtect **proverava svaku aplikaciju kada se prvi put pokrene ili izmeni u odnosu na svoju bazu** poznatog malvera i nesigurnih tipova fajlova. Kada preuzmete fajl putem određenih aplikacija, kao što su Safari, Mail ili Messages, XProtect automatski skenira fajl. Ako se poklapa sa nekim poznatim malverom u svojoj bazi, XProtect će **sprečiti pokretanje fajla** i upozoriti vas na pretnju.

Baza podataka XProtect-a je **redovno ažurirana** od strane Apple-a novim definicijama malvera, a ta ažuriranja se automatski preuzimaju i instaliraju na vaš Mac. To osigurava da je XProtect uvek ažuran sa najnovijim poznatim pretnjama.

Međutim, vredi napomenuti da **XProtect nije antivirus rešenje sa punim funkcijama**. On proverava samo određenu listu poznatih pretnji i ne obavlja skeniranje pri pristupu kao većina antivirus softvera.

Možete dobiti informacije o najnovijem XProtect ažuriranju pokretanjem:
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
XProtect se nalazi na SIP zaštićenoj lokaciji **/Library/Apple/System/Library/CoreServices/XProtect.bundle** i unutar bundle-a možete naći informacije koje XProtect koristi:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Dozvoljava kodu sa tim cdhashes vrednostima da koristi legacy entitlements.
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: Lista pluginova i ekstenzija kojima je zabranjeno učitavanje putem BundleID i TeamID ili koja naznačava minimalnu verziju.
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Yara pravila za detekciju malware-a.
- **`XProtect.bundle/Contents/Resources/gk.db`**: SQLite3 baza podataka sa heševima blokiranih aplikacija i TeamIDs.

Napomena: postoji i druga App na **`/Library/Apple/System/Library/CoreServices/XProtect.app`** povezana sa XProtect koja nije uključena u Gatekeeper proces.

> XProtect Remediator: Na modernim macOS sistemima, Apple isporučuje on-demand skenere (XProtect Remediator) koji se periodično pokreću preko launchd da detektuju i reše familije malware-a. Možete pratiti ove skenove u unified logs:
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### Nije Gatekeeper

> [!CAUTION]
> Imajte na umu da Gatekeeper **nije pokretan svaki put** kada pokrenete aplikaciju; samo _**AppleMobileFileIntegrity**_ (AMFI) će **verifikovati potpise izvršnog koda** kada pokrenete aplikaciju koja je već bila pokrenuta i verifikovana od strane Gatekeeper-a.

Zbog toga je ranije bilo moguće pokrenuti aplikaciju da je Gatekeeper kešira, pa zatim **modifikovati neizvršne fajlove aplikacije** (kao što su Electron asar ili NIB fajlovi) i, ukoliko nije bilo drugih zaštita, aplikacija bi bila **pokrenuta** sa **malicioznim** dodacima.

Međutim, sada to nije moguće jer macOS **sprečava menjanje fajlova** unutar application bundles. Dakle, ako probate [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md) attack, videćete da više nije moguće zloupotrebiti ga jer nakon što se aplikacija pokrene da bi je Gatekeeper keširao, nećete moći da izmenite bundle. I ako, na primer, promenite ime direktorijuma Contents u NotCon (kako je naznačeno u exploit-u), pa zatim pokrenete glavni binarni fajl aplikacije da ga Gatekeeper kešira, to će izazvati grešku i neće se izvršiti.

## Gatekeeper Bypasses

Bilo koji način da se zaobiđe Gatekeeper (uspeti naterati korisnika da preuzme nešto i izvrši to kada bi Gatekeeper trebalo da to zabrani) smatra se ranjivošću u macOS-u. Ovo su neki CVE-ovi dodeljeni tehnikama koje su omogućavale zaobilaženje Gatekeeper-a u prošlosti:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Uočen je slučaj da, ako se za ekstrakciju koristi **Archive Utility**, fajlovi sa **putanjama dužim od 886 karaktera** ne dobijaju extended atribut com.apple.quarantine. Ova situacija nehotično omogućava tim fajlovima da **zaobiđu Gatekeeper-ove** sigurnosne provere.

Pogledajte [**originalni izveštaj**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) za više informacija.

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Kada se aplikacija kreira pomoću **Automator**, informacije o tome šta je potrebno da se izvrši nalaze se u `application.app/Contents/document.wflow`, a ne u izvršnom fajlu. Izvršni fajl je samo generički Automator binarni nazvan **Automator Application Stub**.

Dakle, mogli ste da napravite da `application.app/Contents/MacOS/Automator\ Application\ Stub` **pokazuje simboličkom binarnom vezom na drugi Automator Application Stub u sistemu** i on će izvršiti ono što je u `document.wflow` (vaš skript) **bez pokretanja Gatekeeper-a** jer stvarni izvršni fajl nema quarantine xattr.

Primer očekivane lokacije: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Pogledajte [**originalni izveštaj**](https://ronmasas.com/posts/bypass-macos-gatekeeper) za više informacija.

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

U ovom bypass-u zip fajl je kreiran tako da se aplikacija počne kompresovati od `application.app/Contents` umesto od `application.app`. Dakle, **quarantine attr** je bio primenjen na sve **fajlove iz `application.app/Contents`** ali **ne i na `application.app`**, koji je Gatekeeper proveravao, pa je Gatekeeper bio zaobiđen jer kada je `application.app` pokrenut on **nije imao quarantine atribut.**
```bash
zip -r test.app/Contents test.zip
```
Check the [**original report**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) for more information.

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Iako su komponente različite, eksploatacija ove ranjivosti je veoma slična prethodnoj. U ovom slučaju će se generisati Apple Archive iz **`application.app/Contents`** tako da **`application.app` neće dobiti quarantine attr** kada se dekompresuje pomoću **Archive Utility**.
```bash
aa archive -d test.app/Contents -o test.app.aar
```
Pogledajte [**original report**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) za više informacija.

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

ACL **`writeextattr`** može da se koristi da spreči bilo koga da upiše atribut u fajl:
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
Štaviše, **AppleDouble** file format kopira datoteku uključujući njene ACEs.

U [**source code**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) može se videti da će se tekstualna reprezentacija ACL-a pohranjena unutar xattr-a nazvanog **`com.apple.acl.text`** postaviti kao ACL u dekompresovanoj datoteci. Dakle, ako ste kompresovali aplikaciju u zip fajl koristeći **AppleDouble** file format sa ACL-om koji sprečava da joj se drugi xattr-ovi upisuju... quarantine xattr nije bio postavljen u aplikaciju:
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
Pogledajte [**original report**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) za više informacija.

Imajte na umu da se ovo takođe može iskoristiti pomoću AppleArchives:
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

Otkriveno je da **Google Chrome nije postavljao atribut karantina** za preuzete fajlove zbog nekih internih problema u macOS-u.

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDouble formati fajlova čuvaju atribute fajla u posebnom fajlu koji počinje sa `._`, što pomaže da se atributi fajlova kopiraju **na macOS mašinama**. Međutim, primećeno je da nakon dekompresije AppleDouble fajla, fajlu koji počinje sa `._` **nije dodeljen atribut karantina**.
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you downloaded the resulting test.aar and decompress it, the file test/._a won't have a quarantitne attribute
```
Ako je moguće kreirati fajl kome nije postavljen quarantine attribute, bilo je **moguće zaobići Gatekeeper.** Trik je bio da **napravite DMG file application** koristeći AppleDouble name convention (počnite ime sa `._`) i da kreirate **vidljiv fajl kao sym link na ovaj skriveni** fajl bez quarantine attribute.\
Kada se **dmg file pokrene**, pošto nema quarantine attribute, on će **zaobići Gatekeeper**.
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

A Gatekeeper bypass fixed in macOS Sonoma 14.0 allowed crafted apps to run without prompting. Details were disclosed publicly after patching and the issue was actively exploited in the wild before fix. Ensure Sonoma 14.0 or later is installed.

### [CVE-2024-27853]

A Gatekeeper bypass in macOS 14.4 (released March 2024) stemming from `libarchive` handling of malicious ZIPs allowed apps to evade assessment. Update to 14.4 or later where Apple addressed the issue.

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

An **Automator Quick Action workflow** embedded in a downloaded app could trigger without Gatekeeper assessment, because workflows were treated as data and executed by the Automator helper outside the normal notarization prompt path. A crafted `.app` bundling a Quick Action that runs a shell script (e.g., inside `Contents/PlugIns/*.workflow/Contents/document.wflow`) could therefore execute immediately on launch. Apple added an extra consent dialog and fixed the assessment path in Ventura **13.7**, Sonoma **14.7**, and Sequoia **15**.

### Third‑party unarchivers mis‑propagating quarantine (2023–2024)

Several vulnerabilities in popular extraction tools (e.g., The Unarchiver) caused files extracted from archives to miss the `com.apple.quarantine` xattr, enabling Gatekeeper bypass opportunities. Always rely on macOS Archive Utility or patched tools when testing, and validate xattrs after extraction.

### uchg (from this [talk](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

- Napravite direktorijum koji sadrži aplikaciju.
- Dodajte uchg na aplikaciju.
- Kompresujte aplikaciju u tar.gz fajl.
- Pošaljite tar.gz fajl žrtvi.
- Žrtva otvori tar.gz fajl i pokrene aplikaciju.
- Gatekeeper ne proverava aplikaciju.

### Prevent Quarantine xattr

In an ".app" bundle if the quarantine xattr is not added to it, when executing it **Gatekeeper won't be triggered**.


## References

- Apple Platform Security: About the security content of macOS Sonoma 14.4 (includes CVE-2024-27853) – [https://support.apple.com/en-us/HT214084](https://support.apple.com/en-us/HT214084)
- Eclectic Light: How macOS now tracks the provenance of apps – [https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- Apple: About the security content of macOS Sonoma 14.7 / Ventura 13.7 (CVE-2024-44128) – [https://support.apple.com/en-us/121234](https://support.apple.com/en-us/121234)
- MacRumors: macOS 15 Sequoia removes the Control‑click “Open” Gatekeeper bypass – [https://www.macrumors.com/2024/06/11/macos-sequoia-removes-open-anyway/](https://www.macrumors.com/2024/06/11/macos-sequoia-removes-open-anyway/)

{{#include ../../../banners/hacktricks-training.md}}
