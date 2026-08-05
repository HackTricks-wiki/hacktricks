# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

**Gatekeeper** je bezbednosna funkcija razvijena za Mac operativne sisteme, osmišljena da obezbedi da korisnici na svojim sistemima **pokreću samo pouzdan software**. Funkcioniše tako što **validira software** koji korisnik preuzme i pokuša da otvori iz **izvora izvan App Store-a**, kao što su aplikacija, plug-in ili instalacioni paket.

Ključni mehanizam Gatekeeper-a je proces **verifikacije**. Proverava da li je preuzeti software **potpisao prepoznati developer**, čime se potvrđuje autentičnost software-a. Takođe utvrđuje da li je software **notarizovao Apple**, čime se potvrđuje da ne sadrži poznat zlonameran sadržaj i da nije menjan nakon notarizacije.

Pored toga, Gatekeeper pojačava kontrolu korisnika i bezbednost tako što **traži od korisnika da odobri otvaranje** preuzetog software-a prvi put. Ova zaštita pomaže u sprečavanju korisnika da nenamerno pokrene potencijalno štetan izvršni kod koji je možda pogrešno smatrao bezopasnim data fajlom.

### Potpisi aplikacija

Potpisi aplikacija, poznati i kao code signatures, predstavljaju kritičnu komponentu Apple-ove bezbednosne infrastrukture. Koriste se za **proveru identiteta autora software-a** (developera) i za osiguravanje da kod nije menjan od trenutka kada je poslednji put potpisan.

Evo kako to funkcioniše:

1. **Potpisivanje aplikacije:** Kada je developer spreman da distribuira svoju aplikaciju, on **potpisuje aplikaciju pomoću privatnog ključa**. Ovaj privatni ključ povezan je sa **sertifikatom koji Apple izdaje developeru** kada se on učlani u Apple Developer Program. Proces potpisivanja podrazumeva kreiranje kriptografskog hash-a svih delova aplikacije i šifrovanje tog hash-a privatnim ključem developera.
2. **Distribucija aplikacije:** Potpisana aplikacija se zatim distribuira korisnicima zajedno sa sertifikatom developera, koji sadrži odgovarajući javni ključ.
3. **Verifikacija aplikacije:** Kada korisnik preuzme aplikaciju i pokuša da je pokrene, njegov Mac operativni sistem koristi javni ključ iz sertifikata developera da dešifruje hash. Zatim ponovo izračunava hash na osnovu trenutnog stanja aplikacije i upoređuje ga sa dešifrovanim hash-om. Ako se poklapaju, to znači da **aplikacija nije menjana** od trenutka kada ju je developer potpisao, pa sistem dozvoljava njeno pokretanje.

Potpisi aplikacija predstavljaju ključni deo Apple-ove Gatekeeper tehnologije. Kada korisnik pokuša da **otvori aplikaciju preuzetu sa interneta**, Gatekeeper proverava potpis aplikacije. Ako je potpisana sertifikatom koji je Apple izdao poznatom developeru i kod nije menjan, Gatekeeper dozvoljava pokretanje aplikacije. U suprotnom, blokira aplikaciju i upozorava korisnika.

Počev od macOS Catalina, **Gatekeeper takođe proverava da li je aplikaciju notarizovao** Apple, čime se dodaje još jedan nivo bezbednosti. Proces notarizacije proverava da li aplikacija sadrži poznate bezbednosne probleme i zlonameran kod. Ako prođe ove provere, Apple dodaje ticket aplikaciji koji Gatekeeper može da verifikuje.

#### Provera potpisa

Prilikom provere nekog **malware sample-a** uvek treba da **proverite potpis** binarnog fajla, jer **developer** koji ga je potpisao možda već ima **vezu** sa **malware-om.**
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

Apple-ov proces notarizacije služi kao dodatna zaštita korisnika od potencijalno štetnog softvera. On podrazumeva **da developer pošalje svoju aplikaciju na ispitivanje** servisu **Apple's Notary Service**, koji ne treba mešati sa App Review procesom. Ovaj servis je **automatizovani sistem** koji proverava poslati softver u potrazi za **malicioznim sadržajem** i potencijalnim problemima sa code-signingom.

Ako softver **prođe** ovu proveru bez ikakvih problema, Notary Service generiše ticket za notarizaciju. Developer zatim mora da **pripoji ovaj ticket svom softveru**, što je proces poznat kao „stapling“. Osim toga, ticket za notarizaciju se objavljuje i online, gde mu Gatekeeper, Apple-ova bezbednosna tehnologija, može pristupiti.

Prilikom prve instalacije ili izvršavanja softvera, postojanje ticketa za notarizaciju - bilo da je pripojen izvršnom fajlu ili pronađen online - **obaveštava Gatekeeper da je Apple notarizovao softver**. Kao rezultat toga, Gatekeeper prikazuje opisnu poruku u dijalogu pri prvom pokretanju, koja navodi da je Apple proverio softver u potrazi za malicioznim sadržajem. Ovaj proces povećava poverenje korisnika u bezbednost softvera koji instaliraju ili pokreću na svojim sistemima.

### spctl & syspolicyd

> [!CAUTION]
> Imajte na umu da od verzije Sequoia **`spctl`** više ne dozvoljava izmenu Gatekeeper konfiguracije.

**`spctl`** je CLI alat za izlistavanje i interakciju sa Gatekeeper-om (sa `syspolicyd` daemon-om putem XPC poruka). Na primer, moguće je videti **status** Gatekeeper-a pomoću:
```bash
# Check the status
spctl --status
```
> [!CAUTION]
> Imajte na umu da se provere potpisa GateKeeper-a obavljaju samo nad **datotekama sa atributom Quarantine**, a ne nad svakom datotekom.

GateKeeper će proveriti da li se, na osnovu **podešavanja i potpisa**, neki binary može izvršiti:

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`** je glavni daemon odgovoran za sprovođenje Gatekeeper-a. Održava bazu podataka koja se nalazi u `/var/db/SystemPolicy`, a kod koji podržava ovu [bazu podataka možete pronaći ovde](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp), dok se [SQL template nalazi ovde](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql). Imajte na umu da SIP ne ograničava ovu bazu podataka i da je root može menjati, dok se baza podataka `/var/db/.SystemPolicy-default` koristi kao originalna rezervna kopija u slučaju da se druga baza ošteti.

Pored toga, bundles **`/var/db/gke.bundle`** i **`/var/db/gkopaque.bundle`** sadrže datoteke sa pravilima koja se unose u bazu podataka. Ovu bazu podataka možete proveriti kao root pomoću:
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
**`syspolicyd`** takođe izlaže XPC server sa različitim operacijama kao što su `assess`, `update`, `record` i `cancel`, kojima se takođe može pristupiti pomoću **`Security.framework`-ovih `SecAssessment*`** API-ja, a **`spctl`** zapravo komunicira sa **`syspolicyd`** putem XPC-ja.

Obratite pažnju na to da se prvo pravilo završava sa "**App Store**", a drugo sa "**Developer ID**", kao i na to da je na prethodnoj slici bilo **omogućeno izvršavanje aplikacija iz App Store-a i aplikacija identifikovanih developera**.\
Ako tu postavku **izmenite** na App Store, pravila "**Notarized Developer ID" će nestati**.

Tu se takođe nalazi na hiljade pravila **tipa GKE**:
```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```
Ovo su hash-evi iz:

- `/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`
- `/var/db/gke.bundle/Contents/Resources/gk.db`
- `/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`

Ili prethodne informacije možete izlistati pomoću:
```bash
sudo spctl --list
```
Opcije **`--master-disable`** i **`--global-disable`** alata **`spctl`** će u potpunosti **onemogućiti** ove provere potpisa:
```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```
Kada je u potpunosti omogućen, pojaviće se nova opcija:

<figure><img src="../../../images/image (1151).png" alt=""><figcaption></figcaption></figure>

Moguće je **proveriti da li će App biti dozvoljen od strane GateKeeper-a** pomoću:
```bash
spctl --assess -v /Applications/App.app
```
Moguće je dodati nova pravila u GateKeeper koja dozvoljavaju izvršavanje određenih aplikacija pomoću:
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
Kada je reč o **kernel extensions**, folder `/var/db/SystemPolicyConfiguration` sadrži fajlove sa listama kexts kojima je dozvoljeno učitavanje. Pored toga, `spctl` ima entitlement `com.apple.private.iokit.nvram-csr`, jer može da dodaje nove unapred odobrene kernel extensions, koje takođe moraju da budu sačuvane u NVRAM-u u ključu `kext-allowed-teams`.

#### Upravljanje Gatekeeper-om na macOS 15 (Sequoia) i novijim verzijama

- Dugogodišnje zaobilaženje u Finder-u **Ctrl+Open / Right-click → Open** je uklonjeno; korisnici sada moraju izričito da dozvole blokiranu aplikaciju preko **System Settings → Privacy & Security → Open Anyway** nakon prvog dijaloga o blokiranju.<sup>[4]</sup>
- `spctl --master-disable/--global-disable` više nije prihvaćen; `spctl` je efektivno read-only za procenu i upravljanje oznakama, dok se sprovođenje policy-ja konfiguriše putem UI-ja ili MDM-a.

Počev od macOS 15 Sequoia, krajnji korisnici više ne mogu da menjaju Gatekeeper policy iz `spctl`-a. Upravljanje se obavlja putem System Settings-a ili postavljanjem MDM configuration profile-a sa `com.apple.systempolicy.control` payload-om. Primer dela profile-a kojim se dozvoljavaju App Store i identifikovani developers (ali ne i „Anywhere“):

<details>
<summary>MDM profile za dozvolu App Store-a i identifikovanih developers</summary>
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

### Datoteke u karantinu

Prilikom **preuzimanja** aplikacije ili datoteke, određene macOS **aplikacije**, kao što su web browseri ili email klijenti, **dodaju prošireni atribut datoteke**, poznat kao "**quarantine flag**", preuzetoj datoteci. Ovaj atribut služi kao bezbednosna mera za **označavanje datoteke** kao datoteke koja potiče iz nepouzdanog izvora (interneta) i koja potencijalno može predstavljati rizik. Međutim, ne dodaju sve aplikacije ovaj atribut; na primer, uobičajeni BitTorrent client software ga obično zaobilazi.

**Prisustvo quarantine flag-a signalizira macOS Gatekeeper security feature-u kada korisnik pokuša da izvrši datoteku**.

U slučaju kada **quarantine flag nije prisutan** (kao kod datoteka preuzetih putem nekih BitTorrent klijenata), Gatekeeper **provere možda neće biti izvršene**. Zbog toga korisnici treba da budu oprezni prilikom otvaranja datoteka preuzetih iz manje bezbednih ili nepoznatih izvora.

> [!NOTE] > **Provera** **validnosti** code signatures predstavlja proces koji intenzivno koristi resurse i uključuje generisanje kriptografskih **hash-eva** koda i svih resursa uključenih u njega. Osim toga, provera validnosti sertifikata podrazumeva **online proveru** Apple servera kako bi se utvrdilo da li je sertifikat opozvan nakon izdavanja. Iz ovih razloga, potpuna provera code signature-a i notarization-a **nije praktična pri svakom pokretanju aplikacije**.
>
> Zato se ove provere **izvršavaju samo prilikom pokretanja aplikacija sa quarantine atributom.**

> [!WARNING]
> Ovaj atribut mora biti **postavljen od strane aplikacije koja kreira/preuzima** datoteku.
>
> Međutim, sandboxed datoteke će imati ovaj atribut postavljen na svaku datoteku koju kreiraju. Non sandboxed aplikacije mogu same da ga postave ili da navedu ključ [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) u fajlu **Info.plist**, čime će sistem postaviti prošireni atribut `com.apple.quarantine` na kreirane datoteke,

Pored toga, sve datoteke koje kreira proces koji poziva **`qtn_proc_apply_to_self`** biće stavljene u karantin. Takođe, API **`qtn_file_apply_to_path`** dodaje quarantine atribut na navedenu putanju datoteke.

Moguće je **proveriti njegov status i uključiti/isključiti ga** (potreban je root) pomoću:
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
Takođe možete **proveriti da li datoteka ima quarantine extended attribute** pomoću:
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
Proverite **vrednost** **proširenih** **atributa** i saznajte koja je aplikacija upisala quarantine atribut pomoću:
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
Zapravo, proces „could set quarantine flags to the files it creates“ (već sam pokušao da primenim USER_APPROVED flag na kreiranu datoteku, ali se ne primenjuje):

<details>

<summary>Source Code apply quarantine flags</summary>
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
I pronađite sve fajlove u karantinu pomoću:
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
Informacije o Quarantine takođe se čuvaju u centralnoj bazi podataka kojom upravlja LaunchServices, u **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**, što GUI-ju omogućava da dobije podatke o poreklu fajlova. Osim toga, aplikacije koje žele da sakriju poreklo fajlova mogu da prepišu ove podatke. To je moguće uraditi i putem LaunchServices API-ja.

#### **libquarantine.dylib**

Ova biblioteka izvozi nekoliko funkcija koje omogućavaju manipulaciju poljima proširenih atributa.

`qtn_file_*` API-ji obrađuju politike karantina fajlova, dok se `qtn_proc_*` API-ji primenjuju na procese (fajlove koje je proces kreirao). Neizvezene funkcije `__qtn_syscall_quarantine*` primenjuju politike i pozivaju `mac_syscall` sa argumentom `"Quarantine"` kao prvim argumentom, čime se zahtevi prosleđuju ka `Quarantine.kext`.

#### **Quarantine.kext**

Kernel ekstenzija je dostupna samo kroz **kernel cache na sistemu**; međutim, možete preuzeti **Kernel Debug Kit sa** [**https://developer.apple.com/**](https://developer.apple.com/), koji sadrži verziju ekstenzije sa simbolima.

Ovaj Kext koristi MACF za presretanje nekoliko poziva kako bi pratio sve događaje u životnom ciklusu fajlova: kreiranje, otvaranje, preimenovanje, kreiranje hard linkova... čak i `setxattr`, kako bi sprečio postavljanje proširenog atributa `com.apple.quarantine`.

Takođe koristi nekoliko MIB-ova:

- `security.mac.qtn.sandbox_enforce`: Primenjuje Quarantine zajedno sa Sandbox-om
- `security.mac.qtn.user_approved_exec`: Procesi u karantinu mogu da izvršavaju samo odobrene fajlove

#### Provenance xattr (Ventura i novije verzije)

macOS 13 Ventura je uveo zaseban mehanizam provenance koji se popunjava prvi put kada se aplikaciji u karantinu dozvoli pokretanje.<sup>[2]</sup> Kreiraju se dva artefakta:

- `com.apple.provenance` xattr na `.app` bundle direktorijumu (binarna vrednost fiksne veličine koja sadrži primarni ključ i zastavice).
- Red u tabeli `provenance_tracking` unutar ExecPolicy baze podataka na lokaciji `/var/db/SystemPolicyConfiguration/ExecPolicy/`, u kojem se čuvaju cdhash aplikacije i metapodaci.

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

XProtect je ugrađena **anti-malware** funkcija u macOS-u. XProtect **proverava svaku aplikaciju prilikom njenog prvog pokretanja ili izmene u odnosu na svoju bazu podataka** poznatog malware-a i nebezbednih tipova datoteka. Kada preuzmete datoteku putem određenih aplikacija, kao što su Safari, Mail ili Messages, XProtect automatski skenira datoteku. Ako se podudara sa nekim poznatim malware-om iz njegove baze podataka, XProtect će **sprečiti pokretanje datoteke** i upozoriti vas na pretnju.

Apple **redovno ažurira** XProtect bazu podataka novim definicijama malware-a, a ova ažuriranja se automatski preuzimaju i instaliraju na vaš Mac. To obezbeđuje da XProtect uvek bude ažuriran najnovijim poznatim pretnjama.

Međutim, važno je napomenuti da **XProtect nije potpuno antivirusno rešenje**. On proverava samo određenu listu poznatih pretnji i ne obavlja on-access scanning kao većina antivirusnog softvera.

Informacije o najnovijem XProtect ažuriranju možete dobiti pokretanjem:
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
XProtect se nalazi na SIP protected lokaciji **/Library/Apple/System/Library/CoreServices/XProtect.bundle**, a unutar bundle-a možete pronaći informacije koje XProtect koristi:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Dozvoljava kodu sa tim cdhash vrednostima da koristi legacy entitlements.
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: Lista plugin-ova i ekstenzija kojima nije dozvoljeno učitavanje na osnovu BundleID-ja i TeamID-ja ili koja navodi minimalnu verziju.
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Yara pravila za detekciju malware-a.
- **`XProtect.bundle/Contents/Resources/gk.db`**: SQLite3 baza podataka sa hash vrednostima blokiranih aplikacija i TeamID vrednostima.

Imajte na umu da postoji još jedan App na lokaciji **`/Library/Apple/System/Library/CoreServices/XProtect.app`**, povezan sa XProtect-om, koji nije uključen u Gatekeeper proces.

> XProtect Remediator: Na modernom macOS-u, Apple isporučuje on-demand skenere (XProtect Remediator) koji se periodično pokreću putem launchd-a radi detekcije i saniranja porodica malware-a. Ova skeniranja možete pratiti u unified log-ovima:
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### Nije Gatekeeper

> [!CAUTION]
> Imajte na umu da se Gatekeeper **ne izvršava svaki put** kada izvršite aplikaciju; samo će _**AppleMobileFileIntegrity**_ (AMFI) **proveriti potpise izvršnog koda** kada izvršite aplikaciju koja je već bila izvršena i proverena od strane Gatekeeper-a.

Zbog toga je ranije bilo moguće izvršiti aplikaciju kako bi je Gatekeeper keširao, zatim **izmeniti neizvršne fajlove aplikacije** (kao što su Electron asar ili NIB fajlovi), pa bi, ako nisu postojale druge zaštite, aplikacija bila **izvršena** sa **malicioznim** dodacima.

Međutim, sada to nije moguće zato što macOS **sprečava izmenu fajlova** unutar application bundle-ova. Dakle, ako pokušate [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md) napad, videćete da ga više nije moguće zloupotrebiti, jer nakon izvršavanja aplikacije radi njenog keširanja u Gatekeeper-u nećete moći da izmenite bundle. Ako, na primer, promenite naziv Contents direktorijuma u NotCon (kao što je navedeno u exploit-u), a zatim izvršite glavni binary aplikacije kako biste je keširali u Gatekeeper-u, to će izazvati grešku i aplikacija se neće izvršiti.

## Gatekeeper Bypasses

Svaki način za zaobilaženje Gatekeeper-a (uspešno navođenje korisnika da preuzme i izvrši nešto što bi Gatekeeper trebalo da zabrani) smatra se ranjivošću u macOS-u. Ovo su neki CVE-ovi dodeljeni tehnikama koje su ranije omogućavale zaobilaženje Gatekeeper-a:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Uočeno je da, ako se **Archive Utility** koristi za raspakivanje, fajlovi sa **putanjama dužim od 886 karaktera** ne dobijaju com.apple.quarantine extended attribute. Ova situacija nenamerno omogućava tim fajlovima da **zaobiđu Gatekeeper-ove** bezbednosne provere.<sup>[5]</sup>

Pogledajte [**originalni izveštaj**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) za više informacija.

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Kada se aplikacija kreira pomoću **Automator-a**, informacije o tome šta je potrebno za njeno izvršavanje nalaze se unutar `application.app/Contents/document.wflow`, a ne u executable-u. Executable je samo generički Automator binary pod nazivom **Automator Application Stub**.

Zato je bilo moguće da `application.app/Contents/MacOS/Automator\ Application\ Stub` **pomoću simboličkog linka pokazuje na drugi Automator Application Stub unutar sistema**, koji će izvršiti sadržaj `document.wflow` fajla (vaš script) **bez pokretanja Gatekeeper-a**, jer stvarni executable nema quarantine xattr.<sup>[6]</sup>

Primer očekivane lokacije: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Pogledajte [**originalni izveštaj**](https://ronmasas.com/posts/bypass-macos-gatekeeper) za više informacija.

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

Kod ovog bypass-a, zip fajl je kreiran tako da kompresija počinje od `application.app/Contents`, umesto od `application.app`. Zbog toga je **quarantine attr** primenjen na sve **fajlove iz `application.app/Contents`**, ali ne i na **`application.app`**, koji je Gatekeeper proveravao. Gatekeeper je zato zaobiđen, jer kada je `application.app` pokrenut, **nije imao quarantine attribute.**<sup>[7]</sup>
```bash
zip -r test.app/Contents test.zip
```
Pogledajte [**originalni izveštaj**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) za više informacija.

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Čak i ako se komponente razlikuju, exploitation ove vulnerability je veoma sličan prethodnom. U ovom slučaju generisaćemo Apple Archive iz **`application.app/Contents`**, tako da **`application.app` neće dobiti quarantine attr** kada ga dekompresuje **Archive Utility**.<sup>[8]</sup>
```bash
aa archive -d test.app/Contents -o test.app.aar
```
Pogledajte [**originalni izveštaj**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) za više informacija.

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

ACL **`writeextattr`** može da se koristi za sprečavanje bilo koga da upisuje atribut u datoteku:
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
Štaviše, format datoteka **AppleDouble** kopira datoteku zajedno sa njenim ACE-ovima.<sup>[9]</sup>

U [**izvornom kodu**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) moguće je videti da će ACL tekstualna reprezentacija sačuvana unutar xattr-a pod nazivom **`com.apple.acl.text`** biti postavljena kao ACL u dekompresovanoj datoteci. Dakle, ako ste aplikaciju kompresovali u zip datoteku koristeći format datoteka **AppleDouble**, sa ACL-om koji sprečava upisivanje drugih xattr-ova u nju... quarantine xattr nije bio postavljen u aplikaciji:
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
Proverite [**originalni izveštaj**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) za više informacija.

Imajte na umu da je ovo takođe moglo biti iskorišćeno pomoću AppleArchives:
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

Otkriveno je da **Google Chrome nije postavljao quarantine atribut** preuzetim datotekama zbog određenih internih problema u macOS-u.<sup>[10]</sup>

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDouble formati datoteka čuvaju atribute datoteke u zasebnoj datoteci čiji naziv počinje sa `._`, što omogućava kopiranje atributa datoteka **između macOS računara**. Međutim, primećeno je da nakon dekompresovanja AppleDouble datoteke, datoteci čiji naziv počinje sa `._` **nije bio dodeljen quarantine atribut**.<sup>[11]</sup>
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you downloaded the resulting test.aar and decompress it, the file test/._a won't have a quarantitne attribute
```
Mogućnost kreiranja datoteke kojoj neće biti postavljen atribut quarantine **omogućila je zaobilaženje Gatekeeper-a.** Trik je bio u tome da se kreira **DMG file application** koristeći AppleDouble konvenciju imenovanja (započeti naziv sa `._`) i kreira **vidljiva datoteka kao sym link ka ovoj skrivenoj** datoteci bez atributa quarantine.\
Kada se **dmg file izvrši**, pošto nema atribut quarantine, on će **zaobići Gatekeeper**.
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

Gatekeeper bypass ispravljen u macOS Sonoma 14.0 omogućavao je pokretanje posebno napravljenih aplikacija bez prikaza upita. Detalji su javno objavljeni nakon objavljivanja zakrpe, a problem je pre ispravke aktivno iskorišćavan u praksi. Uverite se da je instaliran Sonoma 14.0 ili noviji.

### [CVE-2024-27853]

Gatekeeper bypass u macOS 14.4 (objavljenom u martu 2024), koji je proizašao iz načina na koji `libarchive` obrađuje zlonamerne ZIP arhive, omogućavao je aplikacijama da zaobiđu proveru. Ažurirajte na 14.4 ili noviji, gde je Apple rešio ovaj problem.<sup>[1]</sup>

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

**Automator Quick Action workflow** ugrađen u preuzetu aplikaciju mogao je da se pokrene bez Gatekeeper provere, jer su workflow-i tretirani kao podaci, a izvršavao ih je Automator pomoćni proces izvan uobičajenog toka za prikaz upita u vezi sa notarizacijom. Zbog toga je posebno napravljena `.app` aplikacija koja sadrži Quick Action koji pokreće shell skriptu (npr. unutar `Contents/PlugIns/*.workflow/Contents/document.wflow`) mogla odmah da se izvrši pri pokretanju. Apple je dodao dodatni dijalog za saglasnost i ispravio tok provere u Ventura **13.7**, Sonoma **14.7** i Sequoia **15**.<sup>[3]</sup>

### Problemi sa prosleđivanjem quarantine oznake u third-party unarchiver alatima (2023–2024)

Nekoliko ranjivosti u popularnim alatima za ekstrakciju (npr. The Unarchiver) dovodilo je do toga da datoteke ekstrahovane iz arhiva ne dobiju `com.apple.quarantine` xattr, čime su nastajale mogućnosti za Gatekeeper bypass. Prilikom testiranja uvek koristite macOS Archive Utility ili zakrpane alate i proverite xattr vrednosti nakon ekstrakcije.

### uchg (iz ovog [predavanja](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

- Kreirajte direktorijum koji sadrži aplikaciju.
- Dodajte uchg aplikaciji.
- Kompresujte aplikaciju u tar.gz datoteku.
- Pošaljite tar.gz datoteku žrtvi.
- Žrtva otvara tar.gz datoteku i pokreće aplikaciju.
- Gatekeeper ne proverava aplikaciju.<sup>[12]</sup>

### Sprečavanje quarantine xattr

Ako se u ".app" bundle-u ne doda quarantine xattr, prilikom izvršavanja **Gatekeeper se neće pokrenuti**.


## Reference

- [1] [Apple Platform Security: O bezbednosnom sadržaju macOS Sonoma 14.4 (uključuje CVE-2024-27853)](https://support.apple.com/en-us/HT214084)
- [2] [Eclectic Light: Kako macOS sada prati poreklo aplikacija](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- [3] [Apple: O bezbednosnom sadržaju macOS Sonoma 14.7 / Ventura 13.7 (CVE-2024-44128)](https://support.apple.com/en-us/121234)
- [4] [MacRumors: macOS 15 Sequoia uklanja Gatekeeper bypass pomoću opcije „Open“ uz pritisnut taster Control](https://www.macrumors.com/2024/06/11/macos-sequoia-removes-open-anyway/)
- [5] [WithSecure Labs: Otkrivanje CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)
- [6] [CVE-2021-30990, Zaobilaženje macOS Gatekeeper-a](https://ronmasas.com/posts/bypass-macos-gatekeeper)
- [7] [Jamf Threat Labs identifikuje ranjivost u Safari-ju koja omogućava Gatekeeper bypass](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)
- [8] [Jamf Threat Labs identifikuje ranjivost u macOS Archive Utility-ju koja omogućava Gatekeeper bypass (CVE-2022-32910)](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)
- [9] [Gatekeeper-ova Ahilova peta: Otkrivanje ranjivosti u macOS-u](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [10] [F-Secure: Otkrivanje Gatekeeper bypass-a (CVE-2023-27943)](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)
- [11] [Pronalaženje i prijavljivanje Gatekeeper bypass exploita uz pomoć Mac Monitor-a](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)
- [12] [CODE BLUE 2023: Zaobilaženje macOS bezbednosnih mehanizama i mehanizama privatnosti — od Gatekeeper-a do System Integrity Protection-a (Koh Nakagawa)](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf)

{{#include ../../../banners/hacktricks-training.md}}
