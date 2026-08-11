# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

**Gatekeeper** je bezbednosna funkcija razvijena za Mac operativne sisteme, osmišljena da obezbedi da korisnici **pokreću samo pouzdan softver** na svojim sistemima. Funkcioniše tako što **proverava softver** koji korisnik preuzme i pokuša da otvori iz **izvora izvan App Store-a**, kao što su aplikacija, plug-in ili instalacioni paket.

Ključni mehanizam Gatekeeper-a je proces **verifikacije**. Proverava da li je preuzeti softver **potpisao prepoznati developer**, čime se obezbeđuje autentičnost softvera. Takođe utvrđuje da li je softver **notarizovao Apple**, potvrđujući da ne sadrži poznat zlonamerni sadržaj i da nakon notarizacije nije menjan.

Pored toga, Gatekeeper dodatno jača kontrolu korisnika i bezbednost tako što **traži od korisnika odobrenje za otvaranje** preuzetog softvera pri prvom pokretanju. Ova zaštita pomaže u sprečavanju korisnika da nenamerno pokrene potencijalno štetan izvršni kod koji je možda zamenio za bezazleni data fajl.

### Application Signatures

Potpisi aplikacija, poznati i kao code signatures, predstavljaju ključnu komponentu Apple-ove bezbednosne infrastrukture. Koriste se za **proveru identiteta autora softvera** (developera) i za potvrdu da kod nije menjan od poslednjeg potpisivanja.

Evo kako to funkcioniše:

1. **Potpisivanje aplikacije:** Kada je developer spreman da distribuira svoju aplikaciju, on **potpisuje aplikaciju koristeći privatni ključ**. Ovaj privatni ključ povezan je sa **sertifikatom koji Apple izdaje developeru** kada se registruje u Apple Developer Program-u. Proces potpisivanja uključuje kreiranje kriptografskog hash-a svih delova aplikacije i šifrovanje tog hash-a privatnim ključem developera.
2. **Distribucija aplikacije:** Potpisana aplikacija se zatim distribuira korisnicima zajedno sa sertifikatom developera, koji sadrži odgovarajući javni ključ.
3. **Verifikacija aplikacije:** Kada korisnik preuzme aplikaciju i pokuša da je pokrene, njegov Mac operativni sistem koristi javni ključ iz sertifikata developera za dešifrovanje hash-a. Zatim ponovo izračunava hash na osnovu trenutnog stanja aplikacije i poredi ga sa dešifrovanim hash-om. Ako se podudaraju, to znači da **aplikacija nije menjana** od kada ju je developer potpisao, pa sistem dozvoljava njeno pokretanje.

Potpisi aplikacija predstavljaju ključni deo Apple-ove Gatekeeper tehnologije. Kada korisnik pokuša da **otvori aplikaciju preuzetu sa interneta**, Gatekeeper proverava potpis aplikacije. Ako je potpisana sertifikatom koji je Apple izdao poznatom developeru i kod nije menjan, Gatekeeper dozvoljava pokretanje aplikacije. U suprotnom, blokira aplikaciju i obaveštava korisnika.

Počev od macOS Catalina, **Gatekeeper takođe proverava da li je Apple notarizovao aplikaciju**, čime se dodaje još jedan sloj bezbednosti. Proces notarizacije proverava da li aplikacija sadrži poznate bezbednosne probleme i malicious code, a ako prođe ove provere, Apple aplikaciji dodaje ticket koji Gatekeeper može da verifikuje.

#### Provera potpisa

Prilikom provere nekog **malware sample-a** uvek treba **proveriti potpis** binarnog fajla, jer developer koji ga je potpisao možda već ima **vezu** sa **malware-om.**
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

Apple-ov proces notarizacije služi kao dodatna zaštita korisnika od potencijalno štetnog softvera. On podrazumeva da **developer šalje svoju aplikaciju na proveru** od strane **Apple's Notary Service**, što ne treba mešati sa App Review procesom. Ovaj servis je **automatizovani sistem** koji proverava poslati softver u potrazi za **malicioznim sadržajem** i potencijalnim problemima sa potpisivanjem koda.

Ako softver **prođe** ovu proveru bez uočenih problema, Notary Service generiše ticket notarizacije. Developer zatim mora da **priloži ovaj ticket svom softveru**, što je proces poznat kao „stapling“. Pored toga, ticket notarizacije se objavljuje i online, gde mu Gatekeeper, Apple-ova bezbednosna tehnologija, može pristupiti.

Prilikom prve instalacije ili izvršavanja softvera od strane korisnika, postojanje ticketa notarizacije - bilo da je priložen izvršnoj datoteci ili pronađen online - **obaveštava Gatekeeper da je Apple notarizovao softver**. Kao rezultat toga, Gatekeeper prikazuje opisnu poruku u dijalogu pri prvom pokretanju, navodeći da je Apple proverio softver u potrazi za malicioznim sadržajem. Ovaj proces tako povećava poverenje korisnika u bezbednost softvera koji instaliraju ili pokreću na svojim sistemima.

### spctl & syspolicyd

> [!CAUTION]
> Imajte na umu da od verzije Sequoia **`spctl`** više ne dozvoljava menjanje Gatekeeper konfiguracije.

**`spctl`** je CLI alat za nabrajanje i interakciju sa Gatekeeper-om (pomoću daemona `syspolicyd` preko XPC poruka). Na primer, **status** Gatekeeper-a moguće je videti pomoću:
```bash
# Check the status
spctl --status
```
> [!CAUTION]
> Imajte na umu da se GateKeeper provere potpisa izvršavaju samo nad **datotekama sa atributom Quarantine**, a ne nad svakom datotekom.

GateKeeper će proveriti da li se, na osnovu **podešavanja i potpisa**, binarni fajl može izvršiti:

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`** je glavni daemon zadužen za primenu Gatekeeper-a. On održava bazu podataka koja se nalazi u `/var/db/SystemPolicy`, a kod za podršku za [bazu podataka ovde](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp), kao i [SQL template ovde](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql). Imajte na umu da SIP ne ograničava pristup bazi i da je u nju moguće upisivati kao root korisnik, dok se baza `/var/db/.SystemPolicy-default` koristi kao originalna rezervna kopija u slučaju da se druga baza ošteti.

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
**`syspolicyd`** takođe izlaže XPC server sa različitim operacijama kao što su `assess`, `update`, `record` i `cancel`, kojima se takođe može pristupiti pomoću **`Security.framework`-ovih `SecAssessment*`** API-ja, a **`spctl`** zapravo komunicira sa **`syspolicyd`** putem XPC-a.

Obratite pažnju na to da se prvo pravilo završava sa "**App Store**", a drugo sa "**Developer ID**", kao i da je na prethodnoj slici bilo **omogućeno izvršavanje aplikacija iz App Store-a i od identifikovanih developera**.\
Ako tu postavku **izmenite** na App Store, pravila "**Notarized Developer ID" će nestati**.

Takođe postoje hiljade pravila **tipa GKE**:
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

Ili možete izlistati prethodne informacije pomoću:
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
Kada bude potpuno omogućen, pojaviće se nova opcija:

<figure><img src="../../../images/image (1151).png" alt=""><figcaption></figcaption></figure>

Moguće je **proveriti da li će GateKeeper dozvoliti pokretanje aplikacije** pomoću:
```bash
spctl --assess -v /Applications/App.app
```
Moguće je dodati nova pravila u GateKeeper kako bi se dozvolilo izvršavanje određenih aplikacija pomoću:
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
U vezi sa **kernel extensions**, fascikla `/var/db/SystemPolicyConfiguration` sadrži fajlove sa listama kext-ova kojima je dozvoljeno učitavanje. Pored toga, `spctl` ima entitlement `com.apple.private.iokit.nvram-csr`, jer može da dodaje nove unapred odobrene kernel extensions, koje takođe moraju biti sačuvane u NVRAM-u pod ključem `kext-allowed-teams`.

#### Upravljanje Gatekeeper-om na macOS 15 (Sequoia) i novijim verzijama

- Dugogodišnji Finder **Ctrl+Open / klik desnim tasterom → Open** bypass je uklonjen; korisnici moraju eksplicitno da dozvole blokiranu aplikaciju kroz **System Settings → Privacy & Security → Open Anyway** nakon prvog dijaloga o blokiranju.<sup>[[4]](#references)</sup>
- `spctl --master-disable/--global-disable` više nisu prihvaćene opcije; `spctl` je praktično read-only za procenu i upravljanje label-ama, dok se sprovođenje policy-ja konfiguriše kroz UI ili MDM.

Počev od macOS 15 Sequoia, krajnji korisnici više ne mogu da menjaju Gatekeeper policy iz `spctl`-a. Upravljanje se obavlja kroz System Settings ili postavljanjem MDM configuration profile-a sa `com.apple.systempolicy.control` payload-om. Primer dela profile-a koji dozvoljava App Store i identifikovane developere (ali ne i opciju „Anywhere“):

<details>
<summary>MDM profile za dozvolu App Store-a i identifikovanih developera</summary>
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

### Quarantine Files

Prilikom **preuzimanja** aplikacije ili datoteke, određene macOS **aplikacije**, kao što su web browseri ili email klijenti, **dodaju prošireni atribut datoteke**, poznat kao "**quarantine flag**", preuzetoj datoteci. Ovaj atribut služi kao bezbednosna mera za **označavanje datoteke** kao datoteke koja potiče iz nepouzdanog izvora (interneta) i koja potencijalno može predstavljati rizik. Međutim, ne dodaju sve aplikacije ovaj atribut; na primer, uobičajeni BitTorrent client software obično zaobilazi ovaj proces.

**Prisustvo quarantine flag-a signalizira macOS-ovoj Gatekeeper bezbednosnoj funkciji kada korisnik pokuša da izvrši datoteku**.

U slučaju kada **quarantine flag nije prisutan** (kao kod datoteka preuzetih putem nekih BitTorrent klijenata), Gatekeeper **provere možda neće biti izvršene**. Zbog toga korisnici treba da budu oprezni prilikom otvaranja datoteka preuzetih iz manje bezbednih ili nepoznatih izvora.

> [!NOTE] > **Provera** **validnosti** code signatures je proces koji zahteva mnogo resursa i uključuje generisanje kriptografskih **hash-eva** koda i svih njegovih priloženih resursa. Osim toga, provera validnosti sertifikata uključuje **online proveru** Apple servera kako bi se utvrdilo da li je sertifikat opozvan nakon izdavanja. Iz tih razloga, potpuna provera code signature i notarizacije je **nepraktična pri svakom pokretanju aplikacije**.
>
> Zbog toga se ove provere **izvršavaju samo prilikom pokretanja aplikacija sa quarantine atributom.**

> [!WARNING]
> Ovaj atribut mora da **postavi aplikacija koja kreira/preuzima** datoteku.
>
> Međutim, sandboxed datoteke će imati ovaj atribut postavljen na svaku datoteku koju kreiraju. Non sandboxed aplikacije mogu same da ga postave ili da navedu ključ [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) u **Info.plist** datoteci, čime će sistem postaviti prošireni atribut `com.apple.quarantine` na kreirane datoteke,

Pored toga, sve datoteke koje kreira proces pozivanjem **`qtn_proc_apply_to_self`** biće quarantined. Ili API **`qtn_file_apply_to_path`** dodaje quarantine atribut navedenoj putanji datoteke.

Moguće je **proveriti njegov status i omogućiti/onemogućiti ga** (zahteva root) pomoću:
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
Proverite **vrednost** **proširenih** **atributa** i saznajte koja je aplikacija upisala atribut quarantine pomoću:
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
# 00c1 -- The user has been allowed to execute this file (QTN_FLAG_USER_APPROVED = 0x0040)
# 607842eb -- Timestamp
# Brave -- App
# F643CD5F-6071-46AB-83AB-390BA944DEC5 -- UID assigned to the file downloaded
```
Zapravo, proces „može da postavi zastavice karantina datotekama koje kreira“ (već sam pokušao da primenim zastavicu USER_APPROVED na kreiranu datoteku, ali nije moguće primeniti je):

<details>

<summary>Izvorni kod za primenu zastavica karantina</summary>
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
I pronađite sve fajlove stavljene u karantin pomoću:
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
Informacije o karantinu takođe se čuvaju u centralnoj bazi podataka kojom upravlja LaunchServices na lokaciji **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**, što GUI-ju omogućava da dobije podatke o poreklu datoteke. Pored toga, aplikacije zainteresovane za skrivanje porekla mogu da ih izmene. To se takođe može uraditi putem LaunchServices APIS-a.

#### **libquarantine.dylib**

Ova biblioteka izvozi nekoliko funkcija koje omogućavaju manipulisanje poljima extended attributes.

`qtn_file_*` APIs se bave pravilima karantina datoteka, dok se `qtn_proc_*` APIs primenjuju na procese (datoteke koje je proces kreirao). Neizvezene funkcije `__qtn_syscall_quarantine*` primenjuju pravila i pozivaju `mac_syscall` sa argumentom `"Quarantine"` kao prvim argumentom, čime se zahtevi šalju ka `Quarantine.kext`.

#### **Quarantine.kext**

Kernel ekstenzija je dostupna samo kroz **kernel cache na sistemu**; međutim, možete preuzeti **Kernel Debug Kit sa** [**https://developer.apple.com/**](https://developer.apple.com/), koji će sadržati simbolikated verziju ekstenzije.

Ovaj Kext koristi MACF za presretanje nekoliko poziva kako bi pratio sve događaje tokom životnog ciklusa datoteka: kreiranje, otvaranje, preimenovanje, kreiranje hard linkova... čak i `setxattr`, kako bi sprečio njegovo postavljanje `com.apple.quarantine` extended attribute-a.

Takođe koristi nekoliko MIB-ova:

- `security.mac.qtn.sandbox_enforce`: Primenjuje karantin zajedno sa Sandbox-om
- `security.mac.qtn.user_approved_exec`: Querantined procesi mogu da izvršavaju samo odobrene datoteke

#### Provenance xattr (Ventura i noviji)

macOS 13 Ventura uveo je zaseban mehanizam provenance koji se popunjava prvi put kada je dozvoljeno pokretanje aplikacije u karantinu.<sup>[[2]](#references)</sup> Kreiraju se dva artefakta:

- `com.apple.provenance` xattr u direktorijumu `.app` bundle-a (binarna vrednost fiksne veličine koja sadrži primarni ključ i flags).
- Red u tabeli `provenance_tracking` unutar ExecPolicy baze podataka na lokaciji `/var/db/SystemPolicyConfiguration/ExecPolicy/`, koji čuva cdhash aplikacije i metapodatke.

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

XProtect je ugrađena **anti-malware** funkcija u macOS-u. XProtect **proverava svaku aplikaciju prilikom prvog pokretanja ili izmene u odnosu na svoju bazu podataka** poznatog malware-a i nebezbednih tipova datoteka. Kada preuzmete datoteku putem određenih aplikacija, kao što su Safari, Mail ili Messages, XProtect automatski skenira datoteku. Ako se podudara sa bilo kojim poznatim malware-om u njegovoj bazi podataka, XProtect će **sprečiti pokretanje datoteke** i upozoriti vas na pretnju.

Apple **redovno ažurira bazu podataka XProtect-a** novim definicijama malware-a, a ova ažuriranja se automatski preuzimaju i instaliraju na vaš Mac. Na taj način se obezbeđuje da XProtect uvek bude ažuriran najnovijim poznatim pretnjama.

Ipak, važno je napomenuti da **XProtect nije potpuno antivirusno rešenje**. Proverava samo određenu listu poznatih pretnji i ne obavlja skeniranje pri pristupu, kao većina antivirusnog softvera.

Informacije o najnovijem ažuriranju XProtect-a možete dobiti pokretanjem:
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
XProtect se nalazi na SIP zaštićenoj lokaciji **/Library/Apple/System/Library/CoreServices/XProtect.bundle**, a unutar bundle-a možete pronaći informacije koje XProtect koristi:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Omogućava kodu sa tim cdhash vrednostima da koristi legacy entitlements.
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: Lista plug-inova i ekstenzija kojima nije dozvoljeno učitavanje na osnovu BundleID i TeamID vrednosti ili koja navodi minimalnu verziju.
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Yara rules za detekciju malware-a.
- **`XProtect.bundle/Contents/Resources/gk.db`**: SQLite3 baza podataka sa hash vrednostima blokiranih aplikacija i TeamID vrednostima.

Imajte na umu da postoji još jedan App na lokaciji **`/Library/Apple/System/Library/CoreServices/XProtect.app`**, povezan sa XProtect-om, koji nije uključen u Gatekeeper proces.

> XProtect Remediator: Na modernom macOS-u, Apple isporučuje on-demand scanners (XProtect Remediator) koji se periodično pokreću putem launchd-a radi detekcije i remediation-a porodica malware-a. Ove scan-ove možete posmatrati u unified logs:
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### Nije Gatekeeper

> [!CAUTION]
> Imajte na umu da se Gatekeeper **ne izvršava svaki put** kada izvršite aplikaciju; samo će _**AppleMobileFileIntegrity**_ proveriti **signatures izvršnog koda** kada izvršite aplikaciju koja je već bila izvršena i verifikovana od strane Gatekeeper-a.

Zbog toga je ranije bilo moguće izvršiti aplikaciju kako bi je Gatekeeper keširao, a zatim **izmeniti fajlove aplikacije koji nisu izvršni** (kao što su Electron asar ili NIB fajlovi), pa bi, ako nisu postojale druge zaštite, aplikacija bila **izvršena** sa **malicious** dodacima.

Međutim, to sada nije moguće zato što macOS **sprečava izmenu fajlova** unutar application bundle-ova. Dakle, ako pokušate [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md) attack, videćete da ga više nije moguće abuse-ovati, jer nakon izvršavanja aplikacije radi keširanja pomoću Gatekeeper-a nećete moći da izmenite bundle. Ako, na primer, promenite ime Contents direktorijuma u NotCon (kao što je navedeno u exploit-u), a zatim izvršite glavni binary aplikacije kako biste ga keširali pomoću Gatekeeper-a, to će izazvati grešku i neće se izvršiti.

## Gatekeeper Bypasses

Svaki način za zaobilaženje Gatekeeper-a (uspešno navođenje korisnika da preuzme nešto i izvrši to kada bi Gatekeeper trebalo da zabrani izvršavanje) smatra se ranjivošću u macOS-u. Ovo su neki CVE-ovi dodeljeni tehnikama koje su u prošlosti omogućavale zaobilaženje Gatekeeper-a:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Uočeno je da, ako se **Archive Utility** koristi za extraction, fajlovi sa **putanjama dužim od 886 karaktera** ne dobijaju com.apple.quarantine extended attribute. Ova situacija nenamerno omogućava tim fajlovima da **zaobiđu Gatekeeper-ove** security provere.<sup>[[5]](#references)</sup>

Pogledajte [**originalni report**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) za više informacija.<sup>[[5]](#references)</sup>

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Kada se aplikacija kreira pomoću **Automator-a**, informacije o tome šta je potrebno za njeno izvršavanje nalaze se unutar `application.app/Contents/document.wflow`, a ne u executable-u. Executable je samo generički Automator binary pod nazivom **Automator Application Stub**.

Zato ste mogli da podesite da `application.app/Contents/MacOS/Automator\ Application\ Stub` **simboličkim linkom pokazuje na drugi Automator Application Stub unutar sistema**, pa bi se izvršilo ono što se nalazi u `document.wflow` fajlu (vaša skripta) **bez pokretanja Gatekeeper-a**, jer stvarni executable nema quarantine xattr.<sup>[[6]](#references)</sup>

Primer očekivane lokacije: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Pogledajte [**originalni report**](https://ronmasas.com/posts/bypass-macos-gatekeeper) za više informacija.<sup>[[6]](#references)</sup>

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

U ovom bypass-u, zip fajl je kreiran tako da kompresija počinje od `application.app/Contents`, umesto od `application.app`. Zato je **quarantine attr** primenjen na sve **fajlove iz `application.app/Contents`**, ali ne i na **`application.app`**, koji je Gatekeeper proveravao. Gatekeeper je zato zaobiđen, jer prilikom pokretanja `application.app` **nije postojao quarantine attribute.**<sup>[[7]](#references)</sup>
```bash
zip -r test.app/Contents test.zip
```
Proverite [**originalni izveštaj**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) za više informacija.<sup>[[7]](#references)</sup>

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Čak i ako se komponente razlikuju, exploitation ove ranjivosti je veoma sličan prethodnom. U ovom slučaju generisaćemo Apple Archive iz **`application.app/Contents`**, tako da **`application.app` neće dobiti quarantine attr** kada se dekompresuje pomoću alata **Archive Utility**.<sup>[[8]](#references)</sup>
```bash
aa archive -d test.app/Contents -o test.app.aar
```
Pogledajte [**originalni izveštaj**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) za više informacija.<sup>[[8]](#references)</sup>

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

ACL **`writeextattr`** može da se koristi za sprečavanje bilo koga da upisuje atribut u fajl:
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
Štaviše, format datoteka **AppleDouble** kopira datoteku zajedno sa njenim ACE-ovima.<sup>[[9]](#references)</sup>

U [**izvornom kodu**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) moguće je videti da će tekstualna reprezentacija ACL-a, sačuvana unutar xattr-a pod nazivom **`com.apple.acl.text`**, biti postavljena kao ACL u dekompresovanoj datoteci. Dakle, ako ste aplikaciju kompresovali u zip datoteku koristeći format **AppleDouble**, sa ACL-om koji sprečava upis drugih xattr-ova u nju... quarantine xattr nije bio postavljen u aplikaciju:
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
Pogledajte [**originalni izveštaj**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) za više informacija.<sup>[[9]](#references)</sup>

Imajte na umu da se ovo takođe može iskoristiti pomoću AppleArchives:
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

Otkriveno je da **Google Chrome nije postavljao atribut karantina** preuzetim datotekama zbog određenih internih problema u macOS-u.<sup>[[10]](#references)</sup>

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDouble čuva atribute datoteke u zasebnoj datoteci čije ime počinje sa `._`; to pomaže pri kopiranju atributa datoteka **između macOS računara**. Međutim, nakon dekompresovanja AppleDouble datoteke, datoteci koja počinje sa `._` **nije bio dodeljen atribut karantina**.<sup>[[11]](#references)</sup>
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you download and decompress the resulting test.aar, test/._a won't have a quarantine attribute
```
Mogućnost kreiranja fajla koji neće imati postavljen atribut quarantine **omogućila je zaobilaženje Gatekeeper-a.** Trik je bio **kreirati DMG file application** koristeći AppleDouble konvenciju imenovanja (započeti ga sa `._`) i kreirati **vidljivi fajl kao sym link ka ovom skrivenom** fajlu bez atributa quarantine.\
Kada se **dmg fajl izvrši**, pošto nema atribut quarantine, **zaobići će Gatekeeper**.
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

Gatekeeper bypass, ispravljen u macOS Sonoma 14.0, omogućavao je pokretanje posebno izrađenih aplikacija bez prikaza upita. Detalji su javno objavljeni nakon patchovanja, a problem je pre ispravke aktivno eksploatisan u wild. Obezbedite da je instaliran Sonoma 14.0 ili noviji.<sup>[[13]](#references)</sup>

### [CVE-2024-27853]

Gatekeeper bypass u macOS 14.4 (objavljenom u martu 2024), koji je poticao od načina na koji `libarchive` obrađuje zlonamerne ZIP datoteke, omogućavao je aplikacijama da izbegnu assessment. Ažurirajte na 14.4 ili noviji, gde je Apple rešio ovaj problem.<sup>[[1]](#references)</sup>

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

**Automator Quick Action workflow** ugrađen u preuzetu aplikaciju mogao je da se aktivira bez Gatekeeper assessment-a, zato što su workflow-i tretirani kao podaci i izvršavani pomoću Automator helper-a izvan uobičajenog toka za notarization prompt. Posebno izrađen `.app` koji sadrži Quick Action koja pokreće shell script (npr. unutar `Contents/PlugIns/*.workflow/Contents/document.wflow`) stoga je mogao da se izvrši odmah pri pokretanju. Apple je dodao dodatni consent dialog i ispravio assessment path u Ventura **13.7**, Sonoma **14.7** i Sequoia **15**.<sup>[[3]](#references)</sup>

### Third‑party unarchivers koji nepravilno prosleđuju quarantine (2023–2024)

Nekoliko ranjivosti u popularnim alatima za ekstrakciju (npr. The Unarchiver) dovodilo je do toga da datotekama izdvojenim iz arhiva nedostaje `com.apple.quarantine` xattr, što je stvaralo mogućnosti za Gatekeeper bypass. Prilikom testiranja uvek koristite macOS Archive Utility ili patched tools i proverite xattrs nakon ekstrakcije.

### uchg (iz ovog [talk-a](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

- Kreirajte direktorijum koji sadrži aplikaciju.
- Dodajte uchg aplikaciji.
- Kompresujte aplikaciju u tar.gz datoteku.
- Pošaljite tar.gz datoteku žrtvi.
- Žrtva otvara tar.gz datoteku i pokreće aplikaciju.
- Gatekeeper ne proverava aplikaciju.<sup>[[12]](#references)</sup>

### Sprečavanje Quarantine xattr

Ako se u ".app" bundle ne doda quarantine xattr, prilikom njegovog izvršavanja **Gatekeeper se neće aktivirati**.

## References

- [1] [Apple Platform Security: O bezbednosnom sadržaju macOS Sonoma 14.4 (uključuje CVE-2024-27853)](https://support.apple.com/en-us/HT214084)
- [2] [Eclectic Light: Kako macOS sada prati poreklo aplikacija](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- [3] [Apple: O bezbednosnom sadržaju macOS Sonoma 14.7 / Ventura 13.7 (CVE-2024-44128)](https://support.apple.com/en-us/121234)
- [4] [MacRumors: macOS 15 Sequoia uklanja Control‑click „Open“ Gatekeeper bypass](https://www.macrumors.com/2024/06/11/macos-sequoia-removes-open-anyway/)
- [5] [WithSecure Labs: Otkrivanje CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)
- [6] [CVE-2021-30990, Zaobilaženje macOS Gatekeeper-a](https://ronmasas.com/posts/bypass-macos-gatekeeper)
- [7] [Jamf Threat Labs identifikovao Safari ranjivost koja omogućava Gatekeeper bypass](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)
- [8] [Jamf Threat Labs identifikovao ranjivost macOS Archive Utility-ja koja omogućava Gatekeeper bypass (CVE-2022-32910)](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)
- [9] [Gatekeeper-ova Ahilova peta: Otkrivanje macOS ranjivosti](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [10] [F-Secure: Otkrivanje Gatekeeper bypass-a (CVE-2023-27943)](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)
- [11] [Pronalaženje i prijavljivanje Gatekeeper bypass exploita uz pomoć Mac Monitor-a](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)
- [12] [CODE BLUE 2023: Zaobilaženje macOS Security and Privacy Mechanisms — od Gatekeeper-a do System Integrity Protection-a (Koh Nakagawa)](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf)
- [13] [Apple: O bezbednosnom sadržaju macOS Sonoma 14 (CVE-2023-41067)](https://support.apple.com/en-us/HT213940)
{{#include ../../../banners/hacktricks-training.md}}
