# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

**Gatekeeper** je bezbednosna funkcija razvijena za Mac operativne sisteme, osmišljena da obezbedi da korisnici **pokreću samo pouzdan softver** na svojim sistemima. Ona proverava softver koji korisnik preuzima i pokušava da otvori iz **izvora izvan App Store-a**, kao što su aplikacija, plug-in ili instalacioni paket.

Ključni mehanizam Gatekeeper-a je proces **verifikacije**. Proverava da li je preuzeti softver **potpisao prepoznat programer**, čime se potvrđuje njegova autentičnost. Pored toga, utvrđuje da li je Apple **notarizovao softver**, potvrđujući da ne sadrži poznat zlonamerni sadržaj i da nije menjan nakon notarizacije.

Gatekeeper dodatno jača kontrolu korisnika i bezbednost tako što **traži od korisnika da odobre prvo otvaranje** preuzetog softvera. Ova zaštita pomaže da se spreči nenamerno pokretanje potencijalno štetnog izvršnog koda koji bi korisnici mogli pogrešno da smatraju bezazlenom datotekom sa podacima.

### Potpisi aplikacija

Potpisi aplikacija, poznati i kao potpisi koda, ključna su komponenta Apple-ove bezbednosne infrastrukture. Koriste se za **proveru identiteta autora softvera** (programera) i za obezbeđivanje da kod nije menjan od poslednjeg potpisivanja.

Evo kako to funkcioniše:

1. **Potpisivanje aplikacije:** Kada je programer spreman da distribuira svoju aplikaciju, **potpisuje je privatnim ključem**. Taj privatni ključ povezan je sa **sertifikatom koji Apple izdaje programeru** kada se učlani u Apple Developer Program. Proces potpisivanja obuhvata kreiranje kriptografskog hash-a svih delova aplikacije i šifrovanje tog hash-a privatnim ključem programera.
2. **Distribucija aplikacije:** Potpisana aplikacija se zatim distribuira korisnicima zajedno sa sertifikatom programera, koji sadrži odgovarajući javni ključ.
3. **Verifikacija aplikacije:** Kada korisnik preuzme aplikaciju i pokuša da je pokrene, Mac operativni sistem koristi javni ključ iz sertifikata programera da dešifruje hash. Zatim ponovo izračunava hash na osnovu trenutnog stanja aplikacije i poredi ga sa dešifrovanim hash-om. Ako se poklapaju, to znači da **aplikacija nije menjana** otkako ju je programer potpisao, pa sistem dozvoljava njeno pokretanje.

Potpisi aplikacija su suštinski deo Apple-ove Gatekeeper tehnologije. Kada korisnik pokuša da **otvori aplikaciju preuzetu sa interneta**, Gatekeeper proverava njen potpis. Ako je potpisana sertifikatom koji je Apple izdao poznatom programeru i kod nije menjan, Gatekeeper dozvoljava pokretanje aplikacije. U suprotnom, blokira aplikaciju i obaveštava korisnika.

Počev od macOS Catalina, **Gatekeeper proverava i da li je Apple notarizovao aplikaciju**, čime se dodaje još jedan sloj bezbednosti. Tokom procesa notarizacije proverava se da li aplikacija sadrži poznate bezbednosne probleme i zlonamerni kod. Ako prođe ove provere, Apple joj dodaje tiket koji Gatekeeper može da verifikuje.

#### Provera potpisa

Kada proveravate neki **malware uzorak**, uvek treba da **proverite potpis** binarne datoteke, jer **programer** koji ju je potpisao možda je već **povezan** sa **malware-om**.

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

Apple-ov proces notarizacije pruža dodatnu zaštitu korisnicima od potencijalno štetnog softvera. On podrazumeva da **programer podnese svoju aplikaciju na proveru** kod **Apple-ove Notary Service**, koju ne treba mešati sa App Review. Ova usluga je **automatizovani sistem** koji proverava da li podneti softver sadrži **zlonameran sadržaj** i da li postoje potencijalni problemi sa potpisivanjem koda.

Ako softver **prođe** ovu proveru bez uočenih problema, Notary Service generiše tiket za notarizaciju. Programer zatim mora da **priloži ovaj tiket svom softveru**, što je poznato kao „stapling“. Pored toga, tiket za notarizaciju objavljuje se i na internetu, gde mu Gatekeeper, Apple-ova bezbednosna tehnologija, može pristupiti.

Pri prvom instaliranju ili pokretanju softvera od strane korisnika, postojanje tiketa za notarizaciju — bilo da je priložen izvršnoj datoteci ili se nalazi na internetu — **obaveštava Gatekeeper da je Apple notarizovao softver**. Zbog toga Gatekeeper u početnom dijalogu za pokretanje prikazuje opisnu poruku koja navodi da je Apple proverio softver na prisustvo zlonamernog sadržaja. Ovaj proces povećava poverenje korisnika u bezbednost softvera koji instaliraju ili pokreću na svojim sistemima.

### spctl & syspolicyd

> [!CAUTION]
> Imajte na umu da od verzije Sequoia, **`spctl`** više ne dozvoljava izmenu Gatekeeper konfiguracije.

**`spctl`** je CLI alatka za pregled i interakciju sa Gatekeeper-om (putem XPC poruka sa demonom `syspolicyd`). Na primer, moguće je videti **status** GateKeeper-a pomoću:

```bash
# Check the status
spctl --status
```

> [!CAUTION]
> Imajte na umu da se provere potpisa GateKeeper-a obavljaju samo nad **datotekama sa atributom Quarantine**, a ne nad svakom datotekom.

GateKeeper će proveriti da li binarna datoteka može da se izvrši u skladu sa **podešavanjima i potpisom**:

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`** je glavni daemon zadužen za sprovođenje pravila Gatekeeper-a. Održava bazu podataka na lokaciji `/var/db/SystemPolicy`, a kod za podršku [bazi podataka možete pronaći ovde](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp), a [SQL predložak ovde](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql). Imajte na umu da SIP ne ograničava pristup bazi podataka i da u nju može da upisuje root. Baza podataka `/var/db/.SystemPolicy-default` koristi se kao originalna rezervna kopija u slučaju da se druga baza ošteti.

Pored toga, paketi **`/var/db/gke.bundle`** i **`/var/db/gkopaque.bundle`** sadrže datoteke sa pravilima koja se unose u bazu podataka. Ovu bazu podataka možete da proverite kao root pomoću:

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

**`syspolicyd`** takođe izlaže XPC server sa različitim operacijama kao što su `assess`, `update`, `record` i `cancel`, kojima se takođe može pristupiti pomoću API-ja **`SecAssessment*` iz `Security.framework`**, a **`spctl`** zapravo komunicira sa **`syspolicyd`** putem XPC-a.

Obratite pažnju na to da se prvo pravilo završava sa „**App Store**“, a drugo sa „**Developer ID**“, kao i da je na prethodnoj slici bilo **omogućeno izvršavanje aplikacija iz App Store-a i od identifikovanih developera**.\
Ako tu postavku **promenite** na App Store, pravila „**Notarized Developer ID**“ će nestati.

Postoje i hiljade pravila tipa **GKE**:

```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```

Ovo su hash vrednosti iz:

- `/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`
- `/var/db/gke.bundle/Contents/Resources/gk.db`
- `/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`

Ili možete izlistati prethodne informacije pomoću:

```bash
sudo spctl --list
```

Opcije **`--master-disable`** i **`--global-disable`** komande **`spctl`** potpuno će **onemogućiti** ove provere potpisa:

```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```

Kada je potpuno omogućen, pojaviće se nova opcija:

<figure><img src="../../../images/image (1151).png" alt=""><figcaption></figcaption></figure>

Moguće je **proveriti da li će GateKeeper dozvoliti pokretanje aplikacije** pomoću:

```bash
spctl --assess -v /Applications/App.app
```

Na macOS 14 i novijim verzijama, **`syspolicy_check`** je korisna provera višeg nivoa pre distribucije paketa aplikacije. Pruža korisnije dijagnostičke informacije o pouzdanom izvršavanju nego običan rezultat komande `spctl`, mada Apple i dalje preporučuje testiranje stvarnog postupka preuzimanja, izdvajanja i prvog pokretanja, jer se tako proverava i prenošenje atributa quarantine.<sup>[[14]](#references)</sup>

```bash
# Check the complete app bundle before distribution
syspolicy_check distribution /path/to/App.app

# Keep the lower-level assessment when comparing policy outcomes
spctl --assess --type execute -vv /path/to/App.app
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

Što se tiče **ekstenzija kernela**, fascikla `/var/db/SystemPolicyConfiguration` sadrži datoteke sa spiskovima kext-ova kojima je dozvoljeno učitavanje. Pored toga, `spctl` ima entitlement `com.apple.private.iokit.nvram-csr`, jer može da dodaje nove unapred odobrene ekstenzije kernela, koje takođe treba sačuvati u NVRAM-u, pod ključem `kext-allowed-teams`.

#### Upravljanje Gatekeeper-om u macOS 15 (Sequoia) i novijim verzijama

- Dugogodišnja Finder prečica za zaobilaženje zaštite **Ctrl+Open / Desni klik → Otvori** je uklonjena; korisnici moraju izričito da dozvole blokiranu aplikaciju u **Podešavanja sistema → Privatnost i bezbednost → Ipak otvori** nakon prvog dijaloga o blokiranju.<sup>[[4]](#references)</sup>
- `spctl --master-disable/--global-disable` više nije prihvaćen kao način za nenadzirane promene pravila. Operacije koje menjaju bazu pravila ili globalno stanje procene su zastarele, zato koristite `spctl` za procenu, a sprovođenje pravila podesite kroz korisnički interfejs ili MDM.

Počevši od macOS 15 Sequoia, krajnji korisnici više ne mogu da menjaju Gatekeeper pravila pomoću `spctl`. Upravljanje se obavlja putem Podešavanja sistema ili postavljanjem MDM konfiguracionog profila sa payload-om `com.apple.systempolicy.control`. Primer dela profila kojim se dozvoljavaju App Store i identifikovani programeri (ali ne i „Bilo gde“):

<details>
<summary>MDM profil za dozvolu aplikacija iz App Store-a i od identifikovanih programera</summary>

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

Prilikom **preuzimanja** aplikacije ili datoteke, određene macOS **aplikacije**, kao što su veb-pregledači ili klijenti e-pošte, **dodaju prošireni atribut datoteke**, poznat kao "**quarantine flag**", preuzetoj datoteci. Ovaj atribut služi kao bezbednosna mera za **označavanje datoteke** kao datoteke koja potiče iz nepouzdanog izvora (interneta) i koja može predstavljati rizik. Međutim, ne dodaju sve aplikacije ovaj atribut; na primer, uobičajeni BitTorrent klijenti obično zaobilaze ovaj postupak.

**Prisustvo quarantine flag-a obaveštava macOS-ovu bezbednosnu funkciju Gatekeeper kada korisnik pokuša da izvrši datoteku**.

Ako **quarantine flag nije prisutan** (kao kod datoteka preuzetih pomoću nekih BitTorrent klijenata), Gatekeeper-ove **provere možda neće biti obavljene**. Zato korisnici treba da budu oprezni prilikom otvaranja datoteka preuzetih iz manje bezbednih ili nepoznatih izvora.

> [!NOTE] > **Provera** **validnosti** potpisa koda je proces koji zahteva mnogo **resursa** i obuhvata generisanje kriptografskih **hash vrednosti** koda i svih pratećih resursa. Pored toga, provera validnosti sertifikata podrazumeva **proveru na mreži** sa Apple serverima da bi se utvrdilo da li je sertifikat opozvan nakon izdavanja. Iz ovih razloga, potpunu proveru potpisa koda i notarizacije **nije praktično obavljati svaki put kada se aplikacija pokrene**.
>
> Zato se ove provere **obavljaju samo pri izvršavanju aplikacija sa quarantine atributom**.

> [!WARNING]
> Ovaj atribut mora da **postavi aplikacija koja kreira/preuzima** datoteku.
>
> Međutim, datoteke koje se kreiraju u sandbox-u imaće ovaj atribut postavljen na svakoj datoteci koju naprave. Aplikacije koje nisu sandbox-ovane mogu same da ga postave ili da navedu ključ [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) u datoteci **Info.plist**, čime će sistem postaviti prošireni atribut `com.apple.quarantine` na kreirane datoteke,

Pored toga, sve datoteke koje kreira proces koji poziva **`qtn_proc_apply_to_self`** stavljaju se u karantin. API **`qtn_file_apply_to_path`** dodaje quarantine atribut navedenoj putanji datoteke.

Moguće je **proveriti njegov status i omogućiti/onemogućiti ga** (potreban je root) pomoću:

```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```

Takođe možete **utvrditi da li datoteka ima prošireni atribut karantina** pomoću:

```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```

Proverite **vrednost** **proširenih** **atributa** i utvrdite koja aplikacija je upisala atribut karantina pomoću:

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

Zapravo, proces „može da postavi karantinske zastavice na fajlove koje kreira“ (već sam pokušao da primenim zastavicu USER_APPROVED na kreirani fajl, ali ne mogu da je primenim):

<details>

<summary>Izvorni kod za primenu karantinskih zastavica</summary>

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

I pronađite sve datoteke u karantinu pomoću:

```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```

Informacije o karantinu čuvaju se i u centralnoj bazi podataka kojom upravlja LaunchServices, u **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**, što GUI-ju omogućava da dobije podatke o poreklu datoteka. Štaviše, aplikacije koje možda žele da sakriju poreklo datoteka mogu da ih prepišu. To se može uraditi i pomoću LaunchServices API-ja.

#### **libquarantine.dylib**

Ova biblioteka izvozi nekoliko funkcija koje omogućavaju izmenu polja proširenih atributa.

API-ji `qtn_file_*` bave se pravilima karantina datoteka, dok se API-ji `qtn_proc_*` primenjuju na procese (datoteke koje je proces kreirao). Neizvezene funkcije `__qtn_syscall_quarantine*` primenjuju pravila pozivanjem `mac_syscall` sa argumentom "Quarantine" kao prvim argumentom, čime se zahtevi prosleđuju u `Quarantine.kext`.

#### **Quarantine.kext**

Ovo kernel proširenje dostupno je samo kroz **kernel cache na sistemu**; međutim, možete preuzeti **Kernel Debug Kit sa** [**https://developer.apple.com/**](https://developer.apple.com/), koji sadrži verziju proširenja sa simbolima.

Ovaj Kext koristi MACF za presretanje nekoliko poziva kako bi uhvatio sve događaje tokom životnog ciklusa datoteka: kreiranje, otvaranje, preimenovanje, kreiranje hard linkova... čak i `setxattr`, da bi sprečio postavljanje proširenog atributa `com.apple.quarantine`.

Koristi i nekoliko MIB-ova:

- `security.mac.qtn.sandbox_enforce`: Sprovodi karantin uz Sandbox
- `security.mac.qtn.user_approved_exec`: Procesi u karantinu mogu da izvršavaju samo odobrene datoteke

#### xattr provenance (Ventura i noviji)

macOS 13 Ventura uveo je odvojen mehanizam provenance koji se popunjava kada se aplikaciji u karantinu prvi put dozvoli pokretanje.<sup>[[2]](#references)</sup> Kreiraju se dva artefakta:

- xattr `com.apple.provenance` u direktorijumu paketa `.app` (binarna vrednost fiksne veličine koja sadrži primarni ključ i zastavice).
- Red u tabeli `provenance_tracking` unutar baze podataka ExecPolicy u `/var/db/SystemPolicyConfiguration/ExecPolicy/`, u kom se čuvaju cdhash aplikacije i metapodaci.

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

XProtect je ugrađena **anti-malware** funkcija u macOS-u. XProtect **proverava svaku aplikaciju pri prvom pokretanju ili nakon izmene, upoređujući je sa svojom bazom podataka** poznatog malvera i nebezbednih tipova datoteka. Kada preuzmete datoteku pomoću određenih aplikacija, kao što su Safari, Mail ili Messages, XProtect je automatski skenira. Ako se podudara sa nekim poznatim malverom iz baze podataka, XProtect će **sprečiti pokretanje datoteke** i upozoriti vas na pretnju.

Apple **redovno ažurira** bazu podataka XProtect novim definicijama malvera, a ova ažuriranja se automatski preuzimaju i instaliraju na vaš Mac. Time se obezbeđuje da XProtect uvek bude ažuriran najnovijim poznatim pretnjama.

Ipak, vredi napomenuti da **XProtect nije potpuno antivirusno rešenje**. Proverava samo određeni spisak poznatih pretnji i ne obavlja skeniranje pri pristupu kao većina antivirusnih programa.

Informacije o najnovijem ažuriranju XProtect možete dobiti pokretanjem:

```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```

XProtect se nalazi na SIP-om zaštićenoj lokaciji **/Library/Apple/System/Library/CoreServices/XProtect.bundle**, a unutar paketa možete pronaći informacije koje XProtect koristi:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Omogućava kodu sa tim cdhash vrednostima da koristi legacy entitlements.
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: Spisak dodataka i ekstenzija čije je učitavanje zabranjeno na osnovu BundleID i TeamID vrednosti, ili koje navode minimalnu verziju.
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Yara pravila za otkrivanje malware-a.
- **`XProtect.bundle/Contents/Resources/gk.db`**: SQLite3 baza podataka sa hash vrednostima blokiranih aplikacija i TeamID vrednostima.

Imajte na umu da postoji još jedna aplikacija u **`/Library/Apple/System/Library/CoreServices/XProtect.app`** koja je povezana sa XProtect-om, ali nije uključena u Gatekeeper proces.

> XProtect Remediator: U novijim verzijama macOS-a, Apple isporučuje skenere na zahtev (XProtect Remediator) koji se periodično pokreću putem launchd-a radi otkrivanja i uklanjanja porodica malware-a. Ova skeniranja možete pratiti u objedinjenim logovima:
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### Nije Gatekeeper

> [!CAUTION]
> Imajte na umu da se Gatekeeper **ne izvršava svaki put** kada pokrenete aplikaciju. Samo će _**AppleMobileFileIntegrity**_ (AMFI) **proveriti potpise izvršnog koda** kada pokrenete aplikaciju koja je već bila pokrenuta i proverena pomoću Gatekeeper-a.

Zato je ranije bilo moguće pokrenuti aplikaciju da bi je Gatekeeper keširao, a zatim **izmeniti datoteke aplikacije koje nisu izvršne** (kao što su Electron asar ili NIB datoteke). Ako nisu bile aktivne druge zaštite, aplikacija bi se **pokrenula** sa **zlonamernim** dodacima.

Međutim, to sada nije moguće jer macOS **sprečava izmenu datoteka** unutar paketa aplikacija. Dakle, ako pokušate napad [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md), videćete da ga više nije moguće iskoristiti: nakon pokretanja aplikacije da bi je Gatekeeper keširao, nećete moći da izmenite paket. A ako, na primer, promenite ime direktorijuma Contents u NotCon (kao što je navedeno u exploit-u), pa zatim pokrenete glavni binarni fajl aplikacije da bi ga Gatekeeper keširao, pojaviće se greška i aplikacija se neće pokrenuti.

## Zaobilaženje Gatekeeper-a

Svaki način zaobilaženja Gatekeeper-a (uspeti da korisnik preuzme nešto i pokrene to iako bi Gatekeeper trebalo da zabrani) smatra se ranjivošću u macOS-u. Ovo su neki CVE-jevi dodeljeni tehnikama koje su ranije omogućavale zaobilaženje Gatekeeper-a:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Uočeno je da datoteke sa **putanjama dužim od 886 znakova** ne dobijaju prošireni atribut com.apple.quarantine kada se za raspakivanje koristi **Archive Utility**. Zbog toga te datoteke nenamerno mogu da **zaobiđu** bezbednosne provere Gatekeeper-a.<sup>[[5]](#references)</sup>

Više informacija potražite u [**originalnom izveštaju**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810).<sup>[[5]](#references)</sup>

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Kada se aplikacija kreira pomoću **Automator-a**, informacije o tome šta treba da pokrene nalaze se u `application.app/Contents/document.wflow`, a ne u izvršnoj datoteci. Izvršna datoteka je samo generički Automator binarni fajl pod nazivom **Automator Application Stub**.

Zato ste mogli da podesite da `application.app/Contents/MacOS/Automator\ Application\ Stub` **pokazuje simboličkom vezom na drugi Automator Application Stub unutar sistema**, pa bi se sadržaj datoteke `document.wflow` (vaša skripta) pokrenuo **bez aktiviranja Gatekeeper-a**, jer stvarna izvršna datoteka nema quarantine xattr.<sup>[[6]](#references)</sup>

Primer očekivane lokacije: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Više informacija potražite u [**originalnom izveštaju**](https://ronmasas.com/posts/bypass-macos-gatekeeper).<sup>[[6]](#references)</sup>

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

U ovom zaobilaženju kreirana je zip datoteka tako što je kompresija započeta od `application.app/Contents`, umesto od `application.app`. Zbog toga je **quarantine atribut** primenjen na sve **datoteke u `application.app/Contents`**, ali **ne i na `application.app`**, koji je Gatekeeper proveravao. Gatekeeper je zaobiđen jer `application.app` **nije imao quarantine atribut kada je pokrenut.**<sup>[[7]](#references)</sup>

```bash
zip -r test.app/Contents test.zip
```

Više informacija potražite u [**originalnom izveštaju**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/).<sup>[[7]](#references)</sup>

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Iako su komponente različite, eksploatacija ove ranjivosti veoma je slična prethodnoj. U ovom slučaju ćemo napraviti Apple Archive od **`application.app/Contents`**, pa **`application.app` neće dobiti quarantine atribut** kada ga raspakuje **Archive Utility**.<sup>[[8]](#references)</sup>

```bash
aa archive -d test.app/Contents -o test.app.aar
```

Pogledajte [**originalni izveštaj**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) za više informacija.<sup>[[8]](#references)</sup>

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

ACL **`writeextattr`** može da se koristi da bi se bilo kome onemogućilo upisivanje atributa u datoteku:

```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```

Štaviše, **AppleDouble** format datoteke kopira datoteku, uključujući njene ACE-ove.<sup>[[9]](#references)</sup>

U [**izvornom kodu**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) može se videti da će tekstualni prikaz ACL-a, sačuvan unutar xattr-a pod nazivom **`com.apple.acl.text`**, biti postavljen kao ACL dekompresovane datoteke. Dakle, ako ste aplikaciju kompresovali u zip datoteku u formatu **AppleDouble**, sa ACL-om koji sprečava upisivanje drugih xattr-a u nju... quarantine xattr nije postavljen u aplikaciju:

```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```

Pogledajte [**originalni izveštaj**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) za više informacija.<sup>[[9]](#references)</sup> Pogledajte [reprodukciju AppleDouble/ACL](macos-fs-tricks/macos-xattr-acls-extra-stuff.md) za korake izrade i validacije sidecar-a.

Imajte na umu da se ovo može iskoristiti i pomoću AppleArchives:

```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```

### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

Otkriveno je da **Google Chrome nije postavljao atribut karantina** preuzetim datotekama zbog određenih internih problema u macOS-u.<sup>[[10]](#references)</sup>

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDouble čuva atribute datoteke u zasebnoj datoteci čiji naziv počinje sa `._`; to olakšava kopiranje atributa datoteka **između macOS uređaja**. Međutim, nakon dekompresovanja AppleDouble datoteke, datoteci čiji naziv počinje sa `._` **nije dodeljen atribut karantina**.<sup>[[11]](#references)</sup>

```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you download and decompress the resulting test.aar, test/._a won't have a quarantine attribute
```

Pošto je bilo moguće napraviti fajl bez atributa quarantine, **bilo je moguće zaobići Gatekeeper.** Trik je bio da se napravi **DMG fajl aplikacije** koristeći konvenciju imenovanja AppleDouble (ime počinje sa `._`) i da se napravi **vidljivi fajl kao simbolička veza ka ovom skrivenom** fajlu bez atributa quarantine.\
Kada se **DMG fajl pokrene**, pošto nema atribut quarantine, **zaobići će Gatekeeper**.

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

Apple je ispravio logičku grešku u LaunchServices-u u macOS Sonoma 14.0 poboljšanjem provera. U javnom bezbednosnom upozorenju navodi se samo da je aplikacija mogla da zaobiđe Gatekeeper, zato nemojte na osnovu samog CVE unosa zaključivati koji je konkretan format nosioca ili lanac eksploatacije korišćen.<sup>[[13]](#references)</sup>

### [CVE-2024-27853]

Propust za zaobilaženje Gatekeeper-a u macOS 14.4 (objavljenom u martu 2024), uzrokovan načinom na koji `libarchive` obrađuje zlonamerne ZIP arhive, omogućavao je aplikacijama da izbegnu procenu. Ažurirajte na verziju 14.4 ili noviju, u kojoj je Apple rešio ovaj problem.<sup>[[1]](#references)</sup>

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

**Automator Quick Action workflow** ugrađen u preuzetu aplikaciju mogao je da se pokrene bez Gatekeeper procene, jer su workflow-i tretirani kao podaci, a izvršavao ih je Automator pomoćni proces izvan uobičajenog toka za prikazivanje zahteva za notarizaciju. Zato je posebno napravljena `.app` aplikacija koja sadrži Quick Action za pokretanje shell skripte (npr. unutar `Contents/PlugIns/*.workflow/Contents/document.wflow`) mogla da se izvrši odmah pri pokretanju. Apple je dodao dodatni dijalog za pristanak i ispravio tok procene u Ventura **13.7**, Sonoma **14.7** i Sequoia **15**.<sup>[[3]](#references)</sup>

### Propusti u prenošenju quarantine oznake pri raspakivanju i kopiranju

Studija iz 2024. otkrila je propuste u prenošenju oznake u testiranim verzijama iZip (ZIP/TAR/7Z), Archiver (ARCHIVER/ZIP/TAR/7Z), BetterZip (ZIP/TAR/7Z), WinRAR (ZIP/TAR/7Z) i 7z Utility (DMG/ZIP/7Z); takođe je zabeležila gubitak atributa pri kopiranju sa hosta na guest putem VMware Tools-a. Nekoliko dobavljača je naknadno objavilo ispravke, zato ove nazive tretirajte kao smernice za **ponovno testiranje određenih verzija**, a ne kao trajni spisak ranjivog softvera. Isti problem na granici poverenja javlja se i u izvornim Unix tokovima rada: `curl`/`scp` ne dodaju quarantine oznaku, a alati komandne linije `tar`/`unzip` je ne nasleđuju automatski iz arhive-nosioca.<sup>[[15]](#references)</sup>

Pri ofanzivnom testiranju uporedite arhivu-nosilac i konačnu aplikaciju posle **svakog** prelaza kroz pregledač, klijent e-pošte, arhiver, sliku diska, sinhronizaciju sa cloud-om, deljenu fasciklu i kopiranje između virtuelnih mašina. Izričito odbijanje komandom `spctl` ne popravlja nedostajući xattr: bez quarantine oznake, uobičajeni Gatekeeper tok pri prvom otvaranju možda nikada neće zatražiti tu procenu.<sup>[[15]](#references)</sup>

```bash
# 1. Confirm the browser-downloaded carrier is quarantined
xattr -p com.apple.quarantine ./payload.zip

# 2. Extract/copy it through the application under test, then inspect the result
xattr -p com.apple.quarantine ./out/Payload.app || echo "QUARANTINE LOST"
spctl --assess --type execute -vv ./out/Payload.app

# 3. Enumerate every app bundle whose top-level directory lost the marker
find ./out -type d -name '*.app' -prune -exec sh -c \
  'for app do xattr -p com.apple.quarantine "$app" >/dev/null 2>&1 || echo "$app"; done' sh {} +
```

### uchg (iz ovog [predavanja](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

- Napravite direktorijum koji sadrži aplikaciju.
- Dodajte uchg aplikaciji.
- Kompresujte aplikaciju u tar.gz datoteku.
- Pošaljite tar.gz datoteku žrtvi.
- Žrtva otvara tar.gz datoteku i pokreće aplikaciju.
- Gatekeeper ne proverava aplikaciju.<sup>[[12]](#references)</sup>

### Sprečavanje xattr-a za karantin

U ".app" paketu, ako mu se ne doda xattr za karantin, **Gatekeeper se neće aktivirati** prilikom njegovog pokretanja.

Pogledajte [macOS FS Tricks](macos-fs-tricks/README.md#avoid-quarantine-xattrs-tricks) za primitive na nivou filesystem-a, flag-a, ACL-a i AppleDouble-a koje mogu sprečiti ili ukloniti extended attributes.





## References

- [1] [Apple Platform Security: O bezbednosnom sadržaju macOS Sonoma 14.4 (uključuje CVE-2024-27853)](https://support.apple.com/en-us/HT214084)
- [2] [Eclectic Light: Kako macOS sada prati poreklo aplikacija](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- [3] [Apple: O bezbednosnom sadržaju macOS Sonoma 14.7 / Ventura 13.7 (CVE-2024-44128)](https://support.apple.com/en-us/121234)
- [4] [MacRumors: macOS 15 Sequoia uklanja Gatekeeper bypass pomoću Control-click „Open“](https://www.macrumors.com/2024/08/06/macos-sequoia-gatekeeper-security-change/)
- [5] [WithSecure Labs: Otkriće CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)
- [6] [CVE-2021-30990, zaobilaženje macOS Gatekeeper-a](https://ronmasas.com/posts/bypass-macos-gatekeeper)
- [7] [Jamf Threat Labs otkriva ranjivost u Safariju koja omogućava zaobilaženje Gatekeeper-a](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)
- [8] [Jamf Threat Labs otkriva ranjivost u macOS Archive Utility-ju koja omogućava zaobilaženje Gatekeeper-a (CVE-2022-32910)](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)
- [9] [Ahilova peta Gatekeeper-a: otkrivanje ranjivosti u macOS-u](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [10] [F-Secure: Otkrivanje zaobilaženja Gatekeeper-a (CVE-2023-27943)](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)
- [11] [Pronalaženje i prijavljivanje exploit-a za zaobilaženje Gatekeeper-a uz pomoć Mac Monitor-a](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)
- [12] [CODE BLUE 2023: Zaobilaženje macOS mehanizama bezbednosti i privatnosti — od Gatekeeper-a do System Integrity Protection-a (Koh Nakagawa)](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf)
- [13] [Apple: O bezbednosnom sadržaju macOS Sonoma 14 (CVE-2023-41067)](https://support.apple.com/en-us/HT213940)
- [14] [Apple Developer Forums: Testiranje notarizovanog proizvoda](https://developer.apple.com/forums/thread/130560)
- [15] [Unit 42: Zaobilaženje Gatekeeper-a — otkrivanje slabosti u macOS bezbednosnom mehanizmu](https://unit42.paloaltonetworks.com/gatekeeper-bypass-macos/)
{{#include ../../../banners/hacktricks-training.md}}
