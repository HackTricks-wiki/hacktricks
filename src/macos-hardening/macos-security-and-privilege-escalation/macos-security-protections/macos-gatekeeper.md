# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

**Gatekeeper** is 'n sekuriteitskenmerk wat vir Mac-bedryfstelsels ontwikkel is, ontwerp om te verseker dat gebruikers **slegs vertroude sagteware uitvoer** op hul stelsels. Dit funksioneer deur **sagteware te valideer** wat 'n gebruiker aflaai en probeer oopmaak vanaf **bronne buite die App Store**, soos 'n app, 'n plug-in of 'n installer-pakket.

Die sleutelmeganisme van Gatekeeper lê in sy **verifikasieproses**. Dit kontroleer of die afgelaaide sagteware **deur 'n erkende ontwikkelaar onderteken is**, wat die sagteware se egtheid verseker. Verder bepaal dit of die sagteware **deur Apple genotariseer is**, wat bevestig dat dit vry is van bekende kwaadwillige inhoud en nie ná notarisation gewysig is nie.

Daarbenewens versterk Gatekeeper gebruikersbeheer en sekuriteit deur **gebruikers te vra om die opening goed te keur** van afgelaaide sagteware wanneer dit die eerste keer gebeur. Hierdie beveiliging help voorkom dat gebruikers per ongeluk potensieel skadelike uitvoerbare kode laat loop wat hulle moontlik vir 'n onskadelike datalêer aangesien het.

### Application Signatures

Application signatures, ook bekend as code signatures, is 'n kritieke komponent van Apple se sekuriteitsinfrastruktuur. Dit word gebruik om **die identiteit van die sagteware-outeur** (die ontwikkelaar) **te verifieer** en om te verseker dat daar nie met die kode gepeuter is sedert dit laas onderteken is nie.

Hier is hoe dit werk:

1. **Signing the Application:** Wanneer 'n ontwikkelaar gereed is om hul application te versprei, **onderteken hulle die application met behulp van 'n private key**. Hierdie private key word geassosieer met 'n **sertifikaat wat Apple aan die ontwikkelaar uitreik** wanneer hulle by die Apple Developer Program inskryf. Die signing-proses behels die skep van 'n kriptografiese hash van alle dele van die app en die enkripsie van hierdie hash met die ontwikkelaar se private key.
2. **Distributing the Application:** Die signed application word dan saam met die ontwikkelaar se sertifikaat aan gebruikers versprei, wat die ooreenstemmende public key bevat.
3. **Verifying the Application:** Wanneer 'n gebruiker die application aflaai en probeer uitvoer, gebruik hul Mac-bedryfstelsel die public key uit die ontwikkelaar se sertifikaat om die hash te dekripteer. Dit bereken dan die hash opnuut gebaseer op die huidige toestand van die application en vergelyk dit met die gedekripteerde hash. As hulle ooreenstem, beteken dit **dat daar nie met die application gewysig is nie** sedert die ontwikkelaar dit onderteken het, en die stelsel laat die application toe om te loop.

Application signatures is 'n noodsaaklike deel van Apple se Gatekeeper-tegnologie. Wanneer 'n gebruiker probeer om **'n application wat van die internet afgelaai is oop te maak**, verifieer Gatekeeper die application signature. As dit onderteken is met 'n sertifikaat wat deur Apple aan 'n bekende ontwikkelaar uitgereik is en daar nie met die kode gepeuter is nie, laat Gatekeeper die application toe om te loop. Andersins blokkeer dit die application en waarsku dit die gebruiker.

Vanaf macOS Catalina **kontroleer Gatekeeper ook of die application deur Apple genotariseer is**, wat 'n ekstra laag sekuriteit bied. Die notarisation-proses kontroleer die application vir bekende sekuriteitskwessies en kwaadwillige kode, en indien hierdie kontroles slaag, voeg Apple 'n ticket by die application wat Gatekeeper kan verifieer.

#### Check Signatures

Wanneer jy 'n **malware sample** kontroleer, moet jy altyd die **signature nagaan**, aangesien die **developer** wat dit onderteken het moontlik reeds **met malware verband hou.**
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
### Notarisering

Apple se notariseringsproses dien as 'n bykomende veiligheidsmaatreël om gebruikers teen potensieel skadelike sagteware te beskerm. Dit behels dat die **ontwikkelaar hul toepassing vir ondersoek indien** deur **Apple's Notary Service**, wat nie met App Review verwar moet word nie. Hierdie diens is 'n **outomatiese stelsel** wat die ingediende sagteware ondersoek vir **kwaadwillige inhoud** en enige moontlike probleme met code-signing.

As die sagteware hierdie inspeksie **slaag** sonder om enige kommer te wek, genereer die Notary Service 'n notariseringskaartjie. Die ontwikkelaar moet dan hierdie **kaartjie aan hul sagteware heg**, 'n proses wat as 'stapling' bekend staan. Verder word die notariseringskaartjie ook aanlyn gepubliseer, waar Gatekeeper, Apple's security technology, toegang daartoe kan kry.

Wanneer die gebruiker die sagteware vir die eerste keer installeer of uitvoer, **lig die bestaan van die notariseringskaartjie - hetsy dit aan die uitvoerbare lêer geheg is of aanlyn gevind word - Gatekeeper in dat Apple die sagteware notariseer het**. Gevolglik vertoon Gatekeeper 'n beskrywende boodskap in die aanvanklike bekendstellingsdialoog, wat aandui dat Apple die sagteware vir kwaadwillige inhoud nagegaan het. Hierdie proses versterk dus gebruikers se vertroue in die sekuriteit van die sagteware wat hulle op hul stelsels installeer of uitvoer.

### spctl & syspolicyd

> [!CAUTION]
> Let daarop dat **`spctl`** vanaf Sequoia weergawe nie meer toelaat dat die Gatekeeper-konfigurasie gewysig word nie.

**`spctl`** is die CLI-instrument om Gatekeeper op te som en daarmee interaksie te hê (met die `syspolicyd` daemon via XPC-boodskappe). Dit is byvoorbeeld moontlik om die **status** van GateKeeper te sien met:
```bash
# Check the status
spctl --status
```
> [!CAUTION]
> Let daarop dat GateKeeper-handtekeningkontroles slegs uitgevoer word op **lêers met die Quarantine-kenmerk**, nie op elke lêer nie.

GateKeeper sal kontroleer of ’n binary volgens die **voorkeure & die handtekening** uitgevoer kan word:

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`** is die hoofdaemon wat verantwoordelik is vir die afdwinging van Gatekeeper. Dit hou ’n databasis by wat in `/var/db/SystemPolicy` geleë is, en dit is moontlik om die kode ter ondersteuning van die [databasis hier](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp) en die [SQL-sjabloon hier](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql) te vind. Let daarop dat die databasis nie deur SIP beperk word nie en deur root geskryf kan word, en dat die databasis `/var/db/.SystemPolicy-default` as ’n oorspronklike rugsteun gebruik word indien die ander een korrup raak.

Verder bevat die bundles **`/var/db/gke.bundle`** en **`/var/db/gkopaque.bundle`** lêers met reëls wat in die databasis ingevoeg word. Jy kan hierdie databasis as root nagaan met:
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
**`syspolicyd`** stel ook 'n XPC-bediener bloot met verskillende bewerkings soos `assess`, `update`, `record` en `cancel`, wat ook bereikbaar is deur **Security.framework** se `SecAssessment*`-API's, en **`spctl`** kommunikeer inderdaad met **`syspolicyd`** via XPC.

Let daarop dat die eerste reël met "**App Store**" geëindig het en die tweede een met "**Developer ID**", en dat dit in die vorige image **geaktiveer was om apps vanaf die App Store en van geïdentifiseerde ontwikkelaars uit te voer**.\
As jy daardie instelling na App Store **wysig**, sal die "**Notarized Developer ID"-reëls verdwyn**.

Daar is ook duisende reëls van **tipe GKE**:
```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```
Dit is hashes afkomstig van:

- `/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`
- `/var/db/gke.bundle/Contents/Resources/gk.db`
- `/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`

Of jy kan die vorige inligting lys met:
```bash
sudo spctl --list
```
Die opsies **`--master-disable`** en **`--global-disable`** van **`spctl`** sal hierdie handtekeningkontroles heeltemal **deaktiveer**:
```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```
Wanneer dit volledig geaktiveer is, sal ’n nuwe opsie verskyn:

<figure><img src="../../../images/image (1151).png" alt=""><figcaption></figcaption></figure>

Dit is moontlik om **te kontroleer of ’n App deur GateKeeper toegelaat sal word** met:
```bash
spctl --assess -v /Applications/App.app
```
Dit is moontlik om nuwe reëls in GateKeeper by te voeg om die uitvoering van sekere apps toe te laat met:
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
Wat **kernel extensions** betref, bevat die vouer `/var/db/SystemPolicyConfiguration` lêers met lyste van kexts wat toegelaat word om gelaai te word. Boonop het `spctl` die entitlement `com.apple.private.iokit.nvram-csr`, omdat dit nuwe voorafgoedgekeurde kernel extensions kan byvoeg wat ook in NVRAM in ’n `kext-allowed-teams`-sleutel gestoor moet word.

#### Bestuur van Gatekeeper op macOS 15 (Sequoia) en later

- Die langdurige Finder **Ctrl/Open / Right-click → Open**-omseiling is verwyder; gebruikers moet ’n geblokkeerde app uitdruklik toelaat via **System Settings → Privacy & Security → Open Anyway** nadat die eerste blokkeringsdialoog verskyn het.<sup>[[4]](#references)</sup>
- `spctl --master-disable/--global-disable` word nie meer aanvaar nie; `spctl` is effektief slegs-lees vir assessment en label-bestuur, terwyl policy enforcement via die UI of MDM gekonfigureer word.

Vanaf macOS 15 Sequoia kan eindgebruikers nie meer Gatekeeper policy vanuit `spctl` wissel nie. Bestuur word via System Settings uitgevoer of deur ’n MDM-konfigurasieprofiel met die `com.apple.systempolicy.control`-payload te ontplooi. Voorbeeldprofiel-fragment om App Store en geïdentifiseerde ontwikkelaars toe te laat (maar nie "Anywhere" nie):

<details>
<summary>MDM-profiel om App Store en geïdentifiseerde ontwikkelaars toe te laat</summary>
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

### Kwarantynlêers

Wanneer ’n toepassing of lêer **afgelaai** word, heg spesifieke macOS-**toepassings**, soos webblaaiers of e-poskliënte, ’n **uitgebreide lêerkenmerk** aan, wat algemeen as die "**kwarantynvlag**" bekend staan, aan die afgelaaide lêer. Hierdie kenmerk dien as ’n sekuriteitsmaatreël om **die lêer te merk** as afkomstig van ’n onbetroubare bron (die internet), en as moontlik riskant. Nie alle toepassings heg egter hierdie kenmerk aan nie; algemene BitTorrent-kliëntprogrammatuur omseil hierdie proses gewoonlik.

**Die teenwoordigheid van ’n kwarantynvlag aktiveer macOS se Gatekeeper-sekuriteitsfunksie wanneer ’n gebruiker probeer om die lêer uit te voer**.

In die geval waar die **kwarantynvlag nie teenwoordig is nie** (soos met lêers wat via sommige BitTorrent-kliënte afgelaai is), **mag Gatekeeper se kontroles nie uitgevoer word nie**. Gebruikers moet dus versigtig wees wanneer hulle lêers oopmaak wat van minder veilige of onbekende bronne afgelaai is.

> [!NOTE] > **Om** die **geldigheid** van kodesignature te **kontroleer**, is ’n **hulpbronintensiewe** proses wat die generering van kriptografiese **hashes** van die kode en al sy gebundelde hulpbronne insluit. Verder behels die kontrolering van sertifikaatgeldigheid ’n **aanlynkontrole** by Apple se bedieners om te bepaal of dit herroep is nadat dit uitgereik is. Om hierdie redes is ’n volledige kodesignature- en notarization-kontrole **onprakties om elke keer wanneer ’n toepassing geloods word, uit te voer**.
>
> Daarom word hierdie kontroles **slegs uitgevoer wanneer toepassings met die gekwarantynde kenmerk uitgevoer word.**

> [!WARNING]
> Hierdie kenmerk moet **deur die toepassing wat die lêer skep/aflaai, gestel word**.
>
> Lêers wat egter sandboxed is, sal hierdie kenmerk hê op elke lêer wat hulle skep. En nie-sandboxed toepassings kan dit self stel, of die [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc)-sleutel in die **Info.plist** spesifiseer, wat die stelsel sal laat om die `com.apple.quarantine`-uitgebreide kenmerk op die geskepte lêers te stel,

Verder word alle lêers wat deur ’n proses geskep word wat **`qtn_proc_apply_to_self`** aanroep, gekwarantyn. Of die API **`qtn_file_apply_to_path`** voeg die kwarantynkenmerk by ’n gespesifiseerde lêerpad.

Dit is moontlik om **die status daarvan te kontroleer en dit te aktiveer/deaktiveer** (root benodig) met:
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
Jy kan ook **vasstel of ’n lêer die quarantine extended attribute het** met:
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
Gaan die **waarde** van die **extended** **attributes** na en vind uit watter app die quarantine attr geskryf het met:
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
Eintlik kan ’n proses “quarantine flags instel vir die lêers wat dit skep” (ek het reeds probeer om die USER_APPROVED-vlag op ’n geskepte lêer toe te pas, maar dit word nie toegepas nie):

<details>

<summary>Bronkode: pas quarantine flags toe</summary>
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

En **verwyder** daardie attribuut met:
```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```
En vind al die lêers in kwarantyn met:
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
Quarantine-inligting word ook gestoor in ’n sentrale databasis wat deur LaunchServices bestuur word in **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**, wat die GUI in staat stel om data oor die lêers se oorsprong te bekom. Dit kan egter deur toepassings oorskryf word wat moontlik daarin belangstel om hul oorsprong te versteek. Dit kan ook vanuit LaunchServices APIS gedoen word.

#### **libquarantine.dylib**

Hierdie biblioteek eksporteer verskeie funksies waarmee die uitgebreide attribuutvelde gemanipuleer kan word.

Die `qtn_file_*` APIs hanteer lêer-Quarantine-beleide, terwyl die `qtn_proc_*` APIs op prosesse toegepas word (lêers wat deur die proses geskep is). Die nie-geëxporteerde `__qtn_syscall_quarantine*`-funksies is dié wat die beleide toepas en `mac_syscall` aanroep met "Quarantine" as die eerste argument, wat die versoeke na `Quarantine.kext` stuur.

#### **Quarantine.kext**

Die kernel extension is slegs deur die **kernel cache op die stelsel** beskikbaar; jy kan egter die **Kernel Debug Kit vanaf** [**https://developer.apple.com/**](https://developer.apple.com/) aflaai, wat ’n gesimboliseerde weergawe van die extension sal bevat.

Hierdie Kext sal via MACF aan verskeie oproepe haak om alle lêerlewensiklusgebeurtenisse vas te vang: skepping, oopmaak, hernoeming, hard-linking... selfs `setxattr`, om te voorkom dat dit die `com.apple.quarantine` uitgebreide attribuut stel.

Dit gebruik ook ’n paar MIBs:

- `security.mac.qtn.sandbox_enforce`: Dwing Quarantine saam met Sandbox af
- `security.mac.qtn.user_approved_exec`: Quarantined procs kan slegs goedgekeurde lêers uitvoer

#### Provenance xattr (Ventura en later)

macOS 13 Ventura het ’n afsonderlike provenance-meganisme bekendgestel wat gevul word wanneer ’n quarantined app vir die eerste keer toegelaat word om te loop.<sup>[[2]](#references)</sup> Twee artefakte word geskep:

- Die `com.apple.provenance` xattr op die `.app`-bundelgids (’n binêre waarde met ’n vaste grootte wat ’n primêre sleutel en vlae bevat).
- ’n Ry in die `provenance_tracking`-tabel binne die ExecPolicy-databasis by `/var/db/SystemPolicyConfiguration/ExecPolicy/` wat die app se cdhash en metadata stoor.

Praktiese gebruik:
```bash
# Inspect provenance xattr (if present)
xattr -p com.apple.provenance /Applications/Some.app | hexdump -C

# Observe Gatekeeper/provenance events in real time
log stream --style syslog --predicate 'process == "syspolicyd"'

# Retrieve historical Gatekeeper decisions for a specific bundle
log show --last 2d --style syslog --predicate 'process == "syspolicyd" && eventMessage CONTAINS[cd] "GK scan"'
```
### XProtect

XProtect is ’n ingeboude **anti-malware**-funksie in macOS. XProtect **kontroleer elke toepassing wanneer dit die eerste keer geloods of gewysig word teen sy databasis** van bekende malware en onveilige lêertipes. Wanneer jy ’n lêer deur sekere toepassings, soos Safari, Mail of Messages, aflaai, skandeer XProtect die lêer outomaties. As dit met enige bekende malware in sy databasis ooreenstem, sal XProtect **verhoed dat die lêer uitgevoer word** en jou oor die bedreiging waarsku.

Die XProtect-databasis word **gereeld deur Apple opgedateer** met nuwe malware-definisies, en hierdie opdaterings word outomaties op jou Mac afgelaai en geïnstalleer. Dit verseker dat XProtect altyd op datum is met die nuutste bekende bedreigings.

Dit is egter belangrik om daarop te let dat **XProtect nie ’n volledige antivirusoplossing is nie**. Dit kontroleer slegs vir ’n spesifieke lys bekende bedreigings en voer nie on-access scanning uit soos die meeste antivirusprogrammatuur nie.

Jy kan inligting oor die nuutste XProtect-opdatering kry deur die volgende uit te voer:
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
XProtect is geleë in 'n SIP protected location by **/Library/Apple/System/Library/CoreServices/XProtect.bundle** en binne die bundle kan jy inligting vind wat XProtect gebruik:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Laat code met daardie cdhashes toe om legacy entitlements te gebruik.
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: Lys van plugins en extensions wat nie toegelaat word om te laai nie, via BundleID en TeamID, of wat 'n minimum weergawe aandui.
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Yara rules om malware op te spoor.
- **`XProtect.bundle/Contents/Resources/gk.db`**: SQLite3-database met hashes van geblokkeerde applications en TeamIDs.

Let daarop dat daar nog 'n App in **`/Library/Apple/System/Library/CoreServices/XProtect.app`** is wat met XProtect verband hou, maar wat nie by die Gatekeeper-proses betrokke is nie.

> XProtect Remediator: Op moderne macOS lewer Apple on-demand scanners (XProtect Remediator) wat periodiek via launchd loop om families van malware op te spoor en te remedieer. Jy kan hierdie scans in unified logs waarneem:
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### Nie Gatekeeper nie

> [!CAUTION]
> Let daarop dat Gatekeeper **nie elke keer uitgevoer word** wanneer jy 'n application uitvoer nie; slegs _**AppleMobileFileIntegrity**_ sal **executable code signatures verifieer** wanneer jy 'n app uitvoer wat reeds deur Gatekeeper uitgevoer en geverifieer is.

Voorheen was dit dus moontlik om 'n app uit te voer om dit met Gatekeeper te cache, en dan **nie-executable files van die application te wysig** (soos Electron asar- of NIB-files), en indien geen ander protections in plek was nie, is die application **uitgevoer** met die **malicious** additions.

Dit is egter nou nie moontlik nie omdat macOS **die wysiging van files** binne application bundles voorkom. As jy dus die [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md)-attack probeer, sal jy vind dat dit nie meer moontlik is om dit te abuse nie, omdat jy, nadat jy die app uitgevoer het om dit met Gatekeeper te cache, nie die bundle sal kan wysig nie. En as jy byvoorbeeld die naam van die Contents-directory na NotCon verander (soos in die exploit aangedui), en dan die main binary van die app uitvoer om dit met Gatekeeper te cache, sal dit 'n error trigger en nie uitvoer nie.

## Gatekeeper Bypasses

Enige manier om Gatekeeper te bypass (dit regkry om die user iets te laat download en uitvoer wanneer Gatekeeper dit behoort te disallow) word as 'n vulnerability in macOS beskou. Dit is sommige CVEs wat aan techniques toegeken is wat in die verlede toegelaat het om Gatekeeper te bypass:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Daar is waargeneem dat, indien die **Archive Utility** vir extraction gebruik word, files met **paths wat 886 characters oorskry** nie die com.apple.quarantine extended attribute ontvang nie. Hierdie situasie laat daardie files onbedoeld toe om **Gatekeeper se** security checks te **omseil**.<sup>[[5]](#references)</sup>

Sien die [**original report**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) vir meer information.

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Wanneer 'n application met **Automator** geskep word, is die information oor wat dit nodig het om uit te voer binne `application.app/Contents/document.wflow`, nie in die executable nie. Die executable is slegs 'n generiese Automator binary genaamd **Automator Application Stub**.

Daarom kon jy `application.app/Contents/MacOS/Automator\ Application\ Stub` **met 'n symbolic link na 'n ander Automator Application Stub binne die system laat wys**, en dit sal uitvoer wat binne `document.wflow` is (jou script) **sonder om Gatekeeper te trigger**, omdat die werklike executable nie die quarantine xattr het nie.<sup>[[6]](#references)</sup>

Voorbeeld van die verwagte location: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Sien die [**original report**](https://ronmasas.com/posts/bypass-macos-gatekeeper) vir meer information.

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

In hierdie bypass is 'n zip file geskep met 'n application wat begin compress het vanaf `application.app/Contents` in plaas van `application.app`. Daarom is die **quarantine attr** toegepas op al die **files vanaf `application.app/Contents`**, maar **nie op `application.app` nie**; dit is wat Gatekeeper nagegaan het. Gatekeeper is dus bypass omdat, toe `application.app` getrigger is, dit **nie die quarantine attribute gehad het nie.**<sup>[[7]](#references)</sup>
```bash
zip -r test.app/Contents test.zip
```
Gaan die [**oorspronklike verslag**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) na vir meer inligting.

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Selfs al verskil die komponente, is die uitbuiting van hierdie kwesbaarheid baie soortgelyk aan die vorige een. In hierdie geval sal ons ’n Apple Archive vanaf **`application.app/Contents`** genereer, sodat **`application.app`** nie die quarantine-kenmerk sal kry wanneer dit deur **Archive Utility** gedekomprimeer word nie.<sup>[[8]](#references)</sup>
```bash
aa archive -d test.app/Contents -o test.app.aar
```
Sien die [**oorspronklike verslag**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) vir meer inligting.

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

Die ACL **`writeextattr`** kan gebruik word om te voorkom dat enigiemand ’n kenmerk in ’n lêer skryf:
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
Verder kopieer die **AppleDouble**-lêerformaat ’n lêer insluitend sy ACEs.<sup>[[9]](#references)</sup>

In die [**source code**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) is dit moontlik om te sien dat die ACL-teksverteenwoordiging wat binne die xattr genaamd **`com.apple.acl.text`** gestoor word, as ACL in die gedekomprimeerde lêer gestel gaan word. Dus, as jy ’n toepassing in ’n zip-lêer met die **AppleDouble**-lêerformaat gekompresseer het met ’n ACL wat verhoed dat ander xattrs daarin geskryf word... is die quarantine xattr nie op die toepassing gestel nie:
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
Kyk na die [**oorspronklike verslag**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) vir meer inligting.

Let daarop dat dit ook met AppleArchives uitgebuit kan word:
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

Daar is ontdek dat **Google Chrome nie die quarantine attribute** aan afgelaaide lêers toegeken het nie weens sekere interne macOS-probleme.<sup>[[10]](#references)</sup>

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDouble file formats stoor die attributes van ’n lêer in ’n aparte lêer wat met `._` begin; dit help om lêerattributes **oor macOS-masjiene heen** te kopieer. Daar is egter opgemerk dat die lêer wat met `._` begin, **nie die quarantine attribute toegeken gekry het nie** nadat ’n AppleDouble-lêer gedekomprimeer is.<sup>[[11]](#references)</sup>
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you downloaded the resulting test.aar and decompress it, the file test/._a won't have a quarantitne attribute
```
Deur 'n lêer te kon skep waarop die quarantine-kenmerk nie gestel sou word nie, was dit **moontlik om Gatekeeper te omseil.** Die truuk was om 'n **DMG file application** te skep deur die AppleDouble-naamkonvensie te gebruik (begin dit met `._`) en 'n **sigbare lêer as 'n simlink na hierdie versteekte** lêer sonder die quarantine-kenmerk te skep.\
Wanneer die **dmg-lêer uitgevoer word**, sal dit, omdat dit nie 'n quarantine-kenmerk het nie, **Gatekeeper omseil**.
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

'n Gatekeeper-bypass wat in macOS Sonoma 14.0 reggestel is, het crafted apps toegelaat om sonder 'n prompt te loop. Besonderhede is ná patching publiek gemaak, en die issue is voor die fix aktief in die wild uitgebuit. Maak seker dat Sonoma 14.0 of later geïnstalleer is.

### [CVE-2024-27853]

'n Gatekeeper-bypass in macOS 14.4 (vrygestel in Maart 2024), wat ontstaan het uit `libarchive` se hantering van malicious ZIPs, het apps toegelaat om assessment te ontduik. Update na 14.4 of later, waar Apple die issue aangespreek het.<sup>[[1]](#references)</sup>

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

'n **Automator Quick Action workflow** wat in 'n afgelaaide app ingebed is, kon sonder Gatekeeper-assessment geaktiveer word, omdat workflows as data behandel en deur die Automator-helper buite die normale notarization-prompt-pad uitgevoer is. 'n Crafted `.app` wat 'n Quick Action bundel wat 'n shell script uitvoer (byvoorbeeld binne `Contents/PlugIns/*.workflow/Contents/document.wflow`) kon dus onmiddellik by launch uitgevoer word. Apple het 'n ekstra consent-dialog bygevoeg en die assessment-pad in Ventura **13.7**, Sonoma **14.7** en Sequoia **15** reggestel.<sup>[[3]](#references)</sup>

### Third‑party unarchivers mis-propagating quarantine (2023–2024)

Verskeie vulnerabilities in gewilde extraction-tools (byvoorbeeld The Unarchiver) het veroorsaak dat lêers wat uit archives geëkstraheer is, die `com.apple.quarantine` xattr gemis het, wat geleenthede vir Gatekeeper-bypass moontlik gemaak het. Maak altyd staat op macOS Archive Utility of patched tools wanneer jy toets, en valideer xattrs ná extraction.

### uchg (from this [talk](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

- Skep 'n directory wat 'n app bevat.
- Voeg uchg by die app.
- Compress die app na 'n tar.gz-lêer.
- Stuur die tar.gz-lêer aan 'n victim.
- Die victim maak die tar.gz-lêer oop en run die app.
- Gatekeeper check nie die app nie.<sup>[[12]](#references)</sup>

### Voorkom Quarantine xattr

In 'n ".app"-bundle, as die quarantine xattr nie daarby gevoeg word nie, sal **Gatekeeper won't be triggered** wanneer dit uitgevoer word.


## References

- [1] [Apple Platform Security: About the security content of macOS Sonoma 14.4 (includes CVE-2024-27853)](https://support.apple.com/en-us/HT214084)
- [2] [Eclectic Light: How macOS now tracks the provenance of apps](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- [3] [Apple: About the security content of macOS Sonoma 14.7 / Ventura 13.7 (CVE-2024-44128)](https://support.apple.com/en-us/121234)
- [4] [MacRumors: macOS 15 Sequoia removes the Control‑click “Open” Gatekeeper bypass](https://www.macrumors.com/2024/06/11/macos-sequoia-removes-open-anyway/)
- [5] [WithSecure Labs: The Discovery of CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)
- [6] [CVE-2021-30990, Bypassing The macOS Gatekeeper](https://ronmasas.com/posts/bypass-macos-gatekeeper)
- [7] [Jamf Threat Labs identifies Safari vulnerability allowing for Gatekeeper bypass](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)
- [8] [Jamf Threat Labs identifies macOS Archive Utility vulnerability allowing for Gatekeeper bypass (CVE-2022-32910)](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)
- [9] [Gatekeeper's Achilles heel: Unearthing a macOS vulnerability](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [10] [F-Secure: Discovery of a Gatekeeper Bypass (CVE-2023-27943)](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)
- [11] [Finding and reporting a Gatekeeper bypass exploit with help from Mac Monitor](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)
- [12] [CODE BLUE 2023: Bypassing macOS Security and Privacy Mechanisms — From Gatekeeper to System Integrity Protection (Koh Nakagawa)](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf)

{{#include ../../../banners/hacktricks-training.md}}
