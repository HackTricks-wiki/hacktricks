# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

**Gatekeeper** is 'n sekuriteitsfunksie wat vir Mac-bedryfstelsels ontwikkel is en ontwerp is om te verseker dat gebruikers **slegs vertroude sagteware** op hul stelsels **uitvoer**. Dit werk deur **sagteware te valideer** wat 'n gebruiker aflaai en probeer oopmaak vanaf **bronne buite die App Store**, soos 'n app, 'n plug-in of 'n installer package.

Die kernmeganisme van Gatekeeper lê in sy **verifikasieproses**. Dit kontroleer of die afgelaaide sagteware **deur 'n erkende ontwikkelaar onderteken is**, wat die sagteware se egtheid verseker. Verder bepaal dit of die sagteware **deur Apple notarised is**, wat bevestig dat dit vry is van bekende malicious inhoud en nie ná notarisation gewysig is nie.

Daarbenewens versterk Gatekeeper gebruikersbeheer en sekuriteit deur **gebruikers te vra om die opening van afgelaaide sagteware goed te keur** wanneer dit die eerste keer oopgemaak word. Hierdie beveiliging help voorkom dat gebruikers per ongeluk potensieel skadelike uitvoerbare code laat loop wat hulle dalk vir 'n onskadelike data file aangesien het.

### Application Signatures

Application signatures, ook bekend as code signatures, is 'n kritieke komponent van Apple se sekuriteitsinfrastruktuur. Dit word gebruik om **die identiteit van die sagteware-outeur** (die ontwikkelaar) **te verifieer** en om te verseker dat daar nie met die code gepeuter is sedert dit laas onderteken is nie.

Hier is hoe dit werk:

1. **Signing the Application:** Wanneer 'n ontwikkelaar gereed is om hul application te versprei, **onderteken hulle die application met 'n private key**. Hierdie private key word geassosieer met 'n **certificate wat Apple aan die ontwikkelaar uitreik** wanneer hulle by die Apple Developer Program inskryf. Die ondertekeningsproses behels die skep van 'n cryptographic hash van alle dele van die app en die encryption van hierdie hash met die ontwikkelaar se private key.
2. **Distributing the Application:** Die ondertekende application word dan saam met die ontwikkelaar se certificate, wat die ooreenstemmende public key bevat, aan gebruikers versprei.
3. **Verifying the Application:** Wanneer 'n gebruiker die application aflaai en probeer uitvoer, gebruik hul Mac-bedryfstelsel die public key uit die ontwikkelaar se certificate om die hash te decrypt. Dit bereken dan die hash weer op grond van die application se huidige toestand en vergelyk dit met die decrypted hash. As hulle ooreenstem, beteken dit dat **die application nie gewysig is nie** sedert die ontwikkelaar dit onderteken het, en die stelsel laat die application toe om te loop.

Application signatures is 'n noodsaaklike deel van Apple se Gatekeeper-tegnologie. Wanneer 'n gebruiker probeer om **'n application wat van die internet afgelaai is oop te maak**, verifieer Gatekeeper die application signature. As dit onderteken is met 'n certificate wat deur Apple aan 'n bekende ontwikkelaar uitgereik is en daar nie met die code gepeuter is nie, laat Gatekeeper die application toe om te loop. Andersins blokkeer dit die application en waarsku dit die gebruiker.

Vanaf macOS Catalina **kontroleer Gatekeeper ook of die application deur Apple notarised is**, wat 'n bykomende sekuriteitslaag bied. Die notarisation-proses kontroleer die application vir bekende sekuriteitskwessies en malicious code, en as hierdie kontroles slaag, voeg Apple 'n ticket by die application wat Gatekeeper kan verifieer.

#### Check Signatures

Wanneer jy 'n **malware sample** kontroleer, moet jy altyd die **signature nagaan**, aangesien die **developer** wat dit onderteken het, moontlik reeds **met malware verband hou.**
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
### Notarization

Apple se notarization-proses dien as 'n bykomende beveiliging om gebruikers teen potensieel skadelike sagteware te beskerm. Dit behels dat die **ontwikkelaar hul toepassing vir ondersoek indien** deur **Apple's Notary Service**, wat nie met App Review verwar moet word nie. Hierdie diens is 'n **geoutomatiseerde stelsel** wat die ingediende sagteware ondersoek vir die teenwoordigheid van **kwaadwillige inhoud** en enige potensiële probleme met code-signing.

As die sagteware hierdie inspeksie **slaag** sonder om enige kommer te wek, genereer die Notary Service 'n notarization-ticket. Die ontwikkelaar moet dan hierdie ticket **aan hul sagteware heg**, 'n proses wat as 'stapling' bekend staan. Verder word die notarization-ticket ook aanlyn gepubliseer, waar Gatekeeper, Apple's sekuriteitstegnologie, toegang daartoe kan kry.

Wanneer die gebruiker die sagteware vir die eerste keer installeer of uitvoer, **stel die bestaan van die notarization-ticket - hetsy dit aan die uitvoerbare lêer geheg is of aanlyn gevind word - Gatekeeper in kennis dat die sagteware deur Apple genotariseer is**. Gevolglik vertoon Gatekeeper 'n beskrywende boodskap in die aanvanklike bekendstellingsdialoog, wat aandui dat Apple die sagteware vir kwaadwillige inhoud nagegaan het. Hierdie proses verhoog sodoende gebruikers se vertroue in die sekuriteit van die sagteware wat hulle op hul stelsels installeer of uitvoer.

### spctl & syspolicyd

> [!CAUTION]
> Let daarop dat **`spctl`** vanaf die Sequoia-weergawe nie meer toelaat dat die Gatekeeper-konfigurasie gewysig word nie.

**`spctl`** is die CLI-instrument om Gatekeeper op te som en daarmee interaksie te hê (met die `syspolicyd`-daemon via XPC-boodskappe). Dit is byvoorbeeld moontlik om die **status** van GateKeeper te sien met:
```bash
# Check the status
spctl --status
```
> [!CAUTION]
> Let daarop dat GateKeeper-handtekeningkontroles slegs uitgevoer word op **lêers met die Quarantine-attribuut**, nie op elke lêer nie.

GateKeeper sal volgens die **voorkeure en die handtekening** kontroleer of ’n binary uitgevoer kan word:

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`** is die hoofdaemon wat verantwoordelik is vir die afdwinging van Gatekeeper. Dit hou ’n databasis by wat in `/var/db/SystemPolicy` geleë is, en dit is moontlik om die kode ter ondersteuning van die [databasis hier](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp) en die [SQL-sjabloon hier](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql) te vind. Let daarop dat die databasis nie deur SIP beperk word nie en deur root geskryf kan word, en dat die databasis `/var/db/.SystemPolicy-default` as ’n oorspronklike rugsteun gebruik word indien die ander een korrup raak.

Daarbenewens bevat die bundles **`/var/db/gke.bundle`** en **`/var/db/gkopaque.bundle`** lêers met reëls wat in die databasis ingevoeg word. Jy kan hierdie databasis as root nagaan met:
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
**`syspolicyd`** stel ook ’n XPC-bediener bloot met verskillende operasies soos `assess`, `update`, `record` en `cancel`, wat ook bereikbaar is deur **`Security.framework` se `SecAssessment*`**-API’s, en **`spctl`** kommunikeer eintlik via XPC met **`syspolicyd`**.

Let daarop dat die eerste reël met "**App Store**" geëindig het en die tweede een met "**Developer ID**", en dat dit in die vorige afbeelding **geaktiveer was om apps van die App Store en geïdentifiseerde ontwikkelaars uit te voer**.\
As jy daardie instelling **wysig** na App Store, sal die "**Notarized Developer ID"-reëls verdwyn**.

Daar is ook duisende reëls van **tipe GKE**:
```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```
Dit is hashes vanaf:

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

Dit is moontlik om **na te gaan of ’n App deur GateKeeper toegelaat sal word** met:
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
Wat **kernel extensions** betref, bevat die vouer `/var/db/SystemPolicyConfiguration` lêers met lyste van kexts wat toegelaat word om gelaai te word. Boonop het `spctl` die entitlement `com.apple.private.iokit.nvram-csr`, omdat dit nuwe voorafgoedgekeurde kernel extensions kan byvoeg wat ook in NVRAM onder ’n `kext-allowed-teams`-sleutel gestoor moet word.

#### Bestuur van Gatekeeper op macOS 15 (Sequoia) en later

- Die jarelange Finder-omseiling met **Ctrl+Open / Regsklik → Open** is verwyder; gebruikers moet ’n geblokkeerde app uitdruklik toelaat via **Stelselinstellings → Privaatheid en sekuriteit → Open in elk geval** nadat die eerste blokkeringsdialoog verskyn het.<sup>[[4]](#references)</sup>
- `spctl --master-disable/--global-disable` word nie meer aanvaar nie; `spctl` is effektief slegs-lees vir assessering en etiketbestuur, terwyl beleidsafdwinging deur die UI of MDM gekonfigureer word.

Vanaf macOS 15 Sequoia kan eindgebruikers nie meer Gatekeeper-beleid vanaf `spctl` wissel nie. Bestuur word via Stelselinstellings uitgevoer, of deur ’n MDM-konfigurasieprofiel met die `com.apple.systempolicy.control`-payload te ontplooi. Voorbeeldprofielbrokkie om App Store en geïdentifiseerde ontwikkelaars toe te laat (maar nie “Enige plek” nie):

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

Wanneer 'n toepassing of lêer **afgelaai** word, heg spesifieke macOS-**toepassings**, soos webblaaiers of e-poskliënte, 'n **uitgebreide lêerkenmerk** aan, algemeen bekend as die "**kwarantynvlag**," aan die afgelaaide lêer. Hierdie kenmerk dien as 'n sekuriteitsmaatreël om die **lêer te merk** as afkomstig van 'n onbetroubare bron (die internet), en as moontlik riskant. Nie alle toepassings heg egter hierdie kenmerk aan nie; algemene BitTorrent-kliëntprogrammatuur omseil hierdie proses gewoonlik.

**Die teenwoordigheid van 'n kwarantynvlag aktiveer macOS se Gatekeeper-sekuriteitsfunksie wanneer 'n gebruiker probeer om die lêer uit te voer**.

In die geval waar die **kwarantynvlag nie teenwoordig is nie** (soos met lêers wat via sommige BitTorrent-kliënte afgelaai word), **word Gatekeeper se kontroles moontlik nie uitgevoer nie**. Gebruikers moet dus versigtig wees wanneer hulle lêers oopmaak wat van minder veilige of onbekende bronne afgelaai is.

> [!NOTE] > **Om** die **geldigheid** van code signatures te **kontroleer**, is 'n **hulpbronintensiewe** proses wat kriptografiese **hashes** van die code en al sy gebundelde hulpbronne genereer. Daarbenewens behels die kontrolering van sertifikaatgeldigheid 'n **aanlynkontrole** by Apple se bedieners om vas te stel of dit herroep is nadat dit uitgereik is. Om hierdie redes is dit **onprakties om 'n volledige code signature- en notarization-kontrole uit te voer elke keer wanneer 'n toepassing geloods word**.
>
> Daarom word hierdie kontroles **slegs uitgevoer wanneer toepassings met die kwarantynkenmerk uitgevoer word.**

> [!WARNING]
> Hierdie kenmerk moet **gestel word deur die toepassing wat** die lêer skep/aflaai.
>
> Lêers wat gesandbox is, sal egter hierdie kenmerk hê vir elke lêer wat hulle skep. En nie-sandboxed toepassings kan dit self stel, of die [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc)-sleutel in die **Info.plist** spesifiseer, wat die stelsel sal laat om die `com.apple.quarantine` uitgebreide kenmerk te stel op die lêers wat geskep word,

Verder word alle lêers wat deur 'n proses geskep word wat **`qtn_proc_apply_to_self`** aanroep, in kwarantyn geplaas. Of die API **`qtn_file_apply_to_path`** voeg die kwarantynkenmerk by 'n gespesifiseerde lêerpad.

Dit is moontlik om die **status daarvan te kontroleer en dit te aktiveer/deaktiveer** (root word vereis) met:
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
Jy kan ook **bepaal of ’n lêer die quarantine extended attribute het** met:
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
Kontroleer die **waarde** van die **extended** **attributes** en vind uit watter app die quarantine attr geskryf het met:
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
Trouens, ’n proses "could set quarantine flags to the files it creates" (Ek het reeds probeer om die USER_APPROVED-vlag op ’n geskepte lêer toe te pas, maar dit word nie toegepas nie):

<details>

<summary>Bronkode: pas kwarantynvlae toe</summary>
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
En vind alle lêers in kwarantyn met:
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
Quarantine-inligting word ook gestoor in ’n sentrale databasis wat deur LaunchServices bestuur word in **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**, wat die GUI toelaat om data oor die lêer se oorsprong te verkry. Boonop kan dit oorskryf word deur applications wat dalk daarin belangstel om die oorsprong daarvan te versteek. Dit kan ook vanaf LaunchServices APIs gedoen word.

#### **libquarantine.dylib**

Hierdie library export verskeie functions waarmee die extended attribute-velde gemanipuleer kan word.

Die `qtn_file_*` APIs hanteer file quarantine policies, terwyl die `qtn_proc_*` APIs op prosesse toegepas word (lêers wat deur die proses geskep word). Die unexported `__qtn_syscall_quarantine*` functions is dié wat die policies toepas. Dit roep `mac_syscall` aan met "Quarantine" as die eerste argument, wat die versoeke na `Quarantine.kext` stuur.

#### **Quarantine.kext**

Die kernel extension is slegs deur die **kernel cache op die stelsel** beskikbaar; jy _kan egter die **Kernel Debug Kit vanaf** [**https://developer.apple.com/**](https://developer.apple.com/) aflaai, wat ’n gesimboliseerde weergawe van die extension sal bevat.

Hierdie Kext sal via MACF aan verskeie calls hook om alle file lifecycle events te onderskep: skepping, opening, hernoeming, hard-linking... selfs `setxattr`, om te voorkom dat dit die `com.apple.quarantine` extended attribute stel.

Dit gebruik ook ’n paar MIBs:

- `security.mac.qtn.sandbox_enforce`: Enforce quarantine saam met Sandbox
- `security.mac.qtn.user_approved_exec`: Quarantined prosesse kan slegs goedgekeurde lêers uitvoer

#### Provenance xattr (Ventura en later)

macOS 13 Ventura het ’n afsonderlike provenance-meganisme bekendgestel wat gevul word die eerste keer wat ’n quarantined app toegelaat word om te run.<sup>[[2]](#references)</sup> Twee artefacts word geskep:

- Die `com.apple.provenance` xattr op die `.app` bundle-gids (’n vaste-grootte binary-waarde wat ’n primary key en flags bevat).
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

Die XProtect-databasis word **gereeld** deur Apple met nuwe malware-definisies **bygewerk**, en hierdie opdaterings word outomaties op jou Mac afgelaai en geïnstalleer. Dit verseker dat XProtect altyd op datum is met die jongste bekende bedreigings.

Dit is egter belangrik om daarop te let dat **XProtect nie ’n volledige antivirusoplossing is nie**. Dit kontroleer slegs vir ’n spesifieke lys bekende bedreigings en voer nie on-access scanning uit soos die meeste antivirusprogrammatuur nie.

Jy kan inligting oor die jongste XProtect-opdatering kry deur die volgende uit te voer:
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
XProtect is geleë in die SIP-beskermde ligging **/Library/Apple/System/Library/CoreServices/XProtect.bundle**, en binne die bundle kan jy inligting vind wat XProtect gebruik:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Laat code met daardie cdhashes toe om legacy entitlements te gebruik.
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: Lys van plugins en extensions wat nie toegelaat word om te laai nie, deur BundleID en TeamID, of wat ’n minimum weergawe aandui.
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Yara-reëls om malware op te spoor.
- **`XProtect.bundle/Contents/Resources/gk.db`**: SQLite3-databasis met hashes van geblokkeerde applications en TeamIDs.

Let daarop dat daar nog ’n App in **`/Library/Apple/System/Library/CoreServices/XProtect.app`** is wat met XProtect verband hou, maar wat nie by die Gatekeeper-proses betrokke is nie.

> XProtect Remediator: Op moderne macOS verskaf Apple on-demand scanners (XProtect Remediator) wat periodiek via launchd loop om families van malware op te spoor en te remedieer. Jy kan hierdie scans in unified logs waarneem:
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### Nie Gatekeeper nie

> [!CAUTION]
> Let daarop dat Gatekeeper **nie elke keer uitgevoer word** wanneer jy ’n application uitvoer nie; slegs _**AppleMobileFileIntegrity**_ (AMFI) sal **uitvoerbare code signatures verifieer** wanneer jy ’n app uitvoer wat reeds deur Gatekeeper uitgevoer en geverifieer is.

Daarom was dit voorheen moontlik om ’n app uit te voer om dit met Gatekeeper te cache, daarna **nie-uitvoerbare files van die application te wysig** (soos Electron asar- of NIB-files), en indien geen ander protections in plek was nie, is die application met die **malicious** toevoegings **uitgevoer**.

Dit is egter nou nie meer moontlik nie omdat macOS **verhoed dat files** binne application bundles gewysig word. As jy dus die [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md)-attack probeer, sal jy vind dat dit nie meer moontlik is om dit te abuse nie, omdat jy ná die uitvoering van die app om dit met Gatekeeper te cache, nie die bundle sal kan wysig nie. En as jy byvoorbeeld die naam van die Contents-directory na NotCon verander (soos in die exploit aangedui word), en dan die hoofbinary van die app uitvoer om dit met Gatekeeper te cache, sal dit ’n error trigger en nie uitvoer nie.

## Gatekeeper Bypasses

Enige manier om Gatekeeper te bypass (om daarin te slaag om die user iets te laat download en uitvoer wanneer Gatekeeper dit behoort te disallow) word as ’n vulnerability in macOS beskou. Hier is ’n paar CVEs wat toegeken is aan techniques wat in die verlede toegelaat het dat Gatekeeper gebypass word:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Daar is waargeneem dat, indien die **Archive Utility** vir extraction gebruik word, files met **paths wat 886 characters oorskry** nie die com.apple.quarantine extended attribute ontvang nie. Hierdie situasie laat daardie files onbedoeld toe om **Gatekeeper se** security checks te **omseil**.<sup>[[5]](#references)</sup>

Raadpleeg die [**original report**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) vir meer inligting.<sup>[[5]](#references)</sup>

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Wanneer ’n application met **Automator** geskep word, is die inligting oor wat dit moet uitvoer binne `application.app/Contents/document.wflow`, en nie in die executable nie. Die executable is slegs ’n generiese Automator-binary genaamd **Automator Application Stub**.

Daarom kon jy `application.app/Contents/MacOS/Automator\ Application\ Stub` **met ’n symbolic link na ’n ander Automator Application Stub binne die system laat wys**, en dit sal uitvoer wat binne `document.wflow` is (jou script) **sonder om Gatekeeper te trigger**, omdat die werklike executable nie die quarantine xattr het nie.<sup>[[6]](#references)</sup>

Voorbeeld van die verwagte ligging: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Raadpleeg die [**original report**](https://ronmasas.com/posts/bypass-macos-gatekeeper) vir meer inligting.<sup>[[6]](#references)</sup>

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

In hierdie bypass is ’n zip-file geskep met ’n application wat begin compress het vanaf `application.app/Contents` in plaas van `application.app`. Daarom is die **quarantine attr** op al die **files vanaf `application.app/Contents`** toegepas, maar **nie op `application.app` nie**. Dit is waarna Gatekeeper gekyk het, en Gatekeeper is dus gebypass omdat `application.app`, toe dit getrigger is, **nie die quarantine attribute gehad het nie.**<sup>[[7]](#references)</sup>
```bash
zip -r test.app/Contents test.zip
```
Kyk na die [**oorspronklike verslag**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) vir meer inligting.<sup>[[7]](#references)</sup>

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Selfs al verskil die komponente, is die uitbuiting van hierdie kwesbaarheid baie soortgelyk aan die vorige een. In hierdie geval sal ons ’n Apple Archive vanaf **`application.app/Contents`** genereer, sodat **`application.app` nie die quarantine-attribuut sal kry wanneer dit deur **Archive Utility** gedekomprimeer word nie**.<sup>[[8]](#references)</sup>
```bash
aa archive -d test.app/Contents -o test.app.aar
```
Raadpleeg die [**oorspronklike verslag**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) vir meer inligting.<sup>[[8]](#references)</sup>

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

Die ACL **`writeextattr`** kan gebruik word om te verhoed dat enigiemand 'n attribuut in 'n lêer skryf:
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
Boonop kopieer die **AppleDouble**-lêerformaat ’n lêer insluitend sy ACEs.<sup>[[9]](#references)</sup>

In die [**broncode**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) is dit moontlik om te sien dat die ACL-teksvoorstelling wat binne die xattr genaamd **`com.apple.acl.text`** gestoor is, as ACL in die gedekomprimeerde lêer gestel gaan word. Dus, as jy ’n toepassing in ’n zip-lêer met die **AppleDouble**-lêerformaat saamgepers het, met ’n ACL wat verhoed dat ander xattrs daarin geskryf word... is die quarantine xattr nie op die toepassing gestel nie:
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
Raadpleeg die [**oorspronklike verslag**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) vir meer inligting.<sup>[[9]](#references)</sup>

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

AppleDouble stoor ’n lêer se attributes in ’n aparte lêer waarvan die naam met `._` begin; dit help om lêerattributes **tussen macOS-masjiene** te kopieer. Nadat ’n AppleDouble-lêer gedekomprimeer is, **is die quarantine attribute nie aan die lêer wat met `._` begin, toegeken nie**.<sup>[[11]](#references)</sup>
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you download and decompress the resulting test.aar, test/._a won't have a quarantine attribute
```
Deur ’n lêer te kon skep waarop die quarantine-attribuut nie gestel sou word nie, was dit **moontlik om Gatekeeper te omseil.** Die truuk was om ’n **DMG-lêer-toepassing** te skep deur die AppleDouble-naamkonvensie te gebruik (begin dit met `._`) en ’n **sigbare lêer as ’n simskakel na hierdie versteekte** lêer sonder die quarantine-attribuut te skep.\
Wanneer die **dmg-lêer uitgevoer word**, sal dit, aangesien dit nie ’n quarantine-attribuut het nie, **Gatekeeper omseil**.
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

'n Gatekeeper-bypass wat in macOS Sonoma 14.0 reggestel is, het toegelaat dat vervaardigde apps sonder 'n versoek uitgevoer word. Besonderhede is ná die patching publiek bekend gemaak, en die probleem is voor die regstelling aktief in die wild uitgebuit. Maak seker dat Sonoma 14.0 of later geïnstalleer is.<sup>[[13]](#references)</sup>

### [CVE-2024-27853]

'n Gatekeeper-bypass in macOS 14.4 (vrygestel in Maart 2024), wat voortgespruit het uit `libarchive` se hantering van kwaadwillige ZIPs, het toegelaat dat apps assessment ontduik. Dateer op na 14.4 of later, waar Apple die probleem aangespreek het.<sup>[[1]](#references)</sup>

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

'n **Automator Quick Action workflow** wat in 'n afgelaaide app ingebed is, kon sonder Gatekeeper-assessment geaktiveer word, omdat workflows as data behandel en deur die Automator-helper buite die normale notarization-prompt-pad uitgevoer is. 'n Vervaardigde `.app` wat 'n Quick Action bundel wat 'n shell script uitvoer (byvoorbeeld binne `Contents/PlugIns/*.workflow/Contents/document.wflow`), kon dus onmiddellik tydens launch uitgevoer word. Apple het 'n ekstra toestemmingsdialoog bygevoeg en die assessment-pad in Ventura **13.7**, Sonoma **14.7** en Sequoia **15** reggestel.<sup>[[3]](#references)</sup>

### Third‑party unarchivers wat quarantine verkeerdelik oordra (2023–2024)

Verskeie kwesbaarhede in gewilde extraction tools (byvoorbeeld The Unarchiver) het veroorsaak dat lêers wat uit archives onttrek is, die `com.apple.quarantine` xattr mis, wat Gatekeeper-bypass-geleenthede moontlik gemaak het. Maak altyd staat op macOS Archive Utility of patched tools wanneer jy toets, en valideer xattrs ná extraction.

### uchg (uit hierdie [talk](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

- Skep 'n directory wat 'n app bevat.
- Voeg uchg by die app.
- Compress die app na 'n tar.gz-lêer.
- Stuur die tar.gz-lêer aan 'n slagoffer.
- Die slagoffer maak die tar.gz-lêer oop en run die app.
- Gatekeeper check nie die app nie.<sup>[[12]](#references)</sup>

### Voorkom Quarantine xattr

In 'n ".app"-bundle, as die quarantine xattr nie daarby gevoeg word nie, sal **Gatekeeper nie ge-trigger word nie** wanneer dit uitgevoer word.

## References

- [1] [Apple Platform Security: Oor die sekuriteitsinhoud van macOS Sonoma 14.4 (sluit CVE-2024-27853 in)](https://support.apple.com/en-us/HT214084)
- [2] [Eclectic Light: Hoe macOS nou die herkoms van apps naspoor](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- [3] [Apple: Oor die sekuriteitsinhoud van macOS Sonoma 14.7 / Ventura 13.7 (CVE-2024-44128)](https://support.apple.com/en-us/121234)
- [4] [MacRumors: macOS 15 Sequoia verwyder die Control‑click-“Open”-Gatekeeper-bypass](https://www.macrumors.com/2024/06/11/macos-sequoia-removes-open-anyway/)
- [5] [WithSecure Labs: Die ontdekking van CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)
- [6] [CVE-2021-30990, Omseiling van die macOS Gatekeeper](https://ronmasas.com/posts/bypass-macos-gatekeeper)
- [7] [Jamf Threat Labs identifiseer Safari-kwesbaarheid wat Gatekeeper-bypass moontlik maak](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)
- [8] [Jamf Threat Labs identifiseer macOS Archive Utility-kwesbaarheid wat Gatekeeper-bypass moontlik maak (CVE-2022-32910)](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)
- [9] [Gatekeeper se Achilles-hiel: 'n macOS-kwesbaarheid ontbloot](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [10] [F-Secure: Ontdekking van 'n Gatekeeper-bypass (CVE-2023-27943)](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)
- [11] [Vind en rapporteer 'n Gatekeeper-bypass-exploit met hulp van Mac Monitor](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)
- [12] [CODE BLUE 2023: Omseiling van macOS-sekuriteits- en privaatheidsmeganismes — Van Gatekeeper tot System Integrity Protection (Koh Nakagawa)](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf)
- [13] [Apple: Oor die sekuriteitsinhoud van macOS Sonoma 14 (CVE-2023-41067)](https://support.apple.com/en-us/HT213940)
{{#include ../../../banners/hacktricks-training.md}}
