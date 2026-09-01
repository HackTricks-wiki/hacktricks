# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

**Gatekeeper** is ’n sekuriteitsfunksie wat vir Mac-bedryfstelsels ontwikkel is, en wat ontwerp is om te verseker dat gebruikers **slegs trusted software** op hul stelsels **run**. Dit funksioneer deur **software** te **valideer** wat ’n gebruiker aflaai en probeer oopmaak vanaf **sources** buite die App Store, soos ’n app, ’n plug-in of ’n installer package.

Die sleutelmeganisme van Gatekeeper lê in sy **verification**-proses. Dit kontroleer of die afgelaaide **software** **signed** is deur ’n erkende developer, om die software se egtheid te verseker. Verder bepaal dit of die software deur Apple **notarised** is, wat bevestig dat dit vry is van bekende malicious content en nie ná notarisation gemanipuleer is nie.

Daarbenewens versterk Gatekeeper gebruikersbeheer en sekuriteit deur gebruikers te **prompt om die opening goed te keur** van afgelaaide software wanneer dit die eerste keer oopgemaak word. Hierdie beveiliging help voorkom dat gebruikers per ongeluk potensieel skadelike executable code uitvoer wat hulle dalk vir ’n onskadelike data file aangesien het.

### Toepassingshandtekeninge

Application signatures, ook bekend as code signatures, is ’n kritieke komponent van Apple se sekuriteitsinfrastruktuur. Hulle word gebruik om die **identiteit van die software author** (die developer) te **verifieer** en om te verseker dat die code nie gemanipuleer is sedert dit laas signed is nie.

Hier is hoe dit werk:

1. **Signing the Application:** Wanneer ’n developer gereed is om sy application te versprei, **sign** hy die application met behulp van ’n **private key**. Hierdie private key word geassosieer met ’n **certificate wat Apple aan die developer uitreik** wanneer hy by die Apple Developer Program inskryf. Die signing-proses behels die skep van ’n cryptographic hash van alle dele van die app en die encryption van hierdie hash met die developer se private key.
2. **Distributing the Application:** Die signed application word dan saam met die developer se certificate aan gebruikers versprei; dit bevat die ooreenstemmende public key.
3. **Verifying the Application:** Wanneer ’n gebruiker die application aflaai en probeer run, gebruik hul Mac-bedryfstelsel die public key uit die developer se certificate om die hash te decrypt. Dit bereken dan die hash weer op grond van die application se huidige toestand en vergelyk dit met die decrypted hash. Indien hulle ooreenstem, beteken dit dat **die application nie modified is nie** sedert die developer dit signed het, en die stelsel laat toe dat die application run.

Application signatures is ’n noodsaaklike deel van Apple se Gatekeeper-tegnologie. Wanneer ’n gebruiker probeer om **’n application oop te maak wat van die internet afgelaai is**, verifieer Gatekeeper die application signature. As dit signed is met ’n certificate wat deur Apple aan ’n bekende developer uitgereik is en die code nie gemanipuleer is nie, laat Gatekeeper die application run. Andersins blokkeer dit die application en waarsku die gebruiker.

Vanaf macOS Catalina **kontroleer Gatekeeper ook of die application deur Apple notarized is**, wat ’n ekstra sekuriteitslaag toevoeg. Die notarization-proses kontroleer die application vir bekende sekuriteitskwessies en malicious code. Indien hierdie kontroles slaag, voeg Apple ’n ticket by die application wat Gatekeeper kan verifieer.

#### Check Signatures

Wanneer jy ’n **malware sample** kontroleer, moet jy altyd die **signature** van die binary **check**, aangesien die **developer** wat dit signed het, dalk reeds met **malware** **related** is.
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

Apple se notariseringsproses dien as 'n bykomende waarborg om gebruikers teen potensieel skadelike sagteware te beskerm. Dit behels dat die **ontwikkelaar hul toepassing vir ondersoek indien** deur **Apple's Notary Service**, wat nie met App Review verwar moet word nie. Hierdie diens is 'n **geoutomatiseerde stelsel** wat die ingediende sagteware ondersoek vir die teenwoordigheid van **kwaadwillige inhoud** en enige moontlike probleme met code-signing.

As die sagteware hierdie inspeksie **slaag** sonder om enige kommer te wek, genereer die Notary Service 'n notariseringskaartjie. Die ontwikkelaar moet dan **hierdie kaartjie aan hul sagteware heg**, 'n proses wat as 'stapling' bekend staan. Verder word die notariseringskaartjie ook aanlyn gepubliseer, waar Gatekeeper, Apple's security technology, toegang daartoe kan verkry.

Wanneer die gebruiker die sagteware die eerste keer installeer of uitvoer, **lig** die bestaan van die notariseringskaartjie - hetsy dit aan die uitvoerbare lêer geheg is of aanlyn gevind word - **Gatekeeper in dat die sagteware deur Apple genotariseer is**. Gevolglik vertoon Gatekeeper 'n beskrywende boodskap in die aanvanklike lanseringsdialoog, wat aandui dat die sagteware deur Apple vir kwaadwillige inhoud nagegaan is. Hierdie proses verhoog sodoende gebruikers se vertroue in die veiligheid van die sagteware wat hulle op hul stelsels installeer of uitvoer.

### spctl & syspolicyd

> [!CAUTION]
> Let daarop dat **`spctl`** vanaf die Sequoia-weergawe nie meer die wysiging van Gatekeeper se konfigurasie toelaat nie.

**`spctl`** is die CLI-instrument om Gatekeeper op te som en daarmee te kommunikeer (met die `syspolicyd`-daemon via XPC-boodskappe). Dit is byvoorbeeld moontlik om die **status** van GateKeeper te sien met:
```bash
# Check the status
spctl --status
```
> [!CAUTION]
> Let daarop dat GateKeeper-handtekeningkontroles slegs uitgevoer word op **lêers met die Quarantine-kenmerk**, nie op elke lêer nie.

GateKeeper sal kontroleer of ’n binary volgens die **voorkeure & die handtekening** uitgevoer kan word:

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`** is die hoofdemon wat verantwoordelik is vir die afdwinging van Gatekeeper. Dit onderhou ’n databasis wat in `/var/db/SystemPolicy` geleë is, en dit is moontlik om die kode vir ondersteuning van die [databasis hier](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp) en die [SQL-sjabloon hier](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql) te vind. Let daarop dat die databasis nie deur SIP beperk word nie en deur root geskryf kan word, en dat die databasis `/var/db/.SystemPolicy-default` as ’n oorspronklike rugsteun gebruik word indien die ander een korrup raak.

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
**`syspolicyd`** stel ook 'n XPC-bediener bloot met verskillende bewerkings soos `assess`, `update`, `record` en `cancel`, wat ook bereikbaar is deur **`Security.framework` se `SecAssessment*`** APIs, en **`spctl`** kommunikeer eintlik met **`syspolicyd`** via XPC.

Let daarop hoe die eerste reël met "**App Store**" geëindig het en die tweede een met "**Developer ID**", en dat dit in die vorige beeld **geaktiveer was om apps vanaf die App Store en geïdentifiseerde ontwikkelaars uit te voer**.\
As jy daardie instelling na App Store **wysig**, sal die "**Notarized Developer ID**"-reëls verdwyn.

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
Die opsies **`--master-disable`** en **`--global-disable`** van **`spctl`** sal hierdie handtekeningkontroles volledig **deaktiveer**:
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
Op macOS 14 en later is **`syspolicy_check`** ’n nuttige hoërvlak-kontrole voor verspreiding vir ’n application bundle. Dit lewer meer bruikbare trusted-execution-diagnostiek as ’n blote **`spctl`**-resultaat, hoewel Apple steeds aanbeveel dat die werklike aflaai-/onttrekkings-/eerste-begin-pad getoets word, omdat dit ook quarantine propagation toets.<sup>[[14]](#references)</sup>
```bash
# Check the complete app bundle before distribution
syspolicy_check distribution /path/to/App.app

# Keep the lower-level assessment when comparing policy outcomes
spctl --assess --type execute -vv /path/to/App.app
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
Met betrekking tot **kernel extensions** bevat die vouer `/var/db/SystemPolicyConfiguration` lêers met lyste van kexts wat gelaai mag word. Boonop het `spctl` die entitlement `com.apple.private.iokit.nvram-csr`, omdat dit nuwe voorafgoedgekeurde kernel extensions kan byvoeg wat ook in NVRAM in ’n `kext-allowed-teams`-sleutel gestoor moet word.

#### Bestuur van Gatekeeper op macOS 15 (Sequoia) en later

- Die jarelange Finder **Ctrl+Open / Right-click → Open**-omseiling is verwyder; gebruikers moet ’n geblokkeerde app uitdruklik toelaat via **System Settings → Privacy & Security → Open Anyway** nadat die eerste blokkeringsdialoog verskyn het.<sup>[[4]](#references)</sup>
- `spctl --master-disable/--global-disable` word nie meer as onbeheerde beleidsveranderings aanvaar nie. Bewerkings wat die reëldatabasis of die globale assesseringstoestand wysig, is deprecated; gebruik dus `spctl` vir assessering en stel enforcement deur die UI of MDM op.

Vanaf macOS 15 Sequoia kan eindgebruikers nie meer die Gatekeeper-beleid vanuit `spctl` wissel nie. Bestuur word via System Settings uitgevoer of deur ’n MDM-konfigurasieprofiel met die `com.apple.systempolicy.control`-payload te ontplooi. Voorbeeldprofiel-fragment om App Store en geïdentifiseerde developers toe te laat (maar nie "Anywhere" nie):

<details>
<summary>MDM-profiel om App Store en geïdentifiseerde developers toe te laat</summary>
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

Wanneer 'n toepassing of lêer **afgelaai** word, **heg** spesifieke macOS-**toepassings**, soos webblaaiers of e-poskliënte, 'n uitgebreide lêerkenmerk, algemeen bekend as die "**quarantine flag**", aan die afgelaaide lêer. Hierdie kenmerk dien as 'n sekuriteitsmaatreël om **die lêer te merk** as afkomstig van 'n onbetroubare bron (die internet), en as iets wat moontlik risiko's kan inhou. Nie alle toepassings heg egter hierdie kenmerk aan nie; algemene BitTorrent-kliëntsagteware omseil hierdie proses gewoonlik.

**Die teenwoordigheid van 'n quarantine flag dui Gatekeeper se macOS-sekuriteitsfunksie aan wanneer 'n gebruiker probeer om die lêer uit te voer**.

In die geval waar die **quarantine flag nie teenwoordig is nie** (soos met lêers wat via sommige BitTorrent-kliënte afgelaai word), **mag Gatekeeper se kontroles nie uitgevoer word nie**. Gebruikers moet dus versigtig wees wanneer hulle lêers oopmaak wat van minder veilige of onbekende bronne afgelaai is.

> [!NOTE] > **Om** die **geldigheid** van code signatures na te gaan, is 'n **hulpbron-intensiewe** proses wat die generering van kriptografiese **hashes** van die code en al sy gebundelde hulpbronne insluit. Verder behels die kontrolering van sertifikaatgeldigheid 'n **aanlynkontrole** by Apple se bedieners om te bepaal of dit herroep is nadat dit uitgereik is. Om hierdie redes is dit **onprakties om elke keer wanneer 'n toepassing geloods word, 'n volledige code signature- en notarization-kontrole uit te voer**.
>
> Daarom word hierdie kontroles **slegs uitgevoer wanneer toepassings met die quarantined-kenmerk uitgevoer word.**

> [!WARNING]
> Hierdie kenmerk moet **deur die toepassing wat die lêer skep/aflaai, gestel word**.
>
> Lêers wat sandboxed is, sal egter hierdie kenmerk op elke lêer wat hulle skep, stel. Nie-sandboxed toepassings kan dit self stel, of die [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc)-sleutel in die **Info.plist** spesifiseer, wat die stelsel sal laat om die `com.apple.quarantine`-uitgebreide kenmerk op die geskepte lêers te stel,

Verder word alle lêers wat deur 'n proses geskep word wat **`qtn_proc_apply_to_self`** aanroep, gekwarantyn. Of die API **`qtn_file_apply_to_path`** voeg die quarantine-kenmerk by 'n gespesifiseerde lêerpad.

Dit is moontlik om **die status daarvan na te gaan en dit te aktiveer/deaktiveer** (root benodig) met:
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
Eintlik kan 'n proses "quarantine flags stel op die lêers wat dit skep" (Ek het reeds probeer om die USER_APPROVED-flag in 'n geskepte lêer toe te pas, maar dit wil dit nie aanvaar nie):

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
En vind al die lêers wat in kwarantyn geplaas is met:
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
Quarantine-inligting word ook in ’n sentrale databasis gestoor wat deur LaunchServices in **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`** bestuur word, wat die GUI toelaat om data oor die lêeroorsprong te verkry. Dit kan boonop deur toepassings oorskryf word wat dalk daarin belangstel om die oorsprong daarvan weg te steek. Dit kan ook vanaf LaunchServices APIS gedoen word.

#### **libquarantine.dylib**

Hierdie biblioteek eksporteer verskeie funksies wat dit moontlik maak om die uitgebreide attribuutvelde te manipuleer.

Die `qtn_file_*` APIs hanteer lêer-Quarantine-beleide, terwyl die `qtn_proc_*` APIs op prosesse toegepas word (lêers wat deur die proses geskep word). Die nie-geëksporteerde `__qtn_syscall_quarantine*`-funksies is die funksies wat die beleide toepas. Hulle roep `mac_syscall` aan met "Quarantine" as die eerste argument, wat die versoeke na `Quarantine.kext` stuur.

#### **Quarantine.kext**

Die kernel extension is slegs deur die **kernel cache op die stelsel** beskikbaar; jy kan egter die **Kernel Debug Kit vanaf** [**https://developer.apple.com/**](https://developer.apple.com/) aflaai, wat ’n gesimboliseerde weergawe van die extension sal bevat.

Hierdie Kext sal via MACF aan verskeie oproepe haak om alle lêerlewensiklusgebeurtenisse te onderskep: skepping, opening, hernoeming, hard-linking... selfs `setxattr`, om te voorkom dat dit die `com.apple.quarantine`-uitgebreide attribuut instel.

Dit gebruik ook ’n paar MIBs:

- `security.mac.qtn.sandbox_enforce`: Dwing Quarantine saam met Sandbox af
- `security.mac.qtn.user_approved_exec`: Quarantined procs kan slegs goedgekeurde lêers uitvoer

#### Provenance xattr (Ventura en later)

macOS 13 Ventura het ’n afsonderlike provenance-meganisme bekendgestel wat gevul word wanneer ’n Quarantined app die eerste keer toegelaat word om te loop.<sup>[[2]](#references)</sup> Twee artefakte word geskep:

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

Die XProtect-databasis word **gereeld** deur Apple opgedateer met nuwe malware-definisies, en hierdie opdaterings word outomaties op jou Mac afgelaai en geïnstalleer. Dit verseker dat XProtect altyd op datum is met die jongste bekende bedreigings.

Dit is egter belangrik om daarop te let dat **XProtect nie ’n antivirusoplossing met volledige funksionaliteit is nie**. Dit kontroleer slegs vir ’n spesifieke lys bekende bedreigings en voer nie on-access scanning uit soos die meeste antivirusprogrammatuur nie.

Jy kan inligting oor die jongste XProtect-opdatering kry deur die volgende uit te voer:
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
XProtect is geleë op die SIP-beskermde ligging **/Library/Apple/System/Library/CoreServices/XProtect.bundle**, en binne die bundle kan jy inligting vind wat XProtect gebruik:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Laat kode met daardie cdhashes toe om legacy entitlements te gebruik.
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: Lys plugins en extensions wat nie toegelaat word om te laai nie, via BundleID en TeamID, of dui ’n minimum weergawe aan.
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Yara rules om malware op te spoor.
- **`XProtect.bundle/Contents/Resources/gk.db`**: SQLite3-databasis met hashes van geblokkeerde applications en TeamIDs.

Let daarop dat daar nog ’n App in **`/Library/Apple/System/Library/CoreServices/XProtect.app`** is wat met XProtect verband hou, maar dit is nie betrokke by die Gatekeeper-proses nie.

> XProtect Remediator: Op moderne macOS lewer Apple on-demand scanners (XProtect Remediator) wat periodiek via launchd loop om families van malware op te spoor en te remedieer. Jy kan hierdie scans in unified logs waarneem:
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### Nie Gatekeeper nie

> [!CAUTION]
> Let daarop dat Gatekeeper **nie elke keer uitgevoer word** wanneer jy ’n application uitvoer nie; slegs _**AppleMobileFileIntegrity**_ sal **uitvoerbare kode-handtekeninge verifieer** wanneer jy ’n app uitvoer wat reeds deur Gatekeeper uitgevoer en geverifieer is.

Voorheen was dit dus moontlik om ’n app uit te voer om dit met Gatekeeper te cache, en dan **nie-uitvoerbare lêers van die application te wysig** (soos Electron asar- of NIB-lêers). Indien geen ander protections in plek was nie, is die application met die **kwaadwillige** toevoegings **uitgevoer**.

Dit is egter nou nie meer moontlik nie, omdat macOS **wysiging van lêers** binne application bundles voorkom. As jy dus die [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md)-attack probeer, sal jy vind dat dit nie meer misbruik kan word nie, omdat jy, nadat jy die app uitgevoer het om dit met Gatekeeper te cache, nie die bundle sal kan wysig nie. As jy byvoorbeeld die naam van die Contents-gids na NotCon verander (soos in die exploit aangedui), en dan die hoofbinary van die app uitvoer om dit met Gatekeeper te cache, sal dit ’n fout veroorsaak en nie uitvoer nie.

## Gatekeeper Bypasses

Enige manier om Gatekeeper te bypass (om daarin te slaag om die user iets te laat download en uitvoer wanneer Gatekeeper dit behoort te blokkeer) word as ’n kwesbaarheid in macOS beskou. Hier is sommige CVEs wat toegeken is aan tegnieke wat in die verlede toegelaat het dat Gatekeeper gebypass word:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Daar is waargeneem dat, indien die **Archive Utility** vir extraction gebruik word, lêers met **paths wat 886 karakters oorskry** nie die com.apple.quarantine extended attribute ontvang nie. Hierdie situasie laat daardie lêers onopsetlik toe om **Gatekeeper se** security checks te **omseil**.<sup>[[5]](#references)</sup>

Raadpleeg die [**original report**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) vir meer inligting.<sup>[[5]](#references)</sup>

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Wanneer ’n application met **Automator** geskep word, is die inligting oor wat dit moet uitvoer binne `application.app/Contents/document.wflow`, en nie in die executable nie. Die executable is slegs ’n generiese Automator-binary genaamd **Automator Application Stub**.

Jy kon dus `application.app/Contents/MacOS/Automator\ Application\ Stub` **met ’n symbolic link na ’n ander Automator Application Stub binne die system laat wys**, en dit sal uitvoer wat binne `document.wflow` is (jou script) **sonder om Gatekeeper te trigger**, omdat die werklike executable nie die quarantine xattr het nie.<sup>[[6]](#references)</sup>

Voorbeeld van die verwagte ligging: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Raadpleeg die [**original report**](https://ronmasas.com/posts/bypass-macos-gatekeeper) vir meer inligting.<sup>[[6]](#references)</sup>

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

In hierdie bypass is ’n zip-lêer geskep met ’n application wat begin compress het vanaf `application.app/Contents` in plaas van `application.app`. Daarom is die **quarantine attr** op al die **lêers vanaf `application.app/Contents`** toegepas, maar **nie op `application.app` nie**—dit is wat Gatekeeper nagegaan het. Gatekeeper is dus gebypass, omdat `application.app`, toe dit getrigger is, **nie die quarantine attribute gehad het nie.**<sup>[[7]](#references)</sup>
```bash
zip -r test.app/Contents test.zip
```
Raadpleeg die [**oorspronklike verslag**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) vir meer inligting.<sup>[[7]](#references)</sup>

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Selfs al verskil die komponente, is die exploitation van hierdie kwesbaarheid baie soortgelyk aan die vorige een. In hierdie geval sal ons ’n Apple Archive vanaf **`application.app/Contents`** genereer, sodat **`application.app`** nie die quarantine attr sal kry wanneer dit deur **Archive Utility** gedekomprimeer word nie.<sup>[[8]](#references)</sup>
```bash
aa archive -d test.app/Contents -o test.app.aar
```
Sien die [**oorspronklike verslag**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) vir meer inligting.<sup>[[8]](#references)</sup>

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

Die ACL **`writeextattr`** kan gebruik word om te voorkom dat enigiemand ’n kenmerk in ’n lêer skryf:
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
Verder kopieer die **AppleDouble**-lêerformaat ’n lêer, insluitend sy ACEs.<sup>[[9]](#references)</sup>

In die [**source code**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) is dit moontlik om te sien dat die ACL-teksvoorstelling wat binne die xattr genaamd **`com.apple.acl.text`** gestoor word, as ACL in die gedekomprimeerde lêer gestel gaan word. Dus, as jy ’n toepassing in ’n zip-lêer met die **AppleDouble**-lêerformaat saamgepers het met ’n ACL wat verhoed dat ander xattrs daarin geskryf word... is die quarantine xattr nie in die toepassing gestel nie:
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

Daar is ontdek dat **Google Chrome nie die quarantine-attribuut op afgelaaide lêers gestel het nie** weens sommige interne macOS-probleme.<sup>[[10]](#references)</sup>

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDouble stoor 'n lêer se eienskappe in 'n aparte lêer waarvan die naam met `._` begin; dit help om lêereienskappe **tussen macOS-masjiene** te kopieer. Nadat 'n AppleDouble-lêer gedekomprimeer is, **is die lêer wat met `._` begin nie die quarantine-attribuut gegee nie**.<sup>[[11]](#references)</sup>
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you download and decompress the resulting test.aar, test/._a won't have a quarantine attribute
```
Deur 'n lêer te kan skep waarop die **quarantine attribute** nie gestel sal word nie, was dit **moontlik om Gatekeeper te omseil.** Die truuk was om 'n **DMG file application** te skep met behulp van die AppleDouble-naamskonvensie (begin dit met `._`) en 'n **sigbare lêer as 'n simboliese skakel na hierdie versteekte** lêer sonder die quarantine attribute te skep.\
Wanneer die **dmg-lêer uitgevoer word**, sal dit, omdat dit nie 'n quarantine attribute het nie, **Gatekeeper omseil**.
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

Apple het ’n LaunchServices-logikafout in macOS Sonoma 14.0 deur verbeterde kontroles reggestel. Die openbare advies vermeld slegs dat ’n app Gatekeeper kon omseil; moet dus nie ’n spesifieke draerformaat of exploitation chain uit die CVE-inskrywing alleen aflei nie.<sup>[[13]](#references)</sup>

### [CVE-2024-27853]

’n Gatekeeper-omseiling in macOS 14.4 (vrygestel in Maart 2024), wat voortgespruit het uit `libarchive` se hantering van kwaadwillige ZIP-lêers, het toegelaat dat apps assessment ontduik. Dateer op na 14.4 of later, waar Apple die probleem aangespreek het.<sup>[[1]](#references)</sup>

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

’n **Automator Quick Action workflow** wat in ’n afgelaaide app ingebed is, kon sonder Gatekeeper-assessment geaktiveer word, omdat workflows as data behandel en deur die Automator-helper buite die normale notarization-prompt-pad uitgevoer is. ’n Aangepaste `.app` wat ’n Quick Action bundel wat ’n shell script uitvoer (byvoorbeeld binne `Contents/PlugIns/*.workflow/Contents/document.wflow`) kon dus onmiddellik tydens launch uitgevoer word. Apple het ’n bykomende toestemmingsdialoog bygevoeg en die assessment-pad in Ventura **13.7**, Sonoma **14.7** en Sequoia **15** reggestel.<sup>[[3]](#references)</sup>

### Quarantine-propageringsfoute by ekstraksie- en kopieergrense

’n Studie uit 2024 het propageringsgapings gevind in die getoetste weergawes van iZip (ZIP/TAR/7Z), Archiver (ARCHIVER/ZIP/TAR/7Z), BetterZip (ZIP/TAR/7Z), WinRAR (ZIP/TAR/7Z) en 7z Utility (DMG/ZIP/7Z); dit het ook waargeneem dat die attribuut verlore gaan tydens VMware Tools-gasheer-na-gas-kopieë. Verskeie vendors het daarna fixes aangekondig; behandel hierdie name dus as leidrade vir **weergawe-spesifieke hertoetsing**, nie as ’n permanente lys van kwesbare sagteware nie. Dieselfde trust-boundary-probleem geld vir native Unix-workflows: `curl`/`scp` voeg nie quarantine by nie, en command-line `tar`/`unzip` erf dit nie outomaties van ’n draerargief nie.<sup>[[15]](#references)</sup>

Vir offensive testing, vergelyk die draer en die finale app ná **elke** browser-, mail client-, archive-, disk-image-, cloud-sync-, shared-folder- en VM-copy-oorgang. ’n Eksplisiete `spctl`-verwerping herstel nie ’n ontbrekende xattr nie: sonder quarantine sal die normale Gatekeeper-pad by die eerste opening moontlik nooit daardie assessment aanvra nie.<sup>[[15]](#references)</sup>
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
### uchg (from this [talk](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

- Skep ’n gids wat ’n app bevat.
- Voeg uchg by die app.
- Komprimeer die app na ’n tar.gz-lêer.
- Stuur die tar.gz-lêer aan ’n slagoffer.
- Die slagoffer maak die tar.gz-lêer oop en voer die app uit.
- Gatekeeper kontroleer nie die app nie.<sup>[[12]](#references)</sup>

### Prevent Quarantine xattr

In ’n ".app"-bundle, as die quarantine xattr nie daarby gevoeg word nie, sal **Gatekeeper nie geaktiveer word nie** wanneer dit uitgevoer word.

Sien [macOS FS Tricks](macos-fs-tricks/README.md#avoid-quarantine-xattrs-tricks) vir filesystem-, flag-, ACL- en AppleDouble-gebaseerde primitives wat extended attributes kan voorkom of weggooi.



## References

- [1] [Apple Platform Security: Oor die sekuriteitsinhoud van macOS Sonoma 14.4 (sluit CVE-2024-27853 in)](https://support.apple.com/en-us/HT214084)
- [2] [Eclectic Light: Hoe macOS nou die herkoms van apps naspoor](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- [3] [Apple: Oor die sekuriteitsinhoud van macOS Sonoma 14.7 / Ventura 13.7 (CVE-2024-44128)](https://support.apple.com/en-us/121234)
- [4] [MacRumors: macOS 15 Sequoia verwyder die Control‑click “Open” Gatekeeper bypass](https://www.macrumors.com/2024/08/06/macos-sequoia-gatekeeper-security-change/)
- [5] [WithSecure Labs: Die ontdekking van CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)
- [6] [CVE-2021-30990, Bypassing The macOS Gatekeeper](https://ronmasas.com/posts/bypass-macos-gatekeeper)
- [7] [Jamf Threat Labs identifies Safari vulnerability allowing for Gatekeeper bypass](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)
- [8] [Jamf Threat Labs identifies macOS Archive Utility vulnerability allowing for Gatekeeper bypass (CVE-2022-32910)](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)
- [9] [Gatekeeper's Achilles heel: Unearthing a macOS vulnerability](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [10] [F-Secure: Discovery of a Gatekeeper Bypass (CVE-2023-27943)](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)
- [11] [Finding and reporting a Gatekeeper bypass exploit with help from Mac Monitor](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)
- [12] [CODE BLUE 2023: Bypassing macOS Security and Privacy Mechanisms — From Gatekeeper to System Integrity Protection (Koh Nakagawa)](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf)
- [13] [Apple: About the security content of macOS Sonoma 14 (CVE-2023-41067)](https://support.apple.com/en-us/HT213940)
- [14] [Apple Developer Forums: Testing a notarised product](https://developer.apple.com/forums/thread/130560)
- [15] [Unit 42: Gatekeeper Bypass — Uncovering Weaknesses in a macOS Security Mechanism](https://unit42.paloaltonetworks.com/gatekeeper-bypass-macos/)
{{#include ../../../banners/hacktricks-training.md}}
