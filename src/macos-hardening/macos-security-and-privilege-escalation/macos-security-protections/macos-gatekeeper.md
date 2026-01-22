# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

**Gatekeeper** is 'n sekuriteitsfunksie vir Mac-bedryfstelsels, bedoel om te verseker dat gebruikers **slegs vertroude sagteware** op hul stelsels uitvoer. Dit funksioneer deur sagteware te **valideer** wat 'n gebruiker aflaai en probeer oopmaak vanaf **bronne buite die App Store**, soos 'n app, 'n plug-in, of 'n installeringspakket.

Die kernmeganisme van Gatekeeper lê in sy **verifiërings**proses. Dit kontroleer of die afgelaaide sagteware **deur 'n erkende ontwikkelaar onderteken is**, wat die sagteware se egtheid verseker. Verder bepaal dit of die sagteware **deur Apple genotariseer is**, wat bevestig dat dit vry is van bekende kwaadwillige inhoud en nie ná die notarisering gemanipuleer is nie.

Bykomend versterk Gatekeeper gebruikersbeheer en sekuriteit deur gebruikers te **vra om die opening te goedkeur** van afgelaaide sagteware die eerste keer. Hierdie beskerming help verhoed dat gebruikers per ongeluk moontlik skadelike uitvoerbare kode uitvoer wat hulle dalk vir 'n onskuldige databestand aangesien het.

### Aansoekhandtekeninge

Aansoekhandtekeninge, ook bekend as code signatures, is 'n kritieke komponent van Apple se sekuriteitsinfrastruktuur. Hulle word gebruik om die **identiteit van die sagteware-outeur** (die ontwikkelaar) te verifieer en om te verseker dat die kode nie sedert dit laas onderteken is gemanipuleer is nie.

Hier is hoe dit werk:

1. **Signing the Application:** Wanneer 'n ontwikkelaar gereed is om hul aansoek te versprei, **onderteken hulle die aansoek met 'n privaat sleutel**. Hierdie privaat sleutel is geassosieer met 'n **sertifikaat wat Apple aan die ontwikkelaar uitreik** wanneer hulle by die Apple Developer Program inskryf. Die ondertekeningsproses behels die skep van 'n kriptografiese hash van alle dele van die app en die enkripsie van hierdie hash met die ontwikkelaar se privaat sleutel.
2. **Distributing the Application:** Die ondertekende aansoek word dan aan gebruikers versprei tesame met die ontwikkelaar se sertifikaat, wat die ooreenstemmende openbare sleutel bevat.
3. **Verifying the Application:** Wanneer 'n gebruiker die aansoek aflaai en probeer laat loop, gebruik hul Mac-bedryfstelsel die openbare sleutel uit die ontwikkelaar se sertifikaat om die hash te ontsleutel. Dit herbereken dan die hash gebaseer op die huidige toestand van die aansoek en vergelyk dit met die ontsleutelde hash. As hulle ooreenstem, beteken dit dat **die aansoek nie sedert die ondertekening gewysig is nie**, en die stelsel laat die aansoek toe om te loop.

Aansoekhandtekeninge is 'n noodsaaklike deel van Apple se Gatekeeper-tegnologie. Wanneer 'n gebruiker probeer om 'n **aansoek wat van die internet afgelaai is te open**, verifieer Gatekeeper die aansoekhandtekening. As dit onderteken is met 'n sertifikaat wat deur Apple aan 'n bekende ontwikkelaar uitgereik is en die kode nie gemanipuleer is nie, laat Gatekeeper die aansoek toe om te loop. Andersins blokkeer dit die aansoek en waarsku die gebruiker.

Vanaf macOS Catalina, **kontroleer Gatekeeper ook of die aansoek deur Apple genotariseer is**, wat 'n ekstra sekuriteitslaag toevoeg. Die notariseringproses ondersoek die aansoek vir bekende sekuriteitsprobleme en kwaadwillige kode, en as hierdie kontroles slaag, voeg Apple 'n ticket by die aansoek wat Gatekeeper kan verifieer.

#### Kontroleer handtekeninge

Wanneer jy 'n **malware sample** ondersoek, moet jy altyd die **handtekening** van die binêre **kontroleer**, aangesien die **ontwikkelaar** wat dit onderteken het dalk reeds **verwant** aan **malware** is.
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

Apple se notariseringproses dien as 'n addisionele beskerming om gebruikers teen moontlik skadelike sagteware te beskerm. Dit behels die **ontwikkelaar wat hul toepassing vir ondersoek indien** by **Apple's Notary Service**, wat nie met App Review verwar moet word nie. Hierdie diens is 'n **outomatiese stelsel** wat die ingediende sagteware ondersoek vir die teenwoordigheid van **skadelike inhoud** en enige potensiële probleme met code-signering.

As die sagteware hierdie inspeksie **slaag** sonder om enige bewyse van kommer te lewer, genereer die Notary Service 'n notariseringsticket. Die ontwikkelaar word dan vereis om **hierdie ticket aan hul sagteware te heg**, 'n proses wat bekend staan as 'stapling.' Verder word die notariseringsticket ook aanlyn gepubliseer waar Gatekeeper, Apple's sekuriteitstegniek, toegang daartoe het.

By die gebruiker se eerste installasie of uitvoering van die sagteware, maak die bestaan van die notariseringsticket — hetsy aan die uitvoerbare lêer gestapeld of aanlyn gevind — **informeer Gatekeeper dat die sagteware deur Apple genotariseer is**. As gevolg daarvan vertoon Gatekeeper 'n beskrywende boodskap in die aanvanklike lanceringsdialoog, wat aandui dat die sagteware deur Apple nagegaan is vir skadelike inhoud. Hierdie proses verhoog dus gebruikersvertroue in die veiligheid van die sagteware wat hulle op hul stelsels installeer of uitvoer.

### spctl & syspolicyd

> [!CAUTION]
> Neem kennis dat vanaf die Sequoia-weergawe, **`spctl`** nie meer toelaat om die Gatekeeper-konfigurasie te verander nie.

**`spctl`** is die CLI-gereedskap om Gatekeeper te ondersoek en daarmee te kommunikeer (met die `syspolicyd` daemon via XPC-boodskappe). Byvoorbeeld, dit is moontlik om die **status** van GateKeeper te sien met:
```bash
# Check the status
spctl --status
```
> [!CAUTION]
> Neem kennis dat GateKeeper-handtekeningkontroles slegs uitgevoer word op **lêers met die Quarantine-attribuut**, nie op elke lêer nie.

GateKeeper sal nagaan of, volgens die **voorkeure & die handtekening**, 'n binary uitgevoer kan word:

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`** is die hoofdaemon wat verantwoordelik is vir die afdwinging van GateKeeper. Dit onderhou 'n databasis geleë in `/var/db/SystemPolicy` en dit is moontlik om die kode wat die [database here](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp) ondersteun te vind en die [SQL template here](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql). Neem kennis dat die databasis nie deur SIP beperk word en skryfbaar deur root is, en die databasis `/var/db/.SystemPolicy-default` word as 'n oorspronklike rugsteun gebruik ingeval die ander korrup raak.

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
**`syspolicyd`** maak ook 'n XPC-bediener beskikbaar met verskeie operasies soos `assess`, `update`, `record` en `cancel`, wat ook bereik kan word met behulp van **`Security.framework`'s `SecAssessment*`** APIs en **`spctl`** praat eintlik met **`syspolicyd`** via XPC.

Let op hoe die eerste reël geëindig het in "**App Store**" en die tweede in "**Developer ID**" en dat in die vorige afbeelding dit **ingeskakel was om apps vanaf die App Store en van geïdentifiseerde ontwikkelaars uit te voer**.\
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
Dit is hashes afkomstig van:

- `/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`
- `/var/db/gke.bundle/Contents/Resources/gk.db`
- `/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`

Of jy kan die vorige inligting lys met:
```bash
sudo spctl --list
```
Die opsies **`--master-disable`** en **`--global-disable`** van **`spctl`** sal hierdie handtekeningkontroles heeltemal **uitskakel:**
```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```
Wanneer dit heeltemal aangeskakel is, sal 'n nuwe opsie verskyn:

<figure><img src="../../../images/image (1151).png" alt=""><figcaption></figcaption></figure>

Dit is moontlik om te **kontroleer of 'n App deur GateKeeper toegelaat sal word** met:
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
Met betrekking tot **kernel extensions**, bevat die gids `/var/db/SystemPolicyConfiguration` lêers met lyste van kexts wat gelaai mag word. Verder het `spctl` die entitlement `com.apple.private.iokit.nvram-csr` omdat dit in staat is om nuwe vooraf-goedgekeurde kernel extensions by te voeg wat ook in NVRAM gestoor moet word onder die sleutel `kext-allowed-teams`.

#### Bestuur van Gatekeeper op macOS 15 (Sequoia) en later

- Die langlopende Finder **Ctrl+Open / Right‑click → Open** omseiling is verwyder; gebruikers moet na die eerste blok-dialoog uitdruklik 'n geblokkeerde app toelaat via **System Settings → Privacy & Security → Open Anyway**.
- `spctl --master-disable/--global-disable` word nie meer aanvaar nie; `spctl` is effektief net-lees vir assessering en etiketbestuur, terwyl beleidsafdwinging via die UI of MDM gekonfigureer word.

Vanaf macOS 15 Sequoia kan eindgebruikers nie meer Gatekeeper‑beleid met `spctl` omskakel nie. Bestuur gebeur via System Settings of deur 'n MDM-konfigurasieprofiel te ontplooi met die `com.apple.systempolicy.control` payload. Voorbeeld van 'n profielfragment om App Store en geïdentifiseerde ontwikkelaars toe te laat (maar nie "Anywhere" nie):

<details>
<summary>MDM‑profiel om App Store en geïdentifiseerde ontwikkelaars toe te laat</summary>
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

By **aflaai** van 'n toepassing of lêer heg sekere macOS **toepassings**, soos webblaaiers of e-poskliënte, 'n uitgebreide lêerattribuut aan die afgelaaide lêer vas — algemeen bekend as die "**kwarantyn-vlag**". Hierdie attribuut dien as 'n sekuriteitsmaatreël om **die lêer te merk** as afkomstig van 'n onbetroubare bron (die internet) en moontlike risiko's in te hou. Nie alle toepassings stel hierdie attribuut egter nie; byvoorbeeld, algemene BitTorrent-kliënte omseil gewoonlik hierdie proses.

**Die teenwoordigheid van 'n kwarantyn-vlag waarsku macOS se Gatekeeper-sekuriteitsfunksie wanneer 'n gebruiker die lêer probeer uitvoer.**

In die geval waar die **kwarantyn-vlag nie teenwoordig is nie** (soos by lêers afgelaai via sommige BitTorrent-kliënte), mag Gatekeeper se **kontroles nie uitgevoer word nie**. Gebruikers moet dus omsigtigheid toepas wanneer hulle lêers van minder veilige of onbekende bronne open.

> [!NOTE] > **Die kontrole** van die **geldigheid** van code-handtekeninge is 'n **hulpbron-intensiewe** proses wat die generering van kriptografiese **hashes** van die kode en al sy ingeslote hulpbronne insluit. Verder behels die verifiëring van sertifikaatgeldigheid 'n **aanlynkontrole** by Apple's servers om te sien of dit na uitreiking herroep is. Om hierdie redes is 'n volledige code-handtekening- en notariseringskontrole **onpraktries om elke keer as 'n app begin word, uit te voer**.
>
> Daarom word hierdie kontroles **slegs uitgevoer wanneer programme met die gekwarantyneerde attribuut uitgevoer word.**

> [!WARNING]
> Hierdie attribuut moet deur die toepassing wat die lêer skep/aflaai **gestel word**.
>
> Lêers wat gesandbox is, sal hierdie attribuut egter op elke lêer wat hulle skep toegepas hê. En nie-sandboxed apps kan dit self stel, of die [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) sleutel in die **Info.plist** spesifiseer, wat die stelsel sal veroorsaak om die `com.apple.quarantine` uitgebreide attribuut op die geskepte lêers te plaas.

Boonop word alle lêers wat deur 'n proses geskep is wat **`qtn_proc_apply_to_self`** aanroep, in kwarantyn geplaas. Of die API **`qtn_file_apply_to_path`** voeg die kwarantyn-attribuut by 'n gespesifiseerde lêerpad.

Dit is moontlik om **sy status te kontroleer en te aktiveer/deaktiveer** (root vereis) met:
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
Jy kan ook **vind of 'n lêer die quarantine extended attribute het** met:
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
Kontroleer die **waarde** van die **uitgebreide** **eienskappe** en vind uit watter app die quarantine attr geskryf het met:
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
In werklikheid kan 'n proses "could set quarantine flags to the files it creates" (ek het reeds probeer om die USER_APPROVED flag op 'n geskepte lêer toe te pas, maar dit wil nie toegepas word nie):

<details>

<summary>Bronkode — toepas quarantine flags</summary>
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
En vind al die gekwarantineerde lêers met:
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
Karantyninligting word ook gestoor in 'n sentrale databasis wat deur LaunchServices bestuur word in **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**, wat die GUI in staat stel om data oor die lêerherkoms te kry. Verder kan dit oorskryf word deur toepassings wat moontlik belangstel om hul herkoms te verberg. Dit kan ook vanaf die LaunchServices APIS gedoen word.

#### **libquarantine.dylib**

Hierdie biblioteek exporteer verskeie funksies wat toelaat om die uitgebreide attribuutvelde te manipuleer.

Die `qtn_file_*` APIs hanteer lêerkarantynbeleid, die `qtn_proc_*` APIs word op prosesse toegepas (lêers wat deur die proses geskep is). Die nie-eksporteerde `__qtn_syscall_quarantine*` funksies is diegene wat die beleide toepas en `mac_syscall` aanroep met "Quarantine" as eerste argument wat die versoeke na `Quarantine.kext` stuur.

#### **Quarantine.kext**

Die kerneluitbreiding is slegs beskikbaar deur die **kernel cache op die stelsel**; jy kan egter die **Kernel Debug Kit vanaf** [**https://developer.apple.com/**](https://developer.apple.com/) aflaai, wat 'n gesimbooliseerde weergawe van die uitbreiding sal bevat.

Hierdie Kext koppel via MACF aan verskeie oproepe om alle lêer-lewenstydsgebeurtenisse te vang: skepping, opening, hernoeming, hard-linking... selfs `setxattr` om te verhoed dat dit die `com.apple.quarantine` uitgebreide attribuut stel.

Dit gebruik ook 'n paar MIBs:

- `security.mac.qtn.sandbox_enforce`: Handhaaf karantyn saam met Sandbox
- `security.mac.qtn.user_approved_exec`: Gekarantyneerde prosesse kan slegs goedgekeurde lêers uitvoer

#### Provenance xattr (Ventura and later)

macOS 13 Ventura het 'n afsonderlike provenance-meganisme ingestel wat gevul word die eerste keer dat 'n gekarantyneerde app toegelaat word om te loop. Twee artefakte word geskep:

- Die `com.apple.provenance` xattr op die `.app` bundle directory (vaste-grootte binêre waarde wat 'n primêre sleutel en vlae bevat).
- 'n Ry in die `provenance_tracking` tabel in die ExecPolicy-databasis by `/var/db/SystemPolicyConfiguration/ExecPolicy/` wat die app se cdhash en metadata stoor.

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

XProtect is a built-in **anti-malware** feature in macOS. XProtect **kontroleer enige toepassing wanneer dit vir die eerste keer begin of gewysig word teen sy databasis** van bekende malware en onveilige lêertipes. Wanneer jy 'n lêer aflaai deur sekere apps, soos Safari, Mail, of Messages, skandeer XProtect die lêer outomaties. As dit ooreenstem met enige bekende malware in sy databasis, sal XProtect **voorkom dat die lêer uitgevoer word** en jou oor die bedreiging waarsku.

Die XProtect-databasis word deur Apple **gereeld opgedateer** met nuwe malware-definisies, en hierdie opdaterings word outomaties op jou Mac afgelaai en geïnstalleer. Dit verseker dat XProtect altyd op datum is met die nuutste bekende bedreigings.

Dit is egter die moeite werd om te noem dat **XProtect nie 'n volledige antivirus-oplossing is nie**. Dit kyk slegs na 'n spesifieke lys bekende bedreigings en voer nie on-access scanning uit soos die meeste antivirus-sagteware nie.

Jy kan inligting oor die nuutste XProtect-opdatering kry deur die volgende te laat loop:
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
XProtect is located on. SIP protected location at **/Library/Apple/System/Library/CoreServices/XProtect.bundle** and inside the bundle you can find information XProtect uses:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Laat kode met daardie cdhashes toe om legacy entitlements te gebruik.
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: Lys van plugins en uitbreidings wat nie toegelaat word om te laai nie via BundleID en TeamID of wat `n minimumweergawe aandui.
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Yara reëls om malware te ontdek.
- **`XProtect.bundle/Contents/Resources/gk.db`**: SQLite3-databasis met hashes van geblokkeerde toepassings en TeamIDs.

Note that there is another App in **`/Library/Apple/System/Library/CoreServices/XProtect.app`** related to XProtect that isn't involved with the Gatekeeper process.

> XProtect Remediator: On modern macOS, Apple ships on-demand scanners (XProtect Remediator) that run periodically via launchd to detect and remediate families of malware. You can observe these scans in unified logs:
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### Nie Gatekeeper nie

> [!CAUTION]
> Let wel dat Gatekeeper **nie elke keer uitgevoer word nie** wanneer jy 'n toepassing uitvoer; slegs _**AppleMobileFileIntegrity**_ (AMFI) sal slegs **uitvoerbare kodehandtekeninge verifieer** wanneer jy 'n app uitvoer wat reeds deur Gatekeeper uitgevoer en geverifieer is.

Daarom was dit voorheen moontlik om 'n app uit te voer om dit deur Gatekeeper te cache, en dan **nie-uitvoerbare lêers van die toepassing te wysig** (soos Electron asar of NIB-lêers) en as daar geen ander beskermings in plek was nie, sou die toepassing met die **kwaadaardige** toevoegings **uitgevoer** word.

Tans is dit egter nie moontlik nie omdat macOS **voorkom dat lêers binne toepassingsbundels gewysig word**. Dus, as jy die [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md) aanval probeer, sal jy vind dat dit nie meer moontlik is om dit te misbruik nie omdat nadat die app uitgevoer is om dit met Gatekeeper te cache, jy nie die bundel kan wysig nie. En as jy byvoorbeeld die naam van die Contents-gids verander na NotCon (soos in die exploit aangedui), en dan die hoof-binary van die app uitvoer om dit met Gatekeeper te cache, sal dit 'n fout veroorsaak en nie uitgevoer word nie.

## Gatekeeper Bypasses

Enige manier om Gatekeeper te omseil (daardie dit jou gelukte om die gebruiker iets af te laai en dit uit te voer wanneer Gatekeeper dit sou verhoed) word as 'n kwesbaarheid in macOS beskou. Hier is 'n paar CVE's wat toegewys is aan tegnieke wat in die verlede toegelaat het om Gatekeeper te omseil:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Daar is waargeneem dat as die **Archive Utility** gebruik word vir uitpak, lêers met **paaie wat 886 karakters oorskry** nie die com.apple.quarantine uitgebreide attribuut ontvang nie. Hierdie situasie laat daardie lêers onbedoeld toe om **Gatekeeper se** veiligheidskontroles te **omseil**.

Check the [**original report**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) for more information.

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Wanneer 'n toepassing met **Automator** geskep word, is die inligting oor wat dit benodig om uit te voer binne `application.app/Contents/document.wflow` en nie in die uitvoerbare binêre nie. Die uitvoerbare is net 'n generiese Automator-binarie genoem **Automator Application Stub**.

Dus kon jy `application.app/Contents/MacOS/Automator\ Application\ Stub` **na 'n simboliese skakel laat wys na 'n ander Automator Application Stub binne die stelsel** en dit sal uitvoer wat binne `document.wflow` is (jou script) **sonder om Gatekeeper te aktiveer** omdat die werklike uitvoerbare nie die quarantine xattr het nie.

Example os expected location: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Check the [**original report**](https://ronmasas.com/posts/bypass-macos-gatekeeper) for more information.

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

In hierdie omseiling is 'n zip-lêer geskep waar 'n toepassing begin saamgepers is vanaf `application.app/Contents` in plaas van `application.app`. Dus is die **quarantine attr** toegepas op al die **lêers uit `application.app/Contents`** maar **nie op `application.app` nie**, wat Gatekeeper kontroleer, so Gatekeeper is omseil omdat wanneer `application.app` geaktiveer is, dit **nie die quarantine-attribuut gehad het nie.**
```bash
zip -r test.app/Contents test.zip
```
Kyk na die [**original report**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) vir meer inligting.

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Selfs al is die komponente verskillend, is die benutting van hierdie kwesbaarheid baie soortgelyk aan die vorige een. In hierdie geval sal 'n Apple Archive gegenereer word vanaf **`application.app/Contents`** sodat **`application.app` won't get the quarantine attr** wanneer dit deur **Archive Utility** uitgepak word.
```bash
aa archive -d test.app/Contents -o test.app.aar
```
Kyk na die [**original report**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) vir meer inligting.

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

Die ACL **`writeextattr`** kan gebruik word om te verhoed dat enigiemand 'n attribuut in 'n lêer skryf:
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
Verder kopieer die **AppleDouble** lêerformaat 'n lêer, insluitend sy ACEs.

In die [**source code**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) is dit moontlik om te sien dat die ACL-teksvoorstelling wat in die xattr met die naam **`com.apple.acl.text`** gestoor is, as ACL in die gedekomprimeerde lêer gestel gaan word. Dus, as jy 'n toepassing in 'n zip-lêer saamgepak het met die **AppleDouble** lêerformaat en met 'n ACL wat verhoed dat ander xattrs daarna geskryf word... is die quarantine xattr nie in die toepassing gestel nie:
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
Kyk na die [**original report**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) vir meer inligting.

Let daarop dat dit ook met AppleArchives uitgebuit kan word:
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

Dit is ontdek dat **Google Chrome die quarantine-attribuut nie by afgelaaide lêers gestel het nie** as gevolg van sekere interne macOS-probleme.

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDouble-lêerformate stoor die attributte van 'n lêer in 'n aparte lêer wat begin met `._`; dit help om lêerattribuutte **oor macOS-masjiene te kopieer**. Dit is egter opgemerk dat nadat 'n AppleDouble-lêer gedekomprimeer is, die lêer wat met `._` begin **nie die quarantine-attribuut ontvang het nie**.
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you downloaded the resulting test.aar and decompress it, the file test/._a won't have a quarantitne attribute
```
Deur 'n lêer te kan skep wat nie die kwarantynattribuut het nie, was dit **moontlik om Gatekeeper te omseil.** Die truuk was om 'n **DMG file application te skep** deur die AppleDouble naamkonvensie te gebruik (begin dit met `._`) en 'n **sigbare lêer as 'n sym link na hierdie verborge** lêer te skep sonder die kwarantynattribuut.\
Wanneer die **dmg file uitgevoer word**, aangesien dit nie 'n kwarantynattribuut het nie, sal dit **Gatekeeper omseil**.
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

'n Gatekeeper-omseiling wat in macOS Sonoma 14.0 herstel is, het toegelaat dat gemanipuleerde apps sonder 'n bevestiging uitgevoer kon word. Details is publiek bekendgemaak ná die pleister, en die probleem is aktief in die veld uitgebuit voordat dit reggestel is. Maak seker macOS Sonoma 14.0 of later is geïnstalleer.

### [CVE-2024-27853]

'n Gatekeeper-omseiling in macOS 14.4 (vrygestel Maart 2024) wat voortgekom het uit die hantering deur `libarchive` van kwaadwillige ZIPs het toegelaat dat apps assessering kon ontduik. Werk op na 14.4 of later waarin Apple die probleem aangespreek het.

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

An **Automator Quick Action workflow** ingebed in 'n afgelaaide app kon sonder Gatekeeper-assessering aktiveer, omdat workflows as data behandel is en deur die Automator-hulp buite die normale notarization-prompt-pad uitgevoer is. 'n Gemanipuleerde `.app` wat 'n Quick Action bundel wat 'n shell script uitvoer (bv. binne `Contents/PlugIns/*.workflow/Contents/document.wflow`) kon dus onmiddellik by opstart uitgevoer word. Apple het 'n ekstra toestemmingsdialoog bygevoeg en die assesseringspad reggemaak in Ventura **13.7**, Sonoma **14.7**, en Sequoia **15**.

### Third‑party unarchivers mis‑propagating quarantine (2023–2024)

Verskeie kwesbaarhede in populêre uitpakgereedskap (bv. The Unarchiver) het veroorsaak dat lêers wat uit argiewe uitgepak is die `com.apple.quarantine` xattr mis, wat Gatekeeper-omseilings moontlik gemaak het. Vertrou altyd op macOS Archive Utility of gepatchte gereedskap wanneer jy toets, en valideer xattrs na uitpak.

### uchg (from this [talk](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

- Skep 'n gids wat 'n app bevat.
- Voeg uchg by die app.
- Pak die app saam in 'n tar.gz-lêer.
- Stuur die tar.gz-lêer na 'n slagoffer.
- Die slagoffer maak die tar.gz-lêer oop en voer die app uit.
- Gatekeeper kontroleer die app nie.

### Prevent Quarantine xattr

In 'n ".app" bundel, as die quarantine xattr nie bygevoeg is nie, sal Gatekeeper nie getrigger word wanneer dit uitgevoer word nie.


## Verwysings

- Apple Platform Security: Oor die veiligheidsinhoud van macOS Sonoma 14.4 (sluit CVE-2024-27853 in) – [https://support.apple.com/en-us/HT214084](https://support.apple.com/en-us/HT214084)
- Eclectic Light: How macOS now tracks the provenance of apps – [https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- Apple: About the security content of macOS Sonoma 14.7 / Ventura 13.7 (CVE-2024-44128) – [https://support.apple.com/en-us/121234](https://support.apple.com/en-us/121234)
- MacRumors: macOS 15 Sequoia removes the Control‑click “Open” Gatekeeper bypass – [https://www.macrumors.com/2024/06/11/macos-sequoia-removes-open-anyway/](https://www.macrumors.com/2024/06/11/macos-sequoia-removes-open-anyway/)

{{#include ../../../banners/hacktricks-training.md}}
