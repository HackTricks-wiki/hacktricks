# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

**Gatekeeper** is ’n sekuriteitsfunksie wat vir Mac-bedryfstelsels ontwikkel is en ontwerp is om te verseker dat gebruikers **slegs vertroude sagteware** op hul stelsels **laat loop**. Dit werk deur sagteware te **valideer** wat ’n gebruiker aflaai en probeer oopmaak vanaf **bronne buite die App Store**, soos ’n toepassing, ’n plug-in of ’n installasiepakket.

Die kernmeganisme van Gatekeeper lê in die **verifikasieproses**. Dit kontroleer of die afgelaaide sagteware **deur ’n erkende ontwikkelaar onderteken is**, wat die egtheid van die sagteware verseker. Verder bepaal dit of die sagteware **deur Apple genotariseer is**, wat bevestig dat dit geen bekende kwaadwillige inhoud bevat nie en nie ná notarisering gepeuter is nie.

Daarbenewens versterk Gatekeeper gebruikersbeheer en sekuriteit deur **gebruikers te vra om die opening goed te keur** wanneer afgelaaide sagteware die eerste keer oopgemaak word. Hierdie voorsorgmaatreël help keer dat gebruikers per ongeluk potensieel skadelike uitvoerbare kode laat loop wat hulle dalk vir ’n onskadelike datalêer aangesien het.

### Toepassingshandtekeninge

Toepassingshandtekeninge, ook bekend as kodehandtekeninge, is ’n kritieke komponent van Apple se sekuriteitsinfrastruktuur. Hulle word gebruik om **die identiteit van die sagteware-outeur** (die ontwikkelaar) **te verifieer** en te verseker dat daar nie met die kode gepeuter is sedert dit laas onderteken is nie.

So werk dit:

1. **Ondertekening van die toepassing:** Wanneer ’n ontwikkelaar gereed is om hul toepassing te versprei, **onderteken hulle die toepassing met ’n private sleutel**. Hierdie private sleutel word gekoppel aan ’n **sertifikaat wat Apple aan die ontwikkelaar uitreik** wanneer hulle by die Apple Developer Program inskryf. Die ondertekeningsproses behels dat ’n kriptografiese hash van alle dele van die toepassing geskep en hierdie hash met die ontwikkelaar se private sleutel geënkripteer word.
2. **Verspreiding van die toepassing:** Die ondertekende toepassing word dan saam met die ontwikkelaar se sertifikaat, wat die ooreenstemmende publieke sleutel bevat, aan gebruikers versprei.
3. **Verifikasie van die toepassing:** Wanneer ’n gebruiker die toepassing aflaai en probeer laat loop, gebruik hul Mac-bedryfstelsel die publieke sleutel uit die ontwikkelaar se sertifikaat om die hash te dekripteer. Dit bereken dan weer die hash op grond van die huidige toestand van die toepassing en vergelyk dit met die gedekripteerde hash. As hulle ooreenstem, beteken dit dat **daar nie aan die toepassing verander is nie** sedert die ontwikkelaar dit onderteken het, en die stelsel laat die toepassing loop.

Toepassingshandtekeninge is ’n noodsaaklike deel van Apple se Gatekeeper-tegnologie. Wanneer ’n gebruiker probeer om **’n toepassing wat van die internet afgelaai is oop te maak**, verifieer Gatekeeper die toepassingshandtekening. As dit onderteken is met ’n sertifikaat wat Apple aan ’n bekende ontwikkelaar uitgereik het en daar nie met die kode gepeuter is nie, laat Gatekeeper die toepassing loop. Anders blokkeer dit die toepassing en waarsku die gebruiker.

Vanaf macOS Catalina kontroleer **Gatekeeper ook of die toepassing deur Apple genotariseer is**, wat ’n ekstra sekuriteitslaag byvoeg. Die notariseringproses kontroleer die toepassing vir bekende sekuriteitsprobleme en kwaadwillige kode. As hierdie kontroles slaag, voeg Apple ’n kaartjie by die toepassing wat Gatekeeper kan verifieer.

#### Kontroleer handtekeninge

Wanneer jy ’n **malware-monster** ondersoek, moet jy altyd die binêre lêer se **handtekening nagaan**, aangesien die **ontwikkelaar** wat dit onderteken het dalk reeds **met malware verbind** word.

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

Apple se notariseringsproses dien as ’n bykomende beskerming om gebruikers teen potensieel skadelike sagteware te beskerm. Dit behels dat die **ontwikkelaar sy toepassing indien vir ondersoek** deur **Apple se Notary Service**, wat nie met App Review verwar moet word nie. Hierdie diens is ’n **outomatiese stelsel** wat die ingediende sagteware ondersoek vir **kwaadwillige inhoud** en enige moontlike probleme met code-signing.

As die sagteware hierdie inspeksie **slaag** sonder dat enige probleme gevind word, genereer die Notary Service ’n notariseringskaartjie. Die ontwikkelaar moet hierdie kaartjie dan **aan hul sagteware heg**, ’n proses wat as 'stapling' bekend staan. Die notariseringskaartjie word ook aanlyn gepubliseer, waar Gatekeeper, Apple se sekuriteitstegnologie, toegang daartoe kan kry.

Wanneer die gebruiker die sagteware vir die eerste keer installeer of uitvoer, **lig die bestaan van die notariseringskaartjie Gatekeeper in dat Apple die sagteware genotariseer het** — of die kaartjie nou aan die uitvoerbare lêer geheg is of aanlyn gevind word. Gevolglik vertoon Gatekeeper ’n beskrywende boodskap in die aanvanklike bekendstellingsdialoog wat aandui dat Apple die sagteware vir kwaadwillige inhoud nagegaan het. Hierdie proses versterk gebruikers se vertroue in die sekuriteit van die sagteware wat hulle op hul stelsels installeer of uitvoer.

### spctl & syspolicyd

> [!CAUTION]
> Let daarop dat **`spctl`** vanaf Sequoia nie meer toelaat dat Gatekeeper se konfigurasie gewysig word nie.

**`spctl`** is die CLI-nutsding om Gatekeeper op te som en daarmee te kommunikeer (met die `syspolicyd`-daemon via XPC-boodskappe). Dit is byvoorbeeld moontlik om die **status** van GateKeeper te sien met:

```bash
# Check the status
spctl --status
```

> [!CAUTION]
> Let daarop dat GateKeeper-handtekeningkontroles slegs op **lêers met die Quarantine-kenmerk** uitgevoer word, nie op elke lêer nie.

GateKeeper sal nagaan of ’n binêre lêer volgens die **voorkeure en die handtekening** uitgevoer kan word:

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`** is die hoofdemon wat verantwoordelik is vir die afdwinging van Gatekeeper. Dit hou ’n databasis by wat in `/var/db/SystemPolicy` geleë is. Die kode vir ondersteuning van die [databasis is hier](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp) beskikbaar en die [SQL-sjabloon is hier](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql). Let daarop dat SIP nie die databasis beperk nie en dat root daarin kan skryf. Die databasis `/var/db/.SystemPolicy-default` word as ’n oorspronklike rugsteun gebruik indien die ander een beskadig raak.

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

**`syspolicyd`** stel ook ’n XPC-bediener met verskillende bewerkings soos `assess`, `update`, `record` en `cancel` beskikbaar. Hierdie bewerkings is ook bereikbaar met **`Security.framework` se `SecAssessment*`**-API’s, en **`spctl`** kommunikeer inderdaad via XPC met **`syspolicyd`**.

Let op dat die eerste reël met "**App Store**" geëindig het en die tweede met "**Developer ID**", en dat dit in die vorige prent **moontlik was om programme van die App Store en geïdentifiseerde ontwikkelaars uit te voer**.\
As jy daardie instelling na App Store **verander**, sal die "**Notarized Developer ID"-reëls verdwyn**.

Daar is ook duisende reëls van **tipe GKE** :

```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```

Dit is die hashes van:

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

Dit is moontlik om met die volgende te **kontroleer of GateKeeper ’n App sal toelaat**:

```bash
spctl --assess -v /Applications/App.app
```

Op macOS 14 en later is **`syspolicy_check`** ’n nuttige hoërvlaktoets vóór verspreiding vir ’n toepassingbundel. Dit lewer meer bruikbare diagnostiek oor vertroude uitvoering as ’n blote `spctl`-resultaat, hoewel Apple steeds aanbeveel om die werklike aflaai-, onttrekkings- en eerste-bekendstellingspad te toets, aangesien dit ook die voortplanting van kwarantyn toets.<sup>[[14]](#references)</sup>

```bash
# Check the complete app bundle before distribution
syspolicy_check distribution /path/to/App.app

# Keep the lower-level assessment when comparing policy outcomes
spctl --assess --type execute -vv /path/to/App.app
```

Dit is moontlik om nuwe reëls in GateKeeper by te voeg om die uitvoering van sekere programme toe te laat met:

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

Wat **kernuitbreidings** betref, bevat die vouer `/var/db/SystemPolicyConfiguration` lêers met lyste van kexts wat toegelaat word om gelaai te word. Boonop het `spctl` die entitlement `com.apple.private.iokit.nvram-csr`, omdat dit nuwe vooraf goedgekeurde kernuitbreidings kan byvoeg wat ook in NVRAM onder ’n `kext-allowed-teams`-sleutel gestoor moet word.

#### Gatekeeper-bestuur op macOS 15 (Sequoia) en later

- Die jarelange Finder-omseiling **Ctrl+Open / Regskliek → Open** is verwyder; gebruikers moet ’n geblokkeerde app uitdruklik toelaat via **Stelselinstellings → Privaatheid en sekuriteit → Open in elk geval** nadat die eerste blokkeringsdialoog verskyn het.<sup>[[4]](#references)</sup>
- `spctl --master-disable/--global-disable` word nie meer as beleidsveranderinge sonder toesig aanvaar nie. Bewerkings wat die reëldatabasis of globale assesseringstoestand wysig, is afgekeur; gebruik dus `spctl` vir assessering en stel afdwinging via die UI of MDM in.

Vanaf macOS 15 Sequoia kan eindgebruikers nie meer Gatekeeper-beleid met `spctl` omskakel nie. Bestuur geskied via Stelselinstellings of deur ’n MDM-konfigurasieprofiel met die `com.apple.systempolicy.control`-payload te ontplooi. Voorbeeld van ’n profielbrokkie om App Store en geïdentifiseerde ontwikkelaars toe te laat (maar nie "Enige plek" nie):

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

Wanneer 'n toepassing of lêer **afgelaai** word, **heg** spesifieke macOS-**toepassings**, soos webblaaiers of e-poskliënte, 'n uitgebreide lêerkenmerk aan die afgelaaide lêer, wat algemeen as die "**quarantine flag**" bekend staan. Hierdie kenmerk dien as 'n sekuriteitsmaatreël om **die lêer te merk** as afkomstig van 'n onbetroubare bron (die internet) en as iets wat moontlik risiko's inhou. Nie alle toepassings heg egter hierdie kenmerk aan nie; algemene BitTorrent-kliëntsagteware omseil hierdie proses gewoonlik.

**Die teenwoordigheid van 'n quarantine flag stel macOS se Gatekeeper-sekuriteitsfunksie in kennis wanneer 'n gebruiker probeer om die lêer uit te voer**.

As die **quarantine flag nie teenwoordig is nie** (soos met lêers wat via sommige BitTorrent-kliënte afgelaai is), **word Gatekeeper se kontroles moontlik nie uitgevoer nie**. Gebruikers moet dus versigtig wees wanneer hulle lêers oopmaak wat van minder veilige of onbekende bronne afgelaai is.

> [!NOTE] > **Om** die **geldigheid** van kodehandtekeninge **te kontroleer**, is 'n **hulpbronintensiewe** proses wat die generering van kriptografiese **hashes** van die kode en al die hulpbronne wat daarmee saamgebundel is, insluit. Om die geldigheid van sertifikate te kontroleer, behels boonop 'n **aanlynkontrole** by Apple se bedieners om te bepaal of die sertifikaat herroep is sedert dit uitgereik is. Om hierdie redes is dit **onprakties om elke keer wanneer 'n toepassing gelanseer word 'n volledige kodehandtekening- en notariseringskontrole uit te voer**.
>
> Daarom word hierdie kontroles **slegs uitgevoer wanneer toepassings met die quarantined-kenmerk uitgevoer word**.

> [!WARNING]
> Hierdie kenmerk moet **gestel word deur die toepassing wat die lêer skep/aflaai**.
>
> Lêers wat in 'n sandbox is, sal egter hierdie kenmerk hê op elke lêer wat hulle skep. Nie-sandbox-toepassings kan dit self stel, of die sleutel [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) in **Info.plist** spesifiseer, wat die stelsel die uitgebreide kenmerk `com.apple.quarantine` op die lêers wat geskep word, sal laat stel.

Boonop word alle lêers wat geskep word deur 'n proses wat **`qtn_proc_apply_to_self`** aanroep, in kwarantyn geplaas. Die API **`qtn_file_apply_to_path`** voeg die quarantine-kenmerk by 'n gespesifiseerde lêerpad.

Dit is moontlik om die **status daarvan na te gaan en dit te aktiveer/deaktiveer** (root word vereis) met:

```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```

Jy kan ook **vasstel of 'n lêer die quarantine-uitgebreide attribuut het** met:

```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```

Gaan die **waarde** van die **uitgebreide** **eienskappe** na en vind uit watter app die quarantine-kenmerk geskryf het met:

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

'n Proses "kan kwarantynvlae stel vir die lêers wat dit skep" (Ek het reeds probeer om die USER_APPROVED-vlag op 'n geskepte lêer toe te pas, maar dit wil dit nie toepas nie):

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

En vind al die lêers in kwarantyn met:

```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```

Quarantine-inligting word ook in ’n sentrale databasis gestoor wat deur LaunchServices bestuur word in **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**, wat die GUI in staat stel om data oor die lêers se oorsprong te verkry. Boonop kan toepassings wat dalk hul oorsprong wil verberg, dit oorskryf. Dit kan ook met LaunchServices APIS gedoen word.

#### **libquarantine.dylib**

Hierdie biblioteek voer verskeie funksies uit wat dit moontlik maak om die uitgebreide attribuutvelde te manipuleer.

Die `qtn_file_*`-APIs hanteer lêer-quarantine-beleide; die `qtn_proc_*`-APIs word op prosesse toegepas (lêers wat deur die proses geskep word). Die nie-uitgevoerde `__qtn_syscall_quarantine*`-funksies is dié wat die beleide toepas. Hulle roep `mac_syscall` met "Quarantine" as die eerste argument aan, wat die versoeke na `Quarantine.kext` stuur.

#### **Quarantine.kext**

Die kernel extension is slegs deur die **kernel cache op die stelsel** beskikbaar; jy _kan_ egter die **Kernel Debug Kit aflaai vanaf** [**https://developer.apple.com/**](https://developer.apple.com/), wat ’n weergawe van die extension met simbole sal bevat.

Hierdie Kext sal verskeie oproepe via MACF onderskep om alle lêerlewensiklusgebeure op te spoor: skepping, opening, hernoeming, hard-linking... selfs `setxattr`, om te verhoed dat dit die `com.apple.quarantine`-uitgebreide attribuut stel.

Dit gebruik ook ’n paar MIBs:

- `security.mac.qtn.sandbox_enforce`: Dwing quarantine saam met Sandbox af
- `security.mac.qtn.user_approved_exec`: Quarantine-procs kan slegs goedgekeurde lêers uitvoer

#### Provenance xattr (Ventura en later)

macOS 13 Ventura het ’n afsonderlike provenance-meganisme bekendgestel wat ingevul word wanneer ’n quarantine-toepassing die eerste keer toegelaat word om te loop.<sup>[[2]](#references)</sup> Twee artefakte word geskep:

- Die `com.apple.provenance` xattr op die `.app`-bundlegids (vaste-grootte binêre waarde wat ’n primêre sleutel en vlae bevat).
- ’n Ry in die `provenance_tracking`-tabel binne die ExecPolicy-databasis by `/var/db/SystemPolicyConfiguration/ExecPolicy/` waarin die toepassing se cdhash en metadata gestoor word.

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

XProtect is ’n ingeboude **anti-malware**-funksie in macOS. XProtect **kontroleer elke toepassing wanneer dit die eerste keer geloods of gewysig word teen sy databasis** van bekende malware en onveilige lêertipes. Wanneer jy ’n lêer deur sekere apps, soos Safari, Mail of Messages, aflaai, skandeer XProtect die lêer outomaties. As dit ooreenstem met enige bekende malware in sy databasis, sal XProtect **verhoed dat die lêer loop** en jou oor die bedreiging waarsku.

Apple **werk die XProtect-databasis gereeld by** met nuwe malware-definisies, en hierdie bywerkings word outomaties afgelaai en op jou Mac geïnstalleer. Dit verseker dat XProtect altyd op datum is met die jongste bekende bedreigings.

Dit is egter die moeite werd om daarop te let dat **XProtect nie ’n volledige antivirusoplossing is nie**. Dit kontroleer slegs vir ’n spesifieke lys bekende bedreigings en doen nie toegangstydskandering soos die meeste antivirusprogrammatuur nie.

Jy kan inligting oor die jongste XProtect-bywerking kry deur die volgende uit te voer:

```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```

XProtect is geleë op ’n SIP-beskermde plek: **/Library/Apple/System/Library/CoreServices/XProtect.bundle**. Binne die bundle kan jy inligting vind wat XProtect gebruik:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Laat kode met daardie cdhashes toe om legacy entitlements te gebruik.
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: Lys plugins en extensions wat nie toegelaat word om te laai nie, volgens BundleID en TeamID, of dui ’n minimum weergawe aan.
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Yara-reëls om malware op te spoor.
- **`XProtect.bundle/Contents/Resources/gk.db`**: SQLite3-databasis met hashes van geblokkeerde toepassings en TeamIDs.

Let daarop dat daar ’n ander App in **`/Library/Apple/System/Library/CoreServices/XProtect.app`** is wat met XProtect verband hou, maar nie by die Gatekeeper-proses betrokke is nie.

> XProtect Remediator: Op moderne macOS lewer Apple skandeerders op aanvraag (XProtect Remediator) wat periodiek via launchd loop om families van malware op te spoor en te verwyder. Jy kan hierdie skanderings in unified logs waarneem:
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### Nie Gatekeeper nie

> [!CAUTION]
> Let daarop dat Gatekeeper **nie elke keer uitgevoer word** wanneer jy ’n toepassing uitvoer nie. Slegs _**AppleMobileFileIntegrity**_ (AMFI) sal **uitvoerbare kode se handtekeninge verifieer** wanneer jy ’n toepassing uitvoer wat reeds deur Gatekeeper uitgevoer en geverifieer is.

Daarom was dit voorheen moontlik om ’n toepassing uit te voer sodat Gatekeeper dit kas, en dan **nie-uitvoerbare lêers van die toepassing te wysig** (soos Electron asar- of NIB-lêers). As daar geen ander beskermingsmaatreëls in plek was nie, is die toepassing dan met die **kwaadwillige** byvoegings **uitgevoer**.

Dit is egter nie meer moontlik nie, omdat macOS **verhoed dat lêers binne toepassingsbundels gewysig word**. As jy dus die [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md)-aanval probeer, sal jy sien dat dit nie meer misbruik kan word nie: nadat jy die toepassing uitgevoer het sodat Gatekeeper dit kas, kan jy nie die bundel wysig nie. As jy byvoorbeeld die naam van die Contents-gids na NotCon verander (soos in die exploit aangedui), en dan die toepassing se hoofbinary uitvoer sodat Gatekeeper dit kas, sal dit ’n fout veroorsaak en nie uitgevoer word nie.

## Gatekeeper-omseilings

Enige manier om Gatekeeper te omseil (dit regkry om die gebruiker iets te laat aflaai en uitvoer wanneer Gatekeeper dit behoort te verbied) word as ’n kwesbaarheid in macOS beskou. Hier is ’n paar CVE’s wat toegeken is aan tegnieke waarmee Gatekeeper in die verlede omseil kon word:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Daar is waargeneem dat lêers met **paaie langer as 886 karakters** nie die uitgebreide kenmerk com.apple.quarantine kry wanneer die **Archive Utility** vir uitpak gebruik word nie. Dit laat daardie lêers onbedoeld toe om **Gatekeeper se** sekuriteitskontroles te omseil.<sup>[[5]](#references)</sup>

Raadpleeg die [**oorspronklike verslag**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) vir meer inligting.<sup>[[5]](#references)</sup>

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Wanneer ’n toepassing met **Automator** geskep word, is die inligting oor wat dit moet uitvoer in `application.app/Contents/document.wflow`, nie in die uitvoerbare lêer nie. Die uitvoerbare lêer is bloot ’n generiese Automator-binary genaamd **Automator Application Stub**.

Daarom kon jy `application.app/Contents/MacOS/Automator\ Application\ Stub` **met ’n simboliese skakel na ’n ander Automator Application Stub binne die stelsel laat wys**. Dit sou dan uitvoer wat in `document.wflow` is (jou script) **sonder om Gatekeeper te aktiveer**, omdat die werklike uitvoerbare lêer nie die quarantine xattr het nie.<sup>[[6]](#references)</sup>

Voorbeeld van die verwagte ligging: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Raadpleeg die [**oorspronklike verslag**](https://ronmasas.com/posts/bypass-macos-gatekeeper) vir meer inligting.<sup>[[6]](#references)</sup>

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

In hierdie omseiling is ’n zip-lêer geskep deur die kompressieproses by `application.app/Contents` te begin, eerder as by `application.app`. Die **quarantine-kenmerk** is dus toegepas op al die **lêers in `application.app/Contents`**, maar **nie op `application.app` nie**. Gatekeeper het juis `application.app` nagegaan, en is dus omseil omdat `application.app` **nie die quarantine-kenmerk gehad het toe dit geaktiveer is nie.**<sup>[[7]](#references)</sup>

```bash
zip -r test.app/Contents test.zip
```

Raadpleeg die [**oorspronklike verslag**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) vir meer inligting.<sup>[[7]](#references)</sup>

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Selfs al verskil die komponente, stem die uitbuiting van hierdie kwesbaarheid baie ooreen met die vorige een. In hierdie geval sal ons ’n Apple Archive van **`application.app/Contents`** genereer, sodat **`application.app`** nie die quarantine-attribuut kry wanneer dit deur **Archive Utility** gedekomprimeer word nie.<sup>[[8]](#references)</sup>

```bash
aa archive -d test.app/Contents -o test.app.aar
```

Kyk na die [**oorspronklike verslag**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) vir meer inligting.<sup>[[8]](#references)</sup>

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

Die ACL **`writeextattr`** kan gebruik word om enigiemand te verhinder om 'n attribuut in 'n lêer te skryf:

```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```

Vir die `com.apple.acl.text`/AppleDouble-meganisme en volledige reproduksie van die sy-aan-lêer, sien [AppleDouble ACL quarantine bypass reproduction](macos-fs-tricks/macos-appledouble-acl-quarantine-bypass.md). Die Gatekeeper-toepassing se ZIP-variant gebruik die volgende volgorde:

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

Daar is ontdek dat **Google Chrome nie die quarantine-kenmerk aan afgelaaide lêers toegeken het nie** weens sekere interne macOS-probleme.<sup>[[10]](#references)</sup>

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDouble stoor ’n lêer se kenmerke in ’n aparte lêer waarvan die naam met `._` begin; dit help om lêerkenmerke **tussen macOS-masjiene** te kopieer. Nadat ’n AppleDouble-lêer egter gedekomprimeer is, **is die lêer wat met `._` begin nie die quarantine-kenmerk toegeken nie**.<sup>[[11]](#references)</sup>

```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you download and decompress the resulting test.aar, test/._a won't have a quarantine attribute
```

Omdat dit moontlik was om ’n lêer te skep waarop die quarantine-attribuut nie gestel sou word nie, was dit **moontlik om Gatekeeper te omseil.** Die truuk was om ’n **DMG-lêertoepassing** te skep met die AppleDouble-naamkonvensie (begin dit met `._`) en ’n **sigbare lêer as ’n simboliese skakel na hierdie versteekte** lêer sonder die quarantine-attribuut te skep.\
Wanneer die **DMG-lêer uitgevoer word**, sal dit, omdat dit nie ’n quarantine-attribuut het nie, **Gatekeeper omseil**.

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

Apple het ’n LaunchServices-logikafout in macOS Sonoma 14.0 reggestel deur kontroles te verbeter. Die openbare advies stel slegs dat ’n app Gatekeeper kon omseil, moet dus nie ’n spesifieke draerformaat of uitbuitingsketting slegs uit die CVE-inskrywing aflei nie.<sup>[[13]](#references)</sup>

### [CVE-2024-27853]

’n Gatekeeper-omseiling in macOS 14.4 (vrygestel in Maart 2024), wat ontstaan het uit `libarchive` se hantering van kwaadwillige ZIP-lêers, het apps toegelaat om assessering te ontduik. Dateer op na 14.4 of later, waar Apple die probleem aangespreek het.<sup>[[1]](#references)</sup>

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

’n **Automator Quick Action workflow** wat in ’n afgelaaide app ingebed is, kon sonder Gatekeeper-assessering geaktiveer word, omdat workflows as data behandel en deur die Automator-helper buite die normale notariseringsversoekpad uitgevoer is. ’n Spesiaal saamgestelde `.app` wat ’n Quick Action bevat wat ’n shell script uitvoer (bv. binne `Contents/PlugIns/*.workflow/Contents/document.wflow`), kon dus onmiddellik met die aanvang uitgevoer word. Apple het ’n bykomende toestemmingsdialoog bygevoeg en die assesseringspad in Ventura **13.7**, Sonoma **14.7** en Sequoia **15** reggestel.<sup>[[3]](#references)</sup>

### Foute met die voortplanting van quarantine by ekstraksie- en kopieergrense

’n Studie uit 2024 het gapings in die voortplanting gevind in die getoetste weergawes van iZip (ZIP/TAR/7Z), Archiver (ARCHIVER/ZIP/TAR/7Z), BetterZip (ZIP/TAR/7Z), WinRAR (ZIP/TAR/7Z) en 7z Utility (DMG/ZIP/7Z); dit het ook waargeneem dat die kenmerk verlore gaan tydens VMware Tools-kopieë van gasheer na gas. Verskeie verskaffers het daarna aangekondig dat hulle regstellings aangebring het, behandel hierdie name dus as aanknopingspunte vir **weergawe-spesifieke hertoetsing**, nie as ’n permanente lys van kwesbare sagteware nie. Dieselfde probleem met vertrouensgrense geld vir inheemse Unix-werkvloeie: `curl`/`scp` voeg nie quarantine by nie, en opdragreël-`tar`/`unzip` erf dit nie outomaties van ’n draerargief nie.<sup>[[15]](#references)</sup>

Vergelyk vir offensiewe toetsing die draer en die finale app ná **elke** oorgang tussen blaaier, e-poskliënt, argief, skyfbeeld, wolksinkronisering, gedeelde vouer en VM-kopie. ’n Uitdruklike `spctl`-weiering herstel nie ’n ontbrekende xattr nie: sonder quarantine sal die normale Gatekeeper-pad by die eerste opening dalk nooit daardie assessering aanvra nie.<sup>[[15]](#references)</sup>

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

### uchg (uit hierdie [toespraak](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

- Skep ’n gids wat ’n app bevat.
- Voeg uchg by die app.
- Druk die app saam in ’n tar.gz-lêer.
- Stuur die tar.gz-lêer aan ’n slagoffer.
- Die slagoffer maak die tar.gz-lêer oop en voer die app uit.
- Gatekeeper kontroleer nie die app nie.<sup>[[12]](#references)</sup>

### Voorkom Quarantine xattr

As die quarantine xattr nie by ’n ".app"-bundel gevoeg word nie, sal Gatekeeper nie geaktiveer word wanneer dit uitgevoer word nie.

Sien [macOS FS Tricks](macos-fs-tricks/README.md#avoid-quarantine-xattrs-tricks) vir lêerstelsel-, vlag-, ACL- en AppleDouble-gebaseerde primitiewe wat kan voorkom dat uitgebreide attribute bygevoeg word of dit kan verwyder.





## References

- [1] [Apple Platform Security: Oor die sekuriteitsinhoud van macOS Sonoma 14.4 (sluit CVE-2024-27853 in)](https://support.apple.com/en-us/HT214084)
- [2] [Eclectic Light: Hoe macOS nou die herkoms van apps naspoor](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- [3] [Apple: Oor die sekuriteitsinhoud van macOS Sonoma 14.7 / Ventura 13.7 (CVE-2024-44128)](https://support.apple.com/en-us/121234)
- [4] [MacRumors: macOS 15 Sequoia verwyder die Control‑click “Open”-omseiling van Gatekeeper](https://www.macrumors.com/2024/08/06/macos-sequoia-gatekeeper-security-change/)
- [5] [WithSecure Labs: Die ontdekking van CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)
- [6] [CVE-2021-30990, omseiling van macOS Gatekeeper](https://ronmasas.com/posts/bypass-macos-gatekeeper)
- [7] [Jamf Threat Labs identifiseer Safari-kwesbaarheid wat Gatekeeper-omseiling moontlik maak](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)
- [8] [Jamf Threat Labs identifiseer ’n kwesbaarheid in macOS Archive Utility wat Gatekeeper-omseiling moontlik maak (CVE-2022-32910)](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)
- [9] [Gatekeeper se achilleshiel: ’n macOS-kwesbaarheid blootgelê](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [10] [F-Secure: Ontdekking van ’n Gatekeeper-omseiling (CVE-2023-27943)](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)
- [11] [Vind en rapporteer ’n Gatekeeper-omseilingsuitbuiting met behulp van Mac Monitor](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)
- [12] [CODE BLUE 2023: Omseiling van macOS-sekuriteits- en privaatheidsmeganismes — van Gatekeeper tot System Integrity Protection (Koh Nakagawa)](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf)
- [13] [Apple: Oor die sekuriteitsinhoud van macOS Sonoma 14 (CVE-2023-41067)](https://support.apple.com/en-us/HT213940)
- [14] [Apple Developer Forums: Toetsing van ’n genotariseerde produk](https://developer.apple.com/forums/thread/130560)
- [15] [Unit 42: Gatekeeper-omseiling — onthulling van swakhede in ’n macOS-sekuriteitsmeganisme](https://unit42.paloaltonetworks.com/gatekeeper-bypass-macos/)
{{#include ../../../banners/hacktricks-training.md}}
