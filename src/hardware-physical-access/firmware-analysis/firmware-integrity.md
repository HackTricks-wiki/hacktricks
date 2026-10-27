# Uadilifu wa Firmware

{{#include ../../banners/hacktricks-training.md}}

Tathmini iliyoidhinishwa ikibaini kuwa uthibitishaji wa saini ya firmware ni dhaifu au haupo, picha ya firmware iliyorekebishwa inaweza kuonyesha athari kwa uadilifu. Mtiririko ufuatao wa majaribio unaongeza bind shell huku ukihifadhi hatua za awali za kutoa, kuiga na kufunga upya firmware.<sup>[[2]](#references)[[3]](#references)</sup>

1. Firmware inaweza kutolewa kwa kutumia firmware-mod-kit (FMK).
2. Usanifu na endianness ya firmware lengwa zinapaswa kutambuliwa.
3. Cross compiler inaweza kujengwa kwa kutumia Buildroot au njia nyingine zinazofaa kwa mazingira husika.
4. Backdoor inaweza kujengwa kwa kutumia cross compiler.
5. Backdoor inaweza kunakiliwa kwenye saraka ya /usr/bin ya firmware iliyotolewa.
6. Binary inayofaa ya QEMU inaweza kunakiliwa kwenye rootfs ya firmware iliyotolewa.
7. Backdoor inaweza kuigwa kwa kutumia chroot na QEMU.
8. Backdoor inaweza kufikiwa kupitia netcat.
9. Binary ya QEMU inapaswa kuondolewa kwenye rootfs ya firmware iliyotolewa.
10. Firmware iliyorekebishwa inaweza kufungwa upya kwa kutumia FMK.
11. Firmware yenye backdoor inaweza kujaribiwa kwa kuiiga kwa kutumia firmware analysis toolkit (FAT) na kuunganisha kwenye IP na port ya backdoor lengwa kwa kutumia netcat.

Ikiwa root shell tayari imepatikana kupitia dynamic analysis, uchezaji wa bootloader, au majaribio ya usalama wa hardware, binary za majaribio zilizokompiliwa awali kama vile implants au reverse shells zinaweza kutekelezwa. `msfvenom` ya Metasploit inaweza kutengeneza payload maalum kwa usanifu husika kwa mtiririko huu wa uthibitishaji:<sup>[[4]](#references)</sup>

1. Usanifu na endianness ya firmware lengwa zinapaswa kutambuliwa.
2. Msfvenom inaweza kutumika kubainisha payload lengwa, IP ya host ya mshambuliaji, nambari ya port ya kusikilizia, aina ya faili, usanifu, platform, na faili la matokeo.
3. Payload inaweza kuhamishiwa kwenye kifaa kilichovamiwa na kuhakikisha kuwa ina ruhusa za kutekelezwa.
4. Metasploit inaweza kutayarishwa kushughulikia maombi yanayoingia kwa kuwasha msfconsole na kusanidi mipangilio kulingana na payload.
5. Reverse shell ya meterpreter inaweza kutekelezwa kwenye kifaa kilichovamiwa.

## Madaraja ya usafirishaji yasiyohitaji uthibitishaji kuelekea itifaki za masasisho zenye haki za juu

Kosa la kawaida katika usanifu wa mifumo iliyopachikwa ni kufichua **itifaki ileile ya amri ya ndani kupitia njia nyingi za usafirishaji**, lakini kutekeleza uthibitishaji kwenye njia moja tu. Kwa mfano, USB inaweza kuhitaji challenge-response huku BLE ikipitisha tu **GATT writes** zisizothibitishwa kwa kidhibiti kilekile cha upendeleo wa juu cha masasisho ya firmware.<sup>[[1]](#references)</sup>

Mtiririko wa kawaida wa mashambulizi:

1. Orodhesha hifadhidata ya BLE GATT na utambue characteristics zinazoweza kuandikwa na zinazotumiwa na app rasmi ya simu.
2. Nasa trafiki ya app na utafute **magic bytes / opcodes** zinazolingana na itifaki ya waya.
3. Rudia amri zenye upendeleo wa juu kupitia BLE **bila ku-pair** na uhakikishe kama shughuli nyeti bado zinafanya kazi.
4. Ikiwa opcodes za masasisho ya firmware, uandishi wa usanidi, utatuzi, au majaribio ya kiwandani zinafikiwa, ichukulie BLE kama **port ya admin inayofikiwa kupitia mawimbi ya redio**.

Ukaguzi wa haraka:

```bash
# Enumerate services/characteristics
ble.enum <MAC>

# Replay a sniffed command
ble.write <MAC> <UUID> <HEX_DATA>

# gatttool equivalent
# gatttool -b <MAC> --char-write-req -a <HANDLE> -n <HEX_DATA>
```

Mambo ya kuthibitisha wakati wa kufanya reverse engineering:

- Je, BLE inahitaji **pairing/bonding**, au muunganisho wa kawaida tu?
- Je, transports zote huelekezwa kwenye jedwali lilelile la ndani la dispatcher?
- Je, opcodes zenye ruhusa za juu huchujwa kwa njia tofauti kwenye USB / BLE / UART / Wi-Fi?
- Je, programu ya simu inaweza kuanzisha kwa mbali vihandle vya kusasisha firmware, recovery, au uchunguzi?

## Kontena za firmware zinazotumia checksum pekee bado zina firmware inayodhibitiwa na mshambuliaji

Kontena la firmware linalolindwa kwa **checksum isiyo na ufunguo** pekee (CRC32, SHA-256, MD5, n.k.) hutambua uharibifu, **si uhalisi**. Ikiwa mshambuliaji anaweza kufikia utaratibu wa kusasisha, anaweza kurekebisha image, kukokotoa upya checksum, na ku-flash msimbo wowote.<sup>[[1]](#references)</sup>

Dalili za hatari wakati wa RE:

- Msimbo wa kusasisha hukagua blob ya checksum iliyo mwishoni pekee, kama `CHK2`, `CRC`, au `SHA256`.
- Hakuna uthibitishaji wa signature au msingi wa uaminifu wa secure boot.
- Hakuna MAC / HMAC inayofungamanishwa na kifaa au usimbaji fiche ulio na uthibitishaji.
- Recovery mode hukubali muundo huohuo wa image usio na uthibitishaji.

Mtiririko wa vitendo wa uthibitishaji:

1. Toa yaliyomo kwenye kontena la firmware na utambue bootloader, firmware kuu, na metadata ya integrity.
2. Badilisha maandishi au bango lisilo na madhara kwenye image.
3. Kokotoa upya checksum kama inavyotarajiwa na updater.
4. Flash image hiyo tena kupitia njia ya kawaida ya kusasisha.
5. Thibitisha mabadiliko wakati wa kuwasha ili kuthibitisha uwezekano wa kubadilisha firmware kiholela.

Ikiwa hili linawezekana kupitia transport inayoweza kufikiwa kwa mbali kama BLE/Wi-Fi, hitilafu hiyo kimsingi ni **ubadilishaji wa firmware ya OTA bila uthibitishaji**.

## Hali ya kusasisha iliyogawanyika na metadata ya integrity inayoweza kuandikwa

Updater inaweza kuthibitisha kichwa cha firmware kilichosainiwa wakati wa usakinishaji, lakini bado ikawasha image kwa kutumia hash iliyohifadhiwa pekee. Kwenye Cypherock X1, Bootloader iliita kazi tofauti za Firewall ili kuthibitisha kichwa na kuweka version/size kwenye RAM, kuhifadhi signature ya firmware kwenye RAM, kuthibitisha image iliyoandikwa, na hatimaye ku-hash image na kuihifadhi kwenye Primary Bootloader Data endelevu. Signature yenyewe haikuhifadhiwa. Kazi hizi zingeweza kuitwa kivyake badala ya kutekeleza muamala mmoja wa kusasisha uliothibitishwa.<sup>[[5]](#references)</sup>

Kwa utekelezaji wa msimbo wa MCU na ufikiaji wa kuandika Flash, shambulio lililoripotiwa liliandika upya image ya programu, likabadilisha thamani za version/size kwenye RAM ya Bootloader inayoshirikiwa na Firewall, kisha likaita kazi ya mwisho ya metadata ili kuhifadhi hash ya image hasidi na kurejesha hali ya kawaida ya kuwasha. Ukaguzi wa kawaida wa integrity wakati wa kuwasha ulikubali hash hiyo bila kuthibitisha tena signature. Unapochunguza updater inayofanana, fuatilia **ni kipengele kipi kinaweza kuita kila kazi**, mahali ambapo thamani zilizothibitishwa huhifadhiwa, na iwapo uamuzi wa kuwasha unathibitisha *image ileile* ambayo hash yake imehifadhiwa. Hili ni tatizo mahususi zaidi kuliko muundo wa image unaotumia checksum pekee: uthibitishaji wa signature ulikuwepo, lakini mabadiliko ya hali hayakufungamanishwa nayo.<sup>[[5]](#references)</sup>

## Signature za secure element juu ya vipimo vya firmware visivyoaminika

Secure element haihakikishi msimbo unaoendeshwa kwa kusaini tu hash inayotolewa na msimbo huo. Kwenye wallet hiyohiyo, secure element ilisaini nambari ya serial ya kifaa, kisha XOR ya cloud nonce na hash ya firmware iliyotolewa kupitia MCU. Firmware iliyoathiriwa ingeweza kuwasilisha hash inayotarajiwa isainiwe huku ikiendesha bytes tofauti. Pia, client mwenza ilipeleka version ya firmware kwenye cloud, kwa hiyo ulinganisho wa hash inayotarajiwa na verifier bado ulitegemea kipimo kilichotoka kwa MCU badala ya usomaji huru wa Flash.<sup>[[5]](#references)</sup>

Matokeo ya upande wa kifaa yalikuwa mpaka tofauti wa uaminifu: cloud ilikagua kifaa, lakini kifaa hakikuthibitisha uamuzi wa cloud. Client iliyorekebishwa ingeweza kuripoti mafanikio ya ndani kwa kifaa kilichobadilishwa. Jaribu kando chanzo cha kipimo na uthibitishaji wa majibu; signature halali ya secure element na skrini ya mafanikio, peke yake, havithibitishi kuwa programu iliyosakinishwa ni halisi.<sup>[[5]](#references)</sup>

Kwa maelezo ya msimbo uliolindwa yaliyowezesha uchambuzi wa updater hii, angalia [Upatikanaji wa firmware kupitia kazi ya kunakili ya Firewall](index.html#disclosing-protected-code-through-a-firewall-copy-task).<sup>[[5]](#references)</sup>

## Kubadilisha kifaa cha pembeni cha USB kinachoaminika kuwa BadUSB kwa ku-flash firmware upya

Wakati kifaa lengwa tayari kinaaminika na host kupitia USB, firmware hasidi huenda isihitaji kutekeleza USB stack mpya kikamilifu. Mara nyingi njia rahisi zaidi ni **kutumia tena usaidizi uliopo wa HID**.<sup>[[1]](#references)</sup>

Mfumo muhimu:

1. Angalia kama kifaa tayari huonekana kama kiolesura cha **HID Consumer Control** / media / vendor HID.
2. Tafuta **HID report descriptor** iliyopo kwenye firmware.
3. Ongeza au badilisha maingizo ya descriptor ili kifaa pia kitangaze uwezo wa **keyboard**.
4. Tumia tena taratibu za firmware zilizopo ambazo tayari hutuma HID reports, badala ya kuandika utekelezaji mpya wa transport.
5. Ingiza report za kubonyeza kitufe na kukiachia ili kuandika amri kwenye host.

Hili hubadilisha uathiriwaji wa firmware kuwa **uathiriwaji wa host**, kwa sababu PC itaamini kifaa cha pembeni kilichoflashiwa upya kuwa keyboard halali.

### Orodha fupi ya ukaguzi wa tathmini

- Je, `dmesg`, Device Manager, au USB descriptors zinaonyesha kiolesura cha HID kilichopo?
- Je, kuna nafasi ya ziada karibu na report descriptor au jedwali la descriptor linaloweza kuhamishwa?
- Je, taratibu zilizopo za kutuma vidhibiti vya media zinaweza kutumika tena kwa keyboard reports?
- Je, host itakubali kiolesura kipya cha keyboard kiotomatiki baada ya ku-flash upya?

## Utekelezaji wa payload unaotegemeka ndani ya firmware ya RTOS

Badala ya kuingiza trampolines zisizo imara kwenye njia za msimbo zisizohusiana, tafuta **kazi za RTOS zilizopo** ambazo hazitumiki au zina athari ndogo katika matumizi ya kawaida.<sup>[[1]](#references)</sup>

Kwa nini hili linafaa:

- Scheduler huanzisha payload yako yenyewe wakati wa kuwasha.
- Unaepuka kuharibu mtiririko muhimu wa udhibiti.
- Payload zinazoanza kwa kuchelewa zina uwezekano mdogo wa kusababisha watchdog reset kuliko zinapoendeshwa ndani ya handler ya USB/network inayohitaji mwitikio wa haraka.

Malengo yanayofaa ni kazi za uchunguzi, majaribio ya kiwandani, telemetry, au huduma za coprocessor zinazoonekana kutofanya kazi katika matumizi ya kawaida.

## Kurudia majaribio ya exploit haraka: tumia tena handlers zisizo na madhara za protocol

Mara tu marekebisho ya firmware yanapowezekana, njia fupi ya kuharakisha RE ni kubadilisha handler ya amri isiyo na madhara (kwa mfano **echo/debug opcode**) na kuweka primitives maalum za **kusoma / kuandika / kutekeleza kumbukumbu**. Hii huepusha ku-flash upya kila jaribio na ni muhimu hasa kifaa kinapounga mkono handler iliyorekebishwa kupitia transport ya waya ya kasi.<sup>[[1]](#references)</sup>

Tumia hili ili:

- Kuthibitisha ramani za kumbukumbu zilizopakiwa katika maeneo mbalimbali
- Kukagua hali ya heap/task moja kwa moja
- Kujaribu payload ndogo kabla ya kuziandika kwenye flash
- Kurejesha function pointers, strings, na descriptor tables kwa usalama

## References

- [1] [Pwnd Blaster: Kudukua PC yako kwa kutumia spika yako bila kuigusa hata mara moja](https://blog.nns.ee/2026/06/03/katana-badusb/)
- [2] [firmware-mod-kit](https://github.com/rampageX/firmware-mod-kit)
- [3] [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit)
- [4] [Metasploit - Jinsi ya kutumia `msfvenom`](https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html)
- [5] [Jinsi na kwa nini tulidukua hardware wallet ya Cypherock: simulizi kamili](https://www.darknavy.org/blog/how_and_why_we_hacked_cypherock_hardware_wallet_the_full_story/)
{{#include ../../banners/hacktricks-training.md}}
