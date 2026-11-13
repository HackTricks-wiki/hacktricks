# Partitions/Mifumo ya Faili/Carving

{{#include ../../../banners/hacktricks-training.md}}

## Partitions

Diski inaweza kuwa na **partitions** nyingi: safu za kimantiki za blocks, si hifadhi zilizotenganishwa kimwili. Mwanzo na urefu wa partition hupimwa kwa **logical sectors**; usidhani kila image hutumia sekta za baiti 512, kwa sababu sekta za kimantiki za baiti 4096 pia zipo.<sup>[[4]](#references)</sup>

### MBR (master Boot Record)

MBR inachukua logical sector ya kwanza (LBA 0); entries zake nne za partition zenye baiti 16 huanza kwenye baiti ya 446. Eneo lililotangulia lina boot code na huenda likawa na disk signature.<sup>[[4]](#references)</sup>\
Inaruhusu hadi **partitions 4** (zisizozidi **1** inaweza kuwa active/**bootable**). Hata hivyo, ukihitaji partitions zaidi unaweza kutumia **extended partitions**. **Baiti mbili** za mwisho za MBR yenye baiti 512 ni boot signature **0x55 0xAA**. Ni partition moja tu inayoweza kuwekewa alama ya active.\
Kwa logical sectors za baiti 512, sehemu za sekta za biti 32 za MBR huwekea kikomo uwezo wa kushughulikia anwani hadi takriban **2 TiB** (2.2 TB).<sup>[[4]](#references)</sup>

![Partitions - MBR (master Boot Record): MBR inaruhusu ukubwa wa juu wa 2.2TB](<../../../images/image (350).png>)

![Partitions - MBR (master Boot Record): MBR inaruhusu ukubwa wa juu wa 2.2TB](<../../../images/image (304).png>)

Katika **baiti 440 hadi 443** za MBR unaweza kupata **Windows Disk Signature** (ikiwa Windows inatumika). Herufi ya logical drive ya hard disk hutegemea Windows Disk Signature. Kubadilisha signature hii kunaweza kuzuia Windows kuwaka (tool: [**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**.

![Partitions - MBR (master Boot Record): Katika baiti 440 hadi 443 za MBR unaweza kupata Windows Disk Signature (ikiwa Windows inatumika). Herufi ya logical drive ya hard disk...](<../../../images/image (310).png>)

**Muundo**

| Offset      | Length     | Kipengee                |
| ----------- | ---------- | ------------------- |
| 0 (0x00)    | 446(0x1BE) | Boot code           |
| 446 (0x1BE) | 16 (0x10)  | Partition ya kwanza     |
| 462 (0x1CE) | 16 (0x10)  | Partition ya pili    |
| 478 (0x1DE) | 16 (0x10)  | Partition ya tatu     |
| 494 (0x1EE) | 16 (0x10)  | Partition ya nne    |
| 510 (0x1FE) | 2 (0x2)    | Signature 0x55 0xAA |

**Muundo wa Rekodi ya Partition**

| Offset    | Length   | Kipengee                                                   |
| --------- | -------- | ------------------------------------------------------ |
| 0 (0x00)  | 1 (0x01) | Alama ya active (0x80 = bootable)                          |
| 1 (0x01)  | 1 (0x01) | Start head                                             |
| 2 (0x02)  | 1 (0x01) | Start sector (biti 0-5); biti za juu za cylinder (6- 7) |
| 3 (0x03)  | 1 (0x01) | Biti 8 za chini za start cylinder                           |
| 4 (0x04)  | 1 (0x01) | Msimbo wa aina ya partition (0x83 = Linux)                     |
| 5 (0x05)  | 1 (0x01) | End head                                               |
| 6 (0x06)  | 1 (0x01) | End sector (biti 0-5); biti za juu za cylinder (6- 7)   |
| 7 (0x07)  | 1 (0x01) | Biti 8 za chini za end cylinder                             |
| 8 (0x08)  | 4 (0x04) | Sekta zinazotangulia partition (little endian)            |
| 12 (0x0C) | 4 (0x04) | Sekta zilizo kwenye partition                                   |

Ili kukagua partition katika image ya MBR ya diski nzima, kwanza pata start LBA yake na ukubwa wa logical sector. `mount` hutumia **byte offset**, si LBA; mfano ulio hapa chini unatumika tu kwa image yenye sekta za baiti 512 ambayo partition yake inaanzia LBA 63. Kwa image zisizoaminika au mifumo ya faili inayotumia journal, badala yake tumia utaratibu uliotengwa, wa kusoma tu, katika [Image Acquisition & Mount](../image-acquisition-and-mount.md).<sup>[[5]](#references)[[11]](#references)</sup>

![Partitions - MBR (master Boot Record): Ili ku-mount MBR kwenye Linux, kwanza unahitaji kupata offset ya mwanzo (unaweza kutumia fdisk na amri ya p)](<../../../images/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

```bash
mmls -b 512 /path/to/image.dd  # Confirm the start LBA from this image
sudo mount -o ro,loop,offset=$((63 * 512)),noatime /path/to/image.dd /media/part/
```

**LBA (Logical block addressing)**

**Logical block addressing** (**LBA**) ni mpango wa kawaida unaotumika **kubainisha mahali zilipo block** za data zilizohifadhiwa kwenye vifaa vya hifadhi ya kompyuta, kwa kawaida mifumo ya hifadhi ya pili kama vile hard disk drives. LBA ni mpango rahisi sana wa uelekezaji wa mstari; **block hutambuliwa kwa faharasa ya nambari kamili**, ambapo block ya kwanza ni LBA 0, ya pili ni LBA 1, na kuendelea.

### GPT (GUID Partition Table)

GUID Partition Table (GPT) huhifadhi GUID ya kipekee kwa kila partition na hutumia metadata ya msingi na ya chelezo. Mpangilio wake hutofautiana na MBR kama ifuatavyo:<sup>[[4]](#references)</sup>

- **Mahali na Ukubwa**: LBA 0 ina **protective MBR**. GPT header ya msingi iko kwenye LBA 1; array ya partition entries hufuata, na array pamoja na header ya chelezo viko mwisho wa disk. GPT hutumia sehemu za LBA za biti 64, ilhali partition entries za MBR hutumia sehemu za LBA za biti 32.
- **Vikomo vya Partition**: Array ya kawaida ya 16-KiB ya entries huhifadhi **entries 128 zenye baiti 128 kila moja**, lakini idadi ya entries hurekodiwa kwenye header badala ya kubainishwa moja kwa moja na GPT. Ukubwa unaoweza kushughulikiwa pia hutegemea ukubwa wa logical sector (takriban **9.4 ZB** kwa sectors za baiti 512).<sup>[[4]](#references)</sup>
- **Majina ya Partition**: Hutoa uwezo wa kuzipa partition majina yenye hadi herufi 36 za Unicode.

**Ustahimilivu na Urejeshaji wa Data**:

- **Uredundansi**: Tofauti na MBR, GPT haihifadhi data ya partitioning na boot katika sehemu moja tu. Huiga data hii sehemu mbalimbali za disk, na hivyo kuongeza uadilifu na ustahimilivu wa data.
- **Cyclic Redundancy Check (CRC)**: Header na array ya partition entries kila moja ina CRC32. CRC hutambua kutolingana; haifuatilii disk mfululizo wala kuitengeneza yenyewe. Ikiwa nakala ya msingi si halali, hakiki nakala ya chelezo kwenye LBA ya mwisho kabla ya kufanya urejeshaji wowote kwenye nakala ya kufanya kazi.<sup>[[4]](#references)</sup>

**Protective MBR (LBA0)**:

- GPT hudumisha uoanifu wa nyuma kupitia protective MBR. Kipengele hiki kiko kwenye nafasi ya MBR ya zamani, lakini kimeundwa kuzuia zana za zamani zinazotegemea MBR zisifute kimakosa disks za GPT, hivyo kulinda uadilifu wa data kwenye disks zilizofomatiwa kwa GPT.

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID_Partition_Table_Scheme.svg/800px-GUID_Partition_Table_Scheme.svg.png](<../../../images/image (1062).png>)

**Hybrid MBR (LBA 0 + GPT)**

[From Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

Katika mifumo ya uendeshaji inayotumia **boot ya GPT kupitia** huduma za **BIOS** badala ya EFI, sector ya kwanza bado inaweza kutumika kuhifadhi msimbo wa hatua ya kwanza ya **bootloader**, lakini **umebadilishwa** ili kutambua **partition** za **GPT**. Bootloader katika MBR haipaswi kudhani kuwa ukubwa wa sector ni baiti 512.

**Header ya partition table (LBA 1)**

[From Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

Header ya partition table hufafanua block zinazoweza kutumika kwenye disk. Pia hufafanua idadi na ukubwa wa partition entries zinazounda partition table (offsets 80 na 84 katika table).

| Offset    | Length   | Contents                                                                                                                                                                     |
| --------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)  | 8 bytes  | Signature ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h or 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID_Partition_Table#cite_note-8)kwenye mashine za little-endian) |
| 8 (0x08)  | 4 bytes  | Revision 1.0 (00h 00h 01h 00h) kwa UEFI 2.8                                                                                                                                  |
| 12 (0x0C) | 4 bytes  | Ukubwa wa header katika little endian (kwa baiti, kwa kawaida 5Ch 00h 00h 00h au baiti 92)                                                                                 |
| 16 (0x10) | 4 bytes  | [CRC32](https://en.wikipedia.org/wiki/CRC32) ya header (offset +0 hadi ukubwa wa header) katika little endian, huku sehemu hii ikiwekwa sifuri wakati wa kukokotoa             |
| 20 (0x14) | 4 bytes  | Imehifadhiwa; lazima iwe sifuri                                                                                                                                              |
| 24 (0x18) | 8 bytes  | LBA ya sasa (mahali ilipo nakala hii ya header)                                                                                                                             |
| 32 (0x20) | 8 bytes  | LBA ya chelezo (mahali ilipo nakala nyingine ya header)                                                                                                                     |
| 40 (0x28) | 8 bytes  | LBA ya kwanza inayoweza kutumika kwa partition (LBA ya mwisho ya primary partition table + 1)                                                                                |
| 48 (0x30) | 8 bytes  | LBA ya mwisho inayoweza kutumika (LBA ya kwanza ya secondary partition table − 1)                                                                                           |
| 56 (0x38) | 16 bytes | Disk GUID katika mixed endian                                                                                                                                               |
| 72 (0x48) | 8 bytes  | LBA ya mwanzo ya array ya partition entries (daima 2 kwenye nakala ya msingi)                                                                                                |
| 80 (0x50) | 4 bytes  | Idadi ya partition entries kwenye array                                                                                                                                     |
| 84 (0x54) | 4 bytes  | Ukubwa wa partition entry moja (kwa kawaida 80h au 128)                                                                                                                     |
| 88 (0x58) | 4 bytes  | CRC32 ya array ya partition entries katika little endian                                                                                                                    |
| 92 (0x5C) | \*       | Imehifadhiwa; lazima iwe sifuri katika sehemu iliyosalia ya block (baiti 420 kwa sector yenye ukubwa wa baiti 512; lakini inaweza kuwa zaidi kwa sector kubwa)               |

**Partition entries (LBA 2–33)**

| Muundo wa GUID partition entry |          |                                                                                                               |
| ------------------------------ | -------- | ------------------------------------------------------------------------------------------------------------- |
| Offset                         | Length   | Contents                                                                                                      |
| 0 (0x00)                       | 16 bytes | [Partition type GUID](https://en.wikipedia.org/wiki/GUID_Partition_Table#Partition_type_GUIDs) (mixed endian) |
| 16 (0x10)                      | 16 bytes | GUID ya kipekee ya partition (mixed endian)                                                                   |
| 32 (0x20)                      | 8 bytes  | LBA ya kwanza ([little endian](https://en.wikipedia.org/wiki/Little_endian))                                  |
| 40 (0x28)                      | 8 bytes  | LBA ya mwisho (inajumuishwa, kwa kawaida ni isiyo shufwa)                                                     |
| 48 (0x30)                      | 8 bytes  | Bendera za sifa (kwa mfano, biti ya 60 huashiria ya kusoma pekee)                                             |
| 56 (0x38)                      | 72 bytes | Jina la partition (vitengo 36 vya msimbo wa [UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE)                 |

**Aina za Partition**

![MBR (master Boot Record) - GPT (GUID Partition Table): 56 (0x38) | 72 bytes | Jina la partition (vitengo 36 vya msimbo wa UTF-16LE)](<../../../images/image (83).png>)

Aina zaidi za partition zinapatikana kwenye [https://en.wikipedia.org/wiki/GUID_Partition_Table](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

### Ukaguzi

Baada ya kupachika picha ya forensics kwa kutumia [**ArsenalImageMounter**](https://arsenalrecon.com/downloads/), unaweza kukagua sector ya kwanza kwa kutumia zana ya Windows [**Active Disk Editor**](https://www.disk-editor.org/index.html)**.** Kwenye picha ifuatayo, **MBR** ilitambuliwa kwenye **sector 0** na kufasiriwa:

![GPT (GUID Partition Table) - Ukaguzi: Baada ya kupachika picha ya forensics kwa kutumia ArsenalImageMounter, unaweza kukagua sector ya kwanza kwa kutumia zana ya Windows Active Disk Editor. Kwenye...](<../../../images/image (354).png>)

Kwa GPT, tafuta signature ya _EFI PART_ kwenye header ya msingi katika **LBA 1**; LBA 0 bado ina protective MBR.<sup>[[4]](#references)</sup>

### Kutafuta data nje ya partition zilizoorodheshwa

Partition entry iliyofutwa au nafasi iliyoachwa bila kutumika kimakusudi inaweza kuacha filesystem nje ya ramani ya sasa ya partition. Kwenye **nakala ghafi iliyothibitishwa ya kufanya kazi**, orodhesha safu zisizotengwa, kisha jaribu LBA ya mwanzo inayowezekana kama filesystem. `mmls` na `fsstat` hutumia **offsets za sector**; zipatie zote mbili ukubwa halisi wa logical sector. Usizichukulie sectors za metadata za GPT kimakosa kuwa volume iliyofichwa.<sup>[[5]](#references)[[6]](#references)</sup>

```bash
mmls -b 512 -A disk.img                # Unallocated ranges: Start and Length
fsstat -b 512 -o 2048 disk.img       # Replace 2048 with a candidate Start LBA
```

Ikiwa `fsstat` haiwezi kutambua mfumo wa faili mwanzoni mwa pengo, tumia TestDisk **Analyse → Quick Search**, kisha **Deeper Search** ikihitajika. Bonyeza `P` kwenye mgombea ili kukagua faili; usichague **Write** kwenye ushahidi. Kwenye picha za GPT, `sgdisk --verify disk.img` hukagua CRC na ulinganifu wa jedwali kuu na nakala rudufu, lakini kichwa rudufu kinaweza kuwa kimepitwa na wakati baada ya kugawa upya, kwa hiyo thibitisha mipaka ya wagombea kwa kutumia miundo ya mfumo wa faili kabla ya kurejesha.<sup>[[9]](#references)[[10]](#references)[[4]](#references)</sup>

## Mifumo ya Faili

### Orodha ya mifumo ya faili ya Windows

- **FAT12/16**: MSDOS, WIN95/98/NT/200
- **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
- **ExFAT**: 2008/2012/2016/VISTA/7/8/10
- **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
- **ReFS**: 2012/2016

### FAT

Mfumo wa faili wa **FAT (File Allocation Table)** umeundwa kuzunguka sehemu yake kuu, jedwali la ugawaji wa faili, lililowekwa mwanzoni mwa volume. Volume huwa na **nakala mbili za FAT**, ingawa BPB inaruhusu moja. FAT12/16 huweka saraka kuu kwenye eneo lisilobadilika; FAT32 huhifadhi saraka yake kuu katika eneo la data, kwenye cluster iliyoainishwa na `BPB_RootClus`.<sup>[[7]](#references)</sup>

Kipimo cha ugawaji ni **cluster**: `BPB_BytsPerSec × BPB_SecPerClus`, ambacho si lazima kiwe baiti 512. Aina ya FAT huamuliwa na idadi ya cluster za data, si mfuatano wa toleo kwenye boot sector. Mipaka ya idadi ya cluster ni:<sup>[[7]](#references)</sup>

- **FAT12**: chini ya cluster 4,085 za data.
- **FAT16**: cluster 4,085 hadi 65,524 za data.
- **FAT32**: angalau cluster 65,525 za data; biti 28 pekee kati ya biti 32 za kila ingizo la FAT hutumika kwa nambari ya cluster.

Sehemu ya biti 32 ya ukubwa wa faili huweka kikomo cha faili ya kawaida kuwa **baiti 2³²−1** (chini kidogo ya 4 GiB).<sup>[[7]](#references)</sup>

Vipengele muhimu vya saraka kuu, hasa kwa FAT12 na FAT16, ni pamoja na:

- **Jina la Faili/Folder** (hadi herufi 8)
- **Sifa**
- **Tarehe za Kuundwa, Kurekebishwa na Kufikiwa Mara ya Mwisho**
- **Anwani ya Jedwali la FAT** (inayoonyesha cluster ya mwanzo ya faili)
- **Ukubwa wa Faili**

### EXT

**Ext2** ndiyo mfumo wa faili unaotumika zaidi kwa partitions **zisizo na journaling** (**partitions ambazo hazibadiliki sana**), kama vile boot partition. **Ext3/4** zina **journaling** na kwa kawaida hutumika kwa **partitions nyingine**.

## **Metadata**

Baadhi ya faili zina metadata. Taarifa hii inahusu maudhui ya faili na wakati mwingine inaweza kumvutia mchambuzi kwa kuwa, kutegemea aina ya faili, inaweza kuwa na taarifa kama:

- Kichwa
- Toleo la MS Office lililotumika
- Mwandishi
- Tarehe za kuundwa na kurekebishwa mara ya mwisho
- Modeli ya kamera
- Viwianishi vya GPS
- Taarifa za picha

Unaweza kutumia zana kama [**exiftool**](https://exiftool.org) na [**Metadiver**](https://www.easymetadata.com/metadiver-2/) kupata metadata ya faili.

## **Urejeshaji wa Faili Zilizofutwa**

### Faili Zilizofutwa Zilizoandikwa Kwenye Rekodi

Kama ilivyoonekana awali, kuna maeneo kadhaa ambako faili hubaki kuhifadhiwa baada ya "kufutwa". Hii ni kwa sababu kwa kawaida kufuta faili kutoka kwenye mfumo wa faili huiweka tu alama kuwa imefutwa, lakini data haiguswi. Kisha, inawezekana kukagua rekodi za faili (kama vile MFT) na kupata faili zilizofutwa.<sup>[[2]](#references)</sup>

Pia, OS kwa kawaida huhifadhi taarifa nyingi kuhusu mabadiliko ya mfumo wa faili na nakala rudufu, kwa hiyo inawezekana kujaribu kuzitumia kurejesha faili au taarifa nyingi iwezekanavyo.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### **File Carving**

**File carving** ni mbinu inayojaribu **kutafuta faili katika data nyingi**. Kuna njia kuu 3 ambazo zana kama hizi hutumia: **Kutegemea vichwa na miisho ya aina za faili**, kutegemea **miundo** ya aina za faili, na kutegemea **maudhui** yenyewe.

File carving rahisi inayotegemea kichwa/mwisho hudhani kuwa vitalu viko mfululizo na inaweza kurejesha kipande tu faili inapogawanyika. Hiki si kikomo kamili: PhotoRec ina chaguo la **Paranoid → bruteforce** linalotumia CPU sana kwa baadhi ya JPEG zilizogawanyika, ilhali uunganishaji upya wa vipande unaotambua muundo wa faili unaweza kurejesha aina nyingine zinazotumika. Tazama [zana za file carving na urejeshaji](file-data-carving-recovery-tools.md#scalpel3-fragmented-carving) kwa utaratibu wa sasa wa kuunganisha upya vipande.<sup>[[8]](#references)</sup>

Kuna zana kadhaa unazoweza kutumia kwa file carving, ukibainisha aina za faili unazotaka kutafuta


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Data Stream **C**arving

Data Stream Carving inafanana na File Carving lakini **badala ya kutafuta faili kamili, hutafuta vipande vya taarifa vinavyovutia**.\
Kwa mfano, badala ya kutafuta faili kamili yenye URL zilizoandikwa kwenye rekodi, mbinu hii itatafuta URL.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Ufutaji Salama

Ni wazi kuwa kuna njia za **kufuta faili na sehemu za rekodi zake kwa "usalama"**. Kwa mfano, inawezekana **kubadilisha maudhui** ya faili kwa data isiyo na maana mara kadhaa, kisha **kuondoa** **rekodi** za faili kutoka kwenye **$MFT** na **$LOGFILE**, na **kuondoa Volume Shadow Copies**.<sup>[[3]](#references)</sup>\
Unaweza kugundua kuwa hata baada ya kufanya hivyo, huenda **bado kuna maeneo mengine yanayoonyesha kuwa faili hiyo ilikuwepo**; hilo ni kweli, na sehemu ya kazi ya mtaalamu wa forensics ni kuyapata.



## References

- [1] [Jedwali la Sehemu za GUID - Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)
- [2] [Jinsi ya kuchanganua ingizo za NTFS $I30 (saraka) ili kupata ushahidi wa faili zilizofutwa](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
- [3] [Huduma ya Volume Shadow Copy (VSS)](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
- [4] [Uainisho wa UEFI: Muundo wa diski ya GPT](https://uefi.org/specs/UEFI/2.9_A/05_GUID_Partition_Table_Format.html)
- [5] [Mwongozo wa mmls wa The Sleuth Kit](https://sleuthkit.org/sleuthkit/man/mmls.html)
- [6] [Mwongozo wa fsstat wa The Sleuth Kit](https://www.sleuthkit.org/sleuthkit/man/fsstat.html)
- [7] [Uainisho wa FAT wa Microsoft](https://academy.cba.mit.edu/classes/networking_communications/SD/FAT.pdf)
- [8] [Chaguo za urejeshaji za PhotoRec](https://www.cgsecurity.org/testdisk_doc/photorec.html)
- [9] [Urejeshaji wa partitions zilizofutwa kwa TestDisk](https://www.cgsecurity.org/testdisk_doc/partition_recovery.html)
- [10] [Mwongozo wa sgdisk](https://manpages.debian.org/trixie/gdisk/sgdisk.8.en.html)
- [11] [Mwongozo wa mount(8)](https://man7.org/linux/man-pages/man8/mount.8.html)
{{#include ../../../banners/hacktricks-training.md}}
