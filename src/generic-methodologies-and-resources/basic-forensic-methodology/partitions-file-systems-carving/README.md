# Bölümler/Dosya Sistemleri/Carving

{{#include ../../../banners/hacktricks-training.md}}

## Bölümler

Bir sabit disk veya **SSD disk, verileri fiziksel olarak ayırmak** amacıyla farklı **partitions** içerebilir.\
Bir diskin **minimum** birimi **sector**'dür (normalde 512B'den oluşur). Bu nedenle her bölümün boyutu bu değerin katı olmalıdır.

### MBR (master Boot Record)

**446B'lik boot code'dan sonra diskin ilk sector'üne** ayrılır. Bu sector, PC'ye bir bölümün neyi ve nereden mount edilmesi gerektiğini belirtmek için gereklidir.\
En fazla **4 partition** kullanımına izin verir (en fazla **yalnızca 1** tanesi active/**bootable** olabilir). Ancak daha fazla bölüm gerekiyorsa **extended partitions** kullanabilirsiniz. Bu ilk sector'ün **son byte'ı**, boot record signature olan **0x55AA**'dır. Yalnızca bir bölüm active olarak işaretlenebilir.\
MBR **en fazla 2.2TB** destekler.

![Partitions - MBR (master Boot Record): MBR en fazla 2.2TB destekler](<../../../images/image (350).png>)

![Partitions - MBR (master Boot Record): MBR en fazla 2.2TB destekler](<../../../images/image (304).png>)

MBR'nin **440 ile 443 arasındaki byte'larında**, (Windows kullanılıyorsa) **Windows Disk Signature**'ı bulabilirsiniz. Sabit diskin logical drive letter'ı Windows Disk Signature'a bağlıdır. Bu signature'ı değiştirmek, Windows'un boot etmesini engelleyebilir (tool: [**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**.

![Partitions - MBR (master Boot Record): MBR'nin 440 ile 443 arasındaki byte'larında (Windows kullanılıyorsa) Windows Disk Signature'ı bulabilirsiniz. Sabit diskin logical drive letter'ı...](<../../../images/image (310).png>)

**Format**

| Offset      | Length     | Item                |
| ----------- | ---------- | ------------------- |
| 0 (0x00)    | 446(0x1BE) | Boot code           |
| 446 (0x1BE) | 16 (0x10)  | First Partition     |
| 462 (0x1CE) | 16 (0x10)  | Second Partition    |
| 478 (0x1DE) | 16 (0x10)  | Third Partition     |
| 494 (0x1EE) | 16 (0x10)  | Fourth Partition    |
| 510 (0x1FE) | 2 (0x2)    | Signature 0x55 0xAA |

**Partition Record Format**

| Offset    | Length   | Item                                                   |
| --------- | -------- | ------------------------------------------------------ |
| 0 (0x00)  | 1 (0x01) | Active flag (0x80 = bootable)                          |
| 1 (0x01)  | 1 (0x01) | Start head                                             |
| 2 (0x02)  | 1 (0x01) | Start sector (bits 0-5); upper bits of cylinder (6- 7) |
| 3 (0x03)  | 1 (0x01) | Start cylinder lowest 8 bits                           |
| 4 (0x04)  | 1 (0x01) | Partition type code (0x83 = Linux)                     |
| 5 (0x05)  | 1 (0x01) | End head                                               |
| 6 (0x06)  | 1 (0x01) | End sector (bits 0-5); upper bits of cylinder (6- 7)   |
| 7 (0x07)  | 1 (0x01) | End cylinder lowest 8 bits                             |
| 8 (0x08)  | 4 (0x04) | Sectors preceding partition (little endian)            |
| 12 (0x0C) | 4 (0x04) | Sectors in partition                                   |

Linux'ta bir MBR'yi mount etmek için öncelikle başlangıç offset'ini almanız gerekir (`fdisk` ve `p` komutunu kullanabilirsiniz).

![Partitions - MBR (master Boot Record): Linux'ta bir MBR'yi mount etmek için öncelikle başlangıç offset'ini almanız gerekir (fdisk ve p komutunu kullanabilirsiniz)](<../../../images/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

Ardından aşağıdaki code'u kullanın
```bash
#Mount MBR in Linux
mount -o ro,loop,offset=<Bytes>
#63x512 = 32256Bytes
mount -o ro,loop,offset=32256,noatime /path/to/image.dd /media/part/
```
**LBA (Logical block addressing)**

**Logical block addressing** (**LBA**), bilgisayar depolama aygıtlarında, genellikle hard disk sürücüleri gibi ikincil depolama sistemlerinde saklanan **veri bloklarının konumunu belirtmek** için kullanılan yaygın bir şemadır. LBA özellikle basit bir doğrusal adresleme şemasıdır; **bloklar bir tamsayı indeksiyle konumlandırılır**; ilk blok LBA 0, ikinci blok LBA 1 olarak devam eder.

### GPT (GUID Partition Table)

GUID Partition Table olarak bilinen GPT, MBR'a (Master Boot Record) kıyasla gelişmiş yetenekleri nedeniyle tercih edilir. **Partition'lar için global olarak benzersiz bir identifier** kullanmasıyla öne çıkan GPT'nin çeşitli özellikleri vardır:

- **Konum ve Boyut**: Hem GPT hem de MBR **sector 0**'dan başlar. Ancak GPT, MBR'ın 32bit'inin aksine **64bit** kullanır.
- **Partition Sınırları**: GPT, Windows sistemlerinde **128 partition'a** kadar destek sunar ve **9.4ZB** veriye kadar kapasite sağlar.
- **Partition İsimleri**: Partition'lara 36 Unicode karaktere kadar isim verme olanağı sunar.

**Veri Dayanıklılığı ve Kurtarma**:

- **Redundancy**: MBR'ın aksine GPT, partition ve boot verilerini tek bir konumla sınırlandırmaz. Bu verileri disk genelinde çoğaltarak veri bütünlüğünü ve dayanıklılığını artırır.
- **Cyclic Redundancy Check (CRC)**: GPT, veri bütünlüğünü sağlamak için CRC kullanır. Veri bozulmasını aktif olarak izler ve bozulma tespit edildiğinde GPT, bozulmuş veriyi diskin başka bir konumundan kurtarmaya çalışır.

**Protective MBR (LBA0)**:

- GPT, protective MBR aracılığıyla geriye dönük uyumluluğu korur. Bu özellik legacy MBR alanında bulunur ancak eski MBR tabanlı utility'lerin GPT disklerini yanlışlıkla üzerine yazmasını önlemek üzere tasarlanmıştır; böylece GPT formatlı disklerdeki veri bütünlüğünü korur.

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID_Partition_Table_Scheme.svg/800px-GUID_Partition_Table_Scheme.svg.png](<../../../images/image (1062).png>)

**Hybrid MBR (LBA 0 + GPT)**

[From Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)<sup>[[1]](#references)</sup>

**EFI** yerine **BIOS** servisleri üzerinden **GPT tabanlı boot** destekleyen işletim sistemlerinde, ilk sector hâlâ **bootloader** kodunun ilk aşamasını depolamak için kullanılabilir; ancak **GPT** **partition'larını** tanıyacak şekilde **modified** edilmiştir. MBR içindeki bootloader, sector boyutunun 512 byte olduğunu varsaymamalıdır.

**Partition table header (LBA 1)**

[From Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)<sup>[[1]](#references)</sup>

Partition table header, disk üzerindeki kullanılabilir blokları tanımlar. Ayrıca partition table'ı oluşturan partition entry'lerinin sayısını ve boyutunu da tanımlar (table'daki 80 ve 84 offset'leri).

| Offset    | Length   | Contents                                                                                                                                                                     |
| --------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)  | 8 bytes  | Signature ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h veya little-endian makinelerde 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID_Partition_Table#_note-8)) |
| 8 (0x08)  | 4 bytes  | UEFI 2.8 için Revision 1.0 (00h 00h 01h 00h)                                                                                                                                  |
| 12 (0x0C) | 4 bytes  | Header size in little endian (byte cinsinden, genellikle 5Ch 00h 00h 00h veya 92 byte)                                                                                                 |
| 16 (0x10) | 4 bytes  | Header'ın [CRC32](https://en.wikipedia.org/wiki/CRC32) değeri (offset +0'dan header size'a kadar), hesaplama sırasında bu field sıfırlanmış olarak little endian biçiminde                             |
| 20 (0x14) | 4 bytes  | Reserved; sıfır olmalıdır                                                                                                                                                       |
| 24 (0x18) | 8 bytes  | Current LBA (bu header kopyasının konumu)                                                                                                                                   |
| 32 (0x20) | 8 bytes  | Backup LBA (diğer header kopyasının konumu)                                                                                                                               |
| 40 (0x28) | 8 bytes  | Partition'lar için kullanılabilir ilk LBA (primary partition table'ın son LBA'sı + 1)                                                                                                       |
| 48 (0x30) | 8 bytes  | Kullanılabilir son LBA (secondary partition table'ın ilk LBA'sı − 1)                                                                                                                    |
| 56 (0x38) | 16 bytes | Mixed endian biçiminde disk GUID'i                                                                                                                                                    |
| 72 (0x48) | 8 bytes  | Bir partition entry dizisinin başlangıç LBA'sı (primary copy'de her zaman 2)                                                                                                     |
| 80 (0x50) | 4 bytes  | Dizideki partition entry sayısı                                                                                                                                         |
| 84 (0x54) | 4 bytes  | Tek bir partition entry'nin boyutu (genellikle 80h veya 128)                                                                                                                        |
| 88 (0x58) | 4 bytes  | Partition entry dizisinin little endian biçimindeki CRC32 değeri                                                                                                                            |
| 92 (0x5C) | \*       | Reserved; bloğun geri kalanı sıfırlardan oluşmalıdır (512 byte sector size için 420 byte; daha büyük sector size değerlerinde daha fazla olabilir)                                      |

**Partition entries (LBA 2–33)**

| GUID partition entry format |          |                                                                                                               |
| --------------------------- | -------- | ------------------------------------------------------------------------------------------------------------- |
| Offset                      | Length   | Contents                                                                                                      |
| 0 (0x00)                    | 16 bytes | [Partition type GUID](https://en.wikipedia.org/wiki/GUID_Partition_Table#Partition_type_GUIDs) (mixed endian) |
| 16 (0x10)                   | 16 bytes | Unique partition GUID (mixed endian)                                                                          |
| 32 (0x20)                   | 8 bytes  | First LBA ([little endian](https://en.wikipedia.org/wiki/Little_endian))                                      |
| 40 (0x28)                   | 8 bytes  | Last LBA (inclusive, usually odd)                                                                             |
| 48 (0x30)                   | 8 bytes  | Attribute flags (ör. bit 60 read-only olduğunu belirtir)                                                               |
| 56 (0x38)                   | 72 bytes | Partition name (36 [UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE code units)                               |

**Partitions Types**

![MBR (master Boot Record) - GPT (GUID Partition Table): 56 (0x38) | 72 bytes | Partition name (36 UTF-16LE code units)](<../../../images/image (83).png>)

Daha fazla partition type için [https://en.wikipedia.org/wiki/GUID_Partition_Table](https://en.wikipedia.org/wiki/GUID_Partition_Table)<sup>[[1]](#references)</sup>

### Inspecting

Forensics image'ı [**ArsenalImageMounter**](https://arsenalrecon.com/downloads/) ile mount ettikten sonra, ilk sector'ü Windows tool'u [**Active Disk Editor**](https://www.disk-editor.org/index.html)**.** kullanarak inceleyebilirsiniz. Aşağıdaki görüntüde **MBR**, **sector 0** üzerinde tespit edilmiş ve yorumlanmıştır:

![GPT (GUID Partition Table) - Inspecting: After mounting the forensics image with ArsenalImageMounter , you can inspect the first sector using the Windows tool Active Disk Editor . In the...](<../../../images/image (354).png>)

Eğer bu bir MBR yerine **GPT table** olsaydı, **sector 1** içinde _EFI PART_ signature'ı görünmeliydi (önceki görüntüde bu sector boştur).

## File-Systems

### Windows file-systems list

- **FAT12/16**: MSDOS, WIN95/98/NT/200
- **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
- **ExFAT**: 2008/2012/2016/VISTA/7/8/10
- **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
- **ReFS**: 2012/2016

### FAT

**FAT (File Allocation Table)** file system'i, volume'un başlangıcında konumlandırılan temel bileşeni file allocation table etrafında tasarlanmıştır. Bu system, table'ın **iki kopyasını** tutarak veriyi korur ve kopyalardan biri bozulsa bile veri bütünlüğünü sağlar. Table ve root folder, system'in startup süreci için kritik olduğundan **sabit bir konumda** bulunmalıdır.

File system'in temel storage birimi, birden fazla sector'den oluşan **cluster, genellikle 512B**'dır. FAT farklı version'lar üzerinden gelişmiştir:

- **FAT12**, 12-bit cluster address'lerini destekler ve 4078 cluster'a kadar (UNIX ile 4084) işlem yapar.
- **FAT16**, 16-bit address'lere geçerek 65.517 cluster'a kadar destek sunar.
- **FAT32**, 32-bit address'lerle daha da gelişmiş olup volume başına 268.435.456 cluster'a kadar izin verir.

FAT version'ları genelindeki önemli bir sınırlama, file size depolamak için kullanılan 32-bit field nedeniyle **4GB maksimum file size** sınırıdır.

Özellikle FAT12 ve FAT16 için root directory'nin temel bileşenleri şunlardır:

- **File/Folder Name** (8 karaktere kadar)
- **Attributes**
- **Creation, Modification, and Last Access Dates**
- **FAT Table Address** (file'ın başlangıç cluster'ını belirtir)
- **File Size**

### EXT

**Ext2**, **journaling kullanmayan** partition'lar (**çok fazla değişmeyen partition'lar**), örneğin boot partition için en yaygın file system'dir. **Ext3/4** **journaling** kullanır ve genellikle **diğer partition'lar** için kullanılır.

## **Metadata**

Bazı file'lar metadata içerir. Bu bilgi file'ın içeriği hakkındadır ve file type'a bağlı olarak analyst için ilginç olabilir. Örneğin şu bilgileri içerebilir:

- Title
- Kullanılan MS Office Version
- Author
- Creation ve last modification tarihleri
- Camera model'i
- GPS coordinates
- Image information

Bir file'ın metadata'sını almak için [**exiftool**](https://exiftool.org) ve [**Metadiver**](https://www.easymetadata.com/metadiver-2/) gibi tool'ları kullanabilirsiniz.

## **Deleted Files Recovery**

### Logged Deleted Files

Daha önce görüldüğü üzere, file "deleted" olduktan sonra hâlâ kaydedilmiş olduğu çeşitli konumlar vardır. Bunun nedeni, bir file'ın file system'den silinmesinin genellikle yalnızca onu deleted olarak işaretlemesi, veriye dokunulmamasıdır. Ardından file'ların registry'lerini (MFT gibi) incelemek ve deleted file'ları bulmak mümkündür.<sup>[[2]](#references)</sup>

Ayrıca OS genellikle file system değişiklikleri ve backup'lar hakkında çok fazla bilgi kaydeder; bu nedenle file'ı veya mümkün olduğunca fazla bilgiyi kurtarmak için bunları kullanmayı deneyebilirsiniz.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### **File Carving**

**File carving**, **veri yığını içinde file'ları bulmaya** çalışan bir tekniktir. Bu tür tool'ların çalışma şeklinin 3 temel yolu vardır: **File type header ve footer'larına dayalı**, file type **structure'larına dayalı** ve doğrudan **içeriğe** dayalı.

Bu tekniğin **fragmented file'ları kurtarmada çalışmadığını** unutmayın. Bir file **contiguous sector'lerde saklanmıyorsa**, bu teknik onu veya en azından bir parçasını bulamaz.

File carving için, aramak istediğiniz file type'ları belirterek kullanabileceğiniz çeşitli tool'lar vardır.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Data Stream **C**arving

Data Stream Carving, File Carving'e benzer; ancak **complete file'lar yerine ilgi çekici bilgi fragment'larını arar**.\
Örneğin, logged URL'leri içeren complete bir file aramak yerine bu teknik URL'leri arar.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Secure Deletion

Açıkça, file'ları ve bunlar hakkındaki log'ların bir kısmını **"securely" silmenin** yolları vardır. Örneğin bir file'ın içeriğini junk data ile birkaç kez **overwrite** etmek, ardından file hakkındaki **$MFT** ve **$LOGFILE** içindeki **log'ları** **remove** etmek ve **Volume Shadow Copies**'leri **remove** etmek mümkündür.<sup>[[3]](#references)</sup>\
Bu işlemi gerçekleştirdikten sonra bile file'ın varlığının hâlâ log'landığı **başka bölümler** olabileceğini fark edebilirsiniz; bu doğrudur ve forensics professional'ın görevinin bir parçası da bunları bulmaktır.

## References

- [1] [GUID Partition Table - Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)
- [2] [How to scan NTFS $I30 (directory) entries for evidence of deleted files](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
- [3] [Volume Shadow Copy Service (VSS)](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)

{{#include ../../../banners/hacktricks-training.md}}
