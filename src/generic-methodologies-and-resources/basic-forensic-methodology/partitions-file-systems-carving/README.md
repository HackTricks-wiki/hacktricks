# Bölümler/Dosya Sistemleri/Carving

{{#include ../../../banners/hacktricks-training.md}}

## Bölümler

Bir sabit disk veya **SSD disk, verileri fiziksel olarak ayırmak amacıyla farklı bölümler içerebilir**.\
Bir diskin **minimum** birimi **sektördür** (normalde 512B'den oluşur). Bu nedenle her bölümün boyutu bu boyutun katı olmalıdır.

### MBR (master Boot Record)

**Önyükleme kodundan sonraki 446B'nin ardından diskin ilk sektöründe** ayrılır. Bu sektör, PC'ye bir bölümün bağlanması gerektiğini ve bunun nereden yapılacağını belirtmek için gereklidir.\
En fazla **4 bölüme** izin verir (en fazla **yalnızca 1** bölüm etkin/**önyüklenebilir** olabilir). Ancak daha fazla bölüme ihtiyacınız varsa **extended partitions** kullanabilirsiniz. Bu ilk sektörün **son baytı**, önyükleme kaydı imzası olan **0x55AA**'dır. Yalnızca bir bölüm etkin olarak işaretlenebilir.\
MBR, **en fazla 2.2TB** destekler.

![Partitions - MBR (master Boot Record): MBR allows max 2.2TB](<../../../images/image (350).png>)

![Partitions - MBR (master Boot Record): MBR allows max 2.2TB](<../../../images/image (304).png>)

MBR'nin **440 ila 443. baytları** arasında **Windows Disk Signature**'ı (Windows kullanılıyorsa) bulabilirsiniz. Sabit diskin mantıksal sürücü harfi, Windows Disk Signature'a bağlıdır. Bu imzanın değiştirilmesi Windows'un önyüklenmesini engelleyebilir (araç: [**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**.

![Partitions - MBR (master Boot Record): From the bytes 440 to the 443 of the MBR you can find the Windows Disk Signature (if Windows is used). The logical drive letter of the hard disk...](<../../../images/image (310).png>)

**Biçim**

| Offset      | Length     | Item                |
| ----------- | ---------- | ------------------- |
| 0 (0x00)    | 446(0x1BE) | Önyükleme kodu      |
| 446 (0x1BE) | 16 (0x10)  | Birinci bölüm       |
| 462 (0x1CE) | 16 (0x10)  | İkinci bölüm        |
| 478 (0x1DE) | 16 (0x10)  | Üçüncü bölüm        |
| 494 (0x1EE) | 16 (0x10)  | Dördüncü bölüm      |
| 510 (0x1FE) | 2 (0x2)    | İmza 0x55 0xAA      |

**Bölüm Kaydı Biçimi**

| Offset    | Length   | Item                                                   |
| --------- | -------- | ------------------------------------------------------ |
| 0 (0x00)  | 1 (0x01) | Etkin bayrağı (0x80 = önyüklenebilir)                  |
| 1 (0x01)  | 1 (0x01) | Başlangıç head'i                                       |
| 2 (0x02)  | 1 (0x01) | Başlangıç sektörü (bit 0-5); silindirin üst bitleri (6- 7) |
| 3 (0x03)  | 1 (0x01) | Başlangıç silindirinin en düşük 8 biti                  |
| 4 (0x04)  | 1 (0x01) | Bölüm türü kodu (0x83 = Linux)                         |
| 5 (0x05)  | 1 (0x01) | Bitiş head'i                                            |
| 6 (0x06)  | 1 (0x01) | Bitiş sektörü (bit 0-5); silindirin üst bitleri (6- 7) |
| 7 (0x07)  | 1 (0x01) | Bitiş silindirinin en düşük 8 biti                      |
| 8 (0x08)  | 4 (0x04) | Bölümden önceki sektörler (little endian)              |
| 12 (0x0C) | 4 (0x04) | Bölümdeki sektörler                                    |

Linux'ta bir MBR'yi bağlamak için önce başlangıç offset'ini almanız gerekir (`fdisk` ve `p` komutunu kullanabilirsiniz).

![Partitions - MBR (master Boot Record): In order to mount an MBR in Linux you first need to get the start offset (you can use fdisk and the p command)](<../../../images/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

Ardından aşağıdaki kodu kullanın
```bash
#Mount MBR in Linux
mount -o ro,loop,offset=<Bytes>
#63x512 = 32256Bytes
mount -o ro,loop,offset=32256,noatime /path/to/image.dd /media/part/
```
**LBA (Logical block addressing)**

**Logical block addressing** (**LBA**), bilgisayar depolama cihazlarında, genellikle hard disk drives gibi ikincil depolama sistemlerinde saklanan **veri bloklarının konumunu belirtmek** için kullanılan yaygın bir şemadır. LBA özellikle basit bir doğrusal adresleme şemasıdır; **bloklar bir tamsayı indeksiyle konumlandırılır**; ilk blok LBA 0, ikinci blok LBA 1 olarak devam eder.

### GPT (GUID Partition Table)

GUID Partition Table olarak bilinen GPT, MBR'ye (Master Boot Record) kıyasla gelişmiş yetenekleri nedeniyle tercih edilir. Bölümler için **global olarak benzersiz bir tanımlayıcıya** sahip olmasıyla öne çıkan GPT'nin çeşitli özellikleri vardır:

- **Konum ve Boyut**: Hem GPT hem de MBR **sector 0**'dan başlar. Ancak GPT, MBR'nin 32bit'inin aksine **64bit** kullanır.
- **Bölüm Sınırları**: GPT, Windows sistemlerinde en fazla **128 partition** destekler ve **9.4ZB**'a kadar veriyi barındırabilir.
- **Bölüm Adları**: 36 Unicode karaktere kadar bölüm adlandırma olanağı sunar.

**Veri Dayanıklılığı ve Kurtarma**:

- **Redundancy**: MBR'nin aksine GPT, partitioning ve boot verilerini tek bir konumla sınırlamaz. Bu verileri disk genelinde çoğaltarak veri bütünlüğünü ve dayanıklılığını artırır.
- **Cyclic Redundancy Check (CRC)**: GPT, veri bütünlüğünü sağlamak için CRC kullanır. Veri bozulmasını aktif olarak izler ve bozulma tespit edildiğinde GPT, bozulmuş veriyi diskin başka bir konumundan kurtarmaya çalışır.

**Protective MBR (LBA0)**:

- GPT, protective MBR aracılığıyla geriye dönük uyumluluğu korur. Bu özellik eski MBR alanında bulunur, ancak eski MBR tabanlı araçların GPT disklerinin üzerine yanlışlıkla yazmasını önleyecek şekilde tasarlanmıştır; böylece GPT formatlı disklerdeki veri bütünlüğü korunur.

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID_Partition_Table_Scheme.svg/800px-GUID_Partition_Table_Scheme.svg.png](<../../../images/image (1062).png>)

**Hybrid MBR (LBA 0 + GPT)**

[Wikipedia'dan](https://en.wikipedia.org/wiki/GUID_Partition_Table)<sup>[[1]](#references)</sup>

**EFI** yerine **BIOS** servisleri üzerinden **GPT-based boot** destekleyen işletim sistemlerinde, ilk sector **bootloader** kodunun ilk aşamasını depolamak için hâlâ kullanılabilir; ancak **GPT** **partitions**'larını tanıyacak şekilde **modified** edilmiştir. MBR'deki bootloader, sector boyutunun 512 byte olduğunu varsaymamalıdır.

**Partition table header (LBA 1)**

[Wikipedia'dan](https://en.wikipedia.org/wiki/GUID_Partition_Table)<sup>[[1]](#references)</sup>

Partition table header, disk üzerindeki kullanılabilir blokları tanımlar. Ayrıca partition table'ı oluşturan partition entry'lerinin sayısını ve boyutunu da tanımlar (tablodaki 80 ve 84 offset'leri).

| Offset    | Length   | Contents                                                                                                                                                                     |
| --------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)  | 8 bytes  | Signature ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h veya little-endian makinelerde 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID_Partition_Table#_note-8)) |
| 8 (0x08)  | 4 bytes  | UEFI 2.8 için Revision 1.0 (00h 00h 01h 00h)                                                                                                                                  |
| 12 (0x0C) | 4 bytes  | little endian formatında header size (byte cinsinden; genellikle 5Ch 00h 00h 00h veya 92 byte)                                                                                 |
| 16 (0x10) | 4 bytes  | little endian formatında header'ın [CRC32](https://en.wikipedia.org/wiki/CRC32) değeri (offset +0'dan header size'a kadar); hesaplama sırasında bu field sıfırlanır              |
| 20 (0x14) | 4 bytes  | Reserved; sıfır olmalıdır                                                                                                                                                       |
| 24 (0x18) | 8 bytes  | Current LBA (bu header kopyasının konumu)                                                                                                                                   |
| 32 (0x20) | 8 bytes  | Backup LBA (diğer header kopyasının konumu)                                                                                                                               |
| 40 (0x28) | 8 bytes  | Partitions için first usable LBA (primary partition table last LBA + 1)                                                                                                       |
| 48 (0x30) | 8 bytes  | Last usable LBA (secondary partition table first LBA − 1)                                                                                                                    |
| 56 (0x38) | 16 bytes | Mixed endian formatında disk GUID'i                                                                                                                                                    |
| 72 (0x48) | 8 bytes  | Bir partition entry dizisinin starting LBA'sı (primary copy'de her zaman 2)                                                                                                     |
| 80 (0x50) | 4 bytes  | Dizideki partition entry sayısı                                                                                                                                         |
| 84 (0x54) | 4 bytes  | Tek bir partition entry'nin size'ı (genellikle 80h veya 128)                                                                                                                        |
| 88 (0x58) | 4 bytes  | little endian formatında partition entry dizisinin CRC32 değeri                                                                                                                            |
| 92 (0x5C) | \*       | Reserved; bloğun geri kalanı zeroes olmalıdır (512 byte sector size için 420 byte; daha büyük sector size değerlerinde daha fazla olabilir)                                      |

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

Daha fazla partition type için: [https://en.wikipedia.org/wiki/GUID_Partition_Table](https://en.wikipedia.org/wiki/GUID_Partition_Table)

### Inspecting

Forensics image'ı [**ArsenalImageMounter**](https://arsenalrecon.com/downloads/) ile mount ettikten sonra ilk sector'ü Windows aracı [**Active Disk Editor**](https://www.disk-editor.org/index.html)**.** ile inceleyebilirsiniz. Aşağıdaki görselde **MBR**, **sector 0** üzerinde tespit edilmiş ve yorumlanmıştır:

![GPT (GUID Partition Table) - Inspecting: Forensics image'ı ArsenalImageMounter ile mount ettikten sonra ilk sector'ü Windows aracı Active Disk Editor ile inceleyebilirsiniz. Görselde...](<../../../images/image (354).png>)

Eğer bir **MBR** yerine **GPT table** varsa, önceki görselde boş olan **sector 1** üzerinde _EFI PART_ signature'ı görünmelidir.

## File-Systems

### Windows file-systems listesi

- **FAT12/16**: MSDOS, WIN95/98/NT/200
- **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
- **ExFAT**: 2008/2012/2016/VISTA/7/8/10
- **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
- **ReFS**: 2012/2016

### FAT

**FAT (File Allocation Table)** file system, volume'un başlangıcında bulunan temel bileşeni file allocation table etrafında tasarlanmıştır. Bu system, tablonun **iki kopyasını** tutarak veriyi korur ve kopyalardan biri bozulsa bile veri bütünlüğünü sağlar. Table ve root folder, system'in startup süreci için kritik olan **sabit bir konumda** bulunmalıdır.

File system'in temel storage birimi, birden fazla sector'den oluşan **cluster, genellikle 512B**'dir. FAT, çeşitli version'lar üzerinden gelişmiştir:

- **FAT12**, 12-bit cluster address'lerini destekler ve 4078 cluster'a kadar (UNIX ile 4084) işlem yapar.
- **FAT16**, 16-bit address'lere geçerek 65.517 cluster'a kadar destek sağlar.
- **FAT32**, 32-bit address'lerle daha da gelişmiş ve volume başına etkileyici bir şekilde 268.435.456 cluster'a izin verir.

FAT version'larının tümündeki önemli bir sınırlama, file size'ı saklamak için kullanılan 32-bit field nedeniyle **4GB maksimum file size** sınırıdır.

Root directory'nin, özellikle FAT12 ve FAT16 için temel bileşenleri şunlardır:

- **File/Folder Name** (en fazla 8 karakter)
- **Attributes**
- **Creation, Modification ve Last Access Dates**
- **FAT Table Address** (file'ın başlangıç cluster'ını gösterir)
- **File Size**

### EXT

**Ext2**, boot partition gibi **journaling yapmayan** (**çok fazla değişmeyen partition'lar**) partition'lar için en yaygın file system'dir. **Ext3/4** **journaling** kullanır ve genellikle **diğer partition'lar** için tercih edilir.

## **Metadata**

Bazı file'lar metadata içerir. Bu bilgiler file'ın içeriğiyle ilgilidir ve file type'a bağlı olarak analyst için ilgi çekici olabilir. Örneğin şu bilgileri içerebilir:

- Title
- Kullanılan MS Office Version
- Author
- Creation ve last modification tarihleri
- Camera model'i
- GPS coordinates
- Image bilgileri

Bir file'ın metadata'sını almak için [**exiftool**](https://exiftool.org) ve [**Metadiver**](https://www.easymetadata.com/metadiver-2/) gibi araçları kullanabilirsiniz.

## **Deleted Files Recovery**

### Logged Deleted Files

Daha önce görüldüğü gibi file, "deleted" edildikten sonra hâlâ kayıtlı kaldığı birkaç yer vardır. Bunun nedeni, file system'den bir file'ın silinmesinin genellikle yalnızca onu deleted olarak işaretlemesi, ancak veriye dokunmamasıdır. Bu nedenle file registry'lerini (MFT gibi) incelemek ve deleted file'ları bulmak mümkündür.<sup>[[2]](#references)</sup>

Ayrıca OS genellikle file system değişiklikleri ve backup'lar hakkında çok miktarda bilgi kaydeder. Bu nedenle file'ı veya mümkün olduğunca fazla bilgiyi kurtarmak için bunları kullanmayı deneyebilirsiniz.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### **File Carving**

**File carving**, **veri yığınının içinde file bulmaya** çalışan bir tekniktir. Bu tür araçların çalışma şekilleri 3 ana yönteme ayrılır: **File type header ve footer'larına dayalı**, file type **structure'larına dayalı** ve doğrudan **content'e** dayalı.

Bu tekniğin **fragmented file'ları kurtarmak için çalışmadığını** unutmayın. Bir file **contiguous sector'lerde saklanmıyorsa**, bu teknik file'ın tamamını veya en azından bir bölümünü bulamaz.

File carving için, aranacak file type'ları belirterek kullanabileceğiniz çeşitli araçlar vardır.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Data Stream **C**arving

Data Stream Carving, File Carving'e benzer; ancak **complete file'ları aramak yerine ilgi çekici bilgi parçalarını arar**.\
Örneğin logged URL'leri içeren complete bir file'ı aramak yerine bu teknik URL'leri arar.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Secure Deletion

Açıkça, file'ları ve bunlarla ilgili log'ların bir kısmını **"securely" delete** etmenin yolları vardır. Örneğin bir file'ın **content'ini** junk data ile birkaç kez **overwrite** etmek, ardından file hakkındaki **log'ları** **$MFT** ve **$LOGFILE**'dan **remove** etmek ve **Volume Shadow Copies**'leri **remove** etmek mümkündür.<sup>[[3]](#references)</sup>\
Bu işlemi gerçekleştirdikten sonra bile file'ın varlığının **hala log'landığı başka bölümler** olabileceğini fark edebilirsiniz. Bu doğrudur ve bunları bulmak forensics profesyonelinin görevinin bir parçasıdır.

## References

- [1] [GUID Partition Table - Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)
- [2] [How to scan NTFS $I30 (directory) entries for evidence of deleted files](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
- [3] [Volume Shadow Copy Service (VSS)](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)

{{#include ../../../banners/hacktricks-training.md}}
