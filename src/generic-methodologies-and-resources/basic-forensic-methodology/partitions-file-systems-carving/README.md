# Bölümler/Dosya Sistemleri/Carving

{{#include ../../../banners/hacktricks-training.md}}

## Bölümler

Bir hard drive veya **SSD disk, verileri fiziksel olarak ayırmak amacıyla farklı bölümler içerebilir**.\
Bir diskin **minimum** birimi **sektördür** (normalde 512B'den oluşur). Bu nedenle her bölümün boyutu bu boyutun katı olmalıdır.

### MBR (master Boot Record)

**446B'lik boot code'dan sonra diskin ilk sektöründe** ayrılır. Bu sektör, PC'ye bir bölümün neyi ve nereden mount etmesi gerektiğini belirtmek için gereklidir.\
En fazla **4 bölüme** izin verir (en fazla **yalnızca 1** bölüm active/**bootable** olabilir). Ancak daha fazla bölüme ihtiyacınız varsa **extended partitions** kullanabilirsiniz. Bu ilk sektörün **son byte'ı**, boot record imzası olan **0x55AA**'dır. Yalnızca bir bölüm active olarak işaretlenebilir.\
MBR, **en fazla 2.2TB** destekler.

![Bölümler - MBR (master Boot Record): MBR en fazla 2.2TB destekler](<../../../images/image (350).png>)

![Bölümler - MBR (master Boot Record): MBR en fazla 2.2TB destekler](<../../../images/image (304).png>)

MBR'nin **440 ile 443 arasındaki byte'larında**, (Windows kullanılıyorsa) **Windows Disk Signature** bulunabilir. Hard disk'in logical drive letter'ı Windows Disk Signature'a bağlıdır. Bu signature'ı değiştirmek Windows'un boot etmesini engelleyebilir (tool: [**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**.

![Bölümler - MBR (master Boot Record): MBR'nin 440 ile 443 arasındaki byte'larında, (Windows kullanılıyorsa) Windows Disk Signature bulunabilir. Hard disk'in logical drive letter'ı...](<../../../images/image (310).png>)

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

![Bölümler - MBR (master Boot Record): Linux'ta bir MBR'yi mount etmek için öncelikle başlangıç offset'ini almanız gerekir (fdisk ve p komutunu kullanabilirsiniz)](<../../../images/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

Ardından aşağıdaki code'u kullanın
```bash
#Mount MBR in Linux
mount -o ro,loop,offset=<Bytes>
#63x512 = 32256Bytes
mount -o ro,loop,offset=32256,noatime /path/to/image.dd /media/part/
```
**LBA (Logical block addressing)**

**Logical block addressing** (**LBA**), bilgisayar depolama cihazlarında, genellikle hard disk sürücüleri gibi ikincil depolama sistemlerinde depolanan veri **bloklarının konumunu belirtmek** için kullanılan yaygın bir şemadır. LBA özellikle basit bir doğrusal adresleme şemasıdır; **bloklar bir tamsayı indeksiyle konumlandırılır**; ilk blok LBA 0, ikinci blok LBA 1 olarak devam eder.

### GPT (GUID Partition Table)

GUID Partition Table, GPT olarak bilinir ve MBR'ye (Master Boot Record) kıyasla gelişmiş yetenekleri nedeniyle tercih edilir. Bölümler için **global olarak benzersiz bir tanımlayıcı** kullanmasıyla öne çıkan GPT'nin çeşitli özellikleri vardır:

- **Konum ve Boyut**: Hem GPT hem de MBR **sektör 0**'dan başlar. Ancak GPT, MBR'nin 32bit yapısının aksine **64bit** ile çalışır.
- **Bölüm Sınırları**: GPT, Windows sistemlerinde en fazla **128 bölüm** destekler ve **9.4ZB**'a kadar veri barındırabilir.
- **Bölüm Adları**: Bölümlere en fazla 36 Unicode karakteriyle ad verme olanağı sunar.

**Veri Dayanıklılığı ve Kurtarma**:

- **Yedeklilik**: MBR'nin aksine GPT, bölümleme ve boot verilerini tek bir konumla sınırlandırmaz. Bu verileri disk genelinde çoğaltarak veri bütünlüğünü ve dayanıklılığını artırır.
- **Cyclic Redundancy Check (CRC)**: GPT, veri bütünlüğünü sağlamak için CRC kullanır. Veri bozulmalarını aktif olarak izler ve bozulma tespit edildiğinde GPT, bozulmuş verileri diskin başka bir konumundan kurtarmaya çalışır.

**Protective MBR (LBA0)**:

- GPT, protective MBR aracılığıyla geriye dönük uyumluluğu korur. Bu özellik eski MBR alanında bulunur, ancak eski MBR tabanlı yardımcı programların GPT disklerinin üzerine yanlışlıkla yazmasını önlemek ve böylece GPT ile biçimlendirilmiş disklerdeki veri bütünlüğünü korumak üzere tasarlanmıştır.

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID_Partition_Table_Scheme.svg/800px-GUID_Partition_Table_Scheme.svg.png](<../../../images/image (1062).png>)

**Hybrid MBR (LBA 0 + GPT)**

[Wikipedia'dan](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

EFI yerine **BIOS** hizmetleri üzerinden **GPT tabanlı boot** destekleyen işletim sistemlerinde, ilk sektör **bootloader** kodunun ilk aşamasını depolamak için hâlâ kullanılabilir; ancak **GPT** **bölümlerini** tanıyacak şekilde **değiştirilmiştir**. MBR'deki bootloader, sektör boyutunun 512 byte olduğunu varsaymamalıdır.

**Partition table header (LBA 1)**

[Wikipedia'dan](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

Partition table header, diskteki kullanılabilir blokları tanımlar. Ayrıca partition table'ı oluşturan partition entry'lerinin sayısını ve boyutunu da tanımlar (tablodaki 80 ve 84 offset'leri).

| Offset    | Length   | İçerik                                                                                                                                                                     |
| --------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)  | 8 bytes  | İmza ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h veya little-endian makinelerde 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID_Partition_Table#cite_note-8)) |
| 8 (0x08)  | 4 bytes  | UEFI 2.8 için Revision 1.0 (00h 00h 01h 00h)                                                                                                                                  |
| 12 (0x0C) | 4 bytes  | little endian biçiminde header boyutu (byte cinsinden; genellikle 5Ch 00h 00h 00h veya 92 byte)                                                                                                 |
| 16 (0x10) | 4 bytes  | little endian biçiminde header'ın CRC32'si (offset +0'dan header boyutuna kadar); hesaplama sırasında bu alan sıfırlanır                             |
| 20 (0x14) | 4 bytes  | Ayrılmış; sıfır olmalıdır                                                                                                                                                       |
| 24 (0x18) | 8 bytes  | Mevcut LBA (bu header kopyasının konumu)                                                                                                                                   |
| 32 (0x20) | 8 bytes  | Backup LBA (diğer header kopyasının konumu)                                                                                                                               |
| 40 (0x28) | 8 bytes  | Bölümler için ilk kullanılabilir LBA (primary partition table son LBA + 1)                                                                                                       |
| 48 (0x30) | 8 bytes  | Son kullanılabilir LBA (secondary partition table ilk LBA − 1)                                                                                                                    |
| 56 (0x38) | 16 bytes | Mixed endian biçiminde disk GUID                                                                                                                                                    |
| 72 (0x48) | 8 bytes  | Partition entry dizisinin başlangıç LBA'sı (primary kopyada her zaman 2)                                                                                                     |
| 80 (0x50) | 4 bytes  | Dizideki partition entry sayısı                                                                                                                                         |
| 84 (0x54) | 4 bytes  | Tek bir partition entry'nin boyutu (genellikle 80h veya 128)                                                                                                                        |
| 88 (0x58) | 4 bytes  | little endian biçiminde partition entry dizisinin CRC32'si                                                                                                                            |
| 92 (0x5C) | \*       | Ayrılmış; bloğun geri kalanı sıfır olmalıdır (512 byte sektör boyutu için 420 byte; daha büyük sektör boyutlarında daha fazla olabilir)                                      |

**Partition entries (LBA 2–33)**

| GUID partition entry format |          |                                                                                                               |
| --------------------------- | -------- | ------------------------------------------------------------------------------------------------------------- |
| Offset                      | Length   | İçerik                                                                                                      |
| 0 (0x00)                    | 16 bytes | [Partition type GUID](https://en.wikipedia.org/wiki/GUID_Partition_Table#Partition_type_GUIDs) (mixed endian) |
| 16 (0x10)                   | 16 bytes | Benzersiz partition GUID (mixed endian)                                                                          |
| 32 (0x20)                   | 8 bytes  | İlk LBA ([little endian](https://en.wikipedia.org/wiki/Little_endian))                                      |
| 40 (0x28)                   | 8 bytes  | Son LBA (dahil, genellikle tek)                                                                             |
| 48 (0x30)                   | 8 bytes  | Attribute flags (ör. bit 60 salt okunur olduğunu belirtir)                                                               |
| 56 (0x38)                   | 72 bytes | Partition adı (36 [UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE code units)                               |

**Partitions Types**

![MBR (master Boot Record) - GPT (GUID Partition Table): 56 (0x38) | 72 bytes | Partition name (36 UTF-16LE code units)](<../../../images/image (83).png>)

Daha fazla partition type için [https://en.wikipedia.org/wiki/GUID_Partition_Table](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

### İnceleme

Forensics image'ını [**ArsenalImageMounter**](https://arsenalrecon.com/downloads/) ile mount ettikten sonra, ilk sektörü Windows aracı [**Active Disk Editor**](https://www.disk-editor.org/index.html)**.** ile inceleyebilirsiniz. Aşağıdaki görselde **sektör 0** üzerinde bir **MBR** tespit edilmiş ve yorumlanmıştır:

![GPT (GUID Partition Table) - İnceleme: Forensics image'ını ArsenalImageMounter ile mount ettikten sonra, ilk sektörü Windows aracı Active Disk Editor ile inceleyebilirsiniz. Görselde...](<../../../images/image (354).png>)

Eğer bir **MBR** yerine **GPT table** olsaydı, önceki görselde boş olan **sektör 1** üzerinde _EFI PART_ imzası görünmeliydi.

## Dosya Sistemleri

### Windows dosya sistemleri listesi

- **FAT12/16**: MSDOS, WIN95/98/NT/200
- **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
- **ExFAT**: 2008/2012/2016/VISTA/7/8/10
- **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
- **ReFS**: 2012/2016

### FAT

**FAT (File Allocation Table)** file system, volume'un başlangıcında bulunan temel bileşeni file allocation table etrafında tasarlanmıştır. Bu sistem, tablonun **iki kopyasını** tutarak verileri korur ve kopyalardan biri bozulsa bile veri bütünlüğünü sağlar. Table ve root folder, sistemin startup süreci açısından kritik olduğundan **sabit bir konumda** bulunmalıdır.

File system'ın temel depolama birimi, birden fazla sektörden oluşan ve **genellikle 512B** boyutundaki bir **cluster**'dır. FAT, farklı sürümlerle geliştirilmiştir:

- **FAT12**, 12-bit cluster address destekler ve 4078 cluster'a (UNIX ile 4084) kadar işlem yapar.
- **FAT16**, 16-bit address kullanarak kapasiteyi artırır ve 65.517 cluster'a kadar destek sağlar.
- **FAT32**, 32-bit address kullanarak daha da gelişir ve volume başına 268.435.456 cluster'a kadar izin verir.

Tüm FAT sürümlerindeki önemli bir sınırlama, file size bilgisini depolamak için kullanılan 32-bit alan nedeniyle **4GB maksimum dosya boyutudur**.

Root directory'nin, özellikle FAT12 ve FAT16 için temel bileşenleri şunlardır:

- **File/Folder Name** (en fazla 8 karakter)
- **Attributes**
- **Creation, Modification ve Last Access Dates**
- **FAT Table Address** (dosyanın başlangıç cluster'ını gösterir)
- **File Size**

### EXT

**Ext2**, boot partition gibi **journaling kullanmayan** (**çok fazla değişmeyen partition'lar**) partition'lar için en yaygın file system'dır. **Ext3/4** **journaling** kullanır ve genellikle **diğer partition'lar** için kullanılır.

## **Metadata**

Bazı dosyalar metadata içerir. Bu bilgiler dosyanın içeriğiyle ilgilidir ve dosya türüne bağlı olarak analyst için bazen ilgi çekici olabilir. Örneğin şu bilgileri içerebilir:

- Title
- Kullanılan MS Office Version
- Author
- Oluşturulma ve son değiştirilme tarihleri
- Kamera modeli
- GPS koordinatları
- Image bilgileri

Bir dosyanın metadata bilgilerini almak için [**exiftool**](https://exiftool.org) ve [**Metadiver**](https://www.easymetadata.com/metadiver-2/) gibi araçları kullanabilirsiniz.

## **Deleted Files Recovery**

### Logged Deleted Files

Daha önce görüldüğü gibi, dosya "silindikten" sonra hâlâ kayıtlı olduğu çeşitli konumlar vardır. Bunun nedeni, genellikle bir dosyanın file system'dan silinmesinin yalnızca onu silinmiş olarak işaretlemesi, ancak veriye dokunulmamasıdır. Bu nedenle dosya kayıtlarını (MFT gibi) incelemek ve silinmiş dosyaları bulmak mümkündür.<sup>[[2]](#references)</sup>

Ayrıca OS genellikle file system değişiklikleri ve backup'lar hakkında çok miktarda bilgi kaydeder; bu nedenle dosyayı veya mümkün olduğunca fazla bilgiyi kurtarmak için bunları kullanmayı deneyebilirsiniz.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### **File Carving**

**File carving**, **veri yığınının içinde dosyaları bulmaya** çalışan bir tekniktir. Bu tür araçların çalışma şekilleri 3 ana yönteme ayrılır: **file type header ve footer'larına**, file type **structure'larına** veya doğrudan **içeriğin kendisine** göre.

Bu tekniğin **fragmented dosyaları kurtarmada çalışmadığını** unutmayın. Bir dosya **contiguous sektörlerde depolanmamışsa**, bu teknik dosyanın tamamını veya en azından bir bölümünü bulamaz.

File carving için kullanabileceğiniz ve aramak istediğiniz file type'ları belirtebileceğiniz çeşitli araçlar vardır.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Data Stream **C**arving

Data Stream Carving, File Carving'e benzer; ancak **tam dosyaları aramak yerine ilgi çekici bilgi parçalarını arar**.\
Örneğin, log'lanmış URL'leri içeren eksiksiz bir dosyayı aramak yerine bu teknik URL'leri arar.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Secure Deletion

Dosyaları ve bunlarla ilgili log'ların bir bölümünü **"güvenli şekilde" silmenin** yolları vardır. Örneğin, bir dosyanın **içeriğinin üzerine** birkaç kez junk data yazmak, ardından dosyayla ilgili **$MFT** ve **$LOGFILE** kayıtlarını **silmek** ve **Volume Shadow Copies'i kaldırmak** mümkündür.<sup>[[3]](#references)</sup>\
Ancak bu işlemi gerçekleştirseniz bile dosyanın varlığının hâlâ log'landığı **başka bölümler** olabileceğini fark edebilirsiniz; bu doğrudur ve forensics uzmanının işinin bir parçası da bunları bulmaktır.

## References

- [1] [GUID Partition Table - Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)
- [2] [Silinmiş dosyaların kanıtlarını bulmak için NTFS $I30 (directory) entry'leri nasıl taranır](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
- [3] [Volume Shadow Copy Service (VSS)](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
{{#include ../../../banners/hacktricks-training.md}}
