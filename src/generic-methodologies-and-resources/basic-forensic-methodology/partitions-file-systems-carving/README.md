# Bölümler/Dosya Sistemleri/Carving

## Bölümler

Bir hard drive veya **SSD disk, verileri fiziksel olarak ayırmak** amacıyla farklı **partition**'lar içerebilir.\
Bir diskin **minimum** birimi **sector**'dür (normalde 512B'den oluşur). Bu nedenle her partition boyutunun bu boyutun katı olması gerekir.

### MBR (master Boot Record)

**Boot code**'un 446B'lik kısmından sonra, **diskin ilk sector'üne** ayrılır. Bu sector, PC'ye bir partition'ın bağlanması gerektiğini ve bunun nereden yapılacağını belirtmek için gereklidir.\
En fazla **4 partition**'a izin verir (en fazla **yalnızca 1 tanesi** active/**bootable** olabilir). Ancak daha fazla partition'a ihtiyacınız varsa **extended partition**'lar kullanabilirsiniz. Bu ilk sector'ün **son byte'ı**, boot record imzası olan **0x55AA**'dır. Yalnızca bir partition active olarak işaretlenebilir.\
MBR, **en fazla 2.2TB** destekler.

![Partitions - MBR (master Boot Record): MBR en fazla 2.2TB destekler](<../../../images/image (350).png>)

![Partitions - MBR (master Boot Record): MBR en fazla 2.2TB destekler](<../../../images/image (304).png>)

MBR'ın **440 ile 443 arasındaki byte'larında**, (Windows kullanılıyorsa) **Windows Disk Signature** bulunabilir. Hard disk'in logical drive letter'ı Windows Disk Signature'a bağlıdır. Bu signature'ı değiştirmek Windows'un boot etmesini engelleyebilir (tool: [**Active Disk Editor**](https://www.disk-editor.org/index.html)**)).

![Partitions - MBR (master Boot Record): MBR'ın 440 ile 443 arasındaki byte'larında, (Windows kullanılıyorsa) Windows Disk Signature bulunabilir. Hard disk'in logical drive letter'ı...](<../../../images/image (310).png>)

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

Linux'ta bir MBR'ı mount etmek için önce başlangıç offset'ini almanız gerekir (`fdisk` ve `p` komutunu kullanabilirsiniz).

![Partitions - MBR (master Boot Record): Linux'ta bir MBR'ı mount etmek için önce başlangıç offset'ini almanız gerekir (fdisk ve p komutunu kullanabilirsiniz)](<../../../images/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

Ardından aşağıdaki kodu kullanın
```bash
#Mount MBR in Linux
mount -o ro,loop,offset=<Bytes>
#63x512 = 32256Bytes
mount -o ro,loop,offset=32256,noatime /path/to/image.dd /media/part/
```
**LBA (Logical block addressing)**

**Logical block addressing** (**LBA**), bilgisayar depolama aygıtlarında, genellikle sabit disk sürücüleri gibi ikincil depolama sistemlerinde depolanan **veri bloklarının konumunu belirtmek** için kullanılan yaygın bir şemadır. LBA özellikle basit bir doğrusal adresleme şemasıdır; **bloklar bir tamsayı diziniyle konumlandırılır**. İlk blok LBA 0, ikinci blok LBA 1 olarak belirtilir ve bu şekilde devam eder.

### GPT (GUID Partition Table)

GPT olarak bilinen GUID Partition Table, MBR'ye (Master Boot Record) kıyasla gelişmiş özellikleri nedeniyle tercih edilir. Bölümler için **global olarak benzersiz bir tanımlayıcı** kullanmasıyla öne çıkan GPT'nin çeşitli özellikleri vardır:

- **Konum ve Boyut**: Hem GPT hem de MBR **sektör 0**'dan başlar. Ancak GPT, MBR'nin 32bit yapısının aksine **64bit** kullanır.
- **Bölüm Sınırları**: GPT, Windows sistemlerinde en fazla **128 bölüm** destekler ve **9.4ZB**'a kadar veriyi barındırabilir.
- **Bölüm Adları**: Bölümlere 36 Unicode karaktere kadar ad verme olanağı sunar.

**Veri Dayanıklılığı ve Kurtarma**:

- **Yedeklilik**: MBR'nin aksine GPT, bölümleme ve boot verilerini tek bir konumla sınırlandırmaz. Bu verileri disk genelinde çoğaltarak veri bütünlüğünü ve dayanıklılığını artırır.
- **Cyclic Redundancy Check (CRC)**: GPT, veri bütünlüğünü sağlamak için CRC kullanır. Veri bozulmalarını aktif olarak izler ve bozulma tespit edildiğinde GPT, bozulmuş veriyi diskteki başka bir konumdan kurtarmayı dener.

**Protective MBR (LBA0)**:

- GPT, protective MBR aracılığıyla geriye dönük uyumluluğu korur. Bu özellik eski MBR tabanlı araçların GPT disklerinin üzerine yanlışlıkla yazmasını önlemek üzere eski MBR alanında bulunur; böylece GPT ile biçimlendirilmiş disklerdeki veri bütünlüğünü korur.

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID_Partition_Table_Scheme.svg/800px-GUID_Partition_Table_Scheme.svg.png](<../../../images/image (1062).png>)

**Hybrid MBR (LBA 0 + GPT)**

[Wikipedia'dan](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

EFI yerine **BIOS** servisleri üzerinden **GPT tabanlı boot** desteği sunan işletim sistemlerinde ilk sektör, **bootloader** kodunun ilk aşamasını depolamak için hâlâ kullanılabilir; ancak **GPT** **bölümlerini** tanıyacak şekilde **değiştirilmiştir**. MBR'deki bootloader, sektör boyutunun 512 byte olduğunu varsaymamalıdır.

**Partition table header (LBA 1)**

[Wikipedia'dan](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

Partition table header, disk üzerindeki kullanılabilir blokları tanımlar. Ayrıca partition table'ı oluşturan partition entry'lerinin sayısını ve boyutunu da tanımlar (tablodaki 80 ve 84 numaralı offset'ler).

| Offset    | Length   | Contents                                                                                                                                                                     |
| --------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)  | 8 bytes  | Signature ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h veya little-endian makinelerde 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID_Partition_Table#_note-8)) |
| 8 (0x08)  | 4 bytes  | UEFI 2.8 için Revision 1.0 (00h 00h 01h 00h)                                                                                                                                  |
| 12 (0x0C) | 4 bytes  | Little endian biçiminde header boyutu (byte cinsinden; genellikle 5Ch 00h 00h 00h veya 92 byte)                                                                             |
| 16 (0x10) | 4 bytes  | Little endian biçiminde header'ın [CRC32](https://en.wikipedia.org/wiki/CRC32) değeri (offset +0'dan header boyutuna kadar); hesaplama sırasında bu alan sıfırlanır             |
| 20 (0x14) | 4 bytes  | Ayrılmış; sıfır olmalıdır                                                                                                                                                       |
| 24 (0x18) | 8 bytes  | Geçerli LBA (bu header kopyasının konumu)                                                                                                                                   |
| 32 (0x20) | 8 bytes  | Backup LBA (diğer header kopyasının konumu)                                                                                                                               |
| 40 (0x28) | 8 bytes  | Bölümler için ilk kullanılabilir LBA (primary partition table'ın son LBA'sı + 1)                                                                                                       |
| 48 (0x30) | 8 bytes  | Son kullanılabilir LBA (secondary partition table'ın ilk LBA'sı − 1)                                                                                                                    |
| 56 (0x38) | 16 bytes | Mixed endian biçiminde disk GUID'i                                                                                                                                                    |
| 72 (0x48) | 8 bytes  | Partition entry dizisinin başlangıç LBA'sı (primary kopyada her zaman 2)                                                                                                     |
| 80 (0x50) | 4 bytes  | Dizideki partition entry sayısı                                                                                                                                         |
| 84 (0x54) | 4 bytes  | Tek bir partition entry'nin boyutu (genellikle 80h veya 128)                                                                                                                        |
| 88 (0x58) | 4 bytes  | Little endian biçiminde partition entry dizisinin CRC32 değeri                                                                                                                            |
| 92 (0x5C) | \*       | Ayrılmış; bloğun geri kalanı sıfırlardan oluşmalıdır (512 byte sektör boyutu için 420 byte; ancak daha büyük sektör boyutlarında daha fazla olabilir)                                      |

**Partition entries (LBA 2–33)**

| GUID partition entry format |          |                                                                                                               |
| --------------------------- | -------- | ------------------------------------------------------------------------------------------------------------- |
| Offset                      | Length   | Contents                                                                                                      |
| 0 (0x00)                    | 16 bytes | [Partition type GUID](https://en.wikipedia.org/wiki/GUID_Partition_Table#Partition_type_GUIDs) (mixed endian) |
| 16 (0x10)                   | 16 bytes | Benzersiz partition GUID'i (mixed endian)                                                                          |
| 32 (0x20)                   | 8 bytes  | İlk LBA ([little endian](https://en.wikipedia.org/wiki/Little_endian))                                      |
| 40 (0x28)                   | 8 bytes  | Son LBA (dahil, genellikle tek)                                                                             |
| 48 (0x30)                   | 8 bytes  | Attribute flags (ör. bit 60 salt okunur anlamına gelir)                                                               |
| 56 (0x38)                   | 72 bytes | Partition adı (36 [UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE code unit)                               |

**Partitions Types**

![MBR (master Boot Record) - GPT (GUID Partition Table): 56 (0x38) | 72 byte | Partition adı (36 UTF-16LE code unit)](<../../../images/image (83).png>)

Daha fazla partition type için [https://en.wikipedia.org/wiki/GUID_Partition_Table](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

### İnceleme

Forensics imajını [**ArsenalImageMounter**](https://arsenalrecon.com/downloads/) ile mount ettikten sonra ilk sektörü Windows aracı [**Active Disk Editor**](https://www.disk-editor.org/index.html)**.** ile inceleyebilirsiniz. Aşağıdaki görselde **sektör 0** üzerinde bir **MBR** tespit edilmiş ve yorumlanmıştır:

![GPT (GUID Partition Table) - İnceleme: Forensics imajını ArsenalImageMounter ile mount ettikten sonra ilk sektörü Windows aracı Active Disk Editor ile inceleyebilirsiniz. Görselde...](<../../../images/image (354).png>)

Bir **MBR** yerine **GPT table** mevcutsa, önceki görselde boş olan **sektör 1** üzerinde _EFI PART_ signature'ı görünmelidir.

## File-Systems

### Windows file-systems listesi

- **FAT12/16**: MSDOS, WIN95/98/NT/200
- **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
- **ExFAT**: 2008/2012/2016/VISTA/7/8/10
- **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
- **ReFS**: 2012/2016

### FAT

**FAT (File Allocation Table)** file system, volume'un başlangıcında bulunan temel bileşeni file allocation table etrafında tasarlanmıştır. Bu sistem, tablonun **iki kopyasını** tutarak verileri korur ve kopyalardan biri bozulsa bile veri bütünlüğünü sağlar. Table ve root folder, sistemin startup süreci açısından kritik olduğundan **sabit bir konumda** bulunmalıdır.

File system'ın temel storage birimi, birden fazla sektörden oluşan ve **genellikle 512B** boyutundaki bir **cluster**'dır. FAT, çeşitli sürümlerle geliştirilmiştir:

- **FAT12**, 12-bit cluster address destekler ve en fazla 4078 cluster'ı (UNIX ile 4084) yönetir.
- **FAT16**, 16-bit address kullanarak bu kapasiteyi artırır ve en fazla 65.517 cluster barındırır.
- **FAT32**, 32-bit address kullanarak daha da gelişir ve volume başına etkileyici şekilde 268.435.456 cluster'a izin verir.

FAT sürümlerinin tümündeki önemli bir sınırlama, file size depolamak için kullanılan 32-bit alan nedeniyle **4GB maksimum dosya boyutu** sınırıdır.

Root directory'nin, özellikle FAT12 ve FAT16 için önemli bileşenleri şunlardır:

- **File/Folder Name** (en fazla 8 karakter)
- **Attributes**
- **Creation, Modification ve Last Access Dates**
- **FAT Table Address** (dosyanın başlangıç cluster'ını belirtir)
- **File Size**

### EXT

**Ext2**, boot partition gibi **journaling kullanmayan** (**çok fazla değişmeyen bölümler**) bölümler için en yaygın file system'dır. **Ext3/4** **journaling** kullanır ve genellikle **diğer bölümler** için kullanılır.

## **Metadata**

Bazı dosyalar metadata içerir. Bu bilgiler dosyanın içeriğiyle ilgilidir ve dosya türüne bağlı olarak analist için bazen ilgi çekici olabilir. Örneğin şu bilgileri içerebilir:

- Title
- Kullanılan MS Office Version
- Author
- Creation ve last modification tarihleri
- Kamera modeli
- GPS koordinatları
- Görüntü bilgileri

Bir dosyanın metadata bilgilerini almak için [**exiftool**](https://exiftool.org) ve [**Metadiver**](https://www.easymetadata.com/metadiver-2/) gibi araçları kullanabilirsiniz.

## **Deleted Files Recovery**

### Logged Deleted Files

Daha önce görüldüğü gibi, dosya "silindikten" sonra hâlâ kayıtlı olduğu çeşitli konumlar vardır. Bunun nedeni, bir file system'dan dosya silme işleminin genellikle yalnızca dosyayı silinmiş olarak işaretlemesi, veriye ise dokunulmamasıdır. Bu nedenle dosyaların registry'lerini (MFT gibi) incelemek ve silinmiş dosyaları bulmak mümkündür.<sup>[[2]](#references)</sup>

Ayrıca OS genellikle file system değişiklikleri ve backup'lar hakkında çok miktarda bilgi kaydeder. Bu nedenle dosyayı veya mümkün olduğunca fazla bilgiyi kurtarmak için bunları kullanmayı denemek mümkündür.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### **File Carving**

**File carving**, **veri yığınının içinde dosyaları bulmaya** çalışan bir tekniktir. Bu tür araçların çalışma şekillerinin 3 ana yolu vardır: **file type header ve footer'larına dayalı**, file type **structure'larına dayalı** ve doğrudan **içeriğin kendisine** dayalı.

Bu tekniğin **fragmented dosyaları kurtarmak için çalışmadığını** unutmayın. Bir dosya **contiguous sektörlerde depolanmamışsa**, bu teknik dosyayı veya en azından bir kısmını bulamaz.

File carving için kullanabileceğiniz ve aramak istediğiniz file type'ları belirtebileceğiniz çeşitli araçlar vardır.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Data Stream **C**arving

Data Stream Carving, File Carving'e benzer; ancak **tam dosyaları aramak yerine ilgi çekici bilgi parçalarını arar**.\
Örneğin log'lanmış URL'leri içeren tam bir dosyayı aramak yerine bu teknik URL'leri arar.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Secure Deletion

Dosyaları ve bunlarla ilgili log'ların bir bölümünü **"güvenli bir şekilde" silmenin** yolları olduğu açıktır. Örneğin bir dosyanın **içeriğinin üzerine** birkaç kez anlamsız veriler yazmak, ardından dosyayla ilgili **$MFT** ve **$LOGFILE** kayıtlarını **silmek** ve **Volume Shadow Copies**'leri **kaldırmak** mümkündür.<sup>[[3]](#references)</sup>\
Ancak bu işlemi gerçekleştirdikten sonra bile dosyanın varlığının hâlâ log'landığı **başka bölümler** olabileceğini fark edebilirsiniz. Bu doğrudur ve forensics profesyonelinin işinin bir parçası da bunları bulmaktır.

## References

- [1] [GUID Partition Table - Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)
- [2] [Silinmiş dosyalara ilişkin kanıtlar için NTFS $I30 (directory) entry'leri nasıl taranır](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
- [3] [Volume Shadow Copy Service (VSS)](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
{{#include ../../../banners/hacktricks-training.md}}
