# Partitions/File Systems/Carving

{{#include ../../../banners/hacktricks-training.md}}

## Partitions

Bir sabit disk veya bir **SSD disk farklı bölümler içerebilir** ve bu, verileri fiziksel olarak ayırma amacını taşır.\
Diskin **minimum** birimi **sektördür** (normalde 512B'den oluşur). Bu nedenle, her bölüm boyutu bu boyutun katı olmalıdır.

### MBR (master Boot Record)

**446B boot kodundan sonra diskin ilk sektöründe** tahsis edilir. Bu sektör, PC'ye bir bölümün ne zaman ve nereden bağlanması gerektiğini belirtmek için gereklidir.\
En fazla **4 bölüm** (en fazla **1** aktif/**bootable** olabilir) olmasına izin verir. Ancak daha fazla bölüme ihtiyacınız varsa **genişletilmiş bölümler** kullanabilirsiniz. Bu ilk sektörün **son baytı** boot kayıt imzası **0x55AA**'dır. Sadece bir bölüm aktif olarak işaretlenebilir.\
MBR **maksimum 2.2TB**'ye izin verir.

![](<../../../images/image (350).png>)

![](<../../../images/image (304).png>)

MBR'nin **440 ile 443 baytları** arasında **Windows Disk İmzası** bulunabilir (Windows kullanılıyorsa). Sabit diskin mantıksal sürücü harfi, Windows Disk İmzasına bağlıdır. Bu imzanın değiştirilmesi, Windows'un başlatılmasını engelleyebilir (araç: [**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**.

![](<../../../images/image (310).png>)

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

Bir MBR'yi Linux'ta bağlamak için önce başlangıç ofsetini almanız gerekir (bunu `fdisk` ve `p` komutunu kullanarak yapabilirsiniz)

![](<../../../images/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

Ve ardından aşağıdaki kodu kullanın
```bash
#Mount MBR in Linux
mount -o ro,loop,offset=<Bytes>
#63x512 = 32256Bytes
mount -o ro,loop,offset=32256,noatime /path/to/image.dd /media/part/
```
**LBA (Mantıksal blok adresleme)**

**Mantıksal blok adresleme** (**LBA**), bilgisayar depolama cihazlarında saklanan veri bloklarının konumunu belirtmek için yaygın olarak kullanılan bir şemadır; genellikle sabit disk sürücüleri gibi ikincil depolama sistemleridir. LBA, özellikle basit bir doğrusal adresleme şemasına sahiptir; **bloklar bir tam sayı indeksi ile konumlandırılır**, ilk blok LBA 0, ikinci LBA 1 şeklindedir.

### GPT (GUID Bölüm Tablosu)

GUID Bölüm Tablosu, GPT olarak bilinir ve MBR (Ana Önyükleme Kaydı) ile karşılaştırıldığında geliştirilmiş yetenekleri nedeniyle tercih edilmektedir. Bölümler için **küresel benzersiz tanımlayıcı** ile ayırt edici olan GPT, birkaç yönden öne çıkmaktadır:

- **Konum ve Boyut**: Hem GPT hem de MBR **sektör 0**'da başlar. Ancak, GPT **64 bit** üzerinde çalışırken, MBR **32 bit** kullanır.
- **Bölüm Sınırları**: GPT, Windows sistemlerinde **128 bölüme** kadar destekler ve **9.4ZB**'a kadar veri depolayabilir.
- **Bölüm İsimleri**: Bölümlere 36 Unicode karaktere kadar isim verme imkanı sunar.

**Veri Dayanıklılığı ve Kurtarma**:

- **Yedeklilik**: MBR'nin aksine, GPT bölümleme ve önyükleme verilerini tek bir yere hapsetmez. Bu verileri disk boyunca çoğaltarak veri bütünlüğünü ve dayanıklılığını artırır.
- **Döngüsel Yedeklilik Kontrolü (CRC)**: GPT, veri bütünlüğünü sağlamak için CRC kullanır. Veri bozulmasını aktif olarak izler ve tespit edildiğinde, GPT bozulmuş veriyi başka bir disk konumundan kurtarmaya çalışır.

**Koruyucu MBR (LBA0)**:

- GPT, koruyucu bir MBR aracılığıyla geriye dönük uyumluluğu sürdürmektedir. Bu özellik, eski MBR tabanlı yardımcı programların yanlışlıkla GPT disklerini üzerine yazmasını önlemek için tasarlanmıştır ve böylece GPT formatlı disklerde veri bütünlüğünü korur.

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID_Partition_Table_Scheme.svg/800px-GUID_Partition_Table_Scheme.svg.png](<../../../images/image (1062).png>)

**Hibrit MBR (LBA 0 + GPT)**

[Wikipedia'dan](https://en.wikipedia.org/wiki/GUID_Partition_Table)

**EFI** yerine **BIOS** hizmetleri aracılığıyla **GPT tabanlı önyükleme** destekleyen işletim sistemlerinde, ilk sektör hala **önyükleyici** kodunun ilk aşamasını depolamak için kullanılabilir, ancak **değiştirilmiş** olarak **GPT** **bölümlerini** tanımak için. MBR'deki önyükleyici, 512 baytlık bir sektör boyutu varsaymamalıdır.

**Bölüm tablosu başlığı (LBA 1)**

[Wikipedia'dan](https://en.wikipedia.org/wiki/GUID_Partition_Table)

Bölüm tablosu başlığı, diskteki kullanılabilir blokları tanımlar. Ayrıca, bölüm tablosunu oluşturan bölüm girişlerinin sayısını ve boyutunu tanımlar (tablodaki 80 ve 84 ofsetleri).

| Ofset     | Uzunluk  | İçerik                                                                                                                                                                     |
| --------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)  | 8 bayt   | İmza ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h veya 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID_Partition_Table#cite_note-8)küçük sonlu makinelerde) |
| 8 (0x08)  | 4 bayt   | UEFI 2.8 için Revizyon 1.0 (00h 00h 01h 00h)                                                                                                                                  |
| 12 (0x0C) | 4 bayt   | Küçük sonlu (bayt cinsinden, genellikle 5Ch 00h 00h 00h veya 92 bayt) başlık boyutu                                                                                                 |
| 16 (0x10) | 4 bayt   | [CRC32](https://en.wikipedia.org/wiki/CRC32) başlığın (ofset +0'dan başlık boyutuna kadar) küçük sonlu, bu alan hesaplama sırasında sıfırlanmıştır                             |
| 20 (0x14) | 4 bayt   | Ayrılmış; sıfır olmalıdır                                                                                                                                                       |
| 24 (0x18) | 8 bayt   | Mevcut LBA (bu başlık kopyasının konumu)                                                                                                                                   |
| 32 (0x20) | 8 bayt   | Yedek LBA (diğer başlık kopyasının konumu)                                                                                                                               |
| 40 (0x28) | 8 bayt   | Bölümler için ilk kullanılabilir LBA (birincil bölüm tablosunun son LBA'sı + 1)                                                                                                       |
| 48 (0x30) | 8 bayt   | Son kullanılabilir LBA (ikincil bölüm tablosunun ilk LBA'sı − 1)                                                                                                                    |
| 56 (0x38) | 16 bayt  | Disk GUID karışık sonlu                                                                                                                                                    |
| 72 (0x48) | 8 bayt   | Bölüm girişlerinin bir dizisinin başlangıç LBA'sı (her zaman birincil kopyada 2)                                                                                                     |
| 80 (0x50) | 4 bayt   | Dizideki bölüm girişlerinin sayısı                                                                                                                                         |
| 84 (0x54) | 4 bayt   | Tek bir bölüm girişinin boyutu (genellikle 80h veya 128)                                                                                                                        |
| 88 (0x58) | 4 bayt   | Bölüm girişleri dizisinin küçük sonlu CRC32'si                                                                                                                            |
| 92 (0x5C) | \*       | Ayrılmış; geri kalan blok için sıfır olmalıdır (512 baytlık bir sektör boyutu için 420 bayt; ancak daha büyük sektör boyutları ile daha fazla olabilir)                                      |

**Bölüm girişleri (LBA 2–33)**

| GUID bölüm giriş formatı |          |                                                                                                               |
| ------------------------- | -------- | ------------------------------------------------------------------------------------------------------------- |
| Ofset                     | Uzunluk  | İçerik                                                                                                      |
| 0 (0x00)                  | 16 bayt  | [Bölüm türü GUID](https://en.wikipedia.org/wiki/GUID_Partition_Table#Partition_type_GUIDs) (karışık sonlu) |
| 16 (0x10)                 | 16 bayt  | Benzersiz bölüm GUID (karışık sonlu)                                                                          |
| 32 (0x20)                 | 8 bayt   | İlk LBA ([küçük sonlu](https://en.wikipedia.org/wiki/Little_endian))                                      |
| 40 (0x28)                 | 8 bayt   | Son LBA (dahil, genellikle tek)                                                                             |
| 48 (0x30)                 | 8 bayt   | Nitelik bayrakları (örneğin, bit 60 yalnızca okunur olduğunu belirtir)                                                               |
| 56 (0x38)                 | 72 bayt  | Bölüm adı (36 [UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE kod birimi)                               |

**Bölüm Türleri**

![](<../../../images/image (83).png>)

Daha fazla bölüm türü için [https://en.wikipedia.org/wiki/GUID_Partition_Table](https://en.wikipedia.org/wiki/GUID_Partition_Table)

### İnceleme

[**ArsenalImageMounter**](https://arsenalrecon.com/downloads/) ile adli görüntüyü monte ettikten sonra, Windows aracı [**Active Disk Editor**](https://www.disk-editor.org/index.html)**'ı** kullanarak ilk sektörü inceleyebilirsiniz. Aşağıdaki görüntüde **sektör 0**'da bir **MBR** tespit edilmiştir ve yorumlanmıştır:

![](<../../../images/image (354).png>)

Eğer bir **MBR yerine bir GPT tablosu** olsaydı, **sektör 1**'de _EFI PART_ imzası görünmelidir (önceki görüntüde bu alan boştur).

## Dosya Sistemleri

### Windows dosya sistemleri listesi

- **FAT12/16**: MSDOS, WIN95/98/NT/200
- **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
- **ExFAT**: 2008/2012/2016/VISTA/7/8/10
- **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
- **ReFS**: 2012/2016

### FAT

**FAT (Dosya Tahsis Tablosu)** dosya sistemi, hacmin başlangıcında yer alan dosya tahsis tablosu etrafında tasarlanmıştır. Bu sistem, verilerin bütünlüğünü sağlamak için tablonun **iki kopyasını** tutarak verileri korur; bu sayede bir kopyası bozulsa bile veri bütünlüğü sağlanır. Tablo, kök klasör ile birlikte **sabit bir konumda** olmalıdır; bu, sistemin başlatma süreci için kritik öneme sahiptir.

Dosya sisteminin temel depolama birimi bir **küme, genellikle 512B**'dir ve birden fazla sektörden oluşur. FAT, sürümler boyunca evrim geçirmiştir:

- **FAT12**, 12 bit küme adreslerini destekler ve 4078 kümeye kadar (4084 UNIX ile) işleyebilir.
- **FAT16**, 16 bit adreslere yükseltilerek 65,517 kümeye kadar destek sağlar.
- **FAT32**, 32 bit adreslerle daha da ilerleyerek her hacim için 268,435,456 kümeye kadar izin verir.

FAT sürümleri arasında önemli bir sınırlama, **4GB maksimum dosya boyutu**'dur; bu, dosya boyutu depolamak için kullanılan 32 bit alan tarafından dayatılmaktadır.

FAT12 ve FAT16 için kök dizininin ana bileşenleri şunlardır:

- **Dosya/Klasör Adı** (en fazla 8 karakter)
- **Nitelikler**
- **Oluşturma, Değiştirme ve Son Erişim Tarihleri**
- **FAT Tablosu Adresi** (dosyanın başlangıç kümesini gösterir)
- **Dosya Boyutu**

### EXT

**Ext2**, **günlük tutmayan** bölümler (**çok fazla değişmeyen bölümler**) için en yaygın dosya sistemidir; **Ext3/4** ise genellikle **diğer bölümler** için **günlük tutan** sistemlerdir.

## **Meta Veriler**

Bazı dosyalar meta veriler içerir. Bu bilgiler, dosyanın içeriği hakkında olup, bazen bir analist için ilginç olabilir; dosya türüne bağlı olarak, aşağıdaki bilgileri içerebilir:

- Başlık
- Kullanılan MS Office Versiyonu
- Yazar
- Oluşturma ve son değiştirme tarihleri
- Kameranın modeli
- GPS koordinatları
- Görüntü bilgileri

Bir dosyanın meta verilerini almak için [**exiftool**](https://exiftool.org) ve [**Metadiver**](https://www.easymetadata.com/metadiver-2/) gibi araçları kullanabilirsiniz.

## **Silinmiş Dosyaların Kurtarılması**

### Kaydedilen Silinmiş Dosyalar

Daha önce görüldüğü gibi, bir dosya "silindikten" sonra hala kaydedildiği birkaç yer vardır. Bunun nedeni, genellikle bir dosyanın dosya sisteminden silinmesinin sadece silindi olarak işaretlenmesidir; ancak veri dokunulmamıştır. Bu nedenle, dosyaların kayıtlarını (MFT gibi) incelemek ve silinmiş dosyaları bulmak mümkündür.

Ayrıca, işletim sistemi genellikle dosya sistemi değişiklikleri ve yedeklemeleri hakkında çok fazla bilgi kaydeder, bu nedenle dosyayı veya mümkün olduğunca fazla bilgiyi kurtarmak için bunları kullanmaya çalışmak mümkündür.

{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### **Dosya Oymacılığı**

**Dosya oymacılığı**, **veri yığınında dosyaları bulmaya çalışan** bir tekniktir. Bu tür araçların çalıştığı 3 ana yol vardır: **Dosya türü başlıkları ve alt başlıklarına dayalı**, dosya türü **yapılarına** dayalı ve **içerik**'e dayalı.

Bu tekniğin **parçalanmış dosyaları geri almak için çalışmadığını** unutmayın. Eğer bir dosya **bitişik sektörlerde depolanmamışsa**, bu teknik onu veya en azından bir kısmını bulamayacaktır.

Aradığınız dosya türlerini belirterek dosya oymacılığı için kullanabileceğiniz birkaç araç vardır.

{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Veri Akışı **C**arving

Veri Akışı Oymacılığı, Dosya Oymacılığına benzer, ancak **tam dosyalar aramak yerine, ilginç bilgi parçalarını arar**.\
Örneğin, kaydedilmiş URL'leri içeren bir tam dosya aramak yerine, bu teknik URL'leri arayacaktır.

{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Güvenli Silme

Açıkça, dosyaları ve bunlarla ilgili logların bir kısmını **"güvenli" bir şekilde silmenin** yolları vardır. Örneğin, bir dosyanın içeriğini birkaç kez gereksiz verilerle **üst üste yazmak** ve ardından dosya ile ilgili **$MFT** ve **$LOGFILE**'dan **logları kaldırmak** ve **Hacim Gölge Kopyalarını** **kaldırmak** mümkündür.\
Bu işlemi gerçekleştirirken, dosyanın varlığının hala **diğer parçalarda kaydedilmiş olabileceğini** fark edebilirsiniz; bu doğrudur ve adli uzmanların işinin bir parçası da bunları bulmaktır.

## Referanslar

- [https://en.wikipedia.org/wiki/GUID_Partition_Table](https://en.wikipedia.org/wiki/GUID_Partition_Table)
- [http://ntfs.com/ntfs-permissions.htm](http://ntfs.com/ntfs-permissions.htm)
- [https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
- [https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
- **iHackLabs Sertifikalı Dijital Adli Windows**

{{#include ../../../banners/hacktricks-training.md}}
