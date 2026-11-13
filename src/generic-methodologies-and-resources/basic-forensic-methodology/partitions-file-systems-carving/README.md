# Bölümler/Dosya Sistemleri/Carving

{{#include ../../../banners/hacktricks-training.md}}

## Bölümler

Bir disk birden fazla **bölüm** içerebilir: bunlar fiziksel olarak ayrı depolama alanları değil, bloklardan oluşan mantıksal aralıklardır. Bölümlerin başlangıç ve uzunlukları **mantıksal sektör** cinsinden ölçülür; her imajın 512 baytlık sektörler kullandığını varsaymayın, çünkü 4096 baytlık mantıksal sektörler de vardır.<sup>[[4]](#references)</sup>

### MBR (Ana Önyükleme Kaydı)

MBR ilk mantıksal sektörü (LBA 0) kaplar; dört adet 16 baytlık bölüm girdisi 446. bayttan başlar. Önceki alan önyükleme kodunu içerir ve disk imzası da içerebilir.<sup>[[4]](#references)</sup>\
En fazla **4 bölüme** izin verir (bunlardan en fazla **yalnızca 1 tanesi** etkin/**önyüklenebilir** olabilir). Ancak daha fazla bölüme ihtiyacınız varsa **genişletilmiş bölümler** kullanabilirsiniz. 512 baytlık MBR'nin son **iki baytı**, önyükleme imzası olan **0x55 0xAA** değeridir. Yalnızca bir bölüm etkin olarak işaretlenebilir.\
512 baytlık mantıksal sektörlerde, MBR'nin 32 bitlik sektör alanları adreslenebilir alanı yaklaşık **2 TiB** (2,2 TB) ile sınırlar.<sup>[[4]](#references)</sup>

![Bölümler - MBR (Ana Önyükleme Kaydı): MBR en fazla 2,2 TB'ı destekler](<../../../images/image (350).png>)

![Bölümler - MBR (Ana Önyükleme Kaydı): MBR en fazla 2,2 TB'ı destekler](<../../../images/image (304).png>)

MBR'nin **440 ile 443. baytları** arasında **Windows Disk İmzası** bulunabilir (Windows kullanılıyorsa). Sabit diskin mantıksal sürücü harfi, Windows Disk İmzası'na bağlıdır. Bu imzayı değiştirmek Windows'un önyüklenmesini engelleyebilir (araç: [**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**.

![Bölümler - MBR (Ana Önyükleme Kaydı): MBR'nin 440 ile 443. baytları arasında Windows Disk İmzası bulunabilir (Windows kullanılıyorsa). Sabit diskin mantıksal sürücü harfi...](<../../../images/image (310).png>)

**Biçim**

| Ofset       | Uzunluk    | Öğe                  |
| ----------- | ---------- | ------------------- |
| 0 (0x00)    | 446(0x1BE) | Önyükleme kodu      |
| 446 (0x1BE) | 16 (0x10)  | İlk bölüm           |
| 462 (0x1CE) | 16 (0x10)  | İkinci bölüm        |
| 478 (0x1DE) | 16 (0x10)  | Üçüncü bölüm        |
| 494 (0x1EE) | 16 (0x10)  | Dördüncü bölüm      |
| 510 (0x1FE) | 2 (0x2)    | 0x55 0xAA imzası    |

**Bölüm Kaydı Biçimi**

| Ofset     | Uzunluk  | Öğe                                                        |
| --------- | -------- | ---------------------------------------------------------- |
| 0 (0x00)  | 1 (0x01) | Etkin bayrağı (0x80 = önyüklenebilir)                      |
| 1 (0x01)  | 1 (0x01) | Başlangıç kafası                                           |
| 2 (0x02)  | 1 (0x01) | Başlangıç sektörü (bit 0-5); silindirin üst bitleri (6-7) |
| 3 (0x03)  | 1 (0x01) | Başlangıç silindirinin en düşük 8 biti                     |
| 4 (0x04)  | 1 (0x01) | Bölüm türü kodu (0x83 = Linux)                             |
| 5 (0x05)  | 1 (0x01) | Bitiş kafası                                               |
| 6 (0x06)  | 1 (0x01) | Bitiş sektörü (bit 0-5); silindirin üst bitleri (6-7)     |
| 7 (0x07)  | 1 (0x01) | Bitiş silindirinin en düşük 8 biti                         |
| 8 (0x08)  | 4 (0x04) | Bölümden önceki sektörler (little endian)                  |
| 12 (0x0C) | 4 (0x04) | Bölümdeki sektörler                                        |

Tam disk MBR imajındaki bir bölümü incelemek için önce başlangıç LBA'sını ve mantıksal sektör boyutunu belirleyin. `mount`, LBA değil **bayt ofseti** alır; aşağıdaki örnek yalnızca 512 baytlık sektörler kullanan ve bölümü LBA 63'te başlayan bir imaj için geçerlidir. Güvenilmeyen imajlar veya günlükleme kullanan dosya sistemleri için bunun yerine [Image Acquisition & Mount](../image-acquisition-and-mount.md) içindeki yalıtılmış, salt okunur iş akışını kullanın.<sup>[[5]](#references)[[11]](#references)</sup>

![Bölümler - MBR (Ana Önyükleme Kaydı): Linux'ta bir MBR'yi bağlamak için önce başlangıç ofsetini bulmanız gerekir (fdisk ve p komutunu kullanabilirsiniz)](<../../../images/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

```bash
mmls -b 512 /path/to/image.dd  # Confirm the start LBA from this image
sudo mount -o ro,loop,offset=$((63 * 512)),noatime /path/to/image.dd /media/part/
```

**LBA (Mantıksal blok adresleme)**

**Mantıksal blok adresleme** (**LBA**), bilgisayar depolama aygıtlarında, genellikle sabit disk sürücüleri gibi ikincil depolama sistemlerinde saklanan veri **bloklarının konumunu belirtmek** için kullanılan yaygın bir yöntemdir. LBA, özellikle basit bir doğrusal adresleme yöntemidir; **bloklar bir tamsayı indeksiyle konumlandırılır**. İlk blok LBA 0, ikinci blok LBA 1 olarak adlandırılır ve bu şekilde devam eder.

### GPT (GUID Bölüm Tablosu)

GUID Bölüm Tablosu (GPT), her bölüm için benzersiz bir GUID saklar ve birincil ve yedek metadata kullanır. Düzeni MBR'den şu şekillerde farklıdır:<sup>[[4]](#references)</sup>

- **Konum ve Boyut**: LBA 0, bir **koruyucu MBR** içerir. Birincil GPT başlığı LBA 1'dedir; bölüm girdisi dizisi bunu izler, yedek dizi ve başlık ise diskin sonundadır. GPT 64 bit LBA alanları kullanırken MBR bölüm girdileri 32 bit LBA alanları kullanır.
- **Bölüm Sınırları**: Yaygın kullanılan 16 KiB'lık bir girdi dizisi **128 baytlık 128 girdi** içerir, ancak girdi sayısı GPT tarafından sabitlenmek yerine başlıkta belirtilir. Adreslenebilir boyut, mantıksal sektör boyutuna da bağlıdır (512 baytlık sektörlerde yaklaşık **9,4 ZB**).<sup>[[4]](#references)</sup>
- **Bölüm Adları**: Bölümlere en fazla 36 Unicode karakterden oluşan adlar verme olanağı sunar.

**Veri Dayanıklılığı ve Kurtarma**:

- **Yedeklilik**: MBR'nin aksine GPT, bölümleme ve önyükleme verilerini tek bir konumla sınırlamaz. Bu verileri disk genelinde çoğaltarak veri bütünlüğünü ve dayanıklılığını artırır.
- **Döngüsel Artıklık Denetimi (CRC)**: Başlık ve bölüm girdisi dizisinin her biri bir CRC32 değerine sahiptir. CRC tutarsızlıkları tespit eder; diski sürekli olarak izlemez veya kendi başına onarmaz. Birincil kopya geçersizse, çalışan bir kopyada kurtarma işlemine başlamadan önce son LBA'daki yedek kopyayı doğrulayın.<sup>[[4]](#references)</sup>

**Koruyucu MBR (LBA0)**:

- GPT, koruyucu MBR aracılığıyla geriye dönük uyumluluğu korur. Bu özellik, eski MBR alanında bulunur ancak eski MBR tabanlı yardımcı programların GPT disklerinin üzerine yanlışlıkla yazmasını önlemek üzere tasarlanmıştır; böylece GPT biçimindeki disklerdeki verilerin bütünlüğünü korur.

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID_Partition_Table_Scheme.svg/800px-GUID_Partition_Table_Scheme.svg.png](<../../../images/image (1062).png>)

**Hibrit MBR (LBA 0 + GPT)**

[Vikipedi'den](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

EFI yerine **BIOS** hizmetleri üzerinden **GPT tabanlı önyüklemeyi** destekleyen işletim sistemlerinde, ilk sektör **bootloader** kodunun ilk aşamasını saklamak için hâlâ kullanılabilir; ancak **GPT** **bölümlerini** tanıyacak şekilde **değiştirilmiş** olmalıdır. MBR'deki bootloader, sektör boyutunun 512 bayt olduğunu varsaymamalıdır.

**Bölüm tablosu başlığı (LBA 1)**

[Vikipedi'den](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

Bölüm tablosu başlığı, diskte kullanılabilir blokları tanımlar. Ayrıca bölüm tablosunu oluşturan bölüm girdilerinin sayısını ve boyutunu da tanımlar (tablodaki 80 ve 84 ofsetleri).

| Ofset     | Uzunluk  | İçerik                                                                                                                                                                       |
| --------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)  | 8 bayt   | İmza ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h veya little-endian makinelerde 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID_Partition_Table#cite_note-8)) |
| 8 (0x08)  | 4 bayt   | UEFI 2.8 için Revizyon 1.0 (00h 00h 01h 00h)                                                                                                                                 |
| 12 (0x0C) | 4 bayt   | Little-endian başlık boyutu (bayt cinsinden; genellikle 5Ch 00h 00h 00h veya 92 bayt)                                                                                        |
| 16 (0x10) | 4 bayt   | Little-endian başlığın [CRC32](https://en.wikipedia.org/wiki/CRC32) değeri (hesaplama sırasında bu alan sıfırlanarak +0 ofsetinden başlık boyutuna kadar)                    |
| 20 (0x14) | 4 bayt   | Ayrılmış; sıfır olmalıdır                                                                                                                                                    |
| 24 (0x18) | 8 bayt   | Geçerli LBA (bu başlık kopyasının konumu)                                                                                                                                    |
| 32 (0x20) | 8 bayt   | Yedek LBA (diğer başlık kopyasının konumu)                                                                                                                                   |
| 40 (0x28) | 8 bayt   | Bölümler için kullanılabilir ilk LBA (birincil bölüm tablosunun son LBA'sı + 1)                                                                                              |
| 48 (0x30) | 8 bayt   | Kullanılabilir son LBA (ikincil bölüm tablosunun ilk LBA'sı − 1)                                                                                                             |
| 56 (0x38) | 16 bayt  | Mixed endian biçiminde disk GUID'si                                                                                                                                          |
| 72 (0x48) | 8 bayt   | Bölüm girdileri dizisinin başlangıç LBA'sı (birincil kopyada her zaman 2)                                                                                                    |
| 80 (0x50) | 4 bayt   | Dizideki bölüm girdilerinin sayısı                                                                                                                                           |
| 84 (0x54) | 4 bayt   | Tek bir bölüm girdisinin boyutu (genellikle 80h veya 128)                                                                                                                    |
| 88 (0x58) | 4 bayt   | Little-endian bölüm girdileri dizisinin CRC32 değeri                                                                                                                         |
| 92 (0x5C) | \*       | Ayrılmış; bloğun geri kalanında sıfır olmalıdır (512 baytlık sektör boyutunda 420 bayt; ancak daha büyük sektör boyutlarında daha fazla olabilir)                             |

**Bölüm girdileri (LBA 2–33)**

| GUID bölüm girdisi biçimi |          |                                                                                                               |
| ------------------------- | -------- | ------------------------------------------------------------------------------------------------------------- |
| Ofset                     | Uzunluk  | İçerik                                                                                                        |
| 0 (0x00)                  | 16 bayt  | [Bölüm türü GUID'si](https://en.wikipedia.org/wiki/GUID_Partition_Table#Partition_type_GUIDs) (mixed endian) |
| 16 (0x10)                 | 16 bayt  | Benzersiz bölüm GUID'si (mixed endian)                                                                         |
| 32 (0x20)                 | 8 bayt   | İlk LBA ([little endian](https://en.wikipedia.org/wiki/Little_endian))                                        |
| 40 (0x28)                 | 8 bayt   | Son LBA (dahil, genellikle tek sayı)                                                                           |
| 48 (0x30)                 | 8 bayt   | Öznitelik bayrakları (ör. 60. bit salt okunur olduğunu belirtir)                                               |
| 56 (0x38)                 | 72 bayt  | Bölüm adı (36 [UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE kod birimi)                                     |

**Bölüm Türleri**

![MBR (ana önyükleme kaydı) - GPT (GUID Bölüm Tablosu): 56 (0x38) | 72 bayt | Bölüm adı (36 UTF-16LE kod birimi)](<../../../images/image (83).png>)

Daha fazla bölüm türü için bkz. [https://en.wikipedia.org/wiki/GUID_Partition_Table](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

### İnceleme

Adli bilişim imajını [**ArsenalImageMounter**](https://arsenalrecon.com/downloads/) ile bağladıktan sonra, ilk sektörü Windows aracı [**Active Disk Editor**](https://www.disk-editor.org/index.html)**.** ile inceleyebilirsiniz. Aşağıdaki görselde **sektör 0**'da bir **MBR** algılanıp yorumlanmıştır:

![GPT (GUID Bölüm Tablosu) - İnceleme: Adli bilişim imajını ArsenalImageMounter ile bağladıktan sonra, ilk sektörü Windows aracı Active Disk Editor ile inceleyebilirsiniz. ...](<../../../images/image (354).png>)

GPT için **LBA 1**'deki birincil başlıkta _EFI PART_ imzasını arayın; LBA 0 hâlâ koruyucu MBR'yi içerir.<sup>[[4]](#references)</sup>

### Listelenen bölümlerin dışındaki verileri bulma

Silinmiş bir bölüm girdisi veya bilerek kullanılmayan bir boşluk, dosya sistemini mevcut bölüm haritasının dışında bırakabilir. **Doğrulanmış bir ham çalışma kopyasında**, ayrılmamış aralıkları listeleyin ve ardından aday başlangıç LBA'sını bir dosya sistemi olarak sınayın. `mmls` ve `fsstat` **sektör ofsetleri** kullanır; ikisine de gerçek mantıksal sektör boyutunu verin. GPT metadata sektörlerini gizli bir birimle karıştırmayın.<sup>[[5]](#references)[[6]](#references)</sup>

```bash
mmls -b 512 -A disk.img                # Unallocated ranges: Start and Length
fsstat -b 512 -o 2048 disk.img       # Replace 2048 with a candidate Start LBA
```

`fsstat` boşluk başlangıcında bir dosya sistemi tanımlayamıyorsa TestDisk'te **Analyse → Quick Search** seçeneğini, gerekirse ardından **Deeper Search** seçeneğini kullanın. Bir adaydaki dosyaları incelemek için `P` tuşuna basın; kanıt üzerinde **Write** seçeneğini kullanmayın. GPT imajlarında `sgdisk --verify disk.img`, CRC'leri ve ana/yedek kopyaların uyumunu denetler; ancak bölümleme yeniden yapıldıktan sonra yedek başlık güncelliğini yitirmiş olabilir. Bu nedenle kurtarma işleminden önce aday sınırlarını dosya sistemi yapılarıyla doğrulayın.<sup>[[9]](#references)[[10]](#references)[[4]](#references)</sup>

## Dosya Sistemleri

### Windows dosya sistemleri listesi

- **FAT12/16**: MSDOS, WIN95/98/NT/200
- **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
- **ExFAT**: 2008/2012/2016/VISTA/7/8/10
- **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
- **ReFS**: 2012/2016

### FAT

**FAT (File Allocation Table)** dosya sistemi, birimin başlangıcında bulunan temel bileşeni olan dosya tahsis tablosu etrafında tasarlanmıştır. Birimde genellikle **iki FAT kopyası** bulunur, ancak BPB tek kopyaya da izin verir. FAT12/16, kök dizini sabit bir bölgede tutar; FAT32 ise kök dizinini, `BPB_RootClus` tarafından belirtilen kümede veri alanında saklar.<sup>[[7]](#references)</sup>

Tahsis birimi bir **kümedir**: `BPB_BytsPerSec × BPB_SecPerClus`; bu değer mutlaka 512 bayt değildir. FAT türü, önyükleme sektöründeki bir sürüm dizesine göre değil, veri kümelerinin sayısına göre belirlenir. Küme sayısı sınırları şöyledir:<sup>[[7]](#references)</sup>

- **FAT12**: 4.085'ten az veri kümesi.
- **FAT16**: 4.085 ila 65.524 veri kümesi.
- **FAT32**: en az 65.525 veri kümesi; küme numarası için her 32 bit FAT girdisinin yalnızca 28 biti kullanılır.

32 bitlik dosya boyutu alanı, normal bir dosyayı **2³²−1 baytla** (4 GiB'ın biraz altında) sınırlar.<sup>[[7]](#references)</sup>

Özellikle FAT12 ve FAT16 için kök dizinin temel bileşenleri şunlardır:

- **Dosya/Klasör Adı** (en fazla 8 karakter)
- **Öznitelikler**
- **Oluşturulma, Değiştirilme ve Son Erişim Tarihleri**
- **FAT Tablosu Adresi** (dosyanın başlangıç kümesini belirtir)
- **Dosya Boyutu**

### EXT

**Ext2**, önyükleme bölümü gibi **journaling kullanmayan** (**fazla değişmeyen bölümler**) bölümler için en yaygın dosya sistemidir. **Ext3/4** ise **journaling** kullanır ve genellikle **diğer bölümlerde** tercih edilir.

## **Metadata**

Bazı dosyalar metadata içerir. Bu bilgiler dosyanın içeriğiyle ilgilidir ve dosya türüne bağlı olarak analist için ilgi çekici olabilir. Örneğin şu bilgileri içerebilir:

- Başlık
- Kullanılan MS Office sürümü
- Yazar
- Oluşturulma ve son değiştirilme tarihleri
- Kamera modeli
- GPS koordinatları
- Görüntü bilgileri

Bir dosyanın metadata bilgilerini almak için [**exiftool**](https://exiftool.org) ve [**Metadiver**](https://www.easymetadata.com/metadiver-2/) gibi araçları kullanabilirsiniz.

## **Silinmiş Dosyaları Kurtarma**

### Kaydı Tutulan Silinmiş Dosyalar

Daha önce görüldüğü gibi, bir dosya "silindikten" sonra da dosyanın kaydedildiği çeşitli yerler bulunur. Bunun nedeni, dosya sisteminde bir dosyanın silinmesinin genellikle yalnızca dosyayı silinmiş olarak işaretlemesi, veriye dokunmamasıdır. Bu durumda dosya kayıtlarını (MFT gibi) inceleyerek silinmiş dosyaları bulmak mümkündür.<sup>[[2]](#references)</sup>

Ayrıca, işletim sistemi genellikle dosya sistemi değişiklikleri ve yedeklemeler hakkında çok sayıda bilgi kaydeder. Bu nedenle dosyayı veya mümkün olduğunca fazla bilgiyi kurtarmak için bunlardan yararlanmayı deneyebilirsiniz.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### **File Carving**

**File carving**, **veri yığınındaki dosyaları bulmaya** çalışan bir tekniktir. Bu tür araçlar temel olarak üç şekilde çalışır: **dosya türlerinin başlık ve sonlandırıcılarına**, dosya türlerinin **yapılarına** veya doğrudan **içeriğe** göre.

Basit başlık/sonlandırıcı carving, bitişik bloklar varsayar ve dosya parçalara bölünmüşse yalnızca bir parça döndürebilir. Ancak bu mutlak bir sınır değildir: PhotoRec, parçalanmış bazı JPEG dosyaları için işlemci yoğun **Paranoid → bruteforce** seçeneğine sahiptir; biçimi tanıyan parça birleştirme yöntemleri de desteklenen diğer türleri kurtarabilir. Güncel bir parça birleştirme iş akışı için [file carving and recovery tools](file-data-carving-recovery-tools.md#scalpel3-fragmented-carving) sayfasına bakın.<sup>[[8]](#references)</sup>

Aramak istediğiniz dosya türlerini belirterek File Carving için kullanabileceğiniz çeşitli araçlar vardır.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Data Stream **Carving**

Data Stream Carving, File Carving'e benzer; ancak **tam dosyaları aramak yerine ilgi çekici bilgi parçalarını arar**.\
Örneğin, kayıtlı URL'leri içeren tam bir dosyayı aramak yerine bu teknik URL'leri arar.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Güvenli Silme

Dosyaları ve bunlarla ilgili günlüklerin bir kısmını **"güvenli" biçimde silmenin** yolları olduğu açıktır. Örneğin, bir dosyanın **içeriğini** birkaç kez anlamsız verilerle **üzerine yazarak** değiştirmek, ardından dosyayla ilgili **$MFT** ve **$LOGFILE** **günlüklerini** ve **Volume Shadow Copies**'i **kaldırmak** mümkündür.<sup>[[3]](#references)</sup>\
Bu işlemi gerçekleştirseniz bile dosyanın varlığının kaydedildiği **başka yerler** olabileceğini fark edebilirsiniz. Bu doğrudur ve bunları bulmak adli bilişim uzmanının işinin bir parçasıdır.



## References

- [1] [GUID Bölümleme Tablosu - Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)
- [2] [Silinmiş dosyalara ilişkin kanıtları bulmak için NTFS $I30 (dizin) girdileri nasıl taranır](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
- [3] [Volume Shadow Copy Hizmeti (VSS)](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
- [4] [UEFI belirtimi: GPT disk düzeni](https://uefi.org/specs/UEFI/2.9_A/05_GUID_Partition_Table_Format.html)
- [5] [The Sleuth Kit mmls kılavuzu](https://sleuthkit.org/sleuthkit/man/mmls.html)
- [6] [The Sleuth Kit fsstat kılavuzu](https://www.sleuthkit.org/sleuthkit/man/fsstat.html)
- [7] [Microsoft FAT belirtimi](https://academy.cba.mit.edu/classes/networking_communications/SD/FAT.pdf)
- [8] [PhotoRec kurtarma seçenekleri](https://www.cgsecurity.org/testdisk_doc/photorec.html)
- [9] [TestDisk silinmiş bölüm kurtarma](https://www.cgsecurity.org/testdisk_doc/partition_recovery.html)
- [10] [sgdisk kılavuzu](https://manpages.debian.org/trixie/gdisk/sgdisk.8.en.html)
- [11] [mount(8) kılavuzu](https://man7.org/linux/man-pages/man8/mount.8.html)
{{#include ../../../banners/hacktricks-training.md}}
