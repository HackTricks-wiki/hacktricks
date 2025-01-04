# File/Data Carving & Recovery Tools

{{#include ../../../banners/hacktricks-training.md}}

## Carving & Recovery tools

Daha fazla araç için [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

Görüntülerden dosya çıkarmak için adli bilimlerde en yaygın kullanılan araç [**Autopsy**](https://www.autopsy.com/download/)'dir. İndirin, kurun ve "gizli" dosyaları bulmak için dosyayı içe aktarmasını sağlayın. Autopsy'nin disk görüntüleri ve diğer türdeki görüntüleri desteklemek için tasarlandığını, ancak basit dosyalar için tasarlanmadığını unutmayın.

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk**, gömülü içeriği bulmak için ikili dosyaları analiz etmek için bir araçtır. `apt` ile kurulabilir ve kaynak kodu [GitHub](https://github.com/ReFirmLabs/binwalk)'ta bulunmaktadır.

**Kullanışlı komutlar**:
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
### Foremost

Başka bir yaygın araç, gizli dosyaları bulmak için **foremost**'tur. Foremost'un yapılandırma dosyasını `/etc/foremost.conf` içinde bulabilirsiniz. Eğer sadece belirli dosyaları aramak istiyorsanız, bunların yorumunu kaldırın. Eğer hiçbirinin yorumunu kaldırmazsanız, foremost varsayılan olarak yapılandırılmış dosya türlerini arayacaktır.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel**, bir dosya içinde gömülü **dosyaları** bulmak ve çıkarmak için kullanılabilecek bir diğer araçtır. Bu durumda, çıkarmak istediğiniz dosya türlerini yapılandırma dosyasından (_/etc/scalpel/scalpel.conf_) yorum satırından çıkarmanız gerekecektir.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor

Bu araç kali içinde gelir ama burada bulabilirsiniz: [https://github.com/simsong/bulk_extractor](https://github.com/simsong/bulk_extractor)

Bu araç bir görüntüyü tarayabilir ve içindeki **pcap'leri** **çıkartır**, **ağ bilgilerini (URL'ler, alan adları, IP'ler, MAC'ler, mailler)** ve daha fazla **dosyayı** alır. Yapmanız gereken tek şey:
```
bulk_extractor memory.img -o out_folder
```
Tüm bilgileri (şifreler?) toplayan aracın üzerinden geçin, **analiz** edin, **paketleri** (okuyun [**Pcaps analizi**](../pcap-inspection/index.html)), **garip alan adları** arayın (kötü amaçlı yazılımlarla veya **var olmayan** alan adlarıyla ilgili).

### PhotoRec

Bunu [https://www.cgsecurity.org/wiki/TestDisk_Download](https://www.cgsecurity.org/wiki/TestDisk_Download) adresinde bulabilirsiniz.

GUI ve CLI sürümleri ile gelir. PhotoRec'in aramasını istediğiniz **dosya türlerini** seçebilirsiniz.

![](<../../../images/image (524).png>)

### binvis

[Kod](https://code.google.com/archive/p/binvis/) ve [web sayfası aracı](https://binvis.io/#/) kontrol edin.

#### BinVis Özellikleri

- Görsel ve aktif **yapı görüntüleyici**
- Farklı odak noktaları için birden fazla grafik
- Bir örneğin bölümlerine odaklanma
- PE veya ELF yürütülebilir dosyalarda **dize ve kaynakları** görme
- Dosyalar üzerinde kriptoanaliz için **desenler** elde etme
- **Packer** veya kodlayıcı algoritmalarını **belirleme**
- Desenler ile Steganografi **tanımlama**
- **Görsel** ikili fark analizi

BinVis, bir kara kutu senaryosunda bilinmeyen bir hedefle tanışmak için harika bir **başlangıç noktasıdır**.

## Özel Veri Karıştırma Araçları

### FindAES

AES anahtarlarını anahtar programlarını arayarak bulur. TrueCrypt ve BitLocker gibi 128, 192 ve 256 bit anahtarları bulabilir.

[Buradan](https://sourceforge.net/projects/findaes/) indirin.

## Tamamlayıcı araçlar

Terminalden görüntüleri görmek için [**viu** ](https://github.com/atanunq/viu) kullanabilirsiniz.\
Bir pdf'yi metne dönüştürmek ve okumak için linux komut satırı aracı **pdftotext** kullanabilirsiniz.

{{#include ../../../banners/hacktricks-training.md}}
