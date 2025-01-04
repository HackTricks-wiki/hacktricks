{{#include ../../../banners/hacktricks-training.md}}

# Carving araçları

## Autopsy

Görüntülerden dosya çıkarmak için adli bilimlerde en yaygın kullanılan araç [**Autopsy**](https://www.autopsy.com/download/)'dir. Bunu indirin, kurun ve "gizli" dosyaları bulmak için dosyayı içe aktarmasını sağlayın. Autopsy'nin disk görüntüleri ve diğer türdeki görüntüleri desteklemek için tasarlandığını, ancak basit dosyalar için tasarlanmadığını unutmayın.

## Binwalk <a id="binwalk"></a>

**Binwalk**, gömülü dosyalar ve veriler için görüntüler ve ses dosyaları gibi ikili dosyaları aramak için bir araçtır. `apt` ile kurulabilir, ancak [kaynağı](https://github.com/ReFirmLabs/binwalk) github'da bulunabilir.  
**Kullanışlı komutlar**:
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
## Foremost

Başka bir yaygın araç **foremost** ile gizli dosyaları bulmaktır. Foremost'un yapılandırma dosyasını `/etc/foremost.conf` içinde bulabilirsiniz. Eğer sadece belirli dosyaları aramak istiyorsanız, bunların yorumunu kaldırın. Eğer hiçbir şeyin yorumunu kaldırmazsanız, foremost varsayılan olarak yapılandırılmış dosya türlerini arayacaktır.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
## **Scalpel**

**Scalpel**, bir dosya içinde gömülü **dosyaları** bulmak ve çıkarmak için kullanılabilecek bir diğer araçtır. Bu durumda, çıkarmak istediğiniz dosya türlerini yapılandırma dosyasından (_/etc/scalpel/scalpel.conf_) yorum satırından çıkarmanız gerekecektir.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
## Bulk Extractor

Bu araç kali içinde gelir ama burada bulabilirsiniz: [https://github.com/simsong/bulk_extractor](https://github.com/simsong/bulk_extractor)

Bu araç bir görüntüyü tarayabilir ve içindeki **pcap'leri** **çıkartabilir**, **ağ bilgilerini (URL'ler, alan adları, IP'ler, MAC'ler, mailler)** ve daha fazla **dosyayı** alabilir. Yapmanız gereken tek şey:
```text
bulk_extractor memory.img -o out_folder
```
Tüm bilgileri gözden geçirin \(şifreler?\), **analiz** edin **paketleri** \(okuyun [ **Pcaps analizi**](../pcap-inspection/index.html)\), **garip alan adları** arayın \(**kötü amaçlı yazılım** ile ilgili veya **var olmayan** alan adları\).

## PhotoRec

Bunu [https://www.cgsecurity.org/wiki/TestDisk_Download](https://www.cgsecurity.org/wiki/TestDisk_Download) adresinde bulabilirsiniz.

GUI ve CLI sürümü ile gelir. PhotoRec'in aramasını istediğiniz **dosya türlerini** seçebilirsiniz.

![](../../../images/image%20%28524%29.png)

# Özel Veri Kazıma Araçları

## FindAES

Anahtar programlarını arayarak AES anahtarlarını arar. TrueCrypt ve BitLocker tarafından kullanılan 128, 192 ve 256 bit anahtarları bulabilir.

[Buradan](https://sourceforge.net/projects/findaes/) indirin.

# Tamamlayıcı araçlar

Terminalden görüntüleri görmek için [**viu** ](https://github.com/atanunq/viu) kullanabilirsiniz. 
Bir pdf'yi metne dönüştürmek ve okumak için linux komut satırı aracı **pdftotext** kullanabilirsiniz.

{{#include ../../../banners/hacktricks-training.md}}
