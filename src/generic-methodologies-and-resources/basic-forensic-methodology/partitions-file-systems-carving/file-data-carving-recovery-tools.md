# File/Data Carving & Recovery Tools

{{#include ../../../banners/hacktricks-training.md}}

## Carving & Recovery tools

Daha fazla araç için [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

Görüntülerden dosya çıkarmak için adli bilimlerde en yaygın kullanılan araç [**Autopsy**](https://www.autopsy.com/download/)'dir. İndirin, kurun ve "gizli" dosyaları bulmak için dosyayı içe aktarmasını sağlayın. Autopsy'nin disk görüntüleri ve diğer türdeki görüntüleri destekleyecek şekilde tasarlandığını, ancak basit dosyaları desteklemediğini unutmayın.

> **2024-2025 güncellemesi** – **4.21** sürümü (Şubat 2025'te yayımlandı) çoklu terabayt görüntüleriyle başa çıkarken belirgin şekilde daha hızlı olan ve çok çekirdekli sistemlerde paralel çıkarımı destekleyen yeniden yapılandırılmış **carving modülü** ekledi.¹ Ayrıca, CI/CD veya büyük ölçekli laboratuvar ortamlarında carving'i betiklemek mümkün kılan küçük bir CLI sarmalayıcı (`autopsycli ingest <case> <image>`) tanıtıldı.
```bash
# Create a case and ingest an evidence image from the CLI (Autopsy ≥4.21)
autopsycli case --create MyCase --base /cases
# ingest with the default ingest profile (includes data-carve module)
autopsycli ingest MyCase /evidence/disk01.E01 --threads 8
```
### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk**, gömülü içeriği bulmak için ikili dosyaları analiz eden bir araçtır. `apt` ile kurulabilir ve kaynak kodu [GitHub](https://github.com/ReFirmLabs/binwalk)'ta bulunmaktadır.

**Kullanışlı komutlar**:
```bash
sudo apt install binwalk         # Installation
binwalk firmware.bin             # Display embedded data
binwalk -e firmware.bin          # Extract recognised objects (safe-default)
binwalk --dd " .* " firmware.bin  # Extract *everything* (use with care)
```
⚠️  **Güvenlik notu** – Sürümler **≤2.3.3** bir **Path Traversal** güvenlik açığından (CVE-2022-4510) etkilenmektedir. Güvensiz örnekleri kesmeden önce güncelleyin (veya bir konteyner/özel olmayan UID ile izole edin).

### Foremost

Gizli dosyaları bulmak için başka bir yaygın araç **foremost**'tur. Foremost'un yapılandırma dosyasını `/etc/foremost.conf` içinde bulabilirsiniz. Belirli dosyaları aramak istiyorsanız, bunların yorumunu kaldırın. Hiçbir şeyi yorumdan çıkarmazsanız, foremost varsayılan olarak yapılandırılmış dosya türlerini arayacaktır.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel**, bir dosya içinde gömülü **dosyaları** bulmak ve çıkarmak için kullanılabilecek başka bir araçtır. Bu durumda, çıkarmak istediğiniz dosya türlerini yapılandırma dosyasından (_/etc/scalpel/scalpel.conf_) yorum satırından çıkarmanız gerekecektir.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor 2.x

Bu araç kali içinde gelir ama burada bulabilirsiniz: <https://github.com/simsong/bulk_extractor>

Bulk Extractor, bir kanıt görüntüsünü tarayabilir ve **pcap parçalarını**, **ağ nesnelerini (URL'ler, alan adları, IP'ler, MAC'ler, e-postalar)** ve birçok diğer nesneyi **birden fazla tarayıcı kullanarak paralel olarak** çıkarabilir.
```bash
# Build from source – v2.1.1 (April 2024) requires cmake ≥3.16
git clone https://github.com/simsong/bulk_extractor.git && cd bulk_extractor
mkdir build && cd build && cmake .. && make -j$(nproc) && sudo make install

# Run every scanner, carve JPEGs aggressively and generate a bodyfile
bulk_extractor -o out_folder -S jpeg_carve_mode=2 -S write_bodyfile=y /evidence/disk.img
```
Kullanışlı post-processing scriptleri (`bulk_diff`, `bulk_extractor_reader.py`), iki görüntü arasındaki artefaktları de-duplicate edebilir veya sonuçları SIEM alımı için JSON'a dönüştürebilir.

### PhotoRec

Bunu <https://www.cgsecurity.org/wiki/TestDisk_Download> adresinde bulabilirsiniz.

GUI ve CLI sürümleri ile gelir. PhotoRec'in aramasını istediğiniz **dosya türlerini** seçebilirsiniz.

![](<../../../images/image (242).png>)

### ddrescue + ddrescueview (başarısız sürücülerin görüntülenmesi)

Bir fiziksel sürücü istikrarsız olduğunda, en iyi uygulama **önce görüntü almak** ve yalnızca görüntü üzerinde carving araçlarını çalıştırmaktır. `ddrescue` (GNU projesi), okunamayan sektörlerin kaydını tutarak bozuk diskleri güvenilir bir şekilde kopyalamaya odaklanır.
```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
ddrescueview suspect.log
```
Version **1.28** (Aralık 2024) **`--cluster-size`** seçeneğini tanıttı; bu, geleneksel sektör boyutlarının artık flash bloklarıyla hizalanmadığı yüksek kapasiteli SSD'lerin görüntülenmesini hızlandırabilir.

### Extundelete / Ext4magic (EXT 3/4 geri yükleme)

Kaynak dosya sistemi Linux EXT tabanlıysa, yakın zamanda silinmiş dosyaları **tam carving olmadan** kurtarabilirsiniz. Her iki araç da yalnızca okunabilir bir görüntü üzerinde doğrudan çalışır:
```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Fallback to full directory scan; supports extents and inline data
ext4magic disk.img -M -f '*.jpg' -d ./recovered
```
> 🛈 Eğer dosya sistemi silindikten sonra monte edildiyse, veri blokları zaten yeniden kullanılmış olabilir - bu durumda uygun carving (Foremost/Scalpel) hala gereklidir.

### binvis

[code](https://code.google.com/archive/p/binvis/) ve [web page tool](https://binvis.io/#/) kontrol edin.

#### BinVis'in Özellikleri

- Görsel ve aktif **yapı görüntüleyici**
- Farklı odak noktaları için birden fazla grafik
- Bir örneğin bölümlerine odaklanma
- PE veya ELF yürütülebilir dosyalarda **dize ve kaynakları görme**
- Dosyalar üzerinde kriptoanaliz için **desenler** elde etme
- **Packer** veya kodlayıcı algoritmalarını **belirleme**
- Desenler ile Steganografi **tanımlama**
- **Görsel** ikili fark analizi

BinVis, bir kara kutu senaryosunda bilinmeyen bir hedefle tanışmak için harika bir **başlangıç noktasıdır**.

## Özel Veri Carving Araçları

### FindAES

Anahtar programlarını arayarak AES anahtarlarını arar. TrueCrypt ve BitLocker gibi 128, 192 ve 256 bit anahtarları bulabilir.

[Buradan](https://sourceforge.net/projects/findaes/) indirin.

### YARA-X (carved artefaktların önceliklendirilmesi)

[YARA-X](https://github.com/VirusTotal/yara-x), 2024'te yayımlanan YARA'nın Rust ile yeniden yazımıdır. Klasik YARA'dan **10-30× daha hızlıdır** ve binlerce carved nesneyi çok hızlı bir şekilde sınıflandırmak için kullanılabilir:
```bash
# Scan every carved object produced by bulk_extractor
yarax -r rules/index.yar out_folder/ --threads 8 --print-meta
```
Hızlandırma, büyük ölçekli araştırmalarda tüm carved dosyaları **auto-tag** yapmayı gerçekçi hale getiriyor.

## Tamamlayıcı araçlar

Terminalden görüntüleri görmek için [**viu** ](https://github.com/atanunq/viu) kullanabilirsiniz.  \
Bir pdf'yi metne dönüştürmek ve okumak için linux komut satırı aracı **pdftotext** kullanabilirsiniz.

## Referanslar

1. Autopsy 4.21 sürüm notları – <https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21>
{{#include ../../../banners/hacktricks-training.md}}
