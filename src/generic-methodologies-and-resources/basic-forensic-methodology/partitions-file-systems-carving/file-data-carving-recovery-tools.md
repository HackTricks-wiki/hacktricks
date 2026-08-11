# File/Data Carving ve Recovery Tools

{{#include ../../../banners/hacktricks-training.md}}

## Carving ve Recovery tools

Daha fazla tool için [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

Forensics'te image'lardan file çıkarmak için kullanılan en yaygın tool [**Autopsy**](https://www.autopsy.com/download/)'dir. Download edin, install edin ve "hidden" file'ları bulması için file'ı ingest etmesini sağlayın. Autopsy'nin disk image'larını ve diğer image türlerini destekleyecek şekilde tasarlandığını, ancak basit file'ları desteklemediğini unutmayın.

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk**, embedded content bulmak için binary file'ları analiz eden bir tool'dur. `apt` aracılığıyla install edilebilir ve source code'u [GitHub](https://github.com/ReFirmLabs/binwalk) üzerindedir.

**Useful commands**:
```bash
sudo apt install binwalk         # Installation
binwalk firmware.bin             # Display embedded data
binwalk -e firmware.bin          # Extract recognised objects (safe-default)
binwalk --dd " .* " firmware.bin  # Extract *everything* (use with care)
```
⚠️  **Güvenlik notu** – **2.1.2b ile 2.3.3 arasındaki** sürümler bir **Path Traversal** güvenlik açığından (CVE-2022-4510) etkilenmektedir; advisory, yamalanmış bir pip sürümü listelememektedir. Etkilenen sürümlerle güvenilmeyen sample'ları çıkarmaktan kaçının veya aracı bir container/non-privileged UID ile izole edin.<sup>[[4]](#references)</sup>

### Foremost

Gizli dosyaları bulmak için kullanılan bir diğer yaygın araç **foremost**'tur. foremost'un configuration dosyasını `/etc/foremost.conf` konumunda bulabilirsiniz. Yalnızca belirli dosyaları aramak istiyorsanız bunların yorum işaretlerini kaldırın. Hiçbir şeyin yorum işaretini kaldırmazsanız foremost, varsayılan olarak yapılandırılmış dosya türlerini arar.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel**, **bir dosyaya gömülü dosyaları** bulmak ve çıkarmak için kullanılabilecek başka bir araçtır. Bu durumda, çıkarmasını istediğiniz dosya türlerinin açıklama satırı işaretini configuration file (_/etc/scalpel/scalpel.conf_) içinden kaldırmanız gerekir.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor 2.x

Bu araç kali ile birlikte gelir, ancak buradan da bulabilirsiniz: <https://github.com/simsong/bulk_extractor>

Bulk Extractor bir evidence image'ı tarayabilir ve **pcap fragments**, **network artefacts (URLs, domains, IPs, MACs, e-mails)** ile diğer birçok nesneyi **birden fazla scanner kullanarak paralel şekilde** carve edebilir.

v2.1.1 sürümü, Autotools build sürecini ve tüm bitişik JPEG'leri carve etmek için `-S jpeg_carve_mode=2` ayarını belgeler.<sup>[[2]](#references)</sup>
```bash
# Build from source – v2.1.1 (April 2024) requires C++17
git clone --branch v2.1.1 --recurse-submodules https://github.com/simsong/bulk_extractor.git
cd bulk_extractor
./bootstrap.sh
./configure
make -j"$(nproc)"
sudo make install

# Scan an image and carve contiguous JPEGs
bulk_extractor -o out_folder -S jpeg_carve_mode=2 /evidence/disk.img
```
Bundled `bulk_diff.py`, iki bulk_extractor çalıştırmasının sonuçlarını karşılaştırırken `bulk_extractor_reader.py`, report ve feature dosyalarını okur.<sup>[[3]](#references)</sup>

### PhotoRec

Bunu <https://www.cgsecurity.org/wiki/TestDisk_Download> adresinde bulabilirsiniz.

GUI ve CLI sürümleriyle birlikte gelir. PhotoRec'in aramasını istediğiniz **dosya türlerini** seçebilirsiniz.

![Her scanner'ı çalıştırın, JPEG'leri agresif şekilde carve edin ve bir bodyfile oluşturun - PhotoRec: GUI ve CLI sürümleriyle birlikte gelir. PhotoRec'in aramasını istediğiniz dosya türlerini seçebilirsiniz](<../../../images/image (242).png>)

### ddrescue + ddrescueview (arızalı sürücüleri imaging)

Fiziksel bir sürücü kararsız olduğunda, en iyi uygulama **önce image'ını almak** ve carving araçlarını yalnızca image üzerinde çalıştırmaktır. `ddrescue` (GNU project), okunamayan sektörlerin log'unu tutarken bozuk diskleri güvenilir şekilde kopyalamaya odaklanır.
```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
ddrescueview suspect.log
```
**`--cluster-size`** seçeneği, bir seferde kaç sektörün kopyalanacağını kontrol eder; daha küçük değerler yavaş disklerde yardımcı olabilir.<sup>[[7]](#references)</sup>

### Extundelete / Ext4magic (EXT 3/4 undelete)

Kaynak dosya sistemi Linux EXT tabanlıysa, **full carving** işlemi yapmadan yakın zamanda silinen dosyaları kurtarabilirsiniz; bu journal tabanlı araçlar unmounted bir dosya sistemi veya salt okunur bir imaj üzerinde çalışır.<sup>[[8]](#references)[[9]](#references)</sup>
```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Multi-stage recovery from an ext4 image
ext4magic disk.img -M -d ./recovered
```
> **Uyumluluk notu** – ext4magic terk edilmiştir; proje sayfası mevcut dosya sistemlerinin artık bununla uyumlu olmadığını belirtir.<sup>[[10]](#references)</sup>

> 🛈 Dosya sistemi silme işleminden sonra bağlandıysa veri blokları zaten yeniden kullanılmış olabilir – bu durumda uygun carving (Foremost/Scalpel) hâlâ gereklidir.

### binvis

[code](https://code.google.com/archive/p/binvis/) ve [web page tool](https://binvis.io/#/) araçlarını inceleyin.

#### BinVis Özellikleri

- Görsel ve aktif **structure viewer**
- Farklı odak noktaları için birden çok grafik
- Bir örneğin belirli bölümlerine odaklanma
- Örneğin PE veya ELF çalıştırılabilirlerinde **string'leri ve kaynakları görme**
- Dosyalarda kriptanaliz için **pattern'ler** elde etme
- **Packer** veya encoder algoritmalarını **belirleme**
- Pattern'ler aracılığıyla **Steganography tespit etme**
- **Görsel** binary-diffing

BinVis, black-boxing senaryosunda **bilinmeyen bir hedefe aşina olmak için harika bir başlangıç noktasıdır**.

## Özel Data Carving Araçları

### FindAES

Anahtar schedule'larını arayarak AES anahtarlarını arar. TrueCrypt ve BitLocker tarafından kullanılanlar gibi 128, 192 ve 256 bit anahtarları bulabilir.

[Buradan](https://sourceforge.net/projects/findaes/) indirin.

### YARA-X (carving ile çıkarılmış artefaktların önceliklendirilmesi)

[YARA-X](https://github.com/VirusTotal/yara-x), 2024'te tanıtılan YARA'nın Rust ile yeniden yazılmış sürümüdür; VirusTotal, bazı regular-expression ve complex-loop rule'larının önemli ölçüde daha hızlı çalışabildiğini bildirir.<sup>[[5]](#references)</sup> CLI adı `yr`'dir ve `scan` komutu recursive scan, thread sayısı ve metadata çıktısını destekler.<sup>[[6]](#references)</sup>
```bash
# Scan every carved object produced by bulk_extractor
yr scan --recursive --threads 8 --print-meta rules/index.yar out_folder/
```
## Tamamlayıcı araçlar

Terminalden görüntüleri görmek için [**viu** ](https://github.com/atanunq/viu) kullanabilirsiniz.  \
Bir pdf dosyasını metne dönüştürmek ve okumak için Linux komut satırı aracı **pdftotext** kullanabilirsiniz.



## References

- [1] [Autopsy 4.21 sürüm notları](https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21.0)
- [2] [bulk_extractor v2.1.1 README](https://github.com/simsong/bulk_extractor/blob/v2.1.1/README.md)
- [3] [bulk_extractor Python araçları README](https://raw.githubusercontent.com/simsong/bulk_extractor/v2.1.1/python/README.txt)
- [4] [binwalk'da path traversal (CVE-2022-4510) - GitHub Advisory Database](https://github.com/advisories/GHSA-3cm8-v4mc-gppg)
- [5] [YARA öldü, çok yaşa YARA-X - VirusTotal Blog](https://blog.virustotal.com/2024/05/yara-is-dead-long-live-yara-x.html)
- [6] [YARA-X CLI komutları](https://virustotal.github.io/yara-x/docs/cli/commands/)
- [7] [GNU ddrescue kılavuzu](https://www.gnu.org/software/ddrescue/manual/ddrescue_manual.html)
- [8] [extundelete](https://extundelete.sourceforge.net/)
- [9] [ext4magic kılavuzu](https://ext4magic.sourceforge.net/manpage_en.html)
- [10] [ext4magic proje durumu](https://sourceforge.net/projects/ext4magic/)
{{#include ../../../banners/hacktricks-training.md}}
