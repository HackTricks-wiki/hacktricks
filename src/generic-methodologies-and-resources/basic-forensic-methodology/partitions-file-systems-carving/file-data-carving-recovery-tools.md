# Dosya/Veri Carving ve Kurtarma Araçları

## Carving ve Kurtarma araçları

[https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery) adresinde daha fazla araç bulunmaktadır.

### Autopsy

Adli bilişimde imajlardan dosya çıkarmak için kullanılan en yaygın araç [**Autopsy**](https://www.autopsy.com/download/)'dir. İndirin, kurun ve "gizli" dosyaları bulması için dosyayı içeri aktarmasını sağlayın. Autopsy'nin disk imajlarını ve diğer imaj türlerini destekleyecek şekilde tasarlandığını, ancak basit dosyaları desteklemediğini unutmayın.

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk**, gömülü içeriği bulmak amacıyla binary dosyaları analiz etmeye yarayan bir araçtır. `apt` üzerinden kurulabilir ve kaynak kodu [GitHub](https://github.com/ReFirmLabs/binwalk) üzerindedir.

**Useful commands**:
```bash
sudo apt install binwalk         # Installation
binwalk firmware.bin             # Display embedded data
binwalk -e firmware.bin          # Extract recognised objects (safe-default)
binwalk --dd " .* " firmware.bin  # Extract *everything* (use with care)
```
⚠️  **Security note** – **2.1.2b ile 2.3.3** arasındaki sürümler bir **Path Traversal** güvenlik açığından (CVE-2022-4510) etkilenmektedir; advisory, yamalanmış bir pip sürümü listelememektedir. Etkilenen sürümlerle güvenilmeyen örnekleri çıkarmaktan kaçının veya aracı bir container/non-privileged UID ile izole edin.<sup>[[4]](#references)</sup>

### Foremost

Gizli dosyaları bulmak için kullanılan diğer yaygın araç **foremost**'tur. foremost'un yapılandırma dosyasını `/etc/foremost.conf` konumunda bulabilirsiniz. Yalnızca belirli dosyaları aramak istiyorsanız ilgili satırların yorumunu kaldırın. Hiçbir satırın yorumunu kaldırmazsanız foremost, varsayılan olarak yapılandırılmış dosya türlerini arar.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel**, **bir dosyaya gömülü dosyaları** bulmak ve çıkarmak için kullanılabilecek başka bir araçtır. Bu durumda, çıkarmasını istediğiniz dosya türlerinin yapılandırma dosyasındaki (_/etc/scalpel/scalpel.conf_) yorum işaretlerini kaldırmanız gerekir.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor 2.x

Bu araç kali ile birlikte gelir, ancak burada bulabilirsiniz: <https://github.com/simsong/bulk_extractor>

Bulk Extractor, bir evidence image'ı tarayabilir ve **pcap parçalarını**, **ağ artefact'larını (URL'ler, domain'ler, IP'ler, MAC'ler, e-postalar)** ve diğer birçok nesneyi **birden fazla scanner kullanarak paralel şekilde** carve edebilir.

v2.1.1 sürümü, bir Autotools build sürecini ve tüm bitişik JPEG'leri carve etmek için kullanılan `-S jpeg_carve_mode=2` ayarını belgelemektedir.<sup>[[2]](#references)</sup>
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
The bundled `bulk_diff.py`, iki bulk_extractor çalıştırmasının sonuçlarını karşılaştırırken `bulk_extractor_reader.py`, report ve feature dosyalarını okur.<sup>[[3]](#references)</sup>

### PhotoRec

Bunu <https://www.cgsecurity.org/wiki/TestDisk_Download> adresinde bulabilirsiniz.

GUI ve CLI sürümleriyle birlikte gelir. PhotoRec'in aramasını istediğiniz **file-types** seçeneklerini belirleyebilirsiniz.

![Her scanner'ı çalıştırın, JPEG'leri agresif şekilde carve edin ve bir bodyfile oluşturun - PhotoRec: GUI ve CLI sürümleriyle birlikte gelir. PhotoRec'in aramasını istediğiniz file-types seçeneklerini belirleyebilirsiniz](<../../../images/image (242).png>)

### ddrescue + ddrescueview (arızalı sürücülerin imaging işlemi)

Fiziksel bir sürücü kararsız olduğunda, en iyi uygulama önce **image'ını almak** ve carving araçlarını yalnızca image üzerinde çalıştırmaktır. `ddrescue` (GNU project), okunamayan sektörlerin günlüğünü tutarken bozuk diskleri güvenilir şekilde kopyalamaya odaklanır.
```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
ddrescueview suspect.log
```
**`--cluster-size`** seçeneği, her seferinde kaç sektörün kopyalanacağını kontrol eder; daha küçük değerler yavaş sürücülerde yardımcı olabilir.<sup>[[7]](#references)</sup>

### Extundelete / Ext4magic (EXT 3/4 undelete)

Kaynak dosya sistemi Linux EXT tabanlıysa, **full carving** işlemi gerçekleştirmeden yakın zamanda silinen dosyaları kurtarabilirsiniz; bu journal tabanlı araçlar unmounted bir dosya sistemi veya salt okunur bir image üzerinde çalışır.<sup>[[8]](#references)[[9]](#references)</sup>
```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Multi-stage recovery from an ext4 image
ext4magic disk.img -M -d ./recovered
```
> **Uyumluluk notu** – ext4magic terk edilmiştir; proje sayfası, mevcut dosya sistemlerinin artık onunla uyumlu olmadığını belirtmektedir.<sup>[[10]](#references)</sup>

> 🛈 Dosya sistemi silme işleminden sonra mount edildiyse veri blokları zaten yeniden kullanılmış olabilir – bu durumda uygun carving (Foremost/Scalpel) hâlâ gereklidir.

### binvis

[code](https://code.google.com/archive/p/binvis/) ve [web page tool](https://binvis.io/#/) araçlarına göz atın.

#### BinVis Özellikleri

- Görsel ve aktif **structure viewer**
- Farklı odak noktaları için birden çok plot
- Bir sample'ın bölümlerine odaklanma
- Örneğin PE veya ELF executable'larında **string'leri ve resource'ları görme**
- Dosyalarda cryptanalysis için **pattern'ler** elde etme
- **Packer veya encoder algorithm'larını tespit etme**
- Pattern'ler aracılığıyla **Steganography'yi tespit etme**
- **Görsel** binary-diffing

BinVis, black-boxing senaryosunda **bilinmeyen bir target'a aşinalık kazanmak için harika bir başlangıç noktasıdır**.

## Specific Data Carving Tools

### FindAES

Key schedule'larını arayarak AES key'lerini arar. TrueCrypt ve BitLocker tarafından kullanılanlar gibi 128, 192 ve 256 bit key'leri bulabilir.

[Buradan](https://sourceforge.net/projects/findaes/) indirin.

### YARA-X (carved artefact'lerin triage'ı)

[YARA-X](https://github.com/VirusTotal/yara-x), 2024'te tanıtılan ve Rust ile yeniden yazılmış bir YARA sürümüdür; VirusTotal, bazı regular-expression ve complex-loop rule'larının önemli ölçüde daha hızlı çalışabildiğini bildirmektedir.<sup>[[5]](#references)</sup> CLI'ı `yr` olarak adlandırılır ve `scan` command'i recursive scan'leri, thread sayısını ve metadata output'unu destekler.<sup>[[6]](#references)</sup>
```bash
# Scan every carved object produced by bulk_extractor
yr scan --recursive --threads 8 --print-meta rules/index.yar out_folder/
```
## Tamamlayıcı araçlar

Terminalden görüntüleri görmek için [**viu** ](https://github.com/atanunq/viu)kullanabilirsiniz.  \
Bir pdf dosyasını metne dönüştürmek ve okumak için linux komut satırı aracı **pdftotext**'i kullanabilirsiniz.



## References

- [1] [Autopsy 4.21 sürüm notları](https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21.0)
- [2] [bulk_extractor v2.1.1 README](https://github.com/simsong/bulk_extractor/blob/v2.1.1/README.md)
- [3] [bulk_extractor Python araçları README](https://raw.githubusercontent.com/simsong/bulk_extractor/v2.1.1/python/README.txt)
- [4] [binwalk'da path traversal (CVE-2022-4510) - GitHub Advisory Database](https://github.com/advisories/GHSA-3cm8-v4mc-gppg)
- [5] [YARA öldü, yaşasın YARA-X - VirusTotal Blog](https://blog.virustotal.com/2024/05/yara-is-dead-long-live-yara-x.html)
- [6] [YARA-X CLI komutları](https://virustotal.github.io/yara-x/docs/cli/commands/)
- [7] [GNU ddrescue kılavuzu](https://www.gnu.org/software/ddrescue/manual/ddrescue_manual.html)
- [8] [extundelete](https://extundelete.sourceforge.net/)
- [9] [ext4magic kılavuzu](https://ext4magic.sourceforge.net/manpage_en.html)
- [10] [ext4magic projesi durumu](https://sourceforge.net/projects/ext4magic/)
{{#include ../../../banners/hacktricks-training.md}}
