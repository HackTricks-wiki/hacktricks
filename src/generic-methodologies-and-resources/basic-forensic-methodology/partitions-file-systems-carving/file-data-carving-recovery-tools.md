# File/Data Carving & Recovery Tools

{{#include ../../../banners/hacktricks-training.md}}

## Carving & Recovery tools

Her zaman orijinal cihaz yerine **doğrulanmış bir kopya** üzerinde carving yapın. Salt okunur edinim ve hash oluşturma iş akışları için [Image Acquisition & Mount](../image-acquisition-and-mount.md) sayfasına bakın.

Daha fazla araç için [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

Adli bilişimde imajlardan dosya çıkarmak için kullanılan en yaygın araç [**Autopsy**](https://www.autopsy.com/download/)'dir. İndirin, kurun ve "gizli" dosyaları bulması için dosyayı ingest etmesini sağlayın. Autopsy'nin disk imajlarını ve diğer imaj türlerini destekleyecek şekilde tasarlandığını, ancak basit dosyaları desteklemediğini unutmayın.

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk**, gömülü içerikleri bulmak için binary dosyaları analiz eden bir araçtır. **Binwalk v3**, otomatik extraction (`-e`), bilinen ve bilinmeyen nesnelerin raw carving işlemi (`-c`), recursive/Matryoshka scanning (`-M`) ve yapılandırılabilir worker thread'leri içeren Rust ile yeniden yazılmış bir sürümdür. Proje, tüm harici extractor'lar gerektiğinde Docker build'inin kullanılmasını önerir; `cargo install binwalk`, Rust CLI'yi kurar ancak bu harici bağımlılıkları kurmaz.<sup>[[11]](#references)</sup>

**Useful v3 commands**:
```bash
cargo install binwalk                 # CLI only; install extractors separately
binwalk firmware.bin                  # Identify embedded content
binwalk -e firmware.bin               # Extract recognised objects
binwalk -c -d carved firmware.bin     # Carve known and unknown objects
binwalk -Me -d extracted firmware.bin # Extract and recursively scan results
binwalk -e -l results.json firmware.bin
```
The legacy v2 `--dd='.*'` tarifi, **-c** seçeneğinin v3 eşdeğeri değildir; eski CTF/write-up komutlarını uygularken önce `binwalk --version` komutunu kontrol edin.<sup>[[11]](#references)</sup>

⚠️  **Güvenlik notu** – **2.1.2b ile 2.3.3** arasındaki sürümler bir **Path Traversal** güvenlik açığından (CVE-2022-4510) etkilenmektedir; advisory, yamalanmış bir pip sürümü listelememektedir. Etkilenen sürümlerle güvenilmeyen örnekleri çıkarmaktan kaçının veya aracı bir container/ayrıcalıksız UID ile izole edin.<sup>[[4]](#references)</sup>

### Foremost

Gizli dosyaları bulmak için kullanılan başka bir yaygın araç **foremost**'tur. Foremost'un yapılandırma dosyasını `/etc/foremost.conf` konumunda bulabilirsiniz. Yalnızca belirli dosyaları aramak istiyorsanız bunların yorum satırı işaretlerini kaldırın. Hiçbir satırın yorum satırı işaretlerini kaldırmazsanız foremost, varsayılan olarak yapılandırılmış dosya türlerini arar.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel**, **bir dosyanın içine gömülü dosyaları** bulmak ve çıkarmak için kullanılabilecek başka bir araçtır. Bu durumda, çıkarmasını istediğiniz dosya türlerinin yorum satırı işaretini yapılandırma dosyasından (_/etc/scalpel/scalpel.conf_) kaldırmanız gerekir.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor 2.x

Bu araç Kali ile birlikte gelir, ancak buradan da bulabilirsiniz: <https://github.com/simsong/bulk_extractor>

Bulk Extractor bir delil imajını tarayabilir ve **pcap fragments**, **network artefacts (URLs, domains, IPs, MACs, e-mails)** ile diğer birçok nesneyi **multiple scanners kullanarak paralel şekilde** carve edebilir.

v2.1.1 sürümü, bir Autotools build sürecini ve tüm bitişik JPEG'leri carve etmek için `-S jpeg_carve_mode=2` ayarını belgeler.<sup>[[2]](#references)</sup>
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
Birlikte gelen `bulk_diff.py`, iki bulk_extractor çalıştırmasının sonuçlarını karşılaştırırken `bulk_extractor_reader.py`, raporu ve feature dosyalarını okur.<sup>[[3]](#references)</sup>

### PhotoRec

Bunu <https://www.cgsecurity.org/wiki/TestDisk_Download> adresinde bulabilirsiniz.

GUI ve CLI sürümleriyle birlikte gelir. PhotoRec'in aramasını istediğiniz **file-types** seçeneklerini belirleyebilirsiniz.

![Her scanner'ı çalıştırın, JPEG'leri agresif şekilde carve edin ve bir bodyfile oluşturun - PhotoRec: GUI ve CLI sürümleriyle birlikte gelir. PhotoRec'in aramasını istediğiniz file-types seçeneklerini belirleyebilirsiniz](<../../../images/image (242).png>)

### The Sleuth Kit `tsk_recover` (metadata-first)

Raw signature carving işleminden önce, volume metadata'sı hâlâ parse edilebiliyorsa filesystem-aware recovery yöntemini deneyin. `tsk_recover`, varsayılan olarak yalnızca unallocated dosyaları dışa aktarır; `-a`, allocated dosyaları seçer ve `-e`, her ikisini de dışa aktarır. Whole-disk image için `mmls` çıktısındaki partition'ın **start sector** değerini `-o` seçeneğine verin (bunu byte'a dönüştürmeyin). Girdi zaten bir partition image ise `-o` seçeneğini kullanmayın.<sup>[[12]](#references)</sup>
```bash
sudo apt install sleuthkit
mmls disk.img                         # Note the partition start sector, e.g. 2048
mkdir recovered-deleted recovered-all
tsk_recover -o 2048 disk.img recovered-deleted/
tsk_recover -e -o 2048 disk.img recovered-all/
```
Bu işlem, filesystem kaynaklı adları ve yolları header/footer carving işleminin koruyamadığı durumlarda koruyabilir; metadata'sı eksik veya kullanılamaz olan girdiler için sonrasında Foremost, Scalpel veya PhotoRec çalıştırın.<sup>[[12]](#references)</sup>

### ddrescue + ddrescueview (arızalı sürücülerin imajının alınması)

Fiziksel bir sürücü kararsız olduğunda, en iyi uygulama **önce imajını almak** ve carving araçlarını yalnızca imaj üzerinde çalıştırmaktır. `ddrescue` (GNU project), okunamayan sektörlerin günlüğünü tutarak hatalı diskleri güvenilir biçimde kopyalamaya odaklanır.
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

Kaynak dosya sistemi Linux EXT tabanlıysa, **full carving** işlemi olmadan yakın zamanda silinen dosyaları kurtarabilirsiniz; bu günlük tabanlı araçlar unmounted bir dosya sistemi veya salt okunur bir image üzerinde çalışır.<sup>[[8]](#references)[[9]](#references)</sup>
```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Multi-stage recovery from an ext4 image
ext4magic disk.img -M -d ./recovered
```
> **Uyumluluk notu** – ext4magic terk edilmiştir; proje sayfası güncel dosya sistemlerinin artık bununla uyumlu olmadığını belirtmektedir.<sup>[[10]](#references)</sup>

> 🛈 Dosya sistemi silme işleminden sonra mount edildiyse veri blokları zaten yeniden kullanılmış olabilir – bu durumda uygun carving (Foremost/Scalpel) hâlâ gereklidir.

### binvis

[code](https://code.google.com/archive/p/binvis/) ve [web page tool](https://binvis.io/#/) araçlarını inceleyin.

#### BinVis Özellikleri

- Görsel ve aktif **structure viewer**
- Farklı odak noktaları için birden fazla plot
- Bir sample'ın belirli bölümlerine odaklanma
- Örneğin PE veya ELF executable'larında **string'leri ve resources'ları görme**
- Dosyalar üzerinde cryptanalysis için **pattern'ler** elde etme
- **Packer veya encoder algorithm'lerini tespit etme**
- Pattern'ler aracılığıyla **Steganography'yi belirleme**
- **Görsel** binary-diffing

BinVis, black-boxing senaryosunda **bilinmeyen bir target'a aşina olmak için harika bir başlangıç noktasıdır**.

## Specific Data Carving Tools

### FindAES

Key schedule'larını arayarak AES key'lerini arar. TrueCrypt ve BitLocker tarafından kullanılanlar gibi 128, 192 ve 256 bit key'leri bulabilir.

[Buradan](https://sourceforge.net/projects/findaes/) indirin.

### YARA-X (carved artefacts için triaging)

[YARA-X](https://github.com/VirusTotal/yara-x), 2024'te tanıtılan YARA'nın Rust ile yeniden yazılmış hâlidir; VirusTotal, bazı regular-expression ve complex-loop rule'larının önemli ölçüde daha hızlı çalışabildiğini bildirmektedir.<sup>[[5]](#references)</sup> CLI'ı `yr` olarak adlandırılır ve `scan` command'i recursive scan'leri, thread sayısını ve metadata output'unu destekler.<sup>[[6]](#references)</sup>
```bash
# Scan every carved object produced by bulk_extractor
yr scan --recursive --threads 8 --print-meta rules/index.yar out_folder/
```
## Tamamlayıcı araçlar

Terminalden görüntüleri görmek için [**viu** ](https://github.com/atanunq/viu) kullanabilirsiniz.  \
Bir pdf dosyasını metne dönüştürmek ve okumak için Linux komut satırı aracı **pdftotext**'i kullanabilirsiniz.





## References

- [1] [Autopsy 4.21 sürüm notları](https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21.0)
- [2] [bulk_extractor v2.1.1 README](https://github.com/simsong/bulk_extractor/blob/v2.1.1/README.md)
- [3] [bulk_extractor Python araçları README](https://raw.githubusercontent.com/simsong/bulk_extractor/v2.1.1/python/README.txt)
- [4] [binwalk'de path traversal (CVE-2022-4510) - GitHub Advisory Database](https://github.com/advisories/GHSA-3cm8-v4mc-gppg)
- [5] [YARA öldü, çok yaşa YARA-X - VirusTotal Blog](https://blog.virustotal.com/2024/05/yara-is-dead-long-live-yara-x.html)
- [6] [YARA-X CLI komutları](https://virustotal.github.io/yara-x/docs/cli/commands/)
- [7] [GNU ddrescue kılavuzu](https://www.gnu.org/software/ddrescue/manual/ddrescue_manual.html)
- [8] [extundelete](https://extundelete.sourceforge.net/)
- [9] [ext4magic kılavuzu](https://ext4magic.sourceforge.net/manpage_en.html)
- [10] [ext4magic proje durumu](https://sourceforge.net/projects/ext4magic/)
- [11] [Binwalk v3 README](https://github.com/ReFirmLabs/binwalk/blob/master/README.md)
- [12] [The Sleuth Kit: tsk_recover kılavuzu](https://sleuthkit.org/sleuthkit/man/tsk_recover.html)
{{#include ../../../banners/hacktricks-training.md}}
