# File/Data Carving ve Recovery Tools

{{#include ../../../banners/hacktricks-training.md}}

## Carving ve Recovery tools

Daha fazla tool için [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

Forensics'te image'lerden file çıkarmak için kullanılan en yaygın tool [**Autopsy**](https://www.autopsy.com/download/)'dir. Tool'u indirin, kurun ve "hidden" file'ları bulması için file'ı ingest etmesini sağlayın. Autopsy'nin disk image'lerini ve diğer image türlerini destekleyecek şekilde tasarlandığını, ancak basit file'ları desteklemediğini unutmayın.

> **2024-2025 update** – Şubat 2025'te yayımlanan **4.21** sürümü, **SleuthKit v4.13** tabanlı yeniden oluşturulmuş bir **carving module** ekledi. Bu module, multi-terabyte image'lerle çalışırken fark edilir ölçüde daha hızlıdır ve multi-core sistemlerde parallel extraction desteği sunar. Ayrıca, carving işlemlerini CI/CD veya büyük ölçekli lab ortamlarında script ile çalıştırmayı mümkün kılan küçük bir CLI wrapper (`autopsycli ingest <case> <image>`) da kullanıma sunuldu.<sup>[[1]](#references)</sup>
```bash
# Create a case and ingest an evidence image from the CLI (Autopsy ≥4.21)
autopsycli case --create MyCase --base /cases
# ingest with the default ingest profile (includes data-carve module)
autopsycli ingest MyCase /evidence/disk01.E01 --threads 8
```
### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk**, gömülü içeriği bulmak için binary dosyaları analiz etmeye yarayan bir tool'dur. `apt` ile kurulabilir ve source kodu [GitHub](https://github.com/ReFirmLabs/binwalk) üzerindedir.

**Faydalı komutlar**:
```bash
sudo apt install binwalk         # Installation
binwalk firmware.bin             # Display embedded data
binwalk -e firmware.bin          # Extract recognised objects (safe-default)
binwalk --dd " .* " firmware.bin  # Extract *everything* (use with care)
```
⚠️  **Güvenlik notu** – **≤2.3.3** sürümleri **Path Traversal** güvenlik açığından (CVE-2022-4510) etkilenir. Güvenilmeyen örnekleri carving işlemine tabi tutmadan önce yükseltin (veya bir container/non-privileged UID ile izole edin).<sup>[[2]](#references)</sup>

### Foremost

Gizli dosyaları bulmak için kullanılan bir diğer yaygın araç **foremost**'tur. foremost'un configuration file dosyasını `/etc/foremost.conf` konumunda bulabilirsiniz. Yalnızca belirli dosyaları aramak istiyorsanız bunların yorum satırı işaretlerini kaldırın. Hiçbirinin yorum satırı işaretini kaldırmazsanız foremost, varsayılan olarak yapılandırılmış dosya türlerini arar.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel**, bir **dosyaya gömülü dosyaları** bulmak ve çıkarmak için kullanılabilecek başka bir araçtır. Bu durumda, çıkarmasını istediğiniz dosya türlerinin yapılandırma dosyasındaki (_/etc/scalpel/scalpel.conf_) yorum satırı işaretlerini kaldırmanız gerekir.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor 2.x

Bu tool Kali ile birlikte gelir, ancak burada bulabilirsiniz: <https://github.com/simsong/bulk_extractor>

Bulk Extractor bir evidence image'ı tarayabilir ve **pcap fragments**, **network artefacts (URLs, domains, IPs, MACs, e-mails)** ile diğer birçok nesneyi **birden fazla scanner kullanarak paralel şekilde** carve edebilir.
```bash
# Build from source – v2.1.1 (April 2024) requires cmake ≥3.16
git clone https://github.com/simsong/bulk_extractor.git && cd bulk_extractor
mkdir build && cd build && cmake .. && make -j$(nproc) && sudo make install

# Run every scanner, carve JPEGs aggressively and generate a bodyfile
bulk_extractor -o out_folder -S jpeg_carve_mode=2 -S write_bodyfile=y /evidence/disk.img
```
Yararlı post-processing script'leri (`bulk_diff`, `bulk_extractor_reader.py`), iki image arasındaki artefact'ları de-duplicate edebilir veya sonuçları SIEM ingestion için JSON'a dönüştürebilir.

### PhotoRec

Bunu <https://www.cgsecurity.org/wiki/TestDisk_Download> adresinde bulabilirsiniz.

GUI ve CLI sürümleriyle birlikte gelir. PhotoRec'in aramasını istediğiniz **file-types** öğelerini seçebilirsiniz.

![Her scanner'ı çalıştırın, JPEG'leri agresif şekilde carve edin ve bir bodyfile oluşturun - PhotoRec: GUI ve CLI sürümleriyle birlikte gelir. PhotoRec'in aramasını istediğiniz file-types öğelerini seçebilirsiniz](<../../../images/image (242).png>)

### ddrescue + ddrescueview (arızalanan drive'ları imaging etme)

Fiziksel bir drive kararsız olduğunda, en iyi uygulama önce onu **image etmek** ve carving araçlarını yalnızca image üzerinde çalıştırmaktır. `ddrescue` (GNU project), okunamayan sektörlerin log'unu tutarken bozuk diskleri güvenilir şekilde kopyalamaya odaklanır.
```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
ddrescueview suspect.log
```
Version **1.28** (Aralık 2024), geleneksel sektör boyutlarının artık flash bloklarıyla hizalanmadığı yüksek kapasiteli SSD'lerde imaging işlemini hızlandırabilen **`--cluster-size`** seçeneğini kullanıma sundu.

### Extundelete / Ext4magic (EXT 3/4 undelete)

Kaynak dosya sistemi Linux tabanlı EXT ise, yakın zamanda silinen dosyaları **full carving** işlemi yapmadan kurtarmanız mümkün olabilir. Her iki araç da salt okunur bir image üzerinde doğrudan çalışır:
```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Fallback to full directory scan; supports extents and inline data
ext4magic disk.img -M -f '*.jpg' -d ./recovered
```
> 🛈 Dosya sistemi silme işleminden sonra mount edildiyse veri blokları zaten yeniden kullanılmış olabilir – bu durumda uygun carving (Foremost/Scalpel) hâlâ gereklidir.

### binvis

[code](https://code.google.com/archive/p/binvis/) ve [web page tool](https://binvis.io/#/) öğelerini inceleyin.

#### BinVis Features

- Görsel ve aktif **structure viewer**
- Farklı odak noktaları için birden fazla plot
- Bir sample'ın belirli bölümlerine odaklanma
- Örneğin PE veya ELF executable'larında **strings ve resources görme**
- Dosyalarda cryptanalysis için **patterns elde etme**
- **Packer veya encoder algoritmalarını tespit etme**
- Patterns aracılığıyla **Steganography tespit etme**
- **Visual** binary-diffing

BinVis, black-boxing senaryosunda **bilinmeyen bir target'a aşina olmak için harika bir başlangıç noktasıdır**.

## Specific Data Carving Tools

### FindAES

Key schedule'larını arayarak AES key'lerini arar. TrueCrypt ve BitLocker tarafından kullanılanlar gibi 128, 192 ve 256 bit key'leri bulabilir.

[Buradan](https://sourceforge.net/projects/findaes/) download edilebilir.

### YARA-X (carved artefact'ları triage etme)

[YARA-X](https://github.com/VirusTotal/yara-x), 2024'te yayımlanan ve Rust ile yeniden yazılmış bir YARA sürümüdür. Classic YARA'dan **10-30× daha hızlıdır** ve binlerce carved object'i çok hızlı şekilde sınıflandırmak için kullanılabilir:<sup>[[3]](#references)</sup>
```bash
# Scan every carved object produced by bulk_extractor
yarax -r rules/index.yar out_folder/ --threads 8 --print-meta
```
Hız artışı, büyük ölçekli incelemelerde tüm carving ile kurtarılan dosyaları **auto-tag** ile etiketlemeyi gerçekçi hale getirir.

## Tamamlayıcı araçlar

Terminalden görüntüleri görmek için [**viu** ](https://github.com/atanunq/viu) kullanabilirsiniz.  \
Bir pdf dosyasını metne dönüştürmek ve okumak için Linux komut satırı aracı **pdftotext**'i kullanabilirsiniz.



## Referanslar

- [1] [Autopsy 4.21 sürüm notları](https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21)
- [2] [binwalk'ta path traversal (CVE-2022-4510) - GitHub Advisory Database](https://github.com/advisories/GHSA-3cm8-v4mc-gppg)
- [3] [YARA öldü, çok yaşa YARA-X - VirusTotal Blog](https://blog.virustotal.com/2024/05/yara-is-dead-long-live-yara-x.html)

{{#include ../../../banners/hacktricks-training.md}}
