# File/Data Carving ve Kurtarma Araçları

{{#include ../../../banners/hacktricks-training.md}}

## Carving ve Kurtarma araçları

Her zaman orijinal cihaz yerine **doğrulanmış bir kopya** üzerinde carving yapın. Salt okunur edinim ve hashing iş akışları için [Image Acquisition & Mount](../image-acquisition-and-mount.md) sayfasına bakın.

Daha fazla araç için [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

Forensics'te imajlardan dosya çıkarmak için en yaygın kullanılan araç [**Autopsy**](https://www.autopsy.com/download/)'dir. İndirip kurun ve "gizli" dosyaları bulması için dosyayı taramasını sağlayın. Autopsy'nin disk imajlarını ve diğer imaj türlerini destekleyecek şekilde tasarlandığını, ancak basit dosyaları desteklemediğini unutmayın.

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk**, gömülü içeriği bulmak için binary dosyaları analiz eden bir araçtır. **Binwalk v3**, otomatik çıkarma (`-e`), bilinen ve bilinmeyen nesneleri ham olarak carve etme (`-c`), özyinelemeli/Matryoshka taraması (`-M`) ve yapılandırılabilir worker thread'leri sunan, Rust ile yeniden yazılmış bir sürümdür. Proje, tüm harici extractor'lar gerektiğinde Docker build'ini önerir; `cargo install binwalk` Rust CLI'ı kurar, ancak bu harici bağımlılıkları kurmaz.<sup>[[11]](#references)</sup>

**Yararlı v3 komutları**:

```bash
cargo install binwalk                 # CLI only; install extractors separately
binwalk firmware.bin                  # Identify embedded content
binwalk -e firmware.bin               # Extract recognised objects
binwalk -c -d carved firmware.bin     # Carve known and unknown objects
binwalk -Me -d extracted firmware.bin # Extract and recursively scan results
binwalk -e -l results.json firmware.bin
```

Eski v2 `--dd='.*'` kullanımı, v3'teki `-c` seçeneğinin karşılığı değildir; eski CTF/write-up komutlarını kullanırken önce `binwalk --version` değerini kontrol edin.<sup>[[11]](#references)</sup>

⚠️  **Güvenlik notu** – **2.1.2b ile 2.3.3** arasındaki sürümler bir **Path Traversal** güvenlik açığından (CVE-2022-4510) etkilenir; güvenlik duyurusunda yamalanmış bir pip sürümü belirtilmemiştir. Etkilenen sürümlerle güvenilmeyen örnekleri çıkarmaktan kaçının veya aracı bir container/non-privileged UID ile yalıtın.<sup>[[4]](#references)</sup>

### Foremost

Gizli dosyaları bulmak için kullanılan diğer yaygın araç **foremost**'tur. foremost'un yapılandırma dosyasını `/etc/foremost.conf` konumunda bulabilirsiniz. Yalnızca belirli dosyaları aramak istiyorsanız, ilgili satırlardaki yorum işaretlerini kaldırın. Hiçbirinin yorum işaretini kaldırmazsanız foremost, varsayılan olarak yapılandırılmış dosya türlerini arar.

```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```

### **Scalpel**

**Scalpel**, **bir dosyanın içine gömülü dosyaları** bulup çıkarmak için kullanılabilecek başka bir araçtır. Bu durumda, çıkarmasını istediğiniz dosya türlerinin yorum satırı işaretini yapılandırma dosyasından (_/etc/scalpel/scalpel.conf_) kaldırmanız gerekir.

```bash
sudo apt-get install scalpel
scalpel file.img -o output
```

### Scalpel3 parçalı carving

Metadata-first recovery ve contiguous carver'lar bölünmüş dosyaları eksik bıraktığında, **Scalpel3** desteklenen biçimleri dosya/blok doğrulayıcılarını kullanarak yeniden birleştirebilir. Yukarıdaki eski `scalpel` komutundan farklı bir kod tabanıdır. Önce carving işleminde kullanılan **aynı blok boyutuyla** gerekli blockmap'i oluşturun; biliniyorsa `fsstat` çıktısındaki dosya sistemi cluster boyutunu kullanın veya bir partition image'ını taramadan önce gerekçelendirilebilir bir değer belirleyin. Yalnızca doğrulanmış bir kopya üzerinde çalıştırın ve çıktıyı ayrı bir birime kaydedin.<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>

```bash
git clone https://github.com/nolaforensix/scalpel3-release.git
cd scalpel3-release && ./init_scalpel3.sh && cd src
./crblockmap -q 4096 /evidence/partition.img /analysis/partition.blockmap
./scalpel3 -Y cpu -q 4096 -w -b -o /analysis/scalpel3 \
  /evidence/partition.img /analysis/partition.blockmap
```

`4096` değerini seçilen blok boyutuyla değiştirin. `-w`, doğrulanmış adayların yanı sıra **PROMISING** adayları da korur; `-b`, yeniden oluşturulan düzenleri kontrol etmeye yardımcı olmak için blockvector dosyaları yazar. PROMISING durumundaki bir dosya veya tanıdık bir uzantıya sahip dosya, kurtarmanın eksiksiz olduğunun kanıtı değildir; kullanmadan önce içeriği doğrulayın.<sup>[[13]](#references)[[14]](#references)</sup> Carving işleminden önce silinmiş bölümleri veya boşlukları bulmak için bkz. [Listelenen bölümlerin dışındaki verileri bulma](./#finding-data-outside-listed-partitions).

### Bulk Extractor 2.x   

Bu araç Kali ile birlikte gelir, ancak buradan da bulabilirsiniz: <https://github.com/simsong/bulk_extractor>

Bulk Extractor, bir kanıt imajını tarayabilir ve **pcap parçalarını**, **ağ artefaktlarını (URL’ler, alan adları, IP’ler, MAC’ler, e-postalar)** ve diğer birçok nesneyi **birden fazla scanner kullanarak paralel biçimde** carve edebilir.

v2.1.1 sürümünde, Autotools ile derleme ve tüm bitişik JPEG’leri carve etmek için `-S jpeg_carve_mode=2` ayarı belgelenmiştir.<sup>[[2]](#references)</sup>

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

Birlikte sunulan `bulk_diff.py` iki bulk_extractor çalıştırmasının sonuçlarını karşılaştırırken, `bulk_extractor_reader.py` rapor ve feature dosyalarını okur.<sup>[[3]](#references)</sup>

### PhotoRec

Bunu <https://www.cgsecurity.org/wiki/TestDisk_Download> adresinde bulabilirsiniz.

GUI ve CLI sürümleriyle birlikte gelir. PhotoRec'in aramasını istediğiniz **file-types** öğelerini seçebilirsiniz.

![Her tarayıcıyı çalıştırın, JPEG'leri agresif biçimde carve edin ve bir bodyfile oluşturun - PhotoRec: GUI ve CLI sürümleriyle birlikte gelir. PhotoRec'in aramasını istediğiniz file-types öğelerini seçebilirsiniz](<../../../images/image (242).png>)

### The Sleuth Kit `tsk_recover` (metadata öncelikli)

Ham imza carving işleminden önce, volume metadata hâlâ ayrıştırılabiliyorsa dosya sistemi farkındalıklı kurtarmayı deneyin. `tsk_recover` varsayılan olarak yalnızca tahsis edilmemiş dosyaları dışa aktarır; `-a` tahsis edilmiş dosyaları seçer, `-e` ise her ikisini de dışa aktarır. Tüm disk imajı için, `mmls` çıktısındaki bölümün **başlangıç sektörünü** `-o` seçeneğine verin (bunu bayta dönüştürmeyin). Girdi zaten bir bölüm imajıysa `-o` seçeneğini kullanmayın.<sup>[[12]](#references)</sup>

```bash
sudo apt install sleuthkit
mmls disk.img                         # Note the partition start sector, e.g. 2048
mkdir recovered-deleted recovered-all
tsk_recover -o 2048 disk.img recovered-deleted/
tsk_recover -e -o 2048 disk.img recovered-all/
```

Bu işlem, header/footer carving işleminin koruyamadığı dosya sistemi kaynaklı adları ve yolları koruyabilir; metadata'sı eksik veya kullanılamaz olan girdiler için ardından Foremost, Scalpel veya PhotoRec çalıştırın.<sup>[[12]](#references)</sup>

### ddrescue + ddrescueview (arızalanan sürücülerin imajını alma)

Fiziksel bir sürücü kararsız olduğunda, en iyi uygulama **önce imajını almak** ve carving araçlarını yalnızca imaj üzerinde çalıştırmaktır. `ddrescue` (GNU projesi), okunamayan sektörlerin günlüğünü tutarken arızalı diskleri güvenilir biçimde kopyalamaya odaklanır.

```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
 ddrescueview suspect.log
```

**`--cluster-size`** seçeneği, her seferinde kaç sektörün kopyalanacağını belirler; daha düşük değerler yavaş sürücülerde yardımcı olabilir.<sup>[[7]](#references)</sup>

### Extundelete / Ext4magic (EXT 3/4 silinen dosya kurtarma)

Kaynak dosya sistemi Linux EXT tabanlıysa, **tam carving yapmadan** yakın zamanda silinen dosyaları kurtarabilirsiniz; günlük tabanlı bu araçlar, bağlanmamış bir dosya sistemi veya salt okunur bir imaj üzerinde çalışır.<sup>[[8]](#references)[[9]](#references)</sup>

```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Multi-stage recovery from an ext4 image
ext4magic disk.img -M -d ./recovered
```

> **Uyumluluk notu** – ext4magic terk edilmiştir; proje sayfasında, güncel dosya sistemlerinin artık onunla uyumlu olmadığı belirtiliyor.<sup>[[10]](#references)</sup>

> 🛈 Dosya sistemi silme işleminden sonra bağlandıysa veri blokları zaten yeniden kullanılmış olabilir; bu durumda doğru carving (Foremost/Scalpel) hâlâ gereklidir.

### binvis

[code](https://code.google.com/archive/p/binvis/) ve [web sayfasındaki aracı](https://binvis.io/#/) inceleyin.

#### BinVis'in özellikleri

- Görsel ve etkileşimli **yapı görüntüleyici**
- Farklı odak noktaları için birden çok grafik
- Bir örneğin belirli bölümlerine odaklanma
- Örneğin PE veya ELF yürütülebilir dosyalarındaki **dizeleri ve kaynakları görme**
- Dosyalarda kriptanaliz için **örüntüler** elde etme
- Packer veya encoder algoritmalarını **tespit etme**
- Örüntüler aracılığıyla Steganography'yi **belirleme**
- Görsel **binary-diffing**

BinVis, black-boxing senaryosunda **bilinmeyen bir hedefi tanımaya başlamak** için harika bir başlangıç noktasıdır.

## Belirli Data Carving Araçları

### FindAES

Anahtar planlarını arayarak AES anahtarlarını bulur. TrueCrypt ve BitLocker tarafından kullanılanlar gibi 128, 192 ve 256 bit anahtarları bulabilir.

[Buradan](https://sourceforge.net/projects/findaes/) indirin.

### YARA-X (carving ile çıkarılan artefaktların önceliklendirilmesi)

[YARA-X](https://github.com/VirusTotal/yara-x), 2024'te tanıtılan YARA'nın Rust ile yeniden yazılmış sürümüdür; VirusTotal, bazı düzenli ifade ve karmaşık döngü kurallarının önemli ölçüde daha hızlı çalışabildiğini bildiriyor.<sup>[[5]](#references)</sup> CLI aracı `yr` olarak adlandırılır ve `scan` komutu özyinelemeli taramaları, iş parçacığı sayısını ve metadata çıktısını destekler.<sup>[[6]](#references)</sup>

```bash
# Scan every carved object produced by bulk_extractor
yr scan --recursive --threads 8 --print-meta rules/index.yar out_folder/
```

## Tamamlayıcı araçlar

Terminalden görüntüleri görmek için [**viu** ](https://github.com/atanunq/viu)kullanabilirsiniz.  \
Bir PDF'yi metne dönüştürüp okumak için Linux komut satırı aracı **pdftotext**'i kullanabilirsiniz.







## References

- [1] [Autopsy 4.21 sürüm notları](https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21.0)
- [2] [bulk_extractor v2.1.1 README](https://github.com/simsong/bulk_extractor/blob/v2.1.1/README.md)
- [3] [bulk_extractor Python araçları README](https://raw.githubusercontent.com/simsong/bulk_extractor/v2.1.1/python/README.txt)
- [4] [binwalk'ta yol geçişi (CVE-2022-4510) - GitHub Advisory Database](https://github.com/advisories/GHSA-3cm8-v4mc-gppg)
- [5] [YARA öldü, çok yaşa YARA-X - VirusTotal Blog](https://blog.virustotal.com/2024/05/yara-is-dead-long-live-yara-x.html)
- [6] [YARA-X CLI komutları](https://virustotal.github.io/yara-x/docs/cli/commands/)
- [7] [GNU ddrescue kılavuzu](https://www.gnu.org/software/ddrescue/manual/ddrescue_manual.html)
- [8] [extundelete](https://extundelete.sourceforge.net/)
- [9] [ext4magic kılavuzu](https://ext4magic.sourceforge.net/manpage_en.html)
- [10] [ext4magic proje durumu](https://sourceforge.net/projects/ext4magic/)
- [11] [Binwalk v3 README](https://github.com/ReFirmLabs/binwalk/blob/master/README.md)
- [12] [The Sleuth Kit: tsk_recover kılavuzu](https://sleuthkit.org/sleuthkit/man/tsk_recover.html)
- [13] [Scalpel3 README](https://github.com/nolaforensix/scalpel3-release/blob/main/README.md)
- [14] [Scalpel3 kılavuzu](https://github.com/nolaforensix/scalpel3-release/blob/main/man/scalpel3.1)
- [15] [Scalpel3 test iş akışı](https://github.com/nolaforensix/scalpel3-release/blob/main/src/TESTS/cmdline.test)
{{#include ../../../banners/hacktricks-training.md}}
