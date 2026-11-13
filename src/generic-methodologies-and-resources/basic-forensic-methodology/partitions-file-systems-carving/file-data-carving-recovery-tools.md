# Zana za File/Data Carving na Recovery

{{#include ../../../banners/hacktricks-training.md}}

## Zana za Carving na Recovery

Fanya carving kila mara kwenye **nakala iliyothibitishwa**, si kifaa asili. Tazama [Image Acquisition & Mount](../image-acquisition-and-mount.md) kwa taratibu za kupata nakala ya kusoma tu na kuhesabu hash.

Zana zaidi katika [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

Zana inayotumika sana katika forensics kutoa faili kutoka kwenye images ni [**Autopsy**](https://www.autopsy.com/download/). Ipakue, isakinishe, kisha ifanye ichanganue faili ili kupata faili "zilizofichwa". Kumbuka kwamba Autopsy imeundwa kusaidia disk images na aina nyingine za images, lakini si faili za kawaida.

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** ni zana ya kuchanganua faili za binary ili kupata maudhui yaliyopachikwa. **Binwalk v3** ni toleo lililoandikwa upya kwa Rust lenye uchimbaji wa kiotomatiki (`-e`), carving ghafi ya vitu vinavyojulikana na visivyojulikana (`-c`), uchanganuzi wa kujirudia/Matryoshka (`-M`) na nyuzi za worker zinazoweza kusanidiwa. Mradi unapendekeza kutumia Docker build yake pale ambapo extractors zote za nje zinahitajika; `cargo install binwalk` husakinisha Rust CLI, lakini si dependencies hizo za nje.<sup>[[11]](#references)</sup>

**Amri muhimu za v3**:

```bash
cargo install binwalk                 # CLI only; install extractors separately
binwalk firmware.bin                  # Identify embedded content
binwalk -e firmware.bin               # Extract recognised objects
binwalk -c -d carved firmware.bin     # Carve known and unknown objects
binwalk -Me -d extracted firmware.bin # Extract and recursively scan results
binwalk -e -l results.json firmware.bin
```

Recipe ya zamani ya v2 `--dd='.*'` **si** sawa na `-c` ya v3; kwanza angalia `binwalk --version` unapofuata amri za zamani za CTF/write-up.<sup>[[11]](#references)</sup>

⚠️  **Dokezo la usalama** – Matoleo **2.1.2b hadi 2.3.3** yanaathiriwa na udhaifu wa **Path Traversal** (CVE-2022-4510); ushauri hauorodheshi toleo lolote la pip lililorekebishwa. Epuka kutoa faili kutoka kwenye sampuli zisizoaminika kwa kutumia matoleo yaliyoathiriwa, au tenga zana hiyo kwa kutumia container/UID isiyo na marupurupu.<sup>[[4]](#references)</sup>

### Foremost

Zana nyingine inayotumika sana kutafuta faili zilizofichwa ni **foremost**. Unaweza kupata faili ya usanidi ya foremost katika `/etc/foremost.conf`. Ikiwa unataka tu kutafuta faili fulani maalum, ziondoe maoni. Usipoondoa maoni yoyote, foremost itatafuta aina za faili zilizosanidiwa kama chaguomsingi.

```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```

### **Scalpel**

**Scalpel** ni zana nyingine inayoweza kutumika kutafuta na kutoa **faili zilizopachikwa ndani ya faili**. Katika hali hii, utahitaji kuondoa alama ya maoni kwenye aina za faili unazotaka kutoa ndani ya faili ya usanidi (_/etc/scalpel/scalpel.conf_).

```bash
sudo apt-get install scalpel
scalpel file.img -o output
```

### Uchongaji wa vipande vilivyotawanyika kwa Scalpel3

Wakati urejeshaji unaotanguliza metadata na zana za kuchonga faili zilizo mfululizo zinapoacha faili zilizogawanyika zikiwa hazijakamilika, **Scalpel3** inaweza kuunganisha tena miundo ya faili inayotumika kwa kutumia vihalalishi vya faili/vizuizi. Ni codebase tofauti na amri ya zamani ya `scalpel` iliyo hapo juu. Kwanza, tengeneza blockmap inayohitajika kwa kutumia **block size ileile** iliyotumika kuchonga; tumia ukubwa wa cluster wa filesystem kutoka `fsstat` unapojulikana, au bainisha thamani inayoweza kutetewa kabla ya kuchanganua picha ya partition. Iendeshe kwenye nakala iliyothibitishwa pekee, na uweke matokeo kwenye volume tofauti.<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>

```bash
git clone https://github.com/nolaforensix/scalpel3-release.git
cd scalpel3-release && ./init_scalpel3.sh && cd src
./crblockmap -q 4096 /evidence/partition.img /analysis/partition.blockmap
./scalpel3 -Y cpu -q 4096 -w -b -o /analysis/scalpel3 \
  /evidence/partition.img /analysis/partition.blockmap
```

Badilisha `4096` kwa ukubwa wa block uliochagua. `-w` huhifadhi wagombea wa **PROMISING** pamoja na wale waliothibitishwa, na `-b` huandika blockvectors ili kusaidia kukagua mipangilio iliyoundwa upya. Faili iliyo katika PROMISING, au yenye kiendelezi kinachojulikana, si uthibitisho wa urejeshaji kamili; thibitisha maudhui kabla ya kuitumia.<sup>[[13]](#references)[[14]](#references)</sup> Ili kupata partitions zilizofutwa au mapengo kabla ya carving, angalia [Kupata data nje ya partitions zilizoorodheshwa](./#finding-data-outside-listed-partitions).

### Bulk Extractor 2.x   

Zana hii inapatikana ndani ya kali, lakini unaweza kuipata hapa: <https://github.com/simsong/bulk_extractor>

Bulk Extractor inaweza kuchanganua picha ya ushahidi na kufanya carving ya **vipande vya pcap**, **artefact za mtandao (URLs, domains, IPs, MACs, barua pepe)** na vitu vingine vingi **kwa wakati mmoja kwa kutumia scanners nyingi**.

Toleo la v2.1.1 linaandika maelekezo ya build ya Autotools na mpangilio wa `-S jpeg_carve_mode=2` wa kufanya carving ya JPEG zote zilizoungana.<sup>[[2]](#references)</sup>

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

`bulk_diff.py` iliyojumuishwa hulinganisha matokeo ya uendeshaji mawili ya bulk_extractor, huku `bulk_extractor_reader.py` ikisoma ripoti na faili za vipengele.<sup>[[3]](#references)</sup>

### PhotoRec

Unaweza kuipata kwenye <https://www.cgsecurity.org/wiki/TestDisk_Download>

Inakuja na matoleo ya GUI na CLI. Unaweza kuchagua **aina za faili** unazotaka PhotoRec itafute.

![Endesha scanners zote, carve JPEGs kwa ukali na utengeneze bodyfile - PhotoRec: Inakuja na matoleo ya GUI na CLI. Unaweza kuchagua aina za faili unazotaka PhotoRec itafute](<../../../images/image (242).png>)

### The Sleuth Kit `tsk_recover` (metadata kwanza)

Kabla ya kufanya signature carving ghafi, jaribu urejeshaji unaozingatia mfumo wa faili wakati metadata ya volume bado inaweza kuchanganuliwa. Kwa chaguo-msingi, `tsk_recover` huhamisha faili ambazo hazijatengwa tu; `-a` huchagua faili zilizotengwa, na `-e` huhamisha zote mbili. Kwa image ya diski nzima, pitisha **sekta ya mwanzo** ya partition kutoka `mmls` kwa `-o` (usiibadilishe kuwa bytes). Ikiwa ingizo tayari ni image ya partition, usitumie `-o`.<sup>[[12]](#references)</sup>

```bash
sudo apt install sleuthkit
mmls disk.img                         # Note the partition start sector, e.g. 2048
mkdir recovered-deleted recovered-all
tsk_recover -o 2048 disk.img recovered-deleted/
tsk_recover -e -o 2048 disk.img recovered-all/
```

Njia hii inaweza kuhifadhi majina na njia zinazotokana na filesystem ambazo header/footer carving haiwezi kuhifadhi; endesha Foremost, Scalpel au PhotoRec baadaye kwa maingizo ambayo metadata yake haipo au haiwezi kutumika.<sup>[[12]](#references)</sup>

### ddrescue + ddrescueview (kutengeneza image ya diski zinazoharibika)

Diski halisi inapokuwa si thabiti, ni bora **kutengeneza image yake kwanza** na kutumia zana za carving kwenye image hiyo pekee. `ddrescue` (mradi wa GNU) inalenga kunakili diski zenye hitilafu kwa njia ya kuaminika huku ikihifadhi logi ya sekta zisizoweza kusomeka.

```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
 ddrescueview suspect.log
```

Chaguo la **`--cluster-size`** hudhibiti idadi ya sekta zinazonakiliwa kwa wakati mmoja; thamani ndogo zaidi zinaweza kusaidia kwa diski zinazoendesha polepole.<sup>[[7]](#references)</sup>

### Extundelete / Ext4magic (urejeshaji wa faili zilizofutwa za EXT 3/4)

Ikiwa mfumo wa faili chanzo unategemea Linux EXT, unaweza kurejesha faili zilizofutwa hivi karibuni **bila kufanya carving kamili**; zana hizi zinazotegemea journal hufanya kazi kwenye mfumo wa faili ambao haujawekwa mount au kwenye image ya kusoma tu.<sup>[[8]](#references)[[9]](#references)</sup>

```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Multi-stage recovery from an ext4 image
ext4magic disk.img -M -d ./recovered
```

> **Maelezo ya uoanifu** – ext4magic imeachwa; ukurasa wa mradi wake unaonya kuwa mifumo ya faili ya sasa haioani nayo tena.<sup>[[10]](#references)</sup>

> 🛈 Ikiwa mfumo wa faili uliwekwa mount baada ya kufutwa, data blocks huenda tayari zimetumiwa tena – katika hali hiyo, carving sahihi (Foremost/Scalpel) bado inahitajika.

### binvis

Angalia [code](https://code.google.com/archive/p/binvis/) na [web page tool](https://binvis.io/#/).

#### Vipengele vya BinVis

- **Kitazamaji cha muundo** kinachoonekana na shirikishi
- Michoro mingi kwa maeneo tofauti ya kuangazia
- Kuangazia sehemu za sampuli
- **Kuona strings na rasilimali**, kwa mfano katika executables za PE au ELF
- Kupata **patterns** za cryptanalysis kwenye files
- **Kutambua** algorithms za packer au encoder
- **Kutambua** Steganography kupitia patterns
- **Ulinganishaji** wa binary unaoonekana

BinVis ni **mahali pazuri pa kuanzia ili kufahamu lengo lisilojulikana** katika hali ya black-boxing.

## Zana Mahususi za Data Carving

### FindAES

Hutafuta funguo za AES kwa kutafuta key schedules zake. Inaweza kupata funguo za biti 128, 192 na 256, kama zile zinazotumiwa na TrueCrypt na BitLocker.

Pakua [hapa](https://sourceforge.net/projects/findaes/).

### YARA-X (kupanga kipaumbele kwa artefacts zilizochongwa)

[YARA-X](https://github.com/VirusTotal/yara-x) ni uandishi upya wa YARA kwa Rust ulioanzishwa mwaka wa 2024; VirusTotal inaripoti kuwa baadhi ya rules za regular-expression na loops changamano zinaweza kufanya kazi kwa kasi zaidi.<sup>[[5]](#references)</sup> CLI yake inaitwa `yr`, na amri ya `scan` inasaidia scans za kujirudia, idadi ya threads na utoaji wa metadata.<sup>[[6]](#references)</sup>

```bash
# Scan every carved object produced by bulk_extractor
yr scan --recursive --threads 8 --print-meta rules/index.yar out_folder/
```

## Zana za ziada

Unaweza kutumia [**viu** ](https://github.com/atanunq/viu)kuona picha kutoka kwenye terminal.  \
Unaweza kutumia zana ya mstari wa amri ya Linux **pdftotext** kubadilisha PDF kuwa maandishi na kuyasoma.







## References

- [1] [Maelezo ya toleo la Autopsy 4.21](https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21.0)
- [2] [README ya bulk_extractor v2.1.1](https://github.com/simsong/bulk_extractor/blob/v2.1.1/README.md)
- [3] [README ya zana za Python za bulk_extractor](https://raw.githubusercontent.com/simsong/bulk_extractor/v2.1.1/python/README.txt)
- [4] [Path traversal katika binwalk (CVE-2022-4510) - Hifadhidata ya Ushauri ya GitHub](https://github.com/advisories/GHSA-3cm8-v4mc-gppg)
- [5] [YARA imekufa, iishi maisha marefu YARA-X - Blogu ya VirusTotal](https://blog.virustotal.com/2024/05/yara-is-dead-long-live-yara-x.html)
- [6] [Amri za CLI za YARA-X](https://virustotal.github.io/yara-x/docs/cli/commands/)
- [7] [Mwongozo wa GNU ddrescue](https://www.gnu.org/software/ddrescue/manual/ddrescue_manual.html)
- [8] [extundelete](https://extundelete.sourceforge.net/)
- [9] [Mwongozo wa ext4magic](https://ext4magic.sourceforge.net/manpage_en.html)
- [10] [Hali ya mradi wa ext4magic](https://sourceforge.net/projects/ext4magic/)
- [11] [README ya Binwalk v3](https://github.com/ReFirmLabs/binwalk/blob/master/README.md)
- [12] [The Sleuth Kit: Mwongozo wa tsk_recover](https://sleuthkit.org/sleuthkit/man/tsk_recover.html)
- [13] [README ya Scalpel3](https://github.com/nolaforensix/scalpel3-release/blob/main/README.md)
- [14] [Mwongozo wa Scalpel3](https://github.com/nolaforensix/scalpel3-release/blob/main/man/scalpel3.1)
- [15] [Mtiririko wa majaribio wa Scalpel3](https://github.com/nolaforensix/scalpel3-release/blob/main/src/TESTS/cmdline.test)
{{#include ../../../banners/hacktricks-training.md}}
