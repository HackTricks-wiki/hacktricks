# File/Data Carving & Recovery Tools

{{#include ../../../banners/hacktricks-training.md}}

## Carving & Recovery tools

More tools in [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

Chombo kinachotumika sana katika uchunguzi kutoa faili kutoka kwa picha ni [**Autopsy**](https://www.autopsy.com/download/). Pakua, sakinisha na fanya iweze kuchukua faili ili kupata faili "zilizofichwa". Kumbuka kwamba Autopsy imejengwa kusaidia picha za diski na aina nyingine za picha, lakini si faili rahisi.

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** ni chombo cha kuchambua faili za binary ili kupata maudhui yaliyojumuishwa. Inaweza kusakinishwa kupitia `apt` na chanzo chake kiko kwenye [GitHub](https://github.com/ReFirmLabs/binwalk).

**Amri muhimu**:
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
### Foremost

Zana lingine la kawaida la kutafuta faili zilizofichwa ni **foremost**. Unaweza kupata faili ya usanidi ya foremost katika `/etc/foremost.conf`. Ikiwa unataka tu kutafuta faili fulani, ondoa alama ya maoni. Ikiwa huondoi alama ya maoni, foremost itatafuta aina zake za faili zilizowekwa kama chaguo-msingi.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** ni chombo kingine ambacho kinaweza kutumika kupata na kutoa **faili zilizojumuishwa ndani ya faili**. Katika kesi hii, utahitaji kuondoa maoni kutoka kwa faili ya usanidi (_/etc/scalpel/scalpel.conf_) aina za faili unazotaka ikatoe.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor

Zana hii inapatikana ndani ya kali lakini unaweza kuipata hapa: [https://github.com/simsong/bulk_extractor](https://github.com/simsong/bulk_extractor)

Zana hii inaweza kuskan picha na itatoa **pcaps** ndani yake, **taarifa za mtandao (URLs, domains, IPs, MACs, mails)** na zaidi **faili**. Unahitaji tu kufanya:
```
bulk_extractor memory.img -o out_folder
```
Navigate through **habari zote** that the tool has gathered (passwords?), **chambua** the **paket** (read[ **Pcaps analysis**](../pcap-inspection/index.html)), search for **domeni za ajabu** (domains related to **malware** or **zisizokuwepo**).

### PhotoRec

You can find it in [https://www.cgsecurity.org/wiki/TestDisk_Download](https://www.cgsecurity.org/wiki/TestDisk_Download)

It comes with GUI and CLI versions. You can select the **aina za faili** you want PhotoRec to search for.

![](<../../../images/image (524).png>)

### binvis

Check the [code](https://code.google.com/archive/p/binvis/) and the [web page tool](https://binvis.io/#/).

#### Features of BinVis

- Visual and active **muonekano wa muundo**
- Multiple plots for different focus points
- Focusing on portions of a sample
- **Kuona stings na rasilimali**, in PE or ELF executables e. g.
- Getting **mifumo** for cryptanalysis on files
- **Kugundua** packer or encoder algorithms
- **Tambua** Steganography by patterns
- **Visual** binary-diffing

BinVis is a great **nukta ya kuanzia kujifunza kuhusu lengo lisilojulikana** in a black-boxing scenario.

## Specific Data Carving Tools

### FindAES

Searches for AES keys by searching for their key schedules. Able to find 128. 192, and 256 bit keys, such as those used by TrueCrypt and BitLocker.

Download [hapa](https://sourceforge.net/projects/findaes/).

## Complementary tools

You can use [**viu** ](https://github.com/atanunq/viu)to see images from the terminal.\
You can use the linux command line tool **pdftotext** to transform a pdf into text and read it.

{{#include ../../../banners/hacktricks-training.md}}
