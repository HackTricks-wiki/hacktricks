# File/Data Carving & Recovery Tools

{{#include ../../../banners/hacktricks-training.md}}

## Carving & Recovery tools

Zana zaidi zinapatikana katika [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

Zana inayotumika sana katika uchunguzi wa forensics kutoa faili kutoka kwa picha ni [**Autopsy**](https://www.autopsy.com/download/). Pakua, sakinisha na fanya iweze kuchukua faili ili kupata faili "zilizofichwa". Kumbuka kwamba Autopsy imejengwa kusaidia picha za diski na aina nyingine za picha, lakini si faili rahisi.

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** ni zana ya kuchambua faili za binary ili kupata maudhui yaliyojumuishwa. Inaweza kusakinishwa kupitia `apt` na chanzo chake kiko kwenye [GitHub](https://github.com/ReFirmLabs/binwalk).

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

**Scalpel** ni chombo kingine ambacho kinaweza kutumika kupata na kutoa **faili zilizojumuishwa katika faili**. Katika kesi hii, utahitaji kuondoa maoni kutoka kwa faili ya usanidi (_/etc/scalpel/scalpel.conf_) aina za faili unazotaka ikatoe.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor

Zana hii inapatikana ndani ya kali lakini unaweza kuipata hapa: [https://github.com/simsong/bulk_extractor](https://github.com/simsong/bulk_extractor)

Zana hii inaweza kuskan picha na itatoa **pcaps** ndani yake, **taarifa za mtandao (URLs, domains, IPs, MACs, mails)** na zaidi **faili**. Unachohitaji kufanya ni:
```
bulk_extractor memory.img -o out_folder
```
Navigatia kupitia **maelezo yote** ambayo chombo kimekusanya (nywila?), **chambua** **paket** (soma [**Pcaps analysis**](../pcap-inspection/)), tafuta **domeni za ajabu** (domeni zinazohusiana na **malware** au **zisizokuwepo**).

### PhotoRec

Unaweza kuipata katika [https://www.cgsecurity.org/wiki/TestDisk_Download](https://www.cgsecurity.org/wiki/TestDisk_Download)

Inakuja na toleo la GUI na CLI. Unaweza kuchagua **aina za faili** unazotaka PhotoRec itafute.

![](<../../../images/image (242).png>)

### binvis

Angalia [code](https://code.google.com/archive/p/binvis/) na [ukurasa wa chombo](https://binvis.io/#/).

#### Vipengele vya BinVis

- Muonekano wa **muundo** wa kuona na wa kazi
- Mchoro mwingi kwa maeneo tofauti ya kuzingatia
- Kuangazia sehemu za sampuli
- **Kuona stings na rasilimali**, katika PE au ELF executable mfano
- Kupata **mifumo** ya uchambuzi wa kificho kwenye faili
- **Kugundua** algorithms za pakker au encoder
- **Tambua** Steganography kwa mifumo
- **Kuona** tofauti za binary

BinVis ni **nukta ya kuanzia nzuri ili kufahamiana na lengo lisilojulikana** katika hali ya black-boxing.

## Zana Maalum za Data Carving

### FindAES

Inatafuta funguo za AES kwa kutafuta ratiba zao za funguo. Inaweza kupata funguo za 128, 192, na 256 bit, kama zile zinazotumiwa na TrueCrypt na BitLocker.

Pakua [hapa](https://sourceforge.net/projects/findaes/).

## Zana za Nyongeza

Unaweza kutumia [**viu**](https://github.com/atanunq/viu) kuona picha kutoka kwenye terminal.\
Unaweza kutumia chombo cha mistari ya amri za linux **pdftotext** kubadilisha pdf kuwa maandiko na kuisoma.

{{#include ../../../banners/hacktricks-training.md}}
