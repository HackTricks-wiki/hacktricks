# File/Data Carving & Recovery Tools

{{#include ../../../banners/hacktricks-training.md}}

## Carving & Recovery tools

Meer gereedskap in [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

Die mees algemene gereedskap wat in forensiese ondersoeke gebruik word om lêers uit beelde te onttrek, is [**Autopsy**](https://www.autopsy.com/download/). Laai dit af, installeer dit en laat dit die lêer verwerk om "versteekte" lêers te vind. Let daarop dat Autopsy gebou is om skyfbeelde en ander soorte beelde te ondersteun, maar nie eenvoudige lêers nie.

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** is 'n gereedskap om binêre lêers te analiseer om ingebedde inhoud te vind. Dit kan geïnstalleer word via `apt` en sy bron is op [GitHub](https://github.com/ReFirmLabs/binwalk).

**Nuttige opdragte**:
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
### Foremost

Nog 'n algemene hulpmiddel om verborge lêers te vind, is **foremost**. Jy kan die konfigurasielêer van foremost in `/etc/foremost.conf` vind. As jy net vir 'n paar spesifieke lêers wil soek, ontkommentarieer hulle. As jy niks ontkommentarieer nie, sal foremost vir sy standaard geconfigureerde lêertipes soek.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** is 'n ander hulpmiddel wat gebruik kan word om **lêers wat in 'n lêer ingebed is** te vind en te onttrek. In hierdie geval sal jy die lêertipes wat jy wil hê dit moet onttrek, uit die konfigurasie-lêer (_/etc/scalpel/scalpel.conf_) moet ontkommentaar.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor

Hierdie hulpmiddel kom binne Kali, maar jy kan dit hier vind: [https://github.com/simsong/bulk_extractor](https://github.com/simsong/bulk_extractor)

Hierdie hulpmiddel kan 'n beeld skandeer en sal **pcaps** daarin **onttrek**, **netwerk inligting (URL's, domeine, IP's, MAC's, e-pos)** en meer **lêers**. Jy hoef net te doen:
```
bulk_extractor memory.img -o out_folder
```
Navigeer deur **alle inligting** wat die hulpmiddel versamel het (wagwoorde?), **analiseer** die **pakkette** (lees[ **Pcaps analise**](../pcap-inspection/index.html)), soek na **vreemde domeine** (domeine wat verband hou met **malware** of **nie-bestaande**).

### PhotoRec

Jy kan dit vind in [https://www.cgsecurity.org/wiki/TestDisk_Download](https://www.cgsecurity.org/wiki/TestDisk_Download)

Dit kom met GUI en CLI weergawes. Jy kan die **lêer-tipes** kies waarvoor jy wil hê PhotoRec moet soek.

![](<../../../images/image (242).png>)

### binvis

Kyk na die [kode](https://code.google.com/archive/p/binvis/) en die [webblad hulpmiddel](https://binvis.io/#/).

#### Kenmerke van BinVis

- Visuele en aktiewe **struktuurkyker**
- Meervoudige grafieke vir verskillende fokuspunte
- Fokus op gedeeltes van 'n monster
- **Sien stings en hulpbronne**, in PE of ELF uitvoerbare lêers bv.
- Kry **patrone** vir kriptoanalise op lêers
- **Identifiseer** pakkers of kodering algoritmes
- **Identifiseer** Steganografie deur patrone
- **Visuele** binêre-diffing

BinVis is 'n uitstekende **beginpunt om bekend te raak met 'n onbekende teiken** in 'n swart-doos scenario.

## Spesifieke Data Carving Hulpmiddels

### FindAES

Soek na AES sleutels deur hul sleutel skedules te soek. In staat om 128, 192, en 256 bit sleutels te vind, soos dié wat deur TrueCrypt en BitLocker gebruik word.

Laai [hier](https://sourceforge.net/projects/findaes/) af.

## Aanvullende hulpmiddels

Jy kan [**viu** ](https://github.com/atanunq/viu) gebruik om beelde vanaf die terminal te sien.\
Jy kan die linux opdraglyn hulpmiddel **pdftotext** gebruik om 'n pdf in teks te omskep en dit te lees.

{{#include ../../../banners/hacktricks-training.md}}
