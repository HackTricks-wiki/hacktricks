{{#include ../../../banners/hacktricks-training.md}}

# Carving gereedskap

## Autopsy

Die mees algemene gereedskap wat in forensiese ondersoeke gebruik word om lêers uit beelde te onttrek, is [**Autopsy**](https://www.autopsy.com/download/). Laai dit af, installeer dit en laat dit die lêer verwerk om "versteekte" lêers te vind. Let daarop dat Autopsy gebou is om skyfbeelde en ander soorte beelde te ondersteun, maar nie eenvoudige lêers nie.

## Binwalk <a id="binwalk"></a>

**Binwalk** is 'n gereedskap om binêre lêers soos beelde en klanklêers te soek vir ingebedde lêers en data.
Dit kan geïnstalleer word met `apt`, maar die [bron](https://github.com/ReFirmLabs/binwalk) kan op github gevind word.
**Nuttige opdragte**:
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
## Foremost

Nog 'n algemene hulpmiddel om verborge lêers te vind, is **foremost**. Jy kan die konfigurasielêer van foremost in `/etc/foremost.conf` vind. As jy net vir 'n paar spesifieke lêers wil soek, ontkommentarieer hulle. As jy niks ontkommentarieer nie, sal foremost vir sy standaard geconfigureerde lêertipes soek.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
## **Scalpel**

**Scalpel** is 'n ander hulpmiddel wat gebruik kan word om **lêers wat in 'n lêer ingebed is** te vind en te onttrek. In hierdie geval sal jy die lêertipes wat jy wil hê dit moet onttrek, uit die konfigurasielêer \(_/etc/scalpel/scalpel.conf_\) moet ontkommentaar.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
## Bulk Extractor

Hierdie hulpmiddel kom binne kali, maar jy kan dit hier vind: [https://github.com/simsong/bulk_extractor](https://github.com/simsong/bulk_extractor)

Hierdie hulpmiddel kan 'n beeld skandeer en sal **pcaps** daarin **onttrek**, **netwerk inligting\(URLs, domeine, IPs, MACs, e-posse\)** en meer **lêers**. Jy hoef net te doen:
```text
bulk_extractor memory.img -o out_folder
```
Navigeer deur **alle inligting** wat die hulpmiddel versamel het \(wagwoorde?\), **analiseer** die **pakkette** \(lees[ **Pcaps analise**](../pcap-inspection/)\), soek vir **vreemde domeine** \(domeine wat verband hou met **malware** of **nie-bestaande**\).

## PhotoRec

Jy kan dit vind in [https://www.cgsecurity.org/wiki/TestDisk_Download](https://www.cgsecurity.org/wiki/TestDisk_Download)

Dit kom met 'n GUI en CLI weergawe. Jy kan die **lêer-tipes** kies waarvoor jy wil hê PhotoRec moet soek.

![](../../../images/image%20%28524%29.png)

# Spesifieke Data Carving Hulpmiddels

## FindAES

Soek vir AES sleutels deur hul sleutel skedules te soek. In staat om 128, 192, en 256 bit sleutels te vind, soos dié wat deur TrueCrypt en BitLocker gebruik word.

Laai [hier](https://sourceforge.net/projects/findaes/) af.

# Aanvullende hulpmiddels

Jy kan [**viu** ](https://github.com/atanunq/viu) gebruik om beelde vanaf die terminal te sien. 
Jy kan die linux opdraglyn hulpmiddel **pdftotext** gebruik om 'n pdf in teks te transformeer en dit te lees.

{{#include ../../../banners/hacktricks-training.md}}
