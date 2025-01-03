{{#include ../../../banners/hacktricks-training.md}}

# Carving-Tools

## Autopsy

Das am häufigsten verwendete Tool in der Forensik zum Extrahieren von Dateien aus Images ist [**Autopsy**](https://www.autopsy.com/download/). Laden Sie es herunter, installieren Sie es und lassen Sie es die Datei verarbeiten, um "versteckte" Dateien zu finden. Beachten Sie, dass Autopsy entwickelt wurde, um Disk-Images und andere Arten von Images zu unterstützen, jedoch keine einfachen Dateien.

## Binwalk <a id="binwalk"></a>

**Binwalk** ist ein Tool zum Suchen von Binärdateien wie Bildern und Audiodateien nach eingebetteten Dateien und Daten. Es kann mit `apt` installiert werden, die [Quelle](https://github.com/ReFirmLabs/binwalk) ist jedoch auf GitHub zu finden.  
**Nützliche Befehle**:
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
## Foremost

Ein weiteres gängiges Tool, um versteckte Dateien zu finden, ist **foremost**. Die Konfigurationsdatei von foremost finden Sie unter `/etc/foremost.conf`. Wenn Sie nur nach bestimmten Dateien suchen möchten, kommentieren Sie diese aus. Wenn Sie nichts auskommentieren, sucht foremost nach den standardmäßig konfigurierten Dateitypen.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
## **Scalpel**

**Scalpel** ist ein weiteres Tool, das verwendet werden kann, um **Dateien, die in einer Datei eingebettet sind**, zu finden und zu extrahieren. In diesem Fall müssen Sie die Dateitypen, die Sie extrahieren möchten, aus der Konfigurationsdatei \(_/etc/scalpel/scalpel.conf_\) auskommentieren.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
## Bulk Extractor

Dieses Tool ist in Kali enthalten, kann aber hier gefunden werden: [https://github.com/simsong/bulk_extractor](https://github.com/simsong/bulk_extractor)

Dieses Tool kann ein Image scannen und wird **pcaps** darin **extrahieren**, **Netzwerkinformationen (URLs, Domains, IPs, MACs, Mails)** und weitere **Dateien**. Sie müssen nur Folgendes tun:
```text
bulk_extractor memory.img -o out_folder
```
Navigieren Sie durch **alle Informationen**, die das Tool gesammelt hat \(Passwörter?\), **analysieren** Sie die **Pakete** \(lesen[ **Pcaps-Analyse**](../pcap-inspection/)\), suchen Sie nach **seltsamen Domains** \(Domains, die mit **Malware** oder **nicht existierenden** in Verbindung stehen\).

## PhotoRec

Sie finden es unter [https://www.cgsecurity.org/wiki/TestDisk_Download](https://www.cgsecurity.org/wiki/TestDisk_Download)

Es kommt mit einer GUI- und CLI-Version. Sie können die **Dateitypen** auswählen, nach denen PhotoRec suchen soll.

![](../../../images/image%20%28524%29.png)

# Spezifische Daten-Carving-Tools

## FindAES

Sucht nach AES-Schlüsseln, indem es nach ihren Schlüsselschemata sucht. In der Lage, 128, 192 und 256 Bit Schlüssel zu finden, wie sie von TrueCrypt und BitLocker verwendet werden.

Laden Sie [hier](https://sourceforge.net/projects/findaes/) herunter.

# Ergänzende Werkzeuge

Sie können [**viu** ](https://github.com/atanunq/viu) verwenden, um Bilder aus dem Terminal anzuzeigen.  
Sie können das Linux-Befehlszeilenwerkzeug **pdftotext** verwenden, um ein PDF in Text umzuwandeln und es zu lesen.

{{#include ../../../banners/hacktricks-training.md}}
