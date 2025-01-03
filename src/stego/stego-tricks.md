# Stego Tricks

{{#include ../banners/hacktricks-training.md}}

## **Estrazione di Dati da File**

### **Binwalk**

Uno strumento per cercare file binari per file e dati nascosti incorporati. È installato tramite `apt` e il suo sorgente è disponibile su [GitHub](https://github.com/ReFirmLabs/binwalk).
```bash
binwalk file # Displays the embedded data
binwalk -e file # Extracts the data
binwalk --dd ".*" file # Extracts all data
```
### **Foremost**

Recupera file basati sui loro header e footer, utile per le immagini png. Installato tramite `apt` con la sua sorgente su [GitHub](https://github.com/korczis/foremost).
```bash
foremost -i file # Extracts data
```
### **Exiftool**

Aiuta a visualizzare i metadati dei file, disponibile [qui](https://www.sno.phy.queensu.ca/~phil/exiftool/).
```bash
exiftool file # Shows the metadata
```
### **Exiv2**

Simile a exiftool, per la visualizzazione dei metadati. Installabile tramite `apt`, sorgente su [GitHub](https://github.com/Exiv2/exiv2), e ha un [sito ufficiale](http://www.exiv2.org/).
```bash
exiv2 file # Shows the metadata
```
### **File**

Identifica il tipo di file con cui stai lavorando.

### **Strings**

Estrae stringhe leggibili dai file, utilizzando varie impostazioni di codifica per filtrare l'output.
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
### **Confronto (cmp)**

Utile per confrontare un file modificato con la sua versione originale trovata online.
```bash
cmp original.jpg stego.jpg -b -l
```
## **Estrazione di Dati Nascosti nel Testo**

### **Dati Nascosti negli Spazi**

Caratteri invisibili in spazi apparentemente vuoti possono nascondere informazioni. Per estrarre questi dati, visita [https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder).

## **Estrazione di Dati dalle Immagini**

### **Identificazione dei Dettagli dell'Immagine con GraphicMagick**

[GraphicMagick](https://imagemagick.org/script/download.php) serve a determinare i tipi di file immagine e identificare potenziali corruzioni. Esegui il comando qui sotto per ispezionare un'immagine:
```bash
./magick identify -verbose stego.jpg
```
Per tentare di riparare un'immagine danneggiata, aggiungere un commento nei metadati potrebbe aiutare:
```bash
./magick mogrify -set comment 'Extraneous bytes removed' stego.jpg
```
### **Steghide per la Cancellazione dei Dati**

Steghide facilita la nascosta dei dati all'interno di file `JPEG, BMP, WAV e AU`, capace di incorporare ed estrarre dati crittografati. L'installazione è semplice utilizzando `apt`, e il suo [codice sorgente è disponibile su GitHub](https://github.com/StefanoDeVuono/steghide).

**Comandi:**

- `steghide info file` rivela se un file contiene dati nascosti.
- `steghide extract -sf file [--passphrase password]` estrae i dati nascosti, la password è facoltativa.

Per l'estrazione basata sul web, visita [questo sito web](https://futureboy.us/stegano/decinput.html).

**Attacco Bruteforce con Stegcracker:**

- Per tentare di decifrare la password su Steghide, utilizza [stegcracker](https://github.com/Paradoxis/StegCracker.git) come segue:
```bash
stegcracker <file> [<wordlist>]
```
### **zsteg per file PNG e BMP**

zsteg si specializza nel rivelare dati nascosti in file PNG e BMP. L'installazione avviene tramite `gem install zsteg`, con il suo [source on GitHub](https://github.com/zed-0xff/zsteg).

**Comandi:**

- `zsteg -a file` applica tutti i metodi di rilevamento su un file.
- `zsteg -E file` specifica un payload per l'estrazione dei dati.

### **StegoVeritas e Stegsolve**

**stegoVeritas** controlla i metadati, esegue trasformazioni delle immagini e applica il brute forcing LSB tra le altre funzionalità. Usa `stegoveritas.py -h` per un elenco completo delle opzioni e `stegoveritas.py stego.jpg` per eseguire tutti i controlli.

**Stegsolve** applica vari filtri di colore per rivelare testi o messaggi nascosti all'interno delle immagini. È disponibile su [GitHub](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve).

### **FFT per la Rilevazione di Contenuti Nascosti**

Le tecniche di Fast Fourier Transform (FFT) possono svelare contenuti nascosti nelle immagini. Risorse utili includono:

- [EPFL Demo](http://bigwww.epfl.ch/demo/ip/demos/FFT/)
- [Ejectamenta](https://www.ejectamenta.com/Fourifier-fullscreen/)
- [FFTStegPic su GitHub](https://github.com/0xcomposure/FFTStegPic)

### **Stegpy per file audio e immagini**

Stegpy consente di incorporare informazioni in file immagine e audio, supportando formati come PNG, BMP, GIF, WebP e WAV. È disponibile su [GitHub](https://github.com/dhsdshdhk/stegpy).

### **Pngcheck per l'analisi dei file PNG**

Per analizzare file PNG o per convalidarne l'autenticità, usa:
```bash
apt-get install pngcheck
pngcheck stego.png
```
### **Strumenti Aggiuntivi per l'Analisi delle Immagini**

Per ulteriori esplorazioni, considera di visitare:

- [Magic Eye Solver](http://magiceye.ecksdee.co.uk/)
- [Image Error Level Analysis](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)
- [Outguess](https://github.com/resurrecting-open-source-projects/outguess)
- [OpenStego](https://www.openstego.com/)
- [DIIT](https://diit.sourceforge.net/)

## **Estrazione di Dati da Audio**

**Audio steganography** offre un metodo unico per nascondere informazioni all'interno di file audio. Vengono utilizzati diversi strumenti per incorporare o recuperare contenuti nascosti.

### **Steghide (JPEG, BMP, WAV, AU)**

Steghide è uno strumento versatile progettato per nascondere dati in file JPEG, BMP, WAV e AU. Istruzioni dettagliate sono fornite nella [documentazione sui trucchi stego](stego-tricks.md#steghide).

### **Stegpy (PNG, BMP, GIF, WebP, WAV)**

Questo strumento è compatibile con una varietà di formati tra cui PNG, BMP, GIF, WebP e WAV. Per ulteriori informazioni, fai riferimento alla [sezione di Stegpy](stego-tricks.md#stegpy-png-bmp-gif-webp-wav).

### **ffmpeg**

ffmpeg è cruciale per valutare l'integrità dei file audio, evidenziando informazioni dettagliate e individuando eventuali discrepanze.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
### **WavSteg (WAV)**

WavSteg eccelle nel nascondere ed estrarre dati all'interno di file WAV utilizzando la strategia del bit meno significativo. È accessibile su [GitHub](https://github.com/ragibson/Steganography#WavSteg). I comandi includono:
```bash
python3 WavSteg.py -r -b 1 -s soundfile -o outputfile

python3 WavSteg.py -r -b 2 -s soundfile -o outputfile
```
### **Deepsound**

Deepsound consente la crittografia e la rilevazione di informazioni all'interno di file audio utilizzando AES-256. Può essere scaricato dalla [pagina ufficiale](http://jpinsoft.net/deepsound/download.aspx).

### **Sonic Visualizer**

Uno strumento prezioso per l'ispezione visiva e analitica dei file audio, Sonic Visualizer può rivelare elementi nascosti non rilevabili con altri mezzi. Visita il [sito ufficiale](https://www.sonicvisualiser.org/) per ulteriori informazioni.

### **DTMF Tones - Dial Tones**

La rilevazione dei toni DTMF nei file audio può essere ottenuta tramite strumenti online come [questo rilevatore DTMF](https://unframework.github.io/dtmf-detect/) e [DialABC](http://dialabc.com/sound/detect/index.html).

## **Altre Tecniche**

### **Binary Length SQRT - QR Code**

I dati binari che si elevano al quadrato per diventare un numero intero potrebbero rappresentare un codice QR. Usa questo frammento per controllare:
```python
import math
math.sqrt(2500) #50
```
Per la conversione da binario a immagine, controlla [dcode](https://www.dcode.fr/binary-image). Per leggere i codici QR, usa [questo lettore di codici a barre online](https://online-barcode-reader.inliteresearch.com/).

### **Traduzione in Braille**

Per tradurre il Braille, il [Branah Braille Translator](https://www.branah.com/braille-translator) è una risorsa eccellente.

## **Riferimenti**

- [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/)
- [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)

{{#include ../banners/hacktricks-training.md}}
