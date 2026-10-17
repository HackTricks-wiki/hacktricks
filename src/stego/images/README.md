# Steganografija slike

{{#include ../../banners/hacktricks-training.md}}

Većina CTF steganografije slika svodi se na jednu od ovih kategorija:

- LSB/bit-ravni (PNG/BMP)
- Payloadi u metapodacima/komentarima
- Neobičnosti PNG chunk-ova / popravka oštećenja
- Alati za JPEG DCT domen (OutGuess itd.)
- Zasnovano na frejmovima (GIF/APNG)

## Brza provera

Dajte prednost dokazima na nivou kontejnera pre detaljne analize sadržaja:

- Proverite datoteku i pregledajte strukturu: `file`, `magick identify -verbose`, validatori formata (npr. `pngcheck`).
- Izdvojite metapodatke i vidljive stringove: `exiftool -a -u -g1`, `strings`.
- Proverite da li postoji ugrađen/dodat sadržaj: `binwalk` i pregled kraja datoteke (`tail | xxd`).
- Izaberite pristup prema kontejneru:
  - PNG/BMP: bit-ravni/LSB i anomalije na nivou chunk-ova.
  - JPEG: metapodaci + alati za DCT domen (porodice nalik OutGuess/F5).
  - GIF/APNG: izdvajanje frejmova, poređenje razlika među frejmovima, trikovi s paletom.

## Bit-ravni / LSB

### Tehnika

PNG/BMP su popularni u CTF-ovima zato što čuvaju piksele na način koji omogućava **laku manipulaciju na nivou bitova**. Klasičan mehanizam skrivanja/izdvajanja je sledeći:

- Svaki kanal piksela (R/G/B/A) ima više bitova.
- **Najmanje značajan bit** (LSB) svakog kanala vrlo malo menja sliku.
- Napadači skrivaju podatke u bitovima nižeg reda, ponekad uz korak, permutaciju ili izbor kanala.

Šta možete očekivati u izazovima:

- Payload se nalazi samo u jednom kanalu (npr. LSB kanala `R`).
- Payload se nalazi u alpha kanalu.
- Payload je komprimovan/kodiran nakon izdvajanja.
- Poruka je raspoređena kroz ravni ili skrivena pomoću XOR-a između ravni.

Dodatne porodice na koje možete naići (zavisno od implementacije):

- **LSB matching** (ne samo menjanje bita, već podešavanja +/-1 radi poklapanja sa ciljnim bitom)
- **Skrivanje zasnovano na paleti/indeksima** (indeksirani PNG/GIF: payload je u indeksima boja, a ne u sirovim RGB vrednostima)
- **Payloadi samo u alpha kanalu** (potpuno nevidljivi u RGB prikazu)

### Alati

#### zsteg

`zsteg` ispituje brojne obrasce za izdvajanje LSB/bit-ravni iz PNG/BMP datoteka:

```bash
zsteg -a file.png
```

Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: pokreće niz transformacija (metapodaci, transformacije slike, brute force LSB varijanti).
- `stegsolve`: ručni vizuelni filteri (izdvajanje kanala, pregledanje ravni, XOR itd.).

Preuzimanje Stegsolve-a: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFT trikovi za bolju vidljivost

FFT nije LSB ekstrakcija; koristi se kada je sadržaj namerno sakriven u frekvencijskom prostoru ili suptilnim obrascima.

- EPFL demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Veb-bazirana početna analiza često se koristi u CTF-ovima:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNG struktura: chunks, oštećenja i skriveni podaci

### Tehnika

PNG je format zasnovan na chunks. U mnogim izazovima payload se čuva na nivou kontejnera/chunk-a, a ne u vrednostima piksela:

- **Dodatni bajtovi posle `IEND`** (mnogi pregledači ignorišu završne bajtove)
- **Nestandardni ancillary chunks** koji sadrže payload-e; pogledajte [PNG chunk walker and carving workflow](../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/png-tricks.md#extract-ancillary-chunk-payloads).
- **Oštećena zaglavlja** koja skrivaju dimenzije ili onemogućavaju parsiranje dok se ne poprave

Važne lokacije chunks koje treba proveriti:

- `tEXt` / `iTXt` / `zTXt` (tekstualni metapodaci, ponekad kompresovani)
- `iCCP` (ICC profil) i drugi ancillary chunks koji se koriste kao nosači podataka
- `eXIf` (EXIF podaci u PNG-u)

### Komande za početnu analizu

```bash
magick identify -verbose file.png
pngcheck -v file.png
```

Na šta obratiti pažnju:

- Neobične kombinacije širine/visine/dubine bita/tipa boje
- CRC/greške u chunkovima (pngcheck obično ukazuje na tačan pomak)
- Upozorenja o dodatnim podacima nakon `IEND`

Ako vam treba detaljniji prikaz chunkova:

```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```

Korisne reference:

- PNG specifikacija (struktura, chunks): https://www.w3.org/TR/PNG/
- Trikovi sa formatima datoteka (rubni slučajevi za PNG/JPEG/GIF): https://github.com/corkami/docs

## JPEG: metapodaci, alati za DCT domen i ograničenja ELA

### Tehnika

JPEG se ne čuva kao sirovi pikseli; kompresovan je u DCT domenu. Zato se JPEG stego alati razlikuju od PNG LSB alata:

- Payload-i u metapodacima/komentarima su na nivou datoteke (lako se uočavaju i brzo proveravaju)
- Stego alati za DCT domen ugrađuju bitove u frekvencijske koeficijente

U praksi, JPEG tretirajte kao:

- Kontejner za segmente metapodataka (lako se uočavaju i brzo proveravaju)
- Kompresovani domen signala (DCT koeficijenti) u kom rade specijalizovani stego alati

### Brze provere

```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```

Lokacije sa mnogo signala:

- EXIF/XMP/IPTC metapodaci
- Segment komentara JPEG-a (`COM`)
- Segmenti aplikacija (`APP1` za EXIF, `APPn` za podatke proizvođača)

### Uobičajeni alati

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

Ako konkretno nailazite na steghide payload-e u JPEG-ovima, razmotrite korišćenje alata `stegseek` (brži bruteforce od starijih skripti):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA ističe različite artefakte ponovne kompresije; može da ukaže na oblasti koje su izmenjene, ali sama po sebi nije stego detektor:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Animirane slike

### Tehnika

Kod animiranih slika pretpostavite da je poruka:

- U jednom frejmu (lako), ili
- Raspoređena kroz više frejmova (redosled je važan), ili
- Vidljiva samo kada uporedite susedne frejmove pomoću diff-a

### Izdvajanje frejmova

```bash
ffmpeg -i anim.gif frame_%04d.png
```

Zatim tretirajte kadrove kao obične PNG-ove: `zsteg`, `pngcheck`, izolovanje kanala.

Alternativni alati:

- `gifsicle --explode anim.gif` (brzo izdvajanje kadrova)
- `imagemagick`/`magick` za transformacije svakog kadra

Upoređivanje razlika između kadrova često je presudno:

```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```

### APNG kodiranje brojem piksela

- Detektujte APNG kontejnere: `exiftool -a -G1 file.png | grep -i animation` or `file`.
- Izdvojite frejmove bez promene vremenskog rasporeda: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
- Rekonstruišite payload-e kodirane brojem piksela po frejmu:

```python
from PIL import Image
import glob
out = []
for f in sorted(glob.glob('frames/frame_*.png')):
    counts = Image.open(f).getcolors()
    target = dict(counts).get((255, 0, 255, 255))  # adjust the target color
    out.append(target or 0)
print(bytes(out).decode('latin1'))
```

Animirani izazovi mogu da kodiraju svaki bajt kao broj pojavljivanja određene boje u svakom frejmu; spajanjem tih brojeva rekonstruiše se poruka.<sup>[[1]](#references)</sup>

## Ugrađivanje zaštićeno lozinkom

Ako sumnjate da je ugrađivanje zaštićeno lozinkom, a ne manipulacijom na nivou piksela, ovo je obično najbrži način.

### steghide

Podržava `JPEG, BMP, WAV, AU` i može da ugrađuje/izdvaja šifrovane payloads.

```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```

Repozitorijum: https://github.com/StefanoDeVuono/steghide

### StegCracker

```bash
stegcracker file.jpg wordlist.txt
```

Repozitorijum: https://github.com/Paradoxis/StegCracker

### stegpy

Podržava PNG/BMP/GIF/WebP/WAV.

Repozitorijum: https://github.com/dhsdshdhk/stegpy



## References

- [1] [Flagvent 2025 (Medium) — Roze, Deda Mrazova lista želja, Božićni metapodaci, Uhvaćeni šum](https://0xdf.gitlab.io/flagvent2025/medium)
{{#include ../../banners/hacktricks-training.md}}
