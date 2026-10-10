# Steganografija slike

{{#include ../../banners/hacktricks-training.md}}

Većina steganografije slika u CTF-ovima svodi se na jednu od ovih kategorija:

- LSB/ravni bitova (PNG/BMP)
- Payload-i u metapodacima/komentarima
- Neobičnosti/oštećenja PNG chunk-ova i njihova popravka
- Alati za JPEG DCT domen (OutGuess itd.)
- Zasnovano na frejmovima (GIF/APNG)

## Brza početna provera

Dajte prednost dokazima na nivou kontejnera pre detaljne analize sadržaja:

- Proverite datoteku i pregledajte strukturu: `file`, `magick identify -verbose`, validatori formata (npr. `pngcheck`).
- Izdvojite metapodatke i vidljive stringove: `exiftool -a -u -g1`, `strings`.
- Proverite da li postoji ugrađen/dodat sadržaj: `binwalk` i pregled kraja datoteke (`tail | xxd`).
- Odaberite granu prema kontejneru:
  - PNG/BMP: ravni bitova/LSB i nepravilnosti na nivou chunk-ova.
  - JPEG: metapodaci i alati za DCT domen (porodice nalik OutGuess/F5).
  - GIF/APNG: izdvajanje frejmova, poređenje frejmova i trikovi s paletama.

## Ravni bitova / LSB

### Tehnika

PNG/BMP su popularni u CTF-ovima jer čuvaju piksele na način koji olakšava **manipulaciju na nivou bitova**. Klasičan mehanizam skrivanja/izdvajanja je:

- Svaki kanal piksela (R/G/B/A) sadrži više bitova.
- **Bit najmanje težine** (LSB) svakog kanala veoma malo menja sliku.
- Napadači skrivaju podatke u tim nižim bitovima, ponekad uz korak, permutaciju ili izbor kanala.

Šta možete očekivati u izazovima:

- Payload je samo u jednom kanalu (npr. LSB kanala `R`).
- Payload je u alpha kanalu.
- Payload se komprimuje/kodira nakon izdvajanja.
- Poruka je raspoređena po ravnima ili skrivena pomoću XOR-a između ravni.

Dodatne porodice koje možete sresti (zavisno od implementacije):

- **LSB matching** (ne samo preokretanje bita već i korekcije +/-1 radi podudaranja sa ciljnim bitom)
- **Skrivanje zasnovano na paleti/indeksu** (indeksirani PNG/GIF: payload je u indeksima boja, a ne u sirovim RGB vrednostima)
- **Payload-i samo u alpha kanalu** (potpuno nevidljivi u RGB prikazu)

### Alati

#### zsteg

`zsteg` nabraja mnoge obrasce za izdvajanje LSB-a/ravni bitova iz PNG/BMP datoteka:

```bash
zsteg -a file.png
```

Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: pokreće niz transformacija (metapodaci, transformacije slike, brute forcing LSB varijanti).
- `stegsolve`: ručni vizuelni filteri (izdvajanje kanala, pregled ravni, XOR itd.).

Preuzimanje Stegsolve-a: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### Trikovi za uočavanje zasnovani na FFT-u

FFT nije LSB ekstrakcija; koristi se u slučajevima kada je sadržaj namerno skriven u frekvencijskom prostoru ili suptilnim šablonima.

- EPFL demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Veb-alati za trijažu koji se često koriste u CTF-ovima:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNG interni format: chunk-ovi, oštećenje i skriveni podaci

### Tehnika

PNG je format zasnovan na chunk-ovima. U mnogim izazovima payload se čuva na nivou kontejnera/chunk-a, a ne u vrednostima piksela:

- **Dodatni bajtovi posle `IEND`** (mnogi preglednici ignorišu završne bajtove)
- **Nestandardni pomoćni chunk-ovi** koji nose payload
- **Oštećena zaglavlja** koja skrivaju dimenzije ili ometaju parsere dok se ne poprave

Važna mesta u chunk-ovima za proveru:

- `tEXt` / `iTXt` / `zTXt` (tekstualni metapodaci, ponekad komprimovani)
- `iCCP` (ICC profil) i drugi pomoćni chunk-ovi koji se koriste kao nosač podataka
- `eXIf` (EXIF podaci u PNG-u)

### Naredbe za trijažu

```bash
magick identify -verbose file.png
pngcheck -v file.png
```

Na šta treba obratiti pažnju:

- Neobične kombinacije širine/visine/dubine boje/tipa boje
- CRC greške i greške u chunkovima (pngcheck obično ukazuje na tačan pomeraj)
- Upozorenja o dodatnim podacima nakon `IEND`

Ako vam treba detaljniji prikaz chunkova:

```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```

Korisne reference:

- PNG specifikacija (struktura, chunks): https://www.w3.org/TR/PNG/
- Trikovi s formatima datoteka (granični slučajevi PNG/JPEG/GIF): https://github.com/corkami/docs

## JPEG: metapodaci, alati za DCT domen i ograničenja ELA

### Tehnika

JPEG se ne čuva kao sirovi pikseli; kompresuje se u DCT domenu. Zato se JPEG stego alati razlikuju od PNG LSB alata:

- Sadržaji metapodataka/komentara nalaze se na nivou datoteke (lako ih je uočiti i brzo pregledati)
- Stego alati za DCT domen ugrađuju bitove u frekvencijske koeficijente

U praksi, JPEG posmatrajte kao:

- Kontejner za segmente metapodataka (lako ih je uočiti i brzo pregledati)
- Kompresovani signalni domen (DCT koeficijenti) u kojem rade specijalizovani stego alati

### Brze provere

```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```

Lokacije sa jakim signalom:

- EXIF/XMP/IPTC metapodaci
- JPEG segment komentara (`COM`)
- Segmenti aplikacije (`APP1` za EXIF, `APPn` za podatke dobavljača)

### Uobičajeni alati

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

Ako se konkretno bavite steghide payload-ima u JPEG-ovima, razmotrite korišćenje alata `stegseek` (brži bruteforce od starijih skripti):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA ističe različite artefakte ponovne kompresije; može vam ukazati na oblasti koje su menjane, ali sam po sebi nije stego detektor:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Animirane slike

### Tehnika

Kod animiranih slika pretpostavite da se poruka nalazi:

- U jednom kadru (lako), ili
- Raspoređena kroz više kadrova (redosled je važan), ili
- Vidljiva je samo kada uporedite uzastopne kadrove

### Izdvajanje kadrova

```bash
ffmpeg -i anim.gif frame_%04d.png
```

Zatim tretirajte frejmove kao obične PNG-ove: `zsteg`, `pngcheck`, izolacija kanala.

Alternativni alati:

- `gifsicle --explode anim.gif` (brzo izdvajanje frejmova)
- `imagemagick`/`magick` za transformacije pojedinačnih frejmova

Poređenje razlika između frejmova često je presudno:

```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```

### APNG kodiranje brojem piksela

- Otkrijte APNG kontejnere: `exiftool -a -G1 file.png | grep -i animation` ili `file`.
- Izdvojite kadrove bez menjanja vremenskog rasporeda: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
- Vratite payload-ove kodirane brojem piksela po kadru:

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

Animirani izazovi mogu kodirati svaki bajt kao broj pojavljivanja određene boje u svakom frejmu; spajanjem tih brojeva rekonstruiše se poruka.<sup>[[1]](#references)</sup>

## Umetanje zaštićeno lozinkom

Ako sumnjate da je umetanje zaštićeno lozinkom umesto da se koristi manipulacija na nivou piksela, ovo je obično najbrži pristup.

### steghide

Podržava `JPEG, BMP, WAV, AU` i može da umeće/izvlači šifrovane payload-e.

```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```

Repo: https://github.com/StefanoDeVuono/steghide

### StegCracker

```bash
stegcracker file.jpg wordlist.txt
```

Repozitorijum: https://github.com/Paradoxis/StegCracker

### stegpy

Podržava PNG/BMP/GIF/WebP/WAV.

Repozitorijum: https://github.com/dhsdshdhk/stegpy

## References

- [1] [Flagvent 2025 (Medium) — ružičasto, Deda Mrazova lista želja, Božićni metapodaci, Uhvaćeni šum](https://0xdf.gitlab.io/flagvent2025/medium)
{{#include ../../banners/hacktricks-training.md}}
