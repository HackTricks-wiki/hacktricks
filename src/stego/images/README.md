# Steganografija u slikama

{{#include ../../banners/hacktricks-training.md}}

Većina CTF steganografije u slikama svodi se na jednu od ovih kategorija:

- LSB/bit-plane (PNG/BMP)
- Payload u metapodacima/komentarima
- Neobičnosti u PNG chunkovima / popravka oštećenja
- Alati za JPEG DCT domen (OutGuess itd.)
- Zasnovano na frejmovima (GIF/APNG)

## Brza trijaža

Prvo proverite dokaze na nivou kontejnera, pre detaljne analize sadržaja. Pogledajte [opšti stego postupak](../workflow/) za identifikaciju i izdvajanje sadržaja iz datoteka pre testova specifičnih za slike.

- Proverite datoteku i pregledajte strukturu: `file`, `magick identify -verbose`, alati za proveru formata (npr. `pngcheck`).
- Izdvojite metapodatke i vidljive nizove: `exiftool -a -u -g1`, `strings`.
- Potražite ugrađeni/dodati sadržaj: `binwalk` i pregled kraja datoteke (`tail | xxd`).
- Odaberite granu prema kontejneru:
  - PNG/BMP: bit-plane/LSB i anomalije na nivou chunkova.
  - JPEG: metapodaci i alati za DCT domen (porodice kao što su OutGuess/F5).
  - GIF/APNG: izdvajanje frejmova, poređenje frejmova, trikovi s paletom.

## Bit-plane / LSB

### Tehnika

PNG/BMP su popularni u CTF-ovima jer čuvaju piksele na način koji olakšava **manipulaciju na nivou bitova**. Klasični mehanizam za skrivanje/izdvajanje je sledeći:

- Svaki kanal piksela (R/G/B/A) ima više bitova.
- **Bit najmanje težine** (LSB) svakog kanala vrlo malo menja sliku.
- Napadači skrivaju podatke u tim bitovima nižeg reda, ponekad uz korak, permutaciju ili izbor kanala.

Šta možete očekivati u izazovima:

- Payload je samo u jednom kanalu (npr. LSB kanala `R`).
- Payload je u alpha kanalu.
- Payload je komprimovan/kodiran nakon izdvajanja.
- Poruka je raspoređena po ravnima ili skrivena XOR-ovanjem ravni.

Dodatne porodice na koje možete naići (u zavisnosti od implementacije):

- **LSB matching** (ne menja se samo bit, već se vrednost podešava za +/-1 da bi odgovarala ciljnom bitu)
- **Skrivanje zasnovano na paleti/indeksima** (indeksirani PNG/GIF: payload je u indeksima boja, a ne u sirovim RGB vrednostima)
- **Payload samo u alpha kanalu** (potpuno nevidljiv u RGB prikazu)

### Indeksi palete indeksiranih boja

Indeksirani PNG ili GIF čuva **indeks** palete za svaki piksel, a ne RGB trojku. Dva indeksa mogu odgovarati istoj vidljivoj boji, pa konverzija u RGB pre analize može ukloniti skrivenu razliku. Pregledajte duplirane ili skoro duplirane unose palete, a zatim napravite binarnu masku piksela koji koriste svaki sumnjivi indeks. Ovim su otkriveni skriveni tekst i izmene QR kodova u nedavnim GIF izazovima.<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup>

Za PNG sa indeksiranim bojama i jednim frejmom (ili **prvi frejm** GIF-a), sačuvajte Pillow režim `P` i promenite `target` u zanimljiv indeks koji skripta prijavi. Pri izboru indeksa proverite i transparentnost (`tRNS` ili indeks transparentnosti GIF-a), kao i RGB vrednosti.<sup>[[3]](#references)[[5]](#references)</sup>

```python
from PIL import Image
im = Image.open("suspect.png")
assert im.mode == "P", "requires indexed pixels; do not convert to RGB"
used = sorted(set(im.getdata()))
palette = im.getpalette()
for i in used:
    same = [j for j in used if j != i and palette[3*i:3*i+3] == palette[3*j:3*j+3]]
    if same:
        print(i, "shares RGB with", same)
target = 1  # replace with an index to isolate
mask = bytes(255 if i == target else 0 for i in im.getdata())
Image.frombytes("L", im.size, mask).save("index-mask.png")
```

Za animirane GIF-ove, pregledajte svaki frejm zasebno. Pillow obično konvertuje kasnije frejmove u RGB/RGBA tokom kompozicije; `GifImagePlugin.LOADING_STRATEGY = GifImagePlugin.LoadingStrategy.RGB_AFTER_DIFFERENT_PALETTE_ONLY` zadržava režim `P` samo dok se paleta ne promeni. Ako frejm ima lokalnu paletu ili je već komponovan, pregledajte njegove originalne indeksirane podatke umesto da RGB-konvertovane piksele tretirate kao indekse.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

### Alati

#### zsteg

`zsteg` enumeriše brojne obrasce izdvajanja LSB/bit-plane podataka iz PNG/BMP fajlova:

```bash
zsteg -a file.png
```

Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: pokreće niz transformacija (metapodaci, transformacije slike, brute force varijanti LSB-a).
- `stegsolve`: ručni vizuelni filteri (izdvajanje kanala, pregled ravni, XOR itd.).

Preuzimanje Stegsolve-a: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### Trikovi za uočavanje zasnovani na FFT-u

FFT nije izdvajanje LSB-a; koristi se u slučajevima kada je sadržaj namerno skriven u frekvencijskom prostoru ili suptilnim obrascima.

- EPFL demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Veb-alati za početnu analizu često se koriste na CTF takmičenjima:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## Interni detalji PNG-a: chunkovi, oštećenja i skriveni podaci

### Tehnika

PNG je format podeljen na chunkove. U mnogim izazovima, payload se čuva na nivou kontejnera/chunka, a ne u vrednostima piksela:

- **Dodatni bajtovi posle `IEND`** (mnogi pregledači ignorišu završne bajtove)
- **Nestandardni pomoćni chunkovi** koji nose payload; pogledajte [PNG alat za prolazak kroz chunkove i tok rada za izdvajanje podataka](../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/png-tricks.md#extract-ancillary-chunk-payloads).
- **Oštećena zaglavlja** koja skrivaju dimenzije ili onemogućavaju rad parsera dok se ne poprave

Važne lokacije chunkova koje treba proveriti:

- `tEXt` / `iTXt` / `zTXt` (tekstualni metapodaci, ponekad kompresovani)
- `iCCP` (ICC profil) i drugi pomoćni chunkovi koji se koriste kao nosioci
- `eXIf` (EXIF podaci u PNG-u)

### Bajtovi filtera PNG scanline-a kao nosilac podataka

PNG čuva jedan bajt tipa filtera (0–4) pre svakog scanline-a u dekompresovanom `IDAT` toku. Ti bajtovi nisu vrednosti piksela; dekodirani RGB pikseli ne čuvaju izvorne izbore filtera, a ponovno kodiranje može da ih promeni. Enkoder može legitimno da koristi različite filtere, ali namerni obrasci mogu da kodiraju kratku poruku; u nedavnom izazovu vrednosti filtera 1–4 korišćene su kao dvo-bitni simboli. Pregledajte **izvornu datoteku** i konkatenirajte sve `IDAT` podatke pre dekompresije. U sledećem slučaju, koji nije prožet i koristi 8-bitni RGB/RGBA, stride je širina pomnožena brojem kanala; Adam7 slike zahtevaju širine scanline-a specifične za svaki prolaz.<sup>[[3]](#references)[[7]](#references)</sup>

<details>
<summary>Prikaži bajtove filtera PNG scanline-a bez ponovnog kodiranja</summary>

```python
from pathlib import Path
import struct, sys, zlib
b = Path(sys.argv[1]).read_bytes()
assert b[:8] == b"\x89PNG\r\n\x1a\n"
w, h, depth, color, comp, method, interlace = struct.unpack(">IIBBBBB", b[16:29])
assert (depth, color, comp, method, interlace) in ((8, 2, 0, 0, 0), (8, 6, 0, 0, 0))
stride = w * (3 if color == 2 else 4)
off, parts = 8, []
while off + 12 <= len(b):
    n = int.from_bytes(b[off:off+4], "big")
    kind = b[off+4:off+8]
    assert off + n + 12 <= len(b)
    if kind == b"IDAT":
        parts.append(b[off+8:off+8+n])
    off += n + 12
    if kind == b"IEND":
        break
raw = zlib.decompress(b"".join(parts))
assert len(raw) == h * (stride + 1)
filters = raw[::stride+1]
assert all(f <= 4 for f in filters)
print(filters.hex(" "))
```

</details>

Pokrenite je kao `python3 filters.py suspect.png`. Proverite da li niz filtera, a ne dekodirani pikseli, prati verovatno mapiranje simbola. Izbor mapiranja zavisi od izazova; sama varijacija nije dokaz steganografije.<sup>[[3]](#references)[[7]](#references)</sup>

### Komande za trijažu

```bash
magick identify -verbose file.png
pngcheck -v file.png
```

Šta treba tražiti:

- Neobične kombinacije širine/visine/dubine boje/tipa boje
- CRC/greške u chunk-ovima (pngcheck obično ukazuje na tačan pomak)
- Upozorenja o dodatnim podacima nakon `IEND`

Ako vam treba detaljniji prikaz chunk-ova:

```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```

Korisne reference:

- PNG specifikacija (struktura, chunk-ovi): https://www.w3.org/TR/PNG/
- Trikovi sa formatima datoteka (rubni slučajevi PNG/JPEG/GIF): https://github.com/corkami/docs

## JPEG: metadata, alati za DCT domen i ograničenja ELA

### Tehnika

JPEG se ne čuva kao sirovi pikseli; kompresuje se u DCT domenu. Zato se JPEG stego alati razlikuju od PNG LSB alata:

- Payload-i u metadata/komentarima nalaze se na nivou datoteke (visok signal i brza provera)
- Stego alati u DCT domenu ugrađuju bitove u frekvencijske koeficijente

U praksi, JPEG posmatrajte kao:

- Kontejner za metadata segmente (visok signal, brza provera)
- Domen kompresovanog signala (DCT koeficijenti) u kojem rade specijalizovani stego alati

### Brze provere

```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```

Lokacije sa najviše signala:

- EXIF/XMP/IPTC metapodaci
- JPEG segment komentara (`COM`)
- Segmenti aplikacija (`APP1` za EXIF, `APPn` za podatke proizvođača)

### Uobičajeni alati

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

Ako konkretno nailazite na steghide payload-e u JPEG-ovima, razmotrite upotrebu alata `stegseek` (brži bruteforce od starijih skripti):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA ističe različite artefakte ponovne kompresije; može da vas usmeri ka oblastima koje su izmenjene, ali sam po sebi nije stego detektor:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Animirane slike

### Tehnika

Kod animiranih slika pretpostavite da se poruka nalazi:

- U jednom kadru (lako), ili
- Raspoređena kroz više kadrova (redosled je važan), ili
- Vidljiva samo kada uporedite uzastopne kadrove

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

- Detektujte APNG kontejnere: `exiftool -a -G1 file.png | grep -i animation` ili `file`.
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

Animirani izazovi mogu da kodiraju svaki bajt kao broj piksela određene boje u svakom kadru; spajanjem tih brojeva rekonstruiše se poruka.<sup>[[1]](#references)</sup>

## Ugrađivanje zaštićeno lozinkom

Ako sumnjate da je ugrađivanje zaštićeno lozinkom, a ne zasnovano na manipulaciji na nivou piksela, ovo je obično najbrži pristup.

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

- [1] [Flagvent 2025 (Medium) — pink, Santa-in spisak želja, Božićni metapodaci, uhvaćeni šum](https://0xdf.gitlab.io/flagvent2025/medium)
- [2] [HackVent 2024 write-up — Izokrenute boje](https://www.bigigloo.de/download/Write-Up_HackVent_2024.pdf)
- [3] [Specifikacija Portable Network Graphics (PNG), treće izdanje](https://www.w3.org/TR/png-3/)
- [4] [XESXOR — Duboko dole, nešto je u vodi](https://www.xesxor.com/writeups/custom-other-deep-down-there-s-something-in-the-water)
- [5] [Pillow formati slikovnih datoteka — GIF](https://pillow.readthedocs.io/en/stable/handbook/image-file-formats.html)
- [6] [Specifikacija GIF89a](https://giflib.sourceforge.net/gifstandard/GIF89a.html)
- [7] [Protokol Afterimage — CTF write-up](https://github.com/Team-Cyfer-Trace/Crest-CTF-2.0-Writeup-by-Cyfer-Trace/blob/main/stegno/Afterimage-Protocol/writeup.md)
{{#include ../../banners/hacktricks-training.md}}
