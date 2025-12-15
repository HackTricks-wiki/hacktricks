# Mtiririko wa Stego

{{#include ../../banners/hacktricks-training.md}}

Mara nyingi matatizo ya stego yanatatuliwa haraka zaidi kwa tathmini ya kimfumo kuliko kwa kujaribu zana za nasibu.

## Mtiririko wa msingi

### Orodha ya haraka ya tathmini

Lengo ni kujibu maswali mawili kwa ufanisi:

1. Kontena/umbizo gani halisi?
2. Je, payload iko kwenye metadata, appended bytes, embedded files, au content-level stego?

#### 1) Tambua kontena
```bash
file target
ls -lah target
```
Kama `file` na extension hazikubaliani, amini `file`. Chukulia miundo ya kawaida kuwa containers inapofaa (mf., nyaraka za OOXML ni ZIP files).

#### 2) Tafuta metadata na strings zilizo dhahiri
```bash
exiftool target
strings -n 6 target | head
strings -n 6 target | tail
```
Jaribu encodings mbalimbali:
```bash
strings -e l -n 6 target | head
strings -e b -n 6 target | head
```
#### 3) Angalia data iliyoongezwa / mafaili yaliyowekwa ndani
```bash
binwalk target
binwalk -e target
```
Iki extraction itashindwa lakini signatures zimeripotiwa, kata offsets kwa mkono kwa kutumia `dd` na endesha tena `file` kwenye eneo lililokatwa.

#### 4) Iki ni picha

- Kagua anomali: `magick identify -verbose file`
- Kama PNG/BMP, orodhesha bit-planes/LSB: `zsteg -a file.png`
- Thibitisha muundo wa PNG: `pngcheck -v file.png`
- Tumia vichujio vya kuona (Stegsolve / StegoVeritas) wakati maudhui yanaweza kuonekana kwa mabadiliko ya channel/plane

#### 5) Iki ni sauti

- Angalia spectrogram kwanza (Sonic Visualiser)
- Decode/kagua streams: `ffmpeg -v info -i file -f null -`
- Kama sauti inaonekana kama tones zilizopangwa, jaribu DTMF decoding

### Zana za msingi

Hizi zinakamata kesi za kiwango cha container zinazotokea mara kwa mara: metadata payloads, appended bytes, na embedded files zilizofichwa kwa extension.

#### Binwalk
```bash
binwalk file
binwalk -e file
binwalk --dd '.*' file
```
I don't have direct access to that repo file. Please paste the contents of src/stego/workflow/README.md (or the specific section you want translated). I will translate the English text to Swahili and keep all markdown, tags, links, paths and code unchanged per your instructions.
```bash
foremost -i file
```
#### Exiftool / Exiv2
```bash
exiftool file
exiv2 file
```
#### faili / strings
```bash
file file
strings -n 6 file
```
#### cmp
```bash
cmp original.jpg stego.jpg -b -l
```
### Makontena, data zilizoongezwa, na polyglot tricks

Changamoto nyingi za steganography zinahusiana na byte za ziada baada ya faili halali, au archive zilizowekwa ndani zilizofichwa kwa extension.

#### Payloads zilizoongezwa

Mifumo mingi haziangalii bytes zinazofuata. ZIP/PDF/script zinaweza kuongezwa kwenye kontena la picha/sauti.

Ukaguzi wa haraka:
```bash
binwalk file
tail -c 200 file | xxd
```
Ikiwa unajua offset, carve kwa kutumia `dd`:
```bash
dd if=file of=carved.bin bs=1 skip=<offset>
file carved.bin
```
#### Magic bytes

Wakati `file` ikichanganyikiwa, angalia magic bytes kwa `xxd` na linganisha na signatures zinazojulikana:
```bash
xxd -g 1 -l 32 file
```
#### Zip iliyoficha

Jaribu `7z` na `unzip` hata kama extension haisemi zip:
```bash
7z l file
unzip -l file
```
### Matukio ya ajabu karibu na stego

Viungo vya haraka kwa mifumo inayojitokeza mara kwa mara karibu na stego (QR-from-binary, braille, etc).

#### QR codes kutoka binary

Ikiwa urefu wa blob ni mraba kamili, inaweza kuwa pixels mbichi za picha/QR.
```python
import math
math.isqrt(2500)  # 50
```
Msaidizi wa Binary-to-image:

- https://www.dcode.fr/binary-image

#### Braille

- https://www.branah.com/braille-translator

## Orodha za marejeo

- https://0xrick.github.io/lists/stego/
- https://github.com/DominicBreuker/stego-toolkit

{{#include ../../banners/hacktricks-training.md}}
