# Stego Workflow

{{#include ../../banners/hacktricks-training.md}}

Matatizo mengi ya stego hutatuliwa haraka zaidi kwa triage ya kimfumo kuliko kujaribu tools za kubahatisha.

## Mtiririko mkuu

### Orodha ya ukaguzi wa triage ya haraka

Lengo ni kujibu maswali mawili kwa ufanisi:

1. Container/format halisi ni ipi?
2. Je, payload iko kwenye metadata, bytes zilizoongezwa mwishoni, files zilizopachikwa, au stego ya kiwango cha maudhui?

#### 1) Tambua container
```bash
file target
ls -lah target
```
Ikiwa `file` na kiendelezi havikubaliani, amini `file`. Chukulia miundo ya kawaida kama containers inapofaa (kwa mfano, hati za OOXML ni faili za ZIP).

#### 2) Tafuta metadata na strings zilizo wazi
```bash
exiftool target
strings -n 6 target | head
strings -n 6 target | tail
```
Jaribu encoding nyingi:
```bash
strings -e l -n 6 target | head
strings -e b -n 6 target | head
```
#### 3) Kagua data iliyoongezwa / files zilizopachikwa
```bash
binwalk target
binwalk -e target
```
Ikiwa uchimbaji hautafaulu lakini signatures zimeripotiwa, kata offsets mwenyewe kwa `dd` na uendeshe tena `file` kwenye eneo lililokatwa.

#### 4) Ikiwa ni picha

- Kagua anomalies: `magick identify -verbose file`
- Ikiwa ni PNG/BMP, orodhesha bit-planes/LSB: `zsteg -a file.png`
- Thibitisha muundo wa PNG: `pngcheck -v file.png`
- Tumia visual filters (Stegsolve / StegoVeritas) wakati maudhui yanaweza kufichuliwa kupitia mabadiliko ya channel/plane

#### 5) Ikiwa ni sauti

- Anza na spectrogram (Sonic Visualiser)
- Decode/kagua streams: `ffmpeg -v info -i file -f null -`
- Ikiwa sauti inafanana na tones zilizopangiliwa, jaribu DTMF decoding

### Zana za msingi

Hizi hugundua hali za kawaida za kiwango cha container: metadata payloads, bytes zilizoongezwa, na files zilizopachikwa zilizofichwa kwa extension.<sup>[[1]](#references)</sup>

#### Binwalk
```bash
binwalk file
binwalk -e file
binwalk --dd '.*' file
```
Repo: https://github.com/ReFirmLabs/binwalk

#### Foremost
```bash
foremost -i file
```
Repo: https://github.com/korczis/foremost

#### Exiftool / Exiv2
```bash
exiftool file
exiv2 file
```
#### file / strings
```bash
file file
strings -n 6 file
```
#### cmp
```bash
cmp original.jpg stego.jpg -b -l
```
### Containers, data iliyoongezwa, na mbinu za polyglot

Changamoto nyingi za steganography huwa na bytes za ziada baada ya faili halali, au archives zilizopachikwa zikifichwa kwa extension.

#### Payloads zilizoongezwa

Formats nyingi hupuuza bytes za mwisho. ZIP/PDF/script inaweza kuongezwa kwenye container ya image/audio.

Ukaguzi wa haraka:
```bash
binwalk file
tail -c 200 file | xxd
```
Ikiwa unajua offset, tumia `dd` kufanya carving:
```bash
dd if=file of=carved.bin bs=1 skip=<offset>
file carved.bin
```
#### Magic bytes

Wakati `file` inapochanganyikiwa, tafuta magic bytes kwa `xxd` na uzilinganishe na signatures zinazojulikana:
```bash
xxd -g 1 -l 32 file
```
#### Zip-in-disguise

Jaribu `7z` na `unzip` hata kama extension haionyeshi kuwa ni zip:
```bash
7z l file
unzip -l file
```
### Mambo ya ajabu yaliyo karibu na stego

Viungo vya haraka vya mifumo inayojitokeza mara kwa mara karibu na stego (QR-from-binary, braille, n.k.).

#### QR codes kutoka binary

Ikiwa urefu wa blob ni square kamili, huenda ikawa pixels ghafi za image/QR.
```python
import math
math.isqrt(2500)  # 50
```
Msaidizi wa binary-kwa-picha:

- [https://www.dcode.fr/binary-image](https://www.dcode.fr/binary-image)

#### Braille

- [https://www.branah.com/braille-translator](https://www.branah.com/braille-translator)

## Marejeo

- [1] [DominicBreuker/stego-toolkit - Docker image yenye zana maarufu zaidi za steganography zilizokusanywa pamoja](https://github.com/DominicBreuker/stego-toolkit)

{{#include ../../banners/hacktricks-training.md}}
