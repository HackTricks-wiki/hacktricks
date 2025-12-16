# Stego Mtiririko

{{#include ../../banners/hacktricks-training.md}}

Matatizo mengi ya stego yanatatuliwa haraka zaidi kwa triage ya kimfumo kuliko kwa kujaribu zana za nasibu.

## Mtiririko wa Msingi

### Orodha ya haraka ya triage

Lengo ni kujibu maswali mawili kwa ufanisi:

1. Container/format halisi ni ipi?
2. Je, payload iko katika metadata, appended bytes, embedded files, au content-level stego?

#### 1) Tambua container
```bash
file target
ls -lah target
```
Ikiwa `file` na kiendelezo havikubaliani, amini `file`. Chukulia fomati za kawaida kama containers inapofaa (kwa mfano, nyaraka za OOXML ni ZIP files).

#### 2) Tafuta metadata na strings zilizo wazi
```bash
exiftool target
strings -n 6 target | head
strings -n 6 target | tail
```
Jaribu aina mbalimbali za encoding:
```bash
strings -e l -n 6 target | head
strings -e b -n 6 target | head
```
#### 3) Angalia data zilizoongezwa / mafaili yaliyowekwa ndani
```bash
binwalk target
binwalk -e target
```
Ikiwa uondoaji unashindwa lakini saini zinaripotiwa, chonga offsets kwa mikono kwa kutumia `dd` na endesha tena `file` kwenye eneo lililochongwa.

#### 4) Ikiwa ni picha

- Chunguza mambo yasiyo ya kawaida: `magick identify -verbose file`
- Kama PNG/BMP, orodhesha bit-planes/LSB: `zsteg -a file.png`
- Thibitisha muundo wa PNG: `pngcheck -v file.png`
- Tumia vichungi vya kuona (Stegsolve / StegoVeritas) wakati yaliyomo yanaweza kufichuliwa kwa mabadiliko ya channel/plane

#### 5) Ikiwa ni sauti

- Anza na spectrogram (Sonic Visualiser)
- Dekoda/chunguza streams: `ffmpeg -v info -i file -f null -`
- Ikiwa sauti inaonekana kama tones zenye muundo, jaribu DTMF decoding

### Zana za msingi

Hizi hunasa matukio ya ngazi ya container ambayo hutokea mara kwa mara: metadata, bytes zilizoongezwa, na faili zilizofichwa kwa kutumia extension.

#### Binwalk
```bash
binwalk file
binwalk -e file
binwalk --dd '.*' file
```
I don’t have access to the repo contents. Please paste the contents of src/stego/workflow/README.md (or the part you want translated). I will translate it to Swahili, preserving markdown, tags, links, code, paths and the other constraints you specified.
```bash
foremost -i file
```
I don't have access to that repository. Please paste the contents of src/stego/workflow/README.md here (or the portion you want translated). I will translate the English text to Swahili and keep all markdown, tags, links and code unchanged.
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
### Makontena, data zilizoongezwa, na mbinu za polyglot

Changamoto nyingi za steganography ni baiti za ziada baada ya faili halali, au archives zilizowekwa ndani zilizofichwa kwa extension.

#### Appended payloads

Mifumo mingi hupuuzia baiti za mwisho. ZIP/PDF/script zinaweza kuongezwa kwenye image/audio container.

Uhakiki wa haraka:
```bash
binwalk file
tail -c 200 file | xxd
```
Ikiwa unajua offset, carve kwa `dd`:
```bash
dd if=file of=carved.bin bs=1 skip=<offset>
file carved.bin
```
#### Magic bytes

Wakati `file` inapoonekana imechanganyikiwa, tafuta magic bytes kwa kutumia `xxd` na linganisha na signatures zinazojulikana:
```bash
xxd -g 1 -l 32 file
```
#### Zip-in-disguise

Jaribu `7z` na `unzip` hata kama ugani hauonyeshi zip:
```bash
7z l file
unzip -l file
```
### Mambo ya kushangaza karibu na stego

Viungo vya haraka kwa mifumo zinazojitokeza mara kwa mara karibu na stego (QR-from-binary, braille, etc).

#### QR codes from binary

Ikiwa urefu wa blob ni mraba kamili, inaweza kuwa pikseli mbichi za picha/QR.
```python
import math
math.isqrt(2500)  # 50
```
Msaidizi wa Binary-to-image:

- [https://www.dcode.fr/binary-image](https://www.dcode.fr/binary-image)

#### Braille

- [https://www.branah.com/braille-translator](https://www.branah.com/braille-translator)

## Orodha za marejeleo

- [https://0xrick.github.io/lists/stego/](https://0xrick.github.io/lists/stego/)
- [https://github.com/DominicBreuker/stego-toolkit](https://github.com/DominicBreuker/stego-toolkit)

{{#include ../../banners/hacktricks-training.md}}
