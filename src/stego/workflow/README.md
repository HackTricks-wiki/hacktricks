# Mchakato wa Stego

{{#include ../../banners/hacktricks-training.md}}

Matatizo mengi ya stego hutatuliwa kwa haraka zaidi kwa triage ya kimfumo kuliko kujaribu tools bila mpangilio.

## Mchakato mkuu

### Orodha ya ukaguzi wa haraka wa triage

Lengo ni kujibu maswali mawili kwa ufanisi:

1. Container/format halisi ni ipi?
2. Payload iko kwenye metadata, bytes zilizoongezwa mwishoni, files zilizopachikwa, au stego ya kiwango cha content?

#### 1) Tambua container
```bash
file target
ls -lah target
```
If `file` na extension haziendani, chunguza signature badala ya kuamini suffix. `file` pia ni heuristic na inaweza kuchanganywa na input iliyoharibika au ya polyglot. Chukulia formats za kawaida kama containers inapofaa (kwa mfano, documents za OOXML ni ZIP packages).<sup>[[2]](#references)</sup>

#### 2) Tafuta metadata na strings zilizo wazi
```bash
exiftool target
strings -n 6 target | head
strings -n 6 target | tail
```
Jaribu encodings nyingi:
```bash
strings -e l -n 6 target | head
strings -e b -n 6 target | head
```
#### 3) Kagua data iliyoongezwa / faili zilizopachikwa
```bash
binwalk target
binwalk -e target
```
Ikiwa uchimbaji hautafaulu lakini signatures zimeripotiwa, kata offsets mwenyewe kwa `dd` na uendeshe tena `file` kwenye eneo lililokatwa.

#### 4) Ikiwa ni picha

- Kagua anomalies: `magick identify -verbose file`
- Ikiwa ni PNG/BMP, hesabu bit-planes/LSB: `zsteg -a file.png`
- Thibitisha muundo wa PNG: `pngcheck -v file.png`
- Tumia visual filters (Stegsolve / StegoVeritas) wakati content inaweza kufichuliwa na mabadiliko ya channel/plane

#### 5) Ikiwa ni audio

- Anza na spectrogram (Sonic Visualiser)
- Decode/kagua streams: `ffmpeg -v info -i file -f null -`
- Ikiwa audio inafanana na structured tones, jaribu DTMF decoding

### Zana za msingi

Hizi hugundua hali za mara kwa mara za kiwango cha container: metadata payloads, bytes zilizoongezwa, na embedded files zilizofichwa kwa kutumia extension isiyo sahihi.<sup>[[1]](#references)[[3]](#references)</sup>

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
Hifadhi ya mradi: `korczis/foremost`.<sup>[[4]](#references)</sup>

#### Exiftool / Exiv2
```bash
exiftool file
exiv2 file
```
Tafadhali tuma maudhui ya `src/stego/workflow/README.md` unayotaka kutafsiri.
```bash
file file
strings -n 6 file
```
#### cmp
```bash
cmp original.jpg stego.jpg -b -l
```
### Kontena, data iliyoambatishwa, na mbinu za polyglot

Changamoto nyingi za steganography huwa na bytes za ziada baada ya file halali, au archives zilizopachikwa zinazojifanya kuwa na extension tofauti.

#### Payloads zilizoambatishwa

Formats nyingi hupuuza bytes zilizo mwishoni. ZIP/PDF/script inaweza kuambatishwa kwenye image/audio container.

Ukaguzi wa haraka:
```bash
binwalk file
tail -c 200 file | xxd
```
Ikiwa unajua offset, fanya carving kwa kutumia `dd`:
```bash
dd if=file of=carved.bin bs=1 skip=<offset>
file carved.bin
```
#### Magic bytes

Wakati `file` inapochanganyikiwa, tafuta magic bytes kwa kutumia `xxd` na uzilinganishe na signatures zinazojulikana:
```bash
xxd -g 1 -l 32 file
```
#### Zip-in-disguise

Jaribu `7z` na `unzip` hata kama extension haisemi zip:
```bash
7z l file
unzip -l file
```
### Makosa ya karibu na stego

Viungo vya haraka vya mifumo inayojitokeza mara kwa mara karibu na stego (QR-from-binary, Braille, n.k.).

#### QR codes kutoka kwenye binary

Ikiwa urefu wa blob ni square kamili, huenda ikawa pixels ghafi za picha/QR.
```python
import math
math.isqrt(2500)  # 50
```
Msaidizi wa kubadilisha binary kuwa picha:

- Msaidizi wa dCode wa binary-image.<sup>[[5]](#references)</sup>

#### Braille

- Translator ya Branah ya Braille.<sup>[[6]](#references)</sup>

## References

- [1] [DominicBreuker/stego-toolkit - Picha ya Docker yenye zana maarufu zaidi za steganography zilizojumuishwa](https://github.com/DominicBreuker/stego-toolkit)
- [2] [Daston et al. — Kanuni za ECMA-376 za Open Packaging](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
- [3] [ReFirmLabs/binwalk](https://github.com/ReFirmLabs/binwalk)
- [4] [korczis/foremost](https://github.com/korczis/foremost)
- [5] [dCode — Picha ya Binary](https://www.dcode.fr/binary-image)
- [6] [Branah — Translator ya Braille](https://www.branah.com/braille-translator)
{{#include ../../banners/hacktricks-training.md}}
