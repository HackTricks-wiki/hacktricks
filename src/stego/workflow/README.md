# Mtiririko wa Stego

{{#include ../../banners/hacktricks-training.md}}

Matatizo mengi ya stego hutatuliwa kwa haraka zaidi kwa triage ya kimfumo kuliko kujaribu tools bila mpangilio.

## Mtiririko mkuu

### Orodha ya ukaguzi wa triage ya haraka

Lengo ni kujibu maswali mawili kwa ufanisi:

1. Container/format halisi ni ipi?
2. Je, payload iko kwenye metadata, bytes zilizoongezwa mwishoni, files zilizopachikwa, au stego ya kiwango cha content?

#### 1) Tambua container
```bash
file target
ls -lah target
```
Ikiwa `file` na extension hazikubaliani, chunguza signature badala ya kuamini suffix. `file` pia ni heuristic na inaweza kuchanganywa na input iliyoharibika au ya polyglot. Chukulia formats za kawaida kama containers inapofaa (kwa mfano, nyaraka za OOXML ni ZIP packages).<sup>[[2]](#references)</sup>

#### 2) Tafuta metadata na strings zinazoonekana wazi
```bash
exiftool target
strings -n 6 target | head
strings -n 6 target | tail
```
Jaribu usimbaji wa aina nyingi:
```bash
strings -e l -n 6 target | head
strings -e b -n 6 target | head
```
#### 3) Angalia data iliyoongezwa / faili zilizopachikwa
```bash
binwalk target
binwalk -e target
```
Iwapo extraction itashindwa lakini signatures zikaripotiwa, manually carve offsets kwa kutumia `dd`, kisha endesha tena `file` kwenye carved region.

#### 4) Ikiwa ni image

- Kagua anomalies: `magick identify -verbose file`
- Ikiwa ni PNG/BMP, enumerate bit-planes/LSB: `zsteg -a file.png`
- Thibitisha muundo wa PNG: `pngcheck -v file.png`
- Tumia visual filters (Stegsolve / StegoVeritas) wakati content inaweza kufichuliwa kupitia channel/plane transforms

#### 5) Ikiwa ni audio

- Anza na spectrogram (Sonic Visualiser)
- Decode/kagua streams: `ffmpeg -v info -i file -f null -`
- Ikiwa audio inafanana na structured tones, jaribu DTMF decoding

### Zana za msingi

Hizi hugundua high-frequency container-level cases: metadata payloads, appended bytes, na embedded files zilizofichwa kwa extension.<sup>[[1]](#references)[[3]](#references)</sup>

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
#### faili / strings
```bash
file file
strings -n 6 file
```
#### cmp
```bash
cmp original.jpg stego.jpg -b -l
```
### Containers, data iliyoongezwa, na mbinu za polyglot

Changamoto nyingi za steganography huwa na bytes za ziada baada ya file halali, au archives zilizopachikwa zinazojificha kwa extension.

#### Payloads zilizoongezwa

Formats nyingi hupuuza bytes zilizo mwishoni. ZIP/PDF/script inaweza kuongezwa kwenye image/audio container.

Ukaguzi wa haraka:
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
### Mambo yasiyo ya kawaida karibu na stego

Viungo vya haraka vya mifumo inayoonekana mara kwa mara karibu na stego (QR-from-binary, braille, n.k.).

#### QR codes kutoka kwenye binary

Ikiwa urefu wa blob ni square kamili, huenda ikawa pikseli ghafi za image/QR.
```python
import math
math.isqrt(2500)  # 50
```
Binary-to-image helper:

- dCode binary-image helper.<sup>[[5]](#references)</sup>

#### Braille

- Branah Braille translator.<sup>[[6]](#references)</sup>

Kwa makusanyo mapana zaidi ya zana za steganography na rasilimali mahususi za mbinu, tazama stego-toolkit iliyounganishwa na orodha iliyoratibiwa ya 0xRick.<sup>[[1]](#references)[[7]](#references)</sup>

## References

- [1] [DominicBreuker/stego-toolkit - Image ya Docker yenye zana maarufu zaidi za steganography zilizowekwa pamoja](https://github.com/DominicBreuker/stego-toolkit)
- [2] [Daston et al. — Mikataba ya Ufungashaji Wazi ya ECMA-376](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
- [3] [ReFirmLabs/binwalk](https://github.com/ReFirmLabs/binwalk)
- [4] [korczis/foremost](https://github.com/korczis/foremost)
- [5] [dCode — Picha ya Binary](https://www.dcode.fr/binary-image)
- [6] [Branah — Mtafsiri wa Braille](https://www.branah.com/braille-translator)
- [7] [0xRick - Rasilimali za Steganography](https://0xrick.github.io/lists/stego/)
{{#include ../../banners/hacktricks-training.md}}
