# Mtiririko wa kazi wa Stego

{{#include ../../banners/hacktricks-training.md}}

Matatizo mengi ya stego hutatuliwa haraka zaidi kwa uchunguzi wa kimfumo kuliko kwa kujaribu zana bila mpangilio.

## Mtiririko mkuu

### Orodha ya ukaguzi wa haraka

Lengo ni kujibu maswali mawili kwa ufanisi:

1. Container/format halisi ni ipi?
2. Payload iko kwenye metadata, bytes zilizoongezwa, files zilizopachikwa, au stego ya kiwango cha maudhui?

#### 1) Tambua container

```bash
file target
ls -lah target
```

Ikiwa `file` na kiendelezi havilingani, chunguza saini badala ya kuamini kiambishi tamati. `file` pia hutumia heuristics na inaweza kupotoshwa na ingizo lenye hitilafu au la polyglot. Ichukulie miundo ya kawaida kama kontena inapofaa (kwa mfano, hati za OOXML ni vifurushi vya ZIP).<sup>[[2]](#references)</sup>

#### 2) Tafuta metadata na mifuatano ya maandishi inayoonekana wazi

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

#### 3) Kagua data iliyoongezwa mwishoni / faili zilizopachikwa

```bash
binwalk target
binwalk -e target
```

Ikiwa uchimbaji utashindwa lakini saini zitaripotiwa, kata offsets kwa kutumia `dd` na uendeshe tena `file` kwenye eneo lililokatwa.

#### 4) Ikiwa ni picha

- Kagua hitilafu: `magick identify -verbose file`
- Ikiwa ni PNG/BMP, orodhesha bit-planes/LSB: `zsteg -a file.png`
- Thibitisha muundo wa PNG: `pngcheck -v file.png`
- Tumia vichujio vya kuona (Stegsolve / StegoVeritas) ikiwa maudhui yanaweza kufichuliwa kupitia mabadiliko ya channel/plane

#### 5) Ikiwa ni sauti

- Anza na spectrogram (Sonic Visualiser)
- Decode/kagua streams: `ffmpeg -v info -i file -f null -`
- Ikiwa sauti inafanana na toni zenye muundo, jaribu DTMF decoding

### Zana muhimu za kila siku

Hizi hugundua hali zinazotokea mara nyingi katika kiwango cha container: payload za metadata, bytes zilizoongezwa, na faili zilizopachikwa zinazofichwa kwa kutumia extension.<sup>[[1]](#references)[[3]](#references)</sup>

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

### Kontena, data iliyoongezwa, na mbinu za polyglot

Changamoto nyingi za steganografia huhusisha baiti za ziada baada ya faili halali, au archive zilizopachikwa na kufichwa kwa kutumia kiendelezi tofauti.

#### Payloads zilizoongezwa

Miundo mingi hupuuza baiti zilizo mwishoni. ZIP/PDF/script inaweza kuongezwa kwenye kontena la picha/sauti.

Ukaguzi wa haraka:

```bash
binwalk file
tail -c 200 file | xxd
```

Ikiwa unajua offset, toa data kwa kutumia `dd`:

```bash
dd if=file of=carved.bin bs=1 skip=<offset>
file carved.bin
```

#### Magic bytes

Wakati `file` inapochanganyikiwa, tafuta magic bytes ukitumia `xxd` na uzilinganishe na saini zinazojulikana:

```bash
xxd -g 1 -l 32 file
```

#### Zip-in-disguise

Jaribu `7z` na `unzip` hata kama kiendelezi hakionyeshi kuwa ni zip:

```bash
7z l file
unzip -l file
```

### Mambo yasiyo ya kawaida yanayohusiana na stego

Viungo vya haraka vya mifumo inayoonekana mara kwa mara karibu na stego (QR kutoka kwa binary, braille, n.k.).

#### QR codes kutoka kwa binary

Ikiwa urefu wa blob ni mraba kamili, huenda ni pikseli ghafi za picha/QR.

```python
import math
math.isqrt(2500)  # 50
```

Msaidizi wa kubadilisha binary kuwa picha:

- Msaidizi wa dCode wa binary-image.<sup>[[5]](#references)</sup>

#### Braille

- Mfasiri wa Braille wa Branah.<sup>[[6]](#references)</sup>

Kwa makusanyo mapana zaidi ya zana za steganografia na rasilimali mahususi za mbinu, tazama stego-toolkit iliyojumuishwa na orodha iliyochaguliwa ya 0xRick.<sup>[[1]](#references)[[7]](#references)</sup>

## References

- [1] [DominicBreuker/stego-toolkit - Picha ya Docker yenye zana maarufu zaidi za steganografia zilizounganishwa pamoja](https://github.com/DominicBreuker/stego-toolkit)
- [2] [Daston et al. — Kanuni za ECMA-376 za Ufungashaji Wazi](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
- [3] [korczis/foremost](https://github.com/ReFirmLabs/binwalk)
- [4] [ReFirmLabs/binwalk](https://github.com/korczis/foremost)
- [5] [dCode — Picha ya Binary](https://www.dcode.fr/binary-image)
- [6] [Branah — Mfasiri wa Braille](https://www.branah.com/braille-translator)
- [7] [0xRick - Rasilimali za Steganografia](https://0xrick.github.io/lists/stego/)
{{#include ../../banners/hacktricks-training.md}}
