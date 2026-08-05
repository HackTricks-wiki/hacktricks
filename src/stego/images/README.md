# 이미지 Steganography

{{#include ../../banners/hacktricks-training.md}}

대부분의 CTF 이미지 stego는 다음 범주 중 하나에 해당합니다:

- LSB/bit-planes (PNG/BMP)
- Metadata/comment payloads
- PNG chunk 이상 현상 / corruption repair
- JPEG DCT-domain tools (OutGuess 등)
- Frame-based (GIF/APNG)

## 빠른 triage

심층적인 content analysis 전에 container-level evidence를 우선 확인합니다:

- 파일을 검증하고 구조를 검사합니다: `file`, `magick identify -verbose`, format validators (예: `pngcheck`).
- Metadata와 visible strings를 추출합니다: `exiftool -a -u -g1`, `strings`.
- embedded/appended content를 확인합니다: `binwalk` 및 end-of-file inspection (`tail | xxd`).
- container에 따라 분기합니다:
- PNG/BMP: bit-planes/LSB 및 chunk-level anomalies.
- JPEG: metadata + DCT-domain tooling (OutGuess/F5-style families).
- GIF/APNG: frame extraction, frame differencing, palette tricks.

## Bit-planes / LSB

### Technique

PNG/BMP는 pixel을 bit-level manipulation이 쉽게 가능한 방식으로 저장하기 때문에 CTF에서 자주 사용됩니다. 일반적인 hide/extract mechanism은 다음과 같습니다:

- 각 pixel channel (R/G/B/A)에는 여러 bit가 있습니다.
- 각 channel의 **least significant bit** (LSB)를 변경해도 image에는 거의 영향을 주지 않습니다.
- Attackers는 이러한 low-order bit에 data를 숨기며, 때로는 stride, permutation 또는 per-channel choice를 적용합니다.

Challenges에서 예상할 수 있는 항목:

- Payload가 하나의 channel에만 있습니다 (예: `R` LSB).
- Payload가 alpha channel에 있습니다.
- Extraction 후 payload가 compressed/encoded 상태입니다.
- Message가 여러 plane에 분산되어 있거나 plane 간 XOR을 통해 숨겨져 있습니다.

접할 수 있는 추가 family (implementation-dependent):

- **LSB matching** (단순히 bit를 뒤집는 것이 아니라 target bit에 맞추기 위해 +/-1 조정)
- **Palette/index-based hiding** (indexed PNG/GIF: raw RGB가 아닌 color indices에 payload를 저장)
- **Alpha-only payloads** (RGB view에서는 완전히 보이지 않음)

### Tooling

#### zsteg

`zsteg`는 PNG/BMP에 대한 다양한 LSB/bit-plane extraction pattern을 열거합니다:
```bash
zsteg -a file.png
```
Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: metadata, image transforms, LSB variants brute forcing 등 다양한 변환을 실행합니다.
- `stegsolve`: 수동 visual filters(channel isolation, plane inspection, XOR 등)를 제공합니다.

Stegsolve download: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFT 기반 visibility tricks

FFT는 LSB extraction이 아니며, content가 frequency space에 의도적으로 숨겨져 있거나 미세한 patterns가 사용된 경우를 위한 것입니다.

- EPFL demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

CTF에서 자주 사용되는 Web-based triage:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNG internals: chunks, corruption, and hidden data

### 기법

PNG는 chunk 기반 format입니다. 많은 challenge에서 payload는 pixel values가 아니라 container/chunk level에 저장됩니다.

- **`IEND` 뒤의 extra bytes** (많은 viewer는 trailing bytes를 무시함)
- **payload를 포함하는 non-standard ancillary chunks**
- **dimensions를 숨기거나 수정하기 전까지 parser를 중단시키는 corrupted headers**

검토해야 할 high-signal chunk locations:

- `tEXt` / `iTXt` / `zTXt` (text metadata, 때로는 compressed)
- `iCCP` (ICC profile) 및 carrier로 사용되는 기타 ancillary chunks
- `eXIf` (PNG의 EXIF data)

### Triage commands
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
확인할 항목:

- 이상한 width/height/bit-depth/colour-type 조합
- CRC/chunk 오류 (`pngcheck`가 보통 정확한 offset을 알려 줌)
- `IEND` 뒤에 추가 데이터가 있다는 경고

더 자세한 chunk 보기가 필요한 경우:
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
유용한 참고 자료:

- PNG specification (구조, chunks): https://www.w3.org/TR/PNG/
- File format tricks (PNG/JPEG/GIF corner cases): https://github.com/corkami/docs

## JPEG: 메타데이터, DCT-domain tools 및 ELA limitations

### Technique

JPEG는 raw pixels로 저장되지 않으며, DCT domain에서 압축됩니다. 따라서 JPEG stego tools는 PNG LSB tools와 다릅니다:

- Metadata/comment payloads는 file-level에 존재합니다 (high-signal이며 빠르게 검사 가능)
- DCT-domain stego tools는 frequency coefficients에 bits를 embed합니다

Operationally, JPEG를 다음과 같이 취급합니다:

- Metadata segments를 위한 container (high-signal이며 빠르게 검사 가능)
- Specialized stego tools가 작동하는 compressed signal domain (DCT coefficients)

### 빠른 확인
```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```
신호가 뚜렷한 위치:

- EXIF/XMP/IPTC metadata
- JPEG comment segment (`COM`)
- Application segments (`APP1` for EXIF, `APPn` for vendor data)

### 일반적인 tools

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

JPEG에서 steghide payloads를 특히 다루는 경우, `stegseek`를 사용하는 것을 고려하세요(기존 scripts보다 빠른 bruteforce):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA는 서로 다른 recompression artifacts를 강조합니다. 이를 통해 편집된 regions를 파악할 수 있지만, 그 자체로는 stego detector가 아닙니다:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Animated images

### Technique

Animated images의 경우, message가 다음 중 하나라고 가정하세요:

- 단일 frame에 있음(easy), 또는
- 여러 frames에 분산되어 있음(ordering이 중요), 또는
- consecutive frames를 diff할 때만 보임

### frames 추출
```bash
ffmpeg -i anim.gif frame_%04d.png
```
그런 다음 frame을 일반 PNG처럼 처리하세요: `zsteg`, `pngcheck`, 채널 분리.

대체 tooling:

- `gifsicle --explode anim.gif` (빠른 frame 추출)
- 프레임별 변환에는 `imagemagick`/`magick`

Frame differencing이 결정적인 경우가 많습니다:
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
### APNG pixel-count 인코딩

- APNG 컨테이너 감지: `exiftool -a -G1 file.png | grep -i animation` 또는 `file`.
- 타이밍을 변경하지 않고 프레임 추출: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
- 프레임별 픽셀 수로 인코딩된 페이로드 복구:
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
Animated challenges에서는 각 frame의 특정 color 개수로 각 byte를 encode할 수 있으며, 개수를 연결하면 message를 reconstruct할 수 있습니다.<sup>[[1]](#references)</sup>

## Password-protected embedding

pixel-level manipulation이 아니라 passphrase로 보호된 embedding이 의심된다면, 일반적으로 이것이 가장 빠른 방법입니다.

### steghide

`JPEG, BMP, WAV, AU`를 지원하며 encrypted payload를 embed/extract할 수 있습니다.
```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```
Repo: https://github.com/StefanoDeVuono/steghide

### StegCracker
```bash
stegcracker file.jpg wordlist.txt
```
Repo: https://github.com/Paradoxis/StegCracker

### stegpy

PNG/BMP/GIF/WebP/WAV를 지원합니다.

Repo: https://github.com/dhsdshdhk/stegpy

## 참고 자료

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
