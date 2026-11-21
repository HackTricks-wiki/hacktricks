# 이미지 스테가노그래피

{{#include ../../banners/hacktricks-training.md}}

대부분의 CTF 이미지 stego는 다음 유형 중 하나에 해당합니다.

- LSB/bit-planes (PNG/BMP)
- 메타데이터/주석 payload
- PNG 청크 이상 현상 / 손상 복구
- JPEG DCT-domain 도구 (OutGuess 등)
- 프레임 기반 (GIF/APNG)

## 빠른 초기 분류

심층적인 콘텐츠 분석에 앞서 컨테이너 수준의 증거를 우선 확인하세요. 이미지별 테스트를 수행하기 전에 파일 식별 및 carving을 하려면 [일반 stego 작업 흐름](../workflow/)을 참고하세요.

- 파일을 검증하고 구조를 확인합니다: `file`, `magick identify -verbose`, 형식 검증 도구 (예: `pngcheck`).
- 메타데이터와 눈에 보이는 문자열을 추출합니다: `exiftool -a -u -g1`, `strings`.
- 삽입되거나 뒤에 추가된 콘텐츠가 있는지 확인합니다: `binwalk` 및 파일 끝부분 확인 (`tail | xxd`).
- 컨테이너 유형에 따라 분석합니다:
  - PNG/BMP: bit-planes/LSB 및 청크 수준 이상 현상.
  - JPEG: 메타데이터와 DCT-domain 도구 (OutGuess/F5 계열).
  - GIF/APNG: 프레임 추출, 프레임 차분, 팔레트 트릭.

## Bit-planes / LSB

### 기법

PNG/BMP는 픽셀을 **비트 수준에서 조작**하기 쉬운 방식으로 저장하기 때문에 CTF에서 자주 사용됩니다. 대표적인 숨기기/추출 방식은 다음과 같습니다.

- 각 픽셀 채널 (R/G/B/A)에는 여러 비트가 있습니다.
- 각 채널의 **최하위 비트** (LSB)는 이미지에 거의 변화를 주지 않습니다.
- 공격자는 이 하위 비트에 데이터를 숨기며, 때로는 stride, permutation 또는 채널별 선택 방식을 사용합니다.

문제에서 예상할 수 있는 유형:

- payload가 한 채널에만 있습니다 (예: `R` LSB).
- payload가 alpha 채널에 있습니다.
- 추출 후 payload가 압축되거나 인코딩됩니다.
- 메시지가 여러 plane에 분산되어 있거나 plane 간 XOR로 숨겨져 있습니다.

접할 수 있는 추가 유형 (구현에 따라 다름):

- **LSB matching** (비트를 뒤집는 것뿐 아니라, 목표 비트에 맞추기 위해 +/-1 조정)
- **팔레트/인덱스 기반 숨기기** (인덱스 PNG/GIF: raw RGB 대신 색상 인덱스에 payload 저장)
- **alpha 전용 payload** (RGB 뷰에서는 완전히 보이지 않음)

### 인덱스 색상 팔레트 인덱스

인덱스 PNG 또는 GIF는 픽셀마다 RGB triplet이 아니라 팔레트 **인덱스**를 저장합니다. 두 인덱스가 같은 가시 색상으로 매핑될 수 있으므로, 분석 전에 RGB로 변환하면 숨겨진 차이가 사라질 수 있습니다. 중복되거나 거의 동일한 팔레트 항목을 살펴본 다음, 의심스러운 각 인덱스를 사용하는 픽셀의 이진 마스크를 렌더링하세요. 이 방법으로 최근 GIF 문제에서 숨겨진 텍스트와 QR 코드 변화를 찾아낸 사례가 있습니다.<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup>

단일 프레임 인덱스 PNG (또는 GIF의 **첫 번째 프레임**)에서는 Pillow의 `P` 모드를 유지하고, 스크립트에서 보고된 흥미로운 인덱스로 `target`을 변경하세요. 인덱스를 고를 때 RGB뿐 아니라 투명도 (`tRNS` 또는 GIF 투명도 인덱스)도 확인하세요.<sup>[[3]](#references)[[5]](#references)</sup>

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

애니메이션 GIF의 경우 프레임을 각각 검사하세요. Pillow는 합성 과정에서 일반적으로 이후 프레임을 RGB/RGBA로 변환합니다. `GifImagePlugin.LOADING_STRATEGY = GifImagePlugin.LoadingStrategy.RGB_AFTER_DIFFERENT_PALETTE_ONLY`를 설정하면 팔레트가 바뀌지 않는 동안에만 `P` 모드가 유지됩니다. 프레임에 로컬 팔레트가 있거나 이미 합성된 경우에는 RGB로 변환된 픽셀을 인덱스로 취급하지 말고, 원본 인덱스 프레임 데이터를 검사하세요.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

### 도구

#### zsteg

`zsteg`는 PNG/BMP에서 다양한 LSB/bit-plane 추출 패턴을 열거합니다:

```bash
zsteg -a file.png
```

Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: 여러 변환(메타데이터, 이미지 변환, LSB 변형 brute force)을 실행합니다.
- `stegsolve`: 수동 시각 필터(채널 분리, plane 검사, XOR 등)를 제공합니다.

Stegsolve 다운로드: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFT 기반 가시성 트릭

FFT는 LSB 추출 방식이 아닙니다. 주파수 공간에 의도적으로 숨겨진 콘텐츠나 미묘한 패턴을 다룰 때 사용합니다.

- EPFL 데모: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

CTF에서 자주 사용하는 웹 기반 초기 분석 도구:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNG 내부 구조: 청크, 손상 및 숨겨진 데이터

### 기법

PNG는 청크 기반 형식입니다. 많은 challenge에서 payload는 픽셀 값이 아니라 컨테이너/청크 수준에 저장됩니다.

- **`IEND` 뒤에 추가된 바이트**(많은 뷰어는 뒤에 붙은 바이트를 무시함)
- **payload를 담은 비표준 ancillary 청크**. [PNG 청크 탐색 및 carving 워크플로](../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/png-tricks.md#extract-ancillary-chunk-payloads)를 참조하세요.
- **손상된 헤더**로 인해 크기가 숨겨지거나 수정 전까지 parser가 제대로 처리하지 못함

우선 확인할 청크 위치:

- `tEXt` / `iTXt` / `zTXt`(텍스트 메타데이터, 압축된 경우도 있음)
- `iCCP`(ICC 프로필) 및 carrier로 사용되는 기타 ancillary 청크
- `eXIf`(PNG의 EXIF 데이터)

### PNG scanline 필터 바이트를 carrier로 사용

PNG는 압축 해제된 `IDAT` 스트림에서 각 scanline 앞에 필터 유형 바이트(0–4)를 하나씩 저장합니다. 이 바이트는 픽셀 값이 아니므로, 디코딩된 RGB 픽셀에는 원래 필터 선택 정보가 보존되지 않으며 재인코딩 시 필터가 달라질 수 있습니다. 인코더는 필터를 정당하게 다양하게 사용할 수 있지만, 의도된 패턴으로 작은 메시지를 인코딩할 수도 있습니다. 최근 challenge에서는 필터 값 1–4를 2비트 심볼로 사용했습니다. **원본 파일**을 검사하고 압축을 풀기 전에 모든 `IDAT` 데이터를 이어 붙이세요. 다음은 인터레이스되지 않은 8비트 RGB/RGBA의 경우이며, stride는 너비에 채널 수를 곱한 값입니다. Adam7 이미지는 pass별 scanline 너비가 필요합니다.<sup>[[3]](#references)[[7]](#references)</sup>

<details>
<summary>재인코딩 없이 PNG scanline 필터 바이트 나열</summary>

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

`python3 filters.py suspect.png`로 실행합니다. 디코딩된 픽셀이 아니라 필터 시퀀스가 그럴듯한 기호 매핑을 따르는지 확인합니다. 매핑 선택은 챌린지마다 다르며, 변형이 있다는 사실만으로 스테가노그래피의 증거가 되지는 않습니다.<sup>[[3]](#references)[[7]](#references)</sup>

### 초기 분석 명령어

```bash
magick identify -verbose file.png
pngcheck -v file.png
```

확인할 항목:

- 이상한 너비/높이/비트 심도/색상 유형 조합
- CRC/청크 오류(pngcheck가 보통 정확한 오프셋을 표시함)
- `IEND` 뒤에 추가 데이터가 있다는 경고

청크를 더 자세히 확인하려면:

```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```

유용한 참고 자료:

- PNG 사양(구조, 청크): https://www.w3.org/TR/PNG/
- 파일 형식 트릭(PNG/JPEG/GIF의 특수 사례): https://github.com/corkami/docs

## JPEG: 메타데이터, DCT 도메인 도구, ELA의 한계

### 기법

JPEG는 원시 픽셀로 저장되지 않고 DCT 도메인에서 압축됩니다. 따라서 JPEG stego 도구는 PNG LSB 도구와 다릅니다.

- 메타데이터/주석 페이로드는 파일 수준에 있으며(신호가 뚜렷하고 빠르게 검사 가능)
- DCT 도메인 stego 도구는 주파수 계수에 비트를 삽입합니다.

실무에서는 JPEG를 다음과 같이 취급합니다.

- 메타데이터 세그먼트 컨테이너(신호가 뚜렷하고 빠르게 검사 가능)
- 전문 stego 도구가 작동하는 압축 신호 도메인(DCT 계수)

### 빠른 점검

```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```

신호가 뚜렷한 위치:

- EXIF/XMP/IPTC metadata
- JPEG comment segment (`COM`)
- Application segments (`APP1` for EXIF, `APPn` for vendor data)

### 일반 도구

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

JPEG에서 steghide payload를 찾는 경우, `stegseek` 사용을 고려하세요(구형 스크립트보다 bruteforce가 빠름):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA는 서로 다른 재압축 아티팩트를 강조합니다. 편집된 영역을 찾는 데 도움이 될 수 있지만, 그 자체로 stego detector는 아닙니다:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## 애니메이션 이미지

### 기법

애니메이션 이미지의 경우, 메시지가 다음 중 하나라고 가정하세요:

- 단일 프레임에 있음(쉬움), 또는
- 여러 프레임에 분산되어 있음(순서가 중요함), 또는
- 연속된 프레임을 diff할 때만 보임

### 프레임 추출

```bash
ffmpeg -i anim.gif frame_%04d.png
```

그런 다음 프레임을 일반 PNG처럼 다룹니다: `zsteg`, `pngcheck`, 채널 분리.

대체 도구:

- `gifsicle --explode anim.gif` (빠른 프레임 추출)
- `imagemagick`/`magick`을 사용한 프레임별 변환

프레임 차분은 결정적인 단서가 되는 경우가 많습니다:

```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```

### APNG 픽셀 수 인코딩

- APNG 컨테이너 감지: `exiftool -a -G1 file.png | grep -i animation` 또는 `file`.
- 프레임을 타이밍 변경 없이 추출: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
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

애니메이션 형식의 문제에서는 각 프레임에 특정 색상이 나타나는 횟수로 각 바이트를 인코딩할 수 있습니다. 횟수를 이어 붙이면 메시지를 복원할 수 있습니다.<sup>[[1]](#references)</sup>

## 암호로 보호된 데이터 삽입

픽셀 단위 조작이 아니라 암호구문으로 보호된 데이터 삽입이 의심된다면, 보통 이 방법이 가장 빠릅니다.

### steghide

`JPEG, BMP, WAV, AU`를 지원하며 암호화된 payload를 삽입하거나 추출할 수 있습니다.

```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```

Repo: https://github.com/StefanoDeVuono/steghide

### StegCracker

```bash
stegcracker file.jpg wordlist.txt
```

저장소: https://github.com/Paradoxis/StegCracker

### stegpy

PNG/BMP/GIF/WebP/WAV를 지원합니다.

저장소: https://github.com/dhsdshdhk/stegpy





## References

- [1] [Flagvent 2025 (중급) — 분홍색, 산타의 위시리스트, 크리스마스 메타데이터, 캡처된 노이즈](https://0xdf.gitlab.io/flagvent2025/medium)
- [2] [HackVent 2024 풀이 — 뒤틀린 색상](https://www.bigigloo.de/download/Write-Up_HackVent_2024.pdf)
- [3] [Portable Network Graphics (PNG) 사양, 제3판](https://www.w3.org/TR/png-3/)
- [4] [XESXOR — 물속 깊은 곳에 무언가가 있다](https://www.xesxor.com/writeups/custom-other-deep-down-there-s-something-in-the-water)
- [5] [Pillow 이미지 파일 형식 — GIF](https://pillow.readthedocs.io/en/stable/handbook/image-file-formats.html)
- [6] [GIF89a 사양](https://giflib.sourceforge.net/gifstandard/GIF89a.html)
- [7] [Afterimage Protocol — CTF 풀이](https://github.com/Team-Cyfer-Trace/Crest-CTF-2.0-Writeup-by-Cyfer-Trace/blob/main/stegno/Afterimage-Protocol/writeup.md)
{{#include ../../banners/hacktricks-training.md}}
