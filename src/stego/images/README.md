# 이미지 스테가노그래피

{{#include ../../banners/hacktricks-training.md}}

대부분의 CTF 이미지 stego는 다음 유형 중 하나에 해당합니다.

- LSB/bit-planes (PNG/BMP)
- Metadata/comment payloads
- PNG chunk 이상 현상 / 손상 복구
- JPEG DCT-domain 도구 (OutGuess 등)
- 프레임 기반 (GIF/APNG)

## 빠른 초기 분석

심층 콘텐츠 분석에 앞서 컨테이너 수준의 증거를 우선 확인합니다.

- 파일을 검증하고 구조를 확인합니다: `file`, `magick identify -verbose`, 형식 검증 도구(예: `pngcheck`).
- Metadata와 눈에 보이는 문자열을 추출합니다: `exiftool -a -u -g1`, `strings`.
- 포함되거나 덧붙은 콘텐츠가 있는지 확인합니다: `binwalk` 및 파일 끝부분 검사 (`tail | xxd`).
- 컨테이너 유형에 따라 분석 방법을 정합니다.
  - PNG/BMP: bit-planes/LSB 및 chunk 수준의 이상 현상.
  - JPEG: metadata 및 DCT-domain 도구 (OutGuess/F5 계열).
  - GIF/APNG: 프레임 추출, 프레임 간 차이 비교, palette 트릭.

## Bit-planes / LSB

### 기법

PNG/BMP는 **bit-level 조작**이 쉬운 방식으로 픽셀을 저장하기 때문에 CTF에서 자주 사용됩니다. 대표적인 숨기기/추출 방식은 다음과 같습니다.

- 각 픽셀 채널 (R/G/B/A)에는 여러 비트가 있습니다.
- 각 채널의 **least significant bit** (LSB)는 이미지를 거의 바꾸지 않습니다.
- 공격자는 이 하위 비트에 데이터를 숨기며, 경우에 따라 stride, permutation 또는 채널별 선택을 사용합니다.

문제에서 예상할 수 있는 항목:

- payload가 하나의 채널에만 있습니다 (예: `R` LSB).
- payload가 alpha 채널에 있습니다.
- 추출 후 payload가 압축되거나 인코딩됩니다.
- 메시지가 여러 plane에 분산되거나 plane 간 XOR로 숨겨져 있습니다.

마주칠 수 있는 추가 유형 (구현에 따라 다름):

- **LSB matching** (단순히 비트를 뒤집는 대신, 목표 비트에 맞추기 위해 +/-1 조정)
- **Palette/index 기반 은닉** (indexed PNG/GIF: raw RGB 값 대신 색상 인덱스에 payload를 숨김)
- **Alpha 전용 payloads** (RGB 뷰에서는 완전히 보이지 않음)

### 도구

#### zsteg

`zsteg`는 PNG/BMP의 다양한 LSB/bit-plane 추출 패턴을 열거합니다.

```bash
zsteg -a file.png
```

Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: 메타데이터, 이미지 변환, LSB 변형 무차별 대입 등을 포함한 여러 변환을 실행합니다.
- `stegsolve`: 수동 시각 필터(채널 분리, 평면 검사, XOR 등)를 제공합니다.

Stegsolve 다운로드: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFT 기반 가시화 기법

FFT는 LSB 추출 기법이 아닙니다. 주파수 공간에 의도적으로 숨긴 콘텐츠나 미묘한 패턴을 찾는 데 사용됩니다.

- EPFL 데모: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

CTF에서 자주 사용하는 웹 기반 초동 분석 도구:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNG 내부 구조: 청크, 손상, 숨겨진 데이터

### 기법

PNG는 청크 기반 형식입니다. 많은 챌린지에서 페이로드는 픽셀 값이 아니라 컨테이너/청크 수준에 저장됩니다.

- **`IEND` 뒤에 추가된 바이트** (많은 뷰어는 뒤에 붙은 바이트를 무시함)
- **페이로드를 담은 비표준 보조 청크**: [PNG 청크 워커 및 데이터 추출 워크플로](../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/png-tricks.md#extract-ancillary-chunk-payloads)를 참조하세요.
- **손상된 헤더**: 크기를 숨기거나 수정하기 전까지 파서가 작동하지 않게 합니다.

우선 확인할 주요 청크 위치:

- `tEXt` / `iTXt` / `zTXt` (텍스트 메타데이터, 때로는 압축됨)
- `iCCP` (ICC 프로파일) 및 페이로드 전달에 사용되는 기타 보조 청크
- `eXIf` (PNG의 EXIF 데이터)

### 초동 분석 명령어

```bash
magick identify -verbose file.png
pngcheck -v file.png
```

확인할 항목:

- 이상한 너비/높이/비트 깊이/색상 유형 조합
- CRC/청크 오류 (pngcheck는 보통 정확한 오프셋을 알려줍니다)
- `IEND` 뒤에 추가 데이터가 있다는 경고

청크를 더 자세히 확인하려면:

```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```

유용한 참고 자료:

- PNG 사양(구조, 청크): https://www.w3.org/TR/PNG/
- 파일 형식 트릭(PNG/JPEG/GIF의 예외 사례): https://github.com/corkami/docs

## JPEG: metadata, DCT 도메인 도구 및 ELA의 한계

### 기법

JPEG는 원시 픽셀로 저장되지 않고 DCT 도메인에서 압축됩니다. 그래서 JPEG stego 도구는 PNG LSB 도구와 다릅니다.

- metadata/comment payload는 파일 수준에 있으며, 눈에 잘 띄고 빠르게 검사할 수 있습니다.
- DCT 도메인 stego 도구는 주파수 계수에 비트를 삽입합니다.

실무에서는 JPEG를 다음과 같이 취급합니다.

- metadata 세그먼트를 담는 컨테이너(눈에 잘 띄고 빠르게 검사 가능)
- 특수 stego 도구가 작동하는 압축 신호 도메인(DCT 계수)

### 빠른 검사 방법

```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```

유력한 위치:

- EXIF/XMP/IPTC metadata
- JPEG comment segment (`COM`)
- Application segments (`APP1` for EXIF, `APPn` for vendor data)

### 일반적인 도구

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

JPEG의 steghide payload를 찾고 있다면 `stegseek` 사용을 고려하세요(기존 스크립트보다 bruteforce가 빠름):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA는 서로 다른 재압축 아티팩트를 강조합니다. 편집된 영역을 찾는 데 도움이 될 수 있지만, 그 자체로 stego detector는 아닙니다:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## 애니메이션 이미지

### 기법

애니메이션 이미지에서는 메시지가 다음과 같은 방식으로 숨겨져 있다고 가정하세요:

- 단일 프레임에 있음(쉬움), 또는
- 여러 프레임에 분산됨(순서가 중요함), 또는
- 연속된 프레임을 비교해야만 보임

### 프레임 추출

```bash
ffmpeg -i anim.gif frame_%04d.png
```

그런 다음 프레임을 일반 PNG처럼 다룹니다: `zsteg`, `pngcheck`, 채널 분리.

대체 도구:

- `gifsicle --explode anim.gif` (빠른 프레임 추출)
- `imagemagick`/`magick` 프레임별 변환

프레임 차분 분석이 결정적인 경우가 많습니다:

```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```

### APNG 픽셀 수 인코딩

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

애니메이션 문제에서는 각 프레임의 특정 색상 개수를 바이트로 인코딩할 수 있습니다. 개수를 이어 붙이면 메시지를 복원할 수 있습니다.<sup>[[1]](#references)</sup>

## 패스워드로 보호된 임베딩

픽셀 수준의 조작이 아니라 패스프레이즈로 보호된 임베딩이 의심된다면, 보통 이 방법이 가장 빠릅니다.

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

Repo: https://github.com/Paradoxis/StegCracker

### stegpy

PNG/BMP/GIF/WebP/WAV를 지원합니다.

Repo: https://github.com/dhsdshdhk/stegpy



## References

- [1] [Flagvent 2025 (Medium) — 분홍색, 산타의 위시리스트, 크리스마스 메타데이터, 캡처된 노이즈](https://0xdf.gitlab.io/flagvent2025/medium)
{{#include ../../banners/hacktricks-training.md}}
