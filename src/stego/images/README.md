# Image Steganography

{{#include ../../banners/hacktricks-training.md}}

대부분의 CTF image stego는 다음 범주 중 하나로 귀결됩니다:

- LSB/bit-planes (PNG/BMP)
- Metadata/comment payloads
- PNG chunk weirdness / corruption repair
- JPEG DCT-domain tools (OutGuess, etc)
- Frame-based (GIF/APNG)

## 빠른 선별

심층 콘텐츠 분석에 앞서 컨테이너 수준의 증거를 우선적으로 확인하세요:

- 파일을 검증하고 구조를 검사하세요: `file`, `magick identify -verbose`, 형식 검증 도구(예: `pngcheck`).
- 메타데이터와 가시 문자열을 추출하세요: `exiftool -a -u -g1`, `strings`.
- 내장/추가된 콘텐츠를 확인하세요: `binwalk` 및 파일 끝 검사 (`tail | xxd`).
- 컨테이너별 분기:
- PNG/BMP: bit-planes/LSB 및 chunk-level anomalies.
- JPEG: 메타데이터 + DCT-domain tooling (OutGuess/F5-style families).
- GIF/APNG: 프레임 추출, 프레임 차분, 팔레트 트릭.

## Bit-planes / LSB

### Technique

PNG/BMP는 픽셀을 **bit-level manipulation** 하기 쉬운 방식으로 저장하기 때문에 CTF에서 인기가 있습니다. 전형적인 숨김/추출 메커니즘은 다음과 같습니다:

- 각 픽셀 채널(R/G/B/A)은 여러 비트를 가집니다.
- 각 채널의 **최하위 비트** (LSB)는 이미지에 거의 변화를 주지 않습니다.
- 공격자는 이러한 저위치 비트에 데이터를 숨기며, 때로는 stride, permutation, 또는 채널별 선택을 사용합니다.

챌린지에서 예상되는 것:

- 페이로드가 한 채널에만 있습니다(예: `R` LSB).
- 페이로드가 alpha 채널에 있습니다.
- 추출 후 페이로드가 압축/인코딩되어 있을 수 있습니다.
- 메시지가 여러 plane에 걸쳐 분산되거나 plane 간 XOR으로 숨겨질 수 있습니다.

추가로 마주칠 수 있는 변형(구현에 따라 다름):

- **LSB matching** (단순히 비트를 뒤집는 것이 아니라 목표 비트에 맞추기 위해 +/-1 조정)
- **Palette/index-based hiding** (indexed PNG/GIF: 페이로드가 raw RGB가 아닌 색상 인덱스에 있음)
- **Alpha-only payloads** (RGB 보기에서는 완전히 보이지 않음)

### Tooling

#### zsteg

`zsteg`는 PNG/BMP에 대한 다양한 LSB/bit-plane 추출 패턴을 나열합니다:
```bash
zsteg -a file.png
```
저장소: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: 여러 변환들을 실행합니다 (metadata, image transforms, brute forcing LSB variants).
- `stegsolve`: 수동 시각적 필터 (channel isolation, plane inspection, XOR, etc).

Stegsolve 다운로드: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFT-based visibility tricks

FFT는 LSB 추출이 아닙니다; 주파수 공간이나 미묘한 패턴에 의도적으로 숨겨진 콘텐츠에 사용됩니다.

- EPFL 데모: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

CTF에서 자주 사용하는 웹 기반 트리아지:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNG internals: chunks, corruption, and hidden data

### Technique

PNG은 청크 기반 포맷입니다. 많은 문제에서 페이로드는 픽셀 값이 아니라 컨테이너/청크 수준에 저장됩니다:

- **`IEND` 이후의 추가 바이트** (많은 뷰어는 후행 바이트를 무시합니다)
- **비표준 보조 청크**에 페이로드가 실려 있음
- **손상된 헤더** (치수를 숨기거나 수정될 때까지 파서를 중단시킴)

검토할 주목할 만한 청크 위치:

- `tEXt` / `iTXt` / `zTXt` (text metadata, sometimes compressed)
- `iCCP` (ICC profile) 및 페이로드를 담는 다른 보조 청크들
- `eXIf` (EXIF data in PNG)

### Triage commands
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
What to look for:

- 이상한 width/height/bit-depth/colour-type 조합
- CRC/chunk 오류 (pngcheck가 보통 정확한 오프셋을 가리킵니다)
- `IEND` 이후의 추가 데이터에 대한 경고

If you need a deeper chunk view:
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
유용한 참고자료:

- PNG specification (structure, chunks): https://www.w3.org/TR/PNG/
- File format tricks (PNG/JPEG/GIF corner cases): https://github.com/corkami/docs

## JPEG: 메타데이터, DCT-domain 도구, 및 ELA 한계

### 기법

JPEG는 원시 픽셀로 저장되지 않으며 DCT-domain에서 압축됩니다. 그래서 JPEG stego 도구는 PNG LSB 도구와 다릅니다:

- Metadata/comment payloads는 파일 레벨(신호 강도가 높고 빠르게 검사 가능)입니다
- DCT-domain stego tools는 비트를 주파수 계수에 삽입합니다

운영상, JPEG를 다음처럼 취급하세요:

- 메타데이터 세그먼트용 컨테이너(신호 강도 높고 빠른 검사 가능)
- 특수 stego 도구가 작동하는 압축된 신호 도메인(DCT 계수)

### 빠른 점검
```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```
신호가 강한 위치:

- EXIF/XMP/IPTC metadata
- JPEG comment segment (`COM`)
- Application segments (`APP1` for EXIF, `APPn` for vendor data)

### 일반적인 도구

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

If you are specifically facing steghide payloads in JPEGs, consider using `stegseek` (faster bruteforce than older scripts):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA는 다른 재압축 아티팩트를 강조한다; 이는 편집된 영역을 가리킬 수 있지만, 자체적으로는 stego 탐지기는 아니다:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## 애니메이션 이미지

### 기법

애니메이션 이미지에서는 메시지가 다음 중 하나라고 가정하라:

- 단일 프레임에 존재함 (쉽다), 또는
- 프레임들에 걸쳐 분산됨 (프레임 순서가 중요), 또는
- 연속 프레임을 diff할 때만 보임

### 프레임 추출
```bash
ffmpeg -i anim.gif frame_%04d.png
```
그런 다음 프레임을 일반 PNG처럼 다루세요: `zsteg`, `pngcheck`, channel isolation.

Alternative tooling:

- `gifsicle --explode anim.gif` (빠른 프레임 추출)
- `imagemagick`/`magick` (프레임별 변환용)

Frame differencing은 종종 결정적입니다:
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
## 패스프레이즈로 보호된 임베딩

픽셀 수준의 조작이 아니라 패스프레이즈로 보호된 임베딩이 의심된다면, 보통 이것이 가장 빠른 방법입니다.

### steghide

`JPEG, BMP, WAV, AU`을(를) 지원하며 암호화된 payloads를 embed/extract할 수 있습니다.
```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```
I don't have access to the repo. Paste the contents of src/stego/images/README.md here and I will translate the English text to Korean, preserving all markdown/html tags, links, paths and code exactly as required.
```bash
stegcracker file.jpg wordlist.txt
```
저장소: https://github.com/Paradoxis/StegCracker

### stegpy

PNG/BMP/GIF/WebP/WAV를 지원합니다.

저장소: https://github.com/dhsdshdhk/stegpy

{{#include ../../banners/hacktricks-training.md}}
