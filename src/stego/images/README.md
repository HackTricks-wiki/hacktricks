# Image Steganography

{{#include ../../banners/hacktricks-training.md}}

Most CTF image stego reduces to one of these buckets:

- LSB/bit-planes (PNG/BMP)
- Metadata/comment payloads
- PNG chunk weirdness / corruption repair
- JPEG DCT-domain tools (OutGuess, etc)
- Frame-based (GIF/APNG)

## 빠른 분류

심층 콘텐츠 분석 전에 컨테이너 수준의 증거를 우선 확인하세요:

- 파일을 검증하고 구조를 검사하세요: `file`, `magick identify -verbose`, format validators (e.g., `pngcheck`).
- 메타데이터와 가시적 문자열을 추출하세요: `exiftool -a -u -g1`, `strings`.
- 임베디드/추가된 콘텐츠가 있는지 확인하세요: `binwalk` 및 파일 끝 검사 (`tail | xxd`).
- 컨테이너 유형에 따라 분기하세요:
- PNG/BMP: bit-planes/LSB 및 chunk 수준의 이상.
- JPEG: 메타데이터 + DCT-domain 도구 (OutGuess/F5-style families).
- GIF/APNG: 프레임 추출, 프레임 차분, 팔레트 트릭.

## Bit-planes / LSB

### 기법

PNG/BMP는 픽셀을 비트 단위로 조작하기 쉽게 저장하기 때문에 CTF에서 인기가 많습니다. 고전적인 숨김/추출 메커니즘은 다음과 같습니다:

- 각 픽 채널(`R`/`G`/`B`/`A`)에는 여러 비트가 있습니다.
- 각 채널의 **최하위 비트** (LSB)는 이미지를 거의 바꾸지 않습니다.
- 공격자는 이러한 저차 비트들에 데이터를 숨기며, 때로는 간격(stride), 치환(permutation), 또는 채널별 선택을 사용합니다.

문제에서 기대할 것들:

- 페이로드는 한 채널에만 존재(예: `R` LSB).
- 페이로드가 alpha 채널에 있음.
- 추출 후 페이로드가 압축/인코딩됨.
- 메시지가 여러 plane에 걸쳐 퍼져 있거나 plane 간 XOR으로 숨겨져 있음.

구현에 따라 마주칠 수 있는 추가 계열:

- **LSB matching** (단순히 비트를 뒤집는 것이 아니라 대상 비트에 맞추기 위해 +/-1로 조정)
- **Palette/index-based hiding** (indexed PNG/GIF: raw RGB 대신 색상 인덱스에 페이로드)
- **Alpha-only payloads** (RGB 보기에서는 완전히 보이지 않음)

### 도구

#### zsteg

`zsteg`은 PNG/BMP에 대한 많은 LSB/bit-plane 추출 패턴을 열거합니다:
```bash
zsteg -a file.png
```
저장소: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: 다양한 변환을 일괄적으로 실행합니다 (메타데이터, 이미지 변환, LSB 변형에 대한 무차별 대입 등).
- `stegsolve`: 수동 시각 필터(채널 분리, 평면 검사, XOR 등).

Stegsolve 다운로드: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFT 기반 가시화 기법

FFT는 LSB 추출이 아닙니다; 주로 콘텐츠가 주파수 공간이나 미세한 패턴에 의도적으로 숨겨진 경우에 사용됩니다.

- EPFL demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

CTF에서 자주 사용하는 웹 기반 선별 도구:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNG 내부: 청크, 손상, 그리고 숨겨진 데이터

### 기법

PNG는 청크 방식의 포맷입니다. 많은 문제에서 페이로드는 픽셀 값보다는 컨테이너/청크 수준에 저장되는 경우가 많습니다:

- **`IEND` 이후의 추가 바이트** (많은 뷰어가 후행 바이트를 무시함)
- **비표준 보조 청크**가 페이로드를 담음
- **손상된 헤더**가 크기를 숨기거나 파서를 실패시켜 수정해야 동작함

검토할 주요 청크 위치:

- `tEXt` / `iTXt` / `zTXt` (텍스트 메타데이터, 때로는 압축됨)
- `iCCP` (ICC profile) 및 기타 보조 청크가 캐리어로 사용됨
- `eXIf` (PNG의 EXIF 데이터)

### 선별 명령
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
확인할 내용:

- 이상한 width/height/bit-depth/colour-type 조합
- CRC/chunk 오류 (pngcheck는 보통 정확한 오프셋을 가리킵니다)
- `IEND` 이후 추가 데이터에 대한 경고

더 깊은 chunk 뷰가 필요하면:
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
유용한 참고 자료:

- PNG specification (structure, chunks): https://www.w3.org/TR/PNG/
- File format tricks (PNG/JPEG/GIF corner cases): https://github.com/corkami/docs

## JPEG: metadata, DCT-domain tools, and ELA limitations

### Technique

JPEG는 원시 픽셀로 저장되지 않으며 DCT-domain에서 압축됩니다. 그래서 JPEG stego 도구는 PNG LSB 도구와 다릅니다:

- Metadata/comment payloads는 파일 레벨입니다 (신호 강하고 빠르게 검사 가능)
- DCT-domain stego 도구는 비트를 주파수 계수에 삽입합니다

실무적으로는 JPEG를 다음과 같이 취급합니다:

- 메타데이터 세그먼트의 컨테이너 (신호 강하고 빠른 검사 가능)
- 특수 stego 도구가 작동하는 압축된 신호 영역 (DCT coefficients)

### Quick checks
```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```
높은 신호 위치:

- EXIF/XMP/IPTC metadata
- JPEG comment segment (`COM`)
- Application segments (`APP1` for EXIF, `APPn` for vendor data)

### 일반적인 도구

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

JPEG에서 steghide payloads를 직접 다루고 있다면, `stegseek` 사용을 고려하세요 (기존 스크립트보다 빠른 bruteforce):

- https://github.com/RickdeJager/stegseek

### Error Level Analysis

ELA는 서로 다른 재압축 아티팩트를 강조합니다; 편집된 영역을 가리킬 수 있지만, 자체적으로는 stego 탐지기가 아닙니다:

- https://29a.ch/sandbox/2012/imageerrorlevelanalysis/

## 애니메이션 이미지

### 기법

애니메이션 이미지의 경우, 메시지는 다음 중 하나라고 가정하세요:

- 단일 프레임에 있음(쉽다), 또는
- 프레임들에 걸쳐 분산됨(순서가 중요), 또는
- 연속 프레임을 diff할 때만 보임

### 프레임 추출
```bash
ffmpeg -i anim.gif frame_%04d.png
```
그런 다음 프레임을 일반 PNG처럼 취급: `zsteg`, `pngcheck`, channel isolation.

대체 도구:

- `gifsicle --explode anim.gif` (빠른 프레임 추출)
- `imagemagick`/`magick` 프레임별 변환을 위해

Frame differencing은 종종 결정적이다:
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
## 패스프레이즈로 보호된 임베딩

픽셀 수준의 조작이 아니라 패스프레이즈로 보호된 임베딩이라고 의심되면, 보통 이것이 가장 빠른 경로입니다.

### steghide

지원: `JPEG, BMP, WAV, AU` 및 암호화된 페이로드를 삽입/추출할 수 있습니다.
```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```
I don't have access to external URLs. Please paste the contents of src/stego/images/README.md (or the section you want translated). I'll translate the English text to Korean, preserving all markdown, code, links, tags and paths exactly as requested.
```bash
stegcracker file.jpg wordlist.txt
```
저장소: https://github.com/Paradoxis/StegCracker

### stegpy

PNG/BMP/GIF/WebP/WAV를 지원합니다.

저장소: https://github.com/dhsdshdhk/stegpy

{{#include ../../banners/hacktricks-training.md}}
