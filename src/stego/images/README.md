# Image Steganography

{{#include ../../banners/hacktricks-training.md}}

Most CTF image stego reduces to one of these buckets:

- LSB/bit-planes (PNG/BMP)
- Metadata/comment payloads
- PNG chunk weirdness / corruption repair
- JPEG DCT-domain tools (OutGuess, etc)
- Frame-based (GIF/APNG)

## 빠른 초기 분석

심층 콘텐츠 분석 전에 컨테이너 수준의 증거를 우선하세요:

- 파일을 검증하고 구조를 검사하세요: `file`, `magick identify -verbose`, format validators (e.g., `pngcheck`).
- 메타데이터와 가시적 문자열을 추출하세요: `exiftool -a -u -g1`, `strings`.
- 포함되었거나 덧붙여진 콘텐츠를 확인하세요: `binwalk` 및 파일 끝 검사 (`tail | xxd`).
- 컨테이너 종류별로 분기:
- PNG/BMP: bit-planes/LSB 및 chunk-level 이상 징후.
- JPEG: metadata + DCT-domain 도구 (OutGuess/F5-style families).
- GIF/APNG: 프레임 추출, 프레임 차분, 팔레트 트릭.

## Bit-planes / LSB

### 기법

PNG/BMP는 픽셀을 저장하는 방식 때문에 CTF에서 인기가 많으며 **비트 수준 조작**이 쉽습니다. 전형적인 숨김/추출 메커니즘은:

- 각 픽셀 채널(R/G/B/A)은 여러 비트를 가집니다.
- 각 채널의 **최하위 비트**(LSB)는 이미지에 거의 영향을 주지 않습니다.
- 공격자는 이러한 저위치 비트에 데이터를 숨기며, 때로는 stride, permutation 또는 채널별 선택을 사용합니다.

문제에서 기대할 것:

- 페이로드는 하나의 채널에만 있습니다(예: `R` LSB).
- 페이로드가 알파 채널에 있습니다.
- 추출 후 페이로드가 압축되거나 인코딩되어 있을 수 있습니다.
- 메시지가 여러 plane에 분산되거나 plane들 간 XOR으로 숨겨져 있을 수 있습니다.

추가로 만날 수 있는 변형들(구현에 따라 다름):

- **LSB matching** (단순히 비트를 뒤집는 것이 아니라 목표 비트에 맞추기 위해 +/-1 조정을 함)
- **Palette/index-based hiding** (indexed PNG/GIF: 페이로드가 원시 RGB가 아닌 색 인덱스에 저장됨)
- **Alpha-only payloads** (RGB 보기에서는 완전히 보이지 않음)

### 도구

#### zsteg

`zsteg`는 PNG/BMP의 다양한 LSB/bit-plane 추출 패턴을 열거합니다:
```bash
zsteg -a file.png
```
Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: 다양한 변환(메타데이터, 이미지 변환, LSB 변형에 대한 brute forcing)을 실행합니다.
- `stegsolve`: 수동 시각 필터(채널 분리, plane inspection, XOR 등).

Stegsolve 다운로드: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFT-based visibility tricks

FFT는 LSB extraction이 아닙니다; 주로 콘텐츠가 주파수 공간이나 미묘한 패턴에 의도적으로 숨겨진 경우에 사용됩니다.

- EPFL demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

CTF에서 자주 사용되는 웹 기반 도구:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNG internals: chunks, corruption, and hidden data

### Technique

PNG은 청크 형식입니다. 많은 챌린지에서 페이로드는 픽셀 값이 아니라 컨테이너/청크 레벨에 저장됩니다:

- **`IEND` 이후의 추가 바이트** (많은 뷰어는 후행 바이트를 무시합니다)
- **비표준 ancillary 청크**에 페이로드가 들어있음
- **손상된 헤더**는 크기를 숨기거나 파서를 고장내어 수정할 때까지 문제를 일으킵니다

검토할 주요 청크 위치:

- `tEXt` / `iTXt` / `zTXt` (텍스트 메타데이터, 때로는 압축됨)
- `iCCP` (ICC 프로파일) 및 다른 ancillary 청크들이 캐리어로 사용됨
- `eXIf` (PNG의 EXIF 데이터)

### Triage commands
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
확인할 항목:

- 이상한 width/height/bit-depth/colour-type 조합
- CRC/chunk 오류 (pngcheck는 보통 정확한 오프셋을 가리킵니다)
- `IEND` 이후 추가 데이터에 대한 경고

더 자세한 chunk 보기가 필요하면:
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
유용한 참고자료:

- PNG specification (structure, chunks): https://www.w3.org/TR/PNG/
- 파일 포맷 팁 (PNG/JPEG/GIF corner cases): https://github.com/corkami/docs

## JPEG: 메타데이터, DCT-domain 도구, 그리고 ELA의 한계

### 기법

JPEG은 raw 픽셀로 저장되지 않으며 DCT 도메인에서 압축됩니다. 그래서 JPEG stego 도구는 PNG LSB 도구와 다릅니다:

- 메타데이터/코멘트 페이로드는 파일 수준(신호 세기가 높고 빠르게 검사 가능)
- DCT-domain stego 도구는 주파수 계수에 비트를 삽입

운영상으로는, JPEG을 다음과 같이 취급한다:

- 메타데이터 세그먼트를 담는 컨테이너(신호 강도 높음, 빠르게 검사 가능)
- 특수한 stego 도구가 작동하는 압축된 신호 도메인(DCT 계수)

### 빠른 확인
```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```
유의미한 위치:

- EXIF/XMP/IPTC metadata
- JPEG 코멘트 세그먼트 (`COM`)
- 애플리케이션 세그먼트 (`APP1` for EXIF, `APPn` for vendor data)

### 일반 도구

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

JPEG에서 steghide 페이로드를 다루는 경우, `stegseek` 사용을 고려하세요 (기존 스크립트보다 더 빠른 bruteforce):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA는 서로 다른 재압축 아티팩트를 강조합니다; 편집된 영역을 지적할 수 있지만 자체적으로 stego detector는 아닙니다:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## 애니메이션 이미지

### 기법

애니메이션 이미지의 경우, 메시지는 다음과 같다고 가정하세요:

- 단일 프레임에 있음(쉬움), 또는
- 프레임에 걸쳐 분산됨(순서 중요), 또는
- 연속된 프레임을 diff할 때만 보임

### 프레임 추출
```bash
ffmpeg -i anim.gif frame_%04d.png
```
그런 다음 프레임을 일반 PNG처럼 처리하세요: `zsteg`, `pngcheck`, channel isolation.

Alternative tooling:

- `gifsicle --explode anim.gif` (fast frame extraction)
- `imagemagick`/`magick` for per-frame transforms

Frame differencing은 종종 결정적입니다:
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
### APNG pixel-count encoding

- APNG 컨테이너 감지: `exiftool -a -G1 file.png | grep -i animation` or `file`.
- 프레임을 재타이밍 없이 추출: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
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
애니메이션 챌린지에서는 각 프레임에서 특정 색의 개수를 각 바이트로 인코딩할 수 있으며, 그 개수들을 이어붙이면 메시지가 재구성됩니다.

## 비밀번호로 보호된 임베딩

픽셀 수준의 조작이 아니라 passphrase로 보호된 embedding이라고 의심된다면, 보통 이것이 가장 빠른 경로입니다.

### steghide

다음 형식을 지원합니다: `JPEG, BMP, WAV, AU`. 또한 embed/extract encrypted payloads가 가능합니다.
```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```
I don't have access to the repository files. Please paste the contents of src/stego/images/README.md (or attach it) and I will translate the relevant English text to Korean while preserving all markdown/html tags, links, paths and code exactly as requested.
```bash
stegcracker file.jpg wordlist.txt
```
저장소: https://github.com/Paradoxis/StegCracker

### stegpy

지원: PNG/BMP/GIF/WebP/WAV.

저장소: https://github.com/dhsdshdhk/stegpy

## 참고자료

- [Flagvent 2025 (Medium) — pink, 산타의 위시리스트, 크리스마스 메타데이터, 캡처된 노이즈](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
