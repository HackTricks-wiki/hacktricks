# 이미지 스테가노그래피

{{#include ../../banners/hacktricks-training.md}}

대부분의 CTF 이미지 스테고 문제는 다음 유형 중 하나에 해당합니다.

- LSB/비트 평면 (PNG/BMP)
- 메타데이터/주석 페이로드
- PNG 청크 이상 현상 / 손상 복구
- JPEG DCT 도메인 도구 (OutGuess 등)
- 프레임 기반 (GIF/APNG)

## 빠른 초기 분석

심층적인 콘텐츠 분석에 앞서 컨테이너 수준의 증거를 우선 확인하세요.

- 파일을 검증하고 구조를 살펴봅니다: `file`, `magick identify -verbose`, 형식 검증 도구 (예: `pngcheck`).
- 메타데이터와 눈에 보이는 문자열을 추출합니다: `exiftool -a -u -g1`, `strings`.
- 삽입되거나 덧붙은 콘텐츠를 확인합니다: `binwalk` 및 파일 끝부분 검사 (`tail | xxd`).
- 컨테이너에 따라 다음과 같이 분석합니다.
  - PNG/BMP: 비트 평면/LSB 및 청크 수준의 이상 현상.
  - JPEG: 메타데이터 + DCT 도메인 도구 (OutGuess/F5 계열).
  - GIF/APNG: 프레임 추출, 프레임 차분 분석, 팔레트 트릭.

## 비트 평면 / LSB

### 기법

PNG/BMP는 픽셀을 **비트 수준 조작**이 쉽도록 저장하므로 CTF에서 많이 사용됩니다. 전형적인 숨기기/추출 방식은 다음과 같습니다.

- 각 픽셀 채널 (R/G/B/A)에는 여러 비트가 있습니다.
- 각 채널의 **최하위 비트** (LSB)를 바꿔도 이미지에는 거의 변화가 없습니다.
- 공격자는 이러한 하위 비트에 데이터를 숨기며, 때로는 일정한 간격, 순열 또는 채널별 선택 방식을 사용합니다.

문제에서 확인할 내용:

- 페이로드가 하나의 채널에만 들어 있습니다 (예: `R` LSB).
- 페이로드가 알파 채널에 들어 있습니다.
- 페이로드를 추출한 뒤 압축/인코딩합니다.
- 메시지가 여러 평면에 분산되어 있거나 평면 간 XOR로 숨겨져 있습니다.

접할 수 있는 추가 계열 (구현에 따라 다름):

- **LSB 매칭** (단순히 비트를 뒤집는 대신, 목표 비트에 맞추기 위해 +/-1 조정)
- **팔레트/인덱스 기반 은닉** (인덱스형 PNG/GIF: 원시 RGB 대신 색상 인덱스에 페이로드 저장)
- **알파 전용 페이로드** (RGB 보기에서는 완전히 보이지 않음)

### 도구

#### zsteg

`zsteg`는 PNG/BMP의 다양한 LSB/비트 평면 추출 패턴을 열거합니다.

```bash
zsteg -a file.png
```

Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: 여러 변환을 실행합니다(메타데이터, 이미지 변환, LSB 변형 무차별 대입).
- `stegsolve`: 수동 시각 필터(채널 분리, 평면 검사, XOR 등).

Stegsolve 다운로드: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFT 기반 가시성 기법

FFT는 LSB 추출 방식이 아닙니다. 주파수 공간이나 미묘한 패턴에 콘텐츠를 의도적으로 숨긴 경우에 사용합니다.

- EPFL 데모: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

CTF에서 자주 사용하는 웹 기반 초기 분석 도구:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNG 내부 구조: 청크, 손상, 숨겨진 데이터

### 기법

PNG는 청크 기반 형식입니다. 많은 챌린지에서 페이로드는 픽셀 값이 아니라 컨테이너/청크 수준에 저장됩니다.

- **`IEND` 뒤의 여분 바이트**(많은 뷰어는 뒤에 붙은 바이트를 무시함)
- **페이로드를 담은 비표준 ancillary 청크**
- **크기를 숨기거나 수정 전까지 파서를 망가뜨리는 손상된 헤더**

검토할 가치가 높은 청크 위치:

- `tEXt` / `iTXt` / `zTXt`(텍스트 메타데이터, 압축되어 있을 수도 있음)
- 페이로드 전달 수단으로 사용되는 `iCCP`(ICC 프로파일) 및 기타 ancillary 청크
- `eXIf`(PNG의 EXIF 데이터)

### 초기 분석 명령

```bash
magick identify -verbose file.png
pngcheck -v file.png
```

찾아볼 항목:

- 비정상적인 너비/높이/비트 심도/색상 유형 조합
- CRC/청크 오류(`pngcheck`는 보통 정확한 오프셋을 알려줍니다)
- `IEND` 뒤에 추가 데이터가 있다는 경고

청크를 더 자세히 보려면:

```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```

Useful references:

- PNG 사양 (구조, 청크): https://www.w3.org/TR/PNG/
- 파일 형식 트릭 (PNG/JPEG/GIF의 특이 사례): https://github.com/corkami/docs

## JPEG: 메타데이터, DCT 도메인 도구 및 ELA의 한계

### 기법

JPEG는 원시 픽셀로 저장되지 않고 DCT 도메인에서 압축됩니다. 따라서 JPEG stego 도구는 PNG LSB 도구와 다릅니다.

- 메타데이터/주석 페이로드는 파일 수준에 있으며, 신호가 뚜렷하고 빠르게 검사할 수 있습니다.
- DCT 도메인 stego 도구는 주파수 계수에 비트를 삽입합니다.

실제로 JPEG는 다음과 같이 취급합니다.

- 메타데이터 세그먼트용 컨테이너 (신호가 뚜렷하고 빠르게 검사 가능)
- 전문 stego 도구가 작동하는 압축 신호 도메인 (DCT 계수)

### 빠른 점검

```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```

유력한 위치:

- EXIF/XMP/IPTC 메타데이터
- JPEG comment 세그먼트 (`COM`)
- 애플리케이션 세그먼트 (EXIF용 `APP1`, 벤더 데이터용 `APPn`)

### 일반 도구

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

JPEG에서 steghide payload를 찾고 있다면 `stegseek` 사용을 고려하세요 (기존 스크립트보다 bruteforce가 빠릅니다):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA는 서로 다른 재압축 아티팩트를 강조합니다. 편집된 영역을 찾는 데 도움이 될 수 있지만, 그 자체로 stego detector는 아닙니다:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## 애니메이션 이미지

### 기법

애니메이션 이미지에서는 메시지가 다음 위치에 있다고 가정하세요:

- 단일 프레임에 있음 (간단함)
- 여러 프레임에 걸쳐 있음 (순서가 중요함)
- 연속된 프레임을 diff할 때만 보임

### 프레임 추출

```bash
ffmpeg -i anim.gif frame_%04d.png
```

그런 다음 프레임을 일반 PNG처럼 처리합니다: `zsteg`, `pngcheck`, 채널 분리.

대체 도구:

- `gifsicle --explode anim.gif` (빠른 프레임 추출)
- 프레임별 변환에는 `imagemagick`/`magick`

프레임 차분이 결정적인 단서가 되는 경우가 많습니다:

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

애니메이션 challenge에서는 각 프레임의 특정 색상 개수를 바이트로 인코딩할 수 있으며, 개수를 이어 붙이면 메시지를 복원할 수 있습니다.<sup>[[1]](#references)</sup>

## Password-protected embedding

픽셀 단위 조작이 아니라 passphrase로 보호된 embedding이 의심된다면, 보통 이 방법이 가장 빠릅니다.

### steghide

`JPEG, BMP, WAV, AU`를 지원하며, 암호화된 payload를 삽입하거나 추출할 수 있습니다.

```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```

저장소: https://github.com/StefanoDeVuono/steghide

### StegCracker

```bash
stegcracker file.jpg wordlist.txt
```

Repo: https://github.com/Paradoxis/StegCracker

### stegpy

PNG/BMP/GIF/WebP/WAV를 지원합니다.

Repo: https://github.com/dhsdshdhk/stegpy

## References

- [1] [Flagvent 2025 (중간) — 핑크, 산타의 위시리스트, 크리스마스 메타데이터, 캡처된 노이즈](https://0xdf.gitlab.io/flagvent2025/medium)
{{#include ../../banners/hacktricks-training.md}}
