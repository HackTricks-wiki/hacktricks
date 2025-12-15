# Stego 워크플로우

{{#include ../../banners/hacktricks-training.md}}

대부분의 stego 문제는 무작위 도구를 시도하는 것보다 체계적인 우선순위 분류(triage)를 통해 더 빨리 해결됩니다.

## 핵심 흐름

### 빠른 triage 체크리스트

목표는 다음 두 가지 질문에 효율적으로 답하는 것입니다:

1. 실제 컨테이너/포맷은 무엇인가?
2. payload가 metadata, appended bytes, embedded files, 또는 content-level stego에 있는가?

#### 1) 컨테이너 식별
```bash
file target
ls -lah target
```
만약 `file`와 확장자가 일치하지 않으면 `file`을 신뢰하세요. 일반적인 포맷은 적절할 때 컨테이너로 취급하세요 (예: OOXML 문서는 ZIP 파일입니다).

#### 2) 메타데이터와 명백한 문자열 찾기
```bash
exiftool target
strings -n 6 target | head
strings -n 6 target | tail
```
여러 인코딩을 시도해 보세요:
```bash
strings -e l -n 6 target | head
strings -e b -n 6 target | head
```
#### 3) 파일에 추가된 데이터 / 포함된 파일 확인
```bash
binwalk target
binwalk -e target
```
If extraction fails but signatures are reported, manually carve offsets with `dd` and re-run `file` on the carved region.

#### 4) 이미지인 경우

- 이상 징후 검사: `magick identify -verbose file`
- PNG/BMP인 경우, bit-planes/LSB 열거: `zsteg -a file.png`
- PNG 구조 검증: `pngcheck -v file.png`
- 채널/플레인 변환으로 내용이 드러날 수 있는 경우 시각적 필터(Stegsolve / StegoVeritas) 사용

#### 5) 오디오인 경우

- 먼저 스펙트로그램 확인 (Sonic Visualiser)
- 스트림 디코드/검사: `ffmpeg -v info -i file -f null -`
- 오디오가 구조화된 톤과 유사하면 DTMF 디코딩을 테스트하세요

### 핵심 도구

These catch the high-frequency container-level cases: metadata payloads, appended bytes, and embedded files disguised by extension.

#### Binwalk
```bash
binwalk file
binwalk -e file
binwalk --dd '.*' file
```
I don't have access to the repository content. Please paste the contents of src/stego/workflow/README.md here (or the portion you want translated). I will translate the English text to Korean, preserving all markdown/html/tags/paths/code exactly as you requested.
```bash
foremost -i file
```
#### Exiftool / Exiv2
```bash
exiftool file
exiv2 file
```
파일 src/stego/workflow/README.md의 내용을 여기에 붙여넣어 주세요. 코드, 링크, 경로, 태그는 그대로 유지하고 영어 텍스트 부분만 한국어로 번역해 드립니다.
```bash
file file
strings -n 6 file
```
#### cmp
```bash
cmp original.jpg stego.jpg -b -l
```
### 컨테이너, 추가된 데이터, 그리고 polyglot 기법

많은 steganography 챌린지들은 유효한 파일 뒤에 추가된 바이트이거나, 확장자로 위장된 임베디드 아카이브입니다.

#### 첨부된 payloads

많은 포맷은 후행 바이트를 무시합니다. ZIP/PDF/script는 이미지/오디오 컨테이너에 덧붙일 수 있습니다.

빠른 검사:
```bash
binwalk file
tail -c 200 file | xxd
```
오프셋을 알고 있다면, `dd`로 carve:
```bash
dd if=file of=carved.bin bs=1 skip=<offset>
file carved.bin
```
#### Magic bytes

`file`가 혼동될 때, `xxd`로 magic bytes를 확인하고 알려진 시그니처와 비교하세요:
```bash
xxd -g 1 -l 32 file
```
#### Zip-in-disguise

확장자가 zip이라고 표시되어 있지 않아도 `7z`와 `unzip`을 시도해보세요:
```bash
7z l file
unzip -l file
```
### Near-stego 주변의 특이사항

stego 주변에 자주 나타나는 패턴(예: QR-from-binary, braille 등)에 대한 빠른 링크입니다.

#### QR codes from binary

blob 길이가 완전제곱수이면 이미지/QR의 원시 픽셀일 수 있습니다.
```python
import math
math.isqrt(2500)  # 50
```
Binary-to-image 도우미:

- https://www.dcode.fr/binary-image

#### 점자

- https://www.branah.com/braille-translator

## 참고 목록

- https://0xrick.github.io/lists/stego/
- https://github.com/DominicBreuker/stego-toolkit

{{#include ../../banners/hacktricks-training.md}}
