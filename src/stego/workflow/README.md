# Stego Workflow

{{#include ../../banners/hacktricks-training.md}}

대부분의 stego 문제는 무작위 도구를 시도하기보다 체계적인 triage로 더 빠르게 해결됩니다.

## 핵심 흐름

### 빠른 triage 체크리스트

목표는 두 가지 질문에 효율적으로 답하는 것입니다:

1. 실제 container/format은 무엇인가?
2. payload가 metadata, appended bytes, embedded files에 있는가, 아니면 content-level stego에 있는가?

#### 1) Identify the container
```bash
file target
ls -lah target
```
만약 `file`과 확장자가 일치하지 않으면, `file`을 신뢰하라. 적절한 경우 일반 형식을 컨테이너로 취급하라 (예: OOXML 문서는 ZIP 파일이다).

#### 2) 메타데이터와 명백한 문자열을 찾아라
```bash
exiftool target
strings -n 6 target | head
strings -n 6 target | tail
```
여러 인코딩을 시도하세요:
```bash
strings -e l -n 6 target | head
strings -e b -n 6 target | head
```
#### 3) 추가된 데이터 / 포함된 파일 확인
```bash
binwalk target
binwalk -e target
```
추출이 실패했지만 시그니처가 보고되면, `dd`로 오프셋을 수동으로 카빙한 다음 카빙한 영역에 대해 `file`을 다시 실행하세요.

#### 4) 이미지인 경우

- 이상 징후 검사: `magick identify -verbose file`
- PNG/BMP인 경우, 비트 평면/LSB 열거: `zsteg -a file.png`
- PNG 구조 검증: `pngcheck -v file.png`
- 채널/평면 변환으로 내용이 드러날 수 있는 경우 시각적 필터(Stegsolve / StegoVeritas)를 사용하세요

#### 5) 오디오인 경우

- 먼저 스펙트로그램 확인 (Sonic Visualiser)
- 스트림 디코드/검사: `ffmpeg -v info -i file -f null -`
- 오디오가 구조화된 톤처럼 보이면 DTMF 디코딩을 시험해보세요

### 기본 도구

이 도구들은 메타데이터 페이로드, 추가된 바이트, 확장자로 위장한 임베디드 파일 등 컨테이너 수준에서 자주 발생하는 경우를 잡아냅니다.

#### Binwalk
```bash
binwalk file
binwalk -e file
binwalk --dd '.*' file
```
#### Foremost
```bash
foremost -i file
```
파일 내용 전체를 받지 못했습니다. src/stego/workflow/README.md의 번역을 원하시면 해당 파일의 내용을 붙여 넣어 주세요.

참고: 현재 제공하신 한 줄(#### Exiftool / Exiv2)은 markdown 헤더와 툴 이름을 포함하므로 규칙에 따라 번역하지 않고 그대로 유지해야 합니다.
```bash
exiftool file
exiv2 file
```
#### 파일 / 문자열
```bash
file file
strings -n 6 file
```
#### cmp
```bash
cmp original.jpg stego.jpg -b -l
```
### 컨테이너, 추가된 데이터 및 polyglot tricks

많은 steganography challenges는 유효한 파일 뒤에 남아 있는 추가 바이트이거나 확장자로 위장된 임베디드 아카이브입니다.

#### Appended payloads

많은 포맷은 후행 바이트를 무시합니다. ZIP/PDF/script가 이미지/오디오 컨테이너에 덧붙여질 수 있습니다.

빠른 확인:
```bash
binwalk file
tail -c 200 file | xxd
```
offset을 알고 있다면 `dd`로 carve하세요:
```bash
dd if=file of=carved.bin bs=1 skip=<offset>
file carved.bin
```
#### 매직 바이트

`file` 명령이 혼동될 때, `xxd`로 매직 바이트를 확인하고 알려진 시그니처들과 비교하세요:
```bash
xxd -g 1 -l 32 file
```
#### Zip-in-disguise

확장자가 zip라고 명시되어 있지 않아도 `7z`와 `unzip`을 시도해보세요:
```bash
7z l file
unzip -l file
```
### stego 인근의 이상 현상

stego 옆에 자주 나타나는 패턴에 대한 빠른 링크 (QR-from-binary, braille 등).

#### QR codes from binary

blob 길이가 완전 제곱수이면 이미지/QR의 원시 픽셀일 수 있습니다.
```python
import math
math.isqrt(2500)  # 50
```
Binary-to-image 변환 도구:

- [https://www.dcode.fr/binary-image](https://www.dcode.fr/binary-image)

#### 점자

- [https://www.branah.com/braille-translator](https://www.branah.com/braille-translator)

## 참고 목록

- [https://0xrick.github.io/lists/stego/](https://0xrick.github.io/lists/stego/)
- [https://github.com/DominicBreuker/stego-toolkit](https://github.com/DominicBreuker/stego-toolkit)

{{#include ../../banners/hacktricks-training.md}}
