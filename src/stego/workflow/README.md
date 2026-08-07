# Stego Workflow

{{#include ../../banners/hacktricks-training.md}}

대부분의 stego 문제는 무작위 도구를 시도하는 것보다 체계적인 triage를 통해 더 빠르게 해결할 수 있습니다.

## 핵심 흐름

### 빠른 triage 체크리스트

목표는 다음 두 가지 질문에 효율적으로 답하는 것입니다.

1. 실제 container/format은 무엇인가?
2. payload가 metadata, appended bytes, embedded files 또는 content-level stego 중 어디에 있는가?

#### 1) container 식별
```bash
file target
ls -lah target
```
`file`과 확장자가 일치하지 않으면 `file`을 신뢰하세요. 적절한 경우 일반적인 형식을 컨테이너로 취급하세요(예: OOXML 문서는 ZIP 파일입니다).

#### 2) 메타데이터와 명확한 문자열 확인하기
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
#### 3) 추가된 데이터 / 임베디드 파일 확인
```bash
binwalk target
binwalk -e target
```
추출이 실패했지만 signatures가 보고되면 `dd`로 offset을 수동으로 carve한 다음, carve된 영역에서 `file`을 다시 실행합니다.

#### 4) 이미지인 경우

- anomalies 검사: `magick identify -verbose file`
- PNG/BMP인 경우 bit-planes/LSB 열거: `zsteg -a file.png`
- PNG 구조 검증: `pngcheck -v file.png`
- channel/plane 변환으로 content가 드러날 수 있는 경우 visual filters(Stegsolve / StegoVeritas) 사용

#### 5) 오디오인 경우

- 먼저 spectrogram 확인(Sonic Visualiser)
- streams decode/inspect: `ffmpeg -v info -i file -f null -`
- 오디오가 structured tones와 유사하면 DTMF decoding 테스트

### 기본 도구

다음 도구들은 metadata payloads, appended bytes, 그리고 extension으로 위장한 embedded files 등 자주 발생하는 container-level cases를 찾아냅니다.<sup>[[1]](#references)</sup>

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
Repo: https://github.com/korczis/foremost

#### Exiftool / Exiv2
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
### 컨테이너, 추가 데이터 및 polyglot tricks

많은 steganography challenge는 유효한 파일 뒤에 추가된 바이트이거나, 확장자로 위장한 embedded archive입니다.

#### Appended payloads

많은 format은 trailing bytes를 무시합니다. ZIP/PDF/script를 image/audio container 뒤에 추가할 수 있습니다.

빠른 확인 방법:
```bash
binwalk file
tail -c 200 file | xxd
```
offset을 알고 있다면 `dd`로 carve하세요:
```bash
dd if=file of=carved.bin bs=1 skip=<offset>
file carved.bin
```
#### Magic bytes

`file`이 올바르게 판단하지 못할 때는 `xxd`로 magic bytes를 확인하고 알려진 signature와 비교합니다:
```bash
xxd -g 1 -l 32 file
```
#### Zip-in-disguise

확장자가 zip이라고 표시되지 않더라도 `7z`와 `unzip`을 사용해 보세요:
```bash
7z l file
unzip -l file
```
### Stego 주변의 특이 사항

Stego 주변에서 자주 나타나는 패턴에 대한 빠른 링크입니다(바이너리에서 QR, 점자 등).

#### 바이너리에서 생성된 QR codes

blob 길이가 완전제곱수라면 이미지/QR의 raw pixels일 수 있습니다.
```python
import math
math.isqrt(2500)  # 50
```
Binary-to-image 도우미:

- [https://www.dcode.fr/binary-image](https://www.dcode.fr/binary-image)

#### 점자

- [https://www.branah.com/braille-translator](https://www.branah.com/braille-translator)

## 참고 자료

- [1] [DominicBreuker/stego-toolkit - 가장 많이 사용되는 steganography 도구가 함께 포함된 Docker image](https://github.com/DominicBreuker/stego-toolkit)

{{#include ../../banners/hacktricks-training.md}}
