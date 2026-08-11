# Stego Workflow

{{#include ../../banners/hacktricks-training.md}}

대부분의 stego 문제는 무작위 도구를 시도하는 것보다 체계적인 triage를 통해 더 빠르게 해결할 수 있습니다.

## Core flow

### Quick triage checklist

목표는 다음 두 가지 질문에 효율적으로 답하는 것입니다.

1. 실제 컨테이너/format은 무엇인가?
2. payload가 metadata, appended bytes, embedded files 또는 content-level stego 중 어디에 있는가?

#### 1) Identify the container
```bash
file target
ls -lah target
```
`file`과 확장자가 일치하지 않으면 접미사를 신뢰하지 말고 signature를 조사하세요. `file` 역시 heuristic이므로 잘못 구성되었거나 polyglot 입력에 의해 혼동될 수 있습니다. 적절한 경우 일반적인 형식을 컨테이너로 취급하세요(예: OOXML 문서는 ZIP 패키지입니다).<sup>[[2]](#references)</sup>

#### 2) metadata와 명확한 문자열 찾기
```bash
exiftool target
strings -n 6 target | head
strings -n 6 target | tail
```
여러 인코딩 시도:
```bash
strings -e l -n 6 target | head
strings -e b -n 6 target | head
```
#### 3) 추가된 데이터 / 임베디드 파일 확인
```bash
binwalk target
binwalk -e target
```
추출에 실패했지만 signature가 보고된 경우, `dd`로 오프셋을 수동으로 carve한 다음 carve된 영역에서 `file`을 다시 실행합니다.

#### 4) 이미지인 경우

- 이상 징후 검사: `magick identify -verbose file`
- PNG/BMP인 경우 bit-plane/LSB 열거: `zsteg -a file.png`
- PNG 구조 검증: `pngcheck -v file.png`
- channel/plane 변환으로 콘텐츠가 드러날 수 있는 경우 visual filter(Stegsolve / StegoVeritas) 사용

#### 5) 오디오인 경우

- 먼저 spectrogram 확인(Sonic Visualiser)
- stream 디코드/검사: `ffmpeg -v info -i file -f null -`
- 오디오가 구조화된 tone과 유사하면 DTMF decoding 테스트

### 기본 도구

다음 도구는 metadata payload, appended bytes, 그리고 확장자로 위장한 embedded files처럼 빈번하게 발생하는 container-level 사례를 탐지합니다.<sup>[[1]](#references)[[3]](#references)</sup>

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
프로젝트 repository: `korczis/foremost`.<sup>[[4]](#references)</sup>

#### Exiftool / Exiv2
```bash
exiftool file
exiv2 file
```
파일 / 문자열
```bash
file file
strings -n 6 file
```
#### cmp
```bash
cmp original.jpg stego.jpg -b -l
```
### Containers, appended data, and polyglot tricks

많은 steganography challenge는 유효한 파일 뒤에 추가된 바이트이거나, 확장자로 위장한 embedded archive입니다.

#### Appended payloads

많은 format은 trailing bytes를 무시합니다. 이미지/audio container 뒤에 ZIP/PDF/script를 추가할 수 있습니다.

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
#### Magic bytes

`file`이 혼동할 때는 `xxd`로 magic bytes를 찾고 알려진 signature와 비교하세요:
```bash
xxd -g 1 -l 32 file
```
#### Zip-in-disguise

확장자가 zip이라고 표시되지 않더라도 `7z`와 `unzip`을 시도하세요:
```bash
7z l file
unzip -l file
```
### stego 인접 특이 패턴

stego 주변에서 자주 나타나는 패턴을 위한 빠른 링크입니다(바이너리에서 QR 생성, 점자 등).

#### 바이너리에서 QR 코드 생성

blob 길이가 완전제곱수라면 이미지/QR의 raw pixels일 수 있습니다.
```python
import math
math.isqrt(2500)  # 50
```
Binary-to-image helper:

- dCode binary-image helper.<sup>[[5]](#references)</sup>

#### Braille

- Branah Braille translator.<sup>[[6]](#references)</sup>

## References

- [1] [DominicBreuker/stego-toolkit - 가장 인기 있는 steganography 도구가 함께 번들된 Docker image](https://github.com/DominicBreuker/stego-toolkit)
- [2] [Daston et al. — ECMA-376 Open Packaging Conventions](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
- [3] [ReFirmLabs/binwalk](https://github.com/ReFirmLabs/binwalk)
- [4] [korczis/foremost](https://github.com/korczis/foremost)
- [5] [dCode — 이진 이미지](https://www.dcode.fr/binary-image)
- [6] [Branah — 점자 번역기](https://www.branah.com/braille-translator)
{{#include ../../banners/hacktricks-training.md}}
