# Stego 워크플로

{{#include ../../banners/hacktricks-training.md}}

대부분의 stego 문제는 무작위로 도구를 사용해 보는 것보다 체계적인 초기 분류를 통해 더 빠르게 해결할 수 있습니다.

## 핵심 흐름

### 빠른 초기 분류 체크리스트

효율적으로 다음 두 가지 질문에 답하는 것이 목표입니다.

1. 실제 컨테이너/형식은 무엇인가?
2. payload는 메타데이터, 추가된 바이트, 내장 파일 또는 콘텐츠 수준의 stego 중 어디에 있는가?

#### 1) 컨테이너 식별하기

```bash
file target
ls -lah target
```

`file` 명령의 결과와 확장자가 일치하지 않으면 확장자를 믿지 말고 시그니처를 조사하세요. `file`도 휴리스틱에 의존하므로 잘못된 형식이거나 여러 형식이 결합된 입력에 혼동될 수 있습니다. 일반적인 형식은 적절한 경우 컨테이너로 취급하세요(예: OOXML 문서는 ZIP 패키지입니다).<sup>[[2]](#references)</sup>

#### 2) 메타데이터와 명확한 문자열 확인하기

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

#### 3) 추가 데이터 / 삽입된 파일 확인

```bash
binwalk target
binwalk -e target
```

추출에 실패했지만 signature가 보고된 경우, `dd`로 오프셋을 수동으로 carve한 다음 carve한 영역에 `file`을 다시 실행합니다.

#### 4) 이미지인 경우

- 이상 징후 검사: `magick identify -verbose file`
- PNG/BMP인 경우, bit-plane/LSB 열거: `zsteg -a file.png`
- PNG 구조 검증: `pngcheck -v file.png`
- 채널/평면 변환으로 콘텐츠가 드러날 수 있는 경우 시각적 필터 사용 (Stegsolve / StegoVeritas)

#### 5) 오디오인 경우

- 먼저 스펙트로그램 확인 (Sonic Visualiser)
- 스트림 디코딩/검사: `ffmpeg -v info -i file -f null -`
- 오디오가 규칙적인 톤처럼 들리면 DTMF 디코딩 테스트

### 기본 도구

이 도구들은 메타데이터 payload, 추가된 바이트, 확장자를 위장한 내장 파일 등 자주 발생하는 컨테이너 수준의 사례를 찾아냅니다.<sup>[[1]](#references)[[3]](#references)</sup>

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

프로젝트 저장소: `korczis/foremost`.<sup>[[4]](#references)</sup>

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

### 컨테이너, 추가 데이터, 그리고 polyglot 기법

많은 스테가노그래피 챌린지에는 유효한 파일 뒤에 추가된 바이트가 있거나, 확장자로 위장한 아카이브가 있습니다.

#### 추가된 payload

많은 형식은 끝에 있는 바이트를 무시합니다. ZIP/PDF/script를 이미지/오디오 컨테이너 뒤에 추가할 수 있습니다.

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

`file`이 혼동할 때는 `xxd`로 magic bytes를 확인하고 알려진 시그니처와 비교합니다:

```bash
xxd -g 1 -l 32 file
```

#### Zip-in-disguise

확장자가 zip이라고 표시되어 있지 않더라도 `7z`와 `unzip`을 사용해 보세요:

```bash
7z l file
unzip -l file
```

### Stego 주변의 특이한 패턴

Stego와 함께 자주 나타나는 패턴(QR-from-binary, 점자 등)의 빠른 링크입니다.

#### 바이너리로 만든 QR 코드

Blob 길이가 완전제곱수라면 이미지/QR의 원시 픽셀 데이터일 수 있습니다.

```python
import math
math.isqrt(2500)  # 50
```

바이너리-이미지 변환 도구:

- dCode binary-image 도구.<sup>[[5]](#references)</sup>

#### 브라유

- Branah 브라유 번역기.<sup>[[6]](#references)</sup>

더 다양한 스테가노그래피 유틸리티 모음과 기법별 자료는 함께 제공되는 stego-toolkit과 0xRick의 엄선 목록을 참고하세요.<sup>[[1]](#references)[[7]](#references)</sup>

## References

- [1] [DominicBreuker/stego-toolkit - 인기 있는 스테가노그래피 도구를 함께 묶은 Docker 이미지](https://github.com/DominicBreuker/stego-toolkit)
- [2] [Daston 외 — ECMA-376 오픈 패키징 규약](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
- [3] [ReFirmLabs/binwalk](https://github.com/ReFirmLabs/binwalk)
- [4] [korczis/foremost](https://github.com/korczis/foremost)
- [5] [dCode — 바이너리 이미지](https://www.dcode.fr/binary-image)
- [6] [Branah — 브라유 번역기](https://www.branah.com/braille-translator)
- [7] [0xRick - 스테가노그래피 자료](https://0xrick.github.io/lists/stego/)
{{#include ../../banners/hacktricks-training.md}}
