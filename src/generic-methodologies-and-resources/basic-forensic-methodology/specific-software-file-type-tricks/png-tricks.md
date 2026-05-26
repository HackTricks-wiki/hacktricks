# PNG Tricks

{{#include ../../../banners/hacktricks-training.md}}

**PNG files**는 **CTFs**, **incident response**, 그리고 **malware staging**에서 매우 흔한데, 이는 **lossless**이고, **chunk-based**이며, 많은 도구가 **extra metadata**, **appended payloads**, 또는 **partially corrupted chunks**가 있어도 이를 정상적으로 렌더링해주기 때문입니다.

PNG를 단순한 이미지가 아니라 **container**로 취급하세요.

## Quick triage

LSB stego로 넘어가기 전에 container-level checks부터 시작하세요. bit-plane/LSB workflow는 [the dedicated image stego page](../../../stego/images/README.md)를 확인하세요.
```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```
찾아볼 유용한 것:

- **Unexpected ancillary chunks** such as `tEXt`, `zTXt`, `iTXt`, `eXIf`, or `iCCP`
- **CRC errors** or malformed chunk lengths
- **Additional data after `IEND`**
- **Multiple `IEND` markers** or recoverable `IDAT` fragments after the formal end of the file
- 파일이 유효한 PNG이면서 **동시에** carve했을 때 ZIP/PDF/script처럼 보이는 경우

기본적으로 최소 유효 구조는 보통 다음과 같습니다:

- `IHDR` (must be first)
- `IDAT` (one or more consecutive chunks)
- `IEND` (must be last)

## Trailing data after `IEND`

가장 신호가 강한 PNG artefacts 중 하나는 **final `IEND` chunk 뒤에 data가 appended된 것**입니다. 많은 decoder가 이를 무시하기 때문에, 다음에 유용합니다:

- **Simple stego / hidden payloads**
- **PNG polyglots**
- **Malware staging**
- **버그가 있는 editor에서 older image data 복구**

빠른 탐지:
```bash
pngcheck -v suspect.png
# Look for: "additional data after IEND chunk"

exiftool suspect.png
# ExifTool usually warns about trailer data after PNG IEND

grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png
# More than one hit is suspicious
```
최종 `IEND` 이후의 모든 것을 carve하고 싶다면:
```bash
IEND_OFF=$(grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png | tail -n1 | cut -d: -f1)
dd if=suspect.png of=png-trailer.bin bs=1 skip=$((IEND_OFF+8))
file png-trailer.bin
binwalk -eM png-trailer.bin
```
또한 generic archive parsers를 PNG 또는 carved trailer에 직접 시도해 보세요:
```bash
7z l suspect.png
unzip -l suspect.png
```
## 잘라낸/가린 스크린샷의 Acropalypse-style 복구

최근 매우 실용적인 PNG 포렌식 트릭은 스크린샷 편집기가 PNG를 저장할 때 먼저 오래된 파일을 **truncating**하지 않고 **overwrote**했는지 확인하는 것입니다. 이런 경우 **이전 이미지**의 bytes가 `IEND` 뒤에 남아 있을 수 있고, 때로는 추가 `IDAT` data를 부분적으로 복구할 수도 있습니다.

이것은 **aCropalypse**(Google Pixel Markup)와 관련된 **Windows Snipping Tool** 이슈로 널리 알려졌습니다. 실제로 "cropped" 또는 "redacted" PNG에 아직 이전 trailing data가 남아 있다면, 원본 스크린샷의 일부를 복구할 수 있을지도 모릅니다.

실용적인 workflow:
```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```
더 깊은 분석을 정당화하는 강한 징후:

- `pngcheck`가 **`IEND` 뒤에 추가 데이터**를 보고함
- **둘 이상의 `IEND`**를 찾음
- 이미지의 겉보기 끝부분 뒤에 **추가 `IDAT` chunk**를 찾음
- 스크린샷이 영향을 받은 것으로 알려진 device/editor에서 생성됨

이런 경우, redaction을 신뢰할 수 있다고 보기 전에 파일을 **aCropalypse recovery tool**에 넣어 복구를 시도하라.

## 실무에서 중요한 chunk abuse

조사에서 가장 흥미로운 PNG chunk는 보통 눈에 띄는 이미지 chunk가 아니라, **text**, **metadata**, 또는 **payload bytes**를 담을 수 있는 chunk들이다:

- `tEXt` / `zTXt` / `iTXt` – text metadata와 compressed text
- `eXIf` – PNG 안의 EXIF data
- `iCCP` – embedded ICC profile
- `PLTE` – indexed images의 palette data이지만, payload-smuggling 시나리오에서도 유용함

다음으로 dump하라:
```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```
For offensive payload persistence inside PNG chunks (for example **PLTE**, **IDAT**, or **tEXt** tricks that survive some PHP image transformations), 자세한 업로드 중심 노트는 여기에서 확인하세요:

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## Corrupted PNG repair

무결성을 확인하고 정확히 손상된 영역을 찾기 위해 **pngcheck**는 여전히 가장 좋은 첫 번째 도구 중 하나입니다:

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

파일이 의도적으로 악성인 것이 아니라 손상된 것이라면, **PCRT**는 CTF와 실습 환경에서 잘못된 헤더, 잘못된 IHDR 값, CRC 문제, 또는 잘못된 chunk 레이아웃 같은 일반적인 문제를 수정하는 데 유용할 수 있습니다.

목표가 가시적인 이미지를 보존하면서 의심스러운 trailer data가 들어 있는 PNG를 **sanitize**하는 것이라면, ExifTool은 trailer를 명시적으로 제거할 수 있습니다:
```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```
민감한 증거는 항상 **복사본**에서 작업하고, 복구를 시도하기 전에 원본의 해시를 보관하세요.

## References

- [https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)

{{#include ../../../banners/hacktricks-training.md}}
