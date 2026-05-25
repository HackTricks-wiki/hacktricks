# PNG Tricks

{{#include ../../../banners/hacktricks-training.md}}

**PNG files**는 **CTFs**, **incident response**, 및 **malware staging**에서 매우 흔합니다. 왜냐하면 이들은 **lossless**이고, **chunk-based**이며, 많은 도구가 **extra metadata**, **appended payloads**, 또는 **partially corrupted chunks**가 있어도 문제없이 렌더링하기 때문입니다.

PNG를 단순한 이미지가 아니라 **container**로 취급하세요.

## Quick triage

LSB stego로 바로 넘어가기 전에 container-level checks부터 시작하세요. bit-plane/LSB workflow는 [전용 image stego 페이지](../../../stego/images/README.md)를 확인하세요.
```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```
찾아볼 유용한 것들:

- `tEXt`, `zTXt`, `iTXt`, `eXIf`, `iCCP` 같은 **예상치 못한 ancillary chunks**
- **CRC errors** 또는 잘못된 chunk 길이
- `IEND` 뒤의 **추가 데이터**
- **여러 개의 `IEND` 마커** 또는 파일의 형식상 끝 이후에 복구 가능한 `IDAT` 조각
- carving했을 때 유효한 PNG이면서 **ZIP/PDF/script처럼도 보이는** 파일

최소 유효 구조는 보통 다음과 같습니다:

- `IHDR` (반드시 첫 번째)
- `IDAT` (하나 이상의 연속된 chunk)
- `IEND` (반드시 마지막)

## `IEND` 뒤의 trailing data

가장 신호가 강한 PNG artefact 중 하나는 **최종 `IEND` chunk 뒤에 덧붙은 data**입니다. 많은 decoder가 이를 무시하므로, 다음에 유용합니다:

- **Simple stego / hidden payloads**
- **PNG polyglots**
- **Malware staging**
- 버그가 있는 editor에서 **이전 image data 복구**

빠른 탐지:
```bash
pngcheck -v suspect.png
# Look for: "additional data after IEND chunk"

exiftool suspect.png
# ExifTool usually warns about trailer data after PNG IEND

grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png
# More than one hit is suspicious
```
마지막 `IEND` 이후의 모든 것을 잘라내고 싶다면:
```bash
IEND_OFF=$(grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png | tail -n1 | cut -d: -f1)
dd if=suspect.png of=png-trailer.bin bs=1 skip=$((IEND_OFF+8))
file png-trailer.bin
binwalk -eM png-trailer.bin
```
또한 generic archive parser를 PNG 또는 carved trailer에 직접 시도해보세요:
```bash
7z l suspect.png
unzip -l suspect.png
```
## 잘린/가려진 스크린샷의 Acropalypse-style 복구

최근 매우 실용적인 PNG 포렌식 trick 중 하나는 스크린샷 편집기가 PNG를 **기존 파일을 먼저 truncating하지 않고** **overwrite**했는지 확인하는 것이다. 이런 경우 `IEND` 뒤에 **이전 이미지**의 바이트가 남아 있을 수 있고, 때로는 추가 `IDAT` 데이터도 부분적으로 복구할 수 있다.

이것은 **aCropalypse**(Google Pixel Markup)와 관련된 **Windows Snipping Tool** 문제로 널리 알려졌다. 실무에서는 "cropped" 또는 "redacted" PNG에 여전히 오래된 trailing data가 남아 있다면, 원본 스크린샷의 일부를 복구할 수 있을지도 모른다.

실용적인 workflow:
```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```
깊은 분석을 강하게 정당화하는 징후:

- `pngcheck`가 **`IEND` 뒤에 추가 데이터가 있다**고 보고함
- **`IEND`가 하나보다 많음**
- 이미지의 겉보기 끝 이후에 **추가 `IDAT` chunk**가 있음
- 스크린샷이 영향을 받았던 것으로 알려진 device/editor에서 생성됨

이런 경우, redaction을 신뢰할 수 있다고 보기 전에 파일을 **aCropalypse recovery tool**에 넣어 복구해 보세요.

## 실제로 중요한 chunk abuse

조사에서 가장 흥미로운 PNG chunk는 보통 눈에 띄는 이미지 chunk가 아니라, **text**, **metadata**, 또는 **payload bytes**를 담을 수 있는 chunk입니다:

- `tEXt` / `zTXt` / `iTXt` – text metadata 및 compressed text
- `eXIf` – PNG 안의 EXIF data
- `iCCP` – embedded ICC profile
- `PLTE` – indexed images의 palette data이지만, payload-smuggling 시나리오에서도 유용함

다음으로 덤프할 수 있습니다:
```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```
공격용 payload를 PNG chunk 내부에 지속시키는 것에 대해(예: 일부 PHP image transformations를 살아남는 **PLTE**, **IDAT**, 또는 **tEXt** tricks), 더 자세한 upload 중심 노트는 여기에서 확인하세요:

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## 손상된 PNG 복구

무결성을 확인하고 정확한 손상 위치를 찾기 위해, **pngcheck**는 여전히 가장 좋은 첫 번째 도구 중 하나입니다:

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

파일이 의도적으로 malicious한 것이 아니라 손상된 것이라면, **PCRT**는 CTF와 lab 작업에서 잘못된 header, 잘못된 IHDR 값, CRC 문제, 또는 잘못된 chunk layout 같은 일반적인 문제를 고치는 데 유용할 수 있습니다.

악성 trailer data가 포함된 PNG를 보이는 이미지는 유지한 채 **sanitize**하고 싶다면, ExifTool로 trailer를 명시적으로 제거할 수 있습니다:
```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```
민감한 증거는 항상 **copy**에서 작업하고, 수리를 시도하기 전에 원본의 hashes를 보관하세요.

## References

- [https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)

{{#include ../../../banners/hacktricks-training.md}}
