# PNG Tricks

{{#include ../../../banners/hacktricks-training.md}}

**PNG 파일**은 **CTF**, **incident response**, **malware staging**에서 매우 흔하게 사용됩니다. **무손실**이고 **chunk 기반**이며, **추가 metadata**, **appended payload**, 또는 **부분적으로 손상된 chunk**가 포함되어 있어도 많은 도구가 문제없이 렌더링하기 때문입니다.

PNG를 단순한 이미지가 아니라 **container**로 취급하세요.

## 빠른 triage

LSB stego로 바로 넘어가기 전에 container 수준의 검사를 먼저 수행하세요. bit-plane/LSB workflow는 [전용 image stego 페이지](../../../stego/images/README.md)를 확인하세요.
```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```
확인할 만한 유용한 항목:

- `tEXt`, `zTXt`, `iTXt`, `eXIf`, `iCCP`와 같은 **예상치 못한 ancillary chunks**
- **CRC errors** 또는 잘못된 chunk 길이
- `IEND` 이후의 **추가 데이터**
- **여러 개의 `IEND` markers** 또는 파일의 공식적인 끝 이후 복구 가능한 `IDAT` fragments
- 유효한 PNG이면서 **carving**했을 때 ZIP/PDF/script처럼 보이는 파일

일반적으로 최소한의 유효한 구조는 다음과 같습니다.

- `IHDR` (반드시 첫 번째여야 함)
- `IDAT` (하나 이상의 연속된 chunks)
- `IEND` (반드시 마지막이어야 함)

## `IEND` 이후의 trailing data

가장 높은 signal을 보이는 PNG artefact 중 하나는 **마지막 `IEND` chunk 이후에 추가된 데이터**입니다. 많은 decoder는 이를 무시하므로 다음 용도로 유용합니다.

- **Simple stego / hidden payloads**
- **PNG polyglots**
- **Malware staging**
- 오류가 있는 editor에서 **이전 image data 복구**

빠른 탐지 방법:
```bash
pngcheck -v suspect.png
# Look for: "additional data after IEND chunk"

exiftool suspect.png
# ExifTool usually warns about trailer data after PNG IEND

grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png
# More than one hit is suspicious
```
최종 `IEND` 이후의 모든 내용을 carve하려면:
```bash
IEND_OFF=$(grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png | tail -n1 | cut -d: -f1)
dd if=suspect.png of=png-trailer.bin bs=1 skip=$((IEND_OFF+8))
file png-trailer.bin
binwalk -eM png-trailer.bin
```
또한 PNG 또는 carve한 trailer에 일반 archive parser를 직접 적용해 보세요:
```bash
7z l suspect.png
unzip -l suspect.png
```
## Acropalypse 스타일의 cropped/redacted screenshot 복구

매우 실용적인 최신 PNG forensic trick은 screenshot editor가 기존 파일을 먼저 **truncating**하지 않고 PNG를 **overwrote**했는지 확인하는 것입니다. 이러한 경우 **previous image**의 bytes가 `IEND` 뒤에 남을 수 있으며, 때로는 추가 `IDAT` data를 부분적으로 reconstruct할 수도 있습니다.

이는 **aCropalypse** (Google Pixel Markup) 및 관련 **Windows Snipping Tool** issue를 통해 널리 알려졌습니다. 실제로 "cropped" 또는 "redacted"된 PNG에 이전 trailing data가 여전히 포함되어 있다면, original screenshot의 일부를 recover할 수 있습니다.<sup>[[1]](#references)</sup>

Practical workflow:
```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```
심층 분석을 강하게 고려해야 하는 징후:

- `pngcheck`가 **`IEND` 이후에 추가 데이터가 있음**을 보고함
- **`IEND`가 둘 이상** 발견됨
- 이미지가 끝난 것으로 보이는 지점 이후에 **추가 `IDAT` chunks**가 발견됨
- 해당 screenshot이 영향을 받은 것으로 알려진 device/editor에서 생성됨

이러한 경우 redaction을 신뢰하기 전에 파일을 **aCropalypse recovery tool**에 전달하세요.

## 실제로 중요한 Chunk 악용

investigation에서 가장 흥미로운 PNG chunks는 대개 명확한 image chunks가 아니라 **text**, **metadata** 또는 **payload bytes**를 포함할 수 있는 chunks입니다:

- `tEXt` / `zTXt` / `iTXt` – text metadata 및 compressed text
- `eXIf` – PNG 내부의 EXIF data
- `iCCP` – embedded ICC profile
- `PLTE` – indexed image의 palette data이지만 payload-smuggling 시나리오에서도 유용함<sup>[[2]](#references)</sup>

다음 명령으로 dump하세요:
```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```
PNG chunk 내부에 offensive payload persistence를 위한 데이터(예: 일부 PHP image transformation에서도 유지되는 **PLTE**, **IDAT**, 또는 **tEXt** tricks)를 삽입하려면, 더 자세한 upload-focused notes를 여기에서 확인하세요<sup>[[2]](#references)</sup>:

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## 손상된 PNG 복구

무결성을 확인하고 정확히 손상된 영역을 찾는 데는 **pngcheck**가 여전히 가장 먼저 사용하기 좋은 도구 중 하나입니다.

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

파일이 의도적으로 악성인 것이 아니라 손상된 경우, **PCRT**는 CTF와 lab 작업에서 잘못된 headers, 잘못된 IHDR values, CRC problems 또는 잘못된 chunk layouts와 같은 일반적인 문제를 수정하는 데 유용할 수 있습니다.

목표가 보이는 이미지를 유지하면서 의심스러운 trailer data가 포함된 PNG를 **sanitize**하는 것이라면, ExifTool로 trailer를 명시적으로 제거할 수 있습니다:
```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```
민감한 증거는 항상 **복사본**으로 작업하고, 복구를 시도하기 전에 원본의 hash를 보관하세요.

## 참고 자료

- [1] [aCropalypse 악용: 잘린 PNG 복구하기](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [2] [PNG의 영구 PHP payload: 이미지에 PHP code를 주입하고 유지하는 방법](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)

{{#include ../../../banners/hacktricks-training.md}}
