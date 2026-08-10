# PNG Tricks

**PNG 파일**은 **CTF**, **incident response**, **malware staging**에서 매우 흔히 사용됩니다. **lossless**이고, **chunk-based**이며, 많은 도구가 **extra metadata**, **appended payloads**, **partially corrupted chunks**를 포함하고 있어도 문제없이 렌더링하기 때문입니다.

PNG를 단순한 이미지가 아니라 **container**로 취급하세요.

## 빠른 triage

LSB stego로 넘어가기 전에 먼저 container-level 검사를 수행하세요. bit-plane/LSB workflow는 [전용 image stego 페이지](../../../stego/images/README.md)를 확인하세요.
```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```
찾아볼 만한 유용한 항목:

- `tEXt`, `zTXt`, `iTXt`, `eXIf`, `iCCP`와 같은 **예상하지 못한 ancillary chunks**
- **CRC 오류** 또는 잘못된 chunk 길이
- `IEND` 이후의 **추가 데이터**
- **여러 `IEND` marker** 또는 파일의 공식적인 끝 이후 복구 가능한 `IDAT` fragments
- 유효한 PNG이면서 **carving했을 때 ZIP/PDF/script처럼 보이는 파일**

일반적으로 유효한 최소 구조는 다음과 같습니다.

- `IHDR` (반드시 첫 번째여야 함)
- `IDAT` (하나 이상의 연속된 chunks)
- `IEND` (반드시 마지막이어야 함)

## `IEND` 이후의 trailing data

PNG에서 가장 높은 신호를 보이는 artefact 중 하나는 **마지막 `IEND` chunk 이후에 추가된 데이터**입니다. 많은 decoder는 이를 무시하므로 다음 용도에 유용합니다.

- **Simple stego / 숨겨진 payloads**
- **PNG polyglots**
- **Malware staging**
- 버그가 있는 editor에서 **이전 이미지 데이터 복구**

빠른 탐지:
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
또한 PNG 또는 carved trailer에 generic archive parsers를 직접 시도하세요:
```bash
7z l suspect.png
unzip -l suspect.png
```
## Acropalypse 스타일의 crop/redacted screenshot 복구

매우 실용적인 최신 PNG forensic 기법은 screenshot editor가 이전 파일을 먼저 **truncating**하지 않고 PNG를 **overwrote**했는지 확인하는 것입니다. 이러한 경우 **previous image**의 바이트가 `IEND` 뒤에 남을 수 있으며, 추가 `IDAT` 데이터가 부분적으로 재구성되는 경우도 있습니다.

이는 **aCropalypse**(Google Pixel Markup)와 관련된 **Windows Snipping Tool** 이슈로 널리 알려졌습니다.<sup>[[3]](#references)</sup> 실제로 "cropped" 또는 "redacted" PNG에 이전 trailing data가 여전히 포함되어 있다면, 원본 screenshot의 일부를 복구할 수 있습니다.<sup>[[1]](#references)</sup>

실용적인 workflow:
```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```
깊이 있는 분석이 필요하다는 강력한 징후:

- `pngcheck`가 **`IEND` 이후의 추가 데이터를 보고함**
- **둘 이상의 `IEND`**를 발견함
- 이미지가 끝난 것으로 보이는 지점 이후에 **추가 `IDAT` chunks**를 발견함
- 해당 screenshot이 과거에 영향을 받은 것으로 알려진 device/editor에서 생성됨

이러한 경우 redaction을 신뢰하기 전에 파일을 **aCropalypse recovery tool**에 전달하세요.

## 실제로 중요한 Chunk abuse

조사에서 가장 흥미로운 PNG chunks는 대개 명확한 image chunks가 아니라 **text**, **metadata** 또는 **payload bytes**를 담을 수 있는 chunks입니다:

- `tEXt` / `zTXt` / `iTXt` – text metadata 및 compressed text
- `eXIf` – PNG 내부의 EXIF data
- `iCCP` – embedded ICC profile
- `PLTE` – indexed images의 palette data이며, payload-smuggling 시나리오에서도 유용합니다.<sup>[[2]](#references)</sup>

다음 명령으로 추출하세요:
```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```
PNG chunks 내부에 offensive payload persistence를 넣는 경우(예: 일부 PHP image transformation을 거친 후에도 유지되는 **PLTE**, **IDAT**, **tEXt** tricks)는 다음의 보다 자세한 upload-focused notes를 확인하세요:<sup>[[2]](#references)</sup>

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## 손상된 PNG 복구

무결성을 확인하고 정확히 손상된 영역을 찾을 때는 **pngcheck**가 여전히 가장 먼저 사용하기 좋은 도구 중 하나입니다.

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

파일이 의도적으로 malicious한 것이 아니라 손상된 경우, CTF와 lab work에서 **PCRT**를 사용하면 잘못된 headers, 올바르지 않은 IHDR values, CRC problems 또는 잘못 구성된 chunk layouts와 같은 일반적인 문제를 수정하는 데 유용할 수 있습니다.

의심스러운 trailer data가 포함된 PNG를 visible image는 유지하면서 **sanitize**하려는 경우, ExifTool을 사용해 trailer를 명시적으로 제거할 수 있습니다:
```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```
민감한 증거는 항상 **복사본**으로 작업하고, 복구를 시도하기 전에 원본의 hash를 보관하세요.

## References

- [1] [aCropalypse 악용: 잘린 PNG 복구](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [2] [PNG의 Persistent PHP payload: 이미지에 PHP code를 주입하고 유지하는 방법](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)
- [3] [NVD - CVE-2023-28303](https://nvd.nist.gov/vuln/detail/CVE-2023-28303)
{{#include ../../../banners/hacktricks-training.md}}
