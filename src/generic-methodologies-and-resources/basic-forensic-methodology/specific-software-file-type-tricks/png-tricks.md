# PNG Tricks

{{#include ../../../banners/hacktricks-training.md}}

**PNG 파일**은 **CTF**, **incident response**, **malware staging**에서 매우 흔히 사용됩니다. **lossless**이고 **chunk-based**이며, **extra metadata**, **appended payloads**, 또는 **partially corrupted chunks**를 포함하고 있어도 많은 도구가 문제없이 렌더링하기 때문입니다.

PNG를 단순한 이미지가 아니라 **container**로 취급하세요.

## Quick triage

LSB stego로 넘어가기 전에 먼저 container-level checks를 수행하세요. bit-plane/LSB workflow는 [전용 image stego 페이지](../../../stego/images/README.md)를 확인하세요.
```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```
확인할 만한 유용한 항목:

- `tEXt`, `zTXt`, `iTXt`, `eXIf`, `iCCP`와 같은 **예상치 못한 ancillary chunks**
- **CRC errors** 또는 잘못된 chunk lengths
- `IEND` 이후의 **추가 데이터**
- **여러 개의 `IEND` markers** 또는 파일의 공식적인 끝 이후 복구 가능한 `IDAT` fragments
- 유효한 PNG이면서 동시에 carve했을 때 ZIP/PDF/script처럼 보이는 파일

일반적으로 유효한 최소 구조는 다음과 같습니다.

- `IHDR` (반드시 첫 번째여야 함)
- `IDAT` (하나 이상의 연속된 chunks)
- `IEND` (반드시 마지막이어야 함)

## `IEND` 이후의 후행 데이터

가장 높은 신호를 보이는 PNG artefacts 중 하나는 **최종 `IEND` chunk 이후에 추가된 데이터**입니다. 많은 decoders는 이를 무시하므로 다음 용도로 유용합니다.

- **Simple stego / 숨겨진 payloads**
- **PNG polyglots**
- **Malware staging**
- 버그가 있는 editors에서 **이전 image data 복구**

빠른 탐지:
```bash
pngcheck -v suspect.png
# Look for: "additional data after IEND chunk"

exiftool suspect.png
# ExifTool usually warns about trailer data after PNG IEND

grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png
# More than one hit is suspicious
```
최종 `IEND` 이후의 모든 데이터를 carve하려면:
```bash
IEND_OFF=$(grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png | tail -n1 | cut -d: -f1)
dd if=suspect.png of=png-trailer.bin bs=1 skip=$((IEND_OFF+8))
file png-trailer.bin
binwalk -eM png-trailer.bin
```
또한 일반적인 archive parser를 PNG 또는 carve된 trailer에 직접 적용해 보세요:
```bash
7z l suspect.png
unzip -l suspect.png
```
## Acropalypse 스타일 cropped/redacted screenshot 복구

매우 실용적인 최신 PNG forensic 기법은 screenshot editor가 기존 파일을 먼저 **truncating**하지 않고 PNG를 **overwrote**했는지 확인하는 것입니다. 이러한 경우 **previous image**의 바이트가 `IEND` 이후에 남을 수 있으며, 때로는 추가 `IDAT` 데이터의 일부를 재구성할 수도 있습니다.

이는 **aCropalypse** (Google Pixel Markup) 및 관련 **Windows Snipping Tool** 이슈로 널리 알려졌습니다.<sup>[[3]](#references)</sup> 실제로 "cropped" 또는 "redacted"된 PNG에 이전 trailing data가 여전히 포함되어 있다면, 원본 screenshot의 일부를 복구할 수 있을 수 있습니다.<sup>[[1]](#references)</sup>

실용적인 workflow:
```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```
심층 분석을 강하게 정당화하는 징후:

- `pngcheck`가 **`IEND` 이후에 추가 데이터가 있음**을 보고함
- **`IEND`가 두 개 이상** 발견됨
- 이미지의 겉보기 끝부분 이후에 **추가 `IDAT` 청크**가 발견됨
- 해당 스크린샷이 영향을 받은 것으로 알려진 장치/편집기에서 생성됨

이런 경우 redaction을 신뢰하기 전에 파일을 **aCropalypse recovery tool**에 넣어 처리하세요.

## 실제로 중요한 Chunk abuse

조사에서 가장 흥미로운 PNG 청크는 일반적인 이미지 청크가 아니라, **텍스트**, **메타데이터** 또는 **payload bytes**를 포함할 수 있는 청크인 경우가 많습니다.

- `tEXt` / `zTXt` / `iTXt` – 텍스트 메타데이터 및 압축된 텍스트
- `eXIf` – PNG 내부의 EXIF 데이터
- `iCCP` – 내장 ICC 프로필
- `PLTE` – indexed image의 팔레트 데이터이지만, payload-smuggling 시나리오에서도 유용함.<sup>[[2]](#references)</sup>

다음 명령으로 덤프합니다:
```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```
PNG chunks 내부에 offensive payload을 persistence하기 위해(예: 일부 PHP image transformation 이후에도 남아 있는 **PLTE**, **IDAT**, **tEXt** tricks) 사용하는 방법은 여기의 더 자세한 upload-focused notes를 확인하세요:<sup>[[2]](#references)</sup>

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## Corrupted PNG repair

무결성을 확인하고 정확히 손상된 영역을 찾을 때 **pngcheck**는 여전히 가장 먼저 사용하기 좋은 도구 중 하나입니다.

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

파일이 의도적으로 악성인 것이 아니라 손상된 경우, **PCRT**는 CTF 및 lab work에서 잘못된 header, 올바르지 않은 IHDR 값, CRC 문제 또는 잘못 구성된 chunk layout과 같은 일반적인 문제를 수정하는 데 유용할 수 있습니다.

의심스러운 trailer data가 포함된 PNG를 visible image는 유지하면서 **sanitize**하려는 경우, ExifTool을 사용해 trailer를 명시적으로 제거할 수 있습니다:
```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```
민감한 증거의 경우 항상 **복사본**으로 작업하고, 복구를 시도하기 전에 원본의 해시를 보관하세요.

## References

- [1] [aCropalypse 악용: 잘린 PNG 복구](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [2] [PNG의 영구 PHP payload: 이미지에 PHP code를 삽입하고 계속 유지하는 방법](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)
- [3] [NVD - CVE-2023-28303](https://nvd.nist.gov/vuln/detail/CVE-2023-28303)
{{#include ../../../banners/hacktricks-training.md}}
