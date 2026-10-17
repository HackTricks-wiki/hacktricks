# PNG 트릭

{{#include ../../../banners/hacktricks-training.md}}

**PNG 파일**은 **무손실**이고 **청크 기반**이며, **추가 메타데이터**, **덧붙인 페이로드**, **부분적으로 손상된 청크**가 있어도 많은 도구에서 문제없이 렌더링되므로 **CTF**, **사고 대응**, **malware staging**에서 매우 흔히 사용됩니다.

PNG를 단순한 이미지가 아니라 **컨테이너**로 취급하세요.

## 빠른 초기 분석

LSB stego로 넘어가기 전에 컨테이너 수준의 검사를 먼저 수행하세요. 비트 플레인/LSB 워크플로는 [전용 이미지 stego 페이지](../../../stego/images/)를 확인하세요.

```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```

확인할 만한 항목:

- **예상치 못한 보조 청크**(예: `tEXt`, `zTXt`, `iTXt`, `eXIf` 또는 `iCCP`)
- **CRC 오류** 또는 잘못된 청크 길이
- **`IEND` 뒤에 추가된 데이터**
- **여러 개의 `IEND` 마커** 또는 파일의 공식적인 끝 뒤에서 복구 가능한 `IDAT` 조각
- 유효한 PNG이면서 **carving했을 때 ZIP/PDF/스크립트처럼 보이는 파일**

일반적으로 최소한의 유효한 구조는 다음과 같습니다.

- `IHDR`(첫 번째여야 함)
- `IDAT`(하나 이상의 연속된 청크)
- `IEND`(마지막이어야 함)

## `IEND` 뒤의 후행 데이터

가장 유용한 PNG 아티팩트 중 하나는 **마지막 `IEND` 청크 뒤에 추가된 데이터**입니다. 많은 디코더가 이 데이터를 무시하므로 다음 용도로 활용할 수 있습니다.

- **간단한 스테가노그래피 / 숨겨진 페이로드**
- **PNG 폴리글롯**
- **Malware 스테이징**
- 버그가 있는 편집기에서 **이전 이미지 데이터 복구**

빠른 탐지 방법:

```bash
pngcheck -v suspect.png
# Look for: "additional data after IEND chunk"

exiftool suspect.png
# ExifTool usually warns about trailer data after PNG IEND

grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png
# More than one hit is suspicious
```

`IEND`를 바이트 검색하는 것은 단서일 뿐입니다. 같은 바이트가 chunk 데이터나 위조된 trailer에 있을 수 있습니다. 안정적으로 추출하려면 PNG signature부터 길이 접두사가 붙은 chunk를 순회하고, 구조적으로 첫 번째 `IEND`에서 멈추세요. [아래 chunk 순회 코드](#extract-ancillary-chunk-payloads)는 trailer도 저장합니다.<sup>[[6]](#references)</sup>

PNG 또는 추출한 trailer에 범용 archive parser를 직접 적용해 보세요:

```bash
7z l suspect.png
unzip -l suspect.png
```

## 잘리거나 가려진 스크린샷의 Acropalypse 스타일 복구

매우 실용적인 최신 PNG 포렌식 기법은 스크린샷 편집기가 이전 파일을 먼저 **잘라내지 않고** PNG를 **덮어썼는지** 확인하는 것입니다. 이런 경우 **이전 이미지**의 바이트가 `IEND` 뒤에 남을 수 있으며, 때로는 추가 `IDAT` 데이터를 부분적으로 재구성할 수도 있습니다.

이 문제는 **aCropalypse**(Google Pixel Markup)와 관련된 **Windows Snipping Tool** 문제를 통해 널리 알려졌습니다.<sup>[[3]](#references)</sup> 실제로 "잘렸거나" "가려진" PNG에 오래된 후행 데이터가 남아 있다면, 원래 스크린샷의 일부를 복구할 수 있습니다.<sup>[[1]](#references)</sup>

실용적인 작업 흐름:

```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```

심층 분석이 필요하다고 강하게 판단할 수 있는 징후:

- `pngcheck`에서 **`IEND` 뒤에 추가 데이터가 있음**이라고 보고함
- **`IEND`가 두 개 이상** 발견됨
- 이미지가 끝난 것처럼 보이는 지점 뒤에서 **추가 `IDAT` 청크**가 발견됨
- 스크린샷이 해당 취약점의 영향을 받은 것으로 알려진 기기/편집기에서 생성됨

이런 경우, 가림 처리를 신뢰하기 전에 파일을 **aCropalypse 복구 도구**에 넣어 확인하세요.

## 실제로 중요한 청크 악용

조사에서 가장 흥미로운 PNG 청크는 대개 눈에 띄는 이미지 청크가 아니라 **텍스트**, **메타데이터** 또는 **payload 바이트**를 담을 수 있는 청크입니다.

- `tEXt` / `zTXt` / `iTXt` – 텍스트 메타데이터 및 압축된 텍스트
- `eXIf` – PNG 내부의 EXIF 데이터
- `iCCP` – 내장 ICC 프로필
- `PLTE` – 인덱스 이미지의 팔레트 데이터이며, payload 은닉 시나리오에서도 유용함.<sup>[[2]](#references)</sup>

다음 명령으로 덤프하세요:

```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```

PNG 청크 내 공격용 페이로드의 지속성(예: 일부 PHP 이미지 변환을 거쳐도 살아남는 **PLTE**, **IDAT**, **tEXt** 트릭)에 대해서는 업로드 관련 자세한 내용이 여기에 있습니다:<sup>[[2]](#references)</sup>

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## 보조 청크 페이로드 추출

공격자는 `IEND` 앞의 **알 수 없는 보조 청크**에 임의의 바이트를 넣을 수 있습니다. 일반적인 PNG 디코더는 알 수 없는 보조 청크를 무시할 수 있지만, 이미지를 바이트로 가져오는 스크립트는 페이로드를 읽고 사용할 수 있습니다. PNG를 여는 것만으로 페이로드가 실행되지는 않습니다.<sup>[[4]](#references)[[6]](#references)</sup> 최초 연구에서는 압축 및 암호화된 사용자 지정 청크를 시연했습니다.<sup>[[4]](#references)</sup> 이후 브라우저 사례에서는 추출한 바이트를 HTML이나 다운로드 파일로 제공했습니다.<sup>[[5]](#references)</sup>

첫 번째 청크 유형 문자가 소문자이면 *보조(ancillary)* 청크이고, 두 번째 문자가 소문자이면 *비공개(private)* 청크입니다. 예를 들어 `paMP`는 비공개인 반면, `pAMP`는 시연을 위해 만든 유형이지만 공개 네임스페이스를 사용합니다.<sup>[[4]](#references)[[6]](#references)</sup> 청크는 `길이 (4바이트, 빅엔디안) | 유형 (4바이트) | 데이터 | CRC (4바이트)` 구조이며, CRC는 유형과 데이터를 대상으로 계산됩니다. 압축된 `IDAT` 데이터 안에서 유형 이름을 grep하는 대신 이 구조를 파싱하세요. 다음 워커는 경계와 CRC를 검증하고, 보조 페이로드를 원시 바이트로 내보내며, 구조적 `IEND` 뒤에 있는 바이트는 모두 `png-trailer.bin`에 기록합니다.<sup>[[6]](#references)</sup>

<details>
<summary>보조 청크와 PNG 트레일러 추출</summary>

```bash
python3 - suspect.png <<'PY'
from pathlib import Path
import sys, zlib

png = Path(sys.argv[1]).read_bytes()
assert png[:8] == b"\x89PNG\r\n\x1a\n", "not a PNG"
off = 8
while off + 12 <= len(png):
    size = int.from_bytes(png[off:off + 4], "big")
    kind = png[off + 4:off + 8]
    if not all(65 <= c <= 90 or 97 <= c <= 122 for c in kind):
        raise ValueError(f"invalid chunk type at {off:#x}")
    end = off + 12 + size
    if size >= 2**31 or end > len(png):
        raise ValueError(f"invalid chunk length at {off:#x}")
    body = png[off + 8:end - 4]
    crc = int.from_bytes(png[end - 4:end], "big")
    if zlib.crc32(kind + body) & 0xffffffff != crc:
        raise ValueError(f"bad CRC at {off:#x}")
    print(f"{off:#010x} {kind.decode('ascii', 'replace')} {size} bytes")
    if 97 <= kind[0] <= 122:
        Path(f"chunk-{kind.decode('ascii')}-{off:x}.bin").write_bytes(body)
    off = end
    if kind == b"IEND":
        if size != 0:
            raise ValueError("IEND must be empty")
        Path("png-trailer.bin").write_bytes(png[off:])
        break
else:
    raise ValueError("no complete IEND chunk")
PY
for f in chunk-*.bin png-trailer.bin; do [ -f "$f" ] && file "$f"; done
```

</details>

carved bytes를 `file`, `strings` 또는 `binwalk`로 검사하고, carrier가 실제로 압축된 경우에만 압축을 해제하세요.<sup>[[4]](#references)</sup> 재인코딩하면 carrier가 제거될 수 있으므로, 이를 신뢰하기 전에 업로드한 바이트와 가져온 바이트를 비교하세요.<sup>[[2]](#references)[[6]](#references)</sup>

## 손상된 PNG 복구

무결성을 확인하고 정확한 손상 위치를 찾을 때, **pngcheck**는 여전히 가장 먼저 사용하기 좋은 도구 중 하나입니다.

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

파일이 의도적으로 악의적으로 변조된 것이 아니라 손상된 경우, **PCRT**는 CTF와 실습 환경에서 잘못된 헤더, 잘못된 IHDR 값, CRC 문제 또는 잘못된 chunk 레이아웃 같은 일반적인 문제를 수정하는 데 유용합니다.

의심스러운 trailer data가 포함된 PNG에서 보이는 이미지는 보존하면서 이를 **정리**하려는 경우, ExifTool을 사용해 trailer를 명시적으로 제거할 수 있습니다.

```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```

민감한 증거를 다룰 때는 항상 **복사본**으로 작업하고, 복구를 시도하기 전에 원본의 해시를 보관하세요.



## References

- [1] [aCropalypse 악용: 잘린 PNG 복구하기](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [2] [PNG의 영구적인 PHP payload: 이미지에 PHP 코드를 삽입하고 유지하는 방법](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)
- [3] [NVD - CVE-2023-28303](https://nvd.nist.gov/vuln/detail/CVE-2023-28303)
- [4] [보조 청크는 민감한 정보를 숨기기에 완벽한 장소](https://ignifexlabs.com/blog/hiding-data-in-png-ancillary-chunks.html)
- [5] [유효한 보조 청크를 사용해 엔드포인트로 데이터를 밀반입하기](https://ignifexlabs.com/blog/png-data-smuggling.html)
- [6] [Portable Network Graphics (PNG) 사양 (제3판)](https://www.w3.org/TR/png-3/)
{{#include ../../../banners/hacktricks-training.md}}
