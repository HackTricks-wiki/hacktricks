# macOS Serial Number

{{#include ../../../banners/hacktricks-training.md}}

## 기본 정보

모든 Mac에 해독 가능한 12자리 serial number가 있다고 가정하지 마세요. Apple의 이전 형식은 제조 및 구성 정보를 인코딩했지만, Apple은 2021년에 새로운 제품을 출시하면서 randomized serial number를 도입하기 시작했습니다. randomized 형식에는 제조 또는 구성 세부 정보가 노출되지 않습니다.<sup>[[1]](#references)</sup>

### 레거시 12자리 형식

2010년부터 randomized 형식으로 전환되기 전까지 제조된 많은 장치에서는 12자리 형식으로 여전히 유용한 inventory 정보를 확인할 수 있습니다.<sup>[[3]](#references)</sup>

- 문자 1–3은 제조 위치를 식별합니다.
- 문자 4–5는 생산 반기 및 주차를 인코딩합니다.
- 문자 6–8은 동일한 위치와 시간에 생산된 unit을 구분합니다.
- 문자 9–12는 model 또는 configuration code를 식별합니다.

예를 들어 `C02L13ECF8J2`는 이 레거시 구조를 따릅니다. Community-maintained factory mapping에는 United States locations의 접두사로 `FC`, `F`, `XA`, `XB`, `QP`, `G8` 등이 있으며, Mexico는 `RN`, Cork는 `CK`, Czech Republic의 Foxconn location은 `VM`, Singapore는 `SG` 또는 `E`, Malaysia는 `MB`, Korea는 `PT` 또는 `CY`, Taiwan은 `EE`, `QT` 또는 `UV`가 사용됩니다. `FK`, `F1`, `F2`, `W8`, `DL`, `DM`, `DN`, `YM`, `7J`, `1C`, `4H`, `WQ`, `F7`, `C0`, `C3`, `C7`을 포함한 수많은 접두사는 Chinese facilities와 연관되어 있으며, `RM`은 refurbished devices와 연관되어 있습니다.<sup>[[3]](#references)</sup>

네 번째 문자 date code는 `C` (2010년 상반기)부터 `Z` (2019년 하반기)까지 이어지며, 이후에는 sequence가 재사용됩니다. 다섯 번째 문자의 경우 숫자 `1`–`9`는 1–9주를 나타내고, 모음과 `S`를 제외한 문자 `C`–`Y`는 10–27주를 나타냅니다. 네 번째 문자가 연도의 하반기를 나타내면 26을 더합니다.<sup>[[3]](#references)</sup>

이러한 mapping은 레거시 triage에 유용하지만 origin, age 또는 authenticity를 입증하는 authoritative proof는 아닙니다. Apple의 inventory data를 통해 결과를 확인하세요.

신뢰할 수 있는 식별을 위해서는 장치에서 serial number를 가져온 다음, character position으로 model을 추론하려 하지 말고 Apple의 coverage 또는 technical-specification lookup을 사용하세요.<sup>[[2]](#references)</sup>

### serial number 가져오기

Graphical interface에서는 **Apple menu > About This Mac** 아래에 표시됩니다.<sup>[[2]](#references)</sup> Shell에서는 다음 명령 중 하나를 사용하여 platform serial number를 읽을 수 있습니다:
```bash
system_profiler SPHardwareDataType | awk -F ': ' '/Serial Number/ {print $2}'
ioreg -rd1 -c IOPlatformExpertDevice | awk -F '"' '/IOPlatformSerialNumber/ {print $4}'
```
시리얼 번호를 인증자가 아닌 식별자로 취급하세요. 등록 또는 소유권 결정을 내리기 전에 관련 Apple 또는 MDM inventory workflow를 통해 기기를 확인하세요.

## References

- [1] [MacRumors - Apple이 무작위 시리얼 번호로 전환을 시작하다](https://www.macrumors.com/2021/05/05/purple-iphone-12-randomized-serial-number/)
- [2] [Apple Support - Mac 모델 이름 및 시리얼 번호 찾기](https://support.apple.com/en-us/102767)
- [3] [Beetstech - Apple 시리얼 번호에 담긴 의미 해독하기](https://beetstech.com/blog/decode-meaning-behind-apple-serial-number)
{{#include ../../../banners/hacktricks-training.md}}
