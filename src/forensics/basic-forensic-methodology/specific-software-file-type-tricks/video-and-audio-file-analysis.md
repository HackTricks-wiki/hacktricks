{{#include ../../../banners/hacktricks-training.md}}

**오디오 및 비디오 파일 조작**은 **CTF 포렌식 챌린지**에서 필수적인 요소로, **스테가노그래피**와 메타데이터 분석을 활용하여 비밀 메시지를 숨기거나 드러냅니다. **[mediainfo](https://mediaarea.net/en/MediaInfo)** 및 **`exiftool`**과 같은 도구는 파일 메타데이터를 검사하고 콘텐츠 유형을 식별하는 데 필수적입니다.

오디오 챌린지에서는 **[Audacity](http://www.audacityteam.org/)**가 파형을 보고 스펙트로그램을 분석하는 데 있어 주요 도구로 두드러지며, 오디오에 인코딩된 텍스트를 발견하는 데 필수적입니다. **[Sonic Visualiser](http://www.sonicvisualiser.org/)**는 상세한 스펙트로그램 분석을 위해 강력히 추천됩니다. **Audacity**는 숨겨진 메시지를 감지하기 위해 트랙을 느리게 하거나 역재생하는 등의 오디오 조작을 허용합니다. **[Sox](http://sox.sourceforge.net/)**는 오디오 파일을 변환하고 편집하는 데 뛰어난 명령줄 유틸리티입니다.

**최하위 비트(LSB)** 조작은 오디오 및 비디오 스테가노그래피에서 일반적인 기술로, 미디어 파일의 고정 크기 청크를 이용해 데이터를 은밀하게 삽입합니다. **[Multimon-ng](http://tools.kali.org/wireless-attacks/multimon-ng)**는 **DTMF 톤** 또는 **모스 부호**로 숨겨진 메시지를 디코딩하는 데 유용합니다.

비디오 챌린지는 종종 오디오 및 비디오 스트림을 묶는 컨테이너 형식을 포함합니다. **[FFmpeg](http://ffmpeg.org/)**는 이러한 형식을 분석하고 조작하는 데 필수적인 도구로, 콘텐츠를 디멀티플렉싱하고 재생할 수 있습니다. 개발자를 위해 **[ffmpy](http://ffmpy.readthedocs.io/en/latest/examples.html)**는 FFmpeg의 기능을 Python에 통합하여 고급 스크립트 상호작용을 가능하게 합니다.

이 도구들의 배열은 CTF 챌린지에서 요구되는 다재다능함을 강조하며, 참가자들은 오디오 및 비디오 파일 내에 숨겨진 데이터를 발견하기 위해 광범위한 분석 및 조작 기술을 사용해야 합니다.

## References

- [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)

{{#include ../../../banners/hacktricks-training.md}}
