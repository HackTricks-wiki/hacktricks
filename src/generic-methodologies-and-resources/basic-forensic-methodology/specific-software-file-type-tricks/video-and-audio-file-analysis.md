# 비디오 및 오디오 파일 분석

{{#include ../../../banners/hacktricks-training.md}}

**오디오 및 비디오 파일 조작**은 **CTF forensics challenges**에서 자주 사용되는 기법으로, **steganography**와 metadata 분석을 활용해 비밀 메시지를 숨기거나 드러냅니다. **[mediainfo](https://mediaarea.net/en/MediaInfo)** 및 **`exiftool`**과 같은 도구는 파일 metadata를 검사하고 콘텐츠 유형을 식별하는 데 필수적입니다.<sup>[[1]](#references)</sup>

오디오 challenges에서는 **[Audacity](http://www.audacityteam.org/)**가 파형을 확인하고 spectrogram을 분석하는 대표적인 도구로, 오디오에 인코딩된 텍스트를 찾아내는 데 필수적입니다. 자세한 spectrogram 분석에는 **[Sonic Visualiser](http://www.sonicvisualiser.org/)**를 적극 권장합니다. **Audacity**를 사용하면 트랙의 속도를 늦추거나 역재생하는 등 오디오를 조작하여 숨겨진 메시지를 탐지할 수 있습니다. 명령줄 유틸리티인 **[Sox](http://sox.sourceforge.net/)**는 오디오 파일 변환 및 편집에 뛰어납니다.<sup>[[1]](#references)</sup>

**Least Significant Bits (LSB)** 조작은 오디오 및 비디오 steganography에서 흔히 사용되는 기법으로, 미디어 파일의 고정 크기 청크를 활용해 데이터를 은밀하게 삽입합니다. **[Multimon-ng](http://tools.kali.org/wireless-attacks/multimon-ng)**는 **DTMF tones** 또는 **Morse code**로 숨겨진 메시지를 디코딩하는 데 유용합니다.<sup>[[1]](#references)</sup>

비디오 challenges에서는 오디오 및 비디오 stream을 묶는 container format이 자주 사용됩니다. **[FFmpeg](http://ffmpeg.org/)**는 이러한 format을 분석하고 조작하는 데 사용하는 대표적인 도구로, 콘텐츠를 demultiplex하고 재생할 수 있습니다. 개발자의 경우 **[ffmpy](http://ffmpy.readthedocs.io/en/latest/examples.html)**를 사용하면 FFmpeg의 기능을 Python에 통합하여 고급 scriptable interaction을 구현할 수 있습니다.<sup>[[1]](#references)</sup>

이러한 도구들은 CTF challenges에 필요한 다재다능함을 보여 줍니다. 참가자는 오디오 및 비디오 파일 내부에 숨겨진 데이터를 찾아내기 위해 폭넓은 분석 및 조작 기법을 활용해야 합니다.

## References

- [1] [비디오 및 오디오 파일 분석 – Trail of Bits CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)

{{#include ../../../banners/hacktricks-training.md}}
