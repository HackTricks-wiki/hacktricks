# 비디오 및 오디오 파일 분석

{{#include ../../../banners/hacktricks-training.md}}

**Audio and video file manipulation**은 **CTF forensics challenges**에서 핵심적으로 사용되며, **steganography**와 metadata analysis를 활용해 비밀 메시지를 숨기거나 드러냅니다. **[mediainfo](https://mediaarea.net/en/MediaInfo)** 및 **`exiftool`**과 같은 도구는 파일 metadata를 검사하고 content types를 식별하는 데 필수적입니다.<sup>[[1]](#references)</sup>

오디오 challenges에서는 **[Audacity](http://www.audacityteam.org/)**가 waveform을 확인하고 spectrograms를 분석하는 대표적인 도구로, 오디오에 인코딩된 텍스트를 발견하는 데 필수적입니다. 자세한 spectrogram analysis에는 **[Sonic Visualiser](http://www.sonicvisualiser.org/)**를 적극 권장합니다. **Audacity**를 사용하면 트랙의 속도를 늦추거나 반대로 재생하는 등의 오디오 조작을 통해 숨겨진 메시지를 탐지할 수 있습니다. 명령줄 유틸리티인 **[Sox](http://sox.sourceforge.net/)**는 오디오 파일을 변환하고 편집하는 데 뛰어납니다.<sup>[[1]](#references)</sup>

**Least Significant Bits (LSB)** manipulation은 오디오 및 비디오 steganography에서 일반적으로 사용되는 기법으로, media files의 고정 크기 chunks를 활용해 데이터를 은밀하게 삽입합니다. **[Multimon-ng](http://tools.kali.org/wireless-attacks/multimon-ng)**는 **DTMF tones** 또는 **Morse code**로 숨겨진 메시지를 디코딩하는 데 유용합니다.<sup>[[1]](#references)</sup>

비디오 challenges에서는 오디오 및 비디오 streams를 묶는 container formats가 자주 사용됩니다. **[FFmpeg](http://ffmpeg.org/)**는 이러한 formats를 분석하고 조작하는 데 사용되는 대표적인 도구로, content를 de-multiplexing하고 재생할 수 있습니다. 개발자에게는 **[ffmpy](http://ffmpy.readthedocs.io/en/latest/examples.html)**가 FFmpeg의 기능을 Python에 통합하여 고급 scriptable interactions를 지원합니다.<sup>[[1]](#references)</sup>

이러한 도구들은 CTF challenges에서 요구되는 versatility를 보여 줍니다. 참가자는 오디오 및 비디오 파일 내부의 hidden data를 찾아내기 위해 폭넓은 analysis 및 manipulation techniques를 사용해야 합니다.

## References

- [1] [비디오 및 오디오 파일 분석 – Trail of Bits CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)
{{#include ../../../banners/hacktricks-training.md}}
