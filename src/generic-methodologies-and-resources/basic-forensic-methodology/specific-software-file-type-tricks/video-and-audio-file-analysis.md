# Video 및 Audio File Analysis

**Audio 및 video file manipulation**은 **CTF forensics challenges**에서 필수적으로 사용되며, **steganography**와 metadata analysis를 활용해 secret messages를 숨기거나 드러냅니다. **[mediainfo](https://mediaarea.net/en/MediaInfo)** 및 **`exiftool`**과 같은 tools는 file metadata를 검사하고 content types를 식별하는 데 필수적입니다.<sup>[[1]](#references)</sup>

Audio challenges에서는 **[Audacity](http://www.audacityteam.org/)**가 waveforms를 확인하고 spectrograms를 분석하는 주요 tool로 사용되며, audio에 encoded된 text를 찾아내는 데 필수적입니다. 자세한 spectrogram analysis에는 **[Sonic Visualiser](http://www.sonicvisualiser.org/)**를 강력히 권장합니다. **Audacity**를 사용하면 tracks의 속도를 늦추거나 reverse하는 등의 audio manipulation을 수행하여 hidden messages를 탐지할 수 있습니다. Command-line utility인 **[Sox](http://sox.sourceforge.net/)**는 audio files의 변환 및 편집에 뛰어납니다.<sup>[[1]](#references)</sup>

**Least Significant Bits (LSB)** manipulation은 audio 및 video steganography에서 일반적으로 사용되는 technique으로, media files의 고정 크기 chunks를 활용해 data를 은밀하게 삽입합니다. **[Multimon-ng](http://tools.kali.org/wireless-attacks/multimon-ng)**는 **DTMF tones** 또는 **Morse code**로 숨겨진 messages를 decoding하는 데 유용합니다.<sup>[[1]](#references)</sup>

Video challenges에서는 audio 및 video streams를 함께 묶는 container formats가 자주 사용됩니다. **[FFmpeg](http://ffmpeg.org/)**는 이러한 formats를 분석하고 manipulation하는 데 가장 널리 사용되는 tool로, content의 de-multiplexing 및 playback이 가능합니다. Developers의 경우 **[ffmpy](http://ffmpy.readthedocs.io/en/latest/examples.html)**를 사용하면 FFmpeg의 capabilities를 Python에 통합하여 advanced scriptable interactions를 구현할 수 있습니다.<sup>[[1]](#references)</sup>

이러한 tools의 조합은 CTF challenges에 필요한 versatility를 보여 줍니다. 참가자는 audio 및 video files 내부의 hidden data를 찾아내기 위해 광범위한 analysis 및 manipulation techniques를 사용해야 합니다.

## References

- [1] [Video 및 Audio file analysis – Trail of Bits CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)
{{#include ../../../banners/hacktricks-training.md}}
