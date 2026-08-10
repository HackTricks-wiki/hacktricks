# Video and Audio File Analysis

**Audio and video file manipulation** は、**CTF forensics challenges** における定番であり、**steganography** と metadata analysis を活用して secret messages を隠したり、発見したりします。**[mediainfo](https://mediaarea.net/en/MediaInfo)** や **`exiftool`** などのツールは、file metadata の検査や content types の特定に不可欠です。<sup>[[1]](#references)</sup>

Audio challenges では、**[Audacity](http://www.audacityteam.org/)** が waveform の表示や spectrogram の分析に適した主要なツールとして際立っており、audio にエンコードされた text の発見に不可欠です。詳細な spectrogram analysis には **[Sonic Visualiser](http://www.sonicvisualiser.org/)** が強く推奨されます。**Audacity** では、track を遅くしたり逆再生したりするなどの audio manipulation によって、hidden messages を検出できます。command-line utility である **[Sox](http://sox.sourceforge.net/)** は、audio files の変換や編集に優れています。<sup>[[1]](#references)</sup>

**Least Significant Bits (LSB)** manipulation は、audio and video steganography で一般的な technique です。media files の固定サイズの chunks を利用して、data を目立たないように埋め込みます。**[Multimon-ng](http://tools.kali.org/wireless-attacks/multimon-ng)** は、**DTMF tones** や **Morse code** として隠された messages の decoding に役立ちます。<sup>[[1]](#references)</sup>

Video challenges では、audio and video streams をまとめる container formats がよく使用されます。**[FFmpeg](http://ffmpeg.org/)** は、これらの formats の分析や manipulation に使用される主要なツールで、content の de-multiplexing と playback が可能です。developers 向けには、**[ffmpy](http://ffmpy.readthedocs.io/en/latest/examples.html)** が FFmpeg の capabilities を Python に統合し、高度で scriptable な interactions を実現します。<sup>[[1]](#references)</sup>

これらの tools は、CTF challenges で求められる versatility を示しています。参加者は、audio and video files 内の hidden data を発見するために、幅広い analysis and manipulation techniques を使い分ける必要があります。

## References

- [1] [Video and Audio file analysis – Trail of Bits CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)
{{#include ../../../banners/hacktricks-training.md}}
