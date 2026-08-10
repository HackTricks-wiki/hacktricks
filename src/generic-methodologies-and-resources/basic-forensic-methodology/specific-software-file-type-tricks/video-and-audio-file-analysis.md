# 视频和音频文件分析

**音频和视频文件操作**是 **CTF forensics challenges** 中的常见内容，利用 **steganography** 和 metadata analysis 来隐藏或揭示秘密消息。诸如 **[mediainfo](https://mediaarea.net/en/MediaInfo)** 和 **`exiftool`** 之类的工具对于检查文件 metadata 和识别内容类型至关重要。<sup>[[1]](#references)</sup>

对于音频 challenges，**[Audacity](http://www.audacityteam.org/)** 是查看波形和分析 spectrogram 的优秀工具，对于发现音频中编码的文本非常重要。强烈推荐使用 **[Sonic Visualiser](http://www.sonicvisualiser.org/)** 进行详细的 spectrogram 分析。**Audacity** 支持减慢或反转音轨等音频操作，以检测隐藏消息。**[Sox](http://sox.sourceforge.net/)** 是一个命令行工具，擅长转换和编辑音频文件。<sup>[[1]](#references)</sup>

**Least Significant Bits (LSB)** manipulation 是音频和视频 steganography 中的常见技术，利用 media files 的固定大小数据块来隐蔽地嵌入数据。**[Multimon-ng](http://tools.kali.org/wireless-attacks/multimon-ng)** 可用于解码隐藏为 **DTMF tones** 或 **Morse code** 的消息。<sup>[[1]](#references)</sup>

视频 challenges 通常涉及将音频和视频 streams 捆绑在一起的 container formats。**[FFmpeg](http://ffmpeg.org/)** 是分析和操作这些 formats 的首选工具，能够对内容进行 de-multiplexing 和播放。对于开发者而言，**[ffmpy](http://ffmpy.readthedocs.io/en/latest/examples.html)** 将 FFmpeg 的功能集成到 Python 中，以支持高级的 scriptable interactions。<sup>[[1]](#references)</sup>

这一系列工具凸显了 CTF challenges 所需的多样化能力：参与者必须运用广泛的分析和操作技术，才能发现音频和视频文件中隐藏的数据。

## References

- [1] [视频和音频文件分析 – Trail of Bits CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)
{{#include ../../../banners/hacktricks-training.md}}
