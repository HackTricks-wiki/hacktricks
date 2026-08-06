# Video and Audio File Analysis

{{#include ../../../banners/hacktricks-training.md}}

**Audio and video file manipulation** は **CTF forensics challenges** における定番であり、**steganography** とメタデータ分析を活用して、秘密のメッセージを隠したり明らかにしたりします。**[mediainfo](https://mediaarea.net/en/MediaInfo)** や **`exiftool`** などのツールは、ファイルのメタデータを調査し、コンテンツタイプを特定するために不可欠です。<sup>[[1]](#references)</sup>

Audio challenges では、波形の表示や spectrogram の分析に **[Audacity](http://www.audacityteam.org/)** が優れたツールとして際立っており、Audio にエンコードされたテキストを発見するうえで不可欠です。詳細な spectrogram 分析には **[Sonic Visualiser](http://www.sonicvisualiser.org/)** が強く推奨されます。**Audacity** では、隠されたメッセージを検出するために、トラックの速度を落としたり逆再生したりするなど、Audio の manipulation が可能です。コマンドライン utility である **[Sox](http://sox.sourceforge.net/)** は、Audio files の変換と編集に優れています。<sup>[[1]](#references)</sup>

**Least Significant Bits (LSB)** manipulation は Audio と video steganography で一般的な technique であり、media files の固定サイズの chunks を利用して、データを目立たない形で埋め込みます。**[Multimon-ng](http://tools.kali.org/wireless-attacks/multimon-ng)** は、**DTMF tones** や **Morse code** として隠されたメッセージの decoding に役立ちます。<sup>[[1]](#references)</sup>

Video challenges では、Audio と video streams をまとめる container formats がよく使用されます。**[FFmpeg](http://ffmpeg.org/)** は、これらの formats の分析と manipulation における go-to tool であり、コンテンツの de-multiplexing と playback が可能です。developers 向けには、**[ffmpy](http://ffmpy.readthedocs.io/en/latest/examples.html)** が FFmpeg の capabilities を Python に統合し、高度で scriptable な interactions を可能にします。<sup>[[1]](#references)</sup>

これらの tools の組み合わせは、CTF challenges で求められる versatility を示しています。参加者は、Audio と video files 内の hidden data を発見するために、幅広い analysis と manipulation techniques を活用する必要があります。

## References

- [1] [Video and Audio file analysis – Trail of Bits CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)

{{#include ../../../banners/hacktricks-training.md}}
