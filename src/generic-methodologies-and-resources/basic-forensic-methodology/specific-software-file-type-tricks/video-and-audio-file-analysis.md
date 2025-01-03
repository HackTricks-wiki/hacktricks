{{#include ../../../banners/hacktricks-training.md}}

**音声および動画ファイルの操作**は、**CTFフォレンジックチャレンジ**の定番であり、**ステガノグラフィー**やメタデータ分析を利用して秘密のメッセージを隠したり明らかにしたりします。**[mediainfo](https://mediaarea.net/en/MediaInfo)**や**`exiftool`**などのツールは、ファイルのメタデータを検査し、コンテンツタイプを特定するために不可欠です。

音声チャレンジでは、**[Audacity](http://www.audacityteam.org/)**が波形を表示し、音声に埋め込まれたテキストを明らかにするために必要なスペクトログラムを分析するための主要なツールとして際立っています。**[Sonic Visualiser](http://www.sonicvisualiser.org/)**は、詳細なスペクトログラム分析に強く推奨されます。**Audacity**は、隠されたメッセージを検出するためにトラックを遅くしたり逆再生したりする音声操作を可能にします。**[Sox](http://sox.sourceforge.net/)**は、音声ファイルの変換と編集に優れたコマンドラインユーティリティです。

**最下位ビット（LSB）**の操作は、音声および動画のステガノグラフィーで一般的な技術であり、メディアファイルの固定サイズのチャンクを利用してデータを目立たないように埋め込むことができます。**[Multimon-ng](http://tools.kali.org/wireless-attacks/multimon-ng)**は、**DTMFトーン**や**モールス信号**として隠されたメッセージをデコードするのに役立ちます。

動画チャレンジは、音声と動画のストリームをバンドルするコンテナフォーマットを含むことがよくあります。**[FFmpeg](http://ffmpeg.org/)**は、これらのフォーマットを分析および操作するための定番であり、デマルチプレクシングやコンテンツの再生が可能です。開発者向けには、**[ffmpy](http://ffmpy.readthedocs.io/en/latest/examples.html)**がFFmpegの機能をPythonに統合し、高度なスクリプト可能なインタラクションを提供します。

このツールの配列は、CTFチャレンジで必要とされる多様性を強調しており、参加者は音声および動画ファイル内の隠されたデータを明らかにするために広範な分析および操作技術を駆使しなければなりません。

## 参考文献

- [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)

{{#include ../../../banners/hacktricks-training.md}}
