# 音声ステガノグラフィ

{{#include ../../banners/hacktricks-training.md}}

一般的なパターン:

- スペクトログラムメッセージ
- WAV LSB embedding
- DTMF / ダイヤルトーンエンコーディング
- メタデータペイロード

## 迅速なトリアージ

専用ツールを使用する前に:

- コーデック/コンテナの詳細と異常を確認:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- 音声にノイズのような内容や音調構造が含まれている場合は、早い段階でスペクトログラムを調べる。
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Spectrogram steganography

### Technique

Spectrogram stego は、時間/周波数にわたってエネルギーを成形し、時間-周波数プロット上でデータが見えるようにすることでデータを隠します。一方で、音声は tones や noise のように聞こえる場合があります。<sup>[[3]](#references)</sup>

### Sonic Visualiser

Spectrogram の調査に使用する主要なツール:

- [Sonic Visualiser](https://www.sonicvisualiser.org/)<sup>[[3]](#references)</sup>

### Alternatives

- Audacity（Spectrogram view と filters）。<sup>[[6]](#references)</sup>
- `sox` は CLI から spectrograms を生成できます:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## FSK / modem のデコード

Frequency-shift keyed 音声は、スペクトログラム上で交互に現れる単一トーンのように見えることがよくあります。おおよその center/shift と baud の推定値が得られたら、`minimodem` で総当たりします。<sup>[[1]](#references)</sup>
```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```
`minimodem` は Bell などの FSK modes とカスタムの mark/space frequencies をサポートします。すべての recording が autodetect できると仮定せず、options を確認してください。出力が文字化けする場合は、`--rx-invert`、明示的な baud mode、または `--samplerate <Hz>` を試してください。<sup>[[4]](#references)</sup>

## WAV LSB

### Technique

非圧縮 PCM (WAV) では、各 sample は整数です。low bits を変更しても waveform はごくわずかしか変化しないため、攻撃者は以下の方法で情報を隠せます。

- 1 sample あたり 1 bit（またはそれ以上）
- channels 間で interleave
- stride/permutation を使用

遭遇する可能性があるその他の audio-hiding の種類：

- Phase coding
- Echo hiding
- Spread-spectrum embedding
- Codec-side channels (format-dependent and tool-dependent)

### WavSteg

以下の commands は `ragibson/Steganography` toolkit の WavSteg を使用します。<sup>[[2]](#references)</sup>
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- DeepSound の公式 repository と releases。<sup>[[7]](#references)</sup>

## DTMF / ダイヤルトーン

### Technique

DTMF は、低周波グループから 1 つ、高周波グループから 1 つの周波数を使用して各 keypad signal を表します。音声が keypad tones や規則的な dual-frequency beeps に似ている場合は、早い段階で DTMF decoding をテストしてください。<sup>[[5]](#references)</sup>

Online decoders:

- `dtmf-detect` browser tool。<sup>[[8]](#references)</sup>
- `ribt/dtmf-decoder`、offline audio-file decoder。<sup>[[9]](#references)</sup>

## References

- [1] [Flagvent 2025 (Medium) — pink、Santa’s Wishlist、Christmas Metadata、Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)
- [2] [ragibson/Steganography](https://github.com/ragibson/Steganography#WavSteg)
- [3] [Sonic Visualiser — documentation](https://www.sonicvisualiser.org/documentation.html)
- [4] [kamalmostafa/minimodem — command-line FSK modem](https://github.com/kamalmostafa/minimodem)
- [5] [ITU-T Recommendation Q.23 — push-button telephone sets の技術的特性](https://www.itu.int/rec/T-REC-Q.23/en)
- [6] [Audacity](https://www.audacityteam.org/)
- [7] [Jpinsoft/DeepSound — 公式 repository と releases](https://github.com/Jpinsoft/DeepSound)
- [8] [`dtmf-detect`](https://unframework.github.io/dtmf-detect/)
- [9] [ribt/dtmf-decoder](https://github.com/ribt/dtmf-decoder)
{{#include ../../banners/hacktricks-training.md}}
