# Audio Steganography

{{#include ../../banners/hacktricks-training.md}}

一般的なパターン:

- Spectrogram messages
- WAV LSB embedding
- DTMF / dial tones encoding
- Metadata payloads

## Quick triage

専用ツールを使用する前に:

- codec/container の詳細と異常を確認:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- audio にノイズのような内容や音調構造が含まれている場合は、早い段階で spectrogram を調査する。
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## スペクトログラム・ステガノグラフィ

### Technique

Spectrogram stego は、時間/周波数全体にわたってエネルギーを形作ることでデータを隠し、時間-周波数プロット上でのみ可視化されるようにします（多くの場合、人間には聞こえないか、ノイズとして認識されます）。

### Sonic Visualiser

Spectrogram の検査に使用する主要なツール:

- [https://www.sonicvisualiser.org/](https://www.sonicvisualiser.org/)

### Alternatives

- Audacity（Spectrogram 表示、フィルター）: https://www.audacityteam.org/
- `sox` は CLI から Spectrogram を生成できます:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## FSK / modem decoding

Frequency-shift keyed audio は、スペクトログラム上で交互に現れる単一トーンのように見えることがよくあります。おおまかな center/shift と baud の推定値が得られたら、`minimodem` で総当たりします:<sup>[[1]](#references)</sup>
```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```
`minimodem` は mark/space tones の自動ゲイン調整と自動検出を行います。出力が文字化けしている場合は、`--rx-invert` または `--samplerate` を調整してください。

## WAV LSB

### Technique

非圧縮 PCM（WAV）では、各サンプルは整数です。下位ビットを変更しても波形はごくわずかしか変化しないため、攻撃者は以下の方法で情報を隠せます。

- サンプルあたり 1 ビット（またはそれ以上）
- チャンネル間でインターリーブ
- ストライド/置換を使用

遭遇する可能性があるその他の audio-hiding の種類:

- Phase coding
- Echo hiding
- Spread-spectrum embedding
- Codec-side channels（format-dependent and tool-dependent）

### WavSteg

出典: https://github.com/ragibson/Steganography#WavSteg<sup>[[2]](#references)</sup>
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- [http://jpinsoft.net/deepsound/download.aspx](http://jpinsoft.net/deepsound/download.aspx)

## DTMF / ダイヤルトーン

### 技法

DTMF は、固定周波数のペア（電話のキーパッド）として文字をエンコードします。音声がキーパッドのトーンや、規則的な二重周波数のビープ音に似ている場合は、早い段階で DTMF decoding を試してください。

オンラインデコーダー:

- [https://unframework.github.io/dtmf-detect/](https://unframework.github.io/dtmf-detect/)
- [http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)

## 参考資料

- [1] [Flagvent 2025 (Medium) — pink、Santa’s Wishlist、Christmas Metadata、Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)
- [2] [ragibson/Steganography](https://github.com/ragibson/Steganography#WavSteg)

{{#include ../../banners/hacktricks-training.md}}
