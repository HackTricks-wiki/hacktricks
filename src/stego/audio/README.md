# Audio Steganography

{{#include ../../banners/hacktricks-training.md}}

一般的なパターン:

- Spectrogram messages
- WAV LSB embedding
- DTMF / dial tones encoding
- Metadata payloads

## クイックトリアージ

専用ツールを使う前に:

- codec/container の詳細と異常を確認する:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- オーディオにノイズのような内容やトーンの構造が含まれている場合、早めに spectrogram を確認する。
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Spectrogram steganography

### 手法

Spectrogram stegoは、時間/周波数に沿ったエネルギー分布を成形してデータを隠し、時間-周波数プロットでのみ可視化されるようにします（多くの場合可聴ではなくノイズとして認識されます）。

### Sonic Visualiser

スペクトログラム検査の主要なツール:

- [https://www.sonicvisualiser.org/](https://www.sonicvisualiser.org/)

### 代替

- Audacity (スペクトログラム表示、フィルタ): https://www.audacityteam.org/
- `sox`はCLIからスペクトログラムを生成できます:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## FSK / modem 復号

FSK 音声はスペクトログラム上で交互に現れる単一トーンのように見えることが多い。大まかな center/shift と baud の推定ができたら、`minimodem` で総当たりしてみる:
```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```
`minimodem` はオートゲインとマーク/スペース音の自動検出を行います。出力が乱れる場合は `--rx-invert` や `--samplerate` を調整してください。

## WAV LSB

### 手法

非圧縮の PCM (WAV) では、各サンプルは整数値です。下位ビットを変更しても波形はごくわずかしか変化しないため、攻撃者は次のように隠すことができます：

- 各サンプルあたり1ビット（またはそれ以上）
- チャンネル間でインターリーブ
- ストライド/順列を伴う

その他に遭遇する可能性のある音声隠蔽の手法：

- Phase coding
- Echo hiding
- Spread-spectrum embedding
- Codec-side channels (format-dependent and tool-dependent)

### WavSteg

出典: https://github.com/ragibson/Steganography#WavSteg
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- [http://jpinsoft.net/deepsound/download.aspx](http://jpinsoft.net/deepsound/download.aspx)

## DTMF / ダイヤル音

### 手法

DTMFは文字を固定周波数のペア（telephone keypad）としてエンコードします。音声がキーパッドのトーンや規則的な二重周波数のビープ音に似ている場合は、早い段階でDTMFデコードを試してください。

オンラインデコーダー:

- [https://unframework.github.io/dtmf-detect/](https://unframework.github.io/dtmf-detect/)
- [http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)

## References

- [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
