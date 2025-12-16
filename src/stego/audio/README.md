# Audio Steganography

{{#include ../../banners/hacktricks-training.md}}

よくあるパターン:

- Spectrogram messages
- WAV LSB embedding
- DTMF / dial tones encoding
- Metadata payloads

## 簡易トリアージ

専用ツールを使う前に:

- コーデック/コンテナの詳細と異常を確認する:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- オーディオにノイズ状の内容や音調構造が含まれている場合、早期にspectrogramを確認する。
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Spectrogram steganography

### Technique

Spectrogram stego は、時間/周波数にわたるエネルギーを成形することでデータを隠し、時間周波数プロット上でのみ可視化される（しばしば可聴ではないかノイズとして認識される）。

### Sonic Visualiser

スペクトログラムの検査向けの主要なツール:

- [https://www.sonicvisualiser.org/](https://www.sonicvisualiser.org/)

### Alternatives

- Audacity (スペクトログラム表示、フィルタ): https://www.audacityteam.org/
- `sox` は CLI からスペクトログラムを生成できます:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## WAV LSB

### 手法

非圧縮 PCM (WAV) では、各サンプルは整数です。下位ビットを変更すると波形はごくわずかにしか変化しないため、攻撃者は次のように隠すことができます:

- サンプルあたり1ビット（またはそれ以上）
- チャンネル間でインターリーブされる
- ストライド／置換を用いる

他に遭遇する可能性のある音声隠蔽方式:

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

DTMFは文字を固定周波数のペア（電話のキーパッド）としてエンコードします。音声がキーパッドの音や規則的な二重周波数のビープ音に似ている場合、早い段階でDTMFデコードを試してください。

オンラインデコーダ：

- [https://unframework.github.io/dtmf-detect/](https://unframework.github.io/dtmf-detect/)
- [http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)

{{#include ../../banners/hacktricks-training.md}}
