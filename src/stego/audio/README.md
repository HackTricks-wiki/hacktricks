# Audio Steganography

{{#include ../../banners/hacktricks-training.md}}

一般的なパターン:

- Spectrogram messages
- WAV LSB embedding
- DTMF / dial tones encoding
- Metadata payloads

## クイックトリアージ

専用ツールを使う前に:

- コーデック/コンテナの詳細と異常を確認する:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- オーディオにノイズのような信号やトーン構造が含まれる場合、早い段階でspectrogramを確認する。
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Spectrogram steganography

### 手法

Spectrogram stego hides data by shaping energy over time/frequency so it becomes visible only in a time-frequency plot (often inaudible or perceived as noise).

### Sonic Visualiser

スペクトログラム検査の主要なツール:

- https://www.sonicvisualiser.org/

### 代替ツール

- Audacity（スペクトログラム表示、フィルタ）： https://www.audacityteam.org/
- `sox` は CLI からスペクトログラムを生成できます：
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## WAV LSB

### 手法

非圧縮の PCM (WAV) では、各サンプルは整数です。下位ビットを変更しても波形はごくわずかにしか変化しないため、攻撃者は次のようにデータを隠せます:

- サンプルあたり 1 ビット（またはそれ以上）
- チャンネル間でインターリーブ
- ストライド／パーミュテーションを用いる

他に遭遇する可能性のある音声隠蔽の手法:

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

- http://jpinsoft.net/deepsound/download.aspx

## DTMF / dial tones

### 手法

DTMFは文字を固定周波数のペア（電話のキーパッド）としてエンコードします。音声がキーパッドの音や規則的な二周波数のビープ音に似ている場合、早い段階でDTMFデコードを試してください。

オンラインデコーダ：

- https://unframework.github.io/dtmf-detect/
- http://dialabc.com/sound/detect/index.html

{{#include ../../banners/hacktricks-training.md}}
