# Audio Steganography

{{#include ../../banners/hacktricks-training.md}}

Common patterns:

- Spectrogram messages
- WAV LSB embedding
- DTMF / dial tones encoding
- Metadata payloads

## Quick triage

Before specialized tooling:

- Confirm codec/container details and anomalies:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- If the audio contains noise-like content or tonal structure, inspect a spectrogram early.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## スペクトログラム steganography

### Technique

Spectrogram stego は、時間/周波数にわたってエネルギーを整形することでデータを隠し、時間-周波数プロットでのみ可視化されるようにします（多くの場合、不可聴またはノイズとして知覚されます）。

### Sonic Visualiser

Spectrogram 検査用の主要な tool：

- [https://www.sonicvisualiser.org/](https://www.sonicvisualiser.org/)

### Alternatives

- Audacity（spectrogram view、filters）：https://www.audacityteam.org/
- `sox` は CLI から spectrograms を生成できます：
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## FSK / modem の復号

Frequency-shift keyed audio は、spectrogram 上で交互に現れる単一トーンのように見えることがよくあります。<sup>[[1]](#references)</sup> おおよその center/shift と baud の推定値が得られたら、`minimodem` で brute force します：
```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```
`minimodem` は mark/space tones を自動ゲイン調整および自動検出します。出力が文字化けする場合は、`--rx-invert` または `--samplerate` を調整してください。

## WAV LSB

### Technique

非圧縮 PCM（WAV）では、各 sample は整数です。下位ビットを変更しても波形はごくわずかしか変化しないため、攻撃者は以下の方法でデータを隠せます。

- 1 sample あたり 1 bit（またはそれ以上）
- channels 間で interleave
- stride/permutation を使用

遭遇する可能性があるその他の audio-hiding の種類：

- Phase coding
- Echo hiding
- Spread-spectrum embedding
- Codec-side channels（format と tool に依存）

### WavSteg

出典: https://github.com/ragibson/Steganography#WavSteg
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- [http://jpinsoft.net/deepsound/download.aspx](http://jpinsoft.net/deepsound/download.aspx)

## DTMF / ダイヤルトーン

### 手法

DTMFは、固定周波数のペア（電話のキーパッド）として文字をエンコードします。音声がキーパッドのトーンや、規則的な2周波数のビープ音に似ている場合は、早い段階でDTMF decodingを試してください。

Online decoders:

- [https://unframework.github.io/dtmf-detect/](https://unframework.github.io/dtmf-detect/)
- [http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)

## 参考資料

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
