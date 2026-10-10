# 音声ステガノグラフィ

{{#include ../../banners/hacktricks-training.md}}

よくあるパターン:

- スペクトログラムメッセージ
- WAVのLSB埋め込み
- DTMF / ダイヤルトーンのエンコード
- メタデータペイロード

## クイックトリアージ

専用ツールを使う前に:

- コーデック/コンテナの詳細と異常を確認:
  - `file audio`
  - `ffmpeg -v info -i audio -f null -`
- 音声にノイズのような内容や音調構造が含まれている場合は、早い段階でスペクトログラムを確認します。

```bash
ffmpeg -v info -i stego.mp3 -f null -
```

## スペクトログラム・ステガノグラフィ

### 手法

Spectrogram stegoは、時間と周波数にわたるエネルギーを調整して、時間-周波数プロット上でデータが見えるように隠します。一方、音声は音やノイズのように聞こえる場合があります。<sup>[[3]](#references)</sup>

### Sonic Visualiser

スペクトログラムの確認に使う主なツール:

- [Sonic Visualiser](https://www.sonicvisualiser.org/)<sup>[[3]](#references)</sup>

### 代替ツール

- Audacity（スペクトログラム表示とフィルター）。<sup>[[6]](#references)</sup>
- `sox`はCLIからスペクトログラムを生成できます:

```bash
sox input.wav -n spectrogram -o spectrogram.png
```

## FSK / モデムのデコード

周波数シフトキーイング（FSK）の音声は、スペクトログラム上で交互に現れる単一トーンとして見えることがよくあります。おおよその中心周波数、シフト幅、ボーレートを推定できたら、`minimodem` で総当たりします：<sup>[[1]](#references)</sup>

```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```

`minimodem` は Bell などの FSK mode とカスタムの mark/space 周波数に対応しています。すべての録音が自動検出できると決めつけず、オプションを確認してください。出力が文字化けする場合は、`--rx-invert`、明示的な baud mode、または `--samplerate <Hz>` を試してください。<sup>[[4]](#references)</sup>

## WAV LSB

### 技法

非圧縮 PCM（WAV）では、各サンプルは整数です。下位ビットを変更しても波形はごくわずかしか変化しないため、攻撃者は次の方法で情報を隠せます。

- 1 サンプルあたり 1 ビット（またはそれ以上）
- 複数のチャンネルに分散
- stride/permutation を使用

遭遇する可能性のあるその他の音声隠蔽手法：

- 位相符号化
- エコー隠蔽
- スペクトラム拡散埋め込み
- コーデック側のサイドチャネル（形式やツールに依存）

### WavSteg

以下のコマンドでは、`ragibson/Steganography` toolkit の WavSteg を使用します。<sup>[[2]](#references)</sup>

```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```

### DeepSound

- DeepSoundの公式リポジトリとリリース。<sup>[[7]](#references)</sup>

## DTMF / ダイヤルトーン

### Technique

DTMFでは、低周波グループから1つ、高周波グループから1つの周波数を使って、各キーパッド信号を表します。音声がキーパッド音や規則的な2周波数のビープ音に似ている場合は、早い段階でDTMFデコードを試してください。<sup>[[5]](#references)</sup>

オンラインデコーダー:

- `dtmf-detect`ブラウザーツール。<sup>[[8]](#references)</sup>
- `ribt/dtmf-decoder`、オフラインの音声ファイルデコーダー。<sup>[[9]](#references)</sup>

## References

- [1] [Flagvent 2025 (Medium) — pink、サンタのウィッシュリスト、クリスマスメタデータ、キャプチャされたノイズ](https://0xdf.gitlab.io/flagvent2025/medium)
- [2] [ragibson/Steganography](https://github.com/ragibson/Steganography#WavSteg)
- [3] [Sonic Visualiser — ドキュメント](https://www.sonicvisualiser.org/documentation.html)
- [4] [kamalmostafa/minimodem — コマンドライン FSK モデム](https://github.com/kamalmostafa/minimodem)
- [5] [ITU-T Recommendation Q.23 — プッシュボタン式電話機の技術的特性](https://www.itu.int/rec/T-REC-Q.23/en)
- [6] [Audacity](https://www.audacityteam.org/)
- [7] [Jpinsoft/DeepSound — 公式リポジトリとリリース](https://github.com/Jpinsoft/DeepSound)
- [8] [`dtmf-detect`](https://unframework.github.io/dtmf-detect/)
- [9] [ribt/dtmf-decoder](https://github.com/ribt/dtmf-decoder)
{{#include ../../banners/hacktricks-training.md}}
