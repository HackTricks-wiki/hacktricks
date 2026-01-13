# Audio Steganography

{{#include ../../banners/hacktricks-training.md}}

常见模式：

- Spectrogram messages
- WAV LSB embedding
- DTMF / dial tones encoding
- Metadata payloads

## 快速排查

在使用专用工具之前：

- 确认 codec/container 的细节和异常：
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- 如果音频包含类似噪声的内容或音调结构，应尽早检查 spectrogram。
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Spectrogram steganography

### 技术

Spectrogram stego 通过在时间/频率上塑造能量来隐藏数据，使其仅在时频图中可见（通常不可听或被当作噪声）。

### Sonic Visualiser

用于谱图检查的主要工具：

- [https://www.sonicvisualiser.org/](https://www.sonicvisualiser.org/)

### 替代工具

- Audacity（谱图视图，滤波器）：https://www.audacityteam.org/
- `sox` 可以从 CLI 生成谱图：
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## FSK / modem 解码

FSK 音频在频谱图中通常看起来像交替的单一音调。 一旦你有了粗略的中心/偏移和波特率估计，就用 `minimodem` 暴力破解：
```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```
`minimodem` 会自动增益并自动检测 mark/space 音调；如果输出杂乱，请调整 `--rx-invert` 或 `--samplerate`。

## WAV LSB

### 技术

对于未压缩的 PCM (WAV)，每个样本都是一个整数。修改低位会很小地改变波形，因此攻击者可以隐藏：

- 每个样本 1 位（或更多）
- 跨通道交错
- 使用步长/置换

你可能遇到的其他音频隐藏类别：

- Phase coding
- Echo hiding
- Spread-spectrum embedding
- Codec-side channels (依赖于格式和工具)

### WavSteg

From: https://github.com/ragibson/Steganography#WavSteg
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- [http://jpinsoft.net/deepsound/download.aspx](http://jpinsoft.net/deepsound/download.aspx)

## DTMF / 拨号音

### 方法

DTMF 将字符编码为一对固定频率（电话按键）。如果音频类似按键音或规则的双频哔声，请尽早测试 DTMF 解码。

在线解码器：

- [https://unframework.github.io/dtmf-detect/](https://unframework.github.io/dtmf-detect/)
- [http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)

## 参考

- [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
