# 音频隐写术

{{#include ../../banners/hacktricks-training.md}}

常见模式：

- Spectrogram 消息
- WAV LSB 嵌入
- DTMF / 拨号音编码
- Metadata payloads

## 快速初筛

在使用 specialized tooling 之前：

- 确认 codec/container 细节和异常：
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- 如果音频包含类似噪声的内容或音调结构，应尽早检查 spectrogram。
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## 频谱图隐写术

### 技术

Spectrogram stego 通过塑造能量在时间和频率上的分布来隐藏数据，使其仅在时频图中可见（通常人耳无法听到，或会被感知为噪声）。

### Sonic Visualiser

用于检查频谱图的主要工具：

- [https://www.sonicvisualiser.org/](https://www.sonicvisualiser.org/)

### 替代工具

- Audacity（频谱图视图、filters）：https://www.audacityteam.org/
- `sox` 可以从 CLI 生成频谱图：
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## FSK / modem 解码

Frequency-shift keyed 音频在 spectrogram 中通常表现为交替的单音。获得大致的中心频率/频移和 baud 估计值后，使用 `minimodem` 进行 brute force：<sup>[[1]](#references)</sup>
```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```
`minimodem` 会自动调整增益并自动检测 mark/space tones；如果输出乱码，请调整 `--rx-invert` 或 `--samplerate`。

## WAV LSB

### Technique

对于未压缩的 PCM（WAV），每个 sample 都是一个整数。修改低位只会使波形发生非常轻微的变化，因此攻击者可以隐藏：

- 每个 sample 1 bit（或更多）
- 在多个声道之间交错
- 使用 stride/permutation

你可能会遇到的其他音频隐藏类型：

- Phase coding
- Echo hiding
- Spread-spectrum embedding
- Codec-side channels（取决于格式和工具）

### WavSteg

来源：https://github.com/ragibson/Steganography#WavSteg<sup>[[2]](#references)</sup>
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- [http://jpinsoft.net/deepsound/download.aspx](http://jpinsoft.net/deepsound/download.aspx)

## DTMF / 拨号音

### Technique

DTMF 将字符编码为成对的固定频率（电话键盘）。如果音频听起来像键盘音或规律的双频 beep，请尽早测试 DTMF decoding。

Online decoders:

- [https://unframework.github.io/dtmf-detect/](https://unframework.github.io/dtmf-detect/)
- [http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)

## References

- [1] [Flagvent 2025 (Medium) — pink、Santa’s Wishlist、Christmas Metadata、Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)
- [2] [ragibson/Steganography](https://github.com/ragibson/Steganography#WavSteg)

{{#include ../../banners/hacktricks-training.md}}
