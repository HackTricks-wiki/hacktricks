# 音频隐写术

{{#include ../../banners/hacktricks-training.md}}

常见模式：

- 频谱图消息
- WAV LSB 嵌入
- DTMF / 拨号音编码
- 元数据 payload

## 快速初筛

在使用专用工具之前：

- 确认 codec/container 详情和异常：
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- 如果音频包含类似噪声的内容或音调结构，尽早检查频谱图。
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Spectrogram steganography

### Technique

Spectrogram stego 通过塑造能量在时间/频率上的分布来隐藏数据，使其在时频图中变得可见，而音频听起来可能只是音调或噪声。<sup>[[3]](#references)</sup>

### Sonic Visualiser

用于检查 spectrogram 的主要工具：

- [Sonic Visualiser](https://www.sonicvisualiser.org/)<sup>[[3]](#references)</sup>

### Alternatives

- Audacity（spectrogram 视图和 filters）。<sup>[[6]](#references)</sup>
- `sox` 可以从 CLI 生成 spectrogram：
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## FSK / modem decoding

Frequency-shift keyed audio 通常在 spectrogram 中表现为交替出现的单音。获得大致的中心频率/频移和 baud 估计值后，可以使用 `minimodem` 进行 brute force：<sup>[[1]](#references)</sup>
```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```
`minimodem` 支持 Bell 和其他 FSK modes，以及自定义的 mark/space frequencies；请查阅其 options，不要假设每个 recording 都能被 autodetected。若输出乱码，请尝试 `--rx-invert`、显式的 baud mode 或 `--samplerate <Hz>`。<sup>[[4]](#references)</sup>

## WAV LSB

### Technique

对于未压缩的 PCM（WAV），每个 sample 都是一个整数。修改低位只会极其轻微地改变 waveform，因此攻击者可以隐藏：

- 每个 sample 1 bit（或更多）
- 在多个 channel 之间交错
- 使用 stride/permutation

你可能遇到的其他 audio-hiding families：

- Phase coding
- Echo hiding
- Spread-spectrum embedding
- Codec-side channels（取决于 format 和 tool）

### WavSteg

以下命令使用 `ragibson/Steganography` toolkit 中的 WavSteg。<sup>[[2]](#references)</sup>
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- DeepSound 的官方 repository 和 releases。<sup>[[7]](#references)</sup>

## DTMF / 拨号音

### 技术

DTMF 使用一个低频组中的频率和一个高频组中的频率来表示每个按键信号。如果音频听起来像键盘音调或规律的双频 beep，应尽早测试 DTMF decoding。<sup>[[5]](#references)</sup>

Online decoders:

- `dtmf-detect` browser tool。<sup>[[8]](#references)</sup>
- `ribt/dtmf-decoder`，用于离线 audio-file decoding。<sup>[[9]](#references)</sup>

## References

- [1] [Flagvent 2025 (Medium) — pink、Santa 的 Wishlist、Christmas Metadata、Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)
- [2] [ragibson/Steganography](https://github.com/ragibson/Steganography#WavSteg)
- [3] [Sonic Visualiser — 文档](https://www.sonicvisualiser.org/documentation.html)
- [4] [kamalmostafa/minimodem — 命令行 FSK 调制解调器](https://github.com/kamalmostafa/minimodem)
- [5] [ITU-T Recommendation Q.23 — 按键式电话机的技术特性](https://www.itu.int/rec/T-REC-Q.23/en)
- [6] [Audacity](https://www.audacityteam.org/)
- [7] [Jpinsoft/DeepSound — 官方 repository 和 releases](https://github.com/Jpinsoft/DeepSound)
- [8] [`dtmf-detect`](https://unframework.github.io/dtmf-detect/)
- [9] [ribt/dtmf-decoder](https://github.com/ribt/dtmf-decoder)
{{#include ../../banners/hacktricks-training.md}}
