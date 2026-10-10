# 音频隐写术

{{#include ../../banners/hacktricks-training.md}}

常见模式：

- 频谱图消息
- WAV LSB 嵌入
- DTMF / 拨号音编码
- 元数据载荷

## 快速检查

使用专用工具前：

- 确认编解码器/容器详情和异常：
  - `file audio`
  - `ffmpeg -v info -i audio -f null -`
- 如果音频包含类似噪声的内容或音调结构，尽早检查频谱图。

```bash
ffmpeg -v info -i stego.mp3 -f null -
```

## 频谱图隐写

### 技术

频谱图隐写通过塑造时间/频率上的能量分布来隐藏数据，使其在时频图中可见，而音频听起来可能只是音调或噪声。<sup>[[3]](#references)</sup>

### Sonic Visualiser

用于检查频谱图的主要工具：

- [Sonic Visualiser](https://www.sonicvisualiser.org/)<sup>[[3]](#references)</sup>

### 替代工具

- Audacity（频谱图视图和滤波器）。<sup>[[6]](#references)</sup>
- `sox` 可从 CLI 生成频谱图：

```bash
sox input.wav -n spectrogram -o spectrogram.png
```

## FSK / modem 解码

频移键控音频在频谱图中通常呈现为交替的单音。估算出大致的中心频率、频移和波特率后，可使用 `minimodem` 暴力尝试：<sup>[[1]](#references)</sup>

```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```

`minimodem` 支持 Bell 和其他 FSK 模式，以及自定义 mark/space 频率；请查阅其选项，而不要假设每段录音都能自动检测。若输出乱码，可尝试 `--rx-invert`、明确指定波特率模式，或使用 `--samplerate <Hz>`。<sup>[[4]](#references)</sup>

## WAV LSB

### 技术

对于未压缩的 PCM（WAV），每个样本都是一个整数。修改低位只会让波形发生极其轻微的变化，因此攻击者可以隐藏：

- 每个样本 1 位（或更多）
- 在多个声道之间交错
- 使用步长/置换

你可能会遇到的其他音频隐藏方式：

- 相位编码
- 回声隐藏
- 扩频嵌入
- 编解码器侧信道（取决于格式和工具）

### WavSteg

以下命令使用 `ragibson/Steganography` 工具包中的 WavSteg。<sup>[[2]](#references)</sup>

```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```

### DeepSound

- DeepSound 的官方仓库和发行版本。<sup>[[7]](#references)</sup>

## DTMF / 拨号音

### 技术

DTMF 使用一个低频组中的频率和一个高频组中的频率来表示每个按键的信号。如果音频听起来像按键音或规律的双频蜂鸣声，请尽早尝试 DTMF 解码。<sup>[[5]](#references)</sup>

在线解码器：

- `dtmf-detect` 浏览器工具。<sup>[[8]](#references)</sup>
- `ribt/dtmf-decoder`，一款离线音频文件解码器。<sup>[[9]](#references)</sup>

## References

- [1] [Flagvent 2025（Medium）— 粉色、圣诞老人的愿望清单、圣诞节元数据、捕获的噪声](https://0xdf.gitlab.io/flagvent2025/medium)
- [2] [ragibson/Steganography](https://github.com/ragibson/Steganography#WavSteg)
- [3] [Sonic Visualiser — 文档](https://www.sonicvisualiser.org/documentation.html)
- [4] [kamalmostafa/minimodem — 命令行 FSK 调制解调器](https://github.com/kamalmostafa/minimodem)
- [5] [ITU-T 建议书 Q.23 — 按键式电话机的技术特性](https://www.itu.int/rec/T-REC-Q.23/en)
- [6] [Audacity](https://www.audacityteam.org/)
- [7] [Jpinsoft/DeepSound — 官方仓库和发行版本](https://github.com/Jpinsoft/DeepSound)
- [8] [`dtmf-detect`](https://unframework.github.io/dtmf-detect/)
- [9] [ribt/dtmf-decoder](https://github.com/ribt/dtmf-decoder)
{{#include ../../banners/hacktricks-training.md}}
