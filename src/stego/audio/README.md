# 音频隐写

{{#include ../../banners/hacktricks-training.md}}

常见模式：

- 频谱图消息
- WAV LSB embedding
- DTMF / 拨号音编码
- 元数据负载

## 快速初步排查

在使用专业工具之前：

- 确认 codec/container 细节和异常：
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- 如果音频包含类似噪声的内容或音调结构，应尽早检查频谱图。
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Spectrogram steganography

### 技术

Spectrogram stego 通过在时间/频率上塑造能量来隐藏数据，使其仅在时频图中可见（通常不可听或被视为噪声）。

### Sonic Visualiser

用于谱图检查的主要工具：

- https://www.sonicvisualiser.org/

### Alternatives

- Audacity (谱图视图、滤镜): https://www.audacityteam.org/
- `sox` 可以从 CLI 生成谱图：
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## WAV LSB

### 技术

对于未压缩的 PCM (WAV)，每个 sample 是一个整数。修改低位会非常轻微地改变波形，因此攻击者可以隐藏：

- 每个 sample 1 bit（或更多）
- 在多个 channels 间交错
- 使用 stride/permutation

你可能会遇到的其他音频隐藏类别：

- Phase coding
- Echo hiding
- Spread-spectrum embedding
- Codec-side channels（依赖 format 和工具）

### WavSteg

来源: https://github.com/ragibson/Steganography#WavSteg
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- http://jpinsoft.net/deepsound/download.aspx

## DTMF / 拨号音

### 方法

DTMF 将字符编码为成对的固定频率（电话键盘）。如果音频类似键盘按键音或规则的双频哔声，应尽早测试 DTMF 解码。

在线解码器:

- https://unframework.github.io/dtmf-detect/
- http://dialabc.com/sound/detect/index.html

{{#include ../../banners/hacktricks-training.md}}
