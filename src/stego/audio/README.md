# Audio Steganography

{{#include ../../banners/hacktricks-training.md}}

常见模式：

- Spectrogram messages
- WAV LSB embedding
- DTMF / dial tones encoding
- Metadata payloads

## 快速排查

在使用专用工具之前：

- 确认 codec/container 详情和异常：
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- 如果音频包含噪声状内容或音调结构，请尽早检查频谱图。
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Spectrogram steganography

### 技术

Spectrogram stego 通过在时间/频率上塑造能量来隐藏数据，使其仅在时频图中可见（通常不可听或被感知为噪声）。

### Sonic Visualiser

用于频谱图检查的主要工具：

- [https://www.sonicvisualiser.org/](https://www.sonicvisualiser.org/)

### 替代工具

- Audacity (频谱图视图，滤波器): https://www.audacityteam.org/
- `sox` 可以从 CLI 生成频谱图：
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## WAV LSB

### 技术

对于未压缩的 PCM (WAV)，每个采样都是一个整数。修改低位会仅微小地改变波形，因此攻击者可以隐藏：

- 每个采样 1 位（或更多）
- 在各通道间交错
- 使用步长/置换

你可能遇到的其他 audio-hiding families：

- Phase coding
- Echo hiding
- Spread-spectrum embedding
- Codec-side channels (取决于格式和工具)

### WavSteg

来源： https://github.com/ragibson/Steganography#WavSteg
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- [http://jpinsoft.net/deepsound/download.aspx](http://jpinsoft.net/deepsound/download.aspx)

## DTMF / 拨号音

### 方法

DTMF 将字符编码为成对的固定频率（电话键盘）。如果音频听起来像按键音或规律的双频哔声，应尽早测试 DTMF 解码。

在线解码器：

- [https://unframework.github.io/dtmf-detect/](https://unframework.github.io/dtmf-detect/)
- [http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)

{{#include ../../banners/hacktricks-training.md}}
