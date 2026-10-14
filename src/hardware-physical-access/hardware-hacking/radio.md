# Radio

{{#include ../../banners/hacktricks-training.md}}

完成信号识别后，针对特定协议开展工作时，请参阅 [RFID/NFC、sub-GHz、红外、BLE 和 LoRaWAN 测试](../radio-hacking/README.md)。

## SigDigger

[**SigDigger**](https://github.com/BatchDrake/SigDigger) 是一款适用于 GNU/Linux 和 macOS 的免费数字信号分析器，旨在从未知无线电信号中提取信息。它通过 SoapySDR 支持 SDR 设备，并提供用于 FSK、PSK、ASK、模拟视频、突发信号和模拟语音信道的实时解调与分析工具。<sup>[[1]](#references)</sup>

### Basic Config

安装后，有几项配置可以考虑调整。\
在设置中（第二个标签页按钮），选择 **SDR device** 或输入文件、要调谐的频率以及采样率。如果主机支持，最高 2.56 Msps 的采样率可能比较实用。

![SigDigger 设置，显示 SDR 设备、输入文件、频率和采样率选项](<../../images/image (245).png>)

在 GUI behaviour 中，如果你的 PC 支持，建议启用以下几项：

![SigDigger - Basic Config: 在 GUI behaviour 中，如果你的 PC 支持，建议启用以下几项](<../../images/image (472).png>)

> [!TIP]
> 如果发现 PC 无法捕获信号，尝试禁用 OpenGL 并降低采样率。

### Uses

- 若要**捕获一段时间的信号并进行分析**，只需按住 "Push to capture" 按钮，直到采集到所需时长。

![Basic Config - Uses: 若要捕获一段时间的信号并进行分析，只需按住 "Push to capture" 按钮，直到采集到所需时长](<../../images/image (960).png>)

- SigDigger 的 **Tuner** 可以帮助你**更好地捕获信号**（但也可能使信号变差）。理想情况下，从 0 开始，逐渐**调高数值，直到**引入的**噪声**比你所需的**信号改善幅度**更大。

![SigDigger Tuner 控件已调整，以改善捕获到的无线电信号](<../../images/image (1099).png>)

### Synchronize with radio channel

使用 [**SigDigger** ](https://github.com/BatchDrake/SigDigger)与要收听的信道同步，配置 "Baseband audio preview" 选项，设置带宽以获取所发送的全部信息，然后将 Tuner 调整到噪声开始明显增大前的水平：<sup>[[1]](#references)</sup>

![SigDigger 已与无线电信道同步，并配置了基带音频预览和带宽](<../../images/image (585).png>)

## Interesting tricks

- 设备发送突发信息时，通常**第一部分是前导码**，因此如果在其中**找不到信息**或**出现错误**，通常**不必担心**。
- 在信息帧中，通常应该能**找到彼此对齐的不同帧**：

![Synchronize with radio channel - Interesting tricks: 在信息帧中，通常应该能找到彼此对齐的不同帧](<../../images/image (1076).png>)

![Synchronize with radio channel - Interesting tricks: 在信息帧中，通常应该能找到彼此对齐的不同帧](<../../images/image (597).png>)

- **恢复电平转换后，可能还需要对其进行解码。**对于 Manchester 编码，一个方向的转换代表 `0`，相反方向代表 `1`；具体极性取决于所使用的约定。
- 即使载荷使用 Manchester 编码，前导码也可能包含一串相同的采样电平，因此在解码前先识别帧边界。

### Uncovering modulation type with IQ

信号中有 3 种存储信息的方式：调制**振幅**、**频率**或**相位**。\
检查信号时，可以通过不同方式判断信息是如何存储的（更多方法见下文），其中一种好方法是查看 IQ 图。

![SigDigger IQ 图，用于判断信号使用振幅、频率还是相位调制](<../../images/image (788).png>)

- **检测 AM**：如果 IQ 图中出现例如**两个圆**（可能一个位于 0，另一个位于不同的振幅），则信号可能是 AM。这是因为在 IQ 图中，0 点到圆的距离表示信号振幅，因此很容易看出是否使用了不同的振幅。
- **检测 PM**：如上图所示，如果发现彼此无关的小圆，可能表示使用了相位调制。这是因为在 IQ 图中，点与 (0,0) 之间的角度表示信号相位，这意味着使用了 4 种不同相位。
  - 注意，如果信息取决于相位是否发生变化，而非相位本身，那么你将无法清晰地看到不同相位。
- **检测 FM**：IQ 图中没有用于识别频率的字段（到中心的距离表示振幅，角度表示相位）。\
  因此，要识别 FM，在图中基本上**只应看到一个圆**。\
  此外，频率偏移会改变信号绕 IQ 圆旋转的速率。因此，在 SigDigger 中，旋转速度或方向的变化可能表示 FM。

## AM Example

{{#file}}
sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### Uncovering AM

#### Checking the envelope

使用 [**SigDigger**](https://github.com/BatchDrake/SigDigger)检查 AM 数据时，信号**包络**可以显示不同的振幅电平。示例信号以振幅调制脉冲发送信息；其中一个脉冲如下所示：<sup>[[1]](#references)</sup>

![SigDigger AM 信号包络，显示清晰的脉冲振幅电平](<../../images/image (590).png>)

以下是波形中部分符号的样子：

![Uncovering AM - Checking the envelope: 波形中部分符号的样子](<../../images/image (734).png>)

#### Checking the Histogram

你可以**选择包含信息的整个信号**，选择 **Amplitude** 模式和 **Selection**，然后点击 **Histogram**。可以看到只有 2 个明显的电平。

![SigDigger 振幅直方图，显示所选 AM 信号的两个明显电平](<../../images/image (264).png>)

例如，如果在这个 AM 信号中选择 Frequency 而非 Amplitude，你只会找到 1 个频率（信息不可能通过调制频率来传输，却只使用一个频率）。

![SigDigger AM 信号的频率直方图，显示一个频率](<../../images/image (732).png>)

如果发现很多频率，这可能并不代表信号是 FM；信号频率可能只是受信道影响而发生了变化。

#### With IQ

在这个示例中，可以看到一个**大圆**，但中心也有**许多点**。

![Checking the Histogram - With IQ: 示例中可以看到一个大圆，但中心也有许多点](<../../images/image (222).png>)

### Get Symbol Rate

#### With one symbol

选择一个明确包含单个符号的最短区间，并查看 **Selection freq**。在此示例中，它为 1.013 kHz，约为 1 kHz。

![Get Symbol Rate - With one symbol: 选择能找到的最短区间（确保其中只有一个符号），然后查看 "Selection freq"。此例中为 1.013 kHz（即 1 kHz）。](<../../images/image (78).png>)

#### With a group of symbols

你也可以指定要选择的符号数量，SigDigger 会计算单个符号的频率（选中的符号越多，结果通常越准确）。在此示例中，我选择了 10 个符号，"Selection freq" 为 1.004 kHz：

![SigDigger 使用选中的 10 个符号计算符号率](<../../images/image (1008).png>)

### Get Bits

识别 AM 并估算出**符号率**后，选择信号区域，配置振幅采样和判决电平，选择 **Gardner clock recovery**，然后点击 **Sample**：

![SigDigger Get Bits 面板已配置 AM 采样、符号率和 Gardner clock recovery](<../../images/image (965).png>)

- **Sync to selection intervals** 表示如果之前已选择区间来查找符号率，就会使用该符号率。
- **Manual** 表示使用指定的符号率。
- 在 **Fixed interval selection** 中，你可以指定要选择的区间数，SigDigger 会据此计算符号率。
- **Gardner clock recovery** 是一个实用的默认选项，但仍需要提供近似的符号率。

点击 Sample 后，会出现以下内容：

![With a group of symbols - Get Bits: 点击 Sample 后出现的内容](<../../images/image (644).png>)

现在，为了让 SigDigger 知道承载信息的电平范围，需要点击**较低电平**，并按住鼠标拖动到最高电平：

![SigDigger 电平范围选择，从较低振幅电平到较高电平](<../../images/image (439).png>)

例如，如果有 **4 个不同的振幅电平**，则需要将 **Bits per symbol** 设置为 **2**，并从最低电平选到最高电平。

最后，**放大 Zoom** 并**调整 Row size**，就能看到比特（也可以全选并复制以获取所有比特）：

![With a group of symbols - Get Bits: 最后，放大 Zoom 并调整 Row size，就能看到比特（也可以全选并复制以获取所有比特）](<../../images/image (276).png>)

如果信号每个符号包含多于 1 个比特（例如 2 个），SigDigger **无法知道哪个符号代表** 00、01、10、11，因此会用不同的**灰度**表示各个符号（复制比特时会使用 **0 到 3 的数字**，你需要自行处理）。

对于 **Manchester** 等线路编码，请根据所使用的约定，将每个有效转换对（`01` 或 `10`）转换为一个数据比特。

## FM Example

{{#file}}
sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### Uncovering FM

#### Checking the frequencies and waveform

以下是一个通过 FM 调制信息的信号示例：

![Uncovering FM - Checking the frequencies and waveform: 通过 FM 调制信息的信号示例](<../../images/image (725).png>)

频谱中清楚地显示了**两个频率**，但在时域波形中可能很难区分：

![SigDigger FM 波形，难以直接区分两个频率](<../../images/image (717).png>)

这是因为采集中心频率位于两个频率之间，因此它们的频率偏移大致相反：

![SigDigger FM 采集结果显示两个频率的偏移大致互为相反数](<../../images/image (942).png>)

如果同步频率**更接近其中一个频率**，就能轻松看到这两个不同的频率：

![Uncovering FM - Checking the frequencies and waveform: 如果同步频率更接近其中一个频率，就能轻松看到这两个不同的频率](<../../images/image (422).png>)

![Uncovering FM - Checking the frequencies and waveform: 如果同步频率更接近其中一个频率，就能轻松看到这两个不同的频率](<../../images/image (488).png>)

#### Checking the histogram

查看包含信息的信号的频率直方图，可以轻松看到两个不同的信号：

![Checking the frequencies and waveform - Checking the histogram: 查看包含信息的信号的频率直方图，可以轻松看到两个不同的信号](<../../images/image (871).png>)

在这种情况下，如果查看 **Amplitude histogram**，会发现**只有一个振幅**，因此信号**不可能是 AM**（如果发现很多振幅，可能是因为信号在信道传输过程中损失了功率）：

![SigDigger FM 信号的振幅直方图，仅显示一个振幅电平](<../../images/image (817).png>)

以下是相位直方图（它非常清楚地表明信号没有进行相位调制）：

![Checking the frequencies and waveform - Checking the histogram: 相位直方图，非常清楚地表明信号没有进行相位调制](<../../images/image (996).png>)

#### With IQ

IQ 图中没有用于识别频率的字段（到中心的距离表示振幅，角度表示相位）。\
因此，要识别 FM，在图中基本上**只应看到一个圆**。\
此外，频率偏移会改变信号绕 IQ 圆旋转的速率。因此，在 SigDigger 中，旋转速度或方向的变化可能表示 FM：

![SigDigger IQ 图中，FM 表现为圆周旋转速度的变化](<../../images/image (81).png>)

### Get Symbol Rate

找到承载符号的频率后，可以使用 **AM 示例中的相同方法**获取符号率。

### Get Bits

确认信号是**频率调制**并确定**符号率**后，可以使用 **AM 示例中的相同方法**获取比特。

## References

- [1] [SigDigger - 适用于 GNU/Linux 和 macOS 的免费数字信号分析器](https://github.com/BatchDrake/SigDigger)
{{#include ../../banners/hacktricks-training.md}}
