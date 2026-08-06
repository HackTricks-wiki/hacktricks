# Radio

{{#include ../../banners/hacktricks-training.md}}

## SigDigger

[**SigDigger** ](https://github.com/BatchDrake/SigDigger)是一个适用于 GNU/Linux 和 macOS 的免费数字信号分析器，旨在从未知 radio 信号中提取信息。它通过 SoapySDR 支持多种 SDR 设备，并允许对 FSK、PSK 和 ASK 信号进行可调制解调、解码模拟视频、分析突发信号以及监听模拟语音信道（全部为实时操作）。<sup>[[1]](#references)</sup>

### Basic Config

安装后，有几项内容可以考虑进行配置。\
在设置中（第二个选项卡按钮），你可以选择 **SDR device** 或 **select a file** 作为读取来源，并选择要调谐的频率和 Sample rate（如果你的 PC 支持，建议最高设置为 2.56Msps）。

![SigDigger 设置界面，显示 SDR device、输入文件、频率和 sample rate 选项](<../../images/image (245).png>)

在 GUI behaviour 中，如果你的 PC 支持，建议启用以下几项：

![SigDigger - Basic Config：在 GUI behaviour 中，建议启用以下几项](<../../images/image (472).png>)

> [!TIP]
> 如果发现你的 PC 无法捕获内容，尝试禁用 OpenGL 并降低 sample rate。

### Uses

- 如果只是想**捕获一段时间的信号并进行分析**，只需一直按住 "Push to capture" 按钮，直到满足所需时长。

![Basic Config - Uses：如果只是想捕获一段时间的信号并进行分析，只需一直按住 "Push to capture" 按钮，直到满足所需时长](<../../images/image (960).png>)

- SigDigger 的 **Tuner** 可以帮助你**更好地捕获信号**（但也可能使信号质量下降）。理想情况下，从 0 开始，持续**增大该值，直到**发现引入的**噪声**大于所需的**信号改善效果**。

![SigDigger Tuner 控件已调整为改善捕获到的 radio 信号](<../../images/image (1099).png>)

### Synchronize with radio channel

使用 [**SigDigger** ](https://github.com/BatchDrake/SigDigger)与想要监听的信道同步，配置 "Baseband audio preview" 选项，将带宽配置为能够获取发送的全部信息，然后将 Tuner 设置为噪声开始明显增加之前的级别：<sup>[[1]](#references)</sup>

![SigDigger 已与 radio 信道同步，并配置了 baseband audio preview 和 bandwidth](<../../images/image (585).png>)

## Interesting tricks

- 当设备以突发方式发送信息时，通常**第一部分会是 preamble**，因此如果在其中**没有找到信息**，或者**其中存在一些错误**，则**无需担心**。
- 在信息帧中，通常应该能**找到彼此对齐良好的不同帧**：

![Synchronize with radio channel - Interesting tricks：在信息帧中，通常应该能找到彼此对齐良好的不同帧](<../../images/image (1076).png>)

![Synchronize with radio channel - Interesting tricks：在信息帧中，通常应该能找到彼此对齐良好的不同帧](<../../images/image (597).png>)

- **恢复 bits 后，可能需要以某种方式处理它们**。例如，在 Manchester codification 中，一个 up+down 会表示 1 或 0，而 down+up 会表示另一个值。因此，一对 1 和 0（ups 和 downs）才对应真正的 1 或 0。
- 即使信号使用 Manchester codification（连续出现超过两个 0 或 1 是不可能的），你仍可能**在 preamble 中找到多个连续的 1 或 0**！

### Uncovering modulation type with IQ

信号中存储信息有 3 种方式：调制**amplitude**、**frequency** 或 **phase**。\
如果你正在检查一个信号，有多种方法可以尝试判断它使用了哪种方式来存储信息（下面还会介绍更多方法），但一种有效的方法是检查 IQ graph。

![SigDigger IQ graph，用于识别信号使用的是 amplitude、frequency 还是 phase modulation](<../../images/image (788).png>)

- **Detecting AM**：如果 IQ graph 中出现例如**两个圆**（可能一个位于 0，另一个位于不同的 amplitude），这可能意味着它是 AM 信号。这是因为在 IQ graph 中，0 与圆之间的距离就是信号的 amplitude，因此可以很容易地观察到使用了不同的 amplitudes。
- **Detecting PM**：如前一张图所示，如果发现彼此无关的小圆，这通常意味着使用了 phase modulation。这是因为在 IQ graph 中，点与 0,0 之间的角度就是信号的 phase，这意味着使用了 4 种不同的 phases。
- 注意，如果信息隐藏在 phase 发生变化这一事实中，而不是隐藏在 phase 本身中，那么你将无法清晰地看到不同的 phases。
- **Detecting FM**：IQ 没有用于识别 frequencies 的字段（到中心的距离是 amplitude，角度是 phase）。\
因此，要识别 FM，在该 graph 中基本上应该**只能看到一个圆**。\
此外，不同的 frequency 会在 IQ graph 中表现为**沿圆周运动速度的加速**（因此，在 SigDigger 中选择信号后，IQ graph 会被填充；如果在生成的圆中发现加速或方向变化，则可能意味着这是 FM）：

## AM Example

{{#file}}
sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### Uncovering AM

#### Checking the envelope

使用 [**SigDigger** ](https://github.com/BatchDrake/SigDigger)检查 AM 信息，只需观察 **envelope**，就能看到不同的清晰 amplitude levels。所使用的信号正在通过 AM 发送带有信息的 pulses，下面是一个 pulse 的样子：<sup>[[1]](#references)</sup>

![SigDigger AM signal envelope，显示清晰的 pulse amplitude levels](<../../images/image (590).png>)

下面是 waveform 中部分 symbol 的样子：

![Uncovering AM - Checking the envelope：waveform 中部分 symbol 的样子](<../../images/image (734).png>)

#### Checking the Histogram

你可以**选择包含信息的整个 signal**，选择 **Amplitude** 模式和 **Selection**，然后点击 **Histogram**。可以观察到只存在两个清晰的 levels。

![SigDigger amplitude histogram，显示所选 AM signal 的两个清晰 levels](<../../images/image (264).png>)

例如，在这个 AM signal 中，如果选择 Frequency 而不是 Amplitude，你只会找到 1 个 frequency（信息不可能通过 frequency modulation 只使用 1 个 freq）。

![SigDigger frequency histogram，用于 AM signal，显示一个 frequency](<../../images/image (732).png>)

如果找到大量 frequencies，这可能不是 FM；信号的 frequency 可能只是受信道影响而发生了变化。

#### With IQ

在这个示例中，可以看到一个**大圆**，同时在**中心还有大量 points**。

![Checking the Histogram - With IQ：示例中可以看到一个大圆，同时在中心还有大量 points](<../../images/image (222).png>)

### Get Symbol Rate

#### With one symbol

选择能找到的最小 symbol（这样可以确定它只有 1 个），然后检查 "Selection freq"。在本例中，它是 1.013kHz（即 1kHz）。

![Get Symbol Rate - With one symbol：选择能找到的最小 symbol（这样可以确定它只有 1 个），然后检查 "Selection freq"。在本例中，它是 1.013kHz（即 1kHz）](<../../images/image (78).png>)

#### With a group of symbols

你也可以指定要选择的 symbols 数量，SigDigger 会计算 1 个 symbol 的 frequency（通常选择的 symbols 越多，结果越准确）。在本例中，我选择了 10 个 symbols，"Selection freq" 为 1.004 Khz：

![SigDigger 使用选定的十个 symbols 组计算 symbol-rate](<../../images/image (1008).png>)

### Get Bits

确认这是一个 **AM modulated** signal 并找到了 **symbol rate**（同时知道在本例中，向上表示 1，向下表示 0）后，就可以很容易地**获取 signal 中编码的 bits**。选择包含信息的 signal，配置 sampling 和 decision，然后按下 sample（确认已选择 **Amplitude**、已配置发现的 **Symbol rate**，并已选择 **Gadner clock recovery**）：

![SigDigger Get Bits panel，已配置 AM sampling、symbol rate 和 Gardner clock recovery](<../../images/image (965).png>)

- **Sync to selection intervals** 表示如果之前选择了用于查找 symbol rate 的 intervals，就会使用该 symbol rate。
- **Manual** 表示使用所指定的 symbol rate。
- 在 **Fixed interval selection** 中，可以指定应选择的 intervals 数量，SigDigger 会据此计算 symbol rate。
- **Gadner clock recovery** 通常是最佳选项，但仍需要指定一个近似的 symbol rate。

按下 sample 后，会出现以下内容：

![With a group of symbols - Get Bits：按下 sample 后的显示结果](<../../images/image (644).png>)

现在，为了让 SigDigger 理解承载信息的 level **range 位于何处**，需要点击**较低的 level**，并持续按住鼠标直到最高 level：

![SigDigger 从较低 amplitude level 到较高 level 的 level-range 选择](<../../images/image (439).png>)

例如，如果存在 **4 个不同的 amplitude levels**，则需要将 **Bits per symbol 配置为 2**，并从最小 level 选择到最大 level。

最后，通过**增大** **Zoom** 并**更改 Row size**，就可以看到 bits（还可以全选并复制，以获取全部 bits）：

![With a group of symbols - Get Bits：增大 Zoom 并更改 Row size 后可以看到 bits，也可以全选并复制以获取全部 bits](<../../images/image (276).png>)

如果 signal 每个 symbol 包含超过 1 个 bit（例如 2 个），SigDigger **无法知道哪个 symbol 是** 00、01、10 或 11，因此会使用不同的 **grey scales** 来表示每个 symbol（复制 bits 时会使用 0 到 3 的**数字**，你需要对其进行处理）。

此外，还可以使用 **codifications**，例如 **Manchester**；up+down 可以是 **1 或 0**，而 down+up 可以是 1 或 0。在这些情况下，需要处理所获得的 ups（1）和 downs（0），将 01 或 10 pairs 替换为 0 或 1。

## FM Example

{{#file}}
sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### Uncovering FM

#### Checking the frequencies and waveform

通过 FM 调制发送信息的 signal 示例：

![Uncovering FM - Checking the frequencies and waveform：通过 FM 调制发送信息的 signal 示例](<../../images/image (725).png>)

在前一张图中，可以很好地观察到使用了**两个 frequencies**，但如果观察 **waveform**，可能**无法正确识别两个不同的 frequencies**：

![SigDigger FM waveform，两个 frequencies 难以直接区分](<../../images/image (717).png>)

这是因为我在两个 frequencies 上捕获了 signal，因此其中一个大约是另一个的负值：

![SigDigger FM capture，显示两个 frequencies 近似互为负值](<../../images/image (942).png>)

如果同步 frequency **更接近其中一个 frequency 而不是另一个**，就可以轻松看到两个不同的 frequencies：

![Uncovering FM - Checking the frequencies and waveform：如果同步 frequency 更接近其中一个 frequency 而不是另一个，就可以轻松看到两个不同的 frequencies](<../../images/image (422).png>)

![Uncovering FM - Checking the frequencies and waveform：如果同步 frequency 更接近其中一个 frequency 而不是另一个，就可以轻松看到两个不同的 frequencies](<../../images/image (488).png>)

#### Checking the histogram

检查包含信息的 signal 的 frequency histogram，可以轻松看到两个不同的 signals：

![Checking the frequencies and waveform - Checking the histogram：检查包含信息的 signal 的 frequency histogram，可以轻松看到两个不同的 signals](<../../images/image (871).png>)

在本例中，如果检查 **Amplitude histogram**，会发现**只有一个 amplitude**，因此它**不可能是 AM**（如果发现多个 amplitudes，可能是因为 signal 在信道中损失了 power）：

![SigDigger amplitude histogram，用于 FM signal，显示单一 amplitude level](<../../images/image (817).png>)

下面是 phase histogram（它非常清楚地表明 signal 不是以 phase 调制的）：

![Checking the frequencies and waveform - Checking the histogram：phase histogram，清楚表明 signal 不是以 phase 调制的](<../../images/image (996).png>)

#### With IQ

IQ 没有用于识别 frequencies 的字段（到中心的距离是 amplitude，角度是 phase）。\
因此，要识别 FM，在该 graph 中基本上应该**只能看到一个圆**。\
此外，不同的 frequency 会在 IQ graph 中表现为**沿圆周运动速度的加速**（因此，在 SigDigger 中选择 signal 后，IQ graph 会被填充；如果在生成的圆中发现加速或方向变化，则可能意味着这是 FM）：

![SigDigger IQ graph，FM 表现为圆周上的加速变化](<../../images/image (81).png>)

### Get Symbol Rate

找到承载 symbols 的 frequencies 后，可以使用 **AM example 中使用的相同 technique** 来获取 symbol rate。

### Get Bits

确认 signal 是 **frequency modulated** 并找到了 **symbol rate** 后，可以使用 **AM example 中使用的相同 technique** 来获取 bits。

## References

- [1] [SigDigger - Free digital signal analyzer for GNU/Linux and macOS](https://github.com/BatchDrake/SigDigger)

{{#include ../../banners/hacktricks-training.md}}
