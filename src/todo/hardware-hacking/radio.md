# 라디오

{{#include ../../banners/hacktricks-training.md}}

## SigDigger

[**SigDigger** ](https://github.com/BatchDrake/SigDigger)는 알 수 없는 라디오 신호에서 정보를 추출하도록 설계된 GNU/Linux 및 macOS용 free digital signal analyzer입니다. SoapySDR을 통해 다양한 SDR 장치를 지원하며, FSK, PSK 및 ASK 신호의 demodulation 조정, analog video decode, bursty signal 분석, analog voice channel 청취를 모두 real time으로 수행할 수 있습니다.<sup>[[1]](#references)</sup>

### 기본 설정

설치 후 고려할 수 있는 몇 가지 설정이 있습니다.\
설정의 두 번째 탭 버튼에서 **SDR device** 또는 읽을 **file**을 선택하고, 조정할 frequency와 Sample rate를 설정할 수 있습니다(PC가 지원한다면 최대 2.56Msps를 권장).

![SDR device, input file, frequency 및 sample rate 옵션을 표시하는 SigDigger 설정](<../../images/image (245).png>)

GUI behaviour에서는 PC가 지원할 경우 몇 가지 옵션을 활성화하는 것이 좋습니다.

![SigDigger - 기본 설정: PC가 지원할 경우 GUI behaviour에서 몇 가지 옵션을 활성화하는 것이 좋음](<../../images/image (472).png>)

> [!TIP]
> PC가 신호를 capture하지 못한다면 OpenGL을 비활성화하고 sample rate를 낮춰 보세요.

### 사용 방법

- 신호를 일정 시간 **capture하고 analyze**하려면 필요한 동안 "Push to capture" 버튼을 누른 상태로 유지합니다.

![기본 설정 - 사용 방법: 신호를 일정 시간 capture하고 analyze하려면 필요한 동안 "Push to capture" 버튼을 누른 상태로 유지](<../../images/image (960).png>)

- SigDigger의 **Tuner**는 **더 나은 signal capture**를 지원합니다(하지만 신호를 저하시킬 수도 있습니다). 이상적으로는 0에서 시작해 **noise**가 유입되어 **신호의 improvement**보다 커지기 전까지 값을 **계속 증가**시키세요.

![capture된 라디오 신호를 개선하도록 조정된 SigDigger tuner control](<../../images/image (1099).png>)

### 라디오 채널과 동기화

[**SigDigger** ](https://github.com/BatchDrake/SigDigger)를 사용해 듣고 싶은 채널과 synchronize하고, "Baseband audio preview" 옵션을 설정한 다음, 전송되는 모든 정보를 얻을 수 있도록 bandwidth를 설정합니다. 이후 noise가 실제로 증가하기 직전 수준으로 Tuner를 설정합니다:<sup>[[1]](#references)</sup>

![baseband audio preview 및 bandwidth가 설정된 SigDigger synchronized 라디오 채널](<../../images/image (585).png>)

## 유용한 tricks

- 장치가 burst 형태로 정보를 전송할 때 일반적으로 **첫 부분은 preamble**이므로, 그 부분에서 **정보를 찾지 못하거나** **일부 errors가 있어도** **걱정할 필요가 없습니다**.
- 정보 frame에서는 일반적으로 **서로 잘 정렬된 여러 frame을 찾을 수 있습니다**.

![라디오 채널과 동기화 - 유용한 tricks: 정보 frame에서는 일반적으로 서로 잘 정렬된 여러 frame을 찾을 수 있음](<../../images/image (1076).png>)

![라디오 채널과 동기화 - 유용한 tricks: 정보 frame에서는 일반적으로 서로 잘 정렬된 여러 frame을 찾을 수 있음](<../../images/image (597).png>)

- **bits를 복구한 후에는 어떤 방식으로든 process해야 할 수 있습니다**. 예를 들어 Manchester codification에서는 up+down이 1 또는 0이고 down+up이 나머지 값입니다. 따라서 1과 0의 쌍(up과 down)이 실제 1 또는 실제 0이 됩니다.
- 신호가 Manchester codification을 사용하더라도(연속해서 0 또는 1이 두 개를 초과해 나타나는 것은 불가능함), **preamble에서는 여러 개의 1 또는 0이 함께 나타날 수 있습니다**!

### IQ로 modulation type 확인

신호에 정보를 저장하는 방법은 **amplitude**, **frequency**, **phase**를 modulation하는 세 가지가 있습니다.\
신호를 확인할 때 어떤 방식이 정보 저장에 사용되는지 알아내기 위해 시도할 수 있는 방법은 여러 가지가 있지만(아래에서 더 많은 방법을 설명함), 좋은 방법 중 하나는 IQ graph를 확인하는 것입니다.

![신호가 amplitude, frequency 또는 phase modulation을 사용하는지 확인하는 데 사용되는 SigDigger IQ graph](<../../images/image (788).png>)

- **AM 감지**: IQ graph에 예를 들어 **두 개의 원**(하나는 0에 있고 다른 하나는 다른 amplitude에 있을 가능성이 있음)이 나타난다면 AM signal일 수 있습니다. IQ graph에서 0과 원 사이의 거리가 signal의 amplitude이므로, 서로 다른 amplitude가 사용되는 것을 쉽게 시각화할 수 있기 때문입니다.
- **PM 감지**: 이전 이미지처럼 서로 관련되지 않은 작은 원이 보인다면 phase modulation이 사용되었을 가능성이 높습니다. IQ graph에서 point와 0,0 사이의 각도가 signal의 phase이므로, 이는 네 가지 서로 다른 phase가 사용되었음을 의미합니다.
- 정보가 phase 자체가 아니라 phase가 변경되었다는 사실에 숨겨져 있다면, 서로 다른 phase가 명확히 구분되어 보이지 않습니다.
- **FM 감지**: IQ에는 frequency를 식별할 field가 없습니다(중심까지의 거리는 amplitude이고 각도는 phase임).\
따라서 FM을 식별하려면 이 graph에서 **기본적으로 원 하나만 보여야 합니다**.\
또한 서로 다른 frequency는 IQ graph에서 **원을 따라 이동하는 속도의 가속**으로 "표현"됩니다(따라서 SysDigger에서 signal을 선택하면 IQ graph가 채워지며, 생성된 원에서 가속 또는 방향 변경이 발견되면 FM일 수 있습니다):

## AM 예시

{{#file}}
sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### AM 확인

#### envelope 확인

[**SigDigger** ](https://github.com/BatchDrake/SigDigger)로 AM 정보를 확인하고 **envelope**만 살펴보면 서로 다른 명확한 amplitude level을 볼 수 있습니다. 사용된 signal은 AM으로 정보가 포함된 pulse를 전송하며, 다음은 하나의 pulse가 나타나는 방식입니다:<sup>[[1]](#references)</sup>

![명확한 pulse amplitude level을 보여주는 SigDigger AM signal envelope](<../../images/image (590).png>)

다음은 waveform과 함께 표시한 symbol 일부입니다.

![AM 확인 - envelope 확인: waveform과 함께 표시한 symbol 일부](<../../images/image (734).png>)

#### Histogram 확인

정보가 있는 **전체 signal을 선택**하고 **Amplitude** mode와 **Selection**을 선택한 다음 **Histogram**을 클릭합니다. 명확한 level이 2개만 표시되는 것을 확인할 수 있습니다.

![선택된 AM signal의 두 가지 명확한 level을 보여주는 SigDigger amplitude histogram](<../../images/image (264).png>)

예를 들어 이 AM signal에서 Amplitude 대신 Frequency를 선택하면 frequency가 하나만 표시됩니다(frequency로 modulation된 정보가 frequency 하나만 사용할 수는 없습니다).

![하나의 frequency를 보여주는 AM signal의 SigDigger frequency histogram](<../../images/image (732).png>)

frequency가 많이 표시된다면 FM이 아닐 가능성이 높으며, channel의 영향으로 signal frequency가 변경된 것일 수 있습니다.

#### IQ 사용

이 예시에서는 **큰 원**뿐 아니라 **중앙에 많은 point**가 있는 것을 볼 수 있습니다.

![Histogram 확인 - IQ 사용: 큰 원과 중앙의 많은 point를 보여주는 예시](<../../images/image (222).png>)

### Symbol Rate 확인

#### 하나의 symbol 사용

찾을 수 있는 가장 작은 symbol을 선택합니다(따라서 정확히 1개라고 확신할 수 있음). 그런 다음 "Selection freq"를 확인합니다. 이 경우 1.013kHz(약 1kHz)입니다.

![Symbol Rate 확인 - 하나의 symbol 사용: 가장 작은 symbol을 선택하고 Selection freq를 확인하는 방법](<../../images/image (78).png>)

#### symbol group 사용

선택할 symbol 수를 지정하면 SigDigger가 symbol 하나의 frequency를 계산하게 할 수도 있습니다(선택한 symbol이 많을수록 일반적으로 더 정확함). 이 시나리오에서는 10개의 symbol을 선택했으며 "Selection freq"는 1.004 Khz입니다.

![선택한 10개의 symbol group을 사용한 SigDigger symbol-rate 계산](<../../images/image (1008).png>)

### Bits 확인

이 signal이 **AM modulated** signal이고 **symbol rate**를 확인했으며(이 경우 위쪽은 1, 아래쪽은 0을 의미함), signal에 encode된 **bits를 얻는** 작업은 매우 쉽습니다. 정보가 포함된 signal을 선택하고 sampling 및 decision을 설정한 다음 sample을 누릅니다(**Amplitude**가 선택되어 있고, 확인한 **Symbol rate**가 설정되어 있으며, **Gadner clock recovery**가 선택되어 있는지 확인).

![AM sampling, symbol rate 및 Gardner clock recovery가 설정된 SigDigger Get Bits panel](<../../images/image (965).png>)

- **Sync to selection intervals**는 이전에 symbol rate를 확인하기 위해 interval을 선택했다면 해당 symbol rate를 사용한다는 의미입니다.
- **Manual**은 표시된 symbol rate를 사용한다는 의미입니다.
- **Fixed interval selection**에서는 선택할 interval 수를 지정하며, 이를 통해 symbol rate를 계산합니다.
- **Gadner clock recovery**가 일반적으로 가장 좋은 option이지만, 대략적인 symbol rate는 여전히 지정해야 합니다.

sample을 누르면 다음과 같이 표시됩니다.

![symbol group 사용 - Bits 확인: sample을 눌렀을 때 표시되는 결과](<../../images/image (644).png>)

이제 SigDigger가 정보를 전달하는 level의 **range가 어디에 있는지** 이해하도록 하려면 **lower level**을 클릭하고 가장 큰 level까지 클릭한 상태를 유지해야 합니다.

![낮은 amplitude level부터 높은 level까지 SigDigger level-range selection](<../../images/image (439).png>)

예를 들어 **서로 다른 amplitude level이 4개**였다면 **Bits per symbol을 2**로 설정하고 가장 작은 level부터 가장 큰 level까지 선택해야 합니다.

마지막으로 **Zoom을 늘리고** **Row size를 변경**하면 bits를 볼 수 있습니다(bits를 모두 선택하고 copy하여 전체 bits를 가져올 수도 있음).

![symbol group 사용 - Bits 확인: Zoom을 늘리고 Row size를 변경하여 bits를 확인하는 방법](<../../images/image (276).png>)

signal이 symbol당 1 bit보다 많은 bits(예: 2)를 포함한다면 SigDigger는 어떤 symbol이 00, 01, 10, 11인지 알 수 없습니다. 따라서 각각을 표현하기 위해 서로 다른 **grey scale**을 사용하며(bits를 copy하면 **0부터 3까지의 numbers**를 사용하므로 이를 처리해야 함), 이를 직접 구분할 수 없습니다.

또한 **codifications**를 사용할 수 있습니다. 예를 들어 **up+down**은 **1 또는 0**이고 down+up은 1 또는 0일 수 있습니다. 이런 경우 얻은 up(1)과 down(0)을 **process**하여 01 또는 10 pair를 0 또는 1로 변환해야 합니다.

## FM 예시

{{#file}}
sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### FM 확인

#### frequency 및 waveform 확인

FM으로 modulated된 정보를 전송하는 signal 예시:

![FM 확인 - frequency 및 waveform 확인: FM으로 modulated된 정보를 전송하는 signal 예시](<../../images/image (725).png>)

이전 이미지에서 **두 개의 frequency가 사용된 것**을 잘 확인할 수 있습니다. 하지만 **waveform을 관찰**하면 **서로 다른 두 frequency를 정확히 식별하지 못할 수 있습니다**.

![두 frequency를 직접 구분하기 어려운 SigDigger FM waveform](<../../images/image (717).png>)

이는 signal을 두 frequency 모두에서 capture했기 때문이며, 따라서 한 frequency는 대략 다른 frequency의 음수가 됩니다.

![서로 다른 두 frequency가 대략 서로의 음수로 나타나는 SigDigger FM capture](<../../images/image (942).png>)

synchronized frequency가 한 frequency에 다른 frequency보다 **더 가까우면**, 서로 다른 두 frequency를 쉽게 확인할 수 있습니다.

![synchronized frequency가 한 frequency에 더 가까울 때 서로 다른 두 frequency를 쉽게 확인할 수 있는 모습](<../../images/image (422).png>)

![synchronized frequency가 한 frequency에 더 가까울 때 서로 다른 두 frequency를 쉽게 확인할 수 있는 모습](<../../images/image (488).png>)

#### Histogram 확인

정보가 포함된 signal의 frequency histogram을 확인하면 서로 다른 두 signal을 쉽게 볼 수 있습니다.

![frequency 및 waveform 확인 - Histogram 확인: 정보가 포함된 signal의 frequency histogram에서 서로 다른 두 signal을 확인하는 모습](<../../images/image (871).png>)

이 경우 **Amplitude histogram**을 확인하면 **amplitude가 하나만** 표시되므로 **AM일 수 없습니다**(amplitude가 많이 표시된다면 channel을 통과하면서 signal이 power를 잃었기 때문일 수 있음).

![하나의 amplitude level을 보여주는 FM signal의 SigDigger amplitude histogram](<../../images/image (817).png>)

다음은 phase histogram입니다(이를 통해 signal이 phase로 modulated되지 않았다는 사실이 매우 명확해짐).

![frequency 및 waveform 확인 - Histogram 확인: phase histogram을 통해 signal이 phase로 modulated되지 않았음을 확인하는 모습](<../../images/image (996).png>)

#### IQ 사용

IQ에는 frequency를 식별할 field가 없습니다(중심까지의 거리는 amplitude이고 각도는 phase임).\
따라서 FM을 식별하려면 이 graph에서 **기본적으로 원 하나만 보여야 합니다**.\
또한 서로 다른 frequency는 IQ graph에서 **원을 따라 이동하는 속도의 가속**으로 "표현"됩니다(따라서 SysDigger에서 signal을 선택하면 IQ graph가 채워지며, 생성된 원에서 가속 또는 방향 변경이 발견되면 FM일 수 있습니다):

![원을 따라 발생하는 가속 변화를 보여주는 SigDigger IQ graph의 FM](<../../images/image (81).png>)

### Symbol Rate 확인

symbol을 전달하는 frequency를 확인했다면 **AM 예시에서 사용한 것과 동일한 technique**을 사용하여 symbol rate를 얻을 수 있습니다.

### Bits 확인

**signal이 frequency로 modulated되었음**과 **symbol rate**를 확인했다면 **AM 예시에서 사용한 것과 동일한 technique**을 사용하여 bits를 얻을 수 있습니다.

## References

- [1] [SigDigger - Free digital signal analyzer for GNU/Linux and macOS](https://github.com/BatchDrake/SigDigger)

{{#include ../../banners/hacktricks-training.md}}
