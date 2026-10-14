# Radio

{{#include ../../banners/hacktricks-training.md}}

## SigDigger

[**SigDigger**](https://github.com/BatchDrake/SigDigger)는 GNU/Linux 및 macOS용 무료 디지털 신호 분석기로, 알려지지 않은 radio 신호에서 정보를 추출하도록 설계되었습니다. SoapySDR을 통해 SDR 장치를 지원하며 FSK, PSK, ASK, 아날로그 비디오, 버스트 신호 및 아날로그 음성 채널을 위한 실시간 복조 및 분석 도구를 제공합니다.<sup>[[1]](#references)</sup>

### Basic Config

설치한 후 설정해 볼 수 있는 몇 가지 항목이 있습니다.\
설정(두 번째 탭 버튼)에서 **SDR 장치** 또는 입력 파일, 튜닝할 주파수, 샘플 레이트를 선택합니다. 호스트가 지원한다면 최대 2.56 Msps의 레이트가 적절할 수 있습니다.

![SDR 장치, 입력 파일, 주파수 및 샘플 레이트 옵션을 보여주는 SigDigger 설정 화면](<../../images/image (245).png>)

PC가 지원한다면 GUI 동작 설정에서 몇 가지 항목을 활성화하는 것이 좋습니다.

![SigDigger - Basic Config: PC가 지원한다면 GUI 동작 설정에서 몇 가지 항목을 활성화하는 것이 좋습니다](<../../images/image (472).png>)

> [!TIP]
> PC에서 신호가 캡처되지 않는 것 같다면 OpenGL을 비활성화하고 샘플 레이트를 낮춰 보세요.

### Uses

- 신호를 **일정 시간 캡처한 다음 분석**하려면 필요한 만큼 "Push to capture" 버튼을 누르고 있으면 됩니다.

![Basic Config - Uses: 신호를 일정 시간 캡처한 다음 분석하려면 필요한 만큼 "Push to capture" 버튼을 누르고 있으면 됩니다](<../../images/image (960).png>)

- SigDigger의 **Tuner**는 **신호를 더 잘 캡처**하도록 도와줍니다(하지만 신호를 저하시킬 수도 있습니다). 이상적으로는 0에서 시작해, 추가되는 **노이즈가 필요한 신호 개선 효과보다 커지기 전까지** 값을 높이세요.

![캡처된 radio 신호를 개선하도록 조정된 SigDigger 튜너 컨트롤](<../../images/image (1099).png>)

### Synchronize with radio channel

[**SigDigger**](https://github.com/BatchDrake/SigDigger)에서 듣고 싶은 채널에 동기화하고, "Baseband audio preview" 옵션을 설정한 다음 전송되는 정보를 모두 포함하도록 대역폭을 설정합니다. 그런 다음 노이즈가 실제로 증가하기 시작하기 직전까지 Tuner를 조정합니다.<sup>[[1]](#references)</sup>

![베이스밴드 오디오 미리보기와 대역폭을 설정하고 radio 채널에 동기화한 SigDigger](<../../images/image (585).png>)

## Interesting tricks

- 장치가 정보를 버스트 형태로 전송할 때는 보통 **첫 부분이 프리앰블**입니다. 따라서 해당 부분에서 **정보를 찾지 못하거나 오류가 있더라도** 걱정할 **필요가 없습니다**.
- 정보 프레임에서는 보통 서로 잘 정렬된 여러 프레임을 **확인할 수 있어야 합니다**.

![Synchronize with radio channel - Interesting tricks: 정보 프레임에서는 서로 잘 정렬된 여러 프레임을 확인할 수 있어야 합니다](<../../images/image (1076).png>)

![Synchronize with radio channel - Interesting tricks: 정보 프레임에서는 서로 잘 정렬된 여러 프레임을 확인할 수 있어야 합니다](<../../images/image (597).png>)

- **레벨 전환을 복구한 뒤에는 디코딩해야 할 수 있습니다.** Manchester encoding에서는 한 방향의 전환이 `0`, 반대 방향의 전환이 `1`을 나타내며, 정확한 극성은 사용 중인 규약에 따라 다릅니다.
- 페이로드에 Manchester encoding을 사용하더라도 프리앰블에는 같은 샘플 레벨이 연속해서 나타날 수 있습니다. 따라서 디코딩하기 전에 프레임 경계를 식별하세요.

### Uncovering modulation type with IQ

신호에 정보를 저장하는 방법은 세 가지입니다. **진폭**, **주파수** 또는 **위상**을 변조하는 것입니다.\
신호를 확인할 때 어떤 방식으로 정보를 저장하는지 알아보는 여러 방법이 있습니다(아래에서 더 많은 방법을 확인할 수 있습니다). IQ 그래프를 확인하는 것도 좋은 방법입니다.

![신호가 진폭, 주파수 또는 위상 변조를 사용하는지 식별하는 데 사용되는 SigDigger IQ 그래프](<../../images/image (788).png>)

- **AM 감지**: IQ 그래프에 예를 들어 **원 두 개**(하나는 0에, 다른 하나는 다른 진폭에)가 나타나면 AM 신호일 수 있습니다. IQ 그래프에서 0과 원 사이의 거리가 신호의 진폭이므로, 서로 다른 진폭이 사용되는 모습을 쉽게 확인할 수 있습니다.
- **PM 감지**: 이전 이미지처럼 서로 관련이 없어 보이는 작은 원들이 나타나면 위상 변조를 사용하고 있을 수 있습니다. IQ 그래프에서 점과 (0,0) 사이의 각도가 신호의 위상이므로, 이 경우 네 가지 위상이 사용된다는 뜻입니다.
  - 정보가 위상 자체가 아니라 위상이 바뀌는 사실에 담겨 있다면, 서로 다른 위상이 명확히 구분되어 보이지 않을 수 있습니다.
- **FM 감지**: IQ에는 주파수를 식별하는 필드가 없습니다(중심까지의 거리는 진폭이고 각도는 위상입니다).\
  따라서 FM을 식별하려면 이 그래프에서 기본적으로 **원 하나만 보여야 합니다**.\
  또한 주파수 오프셋은 IQ 원을 도는 회전 속도를 바꿉니다. 따라서 SigDigger에서는 회전 속도나 방향의 변화를 FM의 징후로 볼 수 있습니다.

## AM Example

{{#file}}
sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### Uncovering AM

#### Checking the envelope

[**SigDigger**](https://github.com/BatchDrake/SigDigger)로 AM 데이터를 살펴볼 때 신호 **엔벨로프**에서 뚜렷한 진폭 레벨을 확인할 수 있습니다. 예시 신호는 진폭 변조 펄스로 정보를 전송하며, 펄스 하나는 다음과 같습니다.<sup>[[1]](#references)</sup>

![명확한 펄스 진폭 레벨이 나타난 SigDigger AM 신호 엔벨로프](<../../images/image (590).png>)

파형으로 보면 심볼 일부가 다음과 같이 나타납니다.

![Uncovering AM - Checking the envelope: 파형으로 보면 심볼 일부가 다음과 같이 나타납니다](<../../images/image (734).png>)

#### Checking the Histogram

정보가 있는 신호 전체를 **선택**하고 **Amplitude** 모드와 **Selection**을 선택한 다음 **Histogram**을 클릭합니다. 뚜렷한 레벨이 두 개만 나타나는 것을 확인할 수 있습니다.

![선택한 AM 신호에서 뚜렷한 레벨 두 개를 보여주는 SigDigger 진폭 히스토그램](<../../images/image (264).png>)

예를 들어 이 AM 신호에서 Amplitude 대신 Frequency를 선택하면 주파수가 하나만 나타납니다(주파수 변조 정보가 주파수 하나만 사용해 전송될 수는 없습니다).

![AM 신호에서 주파수 하나를 보여주는 SigDigger 주파수 히스토그램](<../../images/image (732).png>)

주파수가 많이 보인다면 FM이 아닐 가능성이 큽니다. 채널 때문에 신호 주파수가 변했을 뿐일 수 있습니다.

#### With IQ

이 예시에서는 **큰 원** 하나와 중심에 있는 **여러 점**을 확인할 수 있습니다.

![Checking the Histogram - With IQ: 이 예시에서는 큰 원 하나와 중심에 있는 여러 점을 확인할 수 있습니다](<../../images/image (222).png>)

### Get Symbol Rate

#### With one symbol

심볼 하나가 명확히 포함된 가장 짧은 구간을 선택하고 **Selection freq**를 확인합니다. 이 예시에서는 1.013 kHz로, 약 1 kHz입니다.

![Get Symbol Rate - With one symbol: 찾을 수 있는 가장 짧은 심볼 하나만 선택한 다음 "Selection freq"를 확인합니다. 이 경우 1.013 kHz(약 1 kHz)입니다.](<../../images/image (78).png>)

#### With a group of symbols

선택할 심볼 수를 지정하면 SigDigger가 심볼 하나의 주파수를 계산하도록 할 수도 있습니다(심볼을 많이 선택할수록 더 정확할 가능성이 큽니다). 이 예시에서는 심볼 10개를 선택했으며 "Selection freq"는 1.004 Khz입니다.

![선택된 심볼 10개를 사용한 SigDigger 심볼 레이트 계산](<../../images/image (1008).png>)

### Get Bits

AM을 식별하고 **심볼 레이트**를 추정한 후 신호 영역을 선택하고 진폭 샘플링과 판정 레벨을 설정한 다음 **Gardner clock recovery**를 선택하고 **Sample**을 누릅니다.

![AM 샘플링, 심볼 레이트 및 Gardner clock recovery를 설정한 SigDigger Get Bits 패널](<../../images/image (965).png>)

- **Sync to selection intervals**는 이전에 심볼 레이트를 구하기 위해 구간을 선택했다면 해당 심볼 레이트를 사용한다는 뜻입니다.
- **Manual**은 지정한 심볼 레이트를 사용한다는 뜻입니다.
- **Fixed interval selection**에서는 선택할 구간 수를 지정하고 이를 바탕으로 심볼 레이트를 계산합니다.
- **Gardner clock recovery**는 유용한 기본 설정이지만, 대략적인 심볼 레이트가 필요합니다.

Sample을 누르면 다음 화면이 나타납니다.

![With a group of symbols - Get Bits: Sample을 누르면 다음 화면이 나타납니다](<../../images/image (644).png>)

이제 SigDigger가 정보가 담긴 레벨의 **범위가 어디인지** 인식하도록 하려면 **낮은 레벨**을 클릭한 뒤 가장 높은 레벨까지 클릭한 상태를 유지해야 합니다.

![낮은 진폭 레벨에서 높은 레벨까지 선택하는 SigDigger 레벨 범위 선택](<../../images/image (439).png>)

예를 들어 진폭 레벨이 **네 개**라면 **Bits per symbol을 2**로 설정하고 가장 낮은 레벨부터 가장 높은 레벨까지 선택해야 합니다.

마지막으로 **Zoom**을 **높이고** **Row size를 변경**하면 비트를 확인할 수 있습니다(전체를 선택하고 복사하면 모든 비트를 가져올 수 있습니다).

![With a group of symbols - Get Bits: 마지막으로 Zoom을 높이고 Row size를 변경하면 비트를 확인할 수 있습니다(전체를 선택하고 복사하면 모든 비트를 가져올 수 있습니다)](<../../images/image (276).png>)

신호가 심볼당 1비트보다 많은 비트(예: 2비트)를 담고 있으면 SigDigger는 어떤 심볼이 00, 01, 10, 11인지 알 수 없습니다. 따라서 각 심볼을 서로 다른 **회색조**로 표시합니다(비트를 복사하면 **0부터 3까지의 숫자**가 사용되므로 직접 처리해야 합니다).

**Manchester**와 같은 라인 인코딩에서는 유효한 전환 쌍(`01` 또는 `10`)을 사용 중인 프로토콜의 규약에 따라 데이터 비트로 변환합니다.

## FM Example

{{#file}}
sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### Uncovering FM

#### Checking the frequencies and waveform

FM으로 정보를 변조해 전송하는 신호의 예시입니다.

![Uncovering FM - Checking the frequencies and waveform: FM으로 정보를 변조해 전송하는 신호의 예시](<../../images/image (725).png>)

스펙트럼에서는 **두 주파수**가 명확히 보이지만 시간 영역 파형에서는 구분하기 어려울 수 있습니다.

![시간 영역 파형에서 두 주파수를 직접 구분하기 어려운 SigDigger FM 파형](<../../images/image (717).png>)

캡처가 두 주파수 사이를 중심으로 이루어져 주파수 오프셋이 거의 서로 반대이기 때문에 이런 현상이 나타납니다.

![두 주파수가 대략 서로 반대인 오프셋으로 나타난 SigDigger FM 캡처](<../../images/image (942).png>)

동기화된 주파수가 한 주파수에 다른 주파수보다 **더 가까우면** 서로 다른 두 주파수를 쉽게 확인할 수 있습니다.

![Uncovering FM - Checking the frequencies and waveform: 동기화된 주파수가 한 주파수에 다른 주파수보다 더 가까우면 서로 다른 두 주파수를 쉽게 확인할 수 있습니다](<../../images/image (422).png>)

![Uncovering FM - Checking the frequencies and waveform: 동기화된 주파수가 한 주파수에 다른 주파수보다 더 가까우면 서로 다른 두 주파수를 쉽게 확인할 수 있습니다](<../../images/image (488).png>)

#### Checking the histogram

정보가 있는 신호의 주파수 히스토그램을 확인하면 서로 다른 두 신호를 쉽게 볼 수 있습니다.

![Checking the frequencies and waveform - Checking the histogram: 정보가 있는 신호의 주파수 히스토그램을 확인하면 서로 다른 두 신호를 쉽게 볼 수 있습니다](<../../images/image (871).png>)

이 경우 **Amplitude histogram**을 확인하면 **진폭이 하나만** 나타나므로 **AM일 수 없습니다**(진폭이 많이 나타난다면 채널을 지나면서 신호의 전력이 손실되었기 때문일 수 있습니다).

![진폭 레벨 하나를 보여주는 SigDigger FM 신호 진폭 히스토그램](<../../images/image (817).png>)

위상 히스토그램은 다음과 같습니다(신호가 위상 변조가 아님을 명확히 보여줍니다).

![Checking the frequencies and waveform - Checking the histogram: 위상 히스토그램은 다음과 같습니다(신호가 위상 변조가 아님을 명확히 보여줍니다)](<../../images/image (996).png>)

#### With IQ

IQ에는 주파수를 식별하는 필드가 없습니다(중심까지의 거리는 진폭이고 각도는 위상입니다).\
따라서 FM을 식별하려면 이 그래프에서 기본적으로 **원 하나만 보여야 합니다**.\
또한 주파수 오프셋은 IQ 원을 도는 회전 속도를 바꿉니다. 따라서 SigDigger에서는 회전 속도나 방향의 변화를 FM의 징후로 볼 수 있습니다.

![원 주위의 회전 속도 변화로 FM을 보여주는 SigDigger IQ 그래프](<../../images/image (81).png>)

### Get Symbol Rate

심볼을 전달하는 주파수를 찾았다면 **AM 예시에서 사용한 것과 같은 방법**으로 심볼 레이트를 구할 수 있습니다.

### Get Bits

신호가 **주파수 변조를 사용한다는 사실**과 **심볼 레이트**를 알아냈다면 **AM 예시에서 사용한 것과 같은 방법**으로 비트를 구할 수 있습니다.

## References

- [1] [SigDigger - GNU/Linux 및 macOS용 무료 디지털 신호 분석기](https://github.com/BatchDrake/SigDigger)
{{#include ../../banners/hacktricks-training.md}}
