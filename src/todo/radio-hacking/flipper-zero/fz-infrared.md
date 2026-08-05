# FZ - 적외선

{{#include ../../../banners/hacktricks-training.md}}

## 소개 <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Infrared의 작동 방식에 대한 자세한 내용은 다음을 확인하세요:


{{#ref}}
../infrared.md
{{#endref}}

## Flipper Zero의 IR Signal Receiver <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper는 디지털 IR signal receiver TSOP를 사용하며, **IR 리모컨의 신호를 가로챌 수 있습니다**. Xiaomi와 같이 IR port가 있는 **스마트폰**도 있지만, **대부분은 신호를 전송하기만 할 수 있고** 신호를 **수신할 수 없다는 점**을 기억해야 합니다.<sup>[[1]](#references)</sup>

Flipper의 infrared **receiver는 상당히 민감합니다**. 리모컨과 TV **사이 어딘가에 있는 상태에서도** 신호를 **잡을 수 있습니다**. 리모컨을 Flipper의 IR port에 직접 향하게 할 필요는 없습니다. 이는 누군가 TV 근처에 서서 채널을 변경하고 있고, 여러분과 Flipper는 어느 정도 떨어져 있을 때 유용합니다.

Infrared 신호의 **decoding이** **software** 측에서 수행되므로, Flipper Zero는 잠재적으로 **모든 IR 리모컨 code를 수신하고 전송할 수 있습니다**. 인식할 수 없는 **unknown** protocol의 경우, 수신한 raw signal을 정확히 **기록하고 재생합니다**.<sup>[[1]](#references)</sup>

## 작업

### Universal Remotes

Flipper Zero는 **모든 TV, 에어컨 또는 media center를 제어하는 universal remote로 사용할 수 있습니다**. 이 mode에서 Flipper는 **SD card의 dictionary에 따라** 지원되는 모든 제조업체의 **known code를** **bruteforce합니다**. 식당 TV를 끄기 위해 특정 리모컨을 선택할 필요가 없습니다.<sup>[[1]](#references)</sup>

Universal Remote mode에서 power button을 누르기만 하면, Flipper는 알고 있는 모든 TV의 **"Power Off" command를 순차적으로 전송합니다**: Sony, Samsung, Panasonic... 등. TV가 해당 신호를 수신하면 반응하여 꺼집니다.

이러한 brute-force에는 시간이 걸립니다. dictionary가 클수록 완료하는 데 더 오래 걸립니다. TV가 정확히 어떤 신호를 인식했는지는 TV에서 feedback이 제공되지 않으므로 확인할 수 없습니다.

### 새 리모컨 학습

Flipper Zero로 **infrared signal을 capture할 수 있습니다**. **database에서 signal을 찾으면** Flipper는 자동으로 **어떤 device인지 인식하고** 상호작용할 수 있게 합니다.\
찾지 못한 경우 Flipper는 **signal을 저장하고** **replay할 수 있게 합니다**.<sup>[[1]](#references)</sup>

## References

- [1] [Taking over TVs with Flipper Zero Infrared Port](https://blog.flipperzero.one/infrared/)

{{#include ../../../banners/hacktricks-training.md}}
