# FZ - Infrared

{{#include ../../../banners/hacktricks-training.md}}

## 소개 <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Infrared의 작동 방식에 대한 자세한 정보는 다음을 확인하세요:


{{#ref}}
../infrared.md
{{#endref}}

## Flipper Zero의 IR Signal Receiver <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper Zero는 일반적인 IR 리모컨의 신호를 캡처하기 위해 복조 IR receiver를 사용합니다. 특정 Xiaomi 모델을 포함한 일부 휴대폰에는 IR transmitter가 있지만, 대부분의 휴대폰은 리모컨 신호를 수신하고 디코딩할 수 없습니다.<sup>[[1]](#references)</sup>

Flipper의 infrared **receiver는 매우 민감합니다**. 리모컨과 TV **사이 어딘가에** 있는 상태에서도 신호를 **잡을 수 있습니다**. 리모컨을 Flipper의 IR 포트에 직접 조준할 필요는 없습니다. 이는 누군가 TV 근처에 서서 채널을 변경하고 있을 때, 사용자와 Flipper가 모두 어느 정도 떨어져 있어도 유용합니다.

Protocol decoding은 software에서 수행됩니다. 인식된 protocol은 decoded command로 저장할 수 있으며, 지원되지 않는 protocol은 hardware의 carrier-frequency 및 timing 제한 내에서 raw timing data로 캡처하고 replay할 수 있습니다.<sup>[[1]](#references)</sup>

## 작업

### Universal Remotes

Flipper Zero의 universal-remote mode는 infrared database에 있는 알려진 command를 지원되는 TV, audio equipment, projector 및 air conditioner에 대해 순차적으로 시도합니다. 모든 device를 제어할 수 있는 것은 아니며, 자신이 소유하거나 테스트 권한을 받은 equipment에서만 사용해야 합니다.<sup>[[1]](#references)</sup>

Universal Remote mode에서 power button을 누르기만 하면 Flipper가 알고 있는 모든 TV의 **"Power Off"** command를 **순차적으로 전송**합니다: Sony, Samsung, Panasonic... 등입니다. TV가 해당 신호를 수신하면 반응하여 꺼집니다.

이러한 brute-force에는 시간이 걸립니다. dictionary가 클수록 완료하는 데 더 오래 걸립니다. TV에서 feedback을 제공하지 않으므로 TV가 정확히 어떤 signal을 인식했는지는 알아낼 수 없습니다.

### Learn New Remote

Flipper Zero는 **infrared signal을 캡처**할 수 있습니다. protocol과 command를 인식하면 decoded representation을 저장하고, 그렇지 않으면 나중에 replay할 수 있도록 raw timing data를 저장할 수 있습니다.<sup>[[1]](#references)</sup>

## References

- [1] [Flipper Zero Infrared Port로 TV 장악하기](https://blog.flipperzero.one/infrared/)
{{#include ../../../banners/hacktricks-training.md}}
