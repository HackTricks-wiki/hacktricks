# FZ - Infrared

{{#include ../../../banners/hacktricks-training.md}}

## Intro <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Infrared가 작동하는 방식에 대한 자세한 정보는 다음을 확인하세요:

{{#ref}}
../infrared.md
{{#endref}}

## IR Signal Receiver in Flipper Zero <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper는 **IR 리모컨의 신호를 가로챌 수 있는** 디지털 IR 신호 수신기 TSOP를 사용합니다. Xiaomi와 같은 **스마트폰** 중 일부는 IR 포트를 가지고 있지만, **대부분은 신호를 전송만 할 수 있고** 수신할 수는 없습니다.

Flipper의 적외선 **수신기는 상당히 민감합니다**. 리모컨과 TV 사이의 **어딘가에 있는 동안에도 신호를 잡을 수 있습니다**. 리모컨을 Flipper의 IR 포트에 직접 겨냥할 필요는 없습니다. 이는 누군가 TV 근처에서 채널을 변경할 때 유용하며, 당신과 Flipper는 일정 거리를 두고 있을 수 있습니다.

**적외선 신호의 디코딩**은 **소프트웨어** 측에서 이루어지므로, Flipper Zero는 **모든 IR 리모컨 코드의 수신 및 전송을 지원할 가능성이 있습니다**. 인식할 수 없는 **알 수 없는** 프로토콜의 경우, Flipper는 수신한 원시 신호를 **기록하고 재생**합니다.

## Actions

### Universal Remotes

Flipper Zero는 **모든 TV, 에어컨 또는 미디어 센터를 제어하는 범용 리모컨으로 사용할 수 있습니다**. 이 모드에서 Flipper는 **SD 카드의 사전**에 따라 모든 지원 제조업체의 **알려진 코드**를 **무작위로 시도합니다**. 레스토랑 TV를 끄기 위해 특정 리모컨을 선택할 필요는 없습니다.

범용 리모컨 모드에서 전원 버튼을 누르기만 하면 Flipper는 **알고 있는 모든 TV의 "전원 끄기"** 명령을 순차적으로 전송합니다: Sony, Samsung, Panasonic... 등. TV가 신호를 수신하면 반응하여 꺼집니다.

이러한 무작위 시도는 시간이 걸립니다. 사전이 클수록 완료하는 데 더 오랜 시간이 걸립니다. TV가 정확히 어떤 신호를 인식했는지 알 수 없으며, TV로부터 피드백이 없기 때문입니다.

### Learn New Remote

Flipper Zero로 **적외선 신호를 캡처하는 것이 가능합니다**. 데이터베이스에서 신호를 **찾으면** Flipper는 자동으로 **이 장치가 무엇인지 알게 되고** 상호작용할 수 있게 해줍니다.\
신호를 찾지 못하면 Flipper는 **신호를 저장하고** **재생할 수 있게 해줍니다**.

## References

- [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)

{{#include ../../../banners/hacktricks-training.md}}
