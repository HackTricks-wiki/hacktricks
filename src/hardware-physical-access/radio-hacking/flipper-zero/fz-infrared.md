# FZ - Infrared

{{#include ../../../banners/hacktricks-training.md}}

## 소개 <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Infrared의 작동 방식에 관한 자세한 내용은 다음을 확인하세요:


{{#ref}}
../infrared.md
{{#endref}}

## Flipper Zero의 IR 신호 수신기 <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper Zero는 일반적인 IR 리모컨의 신호를 캡처하기 위해 복조형 IR 수신기를 사용합니다. 일부 Xiaomi 모델을 포함한 몇몇 휴대전화에는 IR 송신기가 있지만, 대부분의 휴대전화는 리모컨 신호를 수신하고 디코딩할 수 없습니다.<sup>[[1]](#references)</sup>

Flipper의 적외선 **수신기는 매우 민감합니다**. 리모컨과 TV 사이의 **중간 어딘가에** 있어도 **신호를 포착할 수 있습니다**. 리모컨을 Flipper의 IR 포트에 직접 겨눌 필요는 없습니다. 누군가 TV 근처에 서서 채널을 바꾸고, 당신과 Flipper는 모두 멀리 떨어져 있을 때 유용합니다.

프로토콜 디코딩은 소프트웨어에서 이루어집니다. 인식된 프로토콜은 디코딩된 명령으로 저장할 수 있으며, 지원하지 않는 프로토콜은 하드웨어의 반송파 주파수 및 타이밍 한도 내에서 원시 타이밍 데이터로 캡처하고 재생할 수 있습니다.<sup>[[1]](#references)</sup>

## 동작

### 범용 리모컨

Flipper Zero의 범용 리모컨 모드는 적외선 데이터베이스에 포함된 명령을 차례로 보내며, 지원 대상은 TV, 오디오 장비, 프로젝터 및 에어컨입니다. 모든 기기를 제어할 수 있는 것은 아니며, 소유하고 있거나 테스트 권한이 있는 장비에만 사용해야 합니다.<sup>[[1]](#references)</sup>

범용 리모컨 모드에서 전원 버튼을 누르기만 하면 Flipper가 알고 있는 모든 TV(Sony, Samsung, Panasonic 등)에 **차례대로 "전원 끄기"** 명령을 보냅니다. TV가 신호를 받으면 반응하여 꺼집니다.

이런 brute-force 방식은 시간이 걸립니다. 사전이 클수록 완료하는 데 더 오래 걸립니다. TV에서 피드백을 보내지 않기 때문에 TV가 정확히 어떤 신호를 인식했는지 확인할 수 없습니다.

### 새 리모컨 학습

Flipper Zero는 **적외선 신호를 캡처할 수 있습니다**. 프로토콜과 명령을 인식하면 디코딩된 표현을 저장하고, 그렇지 않으면 나중에 재생할 수 있도록 원시 타이밍 데이터를 저장할 수 있습니다.<sup>[[1]](#references)</sup>

## References

- [1] [Flipper Zero 적외선 포트로 TV 제어하기](https://blog.flipperzero.one/infrared/)
{{#include ../../../banners/hacktricks-training.md}}
