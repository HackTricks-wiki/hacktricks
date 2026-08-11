# iButton

{{#include ../../banners/hacktricks-training.md}}

## 소개

iButton은 **동전 모양의 금속 케이스**에 내장된 전자 식별 키를 가리키는 일반적인 이름입니다. Dallas Touch Memory 또는 contact memory라고도 합니다. 흔히 “magnetic” 키라고 잘못 불리지만, 실제로는 **자성이 전혀 없습니다**. 사실 내부에는 디지털 protocol로 작동하는 완전한 **microchip**이 들어 있습니다.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (915).png" alt=""><figcaption></figcaption></figure>

### iButton이란? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

iButton이라는 이름은 내구성이 뛰어난 동전 모양의 패키지와 접점 배열을 설명합니다. 홀더에는 플라스틱 fob, ring, pendant 등이 있습니다.

<figure><img src="../../images/image (1078).png" alt=""><figcaption></figcaption></figure>

두 접점이 reader에 닿으면 device가 전원을 공급받고 data를 교환합니다. 움푹 들어간 접점 구조로 인해 바깥쪽 ground 접점이 닿지 않는 경우, key를 reader 벽에 기울이면 접촉을 복구할 수 있습니다.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (290).png" alt=""><figcaption></figcaption></figure>

### **1-Wire protocol** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Dallas/Maxim keys는 1-Wire protocol을 사용합니다. 하나의 data 접점이 양방향 traffic을 전달하며 parasitic power를 제공할 수도 있고, metal can이 return 접점 역할을 합니다. controller가 transaction을 시작하면 device가 응답합니다.<sup>[[2]](#references)</sup>

key (Slave)가 intercom (Master)에 접촉하면 intercom에서 전원을 공급받아 key 내부의 chip이 켜지고 key가 초기화됩니다. 그다음 intercom은 key ID를 요청합니다. 이제 이 과정을 더 자세히 살펴보겠습니다.

Flipper는 key를 읽을 때 controller로 작동할 수 있으며, 저장된 identifier를 reader에 제시할 때 emulated device로 작동할 수 있습니다.<sup>[[1]](#references)</sup>

### Dallas, Cyfral & Metakom keys

이러한 keys의 작동 방식에 대한 정보는 다음 page를 참조하세요: [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)<sup>[[1]](#references)</sup>

### 공격

iButtons는 Flipper Zero를 사용해 공격할 수 있습니다:


{{#ref}}
flipper-zero/fz-ibutton.md
{{#endref}}

## References

- [1] [Flipper Zero로 iButton 다루기](https://blog.flipperzero.one/taming-ibutton/)
- [2] [Analog Devices — software를 통한 1-Wire communication](https://www.analog.com/en/resources/technical-articles/1wire-communication-through-software.html)
{{#include ../../banners/hacktricks-training.md}}
