# iButton

{{#include ../../banners/hacktricks-training.md}}

## 소개

iButton은 **동전 모양의 금속 컨테이너**에 내장된 전자 식별 키를 가리키는 일반적인 명칭입니다. Dallas Touch Memory 또는 contact memory라고도 합니다. 흔히 “magnetic” 키라고 잘못 부르지만, 실제로는 **자기적인 요소가 전혀 없습니다**. 사실 내부에는 디지털 프로토콜로 작동하는 완전한 **microchip**이 들어 있습니다.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (915).png" alt=""><figcaption></figcaption></figure>

### iButton이란? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

일반적으로 iButton은 키와 reader의 물리적 형태, 즉 두 개의 contact가 있는 둥근 동전 모양을 의미합니다. 이를 둘러싸는 프레임은 구멍이 있는 가장 일반적인 plastic holder부터 ring, pendant 등까지 매우 다양합니다.

<figure><img src="../../images/image (1078).png" alt=""><figcaption></figcaption></figure>

키가 reader에 닿으면 **contact가 서로 접촉**하고, 키에 전원이 공급되어 ID를 **전송**합니다. intercom의 **contact PSD가 적절한 크기보다 큰** 경우 키가 즉시 **read되지 않을** 수 있습니다. 이 경우 키와 reader의 외곽선이 서로 접촉하지 못합니다. 그렇다면 reader의 벽 중 하나에 키를 눌러야 합니다.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (290).png" alt=""><figcaption></figcaption></figure>

### **1-Wire protocol** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Dallas 키는 1-wire protocol을 사용해 데이터를 교환합니다. 양방향, 즉 master에서 slave로, 그리고 그 반대 방향으로 데이터를 전송하는 contact가 하나뿐입니다 (!!). 1-wire protocol은 Master-Slave 모델에 따라 작동합니다. 이 topology에서는 항상 Master가 communication을 시작하고 Slave가 지시를 따릅니다.

키(Slave)가 intercom(Master)에 접촉하면 intercom에서 공급되는 전원으로 키 내부의 chip이 켜지고 키가 초기화됩니다. 그 다음 intercom은 키 ID를 요청합니다. 이제 이 과정을 더 자세히 살펴보겠습니다.

Flipper는 Master mode와 Slave mode 모두에서 작동할 수 있습니다. 키 reading mode에서 Flipper는 reader, 즉 Master로 작동합니다. 키 emulation mode에서는 Flipper가 키 역할을 하므로 Slave mode에 있습니다.<sup>[[1]](#references)</sup>

### Dallas, Cyfral & Metakom keys

이러한 키의 작동 방식에 대한 정보는 [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/) 페이지를 참고하세요.<sup>[[1]](#references)</sup>

### Attacks

iButton은 Flipper Zero를 사용해 attack할 수 있습니다:


{{#ref}}
flipper-zero/fz-ibutton.md
{{#endref}}

## References

- [1] [Taming iButton with Flipper Zero](https://blog.flipperzero.one/taming-ibutton/)

{{#include ../../banners/hacktricks-training.md}}
