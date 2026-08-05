# iButton

{{#include ../../banners/hacktricks-training.md}}

## 소개

iButton은 **동전 모양의 금속 케이스**에 들어 있는 전자식 식별 키를 일컫는 일반적인 이름입니다. Dallas Touch Memory 또는 contact memory라고도 합니다. 흔히 “자기식” 키라고 잘못 부르지만, 내부에는 **자성을 띠는 요소가 전혀 없습니다**. 실제로는 디지털 프로토콜로 작동하는 완전한 **microchip**이 내부에 숨겨져 있습니다.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (915).png" alt=""><figcaption></figcaption></figure>

### iButton이란? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

일반적으로 iButton은 키와 reader의 물리적 형태를 의미하며, 두 개의 접점이 있는 둥근 동전 모양입니다. 이를 둘러싸는 프레임은 구멍이 있는 가장 일반적인 플라스틱 홀더부터 링, 펜던트 등까지 다양한 형태가 있습니다.

<figure><img src="../../images/image (1078).png" alt=""><figcaption></figcaption></figure>

키가 reader에 닿으면 **접점이 서로 맞닿고**, 키에 전원이 공급되어 자신의 ID를 **전송**합니다. 때로는 intercom의 **접점 PSD가 필요 이상으로 크기** 때문에 키가 즉시 **읽히지 않을** 수 있습니다. 이 경우 키와 reader의 외곽선이 서로 맞닿지 않을 수 있습니다. 그렇다면 reader의 벽면 중 한쪽에 키를 밀어 붙여야 합니다.

<figure><img src="../../images/image (290).png" alt=""><figcaption></figcaption></figure>

### **1-Wire protocol** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Dallas 키는 1-Wire protocol을 사용해 데이터를 교환합니다. 양방향, 즉 master에서 slave로, 또는 그 반대로 데이터를 전송할 때 데이터 전송에 접점 하나만 사용합니다(!!). 1-Wire protocol은 Master-Slave 모델에 따라 작동합니다. 이 토폴로지에서 Master는 항상 통신을 시작하고 Slave는 그 지시를 따릅니다.

키(Slave)가 intercom(Master)에 접촉하면 intercom에서 공급되는 전원으로 키 내부의 칩이 켜지고 키가 초기화됩니다. 그 후 intercom은 키에 ID를 요청합니다. 이제 이 과정을 더 자세히 살펴보겠습니다.

Flipper는 Master 및 Slave 모드 모두에서 작동할 수 있습니다. 키 reading 모드에서 Flipper는 reader로 동작하므로 Master로 작동합니다. 키 emulation 모드에서는 Flipper가 키인 것처럼 동작하므로 Slave 모드입니다.

### Dallas, Cyfral 및 Metakom 키

이러한 키의 작동 방식에 대한 정보는 다음 페이지를 확인하세요: [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)<sup>[[1]](#references)</sup>

### 공격

iButton은 Flipper Zero를 사용해 공격할 수 있습니다:


{{#ref}}
flipper-zero/fz-ibutton.md
{{#endref}}

## 참고 자료

- [1] [Taming iButton](https://blog.flipperzero.one/taming-ibutton/)

{{#include ../../banners/hacktricks-training.md}}
