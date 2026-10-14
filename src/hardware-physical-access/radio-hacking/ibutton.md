# iButton

{{#include ../../banners/hacktricks-training.md}}

## 소개

iButton은 **동전 모양의 금속 용기**에 들어 있는 전자식 식별 키를 가리키는 일반적인 이름입니다. **Dallas Touch** 메모리 또는 접촉식 메모리라고도 합니다. 흔히 “자기식” 키라고 잘못 불리지만, 내부에는 **자석이 전혀 없습니다**. 실제로는 디지털 프로토콜로 작동하는 완전한 **마이크로칩**이 내장되어 있습니다.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (915).png" alt=""><figcaption></figcaption></figure>

### iButton이란? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

iButton이라는 이름은 내구성 있는 동전 모양의 패키지와 접점 배치를 가리킵니다. 플라스틱 열쇠고리, 반지, 펜던트 형태의 홀더가 있습니다.

<figure><img src="../../images/image (1078).png" alt=""><figcaption></figcaption></figure>

두 접점이 리더기에 닿으면 장치에 전원이 공급되고 데이터가 교환됩니다. 오목한 접점 구조 때문에 바깥쪽 접지 접점이 닿지 않는 경우, 키를 리더기 벽면에 기울여 대면 접촉이 복원될 수 있습니다.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (290).png" alt=""><figcaption></figcaption></figure>

### **1-Wire 프로토콜** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Dallas/Maxim 키는 1-Wire 프로토콜을 사용합니다. 하나의 데이터 접점으로 양방향 통신을 수행하며 기생 전원을 공급할 수도 있고, 금속 케이스가 리턴 접점 역할을 합니다. 컨트롤러가 트랜잭션을 시작하면 장치가 응답합니다.<sup>[[2]](#references)</sup>

키(Slave)가 인터콤(Master)에 닿으면 인터콤에서 전원을 공급받아 키 내부의 칩이 켜지고 키가 초기화됩니다. 그다음 인터콤은 키 ID를 요청합니다. 이어서 이 과정을 더 자세히 살펴보겠습니다.

Flipper는 키를 읽을 때 컨트롤러로, 저장된 식별자를 리더기에 제시할 때 에뮬레이트된 장치로 작동할 수 있습니다.<sup>[[1]](#references)</sup>

### Dallas, Cyfral 및 Metakom 키

이 키의 작동 방식은 [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/) 페이지를 참고하세요.<sup>[[1]](#references)</sup>

### 공격

iButton은 Flipper Zero로 공격할 수 있습니다:


{{#ref}}
flipper-zero/fz-ibutton.md
{{#endref}}

## References

- [1] [Flipper Zero로 iButton 다루기](https://blog.flipperzero.one/taming-ibutton/)
- [2] [Analog Devices — 소프트웨어를 통한 1-Wire 통신](https://www.analog.com/en/resources/technical-articles/1wire-communication-through-software.html)
{{#include ../../banners/hacktricks-training.md}}
