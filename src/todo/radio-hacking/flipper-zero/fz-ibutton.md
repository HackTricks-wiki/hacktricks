# FZ - iButton

{{#include ../../../banners/hacktricks-training.md}}

## Intro

iButton에 대한 더 많은 정보는 다음을 확인하세요:

{{#ref}}
../ibutton.md
{{#endref}}

## Design

다음 이미지의 **파란색** 부분은 Flipper가 **읽을 수 있도록 실제 iButton을** **놓아야 하는 방법**입니다. **녹색** 부분은 Flipper zero로 **iButton을 올바르게 에뮬레이트하기 위해 리더에** **접촉해야 하는 방법**입니다.

<figure><img src="../../../images/image (565).png" alt=""><figcaption></figcaption></figure>

## Actions

### Read

읽기 모드에서 Flipper는 iButton 키가 접촉하기를 기다리며, **Dallas, Cyfral, Metakom**의 세 가지 유형의 키를 소화할 수 있습니다. Flipper는 **키의 유형을 스스로 파악합니다**. 키 프로토콜의 이름은 ID 번호 위의 화면에 표시됩니다.

### Add manually

**Dallas, Cyfral, Metakom** 유형의 iButton을 **수동으로 추가하는** 것이 가능합니다.

### **Emulate**

저장된 iButton(읽기 또는 수동 추가된)을 **에뮬레이트하는** 것이 가능합니다.

> [!NOTE]
> Flipper Zero의 예상 접촉이 리더에 닿지 않는 경우 **외부 GPIO를 사용할 수 있습니다:**

<figure><img src="../../../images/image (138).png" alt=""><figcaption></figcaption></figure>

## References

- [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

{{#include ../../../banners/hacktricks-training.md}}
