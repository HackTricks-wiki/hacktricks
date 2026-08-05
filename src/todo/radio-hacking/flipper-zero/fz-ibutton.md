# FZ - iButton

{{#include ../../../banners/hacktricks-training.md}}

## 소개

iButton에 대한 자세한 정보는 다음을 확인하세요:


{{#ref}}
../ibutton.md
{{#endref}}

## 설계

다음 이미지의 **파란색** 부분은 Flipper가 **읽을 수 있도록 실제 iButton을 배치해야 하는** 위치입니다. **녹색** 부분은 iButton을 **올바르게 에뮬레이트하기 위해** Flipper Zero로 리더기에 **접촉해야 하는** 위치입니다.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (565).png" alt=""><figcaption></figcaption></figure>

## 작업

### 읽기

Read Mode에서 Flipper는 iButton 키가 접촉하기를 기다리며, **Dallas, Cyfral, Metakom** 세 가지 유형의 키를 모두 인식할 수 있습니다. Flipper가 **키 유형을 자동으로 판별합니다**. 키 프로토콜 이름은 ID 번호 위 화면에 표시됩니다.<sup>[[1]](#references)</sup>

### 수동으로 추가

**Dallas, Cyfral, Metakom** 유형의 iButton을 **수동으로 추가할 수 있습니다.**

### **에뮬레이트**

저장된 iButton(읽었거나 수동으로 추가한 iButton)을 **에뮬레이트할 수 있습니다.**

> [!TIP]
> Flipper Zero의 접점을 리더기에 제대로 맞출 수 없다면 **외부 GPIO를 사용할 수 있습니다:**

<figure><img src="../../../images/image (138).png" alt=""><figcaption></figcaption></figure>

## 참고 자료

- [1] [Taming iButton Keys with Flipper Zero](https://blog.flipperzero.one/taming-ibutton/)

{{#include ../../../banners/hacktricks-training.md}}
