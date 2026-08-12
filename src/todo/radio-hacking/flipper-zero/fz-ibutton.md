# FZ - iButton

{{#include ../../../banners/hacktricks-training.md}}

## 소개

iButton 기술에 대한 배경 정보는 다음을 참조하세요.

{{#ref}}
../ibutton.md
{{#endref}}

## 설계

다음 이미지에서 **파란색** 영역은 물리적 iButton을 읽기 위해 Flipper Zero의 접점에 대는 방법을 보여줍니다. **초록색** 영역은 에뮬레이션 중 리더에 닿아야 하는 접점을 보여줍니다.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (565).png" alt=""><figcaption></figcaption></figure>

## 작업

### 읽기

Read 모드에서 Flipper Zero는 키가 접점에 닿을 때까지 기다리고, protocol을 감지한 다음 키 ID 위에 protocol을 표시합니다. 기본 제공 application은 Dallas, Cyfral 및 Metakom access-control key를 지원합니다.<sup>[[2]](#references)</sup>

### 수동으로 추가

Dallas, Cyfral 및 Metakom protocol의 key data를 수동으로 입력할 수 있습니다.<sup>[[2]](#references)</sup>

### 에뮬레이션

물리적 key에서 읽었든 수동으로 입력했든 저장된 key를 에뮬레이션할 수 있습니다.<sup>[[2]](#references)</sup>

> [!TIP]
> 기본 제공 접점이 reader에 닿지 않는 경우 GPIO pin을 통해 data 및 ground 접점을 연결하세요.<sup>[[2]](#references)</sup>

<figure><img src="../../../images/image (138).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [Flipper Zero로 iButton Key 다루기](https://blog.flipperzero.one/taming-ibutton/)
- [2] [Flipper Zero documentation - iButton Key 읽기](https://docs.flipper.net/zero/ibutton/read)
{{#include ../../../banners/hacktricks-training.md}}
