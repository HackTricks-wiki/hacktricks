# FZ - iButton

{{#include ../../../banners/hacktricks-training.md}}

## 소개

iButton 기술의 배경은 다음을 참조하세요.

{{#ref}}
../ibutton.md
{{#endref}}

## 설계

다음 이미지에서 **파란색** 영역은 물리적 iButton을 Flipper Zero의 접점에 대고 읽는 방법을 보여줍니다. **초록색** 영역은 에뮬레이션 중 리더기에 닿아야 하는 접점을 보여줍니다.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (565).png" alt=""><figcaption></figcaption></figure>

## 동작

### 읽기

읽기 모드에서 Flipper Zero는 접점에 키가 닿을 때까지 대기하고, 프로토콜을 감지한 다음 키 ID 위에 프로토콜을 표시합니다. 내장 애플리케이션은 Dallas, Cyfral, Metakom 출입 통제 키를 지원합니다.<sup>[[2]](#references)</sup>

### 수동으로 추가

Dallas, Cyfral, Metakom 프로토콜의 키 데이터를 수동으로 입력할 수 있습니다.<sup>[[2]](#references)</sup>

### 에뮬레이션

물리적 키에서 읽었거나 수동으로 입력한 키를 저장한 뒤 에뮬레이션할 수 있습니다.<sup>[[2]](#references)</sup>

> [!TIP]
> 내장 접점이 리더기에 닿지 않는 경우 GPIO 핀을 통해 데이터 접점과 접지를 연결하세요.<sup>[[2]](#references)</sup>

<figure><img src="../../../images/image (138).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [Flipper Zero로 iButton 키 다루기](https://blog.flipperzero.one/taming-ibutton/)
- [2] [Flipper Zero 문서 - iButton 키 읽기](https://docs.flipper.net/zero/ibutton/read)
{{#include ../../../banners/hacktricks-training.md}}

