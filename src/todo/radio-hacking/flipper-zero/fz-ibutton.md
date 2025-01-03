# FZ - iButton

{{#include ../../../banners/hacktricks-training.md}}

## Intro

iButton nedir hakkında daha fazla bilgi için kontrol edin:

{{#ref}}
../ibutton.md
{{#endref}}

## Design

Aşağıdaki resmin **mavi** kısmı, Flipper'ın **okuyabilmesi için gerçek iButton'ı** nasıl **yerleştirmeniz gerektiğini** gösterir. **Yeşil** kısım ise Flipper Zero'nun **iButton'ı doğru bir şekilde taklit etmek için okuyucuya nasıl** **dokunması gerektiğini** gösterir.

<figure><img src="../../../images/image (565).png" alt=""><figcaption></figcaption></figure>

## Actions

### Read

Okuma Modunda Flipper, iButton anahtarının dokunmasını bekliyor ve üç tür anahtarı sindirebiliyor: **Dallas, Cyfral ve Metakom**. Flipper, anahtarın türünü **kendisi belirleyecektir**. Anahtar protokolünün adı, ID numarasının üzerinde ekranda görüntülenecektir.

### Add manually

**Manuel olarak** aşağıdaki türde bir iButton eklemek mümkündür: **Dallas, Cyfral ve Metakom**

### **Emulate**

Kaydedilmiş iButton'ları (okunan veya manuel olarak eklenen) **taklit etmek** mümkündür.

> [!NOTE]
> Flipper Zero'nun beklenen temaslarının okuyucuya dokunmasını sağlayamazsanız, **harici GPIO'yu kullanabilirsiniz:**

<figure><img src="../../../images/image (138).png" alt=""><figcaption></figcaption></figure>

## References

- [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

{{#include ../../../banners/hacktricks-training.md}}
