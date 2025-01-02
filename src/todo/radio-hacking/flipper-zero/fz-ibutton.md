# FZ - iButton

{{#include ../../../banners/hacktricks-training.md}}

## Giriş

iButton nedir hakkında daha fazla bilgi için kontrol edin:

{{#ref}}
../ibutton.md
{{#endref}}

## Tasarım

Aşağıdaki resmin **mavi** kısmı, Flipper'ın **okuyabilmesi için gerçek iButton'ı** nasıl **yerleştirmeniz gerektiğini** gösterir. **Yeşil** kısım ise Flipper Zero ile okuyucuya **doğru bir şekilde iButton'ı taklit etmek için** nasıl **dokunmanız gerektiğini** gösterir.

<figure><img src="../../../images/image (565).png" alt=""><figcaption></figcaption></figure>

## Eylemler

### Oku

Okuma Modunda Flipper, iButton anahtarının dokunmasını bekliyor ve üç tür anahtardan herhangi birini sindirebiliyor: **Dallas, Cyfral ve Metakom**. Flipper, anahtarın türünü **kendisi belirleyecektir**. Anahtar protokolünün adı, ID numarasının üzerinde ekranda görüntülenecektir.

### Manuel ekle

**Dallas, Cyfral ve Metakom** türünde bir iButton'ı **manuel olarak eklemek** mümkündür.

### **Taklit et**

Kaydedilmiş iButton'ları (okunan veya manuel olarak eklenen) **taklit etmek** mümkündür.

> [!NOTE]
> Flipper Zero'nun beklenen temaslarının okuyucuya dokunmasını sağlayamazsanız, **harici GPIO'yu kullanabilirsiniz:**

<figure><img src="../../../images/image (138).png" alt=""><figcaption></figcaption></figure>

## Referanslar

- [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

{{#include ../../../banners/hacktricks-training.md}}
