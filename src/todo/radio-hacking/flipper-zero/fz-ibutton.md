# FZ - iButton

{{#include ../../../banners/hacktricks-training.md}}

## Giriş

iButton hakkında daha fazla bilgi için bkz.:


{{#ref}}
../ibutton.md
{{#endref}}

## Tasarım

Aşağıdaki görseldeki **mavi** bölüm, Flipper'ın **okuyabilmesi** için **gerçek iButton'ı** yerleştirmeniz gereken yerdir. **Yeşil** bölüm ise bir iButton'ı **doğru şekilde emüle etmek** için Flipper Zero ile okuyucuya **dokunmanız** gereken yerdir.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (565).png" alt=""><figcaption></figcaption></figure>

## Eylemler

### Oku

Read Mode'da Flipper, iButton anahtarının dokundurulmasını bekler ve üç tür anahtardan herhangi birini okuyabilir: **Dallas, Cyfral ve Metakom**. Flipper, anahtarın türünü **kendisi belirler**. Anahtar protokolünün adı, ID numarasının üzerinde ekranda görüntülenir.<sup>[[1]](#references)</sup>

### Manuel olarak ekle

Şu türlerde bir iButton'ı **manuel olarak eklemek** mümkündür: **Dallas, Cyfral ve Metakom**

### **Emüle et**

Kaydedilmiş iButton'ları (okunmuş veya manuel olarak eklenmiş) **emüle etmek** mümkündür.

> [!TIP]
> Flipper Zero'nun beklenen temas noktalarını okuyucuya dokunduramıyorsanız **harici GPIO'yu kullanabilirsiniz:**

<figure><img src="../../../images/image (138).png" alt=""><figcaption></figcaption></figure>

## Referanslar

- [1] [Taming iButton Keys with Flipper Zero](https://blog.flipperzero.one/taming-ibutton/)

{{#include ../../../banners/hacktricks-training.md}}
