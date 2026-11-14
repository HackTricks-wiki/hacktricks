# Node.js/V8 Cached Bytecodeの静的難読化解除

{{#include ../../banners/hacktricks-training.md}}

V8 cached dataは**バージョンに依存する、情報が失われる表現**であり、JavaScriptソースでも従来型のネイティブ実行ファイルでもありません。そのため、有効な静的解析の手順は、まず外側のパッキングを解除し、対応するV8ビルドでキャッシュを逆アセンブルして、中間的な疑似コードモデルに変換したうえで、サンプルを実行せずに依存関係を考慮した変換を適用することです。[View8](https://github.com/suleram/View8)と[jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator)は、`javascript-obfuscator`で保護されたNode.jsペイロードに対して、この手法を実装しています。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## キャッシュの取得と逆アセンブル

すべての`.jsc`ファイルが同じラッパーを使っていると決めつけず、まずプリロードスクリプトやランチャーを調べます。たとえば、`node.exe -r preflight.js app.jsc`のようなランチャーは、メインモジュールの前に`preflight.js`を実行します。解析対象のファミリーでは、プリロードがBrotliレイヤーを解除していました。展開後、バンドルされたランタイムから正確なNode.js/V8の世代を特定します。あるV8バージョンで生成されたキャッシュは、別のバージョンでは拒否されたり、誤ってデコードされたりすることがあります。そのため、該当するV8タグ用の`v8dasm`をビルドまたは入手し、必要なView8および文字列表示用のパッチを適用してください。<sup>[[1]](#references)[[2]](#references)</sup>

このツールキットの、対象を実行しないワークフローは次のとおりです。<sup>[[2]](#references)</sup>

```bash
brotli -d app.jsc -o app.decompressed.jsc
/path/to/matching-v8dasm app.decompressed.jsc > app.jsc.disasm.txt
mkdir -p decompiled deobfuscated
python3 View8/view8.py --input_format disassembled \
  --inp app.jsc.disasm.txt --normalize \
  --out decompiled/app.dec.txt \
  --export_format decompiled serialized
python3 deobf_all.py --inp decompiled/app.dec.pkl \
  --out deobfuscated/app.deobf.txt \
  --export_format decompiled serialized
```

`--normalize` は、生成された関数に実行ごとに変わらない識別子を付与します。テキスト出力は検査用です。シリアライズされたオブジェクトグラフを使うと、独立したパスで関数、宣言元、スコープ、メタデータの関係を保持できます。これは**再構築された JavaScript でも、実行可能な JavaScript でもありません**。<sup>[[1]](#references)[[2]](#references)</sup>

### V8 をビルドせずにキャッシュをトリアージする

raw または Brotli でラップされたキャッシュの場合、`jscd` は Node.js にサンプルを読み込ませずに、ヘッダーを識別し、定数と関数を列挙できます。まずこれを使って、バージョンテーブルがファイルに対応しているかを確認し、より専門的な View8 の難読化解除パスに進む前に、優先して調べる関数を絞り込みます。<sup>[[4]](#references)</sup>

バージョンハッシュは識別の手掛かりであり、単体の逆アセンブラが生成元と同じフラグや読み取り専用スナップショットを使っている証拠ではありません。<sup>[[4]](#references)[[5]](#references)</sup>

```bash
jscd info app.jsc
jscd strings app.jsc > app.strings.txt
jscd functions app.jsc > app.functions.txt
jscd disasm app.jsc > app.jsc.disasm.txt
```

`jscd disasm` は View8 互換のリストを出力するため、キャッシュが対応していれば、上記の View8 コマンドでは `v8dasm` の代わりにその出力を使用できます。関数ツリーとあわせて文字列を調べ、デコーダー呼び出しと有力なエントリポイントを特定してください。`jscd` の近似的な JavaScript 出力を元のソースとして扱わないでください。ツールがバージョンを拒否したり、読み取り専用ヒープのプレースホルダーが残ったりする場合は、推測でプロパティ名を決めるのではなく、対応する V8 ビルドを使うか、同じビルドの名前マップを用意してください。<sup>[[4]](#references)</sup>

Electron アプリケーション内のキャッシュの場合は、まず [ASAR を展開し、main と preload のエントリポイントを調べます](../../desktop-application-security/electron-desktop-apps/)。V8 のバージョン文字列が一致していても、Electron と Node のキャッシュでは、snapshot やポインター圧縮のレイアウトが異なることがあります。<sup>[[4]](#references)</sup>

### View8 の疑似コードを IR として読む

一般的な名前は `func_<name>_0x<address>`、引数は `a0...aN`、仮想レジスターは `r0...rN` で、`ACCU` は V8 のアキュムレーターです。`start` はルートの declarer であり、`Scope[...]`、グローバル、辞書は、ネストした関数によってキャプチャまたは共有される値を表します。すべての式を JavaScript の構文として解析しないでください。たとえば、View8 の `!r6 === "0"` は比較全体の否定（`r6 !== "0"`）を表すため、分岐を再構築するときに重要です。<sup>[[1]](#references)[[3]](#references)</sup>

## 依存関係を考慮した難読化解除

次のパスで必要な入力が明らかになる順序で変換を適用し、出力が安定するまで伝播を繰り返します。実用的な順序は次のとおりです。<sup>[[1]](#references)[[2]](#references)</sup>

1. declarer の階層をたどり、グローバル、レジスター、辞書、`Scope[...]` 参照から値を伝播します。
2. 文字列デコーダーの引数を復元し、暗号化された呼び出しを平文に置き換えます。
3. 隣接する文字列チャンクを結合します。これにより得られるプロパティ名やディスパッチャー順序の文字列が、後続のパスを可能にします。
4. 制御フローのフラット化を解除し、呼び出しプロキシやアトミック操作のラッパーをインライン化して、辞書内の関数参照を解決します。
5. 各文字列、キー、プロキシの解決によって別の間接参照が明らかになる可能性があるため、再度伝播します。
6. 呼び出し箇所を解決した後に限り、識別済みの一度限りの初期化サンクをまとめ、不要なヘルパーを削除します。

### シフトされた RC4 文字列配列をブラックボックスとして復元する

一般的な `javascript-obfuscator` のレイアウトでは、Base64 エンコードされた RC4 チャンクが1つの配列に格納されています。デコーダーのラッパーは数値オフセットと短いキーを渡し、引数の順序が逆になっていることもあります。その後、クロージャースコープでキャプチャされた定数を加算または減算します。ルートデコーダーが強く難読化されている場合は、関数全体を再構築するのではなく、未知の配列インデックスのシフトを実験的に復元します。<sup>[[1]](#references)</sup>

`N` 個のチャンクからなる配列と、同じデコーダーへの複数の呼び出しについては、次のようにします。<sup>[[1]](#references)</sup>

```text
for each observed (numeric_argument, rc4_key):
    candidates = {}
    for shift in 0 .. N-1:
        index = apply_observed_sign(numeric_argument, shift)
        plaintext = RC4(Base64Decode(chunks[index]), rc4_key)
        if plaintext passes encoding/printability checks:
            candidates.add(shift)
root_shift = intersection(candidate_sets)
```

単一の復号結果が印字可能だからといって、シフト値を採用しないでください。誤った暗号文でも、偶然印字可能な結果になることがあります。少なくとも3つの異なる観測結果を使い、すべてで妥当なテキストになるシフト値が一意に見つかった場合にのみ採用してください。次に、wrapper/declarer graphをたどり、各加算または減算を累積し、数値引数が先に来るかどうかを記録します。このメタデータをサンプルごとにキャッシュし、decoderの呼び出しを置き換え、隣接する平文チャンクを連結し、トリアージ用に文字列を個別にエクスポートします。<sup>[[1]](#references)[[2]](#references)</sup>

### アンフラット化してもセマンティクスを維持する

`3|2|1|0|4`のような文字列で駆動されるdispatcher loopでは、順序文字列をデコードし、各状態比較を対応するブロックにマッピングし、View8の否定条件の表記を考慮したうえで、dispatcherの順序でブロックを出力します。ネストされた`continue`は通常のフォールスルーではなく、dispatcherに戻る早期ジャンプを表している場合があります。loopを削除するときは、その`continue`を削除し、囲んでいる`if`の後に元々あった文を、生成した`else`ブランチに移動します。dispatcherを削除するだけでは動作が変わってしまいます。<sup>[[1]](#references)</sup>

### Proxy、演算、遅延thunkをインライン化する

`return a0(a1, a2)`のような転送用helperを正規化してから、その呼び出し箇所を直接呼び出しに置き換えます。減算、除算、比較、メンバーシップテスト、呼び出し用のwrapperも同様に扱います。helperの参照自体が、復号された辞書キーやクロージャ値の背後に格納されていることがあるため、インライン化の前後に文字列と構造の伝播を実行します。<sup>[[1]](#references)</sup>

保存された関数を一度呼び出し、その参照を消去して結果をキャッシュし、以降の呼び出しではそのキャッシュを返すクロージャも認識してください。初期化箇所でこのthunkを畳み込むと、基底にあるdispatcherやcapability functionが明らかになります。ただし、元の実行は新たな呼び出しを毎回行うのではなく、**一度だけ実行してキャッシュする**ものだったと注記してください。<sup>[[1]](#references)</sup>

## 安全性と検証に関する注意事項

- Pythonの`pickle`読み込みはコードを実行する可能性があります。信頼できるView8の実行でローカル生成した`.pkl`ファイルのみを読み込んでください。サンプルから提供されたpickleをデータとして扱ってはいけません。<sup>[[2]](#references)</sup>
- 関数本体が見つからないからといって、ソースにその関数が存在しなかった証拠にはなりません。V8は、遅延関数が初回呼び出しでコンパイルされるまで、メタデータとしてシリアライズすることがあります。静的トリアージでは、そのような関数を未解決として保持してください。<sup>[[6]](#references)</sup>
- パターン駆動の処理は、汎用JavaScript decompilerではありません。未解決の式は保持し、曖昧なdispatcherのバリエーションは、無理に書き換えず手動で調査してください。<sup>[[1]](#references)[[2]](#references)</sup>
- LLMが支援した関数名は、コード内を調べるための手がかりであり、証拠ではありません。利用する場合は依存関係を末端から順に処理し、各ラベルを関数本体、引数、文字列、データフロー、API、副作用と照合して検証してください。<sup>[[1]](#references)[[2]](#references)</sup>



## References

- [1] [JSCealのコンパイル済みV8バイトコードの封印を解く：静的デオブファスケーション](https://research.checkpoint.com/2026/breaking-the-seal-static-deobfuscation-of-jsceals-compiled-v8-bytecode)
- [2] [hasherezade/jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator)
- [3] [suleram/View8](https://github.com/suleram/View8)
- [4] [ejfkdev/jscd](https://github.com/ejfkdev/jscd)
- [5] [V8 SerializedCodeDataヘッダー](https://chromium.googlesource.com/v8/v8/+/main/src/snapshot/code-serializer.h)
- [6] [Node.js vm.Scriptのコードキャッシュ](https://nodejs.org/api/vm.html#scriptcreatecacheddata)
{{#include ../../banners/hacktricks-training.md}}
