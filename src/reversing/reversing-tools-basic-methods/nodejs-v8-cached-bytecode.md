# Node.js/V8 Cached Bytecodeの静的デオブfuscation

{{#include ../../banners/hacktricks-training.md}}

V8 cached dataは**バージョン依存の情報損失を伴う表現**であり、JavaScriptソースでも従来型のネイティブ実行ファイルでもありません。そのため、有効な静的ワークフローは、まず外側のパッキングを解除し、対応するV8ビルドでキャッシュを逆アセンブルして、中間的な疑似コードモデルに変換し、サンプルを実行せずに依存関係を考慮した変換を適用する、という流れになります。[View8](https://github.com/suleram/View8)と[jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator)は、`javascript-obfuscator`で保護されたNode.jsペイロードに対して、このアプローチを実装しています。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## キャッシュの取得と逆アセンブル

まず、すべての`.jsc`ファイルに同じラッパーが使われていると決めつけずに、preload/launcherを調べてください。たとえば、`node.exe -r preflight.js app.jsc`のようなlauncherは、メインモジュールの前に`preflight.js`を実行します。解析対象のファミリーでは、preloadがBrotliレイヤーを解除していました。展開後、バンドルされたランタイムから正確なNode.js/V8世代を特定します。あるV8バージョンで生成されたキャッシュは、別のバージョンでは拒否されたり、誤ってデコードされたりする可能性があるため、該当するV8タグ用の`v8dasm`をビルドまたは入手し、必要なView8パッチと文字列出力パッチを適用してください。<sup>[[1]](#references)[[2]](#references)</sup>

このツールキットの非実行ワークフローは次のとおりです。<sup>[[2]](#references)</sup>

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

`--normalize` を使うと、生成された関数に実行ごとに変わらない識別子が付与されます。テキスト出力は調査用です。シリアライズされたオブジェクトグラフを使うと、独立したパスで関数、宣言元、スコープ、メタデータの関連を保持できます。これは **再構築された JavaScript でも、実行可能な JavaScript でもありません**。<sup>[[1]](#references)[[2]](#references)</sup>

### V8をビルドせずにキャッシュをトリアージする

raw または Brotli でラップされたキャッシュに対して、`jscd` は Node.js でサンプルを読み込まずにヘッダーを識別し、定数と関数を列挙できます。まずこれを使って、ファイルが対応するバージョンテーブルに含まれているかを確認し、より特殊な View8 の難読化解除パスを適用する前に、優先して調査する関数を絞り込みます。<sup>[[4]](#references)</sup>

バージョンハッシュは識別の手掛かりであり、単体の逆アセンブラが生成元と同じフラグや読み取り専用スナップショットを使用している証拠ではありません。<sup>[[4]](#references)[[5]](#references)</sup>

```bash
jscd info app.jsc
jscd strings app.jsc > app.strings.txt
jscd functions app.jsc > app.functions.txt
jscd disasm app.jsc > app.jsc.disasm.txt
```

`jscd disasm` は View8 互換のリスティングを出力するため、cache がサポートされていれば、上記の View8 コマンドでは `v8dasm` の代わりにその出力を使用できます。関数ツリーと併せて文字列を調べ、decoder の呼び出しや有力なエントリーポイントを探してください。`jscd` が出力する近似的な JavaScript を元のソースとして扱ってはいけません。ツールがバージョンを拒否する場合や、read-only-heap のプレースホルダーが残る場合は、推測でプロパティ名を補うのではなく、対応する V8 build に切り替えるか、同じ build の name map を指定してください。<sup>[[4]](#references)</sup>

Electron アプリケーション内の cache を調べる場合は、まず [ASAR を展開し、main と preload のエントリーポイントを調べてください](../../network-services-pentesting/pentesting-web/electron-desktop-apps/)。V8 のバージョン文字列が一致していても、Electron と Node の cache では snapshot や pointer-compression のレイアウトが異なる場合があります。<sup>[[4]](#references)</sup>

### View8 の擬似コードを IR として読む

一般的な名前は `func_<name>_0x<address>`、引数は `a0...aN`、仮想レジスタは `r0...rN` で、`ACCU` は V8 の accumulator です。`start` はルートの declarer で、`Scope[...]`、globals、dictionaries は、ネストした関数がキャプチャまたは共有する値を表します。すべての式を JavaScript の構文として解析してはいけません。たとえば、View8 の `!r6 === "0"` は比較全体の否定（`r6 !== "0"`）を表し、分岐を復元する際に重要です。<sup>[[1]](#references)[[3]](#references)</sup>

## 依存関係を考慮した難読化解除

次のパスに必要な入力が明らかになる順序で変換を適用し、出力が安定するまで伝播を繰り返します。実用的な順序は次のとおりです。<sup>[[1]](#references)[[2]](#references)</sup>

1. declarer の階層をたどり、globals、registers、dictionaries、`Scope[...]` の参照から値を伝播させます。
2. string decoder の引数を復元し、暗号化された呼び出しを平文に置き換えます。
3. 隣接する文字列チャンクを結合します。こうして得られるプロパティ名と dispatcher の順序文字列によって、後続のパスが可能になります。
4. 制御フローの flattening を解除し、call proxy と atomic-operation wrapper を inline 化して、dictionary に格納された関数参照を解決します。
5. 解決された文字列、キー、proxy によって別の間接参照が明らかになる場合があるため、再度伝播させます。
6. 呼び出し箇所を解決した後に限り、認識済みの one-shot 初期化 thunk を畳み込み、不要な helper を削除します。

### シフトされた RC4 文字列配列をブラックボックスとして復元する

よくある `javascript-obfuscator` の構成では、Base64 エンコードされた RC4 チャンクが1つの配列に格納されています。decoder wrapper は数値オフセットと短いキーを渡し、引数の順序が逆になっている場合もあります。その後、closure scope にキャプチャされた定数を加算または減算します。ルート decoder が強く難読化されている場合は、関数全体を復元するのではなく、未知の配列インデックスのシフトを実測して特定してください。<sup>[[1]](#references)</sup>

`N` 個のチャンクを持つ配列と、同じ decoder を呼び出す複数の呼び出しについては、次のとおりです。<sup>[[1]](#references)</sup>

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

単一の復号結果が印字可能だからといって、shiftを採用しないでください。誤ったciphertextでも偶然、印字可能に見えることがあります。少なくとも3つの異なる観察結果を使い、すべてで妥当なテキストになる一意のshiftだけを採用してください。次にwrapper/declarerのグラフをたどり、各加算または減算を累積し、数値引数が先に来るかどうかを記録します。このメタデータをサンプルごとにキャッシュし、decoder呼び出しを置き換え、隣接する平文チャンクを連結し、トリアージ用に文字列を個別にエクスポートします。<sup>[[1]](#references)[[2]](#references)</sup>

### 展開時もセマンティクスを維持する

`3|2|1|0|4`のような文字列で駆動されるdispatcher loopでは、順序文字列をデコードし、各state比較をブロックに対応付け、View8の否定条件の表記を考慮してから、dispatcherの順序でブロックを出力します。ネストされた`continue`は通常のフォールスルーではなく、dispatcherに戻る早期ジャンプを表す場合があります。loopを削除する際は、その`continue`を削除し、囲んでいる`if`の後に元々あった文を、生成した`else`ブランチに移動します。dispatcherを削除するだけでは動作が変わってしまいます。<sup>[[1]](#references)</sup>

### proxy、演算、遅延thunkをインライン化する

呼び出し箇所を直接呼び出しに置き換える前に、`return a0(a1, a2)`のような転送helperを正規化します。減算、除算、比較、メンバーシップテスト、呼び出しのwrapperも同様に扱います。helperへの参照自体が復号された辞書キーやclosureの値の背後に保存されている場合があるため、インライン化の前後に文字列と構造の伝播を実行します。<sup>[[1]](#references)</sup>

保存された関数を一度呼び出し、その参照をクリアし、結果をキャッシュして、以後の呼び出しではそのキャッシュを返すclosureも認識してください。初期化箇所でこのようなthunkをまとめると、基盤となるdispatcherまたはcapability functionが見えるようになります。ただし、元の実行は毎回の新規呼び出しではなく、**一度だけ実行され、結果がキャッシュされる**ものとして注記してください。<sup>[[1]](#references)</sup>

## Safety and validation notes

- Pythonの`pickle`読み込みはコードを実行する可能性があります。信頼できるView8の実行でローカルに生成された`.pkl`ファイルだけを読み込んでください。サンプルから提供されたpickleをデータとして扱ってはいけません。<sup>[[2]](#references)</sup>
- 関数本体が見つからないからといって、ソースにその関数がなかったとは限りません。V8は、初回呼び出しでコンパイルされるまで、遅延関数をメタデータとしてシリアライズする場合があります。静的トリアージでは、そのような関数を未解決としてマークしたままにしてください。<sup>[[6]](#references)</sup>
- パターン駆動のパスは汎用JavaScript decompilerではありません。未解決の式はそのまま保持し、曖昧なdispatcherのバリエーションは、無理に書き換えず手動で調査してください。<sup>[[1]](#references)[[2]](#references)</sup>
- LLMが補助した関数名は、コード内の移動に使うヒントであり、根拠ではありません。これらを使う場合は依存関係をleaf-firstで処理し、各ラベルを関数本体、引数、文字列、データフロー、API、副作用と照らし合わせて検証してください。<sup>[[1]](#references)[[2]](#references)</sup>



## References

- [1] [Breaking the Seal: JSCealのコンパイル済みV8 Bytecodeの静的Deobfuscation](https://research.checkpoint.com/2026/breaking-the-seal-static-deobfuscation-of-jsceals-compiled-v8-bytecode)
- [2] [hasherezade/jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator)
- [3] [suleram/View8](https://github.com/suleram/View8)
- [4] [ejfkdev/jscd](https://github.com/ejfkdev/jscd)
- [5] [V8 SerializedCodeDataヘッダー](https://chromium.googlesource.com/v8/v8/+/main/src/snapshot/code-serializer.h)
- [6] [Node.js vm.Scriptのcode cache](https://nodejs.org/api/vm.html#scriptcreatecacheddata)
{{#include ../../banners/hacktricks-training.md}}
