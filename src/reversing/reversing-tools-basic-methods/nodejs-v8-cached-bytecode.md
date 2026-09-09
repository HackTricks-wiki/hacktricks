# Node.js/V8 Cached Bytecodeの静的Deobfuscation

{{#include ../../banners/hacktricks-training.md}}

V8 cached dataは**version-dependentでlossyな表現**であり、JavaScript sourceでも、従来のnative executableでもありません。したがって有用なstatic workflowは、まず外側のpackingを除去し、対応するV8 buildでcacheをdisassembleし、中間的なpseudocode modelへliftし、sampleを実行せずにdependency-awareなtransformationsを適用するというものです。[View8](https://github.com/suleram/View8)と[jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator)は、`javascript-obfuscator`で保護されたNode.js payloadsに対してこのアプローチを実装しています。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## Cacheの取得とdisassemble

まず、すべての`.jsc`ファイルが同じwrapperを持つと決めつけず、preload/launcherを調査します。たとえば、`node.exe -r preflight.js app.jsc`のようなlauncherは、main moduleの前に`preflight.js`を実行します。分析対象となったfamilyでは、preloadがBrotli layerを除去していました。unpacking後、bundled runtimeから正確なNode.js/V8 generationを特定します。あるV8 versionで生成されたcacheは、別のversionでは拒否されたり、誤ってdecodeされたりする可能性があります。そのため、正確なV8 tagに対応する`v8dasm`をbuildまたは入手し、必要なView8およびstring-printing patchesを適用します。<sup>[[1]](#references)[[2]](#references)</sup>

Toolkitのnon-executing workflowは次のとおりです。<sup>[[2]](#references)</sup>
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
`--normalize` は、実行ごとに生成される関数へ安定した識別子を付与します。テキスト出力は検査用であり、シリアライズされたオブジェクトグラフにより、独立したパスでも関数、宣言元、スコープ、メタデータ間の関係を保持できます。これは**再構築されたものでも、実行可能な JavaScript でもありません**。<sup>[[1]](#references)[[2]](#references)</sup>

### View8 の pseudocode を IR として読む

典型的な名前は `func_<name>_0x<address>` で、引数は `a0...aN`、virtual register は `r0...rN`、`ACCU` は V8 の accumulator です。`start` は root declarer であり、`Scope[...]`、globals、dictionaries は、nested function によって capture または共有される値をモデル化します。すべての式を JavaScript の構文として parse しないでください。たとえば、View8 の `!r6 === "0"` は比較全体の否定（`r6 !== "0"`）を表しており、これは branch を再構築する際に重要です。<sup>[[1]](#references)[[3]](#references)</sup>

## 依存関係を考慮した deobfuscation

次の pass に必要な入力が明らかになる順序で transformation を適用し、出力が安定するまで propagation を繰り返します。実用的な順序は次のとおりです。<sup>[[1]](#references)[[2]](#references)</sup>

1. declarer hierarchy をたどり、globals、registers、dictionaries、`Scope[...]` references から値を propagation します。
2. string-decoder の引数を復元し、encrypted calls を plaintext に置き換えます。
3. 隣接する string chunks を fold します。これにより得られる property names と dispatcher-order strings が、後続の pass を解決します。
4. control flow の flattening を解除し、call proxies と atomic-operation wrappers を inline 化して、dictionary に保持された function references を解決します。
5. 解決された各 string、key、proxy が別の indirection layer を明らかにする可能性があるため、再度 propagation します。
6. 認識済みの one-shot initialization thunks を collapse し、call sites の解決後にのみ dead helpers を削除します。

### shifted RC4 string arrays を black box として復元する

一般的な `javascript-obfuscator` の構成では、Base64 で encode された RC4 chunks を 1 つの array に格納します。Decoder wrappers は numeric offset と短い key を渡し、引数の順序が逆になっている場合もあります。その後、closure scopes に capture された定数を加算または減算します。root decoder が過度に obfuscate されている場合は、function 全体を再構築するのではなく、unknown array-index shift を経験的に復元します。<sup>[[1]](#references)</sup>

`N` 個の chunks からなる array と、同じ decoder への複数の calls に対しては、次のようにします。<sup>[[1]](#references)</sup>
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
単一の printable な復号結果だけで shift を確定しないでください。誤った ciphertext でも偶然 printable に見えることがあります。少なくとも 3 つの異なる観測結果を使用し、それらすべてで妥当なテキストを生成する一意の shift のみを受け入れてください。次に、wrapper/declarer graph をたどり、各加算または減算を累積し、数値引数が先に来るかどうかを記録します。この metadata を sample ごとに cache し、decoder の呼び出しを置き換え、隣接する plaintext chunk を連結して、triage 用に文字列を個別に出力します。<sup>[[1]](#references)[[2]](#references)</sup>

### unflattening 中も semantics を保持する

`3|2|1|0|4` のような文字列で駆動される dispatcher loop では、order string を decode し、各 state comparison を対応する block に割り当て、View8 の negated-condition notation を考慮したうえで、dispatcher の順序に従って block を出力します。ネストされた `continue` は通常の fall-through ではなく、dispatcher へ戻る early jump を表している場合があります。loop を削除するときは、その `continue` を削除し、そこを囲む `if` の後に元々続いていた statements を生成した `else` branch に移動します。dispatcher を単に削除するだけでは behavior が変わります。<sup>[[1]](#references)</sup>

### proxy、operation、lazy thunk を inline する

`return a0(a1, a2)` のような forwarding helper は、call site を direct call に置き換える前に normalize します。subtraction、division、comparison、membership test、invocation 用の wrapper も同様に扱います。helper reference 自体が decrypted dictionary key や closure value の背後に保存されている場合があるため、inlining の前後に string propagation と structure propagation を実行します。<sup>[[1]](#references)</sup>

また、保存された function を一度だけ呼び出し、その reference を clear し、結果を cache して、後続の call ではその cache を返す closure も認識します。initialization site でこの thunk を collapse すると、基盤となる dispatcher または capability function が明らかになります。ただし、元の実行が **one-shot and cached** であり、すべての call を新規 invocation として model 化していないことを注記してください。<sup>[[1]](#references)</sup>

## Safety and validation notes

- Python `pickle` の loading は code を実行できます。trusted な View8 run によってローカルで生成された `.pkl` ファイルだけを load し、sample が提供した pickle を data として扱わないでください。<sup>[[2]](#references)</sup>
- Pattern-driven pass は汎用的な JavaScript decompiler ではありません。未解決の expression を保持し、曖昧な dispatcher variant は rewrite を強制せず手動で確認してください。<sup>[[1]](#references)[[2]](#references)</sup>
- LLM-assisted function name は navigation hint であり、evidence ではありません。使用する場合は dependency を leaf-first で処理しますが、すべての label を body、argument、string、data flow、API、side effect と照合して検証してください。<sup>[[1]](#references)[[2]](#references)</sup>

## References

- [1] [Seal を破る: JSCeal の compiled V8 Bytecode の static deobfuscation](https://research.checkpoint.com/2026/breaking-the-seal-static-deobfuscation-of-jsceals-compiled-v8-bytecode)
- [2] [hasherezade/jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator)
- [3] [suleram/View8](https://github.com/suleram/View8)
{{#include ../../banners/hacktricks-training.md}}
