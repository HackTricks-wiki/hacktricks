# Officeファイル解析

{{#include ../../../banners/hacktricks-training.md}}

詳しくは[https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)を確認してください。ここでは要約のみを示します:<sup>[[4]](#references)</sup>

Microsoft Officeドキュメントには、RTFやOLE/CFBFベースのDOC、XLS、PPTなどの旧形式と、DOCX、XLSX、PPTXなどの新しい**Office Open XML（OOXML）**形式があります。Officeドキュメントにはマクロなどのアクティブコンテンツが含まれる場合があり、フィッシングやマルウェアの一般的な媒介となっています。OOXMLファイルはZIPコンテナであり、解凍してファイル階層とXMLの内容を調査できます。<sup>[[3]](#references)[[4]](#references)</sup>

OOXMLファイルの構造を調べるために、ドキュメントを解凍するコマンドと出力構造を示します。これらのファイルにデータを隠す手法も文書化されており、CTFチャレンジにおけるデータ隠蔽の手法が進化し続けていることがうかがえます。<sup>[[4]](#references)</sup>

解析には、**oletools**と**OfficeDissector**を利用でき、OLEドキュメントとOOXMLドキュメントの両方を調べるための包括的なツールセットを提供します。これらのツールを使うと、マルウェア配布の手段として使われることが多い埋め込みマクロを特定して解析できます。こうしたマクロは通常、追加の悪意あるペイロードをダウンロードして実行します。Libre Officeを利用すれば、Microsoft Officeを使わずにVBAマクロを解析でき、ブレークポイントや監視変数を使ったデバッグも可能です。<sup>[[4]](#references)</sup>

**oletools**のインストールと使用は簡単です。pipでインストールするコマンドと、ドキュメントからマクロを抽出するコマンドを示します。Wordの自動実行マクロには`AutoExec`と`AutoOpen`があり、`Document_Open`はドキュメントを開いたときに実行されるイベントプロシージャです。<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```

パスワードで暗号化された Office ドキュメントについては、[文法駆動型オフラインリカバリワークフロー](../../../generic-hacking/brute-force.md#grammar-driven-combinator-attacks-encrypted-office-example)を参照してください。

---

## OLE Compound File の悪用: Autodesk Revit RFA – ECC の再計算と gzip の制御

Revit RFA モデルは[OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)（別名 CFBF）として保存されます。シリアライズされたモデルは、次のストレージ／ストリームに格納されています:<sup>[[1]](#references)[[3]](#references)</sup>

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

`Global\Latest` の主要なレイアウト（Revit 2025 で確認）:

- ヘッダー
- GZIP 圧縮ペイロード（シリアライズされたオブジェクトグラフ本体）
- ゼロパディング
- Error-Correcting Code (ECC) トレーラー

Revit は ECC トレーラーを使ってストリームの小さな変化を自動修復し、ECC と一致しないストリームを拒否します。そのため、圧縮バイトを単純に編集しても変更は維持されません。変更は元に戻されるか、ファイルが拒否されます。デシリアライザーが受け取る内容をバイト単位で正確に制御するには、次の作業が必要です:<sup>[[1]](#references)</sup>

- Revit 互換の gzip 実装で再圧縮する（Revit が生成／受け入れる圧縮バイトが期待どおりに一致するようにする）。
- パディング済みストリームの ECC トレーラーを再計算し、Revit が変更済みストリームを自動修復せずに受け入れるようにする。

RFA の内容にパッチを適用したり fuzzing したりする実用的なワークフロー:<sup>[[1]](#references)</sup>

1) OLE 複合ドキュメントを展開します。<sup>[[2]](#references)</sup>

```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```

2) gzip/ECC の規則に従って `Global\Latest` を編集する

- `Global/Latest` を分解します。ヘッダーを保持し、ペイロードを gunzip してバイト列を変更した後、Revit 互換の deflate パラメーターで再度 gzip します。
- zero-padding を保持し、ECC trailer を再計算して、Revit が新しいバイト列を受け入れるようにします。
- バイト単位で完全に再現する必要がある場合は、研究で実証されているように、Revit の DLL を使った最小限の wrapper を作成し、その gzip/gunzip 処理と ECC 計算を呼び出すか、これらの仕様を再現する既存の helper を利用します。

3) OLE 複合ドキュメントを再構築する。<sup>[[2]](#references)</sup>

```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```

Notes:<sup>[[1]](#references)[[2]](#references)</sup>

- CompoundFileTool は、NTFS の名前に使用できない文字をエスケープして、ストレージ/ストリームをファイルシステムに書き込みます。必要なストリームのパスは、出力ツリー内の `Global/Latest` です。
- クラウドストレージから RFA を取得するエコシステムプラグインを通じて大規模攻撃を行う場合、ネットワーク経由で注入を試みる前に、パッチ済み RFA がローカルで Revit の整合性チェックに合格すること（gzip/ECC が正しいこと）を確認してください。

悪用に関する知見（gzip ペイロードに配置するバイト列の参考）：<sup>[[1]](#references)</sup>

- Revit のデシリアライザーは 16 ビットのクラスインデックスを読み取り、オブジェクトを構築します。一部の型は非ポリモーフィックで vtable を持ちません。デストラクターの処理を悪用すると、型の取り違えが発生し、エンジンが攻撃者制御のポインターを介して間接呼び出しを実行します。
- `AString`（クラスインデックス `0x1F`）を選ぶと、オブジェクトのオフセット 0 に攻撃者制御のヒープポインターが配置されます。デストラクターのループ中、Revit は実質的に次を実行します。

```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```

- シリアライズされたグラフ内にこのようなオブジェクトを複数配置し、デストラクタループの各反復で1つのgadget（weird machine）が実行されるようにして、従来型のx64 ROP chainへstack pivotするよう構成します。

Windows x64のpivot/gadget構築の詳細はこちら：

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

一般的なROPのガイダンスはこちら：

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

ツール:<sup>[[1]](#references)</sup>

- CompoundFileTool (OSS)：OLE compound fileの展開・再構築用：https://github.com/thezdi/CompoundFileTool.<sup>[[2]](#references)</sup>
- IDA Pro + WinDBG TTD：リバースエンジニアリング／taint解析用。トレースをコンパクトに保つため、TTDでpage heapを無効にします。
- ローカルproxy（例：Fiddler）を使い、テスト用にpluginの通信でRFAを差し替えることで、supply-chain経由の配布をシミュレートできます。

## References

- [1] [Autodesk RevitのRFAファイル解析におけるクラッシュから完全なRCE exploitを作成する（ZDI blog）](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [3] [OLE Compound File (CFBF) ドキュメント](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Forensics CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)
- [5] [olevba ドキュメント (GitHub)](https://github.com/decalage2/oletools/wiki/olevba)
- [6] [Auto Macros (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros)
- [7] [Document.Open event (Word) (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/api/word/document.open)
{{#include ../../../banners/hacktricks-training.md}}
