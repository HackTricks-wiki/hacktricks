# PDFファイル解析

{{#include ../../../banners/hacktricks-training.md}}

**詳細はこちらを確認してください:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/).<sup>[[1]](#references)</sup>

PDF形式は複雑で、データを隠蔽できる可能性があることで知られており、CTFのフォレンジック課題で焦点となる形式です。プレーンテキスト要素とバイナリオブジェクトを組み合わせており、オブジェクトは圧縮または暗号化されている場合があります。また、JavaScriptやFlashなどの言語によるスクリプトを含めることもできます。PDFの構造を理解するには、Didier Stevensの[入門資料](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/)を参照するか、テキストエディタやOrigamiなどのPDF専用エディタを使用できます。

PDFを詳細に調査または操作するには、[qpdf](https://github.com/qpdf/qpdf)や[Origami](https://github.com/mobmewireless/origami-pdf)などのツールを利用できます。PDF内の隠しデータは、次の場所に隠されている可能性があります。

- 非表示レイヤー
- AdobeのXMPメタデータ形式
- 増分世代
- 背景と同じ色のテキスト
- 画像の背後にあるテキスト、または重なり合った画像
- 表示されないコメント

独自のPDF解析には、[PeepDF](https://github.com/jesparza/peepdf)などのPythonライブラリを使って、専用のパーサースクリプトを作成できます。さらに、PDFが隠しデータの保存に利用される可能性は非常に大きいため、元の場所では公開されなくなったものの、PDFのリスクと対策に関するNSAのガイドは今なお有益な情報源です。[ガイドのコピー](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)と、Ange Albertiniによる[PDF形式のトリック集](https://github.com/corkami/docs/blob/master/PDF/PDF.md)も、このテーマをさらに学ぶ際に役立ちます。<sup>[[4]](#references)[[5]](#references)</sup>

## よくある悪意のある構造

攻撃者は、ドキュメントを開いたときや操作したときに自動実行される特定のPDFオブジェクトやアクションを悪用することがよくあります。調査対象となるキーワードは次のとおりです。

* **/OpenAction, /AA** – 開いたとき、または特定のイベント発生時に実行される自動アクション。
* **/JS, /JavaScript** – 埋め込みJavaScript（難読化されていたり、複数のオブジェクトに分割されていたりすることがよくあります）。
* **/Launch, /SubmitForm, /URI, /GoToE** – 外部プロセスやURLを起動するもの。
* **/RichMedia, /Flash, /3D** – ペイロードを隠せるマルチメディアオブジェクト。
* **/EmbeddedFile /Filespec** – ファイル添付（EXE、DLL、OLEなど）。
* **/ObjStm, /XFA, /AcroForm** – シェルコードの隠蔽に悪用されることが多いオブジェクトストリームやフォーム。
* **増分更新** – 複数の%%EOFマーカー、または非常に大きな**/Prev**オフセットは、AVを回避するために署名後にデータが追加されたことを示している可能性があります。

上記のトークンがpowershell、cmd.exe、calc.exe、base64などの不審な文字列とともに現れた場合、そのPDFはより詳細な解析が必要です。

---

## 静的解析のチートシート

以下の例では、ドキュメント化されている`pdf-parser.py`、qpdf、pdfcpuのコマンドラインインターフェースを使用します。<sup>[[7]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
# Fast triage – keyword statistics
pdfid.py suspicious.pdf

# Deep dive – pass supported streams through their declared filters
pdf-parser.py -f suspicious.pdf
pdf-parser.py -a suspicious.pdf                # automatic report

# Search for JavaScript and pretty-print it
pdf-parser.py -search "/JS" -raw suspicious.pdf | js-beautify -

# Dump embedded files
peepdf "open suspicious.pdf" "objects embeddedfile" "extract 15 16 17" -o dumps/

# Remove passwords / encryptions before processing with other tools
qpdf --password='secret' --decrypt suspicious.pdf clean.pdf

# Lint the file with a Go verifier (checks structure violations)
pdfcpu validate -mode strict clean.pdf
```

PDF 内の画像をピクセル化しても、その元のピクセルは削除されません。読み取り可能な文書で、こうした方法で認証情報が隠されているように見える場合は、許可を得たうえで埋め込み画像を抽出し、オフラインで調査してください。結果は画像と適切な参照資料によって異なり、視覚的な復元が保証されるわけではありません。復元したパスワードは、重要な権限を持つアカウントに対して別途検証する必要があります。定期的な host-enumeration scan に、PDF 抽出や画像復元の処理を含めないでください。

その他の有用なプロジェクト（2023～2025年に活発にメンテナンス）:
* **pdfcpu** – PDF の検証、復号、抽出、最適化、操作が可能な Go ライブラリ/CLI。<sup>[[9]](#references)</sup>
* **pdf-inspector** – オブジェクトグラフとストリームを描画するブラウザベースのビジュアライザー。
* **PyMuPDF** – PDF の調査やページのラスター画像へのレンダリングに使える、スクリプト対応の Python バインディング。パーサー/レンダラーは信頼できないファイルによる攻撃対象領域とみなし、適切に隔離された分析環境で実行してください。<sup>[[8]](#references)</sup>

---

## 最近の攻撃手法（2023～2025年）

* **MalDoc in PDF ポリグロット（2023年）** – JPCERT/CC は、Word で作成された VBA マクロ付き MHT ファイルを PDF に追加し、PDF のマジックナンバーを保ちながら Word でも開けるようにする手法を報告しました。悪意のある動作は Word として開いたときに発生するため、PDF 専用の分析ツール、サンドボックス、アンチウイルスではマクロを見逃す場合があります。他の MHT の特徴とともに、`<w:WordDocument>` マーカーを探してください。<sup>[[2]](#references)</sup>
* **署名済み PDF に対する Shadow attacks** – 攻撃者は署名前に PDF 内に隠しコンテンツを配置し、その後、カタログやオブジェクトの参照を変更する増分更新を追加できます。これにより、元の署名が有効なまま、ビューアーには隠しコンテンツが表示されます。この手法は、こうした更新を無害と分類するビューアーを回避できます。<sup>[[6]](#references)</sup>
* **Use-after-free – CVE-2024-30284（Acrobat/Reader）** – Adobe はこの重大な脆弱性を、任意コード実行につながる可能性のある use-after-free と評価しています。APSB24-29 は 2024 年 5 月 14 日に公開されました。<sup>[[3]](#references)</sup>

---

## YARA ルールの簡易テンプレート

```yara
rule Suspicious_PDF_AutoExec {
    meta:
        description = "Generic detection of PDFs with auto-exec actions and JS"
        author      = "HackTricks"
        last_update = "2025-07-20"
    strings:
        $pdf_magic = { 25 50 44 46 }          // %PDF
        $aa        = "/AA" ascii nocase
        $openact   = "/OpenAction" ascii nocase
        $js        = "/JS" ascii nocase
    condition:
        $pdf_magic at 0 and ( all of ($aa, $openact) or ($openact and $js) )
}
```

---

## 防御のヒント

1. **迅速にパッチを適用する** – Acrobat/Readerを最新のContinuousトラックに保ちましょう。実環境で確認されているRCEチェーンの多くは、数か月前に修正されたn-day脆弱性を悪用しています。
2. **ゲートウェイでアクティブコンテンツを除去する** – JavaScript、埋め込みファイル、launchアクション、フォーム、マルチメディアを明示的に削除する、専用のポリシー制御型サニタイザーまたはCDR製品を使用しましょう。`qpdf --qdf`を使うとPDFオブジェクトを検査しやすくなり、pdfcpuは検証・操作機能を提供します。ただし、どちらのコマンドも単独ではアクティブコンテンツが削除された証拠にはなりません。<sup>[[9]](#references)[[10]](#references)</sup>
3. **Content Disarm & Reconstruction (CDR)** – サンドボックスホスト上でPDFを画像（またはPDF/A）に変換し、見た目を保ちながらアクティブオブジェクトを破棄しましょう。
4. **使用頻度の低い機能をブロックする** – Readerのエンタープライズ向け「Enhanced Security」設定では、JavaScript、マルチメディア、3Dレンダリングを無効にできます。
5. **ユーザー教育** – ソーシャルエンジニアリング（請求書や履歴書を装った誘い）が依然として初期侵入経路です。不審な添付ファイルをIRに転送するよう従業員に教育しましょう。

## References

- [1] [フォレンジックCTFフィールドガイド](https://trailofbits.github.io/ctf/forensics/)
- [2] [PDF内のMalDoc – 悪意のあるWordファイルをPDFファイルに埋め込む検出回避手法](https://blogs.jpcert.or.jp/en/2023/08/maldocinpdf.html)
- [3] [Adobeセキュリティ情報 – Adobe AcrobatおよびReader向けセキュリティアップデート（APSB24-29）](https://helpx.adobe.com/security/products/acrobat/apsb24-29.html)
- [4] [itsecure.hu - ガイドのコピー](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)
- [5] [corkami/docs - PDF形式のトリック](https://github.com/corkami/docs/blob/master/PDF/PDF.md)
- [6] [Shadow Attacks: 署名済みPDF内のコンテンツの隠蔽と置換](https://www.pdf-insecurity.org/download/Shadow_Attacks__Hiding_and_Replacing_Content_in_Signed_PDFs.pdf)
- [7] [DidierStevensSuite: pdf-parser.py](https://github.com/DidierStevens/DidierStevensSuite/blob/master/pdf-parser.py)
- [8] [PyMuPDFチュートリアル](https://pymupdf.readthedocs.io/en/latest/tutorial.html)
- [9] [pdfcpu](https://github.com/pdfcpu/pdfcpu)
- [10] [qpdfコマンドラインオプション](https://qpdf.readthedocs.io/en/stable/cli.html)
{{#include ../../../banners/hacktricks-training.md}}
