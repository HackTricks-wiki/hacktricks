# PDFファイル分析

{{#include ../../../banners/hacktricks-training.md}}

**詳細については、次を確認してください:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/)

PDF形式は、その複雑さとデータを隠す可能性で知られており、CTFフォレンジックチャレンジの焦点となっています。これは、圧縮または暗号化される可能性のあるバイナリオブジェクトとプレーンテキスト要素を組み合わせており、JavaScriptやFlashなどの言語でのスクリプトを含むことがあります。PDFの構造を理解するには、Didier Stevensの[入門資料](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/)を参照するか、テキストエディタやOrigamiのようなPDF専用エディタを使用できます。

PDFの詳細な探索や操作には、[qpdf](https://github.com/qpdf/qpdf)や[Origami](https://github.com/mobmewireless/origami-pdf)のようなツールが利用可能です。PDF内の隠れたデータは以下に隠されている可能性があります：

- 見えないレイヤー
- AdobeのXMPメタデータ形式
- 増分生成
- 背景と同じ色のテキスト
- 画像の背後にあるテキストや重なり合った画像
- 表示されていないコメント

カスタムPDF分析には、[PeepDF](https://github.com/jesparza/peepdf)のようなPythonライブラリを使用して、特注のパーススクリプトを作成できます。さらに、PDFの隠れたデータストレージの可能性は非常に広範であり、NSAのPDFリスクと対策に関するガイドのようなリソースは、もはや元の場所ではホストされていませんが、貴重な洞察を提供します。[ガイドのコピー](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%Bútmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)や、Ange Albertiniによる[PDF形式のトリックのコレクション](https://github.com/corkami/docs/blob/master/PDF/PDF.md)は、このテーマに関するさらなる読み物を提供します。

{{#include ../../../banners/hacktricks-training.md}}
