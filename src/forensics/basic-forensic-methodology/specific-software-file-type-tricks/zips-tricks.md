# ZIPs tricks

{{#include ../../../banners/hacktricks-training.md}}

**コマンドラインツール**は**zipファイル**の管理に不可欠で、診断、修復、及びzipファイルのクラッキングに役立ちます。以下は主なユーティリティです：

- **`unzip`**: zipファイルが解凍できない理由を明らかにします。
- **`zipdetails -v`**: zipファイルフォーマットフィールドの詳細な分析を提供します。
- **`zipinfo`**: zipファイルの内容を抽出せずにリストします。
- **`zip -F input.zip --out output.zip`** および **`zip -FF input.zip --out output.zip`**: 壊れたzipファイルの修復を試みます。
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: zipパスワードのブルートフォースクラッキングツールで、約7文字までのパスワードに効果的です。

[Zipファイルフォーマット仕様](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)は、zipファイルの構造と標準に関する包括的な詳細を提供します。

パスワード保護されたzipファイルは**ファイル名やファイルサイズを暗号化しない**ことに注意することが重要です。これは、RARや7zファイルがこの情報を暗号化するのとは異なるセキュリティの欠陥です。さらに、古いZipCrypto方式で暗号化されたzipファイルは、圧縮ファイルの未暗号化コピーが利用可能な場合、**平文攻撃**に対して脆弱です。この攻撃は、既知の内容を利用してzipのパスワードをクラッキングします。この脆弱性は[HackThisの記事](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files)で詳述され、[この学術論文](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf)でさらに説明されています。しかし、**AES-256**暗号化で保護されたzipファイルはこの平文攻撃に対して免疫があり、機密データのために安全な暗号化方法を選択する重要性を示しています。

## References

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)

{{#include ../../../banners/hacktricks-training.md}}
