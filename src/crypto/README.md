# 暗号

{{#include ../banners/hacktricks-training.md}}

このセクションでは、セキュリティテストやCTFで実用的な暗号技術を扱います。一般的なパターンの見分け方、適切なツールの選び方、既知の攻撃の適用方法を説明します。

ファイル内にデータを隠す手法については、**Stego** セクションを参照してください。

## このセクションの使い方

まず、暗号プリミティブとそのパラメーターを特定します。次に、攻撃者が制御または観測できるもの（oracle、leakされた値、nonceの再利用など）を判断してから、攻撃を選択します。

### CTFワークフロー

{{#ref}}
ctf-workflow/README.md
{{#endref}}

### 共通鍵暗号

{{#ref}}
symmetric/README.md
{{#endref}}

### ハッシュ、MAC、KDF

{{#ref}}
hashes/README.md
{{#endref}}

### 公開鍵暗号

{{#ref}}
public-key/README.md
{{#endref}}

### TLSと証明書

{{#ref}}
tls-and-certificates/README.md
{{#endref}}

### マルウェアにおける暗号技術

{{#ref}}
crypto-in-malware/README.md
{{#endref}}

### その他

{{#ref}}
ctf-misc/README.md
{{#endref}}

## クイックセットアップ

隔離されたPython環境を作成し、よく使われるパッケージをインストールします。PyCryptodomeのドキュメントでは、`pip`を使って`pycryptodome`をインストールする方法が推奨されています。SageMathでは、サポート対象の各プラットフォーム向けに個別のインストール手順が用意されています。<sup>[[1]](#references)[[2]](#references)</sup>

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install pycryptodome gmpy2 sympy pwntools
```

SageMathは、代数、格子、RSA、楕円曲線の計算に役立つことがよくあります。<sup>[[2]](#references)</sup>

## References

- [1] [PyCryptodome ドキュメント - インストール](https://www.pycryptodome.org/src/installation)
- [2] [SageMath ドキュメント - インストールガイド](https://doc.sagemath.org/html/en/installation/)
{{#include ../banners/hacktricks-training.md}}
