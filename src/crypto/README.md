# Crypto

{{#include ../banners/hacktricks-training.md}}

このセクションでは、security testing と CTFs のための実践的な暗号技術を扱います。一般的なパターンの認識、適切なツールの選択、既知の攻撃の適用について説明します。

ファイル内にデータを隠す技術については、**Stego** セクションを参照してください。

## このセクションの使い方

まず、primitive とそのパラメータを特定します。次に、攻撃を選択する前に、attacker が何を制御または観測できるかを判断します。たとえば、oracle、leaked value、nonce reuse などです。

### CTF workflow

{{#ref}}
ctf-workflow/README.md
{{#endref}}

### Symmetric cryptography

{{#ref}}
symmetric/README.md
{{#endref}}

### Hashes, MACs, and KDFs

{{#ref}}
hashes/README.md
{{#endref}}

### Public-key cryptography

{{#ref}}
public-key/README.md
{{#endref}}

### TLS and certificates

{{#ref}}
tls-and-certificates/README.md
{{#endref}}

### Cryptography in malware

{{#ref}}
crypto-in-malware/README.md
{{#endref}}

### Miscellaneous

{{#ref}}
ctf-misc/README.md
{{#endref}}

## Quick setup

隔離された Python 環境を作成し、一般的に使用されるパッケージをインストールします。PyCryptodome のドキュメントでは、`pip` を使用して `pycryptodome` をインストールすることを推奨しています。SageMath では、サポート対象の各プラットフォーム向けに個別のインストール手順が提供されています。<sup>[[1]](#references)[[2]](#references)</sup>
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install pycryptodome gmpy2 sympy pwntools
```
SageMathは、algebra、lattice、RSA、elliptic-curveの計算に役立つことがよくあります。<sup>[[2]](#references)</sup>

## References

- [1] [PyCryptodome documentation - インストール](https://www.pycryptodome.org/src/installation)
- [2] [SageMath documentation - インストールガイド](https://doc.sagemath.org/html/en/installation/)
{{#include ../banners/hacktricks-training.md}}
