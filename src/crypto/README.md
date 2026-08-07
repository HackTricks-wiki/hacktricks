# 暗号

{{#include ../banners/hacktricks-training.md}}

このセクションでは、**hacking/CTF向けの実践的な暗号技術**について扱います。一般的なパターンを素早く見分け、適切なツールを選び、既知の攻撃手法を適用する方法を学びます。

ファイル内にデータを隠す方法を探している場合は、**Stego**セクションに進んでください。

## このセクションの使い方

Crypto challengeでは速度が重要です。暗号プリミティブを分類し、自分が制御できるもの（oracle/leak/nonce reuse）を特定してから、既知の攻撃テンプレートを適用します。

### CTFワークフロー
{{#ref}}
ctf-workflow/README.md
{{#endref}}

### 対称暗号
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

### マルウェアにおける暗号
{{#ref}}
crypto-in-malware/README.md
{{#endref}}

### その他
{{#ref}}
ctf-misc/README.md
{{#endref}}

## クイックセットアップ

- Python: `python3 -m venv .venv && source .venv/bin/activate`
- ライブラリ: `pip install pycryptodome gmpy2 sympy pwntools`
- SageMath（lattice/RSA/ECCでは必須になることが多い）: <https://www.sagemath.org/>

{{#include ../banners/hacktricks-training.md}}
