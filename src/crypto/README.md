# Crypto

{{#include ../banners/hacktricks-training.md}}

このセクションは、hacking/CTFs 向けの実践的暗号学に焦点を当てています：一般的なパターンを素早く認識し、適切なツールを選び、既知の攻撃を適用する方法を解説します。

If you're here for hiding data inside files, go to the **Stego** section.

## このセクションの使い方

Crypto チャレンジでは速度が重要です：プリミティブを分類し、制御できるもの（oracle/leak/nonce reuse）を特定し、既知の攻撃テンプレートを適用します。

### CTF workflow
{{#ref}}
ctf-workflow/README.md
{{#endref}}

### Symmetric crypto
{{#ref}}
symmetric/README.md
{{#endref}}

### Hashes, MACs, and KDFs
{{#ref}}
hashes/README.md
{{#endref}}

### Public-key crypto
{{#ref}}
public-key/README.md
{{#endref}}

### TLS and certificates
{{#ref}}
tls-and-certificates/README.md
{{#endref}}

### Crypto in malware
{{#ref}}
crypto-in-malware/README.md
{{#endref}}

### Misc
{{#ref}}
ctf-misc/README.md
{{#endref}}

## クイックセットアップ

- Python: `python3 -m venv .venv && source .venv/bin/activate`
- Libraries: `pip install pycryptodome gmpy2 sympy pwntools`
- SageMath（lattice/RSA/ECC に対してしばしば必須）: https://www.sagemath.org/

{{#include ../banners/hacktricks-training.md}}
