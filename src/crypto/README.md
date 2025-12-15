# Crypto

{{#include ../banners/hacktricks-training.md}}

本节侧重于面向 hacking/CTFs 的实用密码学：如何快速识别常见模式、选择合适的工具，并应用已知的攻击方法。

如果你是来学习在文件中隐藏数据，请前往 **Stego** 部分。

## 如何使用本节

Crypto 挑战强调速度：先对 primitive 进行分类，确认你能控制的内容（oracle/leak/nonce reuse），然后套用已知的攻击模板。

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

## 快速设置

- Python: `python3 -m venv .venv && source .venv/bin/activate`
- 依赖库: `pip install pycryptodome gmpy2 sympy pwntools`
- SageMath（经常用于 lattice/RSA/ECC）：https://www.sagemath.org/

{{#include ../banners/hacktricks-training.md}}
