# Crypto

{{#include ../banners/hacktricks-training.md}}

本节专注于**面向 hacking/CTF 的实用密码学**：如何快速识别常见模式、选择正确的工具，以及应用已知攻击。

如果你是来了解如何将数据隐藏在文件中的，请前往 **Stego** 部分。

## 如何使用本节

Crypto 挑战考验速度：先对 primitive 进行分类，识别你能够控制的内容（oracle/leak/nonce reuse），然后应用已知的攻击模板。

### CTF 工作流
{{#ref}}
ctf-workflow/README.md
{{#endref}}

### 对称加密
{{#ref}}
symmetric/README.md
{{#endref}}

### Hash、MAC 和 KDF
{{#ref}}
hashes/README.md
{{#endref}}

### 公钥密码学
{{#ref}}
public-key/README.md
{{#endref}}

### TLS 和证书
{{#ref}}
tls-and-certificates/README.md
{{#endref}}

### malware 中的 Crypto
{{#ref}}
crypto-in-malware/README.md
{{#endref}}

### 杂项
{{#ref}}
ctf-misc/README.md
{{#endref}}

## 快速设置

- Python：`python3 -m venv .venv && source .venv/bin/activate`
- Libraries：`pip install pycryptodome gmpy2 sympy pwntools`
- SageMath（对于 lattice/RSA/ECC 通常必不可少）：<https://www.sagemath.org/>

{{#include ../banners/hacktricks-training.md}}
