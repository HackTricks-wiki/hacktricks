# Crypto

{{#include ../banners/hacktricks-training.md}}

本节聚焦于安全测试和 CTF 中的实用密码学：识别常见模式、选择合适的工具，并应用已知攻击。

有关将数据隐藏在文件中的技术，请参阅 **Stego** 章节。

## 如何使用本节

首先识别所用原语及其参数。然后确定攻击者可以控制或观察什么，例如 oracle、leak 值或 nonce 重用，再选择攻击方式。

### CTF 工作流程

{{#ref}}
ctf-workflow/README.md
{{#endref}}

### 对称密码学

{{#ref}}
symmetric/README.md
{{#endref}}

### 哈希、MAC 和 KDF

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

### 恶意软件中的密码学

{{#ref}}
crypto-in-malware/README.md
{{#endref}}

### 其他

{{#ref}}
ctf-misc/README.md
{{#endref}}

## 快速设置

创建隔离的 Python 环境，并安装常用软件包。PyCryptodome 的文档建议使用 `pip` 安装 `pycryptodome`；SageMath 则为每个受支持的平台提供单独的安装指南。<sup>[[1]](#references)[[2]](#references)</sup>

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install pycryptodome gmpy2 sympy pwntools
```

SageMath 常用于代数、格、RSA 和椭圆曲线计算。<sup>[[2]](#references)</sup>

## References

- [1] [PyCryptodome 文档 - 安装](https://www.pycryptodome.org/src/installation)
- [2] [SageMath 文档 - 安装指南](https://doc.sagemath.org/html/en/installation/)
{{#include ../banners/hacktricks-training.md}}
