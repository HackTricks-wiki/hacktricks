# Crypto

{{#include ../banners/hacktricks-training.md}}

This section focuses on practical cryptography for security testing and CTFs: recognizing common patterns, selecting suitable tools, and applying known attacks.

For techniques that hide data inside files, see the **Stego** section.

## How to use this section

Start by identifying the primitive and its parameters. Then determine what the attacker controls or observes, such as an oracle, a leaked value, or nonce reuse, before selecting an attack.

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

Create an isolated Python environment and install commonly used packages. PyCryptodome's documentation recommends installing `pycryptodome` with `pip`; SageMath provides separate installation guidance for each supported platform.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install pycryptodome gmpy2 sympy pwntools
```

SageMath is often useful for algebraic, lattice, RSA, and elliptic-curve calculations.<sup>[[2]](#references)</sup>

## References

- [1] [PyCryptodome documentation - Installation](https://www.pycryptodome.org/src/installation)
- [2] [SageMath documentation - Installation guide](https://doc.sagemath.org/html/en/installation/)

{{#include ../banners/hacktricks-training.md}}
