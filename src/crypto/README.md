# Crypto

{{#include ../banners/hacktricks-training.md}}

Esta seção foca em **practical cryptography for hacking/CTFs**: como reconhecer rapidamente padrões comuns, escolher as ferramentas certas e aplicar ataques conhecidos.

Se você está aqui para esconder dados dentro de arquivos, vá para a seção **Stego**.

## Como usar esta seção

Crypto challenges recompensam velocidade: classifique a primitiva, identifique o que você controla (oracle/leak/nonce reuse), e então aplique um template de ataque conhecido.

### Fluxo de trabalho CTF
{{#ref}}
ctf-workflow/README.md
{{#endref}}

### Crypto simétrico
{{#ref}}
symmetric/README.md
{{#endref}}

### Hashes, MACs e KDFs
{{#ref}}
hashes/README.md
{{#endref}}

### Crypto de chave pública
{{#ref}}
public-key/README.md
{{#endref}}

### TLS e certificados
{{#ref}}
tls-and-certificates/README.md
{{#endref}}

### Crypto em malware
{{#ref}}
crypto-in-malware/README.md
{{#endref}}

### Diversos
{{#ref}}
ctf-misc/README.md
{{#endref}}

## Configuração rápida

- Python: `python3 -m venv .venv && source .venv/bin/activate`
- Bibliotecas: `pip install pycryptodome gmpy2 sympy pwntools`
- SageMath (frequentemente essencial para lattice/RSA/ECC): https://www.sagemath.org/

{{#include ../banners/hacktricks-training.md}}
