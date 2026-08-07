# Criptografia

{{#include ../banners/hacktricks-training.md}}

Esta seção se concentra em **criptografia prática para hacking/CTFs**: como reconhecer rapidamente padrões comuns, escolher as ferramentas certas e aplicar ataques conhecidos.

Se você está aqui para ocultar dados dentro de arquivos, acesse a seção **Stego**.

## Como usar esta seção

Os desafios de Crypto recompensam a velocidade: classifique a primitiva, identifique o que você controla (oracle/leak/reutilização de nonce) e aplique um modelo de ataque conhecido.

### Fluxo de trabalho de CTF
{{#ref}}
ctf-workflow/README.md
{{#endref}}

### Criptografia simétrica
{{#ref}}
symmetric/README.md
{{#endref}}

### Hashes, MACs e KDFs
{{#ref}}
hashes/README.md
{{#endref}}

### Criptografia de chave pública
{{#ref}}
public-key/README.md
{{#endref}}

### TLS e certificados
{{#ref}}
tls-and-certificates/README.md
{{#endref}}

### Criptografia em malware
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
- SageMath (frequentemente essencial para lattice/RSA/ECC): <https://www.sagemath.org/>

{{#include ../banners/hacktricks-training.md}}
