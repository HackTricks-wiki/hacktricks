# Crypto

{{#include ../banners/hacktricks-training.md}}

Esta sección se centra en **criptografía práctica para hacking/CTFs**: cómo reconocer rápidamente patrones comunes, elegir las herramientas adecuadas y aplicar ataques conocidos.

If you're here for hiding data inside files, go to the **Stego** section.

## Cómo usar esta sección

Crypto challenges reward speed: classify the primitive, identify what you control (oracle/leak/nonce reuse), then apply a known attack template.

### Flujo de trabajo CTF
{{#ref}}
ctf-workflow/README.md
{{#endref}}

### Criptografía simétrica
{{#ref}}
symmetric/README.md
{{#endref}}

### Hashes, MACs y KDFs
{{#ref}}
hashes/README.md
{{#endref}}

### Criptografía de clave pública
{{#ref}}
public-key/README.md
{{#endref}}

### TLS y certificados
{{#ref}}
tls-and-certificates/README.md
{{#endref}}

### Crypto en malware
{{#ref}}
crypto-in-malware/README.md
{{#endref}}

### Varios
{{#ref}}
ctf-misc/README.md
{{#endref}}

## Configuración rápida

- Python: `python3 -m venv .venv && source .venv/bin/activate`
- Librerías: `pip install pycryptodome gmpy2 sympy pwntools`
- SageMath (a menudo esencial para lattice/RSA/ECC): https://www.sagemath.org/

{{#include ../banners/hacktricks-training.md}}
