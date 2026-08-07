# Criptografía

{{#include ../banners/hacktricks-training.md}}

Esta sección se centra en la **criptografía práctica para hacking/CTFs**: cómo reconocer rápidamente patrones comunes, elegir las herramientas adecuadas y aplicar ataques conocidos.

Si estás aquí para ocultar datos dentro de archivos, ve a la sección **Stego**.

## Cómo usar esta sección

Los desafíos de Crypto recompensan la velocidad: clasifica la primitive, identifica qué controlas (oracle/leak/nonce reuse) y aplica una plantilla de ataque conocida.

### Flujo de trabajo de CTF
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

### Criptografía en malware
{{#ref}}
crypto-in-malware/README.md
{{#endref}}

### Miscelánea
{{#ref}}
ctf-misc/README.md
{{#endref}}

## Configuración rápida

- Python: `python3 -m venv .venv && source .venv/bin/activate`
- Librerías: `pip install pycryptodome gmpy2 sympy pwntools`
- SageMath (a menudo esencial para lattice/RSA/ECC): <https://www.sagemath.org/>

{{#include ../banners/hacktricks-training.md}}
