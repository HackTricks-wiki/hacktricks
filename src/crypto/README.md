# Crypto

{{#include ../banners/hacktricks-training.md}}

Questa sezione si concentra sulla **crittografia pratica per hacking/CTFs**: come riconoscere rapidamente i pattern comuni, scegliere gli strumenti giusti e applicare attacchi noti.

Se sei qui per nascondere dati all'interno di file, vai alla sezione **Stego**.

## Come usare questa sezione

Le sfide Crypto premiano la velocità: classifica la primitiva, identifica cosa controlli (oracle/leak/nonce reuse), poi applica un template di attacco noto.

### Flusso di lavoro CTF
{{#ref}}
ctf-workflow/README.md
{{#endref}}

### Crittografia simmetrica
{{#ref}}
symmetric/README.md
{{#endref}}

### Hash, MAC e KDF
{{#ref}}
hashes/README.md
{{#endref}}

### Crittografia a chiave pubblica
{{#ref}}
public-key/README.md
{{#endref}}

### TLS e certificati
{{#ref}}
tls-and-certificates/README.md
{{#endref}}

### Crypto nel malware
{{#ref}}
crypto-in-malware/README.md
{{#endref}}

### Varie
{{#ref}}
ctf-misc/README.md
{{#endref}}

## Configurazione rapida

- Python: `python3 -m venv .venv && source .venv/bin/activate`
- Libraries: `pip install pycryptodome gmpy2 sympy pwntools`
- SageMath (spesso essenziale per lattice/RSA/ECC): https://www.sagemath.org/

{{#include ../banners/hacktricks-training.md}}
