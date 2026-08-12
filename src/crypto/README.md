# Crypto

{{#include ../banners/hacktricks-training.md}}

Questa sezione si concentra sulla crittografia pratica per i security testing e i CTF: riconoscere i pattern comuni, selezionare gli strumenti adatti e applicare gli attacchi noti.

Per le tecniche che nascondono dati all'interno dei file, consulta la sezione **Stego**.

## Come usare questa sezione

Inizia identificando la primitiva e i relativi parametri. Determina quindi cosa può controllare o osservare l'attaccante, ad esempio un oracle, un valore leaked o il riutilizzo di un nonce, prima di selezionare un attacco.

### Workflow per i CTF

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

### Crittografia nei malware

{{#ref}}
crypto-in-malware/README.md
{{#endref}}

### Varie

{{#ref}}
ctf-misc/README.md
{{#endref}}

## Configurazione rapida

Crea un ambiente Python isolato e installa i pacchetti comunemente utilizzati. La documentazione di PyCryptodome consiglia di installare `pycryptodome` con `pip`; SageMath fornisce istruzioni di installazione separate per ogni piattaforma supportata.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install pycryptodome gmpy2 sympy pwntools
```
SageMath è spesso utile per i calcoli algebrici, reticolari, RSA e sulle curve ellittiche.<sup>[[2]](#references)</sup>

## References

- [1] [Documentazione di PyCryptodome - Installazione](https://www.pycryptodome.org/src/installation)
- [2] [Documentazione di SageMath - Guida all'installazione](https://doc.sagemath.org/html/en/installation/)
{{#include ../banners/hacktricks-training.md}}
