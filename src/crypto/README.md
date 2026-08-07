# क्रिप्टो

{{#include ../banners/hacktricks-training.md}}

यह section **hacking/CTFs के लिए practical cryptography** पर केंद्रित है: common patterns को जल्दी पहचानना, सही tools चुनना और ज्ञात attacks लागू करना।

यदि आप files के अंदर data छिपाने के लिए यहां आए हैं, तो **Stego** section पर जाएं।

## इस section का उपयोग कैसे करें

Crypto challenges speed को पुरस्कृत करते हैं: primitive को classify करें, पहचानें कि आपके नियंत्रण में क्या है (oracle/leak/nonce reuse), फिर किसी ज्ञात attack template को लागू करें।

### CTF workflow
{{#ref}}
ctf-workflow/README.md
{{#endref}}

### Symmetric crypto
{{#ref}}
symmetric/README.md
{{#endref}}

### Hashes, MACs, और KDFs
{{#ref}}
hashes/README.md
{{#endref}}

### Public-key crypto
{{#ref}}
public-key/README.md
{{#endref}}

### TLS और certificates
{{#ref}}
tls-and-certificates/README.md
{{#endref}}

### Malware में crypto
{{#ref}}
crypto-in-malware/README.md
{{#endref}}

### Misc
{{#ref}}
ctf-misc/README.md
{{#endref}}

## Quick setup

- Python: `python3 -m venv .venv && source .venv/bin/activate`
- Libraries: `pip install pycryptodome gmpy2 sympy pwntools`
- SageMath (lattice/RSA/ECC के लिए अक्सर essential): <https://www.sagemath.org/>

{{#include ../banners/hacktricks-training.md}}
