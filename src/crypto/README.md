# Crypto

{{#include ../banners/hacktricks-training.md}}

This section focuses on **practical cryptography for hacking/CTFs**: how to quickly recognize common patterns, pick the right tools, and apply known attacks.

यदि आप फ़ाइलों के अंदर डेटा छिपाने के लिए यहाँ हैं, तो **Stego** सेक्शन पर जाएँ।

## इस अनुभाग का उपयोग कैसे करें

Crypto चुनौतियाँ तेजी को पुरस्कृत करती हैं: क्रिप्टोग्राफिक primitive को वर्गीकृत करें, यह पहचानें कि आप क्या नियंत्रित करते हैं (oracle/leak/nonce reuse), और फिर किसी ज्ञात attack template को लागू करें।

### CTF workflow
{{#ref}}
ctf-workflow/README.md
{{#endref}}

### Symmetric crypto
{{#ref}}
symmetric/README.md
{{#endref}}

### Hashes, MACs, and KDFs
{{#ref}}
hashes/README.md
{{#endref}}

### Public-key crypto
{{#ref}}
public-key/README.md
{{#endref}}

### TLS and certificates
{{#ref}}
tls-and-certificates/README.md
{{#endref}}

### Crypto in malware
{{#ref}}
crypto-in-malware/README.md
{{#endref}}

### Misc
{{#ref}}
ctf-misc/README.md
{{#endref}}

## त्वरित सेटअप

- Python: `python3 -m venv .venv && source .venv/bin/activate`
- Libraries: `pip install pycryptodome gmpy2 sympy pwntools`
- SageMath (अक्सर lattice/RSA/ECC के लिए आवश्यक): https://www.sagemath.org/

{{#include ../banners/hacktricks-training.md}}
