# क्रिप्टो

{{#include ../banners/hacktricks-training.md}}

यह section security testing और CTFs के लिए practical cryptography पर केंद्रित है: आम patterns पहचानना, उपयुक्त tools चुनना और ज्ञात attacks लागू करना।

फ़ाइलों के अंदर data छिपाने की techniques के लिए **Stego** section देखें।

## इस section का उपयोग कैसे करें

सबसे पहले primitive और उसके parameters पहचानें। फिर attack चुनने से पहले तय करें कि attacker किन चीज़ों को नियंत्रित या देख सकता है, जैसे oracle, leaked value या nonce reuse।

### CTF workflow

{{#ref}}
ctf-workflow/README.md
{{#endref}}

### Symmetric cryptography

{{#ref}}
symmetric/README.md
{{#endref}}

### Hashes, MACs और KDFs

{{#ref}}
hashes/README.md
{{#endref}}

### Public-key cryptography

{{#ref}}
public-key/README.md
{{#endref}}

### TLS और certificates

{{#ref}}
tls-and-certificates/README.md
{{#endref}}

### Malware में cryptography

{{#ref}}
crypto-in-malware/README.md
{{#endref}}

### विविध

{{#ref}}
ctf-misc/README.md
{{#endref}}

## Quick setup

एक isolated Python environment बनाएँ और आमतौर पर इस्तेमाल होने वाले packages install करें। PyCryptodome का documentation, `pip` से `pycryptodome` install करने की सलाह देता है; SageMath हर supported platform के लिए अलग installation guidance देता है।<sup>[[1]](#references)[[2]](#references)</sup>

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install pycryptodome gmpy2 sympy pwntools
```

SageMath अक्सर algebraic, lattice, RSA और elliptic-curve की गणनाओं के लिए उपयोगी है।<sup>[[2]](#references)</sup>

## References

- [1] [PyCryptodome दस्तावेज़ - इंस्टॉलेशन](https://www.pycryptodome.org/src/installation)
- [2] [SageMath दस्तावेज़ - इंस्टॉलेशन गाइड](https://doc.sagemath.org/html/en/installation/)
{{#include ../banners/hacktricks-training.md}}
