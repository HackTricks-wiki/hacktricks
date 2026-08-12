# क्रिप्टो

{{#include ../banners/hacktricks-training.md}}

यह section security testing और CTFs के लिए practical cryptography पर केंद्रित है: common patterns पहचानना, उपयुक्त tools चुनना और ज्ञात attacks लागू करना।

Files के अंदर data छिपाने वाली techniques के लिए **Stego** section देखें।

## इस section का उपयोग कैसे करें

Primitive और उसके parameters की पहचान करके शुरुआत करें। फिर यह निर्धारित करें कि attacker किस चीज़ को control या observe करता है, जैसे कि oracle, leaked value या nonce reuse, और उसके बाद attack चुनें।

### CTF workflow

{{#ref}}
ctf-workflow/README.md
{{#endref}}

### Symmetric cryptography

{{#ref}}
symmetric/README.md
{{#endref}}

### Hashes, MACs, और KDFs

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

## त्वरित setup

एक isolated Python environment बनाएँ और commonly used packages install करें। PyCryptodome का documentation `pip` के साथ `pycryptodome` install करने की recommendation देता है; SageMath प्रत्येक supported platform के लिए अलग installation guidance प्रदान करता है।<sup>[[1]](#references)[[2]](#references)</sup>
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install pycryptodome gmpy2 sympy pwntools
```
SageMath अक्सर बीजगणितीय, lattice, RSA और elliptic-curve गणनाओं के लिए उपयोगी होता है।<sup>[[2]](#references)</sup>

## References

- [1] [PyCryptodome दस्तावेज़ीकरण - स्थापना](https://www.pycryptodome.org/src/installation)
- [2] [SageMath दस्तावेज़ीकरण - स्थापना मार्गदर्शिका](https://doc.sagemath.org/html/en/installation/)
{{#include ../banners/hacktricks-training.md}}
