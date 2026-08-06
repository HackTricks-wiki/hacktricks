# Аналіз pcap DNSCat

{{#include ../../../banners/hacktricks-training.md}}

Якщо у вас є pcap із даними, які **exfiltrated через DNSCat** (без використання шифрування), ви можете знайти exfiltrated вміст.

Потрібно лише знати, що **перші 9 байтів** не є реальними даними, а пов’язані з **C\&C communication**:<sup>[[1]](#references)</sup>
```python
from scapy.all import rdpcap, DNSQR, DNSRR
import struct

f = ""
last = ""
for p in rdpcap('ch21.pcap'):
if p.haslayer(DNSQR) and not p.haslayer(DNSRR):

qry = p[DNSQR].qname.replace(".jz-n-bs.local.","").strip().split(".")
qry = ''.join(_.decode('hex') for _ in qry)[9:]
if last != qry:
print(qry)
f += qry
last = qry

#print(f)
```
Для отримання додаткової інформації: [https://github.com/jrmdev/ctf-writeups/tree/master/bsidessf-2017/dnscap](https://github.com/jrmdev/ctf-writeups/tree/master/bsidessf-2017/dnscap)<sup>[[1]](#references)</sup>\
[https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md](https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md)

Існує script, який працює з Python3: [https://github.com/josemlwdf/DNScat-Decoder](https://github.com/josemlwdf/DNScat-Decoder)
```
python3 dnscat_decoder.py sample.pcap bad_domain
```
## Посилання

- [1] [Звіт з pcap-форензіки DNSCat2 — BSidesSF 2017 CTF](https://github.com/jrmdev/ctf-writeups/tree/master/bsidessf-2017/dnscap)

{{#include ../../../banners/hacktricks-training.md}}
