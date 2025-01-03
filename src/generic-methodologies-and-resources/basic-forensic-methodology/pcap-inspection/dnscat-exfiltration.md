# DNSCat pcap analiza

{{#include ../../../banners/hacktricks-training.md}}

Ako imate pcap sa podacima koji se **ekstrahuju putem DNSCat** (bez korišćenja enkripcije), možete pronaći ekstrahovani sadržaj.

Samo treba da znate da su **prvih 9 bajtova** lažni podaci, već su povezani sa **C\&C komunikacijom**:
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
Za više informacija: [https://github.com/jrmdev/ctf-writeups/tree/master/bsidessf-2017/dnscap](https://github.com/jrmdev/ctf-writeups/tree/master/bsidessf-2017/dnscap)\
[https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md](https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md)

Postoji skripta koja radi sa Python3: [https://github.com/josemlwdf/DNScat-Decoder](https://github.com/josemlwdf/DNScat-Decoder)
```
python3 dnscat_decoder.py sample.pcap bad_domain
```
{{#include ../../../banners/hacktricks-training.md}}
