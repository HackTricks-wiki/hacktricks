# DNSCat pcap analizi

{{#include ../../../banners/hacktricks-training.md}}

Eğer şifreleme kullanmadan **DNSCat** ile **sızdırılan** verilerin olduğu bir pcap dosyanız varsa, sızdırılan içeriği bulabilirsiniz.

Sadece **ilk 9 baytın** gerçek veri olmadığını ve **C\&C iletişimi** ile ilgili olduğunu bilmeniz yeterlidir:
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
Daha fazla bilgi için: [https://github.com/jrmdev/ctf-writeups/tree/master/bsidessf-2017/dnscap](https://github.com/jrmdev/ctf-writeups/tree/master/bsidessf-2017/dnscap)\
[https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md](https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md)

Python3 ile çalışan bir script bulunmaktadır: [https://github.com/josemlwdf/DNScat-Decoder](https://github.com/josemlwdf/DNScat-Decoder)
```
python3 dnscat_decoder.py sample.pcap bad_domain
```
{{#include ../../../banners/hacktricks-training.md}}
