# DNSCat pcap analysis

{{#include ../../../banners/hacktricks-training.md}}

暗号化を使用せずに **DNSCat によってデータが exfiltration されている** pcap がある場合、exfiltration されたコンテンツを見つけることができます。

知っておく必要があるのは、**最初の 9 バイト**は実際のデータではなく、**C\&C 通信**に関連するものだということだけです。<sup>[[1]](#references)</sup>
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
詳細については、[https://github.com/jrmdev/ctf-writeups/tree/master/bsidessf-2017/dnscap](https://github.com/jrmdev/ctf-writeups/tree/master/bsidessf-2017/dnscap)<sup>[[1]](#references)</sup>\
[https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md](https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md)

Python3で動作するscriptがあります: [https://github.com/josemlwdf/DNScat-Decoder](https://github.com/josemlwdf/DNScat-Decoder)
```
python3 dnscat_decoder.py sample.pcap bad_domain
```
## 参考文献

- [1] [DNSCat2 pcapフォレンジック解析記事 – BSidesSF 2017 CTF](https://github.com/jrmdev/ctf-writeups/tree/master/bsidessf-2017/dnscap)

{{#include ../../../banners/hacktricks-training.md}}
