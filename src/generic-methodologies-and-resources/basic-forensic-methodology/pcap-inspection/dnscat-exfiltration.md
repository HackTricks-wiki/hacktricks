# DNSCat pcap 分析

暗号化を使用せずに **DNSCat によって exfiltration されたデータ**を含む PCAP がある場合、exfiltration された内容を復元できる可能性があります。

以下で参照している BSidesSF 2017 の capture について、write-up では、decode された各 query が転送された content の前に dnscat 固有のデータを 9 バイト含んでいると推測しています。dnscat2 では異なる packet type と header layout が定義されているため、他の traffic にその offset を適用する前に、該当する framing を確認してください。<sup>[[1]](#references)[[2]](#references)</sup>
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
詳細については、[BSidesSF 2017 write-up](https://github.com/jrmdev/ctf-writeups/tree/master/bsidessf-2017/dnscap) および [dnscat2 protocol documentation](https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md) を参照してください。

[DNScat-Decoder](https://github.com/josemlwdf/DNScat-Decoder) repository には、指定した domain の DNS queries を filter することで、PCAP から streams を抽出する Python 3 decoder が用意されています。<sup>[[3]](#references)</sup>
```
python3 dnscat_decoder.py sample.pcap bad_domain
```
## References

- [1] [dnscat2 protocol documentation](https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md)
- [2] [DNSCat2 pcap forensics writeup – BSidesSF 2017 CTF](https://github.com/jrmdev/ctf-writeups/tree/master/bsidessf-2017/dnscap)
- [3] [DNScat-Decoder](https://github.com/josemlwdf/DNScat-Decoder)
{{#include ../../../banners/hacktricks-training.md}}
