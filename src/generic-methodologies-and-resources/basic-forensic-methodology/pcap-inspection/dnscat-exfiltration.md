# DNSCat pcap 分析

{{#include ../../../banners/hacktricks-training.md}}

**DNSCat によって exfiltration されたデータ**（暗号化を使用していない場合）を含む PCAP がある場合、exfiltration された内容を復元できる可能性があります。

以下で参照されている BSidesSF 2017 の capture については、write-up で、各 decoded query の先頭には転送された内容の前に dnscat 固有のデータが 9 バイト含まれていると推測されています。dnscat2 では異なる packet type と header layout が定義されているため、他の traffic にこの offset を適用する前に、該当する framing を確認してください。<sup>[[1]](#references)[[2]](#references)</sup>
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
詳細については、[BSidesSF 2017 write-up](https://github.com/jrmdev/ctf-writeups/tree/master/bsidessf-2017/dnscap)および[dnscat2 protocol documentation](https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md)を参照してください。

[DNScat-Decoder](https://github.com/josemlwdf/DNScat-Decoder) repositoryは、指定したドメインのDNSクエリをフィルタリングして、PCAPからstreamsを抽出するPython 3 decoderを提供します。<sup>[[3]](#references)</sup>
```
python3 dnscat_decoder.py sample.pcap bad_domain
```
## References

- [1] [dnscat2 protocol ドキュメント](https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md)
- [2] [DNSCat2 pcap forensics writeup – BSidesSF 2017 CTF](https://github.com/jrmdev/ctf-writeups/tree/master/bsidessf-2017/dnscap)
- [3] [DNScat-Decoder](https://github.com/josemlwdf/DNScat-Decoder)
{{#include ../../../banners/hacktricks-training.md}}
