# DNSCat pcap 分析

{{#include ../../../banners/hacktricks-training.md}}

如果你有一份包含通过 **DNSCat exfiltration** 的数据的 pcap（未使用 encryption），就可以找到被 exfiltrated 的内容。

你只需要知道，**前 9 个字节** 不是真实数据，而是与 **C\&C communication** 相关：<sup>[[1]](#references)</sup>
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
更多信息：[https://github.com/jrmdev/ctf-writeups/tree/master/bsidessf-2017/dnscap](https://github.com/jrmdev/ctf-writeups/tree/master/bsidessf-2017/dnscap)\
[https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md](https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md)

有一个适用于 Python3 的脚本：[https://github.com/josemlwdf/DNScat-Decoder](https://github.com/josemlwdf/DNScat-Decoder)
```
python3 dnscat_decoder.py sample.pcap bad_domain
```
## 参考资料

- [1] [DNSCat2 pcap 取证分析 – BSidesSF 2017 CTF](https://github.com/jrmdev/ctf-writeups/tree/master/bsidessf-2017/dnscap)

{{#include ../../../banners/hacktricks-training.md}}
