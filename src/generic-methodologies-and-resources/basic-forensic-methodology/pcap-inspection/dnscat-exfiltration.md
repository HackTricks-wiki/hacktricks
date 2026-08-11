# DNSCat pcap 分析

{{#include ../../../banners/hacktricks-training.md}}

如果你有一个包含通过 **DNSCat**（未使用加密）**exfiltrated** 数据的 PCAP，可能可以恢复被 **exfiltrated** 的内容。

对于下方引用的 BSidesSF 2017 capture，相关 write-up 推断每个 decoded query 的开头包含 9 字节的 dnscat-specific 数据，之后才是传输的内容。由于 dnscat2 定义了不同的 packet types 和 header layouts，因此在将该 offset 应用于其他 traffic 之前，请先验证相关的 framing。<sup>[[1]](#references)[[2]](#references)</sup>
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
如需更多信息，请参阅 [BSidesSF 2017 write-up](https://github.com/jrmdev/ctf-writeups/tree/master/bsidessf-2017/dnscap) 和 [dnscat2 protocol documentation](https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md)。

[DNScat-Decoder](https://github.com/josemlwdf/DNScat-Decoder) repository 提供了一个 Python 3 decoder，可通过筛选指定 domain 的 DNS queries，从 PCAP 中提取 streams。<sup>[[3]](#references)</sup>
```
python3 dnscat_decoder.py sample.pcap bad_domain
```
## References

- [1] [dnscat2 协议文档](https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md)
- [2] [DNSCat2 pcap 取证分析 – BSidesSF 2017 CTF](https://github.com/jrmdev/ctf-writeups/tree/master/bsidessf-2017/dnscap)
- [3] [DNScat-Decoder](https://github.com/josemlwdf/DNScat-Decoder)
{{#include ../../../banners/hacktricks-training.md}}
