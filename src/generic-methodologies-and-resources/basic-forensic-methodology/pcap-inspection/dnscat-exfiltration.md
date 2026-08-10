# DNSCat pcap analizi

**DNSCat** tarafından (şifreleme kullanılmadan) **exfiltrated** edilen verileri içeren bir PCAP dosyanız varsa, exfiltrated içeriği kurtarmanız mümkün olabilir.

Aşağıda referans verilen BSidesSF 2017 capture için write-up, decode edilen her query'nin aktarılan içerikten önce dnscat'e özgü 9 byte veriyle başladığını ortaya koymuştur. dnscat2 farklı packet türleri ve header düzenleri tanımladığından, bu offset'i diğer traffic üzerinde uygulamadan önce ilgili framing'i doğrulayın.<sup>[[1]](#references)[[2]](#references)</sup>
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
Daha fazla bilgi için [BSidesSF 2017 write-up](https://github.com/jrmdev/ctf-writeups/tree/master/bsidessf-2017/dnscap) ve [dnscat2 protocol documentation](https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md) sayfalarına bakın.

[DNScat-Decoder](https://github.com/josemlwdf/DNScat-Decoder) repository'si, belirtilen bir domain için DNS sorgularını filtreleyerek PCAP'ten akışları çıkaran bir Python 3 decoder sağlar.<sup>[[3]](#references)</sup>
```
python3 dnscat_decoder.py sample.pcap bad_domain
```
## References

- [1] [dnscat2 protokol dokümantasyonu](https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md)
- [2] [DNSCat2 pcap adli inceleme yazısı – BSidesSF 2017 CTF](https://github.com/jrmdev/ctf-writeups/tree/master/bsidessf-2017/dnscap)
- [3] [DNScat-Decoder](https://github.com/josemlwdf/DNScat-Decoder)
{{#include ../../../banners/hacktricks-training.md}}
