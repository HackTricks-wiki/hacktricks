# DNSCat pcap analizi

{{#include ../../../banners/hacktricks-training.md}}

DNSCat tarafından **exfiltrated** edilen (şifreleme kullanılmadan) verileri içeren bir PCAP dosyanız varsa, exfiltrated içeriği kurtarmanız mümkün olabilir.

Aşağıda referans verilen BSidesSF 2017 capture için hazırlanan write-up, decode edilen her sorgunun aktarılan içerikten önce dnscat'e özgü 9 byte veriyle başladığı sonucuna varmıştır. dnscat2 farklı packet türleri ve header düzenleri tanımladığından, bu offset'i diğer traffic için uygulamadan önce ilgili framing yapısını doğrulayın.<sup>[[1]](#references)[[2]](#references)</sup>
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

[DNScat-Decoder](https://github.com/josemlwdf/DNScat-Decoder) repository'si, DNS sorgularını belirtilen bir domain için filtreleyerek bir PCAP'ten stream'leri çıkaran bir Python 3 decoder sağlar.<sup>[[3]](#references)</sup>
```
python3 dnscat_decoder.py sample.pcap bad_domain
```
## References

- [1] [dnscat2 protocol documentation](https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md)
- [2] [DNSCat2 pcap adli inceleme yazısı – BSidesSF 2017 CTF](https://github.com/jrmdev/ctf-writeups/tree/master/bsidessf-2017/dnscap)
- [3] [DNScat-Decoder](https://github.com/josemlwdf/DNScat-Decoder)
{{#include ../../../banners/hacktricks-training.md}}
