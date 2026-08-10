# DNSCat pcap 분석

암호화를 사용하지 않고 **DNSCat으로 exfiltration된 데이터**가 포함된 PCAP이 있다면, exfiltration된 콘텐츠를 복구할 수 있습니다.

아래에 참조된 BSidesSF 2017 capture의 write-up에서는 각 decoded query가 전송된 콘텐츠 앞에 9바이트의 dnscat-specific data로 시작한다고 추정했습니다. dnscat2는 서로 다른 packet type과 header layout을 정의하므로, 이 offset을 다른 traffic에 적용하기 전에 관련 framing을 확인해야 합니다.<sup>[[1]](#references)[[2]](#references)</sup>
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
자세한 내용은 [BSidesSF 2017 write-up](https://github.com/jrmdev/ctf-writeups/tree/master/bsidessf-2017/dnscap)과 [dnscat2 protocol documentation](https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md)을 참조하세요.

[DNScat-Decoder](https://github.com/josemlwdf/DNScat-Decoder) repository는 지정된 domain에 대한 DNS queries를 filtering하여 PCAP에서 streams를 추출하는 Python 3 decoder를 제공합니다.<sup>[[3]](#references)</sup>
```
python3 dnscat_decoder.py sample.pcap bad_domain
```
## References

- [1] [dnscat2 protocol documentation](https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md)
- [2] [DNSCat2 pcap 포렌식 분석 문서 - BSidesSF 2017 CTF](https://github.com/jrmdev/ctf-writeups/tree/master/bsidessf-2017/dnscap)
- [3] [DNScat-Decoder](https://github.com/josemlwdf/DNScat-Decoder)
{{#include ../../../banners/hacktricks-training.md}}
