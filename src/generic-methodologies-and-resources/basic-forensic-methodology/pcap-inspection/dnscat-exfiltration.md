# DNSCat pcap 분석

{{#include ../../../banners/hacktricks-training.md}}

DNSCat에 의해 **유출된 데이터**가 포함된 pcap 파일이 있다면 (암호화를 사용하지 않고), 유출된 내용을 찾을 수 있습니다.

**첫 9 바이트**는 실제 데이터가 아니라 **C\&C 통신**과 관련이 있다는 것만 알면 됩니다:
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
자세한 정보는 다음을 참조하세요: [https://github.com/jrmdev/ctf-writeups/tree/master/bsidessf-2017/dnscap](https://github.com/jrmdev/ctf-writeups/tree/master/bsidessf-2017/dnscap)\
[https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md](https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md)

Python3와 함께 작동하는 스크립트가 있습니다: [https://github.com/josemlwdf/DNScat-Decoder](https://github.com/josemlwdf/DNScat-Decoder)
```
python3 dnscat_decoder.py sample.pcap bad_domain
```
{{#include ../../../banners/hacktricks-training.md}}
