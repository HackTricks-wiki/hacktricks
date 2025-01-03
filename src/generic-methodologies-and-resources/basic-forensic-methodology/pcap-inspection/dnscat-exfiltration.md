# DNSCat pcap विश्लेषण

{{#include ../../../banners/hacktricks-training.md}}

यदि आपके पास **DNSCat द्वारा डेटा का exfiltrated** (बिना एन्क्रिप्शन का उपयोग किए) के साथ pcap है, तो आप exfiltrated सामग्री को ढूंढ सकते हैं।

आपको केवल यह जानने की आवश्यकता है कि **पहले 9 बाइट्स** वास्तविक डेटा नहीं हैं बल्कि **C\&C संचार** से संबंधित हैं:
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
अधिक जानकारी के लिए: [https://github.com/jrmdev/ctf-writeups/tree/master/bsidessf-2017/dnscap](https://github.com/jrmdev/ctf-writeups/tree/master/bsidessf-2017/dnscap)\
[https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md](https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md)

एक स्क्रिप्ट है जो Python3 के साथ काम करती है: [https://github.com/josemlwdf/DNScat-Decoder](https://github.com/josemlwdf/DNScat-Decoder)
```
python3 dnscat_decoder.py sample.pcap bad_domain
```
{{#include ../../../banners/hacktricks-training.md}}
