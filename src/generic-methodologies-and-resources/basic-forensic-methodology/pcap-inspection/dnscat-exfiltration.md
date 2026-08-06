# DNSCat pcap विश्लेषण

{{#include ../../../banners/hacktricks-training.md}}

यदि आपके पास **DNSCat द्वारा exfiltrate किया गया data** (encryption का उपयोग किए बिना) वाला pcap है, तो आप exfiltrate की गई सामग्री ढूंढ सकते हैं।

आपको केवल यह जानना आवश्यक है कि **पहले 9 bytes** वास्तविक data नहीं हैं, बल्कि **C\&C communication** से संबंधित हैं:<sup>[[1]](#references)</sup>
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

Python3 के साथ काम करने वाली एक script है: [https://github.com/josemlwdf/DNScat-Decoder](https://github.com/josemlwdf/DNScat-Decoder)
```
python3 dnscat_decoder.py sample.pcap bad_domain
```
## संदर्भ

- [1] [DNSCat2 pcap forensics writeup – BSidesSF 2017 CTF](https://github.com/jrmdev/ctf-writeups/tree/master/bsidessf-2017/dnscap)

{{#include ../../../banners/hacktricks-training.md}}
