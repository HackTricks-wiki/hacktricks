# DNSCat pcap analysis

यदि आपके पास **DNSCat द्वारा exfiltrate किए गए data** वाला PCAP है (encryption का उपयोग किए बिना), तो संभव है कि आप exfiltrate किए गए content को recover कर सकें।

नीचे संदर्भित BSidesSF 2017 capture के लिए, write-up में अनुमान लगाया गया था कि प्रत्येक decoded query transferred content से पहले 9 bytes का dnscat-specific data शुरू करती थी। क्योंकि dnscat2 अलग-अलग packet types और header layouts define करता है, इसलिए उस offset को अन्य traffic पर लागू करने से पहले संबंधित framing को verify करें।<sup>[[1]](#references)[[2]](#references)</sup>
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
अधिक जानकारी के लिए [BSidesSF 2017 write-up](https://github.com/jrmdev/ctf-writeups/tree/master/bsidessf-2017/dnscap) और [dnscat2 protocol documentation](https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md) देखें।

[DNScat-Decoder](https://github.com/josemlwdf/DNScat-Decoder) repository एक Python 3 decoder प्रदान करती है, जो निर्दिष्ट domain के लिए DNS queries को filter करके PCAP से streams extract करता है।<sup>[[3]](#references)</sup>
```
python3 dnscat_decoder.py sample.pcap bad_domain
```
## References

- [1] [dnscat2 protocol documentation](https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md)
- [2] [DNSCat2 pcap forensics writeup – BSidesSF 2017 CTF](https://github.com/jrmdev/ctf-writeups/tree/master/bsidessf-2017/dnscap)
- [3] [DNScat-Decoder](https://github.com/josemlwdf/DNScat-Decoder)
{{#include ../../../banners/hacktricks-training.md}}
