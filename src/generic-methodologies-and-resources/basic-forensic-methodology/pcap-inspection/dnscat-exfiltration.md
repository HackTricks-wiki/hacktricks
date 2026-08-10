# Uchambuzi wa DNSCat pcap

Ikiwa una PCAP yenye data inayofanyiwa **exfiltration na DNSCat** (bila kutumia encryption), unaweza kuweza kurejesha maudhui yaliyofanyiwa exfiltration.

Kwa capture ya BSidesSF 2017 iliyorejelewa hapa chini, write-up ilibaini kuwa kila query iliyodecodewa ilianza na bytes 9 za data maalum ya dnscat kabla ya maudhui yaliyohamishwa. Kwa kuwa dnscat2 inafafanua aina tofauti za packets na mipangilio ya headers, thibitisha framing husika kabla ya kutumia offset hiyo kwenye traffic nyingine.<sup>[[1]](#references)[[2]](#references)</sup>
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
Kwa maelezo zaidi, tazama [BSidesSF 2017 write-up](https://github.com/jrmdev/ctf-writeups/tree/master/bsidessf-2017/dnscap) na [dnscat2 protocol documentation](https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md).

Hazina ya [DNScat-Decoder](https://github.com/josemlwdf/DNScat-Decoder) hutoa decoder ya Python 3 inayotoa streams kutoka kwenye PCAP kwa kuchuja DNS queries za domain maalum.<sup>[[3]](#references)</sup>
```
python3 dnscat_decoder.py sample.pcap bad_domain
```
## References

- [1] [nyaraka za itifaki ya dnscat2](https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md)
- [2] [Maelezo ya uchunguzi wa pcap wa DNSCat2 – CTF ya BSidesSF 2017](https://github.com/jrmdev/ctf-writeups/tree/master/bsidessf-2017/dnscap)
- [3] [DNScat-Decoder](https://github.com/josemlwdf/DNScat-Decoder)
{{#include ../../../banners/hacktricks-training.md}}
