# Uchambuzi wa DNSCat pcap

{{#include ../../../banners/hacktricks-training.md}}

Ikiwa una PCAP yenye data **iliyo-exfiltrated na DNSCat** (bila kutumia encryption), huenda ukaweza kurejesha maudhui yaliyo-exfiltrated.

Kwa capture ya BSidesSF 2017 iliyorejelewa hapa chini, write-up ilihitimisha kuwa kila query iliyodecodewa ilianza na bytes 9 za data maalum ya dnscat kabla ya maudhui yaliyohamishwa. Kwa sababu dnscat2 hufafanua aina tofauti za pakiti na miundo ya header, thibitisha framing husika kabla ya kutumia offset hiyo kwenye traffic nyingine.<sup>[[1]](#references)[[2]](#references)</sup>
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
Kwa maelezo zaidi, tazama [maelezo ya BSidesSF 2017](https://github.com/jrmdev/ctf-writeups/tree/master/bsidessf-2017/dnscap) na [hati za protocol ya dnscat2](https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md).

Repository ya [DNScat-Decoder](https://github.com/josemlwdf/DNScat-Decoder) hutoa decoder ya Python 3 inayotoa streams kutoka kwenye PCAP kwa kuchuja DNS queries za domain iliyobainishwa.<sup>[[3]](#references)</sup>
```
python3 dnscat_decoder.py sample.pcap bad_domain
```
## References

- [1] [Nyaraka za itifaki ya dnscat2](https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md)
- [2] [Maelezo ya forensics ya pcap ya DNSCat2 – BSidesSF 2017 CTF](https://github.com/jrmdev/ctf-writeups/tree/master/bsidessf-2017/dnscap)
- [3] [DNScat-Decoder](https://github.com/josemlwdf/DNScat-Decoder)
{{#include ../../../banners/hacktricks-training.md}}
