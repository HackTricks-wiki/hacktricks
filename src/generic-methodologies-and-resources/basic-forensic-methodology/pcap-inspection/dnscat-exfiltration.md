# DNSCat pcap analiza

Ako imate PCAP sa podacima koje **DNSCat eksfiltrira** (bez korišćenja encryption-a), možda ćete moći da povratite eksfiltrirani sadržaj.

Za capture sa BSidesSF 2017 naveden ispod, u analizi je zaključeno da je svaki dekodirani upit počinjao sa 9 bajtova dnscat-specifičnih podataka pre prenetog sadržaja. Pošto dnscat2 definiše različite tipove paketa i layout-e zaglavlja, proverite relevantni framing pre nego što taj offset primenite na drugi traffic.<sup>[[1]](#references)[[2]](#references)</sup>
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
Za više informacija pogledajte [BSidesSF 2017 write-up](https://github.com/jrmdev/ctf-writeups/tree/master/bsidessf-2017/dnscap) i [dnscat2 protocol documentation](https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md).

Repozitorijum [DNScat-Decoder](https://github.com/josemlwdf/DNScat-Decoder) pruža decoder za Python 3 koji izdvaja stream-ove iz PCAP-a filtriranjem DNS upita za navedeni domen.<sup>[[3]](#references)</sup>
```
python3 dnscat_decoder.py sample.pcap bad_domain
```
## References

- [1] [dokumentacija dnscat2 protokola](https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md)
- [2] [forenzički writeup DNSCat2 pcap-a – BSidesSF 2017 CTF](https://github.com/jrmdev/ctf-writeups/tree/master/bsidessf-2017/dnscap)
- [3] [DNScat-Decoder](https://github.com/josemlwdf/DNScat-Decoder)
{{#include ../../../banners/hacktricks-training.md}}
