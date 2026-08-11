# DNSCat pcap analiza

{{#include ../../../banners/hacktricks-training.md}}

Ako imate PCAP sa podacima koji su **ekfiltrirani pomoću DNSCat-a** (bez korišćenja enkripcije), možda ćete moći da povratite ekfiltrirani sadržaj.

Za snimak BSidesSF 2017 naveden u nastavku, u analizi je zaključeno da je svaki dekodirani upit počinjao sa 9 bajtova podataka specifičnih za dnscat, pre prenetog sadržaja. Pošto dnscat2 definiše različite tipove paketa i rasporede zaglavlja, proverite relevantno uokviravanje pre primene tog pomaka na drugi saobraćaj.<sup>[[1]](#references)[[2]](#references)</sup>
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

Repository [DNScat-Decoder](https://github.com/josemlwdf/DNScat-Decoder) obezbeđuje decoder za Python 3 koji izdvaja streamove iz PCAP-a filtriranjem DNS upita za navedeni domen.<sup>[[3]](#references)</sup>
```
python3 dnscat_decoder.py sample.pcap bad_domain
```
## References

- [1] [dnscat2 dokumentacija protokola](https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md)
- [2] [DNSCat2 pcap forenzički prikaz – BSidesSF 2017 CTF](https://github.com/jrmdev/ctf-writeups/tree/master/bsidessf-2017/dnscap)
- [3] [DNScat-Decoder](https://github.com/josemlwdf/DNScat-Decoder)
{{#include ../../../banners/hacktricks-training.md}}
