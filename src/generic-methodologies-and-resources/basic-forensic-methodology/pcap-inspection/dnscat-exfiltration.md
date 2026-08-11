# DNSCat pcap-analise

{{#include ../../../banners/hacktricks-training.md}}

As jy ’n PCAP het met data wat **deur DNSCat geëksfiltreer word** (sonder encryption), kan jy moontlik die geëksfiltreerde inhoud herwin.

Vir die BSidesSF 2017-capture waarna hieronder verwys word, het die verslag afgelei dat elke gedekodeerde query met 9 grepe dnscat-spesifieke data begin het voordat die oorgedrade inhoud gevolg het. Omdat dnscat2 verskillende packet types en header-uitlegte definieer, moet jy die relevante framing verifieer voordat jy daardie offset op ander verkeer toepas.<sup>[[1]](#references)[[2]](#references)</sup>
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
Vir meer inligting, sien die [BSidesSF 2017 write-up](https://github.com/jrmdev/ctf-writeups/tree/master/bsidessf-2017/dnscap) en die [dnscat2 protocol documentation](https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md).

Die [DNScat-Decoder](https://github.com/josemlwdf/DNScat-Decoder)-repository verskaf ’n Python 3-decoder wat streams uit ’n PCAP onttrek deur DNS queries vir ’n gespesifiseerde domein te filter.<sup>[[3]](#references)</sup>
```
python3 dnscat_decoder.py sample.pcap bad_domain
```
## References

- [1] [dnscat2-protokoldokumentasie](https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md)
- [2] [DNSCat2 pcap-forensiese verslag – BSidesSF 2017 CTF](https://github.com/jrmdev/ctf-writeups/tree/master/bsidessf-2017/dnscap)
- [3] [DNScat-Decoder](https://github.com/josemlwdf/DNScat-Decoder)
{{#include ../../../banners/hacktricks-training.md}}
