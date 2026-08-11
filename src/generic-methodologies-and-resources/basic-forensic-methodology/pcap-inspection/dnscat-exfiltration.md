# Analisi di pcap DNSCat

{{#include ../../../banners/hacktricks-training.md}}

Se disponi di un PCAP con dati **esfiltrati tramite DNSCat** (senza utilizzare la crittografia), potresti riuscire a recuperare il contenuto esfiltrato.

Per la cattura di BSidesSF 2017 indicata di seguito, l'analisi ha dedotto che ogni query decodificata iniziava con 9 byte di dati specifici di dnscat, seguiti dal contenuto trasferito. Poiché dnscat2 definisce diversi tipi di pacchetto e layout delle intestazioni, verifica il framing pertinente prima di applicare quell'offset ad altro traffico.<sup>[[1]](#references)[[2]](#references)</sup>
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
Per ulteriori informazioni, consulta il [write-up di BSidesSF 2017](https://github.com/jrmdev/ctf-writeups/tree/master/bsidessf-2017/dnscap) e la [documentazione del protocollo dnscat2](https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md).

Il repository [DNScat-Decoder](https://github.com/josemlwdf/DNScat-Decoder) fornisce un decoder Python 3 che estrae gli stream da un PCAP filtrando le query DNS per un dominio specificato.<sup>[[3]](#references)</sup>
```
python3 dnscat_decoder.py sample.pcap bad_domain
```
## References

- [1] [documentazione del protocollo dnscat2](https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md)
- [2] [analisi forense del pcap DNSCat2 – CTF BSidesSF 2017](https://github.com/jrmdev/ctf-writeups/tree/master/bsidessf-2017/dnscap)
- [3] [DNScat-Decoder](https://github.com/josemlwdf/DNScat-Decoder)
{{#include ../../../banners/hacktricks-training.md}}
