# DNSCat-PCAP-Analyse

Wenn du eine PCAP-Datei mit Daten hast, die **durch DNSCat exfiltriert wurden** (ohne Verschlüsselung), kannst du möglicherweise den exfiltrierten Inhalt wiederherstellen.

Für den unten referenzierten Mitschnitt von BSidesSF 2017 wurde im Write-up festgestellt, dass jede decodierte Anfrage mit 9 Bytes DNSCat-spezifischer Daten begann, bevor der übertragene Inhalt folgte. Da dnscat2 verschiedene Pakettypen und Header-Strukturen definiert, solltest du die relevante Framing-Struktur überprüfen, bevor du diesen Offset auf anderen Traffic anwendest.<sup>[[1]](#references)[[2]](#references)</sup>
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
Weitere Informationen finden Sie im [BSidesSF 2017 write-up](https://github.com/jrmdev/ctf-writeups/tree/master/bsidessf-2017/dnscap) und in der [dnscat2 protocol documentation](https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md).

Das Repository [DNScat-Decoder](https://github.com/josemlwdf/DNScat-Decoder) stellt einen Python-3-decoder bereit, der Streams aus einem PCAP extrahiert, indem DNS queries für eine angegebene Domain gefiltert werden.<sup>[[3]](#references)</sup>
```
python3 dnscat_decoder.py sample.pcap bad_domain
```
## References

- [1] [dnscat2-Protokolldokumentation](https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md)
- [2] [DNSCat2-PCAP-Forensikbericht – BSidesSF 2017 CTF](https://github.com/jrmdev/ctf-writeups/tree/master/bsidessf-2017/dnscap)
- [3] [DNScat-Decoder](https://github.com/josemlwdf/DNScat-Decoder)
{{#include ../../../banners/hacktricks-training.md}}
