# DNSCat pcap-Analyse

{{#include ../../../banners/hacktricks-training.md}}

Wenn Sie eine pcap-Datei mit Daten haben, die **von DNSCat exfiltriert** werden (ohne Verschlüsselung), können Sie den exfiltrierten Inhalt finden.

Sie müssen nur wissen, dass die **ersten 9 Bytes** keine echten Daten sind, sondern mit der **C\&C-Kommunikation** zusammenhängen:
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
Für weitere Informationen: [https://github.com/jrmdev/ctf-writeups/tree/master/bsidessf-2017/dnscap](https://github.com/jrmdev/ctf-writeups/tree/master/bsidessf-2017/dnscap)\
[https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md](https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md)

Es gibt ein Skript, das mit Python3 funktioniert: [https://github.com/josemlwdf/DNScat-Decoder](https://github.com/josemlwdf/DNScat-Decoder)
```
python3 dnscat_decoder.py sample.pcap bad_domain
```
{{#include ../../../banners/hacktricks-training.md}}
