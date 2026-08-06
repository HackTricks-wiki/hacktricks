# Ανάλυση pcap του DNSCat

{{#include ../../../banners/hacktricks-training.md}}

Αν έχετε ένα pcap με δεδομένα που **εξάγονται μέσω DNSCat** (χωρίς χρήση encryption), μπορείτε να βρείτε το περιεχόμενο που εξήχθη.

Αρκεί να γνωρίζετε ότι τα **πρώτα 9 bytes** δεν είναι πραγματικά δεδομένα, αλλά σχετίζονται με την **επικοινωνία C\&C**:<sup>[[1]](#references)</sup>
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
Για περισσότερες πληροφορίες: [https://github.com/jrmdev/ctf-writeups/tree/master/bsidessf-2017/dnscap](https://github.com/jrmdev/ctf-writeups/tree/master/bsidessf-2017/dnscap)<sup>[[1]](#references)</sup>\
[https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md](https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md)

Υπάρχει ένα script που λειτουργεί με Python3: [https://github.com/josemlwdf/DNScat-Decoder](https://github.com/josemlwdf/DNScat-Decoder)
```
python3 dnscat_decoder.py sample.pcap bad_domain
```
## Αναφορές

- [1] [DNSCat2 pcap forensics writeup – BSidesSF 2017 CTF](https://github.com/jrmdev/ctf-writeups/tree/master/bsidessf-2017/dnscap)

{{#include ../../../banners/hacktricks-training.md}}
