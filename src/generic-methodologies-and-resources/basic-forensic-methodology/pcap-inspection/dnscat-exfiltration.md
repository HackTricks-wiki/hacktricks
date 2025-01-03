# Ανάλυση pcap του DNSCat

{{#include ../../../banners/hacktricks-training.md}}

Αν έχετε pcap με δεδομένα που **εξάγονται από το DNSCat** (χωρίς χρήση κρυπτογράφησης), μπορείτε να βρείτε το εξαγόμενο περιεχόμενο.

Πρέπει μόνο να γνωρίζετε ότι τα **πρώτα 9 bytes** δεν είναι πραγματικά δεδομένα αλλά σχετίζονται με την **επικοινωνία C\&C**:
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
Για περισσότερες πληροφορίες: [https://github.com/jrmdev/ctf-writeups/tree/master/bsidessf-2017/dnscap](https://github.com/jrmdev/ctf-writeups/tree/master/bsidessf-2017/dnscap)\
[https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md](https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md)

Υπάρχει ένα σενάριο που λειτουργεί με Python3: [https://github.com/josemlwdf/DNScat-Decoder](https://github.com/josemlwdf/DNScat-Decoder)
```
python3 dnscat_decoder.py sample.pcap bad_domain
```
{{#include ../../../banners/hacktricks-training.md}}
