# DNSCat ανάλυση pcap

{{#include ../../../banners/hacktricks-training.md}}

Εάν έχετε ένα PCAP με δεδομένα που **έχουν εξαχθεί μέσω DNSCat** (χωρίς χρήση encryption), ίσως μπορέσετε να ανακτήσετε το περιεχόμενο που εξήχθη.

Για το capture του BSidesSF 2017 που αναφέρεται παρακάτω, το write-up συμπέρανε ότι κάθε decoded query ξεκινούσε με 9 bytes δεδομένων ειδικών για το dnscat, πριν από το μεταφερόμενο περιεχόμενο. Επειδή το dnscat2 ορίζει διαφορετικούς τύπους πακέτων και διατάξεις header, επαληθεύστε το σχετικό framing πριν εφαρμόσετε αυτό το offset σε άλλη κίνηση.<sup>[[1]](#references)[[2]](#references)</sup>
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
Για περισσότερες πληροφορίες, δείτε την [τεχνική ανάλυση του BSidesSF 2017](https://github.com/jrmdev/ctf-writeups/tree/master/bsidessf-2017/dnscap) και την [τεκμηρίωση του πρωτοκόλλου dnscat2](https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md).

Το repository [DNScat-Decoder](https://github.com/josemlwdf/DNScat-Decoder) παρέχει έναν decoder σε Python 3, ο οποίος εξάγει streams από ένα PCAP φιλτράροντας τα DNS queries για ένα καθορισμένο domain.<sup>[[3]](#references)</sup>
```
python3 dnscat_decoder.py sample.pcap bad_domain
```
## References

- [1] [τεκμηρίωση πρωτοκόλλου dnscat2](https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md)
- [2] [ανάλυση forensics pcap του DNSCat2 – BSidesSF 2017 CTF](https://github.com/jrmdev/ctf-writeups/tree/master/bsidessf-2017/dnscap)
- [3] [DNScat-Decoder](https://github.com/josemlwdf/DNScat-Decoder)
{{#include ../../../banners/hacktricks-training.md}}
