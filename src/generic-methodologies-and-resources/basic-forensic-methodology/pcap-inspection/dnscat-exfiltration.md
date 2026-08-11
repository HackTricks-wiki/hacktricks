# Analyse de pcap DNSCat

{{#include ../../../banners/hacktricks-training.md}}

Si vous avez un PCAP contenant des données **exfiltrées par DNSCat** (sans chiffrement), vous pourrez peut-être récupérer le contenu exfiltré.

Pour la capture BSidesSF 2017 référencée ci-dessous, le write-up a déduit que chaque requête décodée commençait par 9 octets de données spécifiques à dnscat avant le contenu transféré. Comme dnscat2 définit différents types de paquets et structures d’en-tête, vérifiez le framing correspondant avant d’appliquer cet offset à d’autres trafics.<sup>[[1]](#references)[[2]](#references)</sup>
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
Pour plus d'informations, consultez le [compte rendu de BSidesSF 2017](https://github.com/jrmdev/ctf-writeups/tree/master/bsidessf-2017/dnscap) et la [documentation du protocole dnscat2](https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md).

Le dépôt [DNScat-Decoder](https://github.com/josemlwdf/DNScat-Decoder) fournit un décodeur Python 3 qui extrait les flux d'un PCAP en filtrant les requêtes DNS pour un domaine spécifié.<sup>[[3]](#references)</sup>
```
python3 dnscat_decoder.py sample.pcap bad_domain
```
## References

- [1] [documentation du protocole dnscat2](https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md)
- [2] [compte rendu de forensique pcap de DNSCat2 – CTF BSidesSF 2017](https://github.com/jrmdev/ctf-writeups/tree/master/bsidessf-2017/dnscap)
- [3] [DNScat-Decoder](https://github.com/josemlwdf/DNScat-Decoder)
{{#include ../../../banners/hacktricks-training.md}}
