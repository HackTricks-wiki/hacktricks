# Analiza pcap DNSCat

Jeśli masz plik PCAP z danymi **eksfiltrowanymi przez DNSCat** (bez użycia szyfrowania), możesz być w stanie odzyskać wyeksfiltrowaną zawartość.

W przypadku przechwyconego ruchu BSidesSF 2017, do którego odniesiono się poniżej, w analizie przyjęto, że każde zdekodowane zapytanie zaczynało się od 9 bajtów danych charakterystycznych dla dnscat, poprzedzających przesyłaną zawartość. Ponieważ dnscat2 definiuje różne typy pakietów i układy nagłówków, przed zastosowaniem tego przesunięcia do innego ruchu zweryfikuj odpowiednie ramkowanie.<sup>[[1]](#references)[[2]](#references)</sup>
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
Więcej informacji znajdziesz w [opisie BSidesSF 2017](https://github.com/jrmdev/ctf-writeups/tree/master/bsidessf-2017/dnscap) oraz w [dokumentacji protokołu dnscat2](https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md).

Repozytorium [DNScat-Decoder](https://github.com/josemlwdf/DNScat-Decoder) udostępnia decoder w Pythonie 3, który wyodrębnia strumienie z pliku PCAP, filtrując zapytania DNS dla określonej domeny.<sup>[[3]](#references)</sup>
```
python3 dnscat_decoder.py sample.pcap bad_domain
```
## References

- [1] [dokumentacja protokołu dnscat2](https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md)
- [2] [analiza forensics PCAP DNSCat2 – CTF BSidesSF 2017](https://github.com/jrmdev/ctf-writeups/tree/master/bsidessf-2017/dnscap)
- [3] [DNScat-Decoder](https://github.com/josemlwdf/DNScat-Decoder)
{{#include ../../../banners/hacktricks-training.md}}
