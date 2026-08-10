# Аналіз DNSCat у pcap

Якщо у вас є PCAP із даними, які **exfiltrated by DNSCat** (без використання шифрування), можливо, вам вдасться відновити exfiltrated content.

Для capture BSidesSF 2017, на який наведено посилання нижче, у write-up було зроблено висновок, що кожен decoded query починався з 9 байтів dnscat-specific data перед transferred content. Оскільки dnscat2 визначає різні типи пакетів і структури заголовків, перевірте відповідне framing, перш ніж застосовувати це зміщення до іншого traffic.<sup>[[1]](#references)[[2]](#references)</sup>
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
Додаткову інформацію дивіться у [звіті BSidesSF 2017](https://github.com/jrmdev/ctf-writeups/tree/master/bsidessf-2017/dnscap) і [документації протоколу dnscat2](https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md).

Репозиторій [DNScat-Decoder](https://github.com/josemlwdf/DNScat-Decoder) містить декодер для Python 3, який витягує потоки з PCAP, фільтруючи DNS-запити для вказаного домену.<sup>[[3]](#references)</sup>
```
python3 dnscat_decoder.py sample.pcap bad_domain
```
## References

- [1] [документація протоколу dnscat2](https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md)
- [2] [форензичний аналіз pcap DNSCat2 — CTF BSidesSF 2017](https://github.com/jrmdev/ctf-writeups/tree/master/bsidessf-2017/dnscap)
- [3] [DNScat-Decoder](https://github.com/josemlwdf/DNScat-Decoder)
{{#include ../../../banners/hacktricks-training.md}}
