# Análise de pcap do DNSCat

Se você tiver um PCAP com dados sendo **exfiltrados pelo DNSCat** (sem usar criptografia), poderá conseguir recuperar o conteúdo exfiltrado.

Para a captura do BSidesSF 2017 referenciada abaixo, o write-up inferiu que cada consulta decodificada começava com 9 bytes de dados específicos do dnscat antes do conteúdo transferido. Como o dnscat2 define diferentes tipos de pacotes e layouts de cabeçalho, verifique o framing relevante antes de aplicar esse deslocamento a outro tráfego.<sup>[[1]](#references)[[2]](#references)</sup>
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
Para mais informações, consulte o [relato do BSidesSF 2017](https://github.com/jrmdev/ctf-writeups/tree/master/bsidessf-2017/dnscap) e a [documentação do protocolo dnscat2](https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md).

O repositório [DNScat-Decoder](https://github.com/josemlwdf/DNScat-Decoder) fornece um decoder em Python 3 que extrai streams de um PCAP filtrando consultas DNS para um domínio especificado.<sup>[[3]](#references)</sup>
```
python3 dnscat_decoder.py sample.pcap bad_domain
```
## References

- [1] [documentação do protocolo dnscat2](https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md)
- [2] [relato de forense de pcap do DNSCat2 – BSidesSF 2017 CTF](https://github.com/jrmdev/ctf-writeups/tree/master/bsidessf-2017/dnscap)
- [3] [DNScat-Decoder](https://github.com/josemlwdf/DNScat-Decoder)
{{#include ../../../banners/hacktricks-training.md}}
