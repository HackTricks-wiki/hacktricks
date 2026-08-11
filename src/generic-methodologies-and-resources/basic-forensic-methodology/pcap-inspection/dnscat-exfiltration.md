# Análisis de pcap de DNSCat

{{#include ../../../banners/hacktricks-training.md}}

Si tienes un PCAP con datos **exfiltrados mediante DNSCat** (sin usar cifrado), es posible que puedas recuperar el contenido exfiltrado.

Para la captura de BSidesSF 2017 mencionada a continuación, el write-up dedujo que cada consulta decodificada comenzaba con 9 bytes de datos específicos de dnscat antes del contenido transferido. Debido a que dnscat2 define distintos tipos de paquetes y diseños de cabecera, verifica el framing relevante antes de aplicar ese desplazamiento a otro tráfico.<sup>[[1]](#references)[[2]](#references)</sup>
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
Para obtener más información, consulta el [informe de BSidesSF 2017](https://github.com/jrmdev/ctf-writeups/tree/master/bsidessf-2017/dnscap) y la [documentación del protocolo dnscat2](https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md).

El repositorio [DNScat-Decoder](https://github.com/josemlwdf/DNScat-Decoder) proporciona un decoder para Python 3 que extrae streams de un PCAP filtrando las consultas DNS para un dominio especificado.<sup>[[3]](#references)</sup>
```
python3 dnscat_decoder.py sample.pcap bad_domain
```
## References

- [1] [documentación del protocolo dnscat2](https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md)
- [2] [writeup de forensics de pcap de DNSCat2 – BSidesSF 2017 CTF](https://github.com/jrmdev/ctf-writeups/tree/master/bsidessf-2017/dnscap)
- [3] [DNScat-Decoder](https://github.com/josemlwdf/DNScat-Decoder)
{{#include ../../../banners/hacktricks-training.md}}
