# DNSCat pcap analysis

{{#include ../../../banners/hacktricks-training.md}}

If you have a PCAP with data being **exfiltrated by DNSCat** (without using encryption), you may be able to recover the exfiltrated content.

For the BSidesSF 2017 capture referenced below, the write-up inferred that each decoded query began with 9 bytes of dnscat-specific data before the transferred content. Because dnscat2 defines different packet types and header layouts, verify the relevant framing before applying that offset to other traffic.<sup>[[1]](#references)[[2]](#references)</sup>

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

For more information, see the [BSidesSF 2017 write-up](https://github.com/jrmdev/ctf-writeups/tree/master/bsidessf-2017/dnscap) and the [dnscat2 protocol documentation](https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md).

The [DNScat-Decoder](https://github.com/josemlwdf/DNScat-Decoder) repository provides a Python 3 decoder that extracts streams from a PCAP by filtering DNS queries for a specified domain.<sup>[[3]](#references)</sup>

```
python3 dnscat_decoder.py sample.pcap bad_domain
```

## References

- [1] [dnscat2 protocol documentation](https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md)
- [2] [DNSCat2 pcap forensics writeup – BSidesSF 2017 CTF](https://github.com/jrmdev/ctf-writeups/tree/master/bsidessf-2017/dnscap)
- [3] [DNScat-Decoder](https://github.com/josemlwdf/DNScat-Decoder)

{{#include ../../../banners/hacktricks-training.md}}
