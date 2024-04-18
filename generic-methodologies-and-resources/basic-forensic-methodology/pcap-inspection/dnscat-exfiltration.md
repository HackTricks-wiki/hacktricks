

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) is a **dark-web** fueled search engine that offers **free** functionalities to check if a company or its customers have been **compromised** by **stealer malwares**.

Their primary goal of WhiteIntel is to combat account takeovers and ransomware attacks resulting from information-stealing malware.

You can check their website and try their engine for **free** at:

{% embed url="https://whiteintel.io" %}

---

If you have pcap with data being **exfiltrated by DNSCat** (without using encryption), you can find the exfiltrated content.

You only need to know that the **first 9 bytes** are not real data but are related to the **C\&C communication**:

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

For more information: [https://github.com/jrmdev/ctf-writeups/tree/master/bsidessf-2017/dnscap](https://github.com/jrmdev/ctf-writeups/tree/master/bsidessf-2017/dnscap)\
[https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md](https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md)


There is a script that works with Python3: [https://github.com/josemlwdf/DNScat-Decoder](https://github.com/josemlwdf/DNScat-Decoder)

```
python3 dnscat_decoder.py sample.pcap bad_domain
```

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>


