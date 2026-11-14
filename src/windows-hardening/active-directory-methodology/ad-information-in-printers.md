# प्रिंटर में जानकारी

{{#include ../../banners/hacktricks-training.md}}

सेव किए गए LDAP credentials वाला प्रिंटर उन्हें उजागर कर सकता है, यदि उसकी server setting बदल दी जाए और फिर वह किसी rogue endpoint से authenticate करे।<sup>[[2]](#references)</sup> नतीजा bind method पर निर्भर करता है: असुरक्षित simple bind में password उजागर हो जाता है, जबकि SASL challenge-response bind में यह plaintext के रूप में उजागर नहीं होता।<sup>[[8]](#references)</sup> देखें [LDAP authentication and transport security](../../network-services-pentesting/pentesting-ldap.md#cleartext-credentials-and-tls-downgrade-risks).

इसके अलावा, कई प्रिंटर में **usernames वाले logs** होते हैं या वे Domain Controller से **सभी usernames download** कर सकते हैं।

यह सारी **संवेदनशील जानकारी** और सुरक्षा की आम **कमी** प्रिंटर को attackers के लिए बहुत दिलचस्प बनाती है।

इस विषय पर कुछ शुरुआती blogs:

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)<sup>[[4]](#references)</sup>
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)<sup>[[5]](#references)</sup>

---

## प्रिंटर कॉन्फ़िगरेशन

- **स्थान**: LDAP server list आमतौर पर web interface में मिलती है (जैसे *Network ➜ LDAP Setting ➜ Setting Up LDAP*).
- **व्यवहार**: कई embedded web servers, credentials दोबारा दर्ज किए बिना LDAP server में बदलाव करने देते हैं (सुविधा → सुरक्षा जोखिम)।
- **Exploit**: LDAP server address को attacker-controlled host पर redirect करें और प्रिंटर को आपसे bind करवाने के लिए *Test Connection* / *Address Book Sync* button का उपयोग करें।

---

## Credentials कैप्चर करना

### विधि 1 – Netcat Listener

```bash
sudo nc -k -v -l -p 389     # Plain LDAP only
```

एक साधारण BindRequest, BER stream में bind DN और password उजागर कर सकता है, भले ही server बाद में login अस्वीकार कर दे। केवल anonymous lookup या SASL negotiation से वह stored password उजागर नहीं होता।<sup>[[8]](#references)</sup>

636/3269 पर एक साधारण `nc` listener को LDAP bind नहीं, बल्कि TLS handshake दिखता है। LDAPS के लिए TLS-सक्षम endpoint आवश्यक है। यदि printer बदले हुए hostname को स्वीकार करता है और नए endpoint के पास उस hostname के लिए वैध certificate है, तो केवल certificate validation pass-back को नहीं रोकता; client को यह भी सीमित करना होगा कि stored credential प्राप्त करने के लिए कौन-सा server अधिकृत है।<sup>[[8]](#references)</sup>

### Method 2 – Full Rogue LDAP server (अनुशंसित)

किसी printer को bind करने की कोशिश से पहले वैध LDAP response की आवश्यकता हो सकती है।<sup>[[10]](#references)</sup> एक full LDAP server उस शुरुआती exchange को संभाल सकता है, लेकिन वह किसी ऐसे client से उसका password उजागर नहीं करवा सकता जो strong SASL mechanism या इच्छित TLS server से बंधा हो।<sup>[[8]](#references)[[10]](#references)</sup>

```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # use a base DN compatible with the printer lookup

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```

किसी lookup को connection का सबूत मानें, password disclosure का प्रमाण नहीं। Password तभी expose होता है जब client plaintext password वाला bind भेजता है; वास्तविक bind mechanism और TLS state जाँचें।<sup>[[8]](#references)</sup>

> 💡  Responder में rogue LDAP और SMB authentication services शामिल हैं। एक simple LDAP bind configured password expose कर सकता है, जबकि NTLM authentication challenge-response material उत्पन्न करता है; दोनों परिणामों को clear-text password न बताएं।

### SASL mechanism selection

कुछ printer LDAP clients, LDAP server द्वारा advertise किए गए mechanisms में से चुनते हैं।<sup>[[8]](#references)[[10]](#references)</sup> Research से पता चला कि advertised plaintext SASL mechanism स्वीकार करने को तैयार client, उस स्थिति में password भेज सकता है जहाँ उसका सामान्य NTLM negotiation केवल challenge-response data देता।<sup>[[9]](#references)[[10]](#references)</sup> यह **client-policy failure** है, सभी SASL binds का गुण नहीं: जो client अधिक मजबूत mechanism की मांग करता है या intended TLS server को pin करता है, उसे इसके बजाय fail closed होना चाहिए।<sup>[[8]](#references)</sup> OpenLDAP plaintext-capable SASL mechanisms को default रूप से disable करता है, इसलिए stock daemon यह साबित नहीं करता कि printer पर यह व्यवहार मौजूद है।<sup>[[11]](#references)</sup>

---

## हालिया Pass-Back Vulnerabilities (2024-2025)

Pass-back कोई *सैद्धांतिक मुद्दा नहीं* है – vendors 2024/2025 में लगातार ऐसे advisories प्रकाशित कर रहे हैं जो इस attack class का सटीक वर्णन करते हैं।

### Xerox VersaLink – CVE-2024-12510 & CVE-2024-12511

Xerox VersaLink C70xx MFPs के Firmware ≤ 57.69.91 में authenticated admin (या default creds बने रहने पर कोई भी व्यक्ति):

* **CVE-2024-12510 – LDAP pass-back**: LDAP server address बदलकर lookup trigger कर सकता था, जिससे device configured Windows credentials को attacker-controlled host पर leak कर देता था।
* **CVE-2024-12511 – SMB/FTP pass-back**: *scan-to-folder* destinations के ज़रिए वही समस्या, जिससे NetNTLMv2 या FTP clear-text creds leak होते थे।<sup>[[2]](#references)</sup>

एक simple listener, जैसे:

```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```

या एक rogue SMB server (`impacket-smbserver`) credentials harvest करने के लिए पर्याप्त है।  

### Canon imageRUNNER / imageCLASS – Advisory 20 May 2025

Canon ने दर्जनों Laser & MFP product lines में **SMTP/LDAP pass-back** कमजोरी की पुष्टि की। admin access वाला attacker server configuration में बदलाव कर सकता है और LDAP **या** SMTP के लिए stored credentials retrieve कर सकता है (कई organizations scan-to-mail की अनुमति देने के लिए privileged account का उपयोग करते हैं)।<sup>[[3]](#references)</sup>

Vendor के guidance में स्पष्ट रूप से ये सुझाव दिए गए हैं:

1. उपलब्ध होते ही patched firmware पर update करें।
2. मजबूत और unique admin passwords का उपयोग करें।
3. Printer integration के लिए privileged AD accounts का उपयोग न करें।

---

### Brother devices और OEM variants – service credentials तक serial-derived admin access

2025 में हुई एक coordinated disclosure में प्रभावित Brother devices पर एक विशेष रूप से उपयोगी chain दिखाई गई; vulnerability set के कुछ हिस्से OEM models को भी प्रभावित करते हैं, इसलिए अपने model को vendor advisory से मिलाकर सत्यापित करें। Vulnerable firmware पर unauthenticated attacker HTTP/HTTPS/IPP के ज़रिए device serial प्राप्त कर सकता है, जबकि serial SNMP या PJL जैसे management protocols के ज़रिए भी उपलब्ध हो सकते हैं। अगर factory password कभी बदला नहीं गया है, तो serial से administrator password निश्चित रूप से निकाला जा सकता है। Authentication के बाद, अलग pass-back flaw CVE-2024-51984, LDAP या FTP जैसे configured external services के passwords को plaintext में उजागर करता है, जिससे printer-management access को दोबारा इस्तेमाल किए जा सकने वाले network credentials में बदला जा सकता है। Firmware service-password disclosure को ठीक करता है, लेकिन पहले से निर्मित devices पर operator को serial-derived initial administrator password बदलना अब भी आवश्यक है।<sup>[[6]](#references)</sup>

मौजूदा Metasploit में एक auxiliary module शामिल है, जो HTTP, SNMP या PJL के ज़रिए serial खोजता है, संभावित initial password तैयार करता है और वैकल्पिक रूप से उसे web console पर verify करता है। `DiscoverSerialVia=AUTO` समर्थित discovery paths को आज़माता है; अगर asset inventory में serial पहले से मौजूद है, तो इसके बजाय `TargetSerial` दें।<sup>[[7]](#references)</sup>

```text
msfconsole -q
use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978
set RHOSTS <printer-ip>
set DiscoverSerialVia AUTO
run
```

परिणाम का उपयोग केवल अधिकृत assets को validate करने के लिए करें। Password काम करेगा या नहीं, यह exact model पर और, खास तौर पर, इस पर निर्भर करता है कि factory administrator password पहले ही बदला गया है या नहीं।<sup>[[6]](#references)[[7]](#references)</sup>

---

## Automated Enumeration / Exploitation Tools

| Tool | Purpose | Example |
|------|---------|---------|
| **PRET** (Printer Exploitation Toolkit) | PostScript/PJL/PCL का दुरुपयोग, file-system access, default-creds की जाँच, *SNMP discovery*; [PJL assessment](../../network-services-pentesting/9100-pjl.md) देखें | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | HTTP/HTTPS के ज़रिए configuration (जिसमें address books और LDAP creds भी शामिल हैं) इकट्ठा करना | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | Rogue authentication services चलाना और SMB callbacks से NetNTLM capture/relay करना | `sudo responder -I eth0 -v` |
| **Metasploit Brother auxiliary** | Serial का पता लगाना, संभावित factory administrator password निकालना और web-console access verify करना | `use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978` |

---

## Hardening & Detection

1. **Patch / firmware-update** MFPs तुरंत करें (vendor PSIRT bulletins देखें)।
2. **Factory administrator passwords बदलें** – firmware अकेले, पहले से निर्मित प्रभावित Brother/OEM devices के serial से निकाले जा सकने वाले initial passwords को नहीं हटाता।<sup>[[6]](#references)</sup>
3. **Least-Privilege Service Accounts** – LDAP/SMB/SMTP के लिए कभी भी Domain Admin का उपयोग न करें; केवल *read-only* OU scopes तक सीमित रखें।
4. **Management Access सीमित करें** – printer के web/IPP/SNMP interfaces को management VLAN में रखें या ACL/VPN के पीछे रखें।
5. **Printer egress सीमित करें** – प्रत्येक device को केवल अपेक्षित DC/LDAP, mail, DNS/NTP, print और scan-file destinations से संपर्क करने दें। Pass-back के लिए attacker द्वारा चुने गए endpoint पर callback आवश्यक है।
6. **अनुपयोगी Protocols बंद करें** – FTP, Telnet, raw-9100 और पुराने SSL ciphers।
7. **Audit Logging सक्षम करें** – कुछ devices LDAP/SMTP failures को syslog कर सकते हैं; अप्रत्याशित binds को correlate करें।
8. **Authentication destinations monitor करें** – जब कोई printer अपनी allowlist से बाहर के host पर LDAP, SMB, SMTP या FTP शुरू करे, तो alert दें; खासकर management login या configuration change के तुरंत बाद।
9. **SNMPv3 का उपयोग करें या SNMP बंद करें** – community `public` से अक्सर device और serial की जानकारी leak होती है।

---



---



## References

- [1] [यह तो बस एक printer है… इससे बुरा क्या हो सकता है?](https://grimhacker.com/2018/03/09/just-a-printer/)
- [2] [Xerox Versalink C7025 Multifunction Printer: Pass-Back Attack की vulnerabilities (ठीक की गईं)](https://www.rapid7.com/blog/post/2025/02/14/xerox-versalink-c7025-multifunction-printer-pass-back-attack-vulnerabilities-fixed/)
- [3] [CP2025-004: Production Printers, Office/Small Office Multifunction Printers और Laser Printers के लिए Vulnerability Mitigation/Remediation](https://psirt.canon/advisory-information/cp2025-004/)
- [4] [Netcat के ज़रिए Printer से Domain Credentials प्राप्त करना](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [5] [Penetration Test Engagement के दौरान Multifunction Printers का Exploitation](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [6] [कई Brother Devices: कई Vulnerabilities (ठीक की गईं)](https://www.rapid7.com/blog/post/multiple-brother-devices-multiple-vulnerabilities-fixed/)
- [7] [Metasploit: Brother default administrator authentication bypass module](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978.rb)
- [8] [RFC 4513 – LDAP authentication methods और security mechanisms](https://datatracker.ietf.org/doc/html/rfc4513)
- [9] [LDAP passback Docker server](https://github.com/cybertrinchera/ldap-passback-docker)
- [10] [LDAP pass back attack – ACCEIS](https://www.acceis.fr/ldap-pass-back-attack/)
- [11] [slapd-config(5) – SASL security properties](https://man7.org/linux/man-pages/man5/slapd-config.5.html)
{{#include ../../banners/hacktricks-training.md}}
