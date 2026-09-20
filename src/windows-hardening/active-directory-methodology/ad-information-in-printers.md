# Printers में Information

{{#include ../../banners/hacktricks-training.md}}

Internet पर कई blogs **default/weak** logon credentials के साथ LDAP से configured printers को छोड़ने के **खतरों को उजागर** करते हैं।  \
ऐसा इसलिए है क्योंकि attacker **printer को rogue LDAP server के विरुद्ध authenticate करने के लिए trick कर सकता है** (आमतौर पर `nc -vv -l -p 389` या `slapd -d 2` पर्याप्त होता है) और printer के **credentials को clear-text में capture** कर सकता है।

इसके अलावा, कई printers में **usernames वाले logs** होते हैं या वे Domain Controller से **सभी usernames download** करने में सक्षम हो सकते हैं।

यह सभी **sensitive information** और security की आम **कमी** printers को attackers के लिए बहुत interesting बनाती है।

इस topic पर कुछ introductory blogs:

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)<sup>[[4]](#references)</sup>
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)<sup>[[5]](#references)</sup>

---

## Printer Configuration

- **Location**: LDAP server list आमतौर पर web interface में मिलती है (जैसे *Network ➜ LDAP Setting ➜ Setting Up LDAP*)।
- **Behavior**: कई embedded web servers **credentials दोबारा enter किए बिना** LDAP server में modifications की अनुमति देते हैं (usability feature → security risk)।
- **Exploit**: LDAP server address को attacker-controlled host पर redirect करें और printer को आपके server से bind करने के लिए *Test Connection* / *Address Book Sync* button का उपयोग करें।

---

## Credentials Capture

### Method 1 – Netcat Listener
```bash
sudo nc -k -v -l -p 389     # Plain LDAP only
```
छोटे/पुराने MFPs एक साधारण *simple-bind* भेज सकते हैं, जिसमें उनका bind DN और password raw BER stream में दिखाई देते हैं। आधुनिक devices आमतौर पर पहले anonymous query करते हैं और उसके बाद bind का प्रयास करते हैं, इसलिए परिणाम अलग-अलग हो सकते हैं।<sup>[[1]](#references)</sup>

636/3269 पर plain `nc` listener को केवल TLS ciphertext प्राप्त होता है; LDAPS का परीक्षण करने के लिए TLS-capable LDAP endpoint आवश्यक है, और जब device server certificate को सही ढंग से validate करता है, तो redirection विफल होनी चाहिए।

### Method 2 – Full Rogue LDAP server (recommended)

क्योंकि कई devices authenticate करने से *पहले* anonymous search करेंगे, इसलिए एक वास्तविक LDAP daemon चलाने से कहीं अधिक विश्वसनीय परिणाम मिलते हैं:<sup>[[1]](#references)</sup>
```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # set any base-DN – it will not be validated

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```
जब printer अपना lookup करता है, तो आपको debug output में clear-text credentials दिखाई देंगे।

> 💡 Responder में rogue LDAP और SMB authentication services शामिल हैं। एक simple LDAP bind configured password को expose कर सकता है, जबकि NTLM authentication challenge-response material उत्पन्न करता है; दोनों outcomes को clear-text password के रूप में describe न करें।

---

## Recent Pass-Back Vulnerabilities (2024-2025)

Pass-back कोई *theoretical issue* नहीं है – vendors 2024/2025 में लगातार ऐसे advisories प्रकाशित कर रहे हैं, जो इस attack class का बिल्कुल सटीक वर्णन करते हैं।

### Xerox VersaLink – CVE-2024-12510 & CVE-2024-12511

Xerox VersaLink C70xx MFPs के Firmware ≤ 57.69.91 में authenticated admin (या default creds रहने पर कोई भी व्यक्ति) यह कर सकता था:

* **CVE-2024-12510 – LDAP pass-back**: LDAP server address बदलकर lookup trigger करना, जिससे device configured Windows credentials को attacker-controlled host पर leak कर देता है।
* **CVE-2024-12511 – SMB/FTP pass-back**: *scan-to-folder* destinations के माध्यम से यही समस्या, जिससे NetNTLMv2 या FTP clear-text creds leak हो जाते हैं।<sup>[[2]](#references)</sup>

एक simple listener, जैसे:
```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```
या एक rogue SMB server (`impacket-smbserver`) credentials harvest करने के लिए पर्याप्त है।

### Canon imageRUNNER / imageCLASS – Advisory 20 May 2025

Canon ने दर्जनों Laser & MFP product lines में **SMTP/LDAP pass-back** कमजोरी की पुष्टि की। Admin access वाला attacker server configuration को modify कर सकता है और LDAP **या** SMTP के लिए stored credentials प्राप्त कर सकता है (कई organizations scan-to-mail की अनुमति देने के लिए privileged account का उपयोग करते हैं)।<sup>[[3]](#references)</sup>

Vendor guidance स्पष्ट रूप से निम्नलिखित की सिफारिश करती है:

1. उपलब्ध होते ही patched firmware पर update करें।
2. Strong, unique admin passwords का उपयोग करें।
3. Printer integration के लिए privileged AD accounts का उपयोग करने से बचें।

---

### Brother devices and OEM variants – serial-derived admin access to service credentials

2025 के एक coordinated disclosure ने affected Brother devices पर विशेष रूप से उपयोगी chain प्रदर्शित की; vulnerability set के कुछ हिस्से OEM models को भी प्रभावित करते हैं, इसलिए exact model को उसके vendor advisory से verify करें। Unauthenticated attacker vulnerable firmware पर HTTP/HTTPS/IPP के माध्यम से device serial प्राप्त कर सकता है, जबकि serials SNMP या PJL जैसे management protocols के माध्यम से भी उपलब्ध हो सकते हैं। यदि factory password कभी बदला नहीं गया है, तो serial deterministic रूप से administrator password प्रदान करता है। Authenticate करने के बाद, अलग pass-back flaw CVE-2024-51984 configured external-service passwords, जैसे LDAP या FTP, को plaintext में expose करता है, जिससे printer-management access reusable network credentials में बदल जाता है। Firmware service-password disclosure को ठीक करता है, लेकिन पहले से निर्मित devices में operator को अभी भी serial-derived initial administrator password बदलना आवश्यक है।<sup>[[6]](#references)</sup>

Current Metasploit में एक auxiliary module शामिल है, जो HTTP, SNMP या PJL के माध्यम से serial discover करता है, candidate initial password generate करता है और वैकल्पिक रूप से web console के विरुद्ध उसे verify करता है। `DiscoverSerialVia=AUTO` supported discovery paths को आज़माता है; जब asset inventory में serial पहले से मौजूद हो, तो इसके बजाय `TargetSerial` प्रदान करें।<sup>[[7]](#references)</sup>
```text
msfconsole -q
use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978
set RHOSTS <printer-ip>
set DiscoverSerialVia AUTO
run
```
इस परिणाम का उपयोग केवल अधिकृत assets को validate करने के लिए करें। Password के काम करने की संभावना exact model पर और, महत्वपूर्ण रूप से, इस बात पर निर्भर करती है कि factory administrator password पहले ही बदला गया है या नहीं।<sup>[[6]](#references)[[7]](#references)</sup>

---

## Automated Enumeration / Exploitation Tools

| Tool | Purpose | Example |
|------|---------|---------|
| **PRET** (Printer Exploitation Toolkit) | PostScript/PJL/PCL abuse, file-system access, default-creds check, *SNMP discovery* | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | HTTP/HTTPS के माध्यम से configuration (address books और LDAP creds सहित) प्राप्त करना | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | rogue authentication services चलाना और SMB callbacks से NetNTLM को capture/relay करना | `sudo responder -I eth0 -v` |
| **Metasploit Brother auxiliary** | serial खोजना, candidate factory administrator password निकालना और web-console access verify करना | `use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978` |

---

## Hardening & Detection

1. **MFPs को prompt तरीके से patch / firmware-update करें** (vendor PSIRT bulletins जांचें)।
2. **Factory administrator passwords बदलें** – केवल firmware अपडेट करने से पहले से निर्मित प्रभावित Brother/OEM devices के serial-derived initial passwords हटते नहीं हैं।<sup>[[6]](#references)</sup>
3. **Least-Privilege Service Accounts** – LDAP/SMB/SMTP के लिए कभी भी Domain Admin का उपयोग न करें; इन्हें केवल *read-only* OU scopes तक सीमित रखें।
4. **Management Access प्रतिबंधित करें** – printer web/IPP/SNMP interfaces को management VLAN में या ACL/VPN के पीछे रखें।
5. **Printer egress सीमित करें** – प्रत्येक device को केवल अपेक्षित DC/LDAP, mail, DNS/NTP, print और scan-file destinations से संपर्क करने दें। Pass-back के लिए attacker-selected endpoint को callback आवश्यक होता है।
6. **Unused Protocols disable करें** – FTP, Telnet, raw-9100 और पुराने SSL ciphers।
7. **Audit Logging enable करें** – कुछ devices LDAP/SMTP failures को syslog कर सकते हैं; unexpected binds को correlate करें।
8. **Authentication destinations monitor करें** – जब कोई printer अपनी allowlist से बाहर के host को LDAP, SMB, SMTP या FTP connection शुरू करे, तो alert दें, विशेष रूप से management login या configuration change के तुरंत बाद।
9. **SNMPv3 या SNMP disable करें** – community `public` अक्सर device और serial information leak करती है।

---



---

## References

- [1] [यह केवल एक printer है… सबसे बुरा क्या हो सकता है?](https://grimhacker.com/2018/03/09/just-a-printer/)
- [2] [Xerox Versalink C7025 Multifunction Printer: Pass-Back Attack Vulnerabilities (Fixed)](https://www.rapid7.com/blog/post/2025/02/14/xerox-versalink-c7025-multifunction-printer-pass-back-attack-vulnerabilities-fixed/)
- [3] [Production Printers, Office/Small Office Multifunction Printers और Laser Printers के लिए CP2025-004 Vulnerability Mitigation/Remediation](https://psirt.canon/advisory-information/cp2025-004/)
- [4] [Netcat के माध्यम से Printer से Domain Credentials प्राप्त करना](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [5] [Penetration Test Engagement के दौरान Multifunction Printers का Exploitation](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [6] [Multiple Brother Devices: Multiple Vulnerabilities (FIXED)](https://www.rapid7.com/blog/post/multiple-brother-devices-multiple-vulnerabilities-fixed/)
- [7] [Metasploit: Brother default administrator authentication bypass module](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978.rb)
{{#include ../../banners/hacktricks-training.md}}
