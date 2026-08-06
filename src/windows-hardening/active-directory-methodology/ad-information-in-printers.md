# Printers में Information

{{#include ../../banners/hacktricks-training.md}}

Internet पर कई blogs **default/weak** logon credentials के साथ LDAP से configured printers को छोड़ने के खतरों को **highlight** करते हैं।  \
ऐसा इसलिए है क्योंकि attacker **printer को rogue LDAP server के विरुद्ध authenticate करने के लिए trick कर सकता है** (आमतौर पर `nc -vv -l -p 389` या `slapd -d 2` पर्याप्त होता है) और printer के **credentials को clear-text में capture** कर सकता है।

इसके अलावा, कई printers में **usernames वाले logs** मौजूद होते हैं या वे Domain Controller से **सभी usernames download** करने में भी सक्षम हो सकते हैं।

यह सारी **sensitive information** और security की सामान्य **कमी** printers को attackers के लिए बहुत interesting बनाती है।

इस topic से संबंधित कुछ introductory blogs:

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)<sup>[[4]](#references)</sup>
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)<sup>[[5]](#references)</sup>

---

## Printer Configuration

- **Location**: LDAP server list आमतौर पर web interface में मिलती है (जैसे *Network ➜ LDAP Setting ➜ Setting Up LDAP*)।
- **Behavior**: कई embedded web servers **credentials को दोबारा enter किए बिना LDAP server में modifications** की अनुमति देते हैं (usability feature → security risk)।
- **Exploit**: LDAP server address को attacker-controlled host पर redirect करें और *Test Connection* / *Address Book Sync* button का उपयोग करके printer को आपके server से bind करने के लिए force करें।

---

## Capturing Credentials

### Method 1 – Netcat Listener
```bash
sudo nc -k -v -l -p 389     # LDAPS → 636 (or 3269)
```
छोटे/पुराने MFPs clear-text में एक साधारण *simple-bind* भेज सकते हैं, जिसे netcat capture कर सकता है। आधुनिक devices आमतौर पर पहले anonymous query करते हैं और फिर bind का प्रयास करते हैं, इसलिए results अलग-अलग हो सकते हैं।<sup>[[1]](#references)</sup>

### विधि 2 – Full Rogue LDAP server (अनुशंसित)

क्योंकि कई devices authenticate करने से *पहले* anonymous search जारी करते हैं, इसलिए एक वास्तविक LDAP daemon स्थापित करने पर अधिक विश्वसनीय results मिलते हैं:<sup>[[1]](#references)</sup>
```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # set any base-DN – it will not be validated

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```
जब printer अपना lookup करता है, तो आपको debug output में clear-text credentials दिखाई देंगे।

> 💡  आप `impacket/examples/ldapd.py` (Python rogue LDAP) या `Responder -w -r -f` का उपयोग LDAP/SMB पर NTLMv2 hashes harvest करने के लिए भी कर सकते हैं।

---

## हाल की Pass-Back Vulnerabilities (2024-2025)

Pass-back कोई *theoretical issue* **नहीं** है – vendors 2024/2025 में लगातार advisories प्रकाशित कर रहे हैं, जो इस attack class का बिल्कुल स्पष्ट वर्णन करती हैं।

### Xerox VersaLink – CVE-2024-12510 & CVE-2024-12511

Xerox VersaLink C70xx MFPs के Firmware ≤ 57.69.91 में authenticated admin (या default creds रहने पर कोई भी व्यक्ति) निम्न कार्य कर सकता था:

* **CVE-2024-12510 – LDAP pass-back**: LDAP server address बदलना और lookup trigger करना, जिससे device configured Windows credentials को attacker-controlled host पर leak कर देता है।
* **CVE-2024-12511 – SMB/FTP pass-back**: *scan-to-folder* destinations के माध्यम से यही समस्या, जिससे NetNTLMv2 या FTP clear-text creds leak हो जाते हैं।<sup>[[2]](#references)</sup>

एक simple listener, जैसे:
```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```
या एक rogue SMB server (`impacket-smbserver`) credentials harvest करने के लिए पर्याप्त है।

### Canon imageRUNNER / imageCLASS – Advisory 20 May 2025

Canon ने दर्जनों Laser और MFP product lines में **SMTP/LDAP pass-back** weakness की पुष्टि की। Admin access वाला attacker server configuration को modify कर सकता है और LDAP **या** SMTP के लिए stored credentials retrieve कर सकता है (कई organizations scan-to-mail की अनुमति देने के लिए privileged account का उपयोग करते हैं)।<sup>[[3]](#references)</sup>

Vendor guidance स्पष्ट रूप से निम्नलिखित की सिफारिश करता है:

1. उपलब्ध होते ही patched firmware पर update करें।
2. Strong और unique admin passwords का उपयोग करें।
3. Printer integration के लिए privileged AD accounts का उपयोग करने से बचें।

---

## Automated Enumeration / Exploitation Tools

| Tool | Purpose | Example |
|------|---------|---------|
| **PRET** (Printer Exploitation Toolkit) | PostScript/PJL/PCL abuse, file-system access, default-creds check, *SNMP discovery* | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | HTTP/HTTPS के माध्यम से configuration (address books और LDAP creds सहित) harvest करना | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | SMB/FTP pass-back से NetNTLM hashes capture और relay करना | `responder -I eth0 -wrf` |
| **impacket-ldapd.py** | Clear-text binds प्राप्त करने वाली lightweight rogue LDAP service | `python ldapd.py -debug` |

---

## Hardening & Detection

1. **Patch / firmware-update** MFPs तुरंत करें (vendor PSIRT bulletins देखें)।
2. **Least-Privilege Service Accounts** – LDAP/SMB/SMTP के लिए कभी भी Domain Admin का उपयोग न करें; इन्हें *read-only* OU scopes तक सीमित रखें।
3. **Restrict Management Access** – printer web/IPP/SNMP interfaces को management VLAN में या ACL/VPN के पीछे रखें।
4. **Disable Unused Protocols** – FTP, Telnet, raw-9100 और पुराने SSL ciphers।
5. **Enable Audit Logging** – कुछ devices LDAP/SMTP failures को syslog कर सकते हैं; unexpected binds को correlate करें।
6. **Clear-Text LDAP binds की निगरानी करें** जो unusual sources से हों (printers को सामान्यतः केवल DCs से communicate करना चाहिए)।
7. **SNMPv3 या disable SNMP** – community `public` अक्सर device और LDAP config leak करता है।

---

## References

- [1] [It's just a printer… What's the worst that could happen?](https://grimhacker.com/2018/03/09/just-a-printer/)
- [2] [Xerox Versalink C7025 Multifunction Printer: Pass-Back Attack Vulnerabilities (Fixed)](https://www.rapid7.com/blog/post/2025/02/14/xerox-versalink-c7025-multifunction-printer-pass-back-attack-vulnerabilities-fixed/)
- [3] [CP2025-004 Vulnerability Mitigation/Remediation for Production Printers, Office/Small Office Multifunction Printers and Laser Printers](https://psirt.canon/advisory-information/cp2025-004/)
- [4] [Obtaining Domain Credentials through a Printer with Netcat](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [5] [Exploiting Multifunction Printers During A Penetration Test Engagement](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

{{#include ../../banners/hacktricks-training.md}}
