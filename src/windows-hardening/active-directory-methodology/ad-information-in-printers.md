# प्रिंटर में जानकारी

{{#include ../../banners/hacktricks-training.md}}

इंटरनेट पर कई ब्लॉग **डिफ़ॉल्ट/कमज़ोर लॉगिन credentials के साथ LDAP कॉन्फ़िगर किए गए प्रिंटर छोड़ने के ख़तरों को उजागर करते हैं**।  \
ऐसा इसलिए है क्योंकि कोई attacker **प्रिंटर को rogue LDAP server के विरुद्ध authenticate करने के लिए बरगला सकता है** (आमतौर पर `nc -vv -l -p 389` या `slapd -d 2` पर्याप्त होता है) और प्रिंटर के **credentials को clear-text में capture कर सकता है**।

इसके अलावा, कई प्रिंटर में **usernames वाले logs** होते हैं या वे Domain Controller से **सभी usernames download** भी कर सकते हैं।

यह सारी **sensitive information** और सुरक्षा की आम **कमी** प्रिंटर को attackers के लिए बहुत दिलचस्प बनाती है।

इस विषय पर कुछ शुरुआती ब्लॉग:

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)<sup>[[4]](#references)</sup>
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)<sup>[[5]](#references)</sup>

---

## प्रिंटर कॉन्फ़िगरेशन

- **स्थान**: LDAP server की सूची आमतौर पर web interface में मिलती है (उदाहरण के लिए *Network ➜ LDAP Setting ➜ Setting Up LDAP*)।
- **व्यवहार**: कई embedded web servers LDAP server में बदलाव करने देते हैं, **बिना credentials दोबारा दर्ज किए** (उपयोगिता की सुविधा → सुरक्षा जोखिम)।
- **Exploit**: LDAP server address को attacker के नियंत्रण वाले host पर redirect करें और प्रिंटर को आपके server से bind करने के लिए *Test Connection* / *Address Book Sync* बटन का उपयोग करें।

---

## Credentials को Capture करना

### विधि 1 – Netcat Listener

```bash
sudo nc -k -v -l -p 389     # Plain LDAP only
```

छोटे/पुराने MFPs एक साधारण *simple-bind* भेज सकते हैं, जिसमें bind DN और password raw BER stream में दिखाई देते हैं। आधुनिक डिवाइस आमतौर पर पहले anonymous query करते हैं और फिर bind करने की कोशिश करते हैं, इसलिए नतीजे अलग-अलग हो सकते हैं।<sup>[[1]](#references)</sup>

636/3269 पर एक साधारण `nc` listener को केवल TLS ciphertext मिलता है; LDAPS की जाँच के लिए TLS-सक्षम LDAP endpoint की ज़रूरत होती है, और यदि डिवाइस server certificate को सही ढंग से validate करता है, तो redirection विफल हो जाना चाहिए।

### Method 2 – Full Rogue LDAP server (recommended)

क्योंकि कई डिवाइस authenticate करने से *पहले* anonymous search करते हैं, इसलिए एक वास्तविक LDAP daemon चलाने से कहीं अधिक विश्वसनीय नतीजे मिलते हैं:<sup>[[1]](#references)</sup>

```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # set any base-DN – it will not be validated

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```

जब printer lookup करता है, तो debug output में आपको clear-text credentials दिखाई देंगे।

> 💡 Responder में rogue LDAP और SMB authentication services शामिल हैं। एक साधारण LDAP bind से configured password उजागर हो सकता है, जबकि NTLM authentication से challenge-response material मिलता है; इन दोनों परिणामों को clear-text password के रूप में वर्णित न करें।

---

## Recent Pass-Back Vulnerabilities (2024-2025)

Pass-back कोई *सैद्धांतिक* समस्या नहीं है – vendors 2024/2025 में लगातार ऐसे advisories प्रकाशित कर रहे हैं, जिनमें इस attack class का सटीक वर्णन है।

### Xerox VersaLink – CVE-2024-12510 & CVE-2024-12511

Xerox VersaLink C70xx MFPs के firmware ≤ 57.69.91 में authenticated admin (या default creds बने रहने पर कोई भी व्यक्ति):

* **CVE-2024-12510 – LDAP pass-back**: LDAP server address बदलकर lookup trigger कर सकता था, जिससे device configured Windows credentials को attacker-controlled host पर leak कर देता था।
* **CVE-2024-12511 – SMB/FTP pass-back**: *scan-to-folder* destinations के ज़रिए यही समस्या होती थी, जिससे NetNTLMv2 या FTP clear-text creds leak होते थे।<sup>[[2]](#references)</sup>

ऐसा एक साधारण listener:

```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```

या एक rogue SMB server (`impacket-smbserver`) credentials हासिल करने के लिए पर्याप्त है।  

### Canon imageRUNNER / imageCLASS – Advisory 20 May 2025

Canon ने दर्जनों Laser और MFP product lines में **SMTP/LDAP pass-back** कमजोरी की पुष्टि की। Admin access वाला attacker server configuration में बदलाव करके LDAP **या** SMTP के लिए stored credentials हासिल कर सकता है (कई संगठन scan-to-mail की अनुमति देने के लिए privileged account का इस्तेमाल करते हैं)।<sup>[[3]](#references)</sup>

Vendor के निर्देशों में स्पष्ट रूप से ये सुझाव दिए गए हैं:

1. उपलब्ध होते ही patched firmware पर अपडेट करें।
2. मजबूत और unique admin passwords का इस्तेमाल करें।
3. Printer integration के लिए privileged AD accounts का इस्तेमाल न करें।

---

### Brother devices और OEM variants – serial से निकला service credentials तक admin access

2025 में coordinated disclosure ने प्रभावित Brother devices पर एक खास तौर पर उपयोगी chain का प्रदर्शन किया; vulnerability set के कुछ हिस्से OEM models को भी प्रभावित करते हैं, इसलिए अपने model की पुष्टि vendor advisory से करें। Vulnerable firmware पर unauthenticated attacker HTTP/HTTPS/IPP के ज़रिए device serial हासिल कर सकता है, जबकि serials SNMP या PJL जैसे management protocols से भी उपलब्ध हो सकते हैं। अगर factory password कभी बदला न गया हो, तो serial से administrator password निश्चित रूप से निकाला जा सकता है। Authentication के बाद, अलग pass-back flaw CVE-2024-51984, LDAP या FTP जैसे configured external services के passwords को plaintext में उजागर करता है, जिससे printer-management access का इस्तेमाल दोबारा किए जा सकने वाले network credentials के रूप में किया जा सकता है। Firmware update service-password disclosure को ठीक करता है, लेकिन पहले से निर्मित devices पर operator को serial से निकले शुरुआती administrator password को बदलना अब भी ज़रूरी है।<sup>[[6]](#references)</sup>

वर्तमान Metasploit में एक auxiliary module शामिल है, जो HTTP, SNMP या PJL के ज़रिए serial खोजता है, संभावित शुरुआती password बनाता है और वैकल्पिक रूप से उसे web console पर verify करता है। `DiscoverSerialVia=AUTO` उपलब्ध discovery paths को आज़माता है; अगर asset inventory में serial पहले से मौजूद है, तो इसके बजाय `TargetSerial` दें।<sup>[[7]](#references)</sup>

```text
msfconsole -q
use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978
set RHOSTS <printer-ip>
set DiscoverSerialVia AUTO
run
```

केवल अधिकृत एसेट्स को validate करने के लिए परिणाम का उपयोग करें। पासवर्ड काम करेगा या नहीं, यह सटीक मॉडल पर और, महत्वपूर्ण रूप से, इस बात पर निर्भर करता है कि factory administrator password पहले ही बदला गया है या नहीं।<sup>[[6]](#references)[[7]](#references)</sup>

---

## स्वचालित Enumeration / Exploitation Tools

| टूल | उद्देश्य | उदाहरण |
|------|---------|---------|
| **PRET** (Printer Exploitation Toolkit) | PostScript/PJL/PCL का दुरुपयोग, file-system access, default-creds check, *SNMP discovery* | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | HTTP/HTTPS के ज़रिए configuration (जिसमें address books और LDAP creds शामिल हैं) हासिल करना | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | rogue authentication services चलाना और SMB callbacks से NetNTLM capture/relay करना | `sudo responder -I eth0 -v` |
| **Metasploit Brother auxiliary** | serial का पता लगाना, संभावित factory administrator password निकालना और web-console access सत्यापित करना | `use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978` |

---

## Hardening और Detection

1. **MFPs को prompt तरीके से patch / firmware-update करें** (vendor PSIRT bulletins देखें)।
2. **Factory administrator passwords बदलें** – केवल firmware update करने से पहले निर्मित प्रभावित Brother/OEM devices के serial से निकाले जा सकने वाले शुरुआती passwords नहीं हटते।<sup>[[6]](#references)</sup>
3. **Least-Privilege Service Accounts** – LDAP/SMB/SMTP के लिए कभी भी Domain Admin का उपयोग न करें; केवल *read-only* OU scopes तक सीमित रखें।
4. **Management Access सीमित करें** – printer के web/IPP/SNMP interfaces को management VLAN में रखें या ACL/VPN के पीछे रखें।
5. **Printer egress सीमित करें** – प्रत्येक device को केवल अपेक्षित DC/LDAP, mail, DNS/NTP, print और scan-file destinations से संपर्क करने दें। Pass-back के लिए attacker द्वारा चुने गए endpoint पर callback आवश्यक है।
6. **अनुपयोगी Protocols बंद करें** – FTP, Telnet, raw-9100, पुराने SSL ciphers।
7. **Audit Logging सक्षम करें** – कुछ devices LDAP/SMTP failures को syslog कर सकते हैं; अप्रत्याशित binds का मिलान करें।
8. **Authentication destinations मॉनिटर करें** – जब कोई printer अपनी allowlist से बाहर के host को LDAP, SMB, SMTP या FTP शुरू करे, तो alert दें; खासकर management login या configuration change के तुरंत बाद।
9. **SNMPv3 का उपयोग करें या SNMP बंद करें** – `public` community से अक्सर device और serial की जानकारी leak होती है।

---



---

## References

- [1] [यह तो बस एक printer है… इससे बुरा क्या हो सकता है?](https://grimhacker.com/2018/03/09/just-a-printer/)
- [2] [Xerox Versalink C7025 Multifunction Printer: Pass-Back Attack की कमजोरियाँ (ठीक की गईं)](https://www.rapid7.com/blog/post/2025/02/14/xerox-versalink-c7025-multifunction-printer-pass-back-attack-vulnerabilities-fixed/)
- [3] [Production Printers, Office/Small Office Multifunction Printers और Laser Printers के लिए CP2025-004 Vulnerability Mitigation/Remediation](https://psirt.canon/advisory-information/cp2025-004/)
- [4] [Netcat के ज़रिए Printer से Domain Credentials प्राप्त करना](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [5] [Penetration Test Engagement के दौरान Multifunction Printers का Exploitation](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [6] [कई Brother Devices: कई Vulnerabilities (ठीक की गईं)](https://www.rapid7.com/blog/post/multiple-brother-devices-multiple-vulnerabilities-fixed/)
- [7] [Metasploit: Brother default administrator authentication bypass module](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978.rb)
{{#include ../../banners/hacktricks-training.md}}
