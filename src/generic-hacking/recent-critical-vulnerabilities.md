# Recent Critical Vulnerabilities and Exploitation Techniques (July 2025)

This document summarizes recent high-profile vulnerabilities and exploitation techniques disclosed in July 2025, including detailed attack vectors and mitigation advice.

---

## CVE-2025-6463: Arbitrary File Deletion in WordPress Forminator Plugin

- **Vulnerability Type:** Unauthenticated Arbitrary File Deletion
- **Impact:** Allows deletion of any file on the web server, including critical files like `wp-config.php`.
- **Attack Vector:** Sending crafted HTTP requests to the vulnerable Forminator plugin endpoint.
- **Consequence:** Deleting `wp-config.php` can lead to remote code execution and full site compromise.

### Exploitation Details
An unauthenticated attacker can craft HTTP requests targeting the Forminator WordPress plugin to delete arbitrary files. The critical file `wp-config.php` contains database credentials and configuration; its deletion can disrupt the site and enable further exploitation such as remote code execution.

### Mitigation
- Update the Forminator plugin to the latest patched version.
- Implement web application firewall (WAF) rules to block malicious requests targeting the plugin.

---

## CVE-2025-5349 & CVE-2025-5777: Citrix NetScaler ADC and Gateway Vulnerabilities

- **CVE-2025-5349:** Improper Access Control in Management Interface
- **CVE-2025-5777:** Memory Over-read due to Insufficient Input Validation
- **Impact:** Unauthorized access and potential exposure of sensitive data.
- **Attack Vector:** Exploitation of management interface and input validation flaws.

### Exploitation Details
CVE-2025-5349 allows unauthorized access to the management interface due to improper access control. CVE-2025-5777 causes memory over-read when configured as a Gateway, potentially leaking sensitive information.

### Mitigation
- Apply official patches from Citrix immediately.
- Use IPS signatures from security vendors such as Check Point to detect and block exploitation attempts.

---

## CVE-2025-47812: Authentication Bypass and Remote Code Execution in Wing FTP Server

- **Vulnerability Type:** Null-byte Injection Authentication Bypass
- **Impact:** Allows login without valid credentials and remote code execution.
- **Attack Vector:** Injecting a null byte (`%00`) in the username field to bypass authentication.

### Exploitation Details
Attackers exploit a null-byte injection in the username field, tricking the server into accepting the login without valid credentials. Once authenticated, attackers gain access via the UID cookie, enabling full system compromise.

### Mitigation
- Update Wing FTP Server to the latest patched version.
- Monitor for unusual login patterns and use IPS signatures to detect exploitation.

---

## RondoDox Botnet: IoT Device Exploitation

- **Target Devices:** TBK DVRs and Four-Faith routers
- **Exploited CVEs:** CVE-2024-3721 and CVE-2024-12856
- **Impact:** Establishes persistence, disguises traffic, downloads payloads, and enables DDoS attacks.

### Exploitation Details
The RondoDox botnet infects IoT devices by exploiting known vulnerabilities. It disguises its network traffic as gaming or VPN packets, downloads additional payloads over secure connections, and uses infected devices to launch distributed denial-of-service (DDoS) attacks.

### Mitigation
- Patch affected IoT devices with vendor updates.
- Monitor network traffic for anomalies resembling gaming or VPN packets.
- Employ network segmentation and firewall rules to limit device exposure.

---

## References

- [Check Point Research 6th July 2025 Threat Intelligence Report](https://research.checkpoint.com/2025/6th-july-threat-intelligence-report/)
- [Wordfence on CVE-2025-6463](https://www.wordfence.com/blog/2025/07/600000-wordpress-sites-affected-by-arbitrary-file-deletion-vulnerability-in-forminator-wordpress-plugin/)
- [Citrix Advisory CTX693420](https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX693420)
- [RCESecurity on Wing FTP Server RCE](http://rcesecurity.com/2025/06/what-the-null-wing-ftp-server-rce-cve-2025-47812/)
- [Fortinet Blog on RondoDox Botnet](https://www.fortinet.com/blog/threat-research/rondobox-unveiled-breaking-down-a-botnet-threat)

---

*This document is part of HackTricks generic hacking section and aims to keep security professionals updated on recent critical vulnerabilities and exploitation techniques.*
