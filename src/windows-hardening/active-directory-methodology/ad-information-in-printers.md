# Information in Printers

{{#include ../../banners/hacktricks-training.md}}

A printer with saved LDAP credentials can expose them if its server setting is changed and it then authenticates to a rogue endpoint.<sup>[[2]](#references)</sup> The result depends on the bind method: an unprotected simple bind reveals the password, while a SASL challenge-response bind does not reveal it as plaintext.<sup>[[8]](#references)</sup> See [LDAP authentication and transport security](../../network-services-pentesting/pentesting-ldap.md#cleartext-credentials-and-tls-downgrade-risks).

Also, several printers will contain **logs with usernames** or could even be able to **download all usernames** from the Domain Controller.

All this **sensitive information** and the common **lack of security** makes printers very interesting for attackers.

Some introductory blogs about the topic:

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)<sup>[[4]](#references)</sup>
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)<sup>[[5]](#references)</sup>

---

## Printer Configuration

- **Location**: The LDAP server list is usually found in the web interface (e.g. *Network ➜ LDAP Setting ➜ Setting Up LDAP*).
- **Behavior**: Many embedded web servers allow LDAP server modifications **without re-entering credentials** (usability feature → security risk).
- **Exploit**: Redirect the LDAP server address to an attacker-controlled host and use the *Test Connection* / *Address Book Sync* button to force the printer to bind to you.

---

## Capturing Credentials

### Method 1 – Netcat Listener

```bash
sudo nc -k -v -l -p 389     # Plain LDAP only
```

A simple BindRequest can expose the bind DN and password in the BER stream even if the server later rejects the login. An anonymous lookup or SASL negotiation alone does not expose that stored password.<sup>[[8]](#references)</sup>

A plain `nc` listener on 636/3269 sees a TLS handshake, not an LDAP bind. LDAPS requires a TLS-capable endpoint. Certificate validation alone does not stop pass-back if the printer accepts a changed hostname and the new endpoint has a valid certificate for that hostname; the client must also restrict which server is authorized to receive the stored credential.<sup>[[8]](#references)</sup>

### Method 2 – Full Rogue LDAP server (recommended)

A printer may require a valid LDAP response before it attempts a bind.<sup>[[10]](#references)</sup> A full LDAP server can handle that preliminary exchange, but it cannot make a client pinned to a strong SASL mechanism or the intended TLS server reveal its password.<sup>[[8]](#references)[[10]](#references)</sup>

```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # use a base DN compatible with the printer lookup

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```

Treat a lookup as evidence of a connection, not proof of password disclosure. A password is exposed only if the client sends a plaintext password-bearing bind; check the actual bind mechanism and TLS state.<sup>[[8]](#references)</sup>

> 💡  Responder includes rogue LDAP and SMB authentication services. A simple LDAP bind can expose the configured password, whereas NTLM authentication produces challenge-response material; do not describe both outcomes as a clear-text password.

### SASL mechanism selection

Some printer LDAP clients choose from the mechanisms an LDAP server advertises.<sup>[[8]](#references)[[10]](#references)</sup> Research showed that a client willing to accept an advertised plaintext SASL mechanism could send a password where its usual NTLM negotiation would only yield challenge-response data.<sup>[[9]](#references)[[10]](#references)</sup> This is a **client-policy failure**, not a property of all SASL binds: a client that requires a stronger mechanism or pins the intended TLS server should fail closed instead.<sup>[[8]](#references)</sup> OpenLDAP disables plaintext-capable SASL mechanisms by default, so a stock daemon does not establish that this behavior exists on a printer.<sup>[[11]](#references)</sup>

---

## Recent Pass-Back Vulnerabilities (2024-2025)

Pass-back is *not* a theoretical issue – vendors keep publishing advisories in 2024/2025 that exactly describe this attack class.

### Xerox VersaLink – CVE-2024-12510 & CVE-2024-12511

Firmware ≤ 57.69.91 of Xerox VersaLink C70xx MFPs allowed an authenticated admin (or anyone when default creds remain) to:

* **CVE-2024-12510 – LDAP pass-back**: change the LDAP server address and trigger a lookup, causing the device to leak the configured Windows credentials to the attacker-controlled host.
* **CVE-2024-12511 – SMB/FTP pass-back**: identical issue via *scan-to-folder* destinations, leaking NetNTLMv2 or FTP clear-text creds.<sup>[[2]](#references)</sup>

A simple listener such as:

```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```

or a rogue SMB server (`impacket-smbserver`) is enough to harvest the credentials.  

### Canon imageRUNNER / imageCLASS – Advisory 20 May 2025

Canon confirmed a **SMTP/LDAP pass-back** weakness in dozens of Laser & MFP product lines. An attacker with admin access can modify the server configuration and retrieve the stored credentials for LDAP **or** SMTP (many orgs use a privileged account to allow scan-to-mail).<sup>[[3]](#references)</sup>

The vendor guidance explicitly recommends:

1. Updating to patched firmware as soon as available.
2. Using strong, unique admin passwords.
3. Avoiding privileged AD accounts for printer integration.

---

### Brother devices and OEM variants – serial-derived admin access to service credentials

A 2025 coordinated disclosure demonstrated an especially useful chain on affected Brother devices; parts of the vulnerability set also affect OEM models, so verify the exact model against its vendor advisory. An unauthenticated attacker can obtain the device serial through HTTP/HTTPS/IPP on vulnerable firmware, while serials may also be available through management protocols such as SNMP or PJL. If the factory password was never changed, the serial deterministically yields the administrator password. After authenticating, the separate pass-back flaw CVE-2024-51984 exposes configured external-service passwords such as LDAP or FTP in plaintext, turning printer-management access into reusable network credentials. Firmware fixes the service-password disclosure, but previously manufactured devices still require the operator to replace the serial-derived initial administrator password.<sup>[[6]](#references)</sup>

Current Metasploit includes an auxiliary module that discovers the serial over HTTP, SNMP, or PJL, generates the candidate initial password, and optionally verifies it against the web console. `DiscoverSerialVia=AUTO` tries the supported discovery paths; provide `TargetSerial` instead when the asset inventory already contains the serial.<sup>[[7]](#references)</sup>

```text
msfconsole -q
use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978
set RHOSTS <printer-ip>
set DiscoverSerialVia AUTO
run
```

Use the result only to validate authorized assets. Whether the password works depends on the exact model and, critically, whether the factory administrator password has already been changed.<sup>[[6]](#references)[[7]](#references)</sup>

---

## Automated Enumeration / Exploitation Tools

| Tool | Purpose | Example |
|------|---------|---------|
| **PRET** (Printer Exploitation Toolkit) | PostScript/PJL/PCL abuse, file-system access, default-creds check, *SNMP discovery*; see [PJL assessment](../../network-services-pentesting/9100-pjl.md) | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | Harvest configuration (including address books & LDAP creds) via HTTP/HTTPS | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | Run rogue authentication services and capture/relay NetNTLM from SMB callbacks | `sudo responder -I eth0 -v` |
| **Metasploit Brother auxiliary** | Discover a serial, derive the candidate factory administrator password, and verify web-console access | `use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978` |

---

## Hardening & Detection

1. **Patch / firmware-update** MFPs promptly (check vendor PSIRT bulletins).
2. **Replace factory administrator passwords** – firmware alone does not remove serial-derived initial passwords from previously manufactured affected Brother/OEM devices.<sup>[[6]](#references)</sup>
3. **Least-Privilege Service Accounts** – never use Domain Admin for LDAP/SMB/SMTP; restrict to *read-only* OU scopes.
4. **Restrict Management Access** – place printer web/IPP/SNMP interfaces in a management VLAN or behind an ACL/VPN.
5. **Constrain printer egress** – allow each device to contact only the expected DC/LDAP, mail, DNS/NTP, print, and scan-file destinations. Pass-back requires a callback to an attacker-selected endpoint.
6. **Disable Unused Protocols** – FTP, Telnet, raw-9100, older SSL ciphers.
7. **Enable Audit Logging** – some devices can syslog LDAP/SMTP failures; correlate unexpected binds.
8. **Monitor authentication destinations** – alert when a printer initiates LDAP, SMB, SMTP, or FTP to a host outside its allowlist, especially immediately after a management login or configuration change.
9. **SNMPv3 or disable SNMP** – community `public` often leaks device and serial information.

---



---



## References

- [1] [It's just a printer… What's the worst that could happen?](https://grimhacker.com/2018/03/09/just-a-printer/)
- [2] [Xerox Versalink C7025 Multifunction Printer: Pass-Back Attack Vulnerabilities (Fixed)](https://www.rapid7.com/blog/post/2025/02/14/xerox-versalink-c7025-multifunction-printer-pass-back-attack-vulnerabilities-fixed/)
- [3] [CP2025-004 Vulnerability Mitigation/Remediation for Production Printers, Office/Small Office Multifunction Printers and Laser Printers](https://psirt.canon/advisory-information/cp2025-004/)
- [4] [Obtaining Domain Credentials through a Printer with Netcat](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [5] [Exploiting Multifunction Printers During A Penetration Test Engagement](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [6] [Multiple Brother Devices: Multiple Vulnerabilities (FIXED)](https://www.rapid7.com/blog/post/multiple-brother-devices-multiple-vulnerabilities-fixed/)
- [7] [Metasploit: Brother default administrator authentication bypass module](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978.rb)
- [8] [RFC 4513 – LDAP authentication methods and security mechanisms](https://datatracker.ietf.org/doc/html/rfc4513)
- [9] [LDAP passback Docker server](https://github.com/cybertrinchera/ldap-passback-docker)
- [10] [LDAP pass back attack – ACCEIS](https://www.acceis.fr/ldap-pass-back-attack/)
- [11] [slapd-config(5) – SASL security properties](https://man7.org/linux/man-pages/man5/slapd-config.5.html)
{{#include ../../banners/hacktricks-training.md}}
