# Inligting in Drukkers

{{#include ../../banners/hacktricks-training.md}}

Daar is verskeie blogs op die internet wat die **gevare beklemtoon van drukkers wat met LDAP en verstek-/swak** aanmeldingscredentials gekonfigureer is.  \
Dit is omdat 'n aanvaller die **drukker kan mislei om teen 'n rogue LDAP-server te authenticate** (tipies is `nc -vv -l -p 389` of `slapd -d 2` voldoende) en die drukker se **credentials in clear-text** kan vaslê.

Daarbenewens sal verskeie drukkers **logs met gebruikersname** bevat of selfs in staat wees om **alle gebruikersname** vanaf die Domain Controller af te laai.

Al hierdie **sensitiewe inligting** en die algemene **gebrek aan sekuriteit** maak drukkers baie interessant vir aanvallers.

'n Paar inleidende blogs oor die onderwerp:

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)<sup>[[4]](#references)</sup>
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)<sup>[[5]](#references)</sup>

---

## Drukkerkonfigurasie

- **Ligging**: Die LDAP-serverlys word gewoonlik in die webinterface gevind (bv. *Network ➜ LDAP Setting ➜ Setting Up LDAP*).
- **Gedrag**: Baie ingebedde webservers laat LDAP-serverwysigings toe **sonder om credentials weer in te voer** (bruikbaarheidsfunksie → sekuriteitsrisiko).
- **Exploit**: Herlei die LDAP-serveradres na 'n aanvallerbeheerde host en gebruik die *Test Connection* / *Address Book Sync*-knoppie om die drukker te forseer om teen jou te bind.

---

## Vaslegging van Credentials

### Method 1 – Netcat Listener
```bash
sudo nc -k -v -l -p 389     # LDAPS → 636 (or 3269)
```
Klein/ou MFP's mag dalk 'n eenvoudige *simple-bind* in clear-text stuur wat netcat kan vaslê. Moderne toestelle doen gewoonlik eers 'n anonymous query en probeer dan die bind, dus wissel die resultate.<sup>[[1]](#references)</sup>

### Metode 2 – Volledige Rogue LDAP server (aanbeveel)

Omdat baie toestelle 'n anonymous search *voor* authentication uitvoer, lewer die opstel van 'n werklike LDAP daemon baie meer betroubare resultate:<sup>[[1]](#references)</sup>
```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # set any base-DN – it will not be validated

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```
Wanneer die printer sy lookup uitvoer, sal jy die clear-text credentials in die debug output sien.

> 💡  Jy kan ook `impacket/examples/ldapd.py` (Python rogue LDAP) of `Responder -w -r -f` gebruik om NTLMv2 hashes oor LDAP/SMB te harvest.

---

## Onlangse Pass-Back Kwesbaarhede (2024-2025)

Pass-back is *nie* ’n teoretiese probleem nie – vendors publiseer steeds advisories in 2024/2025 wat hierdie aanvalsklas presies beskryf.

### Xerox VersaLink – CVE-2024-12510 & CVE-2024-12511

Firmware ≤ 57.69.91 van Xerox VersaLink C70xx MFPs het ’n authenticated admin (of enigiemand wanneer default creds behoue bly) toegelaat om:

* **CVE-2024-12510 – LDAP pass-back**: die LDAP server address te verander en ’n lookup te trigger, wat veroorsaak dat die toestel die gekonfigureerde Windows credentials na die attacker-controlled host leak.
* **CVE-2024-12511 – SMB/FTP pass-back**: identiese probleem via *scan-to-folder* destinations, wat NetNTLMv2 of FTP clear-text creds leak.<sup>[[2]](#references)</sup>

’n Eenvoudige listener soos:
```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```
of 'n rogue SMB server (`impacket-smbserver`) is genoeg om die credentials te harvest.

### Canon imageRUNNER / imageCLASS – Raadgewing 20 Mei 2025

Canon het 'n **SMTP/LDAP pass-back**-swakheid in dosyne Laser- & MFP-produkreekse bevestig. 'n Aanvaller met admin-toegang kan die bedienerkonfigurasie wysig en die gestoorde credentials vir LDAP **of** SMTP bekom (baie organisasies gebruik 'n bevoorregte rekening om scan-to-mail toe te laat).<sup>[[3]](#references)</sup>

Die vendor se leiding beveel uitdruklik die volgende aan:

1. Dateer op na patched firmware sodra dit beskikbaar is.
2. Gebruik sterk, unieke admin-wagwoorde.
3. Vermy bevoorregte AD-rekeninge vir printer-integrasie.

---

## Automated Enumeration / Exploitation Tools

| Tool | Doel | Voorbeeld |
|------|---------|---------|
| **PRET** (Printer Exploitation Toolkit) | PostScript/PJL/PCL-misbruik, lêerstelseltoegang, default-creds-check, *SNMP discovery* | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | Harvest konfigurasie (insluitend address books & LDAP creds) via HTTP/HTTPS | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | Capture & relay NetNTLM-hashes vanaf SMB/FTP pass-back | `responder -I eth0 -wrf` |
| **impacket-ldapd.py** | Lightweight rogue LDAP service om clear-text binds te ontvang | `python ldapd.py -debug` |

---

## Hardening & Detection

1. **Patch / firmware-update** MFPs prompt (kyk na vendor PSIRT-bulletins).
2. **Least-Privilege Service Accounts** – moet nooit Domain Admin vir LDAP/SMB/SMTP gebruik nie; beperk dit tot *read-only* OU-scopes.
3. **Restrict Management Access** – plaas printer-web/IPP/SNMP-interfaces in 'n management VLAN of agter 'n ACL/VPN.
4. **Disable Unused Protocols** – FTP, Telnet, raw-9100, ouer SSL-ciphers.
5. **Enable Audit Logging** – sommige devices kan LDAP/SMTP-failures na syslog stuur; korreleer onverwagte binds.
6. **Monitor for Clear-Text LDAP binds** op ongewone bronne (printers behoort normaalweg slegs met DCs te kommunikeer).
7. **SNMPv3 or disable SNMP** – community `public` lek dikwels device- & LDAP-konfigurasie.

---

## Verwysings

- [1] [It's just a printer… What's the worst that could happen?](https://grimhacker.com/2018/03/09/just-a-printer/)
- [2] [Xerox Versalink C7025 Multifunction Printer: Pass-Back Attack Vulnerabilities (Fixed)](https://www.rapid7.com/blog/post/2025/02/14/xerox-versalink-c7025-multifunction-printer-pass-back-attack-vulnerabilities-fixed/)
- [3] [CP2025-004 Vulnerability Mitigation/Remediation for Production Printers, Office/Small Office Multifunction Printers and Laser Printers](https://psirt.canon/advisory-information/cp2025-004/)
- [4] [Obtaining Domain Credentials through a Printer with Netcat](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [5] [Exploiting Multifunction Printers During A Penetration Test Engagement](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

{{#include ../../banners/hacktricks-training.md}}
