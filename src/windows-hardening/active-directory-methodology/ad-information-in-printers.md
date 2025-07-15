# Inligting in Drukkers

{{#include ../../banners/hacktricks-training.md}}

Daar is verskeie blogs op die Internet wat **die gevare van die gebruik van drukkers met LDAP met standaard/zwak** aanmeldingsbesonderhede beklemtoon.  \
Dit is omdat 'n aanvaller die printer kan **mislei om teen 'n kwaadwillige LDAP-bediener te autentiseer** (tipies is 'n `nc -vv -l -p 389` of `slapd -d 2` genoeg) en die printer **aanmeldingsbesonderhede in duidelike teks** kan vang.

Ook, verskeie drukkers sal **logs met gebruikersname** bevat of kan selfs in staat wees om **alle gebruikersname** van die Domeinbeheerder af te laai.

Al hierdie **sensitiewe inligting** en die algemene **gebrek aan sekuriteit** maak drukkers baie interessant vir aanvallers.

Sommige inleidende blogs oor die onderwerp:

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

---
## Drukker Konfigurasie

- **Ligging**: Die LDAP-bedienerlys word gewoonlik in die webkoppelvlak gevind (bv. *Netwerk ➜ LDAP Instelling ➜ LDAP Opstelling*).
- **Gedrag**: Baie ingebedde webbedieners laat LDAP-bedienerwysigings toe **sonder om weer aanmeldingsbesonderhede in te voer** (bruikbaarheid kenmerk → sekuriteitsrisiko).
- **Eksploiteer**: Herlei die LDAP-bedieneradres na 'n aanvaller-beheerde gasheer en gebruik die *Toets Verbinding* / *Adresboek Sinchroniseer* knoppie om die printer te dwing om aan jou te bind.

---
## Vang Aanmeldingsbesonderhede

### Metode 1 – Netcat Luisteraar
```bash
sudo nc -k -v -l -p 389     # LDAPS → 636 (or 3269)
```
Klein/ou MFP's kan 'n eenvoudige *simple-bind* in duidelike teks stuur wat netcat kan vang. Moderne toestelle voer gewoonlik eers 'n anonieme navraag uit en probeer dan die bind, so resultate verskil.

### Metode 2 – Volledige Rogue LDAP bediener (aanbeveel)

Omdat baie toestelle 'n anonieme soektog *voor* outentisering sal uitvoer, lewer die opstelling van 'n werklike LDAP daemon baie meer betroubare resultate:
```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # set any base-DN – it will not be validated

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```
Wanneer die drukker sy soektog uitvoer, sal jy die duidelike teks geloofsbriewe in die foutopsporing-uitset sien.

> 💡 Jy kan ook `impacket/examples/ldapd.py` (Python rogue LDAP) of `Responder -w -r -f` gebruik om NTLMv2 hashes oor LDAP/SMB te versamel.

---
## Onlangse Pass-Back Kwessies (2024-2025)

Pass-back is *nie* 'n teoretiese probleem nie – verskaffers publiseer voortaan advies in 2024/2025 wat hierdie aanvalsklas presies beskryf.

### Xerox VersaLink – CVE-2024-12510 & CVE-2024-12511

Firmware ≤ 57.69.91 van Xerox VersaLink C70xx MFPs het 'n geverifieerde admin (of enige iemand wanneer standaard geloofsbriewe bly) toegelaat om:

* **CVE-2024-12510 – LDAP pass-back**: die LDAP-bedieneradres te verander en 'n soektog te aktiveer, wat die toestel laat lek van die geconfigureerde Windows geloofsbriewe na die aanvaller-beheerde gasheer.
* **CVE-2024-12511 – SMB/FTP pass-back**: identiese probleem via *scan-to-folder* bestemmings, wat NetNTLMv2 of FTP duidelike teks geloofsbriewe lek.

'n Eenvoudige luisteraar soos:
```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```
of 'n rogue SMB-bediener (`impacket-smbserver`) is genoeg om die geloofsbriewe te versamel.

### Canon imageRUNNER / imageCLASS – Advies 20 Mei 2025

Canon het 'n **SMTP/LDAP pass-back** swakheid in dosyne Laser & MFP produklyne bevestig. 'n Aanvaller met admin toegang kan die bediener konfigurasie verander en die gestoor geloofsbriewe vir LDAP **of** SMTP onttrek (baie organisasies gebruik 'n bevoorregte rekening om scan-to-mail toe te laat).

Die verskaffer se leiding beveel eksplisiet aan:

1. Opdateer na gepatchte firmware sodra dit beskikbaar is.
2. Gebruik sterk, unieke admin wagwoorde.
3. Vermy bevoorregte AD rekeninge vir drukker integrasie.

---
## Geoutomatiseerde Enumerasie / Exploitatie Gereedskap

| Gereedskap | Doel | Voorbeeld |
|------------|------|-----------|
| **PRET** (Printer Exploitation Toolkit) | PostScript/PJL/PCL misbruik, lêerstelsels toegang, standaard-geloofsbriewe kontrole, *SNMP ontdekking* | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | Versamel konfigurasie (insluitend adresboeke & LDAP geloofsbriewe) via HTTP/HTTPS | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | Vang & herlei NetNTLM hashes van SMB/FTP pass-back | `responder -I eth0 -wrf` |
| **impacket-ldapd.py** | Liggewig rogue LDAP diens om duidelike teks binds te ontvang | `python ldapd.py -debug` |

---
## Versterking & Opsporing

1. **Patch / firmware-opdatering** MFPs vinnig (kontroleer verskaffer PSIRT bulletins).
2. **Minimale Privilege Diens Rekeninge** – gebruik nooit Domein Admin vir LDAP/SMB/SMTP; beperk tot *lees-alleen* OU skope.
3. **Beperk Bestuurs Toegang** – plaas drukker web/IPP/SNMP interfaces in 'n bestuurs VLAN of agter 'n ACL/VPN.
4. **Deaktiveer Ongebruikte Protokolle** – FTP, Telnet, raw-9100, ouer SSL ciphers.
5. **Aktiveer Oudit Logging** – sommige toestelle kan syslog LDAP/SMTP mislukkings; korreleer onverwagte binds.
6. **Monitor vir Duidelike-Teks LDAP binds** op ongewone bronne (drukker behoort normaalweg net met DCs te kommunikeer).
7. **SNMPv3 of deaktiveer SNMP** – gemeenskap `public` lek dikwels toestel & LDAP konfigurasie.

---
## Verwysings

- [https://grimhacker.com/2018/03/09/just-a-printer/](https://grimhacker.com/2018/03/09/just-a-printer/)
- Rapid7. “Xerox VersaLink C7025 MFP Pass-Back Aanval Kw vulnerabilities.” Februarie 2025.
- Canon PSIRT. “Kw vulnerabilities Mitigering Teen SMTP/LDAP Passback vir Laser Drukkers en Klein Kantoor Multifunksie Drukkers.” Mei 2025.

{{#include ../../banners/hacktricks-training.md}}
