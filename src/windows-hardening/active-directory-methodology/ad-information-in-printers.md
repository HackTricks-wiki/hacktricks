# Inligting in Drukkers

{{#include ../../banners/hacktricks-training.md}}

Daar is verskeie blogs op die Internet wat die **gevare beklemtoon daarvan om drukkers met LDAP en verstek-/swak** aanmeldbewyse opgestel te laat.  \
Dit is omdat 'n aanvaller die **drukker kan mislei om teen 'n rogue LDAP-bediener te authenticate** (tipies is 'n `nc -vv -l -p 389` of `slapd -d 2` voldoende) en die drukker se **bewyse in clear-text** kan vaslê.

Daarbenewens sal verskeie drukkers **logs met gebruikersname** bevat of selfs in staat wees om **alle gebruikersname** vanaf die Domain Controller af te laai.

Al hierdie **sensitiewe inligting** en die algemene **gebrek aan sekuriteit** maak drukkers baie interessant vir aanvallers.

Enkele inleidende blogs oor die onderwerp:

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)<sup>[[4]](#references)</sup>
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)<sup>[[5]](#references)</sup>

---

## Drukkerkonfigurasie

- **Ligging**: Die LDAP-bedienerlys word gewoonlik in die webkoppelvlak gevind (bv. *Network ➜ LDAP Setting ➜ Setting Up LDAP*).
- **Gedrag**: Baie ingebedde webbedieners laat LDAP-bedienerwysigings **toe sonder om bewyse weer in te voer** (bruikbaarheidsfunksie → sekuriteitsrisiko).
- **Exploit**: Herlei die LDAP-bedieneradres na 'n aanvallerbeheerde gasheer en gebruik die *Test Connection* / *Address Book Sync*-knoppie om die drukker te dwing om teen jou te bind.

---

## Vaslegging van Bewyse

### Metode 1 – Netcat Listener
```bash
sudo nc -k -v -l -p 389     # Plain LDAP only
```
Klein/ou MFPs kan ’n eenvoudige *simple-bind* stuur waarvan die bind DN en wagwoord in die rou BER-stroom sigbaar is. Moderne toestelle voer gewoonlik eers ’n anonymous query uit en probeer daarna die bind, so resultate wissel.<sup>[[1]](#references)</sup>

’n Gewone `nc`-listener op 636/3269 ontvang slegs TLS-ciphertext; om LDAPS te toets, vereis ’n TLS-capable LDAP-endpoint, en redirection behoort te misluk wanneer die toestel die bedienersertifikaat korrek valideer.

### Method 2 – Volledige Rogue LDAP server (aanbeveel)

Omdat baie toestelle ’n anonymous search *voor* authentication sal uitvoer, lewer dit baie meer betroubare resultate om ’n werklike LDAP-daemon op te stel:<sup>[[1]](#references)</sup>
```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # set any base-DN – it will not be validated

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```
Wanneer die printer sy lookup uitvoer, sal jy die clear-text credentials in die debug-uitset sien.

> 💡  Responder sluit rogue LDAP- en SMB-authentication services in. ’n Eenvoudige LDAP bind kan die gekonfigureerde password blootlê, terwyl NTLM authentication challenge-response-materiaal produseer; moenie albei uitkomste as ’n clear-text password beskryf nie.

---

## Onlangse Pass-Back Vulnerabilities (2024-2025)

Pass-back is *nie* ’n teoretiese probleem nie – vendors publiseer steeds advisories in 2024/2025 wat presies hierdie attack class beskryf.

### Xerox VersaLink – CVE-2024-12510 & CVE-2024-12511

Firmware ≤ 57.69.91 van Xerox VersaLink C70xx MFPs het ’n geauthentiseerde admin (of enigiemand wanneer default creds behoue bly) toegelaat om:

* **CVE-2024-12510 – LDAP pass-back**: die LDAP-serveradres te verander en ’n lookup te trigger, wat veroorsaak dat die device die gekonfigureerde Windows credentials na die attacker-controlled host leë.
* **CVE-2024-12511 – SMB/FTP pass-back**: identiese probleem via *scan-to-folder*-bestemmings, wat NetNTLMv2 of FTP clear-text creds leë.<sup>[[2]](#references)</sup>

’n Eenvoudige listener soos:
```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```
of ’n rogue SMB server (`impacket-smbserver`) is genoeg om die credentials te harvest.

### Canon imageRUNNER / imageCLASS – Advisory 20 May 2025

Canon het ’n **SMTP/LDAP pass-back**-swakheid in dosyne Laser- en MFP-produklyne bevestig. ’n Aanvaller met admin access kan die bedienerkonfigurasie wysig en die gestoorde credentials vir LDAP **of** SMTP herwin (baie organisasies gebruik ’n bevoorregte rekening om scan-to-mail toe te laat).<sup>[[3]](#references)</sup>

Die vendor guidance beveel uitdruklik die volgende aan:

1. Dateer op na patched firmware sodra dit beskikbaar is.
2. Gebruik sterk, unieke admin passwords.
3. Vermy bevoorregte AD-rekeninge vir printer-integrasie.

---

### Brother devices en OEM-variante – serial-derived admin access tot service credentials

’n 2025 coordinated disclosure het ’n besonder nuttige chain op geaffekteerde Brother devices gedemonstreer; dele van die vulnerability set raak ook OEM-modelle, dus moet jy die presiese model teen sy vendor advisory verifieer. ’n Unauthenticated attacker kan die device serial via HTTP/HTTPS/IPP op vulnerable firmware bekom, terwyl serials ook deur management protocols soos SNMP of PJL beskikbaar kan wees. Indien die factory password nooit verander is nie, lewer die serial deterministies die administrator password. Ná authentication stel die afsonderlike pass-back flaw CVE-2024-51984 gekonfigureerde external-service passwords soos LDAP of FTP in plaintext bloot, wat printer-management access in herbruikbare network credentials omskep. Firmware herstel die service-password disclosure, maar devices wat voorheen vervaardig is, vereis steeds dat die operator die serial-derived initial administrator password vervang.<sup>[[6]](#references)</sup>

Huidige Metasploit sluit ’n auxiliary module in wat die serial oor HTTP, SNMP of PJL ontdek, die kandidaat initial password genereer en dit opsioneel teen die web console verifieer. `DiscoverSerialVia=AUTO` probeer die ondersteunde discovery paths; verskaf eerder `TargetSerial` wanneer die asset inventory reeds die serial bevat.<sup>[[7]](#references)</sup>
```text
msfconsole -q
use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978
set RHOSTS <printer-ip>
set DiscoverSerialVia AUTO
run
```
Gebruik die resultaat slegs om gemagtigde bates te valideer. Of die wagwoord werk, hang af van die presiese model en, krities, daarvan af of die fabrieksadministrateurwagwoord reeds verander is.<sup>[[6]](#references)[[7]](#references)</sup>

---

## Outomatiese Enumerasie / Exploitation Tools

| Tool | Doel | Voorbeeld |
|------|---------|---------|
| **PRET** (Printer Exploitation Toolkit) | Misbruik van PostScript/PJL/PCL, lêerstelseltoegang, kontrole van verstekbewyse, *SNMP-discovery* | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | Oes konfigurasie (insluitend adresboeke en LDAP-bewyse) via HTTP/HTTPS | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | Begin rogue authentication services en vang/relay NetNTLM vanaf SMB callbacks | `sudo responder -I eth0 -v` |
| **Metasploit Brother auxiliary** | Ontdek ’n reeksnommer, lei die kandidaat-fabrieksadministrateurwagwoord af en verifieer toegang tot die webkonsole | `use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978` |

---

## Verharding & Opsporing

1. **Patch / firmware-update** MFP’s betyds (kyk na die verskaffer se PSIRT-bulletins).
2. **Vervang fabrieksadministrateurwagwoorde** – firmware alleen verwyder nie reeksnommer-afgeleide aanvanklike wagwoorde van voorheen vervaardigde, geaffekteerde Brother/OEM-toestelle nie.<sup>[[6]](#references)</sup>
3. **Diensrekeninge met die minste voorregte** – moet nooit Domain Admin vir LDAP/SMB/SMTP gebruik nie; beperk dit tot *leesalleen*-OU-omvang.
4. **Beperk bestuurstoegang** – plaas drukker-web-/IPP-/SNMP-koppelvlakke in ’n bestuurs-VLAN of agter ’n ACL/VPN.
5. **Beperk drukker-egress** – laat elke toestel slegs met die verwagte DC/LDAP-, pos-, DNS/NTP-, druk- en skandeer-lêerbestemmings kommunikeer. Pass-back vereis ’n callback na ’n aanvallergekose endpoint.
6. **Deaktiveer Ongebruikte Protokolle** – FTP, Telnet, rou-9100, ouer SSL-ciphers.
7. **Aktiveer ouditlogging** – sommige toestelle kan LDAP/SMTP-foute na syslog stuur; korreleer onverwagte binds.
8. **Monitor authentication destinations** – waarsku wanneer ’n drukker LDAP, SMB, SMTP of FTP na ’n gasheer buite sy allowlist inisieer, veral onmiddellik ná ’n bestuursaanmelding of konfigurasieverandering.
9. **SNMPv3 of deaktiveer SNMP** – community `public` lek dikwels toestel- en reeksnommerinligting.

---



---

## References

- [1] [Dis net ’n drukker… Wat is die ergste wat kan gebeur?](https://grimhacker.com/2018/03/09/just-a-printer/)
- [2] [Xerox Versalink C7025-multifunksiedrukker: Pass-Back-aanvalskwesbaarhede (reggestel)](https://www.rapid7.com/blog/post/2025/02/14/xerox-versalink-c7025-multifunction-printer-pass-back-attack-vulnerabilities-fixed/)
- [3] [CP2025-004 Kwesbaarheidsversagting/-remediëring vir produksiedrukkers, multifunksiedrukkers vir kantoor-/kleinkantoorgebruik en laserdrukkers](https://psirt.canon/advisory-information/cp2025-004/)
- [4] [Verkryging van domeinbewyse deur ’n drukker met Netcat](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [5] [Exploitation van multifunksiedrukkers tydens ’n penetration testing-opdrag](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [6] [Veelvuldige Brother-toestelle: Veelvuldige kwesbaarhede (REGGESTEL)](https://www.rapid7.com/blog/post/multiple-brother-devices-multiple-vulnerabilities-fixed/)
- [7] [Metasploit: Brother default administrator authentication bypass-module](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978.rb)
{{#include ../../banners/hacktricks-training.md}}
