# Inligting in drukkers

{{#include ../../banners/hacktricks-training.md}}

Daar is verskeie blogs op die Internet wat **die gevare uitlig van drukkers wat met LDAP en verstek-/swak aanmeldbewyse opgestel is**.  \
Dit is omdat ’n aanvaller **die drukker kan mislei om teen ’n kwaadwillige LDAP-bediener te autentiseer** (gewoonlik is `nc -vv -l -p 389` of `slapd -d 2` genoeg) en die drukker se **aanmeldbewyse in gewone teks vas te lê**.

Daarbenewens bevat verskeie drukkers **logboeke met gebruikersname**, of kan hulle selfs **alle gebruikersname** van die Domain Controller **aflaai**.

Al hierdie **sensitiewe inligting** en die algemene **gebrek aan sekuriteit** maak drukkers baie interessant vir aanvallers.

Enkele inleidende blogs oor die onderwerp:

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)<sup>[[4]](#references)</sup>
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)<sup>[[5]](#references)</sup>

---

## Drukkeropstelling

- **Ligging**: Die LDAP-bedienerlys word gewoonlik in die webkoppelvlak gevind (bv. *Network ➜ LDAP Setting ➜ Setting Up LDAP*).
- **Gedrag**: Baie ingebedde webbedieners laat toe dat LDAP-bedieners gewysig word **sonder om aanmeldbewyse weer in te voer** (gebruikersvriendelike kenmerk → sekuriteitsrisiko).
- **Uitbuiting**: Herlei die LDAP-bedieneradres na ’n gasheer wat deur die aanvaller beheer word en gebruik die *Test Connection* / *Address Book Sync*-knoppie om die drukker te dwing om aan jou te bind.

---

## Vaslegging van aanmeldbewyse

### Metode 1 – Netcat-luisteraar

```bash
sudo nc -k -v -l -p 389     # Plain LDAP only
```

Klein/ou MFP's kan 'n eenvoudige *simple-bind* stuur waarvan die bind-DN en wagwoord in die rou BER-stroom sigbaar is. Moderne toestelle voer gewoonlik eers 'n anonieme navraag uit en probeer dan die bind, so die resultate wissel.<sup>[[1]](#references)</sup>

'n Gewone `nc`-luisteraar op 636/3269 ontvang slegs TLS-syferteks; om LDAPS te toets, is 'n TLS-bekwame LDAP-eindpunt nodig, en herleiding behoort te misluk wanneer die toestel die bediener se sertifikaat korrek valideer.

### Method 2 – Full Rogue LDAP server (recommended)

Omdat baie toestelle 'n anonieme soektog sal uitvoer *voordat* hulle staaf, lewer die opstelling van 'n werklike LDAP-daemon baie meer betroubare resultate:<sup>[[1]](#references)</sup>

```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # set any base-DN – it will not be validated

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```

Wanneer die drukker sy opsoek uitvoer, sal jy die geloofsbriewe in gewone teks in die ontfoutingsuitset sien.

> 💡 Responder sluit rogue LDAP- en SMB-verifikasiedienste in. ’n Eenvoudige LDAP-bind kan die gekonfigureerde wagwoord blootlê, terwyl NTLM-verifikasie challenge-response-materiaal oplewer; moenie albei uitkomste as ’n wagwoord in gewone teks beskryf nie.

---

## Onlangse Pass-Back-kwesbaarhede (2024-2025)

Pass-back is *nie* ’n teoretiese probleem nie – verskaffers publiseer steeds in 2024/2025 sekuriteitsadvies wat hierdie aanvalsklas presies beskryf.

### Xerox VersaLink – CVE-2024-12510 & CVE-2024-12511

Firmware ≤ 57.69.91 van Xerox VersaLink C70xx MFP’s het ’n geverifieerde admin (of enigiemand wanneer die verstekbewyse onveranderd is) toegelaat om:

* **CVE-2024-12510 – LDAP pass-back**: die LDAP-bedieneradres te verander en ’n opsoek te aktiveer, wat veroorsaak dat die toestel die gekonfigureerde Windows-bewyse na die aanvallerbeheerde gasheer lek.
* **CVE-2024-12511 – SMB/FTP pass-back**: dieselfde probleem via *scan-to-folder*-bestemmings, wat NetNTLMv2- of FTP-bewyse in gewone teks laat lek.<sup>[[2]](#references)</sup>

’n Eenvoudige listener soos:

```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```

of ’n kwaadwillige SMB-bediener (`impacket-smbserver`) is genoeg om die geloofsbriewe te harvest.  

### Canon imageRUNNER / imageCLASS – Advies van 20 Mei 2025

Canon het ’n **SMTP/LDAP pass-back**-swakheid in tientalle Laser- en MFP-produkreekse bevestig. ’n Aanvaller met admin-toegang kan die bedienerkonfigurasie wysig en die gestoorde LDAP- **of** SMTP-geloofsbriewe bekom (baie organisasies gebruik ’n bevoorregte rekening om skandeer-na-e-pos toe te laat).<sup>[[3]](#references)</sup>

Die verskaffer se leiding beveel uitdruklik die volgende aan:

1. Dateer op na fermware met die regstelling sodra dit beskikbaar is.
2. Gebruik sterk, unieke admin-wagwoorde.
3. Vermy die gebruik van bevoorregte AD-rekeninge vir drukkerintegrasie.

---

### Brother-toestelle en OEM-variante – reeksnommer-afgeleide admin-toegang tot diensgeloofsbriewe

’n Gekoördineerde openbaarmaking in 2025 het ’n besonder nuttige aanvalsketting op geaffekteerde Brother-toestelle gedemonstreer; dele van die kwesbaarheidstel raak ook OEM-modelle, dus moet die presiese model teen die verskaffer se advies nagegaan word. ’n Aanvaller sonder verifikasie kan die toestel se reeksnommer via HTTP/HTTPS/IPP op kwesbare fermware bekom, terwyl reeksnommers ook via bestuursprotokolle soos SNMP of PJL beskikbaar kan wees. As die fabriekswagwoord nooit verander is nie, bepaal die reeksnommer die administrateurwagwoord. Ná verifikasie stel die afsonderlike pass-back-fout CVE-2024-51984 gekonfigureerde wagwoorde vir eksterne dienste, soos LDAP of FTP, in gewone teks bloot; só word drukkerbestuurtoegang omskep in herbruikbare netwerkgeloofsbriewe. Fermware herstel die blootlegging van dienswagwoorde, maar vir toestelle wat reeds vervaardig is, moet die operateur steeds die aanvanklike administrateurwagwoord wat van die reeksnommer afgelei is, vervang.<sup>[[6]](#references)</sup>

Die huidige Metasploit bevat ’n auxiliary-module wat die reeksnommer via HTTP, SNMP of PJL ontdek, die moontlike aanvanklike wagwoord genereer en dit opsioneel teen die webkonsole verifieer. `DiscoverSerialVia=AUTO` probeer die ondersteunde ontdekkingsroetes; verskaf eerder `TargetSerial` wanneer die bate-inventaris reeds die reeksnommer bevat.<sup>[[7]](#references)</sup>

```text
msfconsole -q
use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978
set RHOSTS <printer-ip>
set DiscoverSerialVia AUTO
run
```

Gebruik die resultaat slegs om gemagtigde bates te valideer. Of die wagwoord werk, hang af van die presiese model en, veral, of die fabrieksadministrateurwagwoord reeds verander is.<sup>[[6]](#references)[[7]](#references)</sup>

---

## Outomatiese Enumeration / Exploitation Tools

| Tool | Doel | Voorbeeld |
|------|---------|---------|
| **PRET** (Printer Exploitation Toolkit) | Misbruik van PostScript/PJL/PCL, toegang tot die lêerstelsel, nagaan van verstekbewyse, *SNMP-discovery* | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | Oes konfigurasie (insluitend adresboeke en LDAP-bewyse) via HTTP/HTTPS | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | Laat rogue-verifikasiedienste loop en vang/relê NetNTLM vanaf SMB-callbacks | `sudo responder -I eth0 -v` |
| **Metasploit Brother auxiliary** | Ontdek ’n reeksnommer, lei die moontlike fabrieksadministrateurwagwoord af en verifieer toegang tot die webkonsole | `use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978` |

---

## Verharding en Opsporing

1. **Dateer MFP’s betyds op met patches/firmware** (raadpleeg die PSIRT-bulletins van die verskaffer).
2. **Vervang fabrieksadministrateurwagwoorde** – firmware alleen verwyder nie reeksnommer-afgeleide aanvanklike wagwoorde van voorheen vervaardigde, geraakte Brother/OEM-toestelle nie.<sup>[[6]](#references)</sup>
3. **Diensrekeninge met die minste voorregte** – gebruik nooit Domain Admin vir LDAP/SMB/SMTP nie; beperk dit tot *leesalleen*-OU-reikwydtes.
4. **Beperk bestuurstoegang** – plaas die drukker se web-/IPP-/SNMP-koppelvlakke in ’n bestuurs-VLAN of agter ’n ACL/VPN.
5. **Beperk drukkeruitgaande verkeer** – laat elke toestel toe om slegs met die verwagte DC/LDAP-, e-pos-, DNS/NTP-, druk- en skandeer-lêerbestemmings te kommunikeer. Pass-back vereis ’n callback na ’n aanvallergekose eindpunt.
6. **Deaktiveer ongebruikte protokolle** – FTP, Telnet, raw-9100 en ouer SSL-syfersuites.
7. **Aktiveer ouditregistrasie** – sommige toestelle kan LDAP-/SMTP-foute na syslog stuur; korreleer onverwagte bindings.
8. **Monitor verifikasi bestemmings** – waarsku wanneer ’n drukker LDAP, SMB, SMTP of FTP begin gebruik na ’n gasheer buite sy toelatingslys, veral onmiddellik ná ’n aanmelding by die bestuurskoppelvlak of ’n konfigurasieverandering.
9. **Gebruik SNMPv3 of deaktiveer SNMP** – die community `public` lek dikwels toestel- en reeksnommerinligting.

---



---

## References

- [1] [Dis net ’n drukker… Wat is die ergste wat kan gebeur?](https://grimhacker.com/2018/03/09/just-a-printer/)
- [2] [Xerox Versalink C7025-multifunksiedrukker: kwesbaarhede vir Pass-Back-aanvalle (reggestel)](https://www.rapid7.com/blog/post/2025/02/14/xerox-versalink-c7025-multifunction-printer-pass-back-attack-vulnerabilities-fixed/)
- [3] [CP2025-004: Versagting/herstel van kwesbaarhede vir produksiedrukkers, multifunksiedrukkers vir kantore/klein kantore en laserdrukkers](https://psirt.canon/advisory-information/cp2025-004/)
- [4] [Verkryging van domeinbewyse deur ’n drukker met Netcat](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [5] [Uitbuiting van multifunksiedrukkers tydens ’n penetrasietoetsopdrag](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [6] [Verskeie Brother-toestelle: Verskeie kwesbaarhede (REGGESTEL)](https://www.rapid7.com/blog/post/multiple-brother-devices-multiple-vulnerabilities-fixed/)
- [7] [Metasploit: Brother-module vir die omseiling van verstekadministrateurverifikasie](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978.rb)
{{#include ../../banners/hacktricks-training.md}}
