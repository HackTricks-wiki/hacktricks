# Inligting in Drukkers

{{#include ../../banners/hacktricks-training.md}}

’n Drukker met gestoorde LDAP-aanmeldbesonderhede kan dit blootlê as sy bedienerinstelling verander word en dit daarna by ’n kwaadwillige endpoint aanmeld.<sup>[[2]](#references)</sup> Die resultaat hang af van die bind-metode: ’n onbeskermde simple bind onthul die wagwoord, terwyl ’n SASL challenge-response-bind dit nie as gewone teks onthul nie.<sup>[[8]](#references)</sup> Sien [LDAP authentication and transport security](../../network-services-pentesting/pentesting-ldap.md#cleartext-credentials-and-tls-downgrade-risks).

Daarbenewens bevat verskeie drukkers **logs met gebruikersname** of kan hulle selfs **alle gebruikersname** van die Domain Controller **aflaai**.

Al hierdie **sensitiewe inligting** en die algemene **gebrek aan sekuriteit** maak drukkers baie interessant vir aanvallers.

Enkele inleidende blogs oor die onderwerp:

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)<sup>[[4]](#references)</sup>
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)<sup>[[5]](#references)</sup>

---

## Drukkerkonfigurasie

- **Ligging**: Die LDAP-bedienerlys word gewoonlik in die webkoppelvlak gevind (bv. *Network ➜ LDAP Setting ➜ Setting Up LDAP*).
- **Gedrag**: Baie ingebedde webbedieners laat toe dat LDAP-bedieners gewysig word **sonder om aanmeldbesonderhede weer in te voer** (gebruiksgemakfunksie → sekuriteitsrisiko).
- **Uitbuiting**: Herlei die LDAP-bedieneradres na ’n aanvaller-beheerde gasheer en gebruik die *Test Connection* / *Address Book Sync*-knoppie om die drukker te dwing om by jou aan te meld.

---

## Aanmeldbesonderhede vaslê

### Metode 1 – Netcat-luisteraar

```bash
sudo nc -k -v -l -p 389     # Plain LDAP only
```

’n Eenvoudige BindRequest kan die bind-DN en wagwoord in die BER-stroom blootstel, selfs al weier die bediener later die aanmelding. ’n Anonieme opsoek of SASL-onderhandeling alleen stel nie die gestoorde wagwoord bloot nie.<sup>[[8]](#references)</sup>

’n Gewone `nc`-luisteraar op 636/3269 sien ’n TLS-handdruk, nie ’n LDAP-bind nie. LDAPS vereis ’n TLS-geskikte eindpunt. Sertifikaatvalidering alleen keer nie pass-back nie as die drukker ’n veranderde gasheernaam aanvaar en die nuwe eindpunt ’n geldige sertifikaat vir daardie gasheernaam het; die kliënt moet ook beperk watter bediener gemagtig is om die gestoorde geloofsbriewe te ontvang.<sup>[[8]](#references)</sup>

### Metode 2 – Volledige Rogue LDAP server (aanbeveel)

’n Drukker kan ’n geldige LDAP-antwoord vereis voordat dit probeer bind.<sup>[[10]](#references)</sup> ’n Volledige LDAP-bediener kan daardie voorlopige uitruiling hanteer, maar dit kan nie ’n kliënt wat aan ’n sterk SASL-meganisme of die bedoelde TLS-bediener gebind is, sy wagwoord laat openbaar nie.<sup>[[8]](#references)[[10]](#references)</sup>

```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # use a base DN compatible with the printer lookup

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```

Behandel ’n opsoek as bewys van ’n verbinding, nie as bewys dat ’n wagwoord openbaar gemaak is nie. ’n Wagwoord word slegs blootgestel as die kliënt ’n bind met ’n wagwoord in gewone teks stuur; kontroleer die werklike bind-meganisme en TLS-status.<sup>[[8]](#references)</sup>

> 💡  Responder sluit rogue LDAP- en SMB-verifikasiedienste in. ’n Eenvoudige LDAP-bind kan die gekonfigureerde wagwoord blootstel, terwyl NTLM-verifikasie challenge-response-materiaal oplewer; moenie albei uitkomste as ’n wagwoord in gewone teks beskryf nie.

### Keuse van SASL-meganisme

Sommige drukker-LDAP-kliënte kies uit die meganismes wat ’n LDAP-bediener adverteer.<sup>[[8]](#references)[[10]](#references)</sup> Navorsing het getoon dat ’n kliënt wat bereid is om ’n geadverteerde SASL-meganisme in gewone teks te aanvaar, ’n wagwoord kan stuur, terwyl sy gewone NTLM-onderhandeling slegs challenge-response-data sou oplewer.<sup>[[9]](#references)[[10]](#references)</sup> Dit is ’n **kliëntbeleidsfaling**, nie ’n eienskap van alle SASL-binds nie: ’n kliënt wat ’n sterker meganisme vereis of die beoogde TLS-bediener vaspen, behoort eerder veilig te faal.<sup>[[8]](#references)</sup> OpenLDAP deaktiveer SASL-meganismes wat gewone teks ondersteun by verstek, dus bewys ’n standaard-daemon nie dat hierdie gedrag op ’n drukker voorkom nie.<sup>[[11]](#references)</sup>

---

## Onlangse Pass-Back-kwesbaarhede (2024-2025)

Pass-back is *nie* ’n teoretiese probleem nie – verskaffers publiseer steeds in 2024/2025 sekuriteitsbulletins wat hierdie aanvalsklas presies beskryf.

### Xerox VersaLink – CVE-2024-12510 & CVE-2024-12511

Firmware ≤ 57.69.91 van Xerox VersaLink C70xx MFP’s het ’n geverifieerde admin (of enigiemand indien die verstekbewyse steeds gebruik word) toegelaat om:

* **CVE-2024-12510 – LDAP pass-back**: die LDAP-bedieneradres te verander en ’n opsoek te aktiveer, wat veroorsaak dat die toestel die gekonfigureerde Windows-aanmeldbewyse na die aanvallerbeheerde gasheer lek.
* **CVE-2024-12511 – SMB/FTP pass-back**: dieselfde probleem via *scan-to-folder*-bestemmings, wat NetNTLMv2- of FTP-aanmeldbewyse in gewone teks uitlek.<sup>[[2]](#references)</sup>

’n Eenvoudige listener soos:

```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```

of ’n skelm SMB-bediener (`impacket-smbserver`) is genoeg om die aanmeldbesonderhede te oes.  

### Canon imageRUNNER / imageCLASS – Advies van 20 Mei 2025

Canon het ’n **SMTP/LDAP pass-back**-swakheid in dosyne Laser- en MFP-produklyne bevestig. ’n Aanvaller met admin-toegang kan die bedienerkonfigurasie wysig en die gestoorde aanmeldbesonderhede vir LDAP **of** SMTP herwin (baie organisasies gebruik ’n bevoorregte rekening om skandeer-na-e-pos moontlik te maak).<sup>[[3]](#references)</sup>

Die verskaffer se leiding beveel uitdruklik die volgende aan:

1. Werk so gou moontlik na reggestelde firmware op.
2. Gebruik sterk, unieke admin-wagwoorde.
3. Vermy bevoorregte AD-rekeninge vir drukkerintegrasie.

---

### Brother-toestelle en OEM-variante – admin-toegang afgelei van reeksnommer lei tot diensaanmeldbesonderhede

’n Gekoördineerde bekendmaking in 2025 het ’n besonder nuttige aanvalsketting op geraakte Brother-toestelle gedemonstreer; dele van die kwesbaarheidsversameling raak ook OEM-modelle, dus moet jy die presiese model aan die hand van die verskaffer se advies verifieer. ’n Aanvaller sonder verifikasie kan die toestel se reeksnommer via HTTP/HTTPS/IPP op kwesbare firmware verkry, terwyl reeksnommers moontlik ook via bestuursprotokolle soos SNMP of PJL beskikbaar is. As die fabriekswagwoord nooit verander is nie, bepaal die reeksnommer die admin-wagwoord. Ná verifikasie stel die afsonderlike pass-back-fout CVE-2024-51984 gekonfigureerde wagwoorde vir eksterne dienste, soos LDAP of FTP, in gewone teks bloot, wat toegang tot drukkerbestuur omskep in herbruikbare netwerkaanmeldbesonderhede. Firmware herstel die blootlegging van dienswagwoorde, maar toestelle wat reeds vervaardig is, vereis steeds dat die operateur die aanvanklike admin-wagwoord wat van die reeksnommer afgelei is, vervang.<sup>[[6]](#references)</sup>

Huidige Metasploit sluit ’n auxiliary-module in wat die reeksnommer via HTTP, SNMP of PJL ontdek, ’n kandidaat-aanvanklike wagwoord genereer en dit opsioneel teen die webkonsole verifieer. `DiscoverSerialVia=AUTO` probeer die ondersteunde ontdekkingsmetodes; verskaf eerder `TargetSerial` wanneer die bate-inventaris reeds die reeksnommer bevat.<sup>[[7]](#references)</sup>

```text
msfconsole -q
use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978
set RHOSTS <printer-ip>
set DiscoverSerialVia AUTO
run
```

Gebruik die resultaat slegs om gemagtigde bates te valideer. Of die wagwoord werk, hang af van die presiese model en, van kritieke belang, of die fabrieksadministrateurwagwoord reeds verander is.<sup>[[6]](#references)[[7]](#references)</sup>

---

## Outomatiese Enumerasie- / Exploitation-nutsgoed

| Tool | Doel | Voorbeeld |
|------|---------|---------|
| **PRET** (Printer Exploitation Toolkit) | Misbruik van PostScript/PJL/PCL, toegang tot lêerstelsel, nagaan van verstekbewyse, *SNMP discovery*; sien [PJL-assessering](../../network-services-pentesting/9100-pjl.md) | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | Oes konfigurasie (insluitend adresboeke en LDAP-bewyse) via HTTP/HTTPS | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | Laat kwaadwillige authentication services loop en vang/relê NetNTLM vanaf SMB-callbacks | `sudo responder -I eth0 -v` |
| **Metasploit Brother auxiliary** | Ontdek 'n reeksnommer, lei die moontlike fabrieksadministrateurwagwoord af en verifieer toegang tot die webkonsole | `use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978` |

---

## Versterking en opsporing

1. **Pas opdaterings toe / dateer firmware op** MFP's stiptelik op (raadpleeg die verskaffer se PSIRT-bulletins).
2. **Vervang fabrieksadministrateurwagwoorde** – firmware alleen verwyder nie reeksnommer-afgeleide aanvanklike wagwoorde van voorheen vervaardigde geaffekteerde Brother/OEM-toestelle nie.<sup>[[6]](#references)</sup>
3. **Diensrekeninge met die minste voorregte** – gebruik nooit Domain Admin vir LDAP/SMB/SMTP nie; beperk dit tot *leesalleen*-OU-omvang.
4. **Beperk bestuurstoegang** – plaas printerweb-/IPP-/SNMP-koppelvlakke in 'n bestuurs-VLAN of agter 'n ACL/VPN.
5. **Beperk printer-uitgaande verkeer** – laat elke toestel slegs toe om die verwagte DC/LDAP-, pos-, DNS/NTP-, druk- en skandeer-lêerbestemmings te kontak. Pass-back vereis 'n callback na 'n aanvaller-geselekteerde eindpunt.
6. **Deaktiveer ongebruikte protokolle** – FTP, Telnet, raw-9100, ouer SSL-ciphers.
7. **Aktiveer ouditregistrasie** – sommige toestelle kan LDAP/SMTP-foute na syslog stuur; korreleer onverwagte binds.
8. **Monitor authentication-bestemmings** – waarsku wanneer 'n printer LDAP, SMB, SMTP of FTP na 'n gasheer buite sy allowlist begin, veral onmiddellik ná 'n bestuursaanmelding of konfigurasieverandering.
9. **SNMPv3 of deaktiveer SNMP** – community `public` lek dikwels toestel- en reeksnommerinligting.

---



---



## References

- [1] [Dis net 'n printer… Wat is die ergste wat kan gebeur?](https://grimhacker.com/2018/03/09/just-a-printer/)
- [2] [Xerox Versalink C7025 Multifunction Printer: Pass-Back-aanvalkwesbaarhede (reggestel)](https://www.rapid7.com/blog/post/2025/02/14/xerox-versalink-c7025-multifunction-printer-pass-back-attack-vulnerabilities-fixed/)
- [3] [CP2025-004: Kwesbaarheidsversagting/-remediëring vir produksieprinters, multifunksieprinters vir kantore/klein kantore en laserprinters](https://psirt.canon/advisory-information/cp2025-004/)
- [4] [Verkryging van domeinbewyse deur 'n printer met Netcat](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [5] [Exploiting Multifunction Printers During A Penetration Test Engagement](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [6] [Verskeie Brother-toestelle: Verskeie kwesbaarhede (REGGESTEL)](https://www.rapid7.com/blog/post/multiple-brother-devices-multiple-vulnerabilities-fixed/)
- [7] [Metasploit: Brother-module vir die omseiling van verstekadministrateur-authentication](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978.rb)
- [8] [RFC 4513 – LDAP-authenticationmetodes en sekuriteitsmeganismes](https://datatracker.ietf.org/doc/html/rfc4513)
- [9] [LDAP-passback-Docker-bediener](https://github.com/cybertrinchera/ldap-passback-docker)
- [10] [LDAP-passback-aanval – ACCEIS](https://www.acceis.fr/ldap-pass-back-attack/)
- [11] [slapd-config(5) – SASL-sekuriteitseienskappe](https://man7.org/linux/man-pages/man5/slapd-config.5.html)
{{#include ../../banners/hacktricks-training.md}}
