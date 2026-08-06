# Taarifa katika Printers

{{#include ../../banners/hacktricks-training.md}}

Kuna blogu kadhaa kwenye Internet ambazo **zinaangazia hatari za kuacha printers zikiwa zimesanidiwa kwa LDAP zikiwa na** credentials **za kuingia za msingi/dhaifu**.  \
Hii ni kwa sababu mshambuliaji anaweza **kudanganya printer ithibitishe dhidi ya rogue LDAP server** (kwa kawaida `nc -vv -l -p 389` au `slapd -d 2` inatosha) na kunasa **credentials za printer katika maandishi wazi**.

Pia, printers kadhaa zitakuwa na **logs zenye usernames** au zinaweza hata **kupakua usernames zote** kutoka kwa Domain Controller.

Taarifa hizi zote **nyeti** pamoja na **ukosefu wa usalama** unaoonekana mara kwa mara huwafanya printers kuvutia sana kwa attackers.

Baadhi ya blogu za utangulizi kuhusu mada hii:

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)<sup>[[4]](#references)</sup>
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)<sup>[[5]](#references)</sup>

---

## Usanidi wa Printer

- **Mahali**: Orodha ya LDAP server kwa kawaida hupatikana katika web interface (mfano *Network ➜ LDAP Setting ➜ Setting Up LDAP*).
- **Tabia**: Embedded web servers nyingi huruhusu marekebisho ya LDAP server **bila kuingiza tena credentials** (kipengele cha usability → security risk).
- **Exploit**: Elekeza anwani ya LDAP server kwenye host inayodhibitiwa na attacker na utumie kitufe cha *Test Connection* / *Address Book Sync* kulazimisha printer ifanye bind kwako.

---

## Kukamata Credentials

### Method 1 – Netcat Listener
```bash
sudo nc -k -v -l -p 389     # LDAPS → 636 (or 3269)
```
MFP ndogo/za zamani zinaweza kutuma *simple-bind* rahisi kwa clear-text ambayo netcat inaweza kunasa. Vifaa vya kisasa kwa kawaida hufanya query ya anonymous kwanza kisha hujaribu bind, kwa hiyo matokeo hutofautiana.<sup>[[1]](#references)</sup>

### Mbinu 2 – Full Rogue LDAP server (inayopendekezwa)

Kwa sababu vifaa vingi vitatoa search ya anonymous *kabla* ya kufanya authentication, kuanzisha LDAP daemon halisi hutoa matokeo yanayoaminika zaidi:<sup>[[1]](#references)</sup>
```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # set any base-DN – it will not be validated

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```
Unapochapisha kifaa kinapotekeleza lookup yake, utaona credentials zilizo katika clear-text kwenye debug output.

> 💡  Unaweza pia kutumia `impacket/examples/ldapd.py` (Python rogue LDAP) au `Responder -w -r -f` kuvuna NTLMv2 hashes kupitia LDAP/SMB.

---

## Recent Pass-Back Vulnerabilities (2024-2025)

Pass-back *si* suala la kinadharia – vendors wanaendelea kuchapisha advisories mwaka wa 2024/2025 zinazoeleza kikamilifu aina hii ya attack.

### Xerox VersaLink – CVE-2024-12510 & CVE-2024-12511

Firmware ≤ 57.69.91 ya Xerox VersaLink C70xx MFPs iliwaruhusu admin aliye-authenticate (au mtu yeyote ikiwa default creds bado zipo) kufanya yafuatayo:

* **CVE-2024-12510 – LDAP pass-back**: kubadilisha anwani ya LDAP server na kuanzisha lookup, hali inayosababisha kifaa ku-leak Windows credentials zilizosanidiwa kwenda kwenye host inayodhibitiwa na attacker.
* **CVE-2024-12511 – SMB/FTP pass-back**: suala lilelile kupitia destinations za *scan-to-folder*, liki-leak NetNTLMv2 au FTP clear-text creds.<sup>[[2]](#references)</sup>

Listener rahisi kama huu:
```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```
au rogue SMB server (`impacket-smbserver`) inatosha kuvuna credentials.

### Canon imageRUNNER / imageCLASS – Ushauri wa 20 Mei 2025

Canon ilithibitisha udhaifu wa **SMTP/LDAP pass-back** katika mistari kadhaa ya bidhaa za Laser & MFP. Mshambuliaji aliye na ufikiaji wa admin anaweza kubadilisha usanidi wa server na kupata credentials zilizohifadhiwa za LDAP **au** SMTP (mashirika mengi hutumia akaunti yenye privileged access kuruhusu scan-to-mail).<sup>[[3]](#references)</sup>

Mwongozo wa vendor unapendekeza wazi:

1. Kusasisha hadi firmware yenye patch mara tu inapopatikana.
2. Kutumia nywila za admin imara na za kipekee.
3. Kuepuka akaunti za AD zenye privileged access kwa ajili ya integration ya printer.

---

## Zana za Automated Enumeration / Exploitation

| Zana | Madhumuni | Mfano |
|------|---------|---------|
| **PRET** (Printer Exploitation Toolkit) | Matumizi mabaya ya PostScript/PJL/PCL, ufikiaji wa file-system, ukaguzi wa default-creds, *SNMP discovery* | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | Kuvuna usanidi (ikiwemo address books na LDAP creds) kupitia HTTP/HTTPS | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | Kukamata na ku-relay NetNTLM hashes kutoka SMB/FTP pass-back | `responder -I eth0 -wrf` |
| **impacket-ldapd.py** | Huduma nyepesi ya rogue LDAP ya kupokea binds zilizo katika clear-text | `python ldapd.py -debug` |

---

## Hardening & Detection

1. **Patch / firmware-update** MFPs kwa wakati (angalia taarifa za PSIRT za vendor).
2. **Akaunti za Service zenye Least Privilege** – kamwe usitumie Domain Admin kwa LDAP/SMB/SMTP; zuia matumizi yake kwenye scopes za OU za *read-only*.
3. **Zuia Ufikiaji wa Management** – weka interfaces za printer za web/IPP/SNMP kwenye management VLAN au nyuma ya ACL/VPN.
4. **Zima Protocols Zisizotumika** – FTP, Telnet, raw-9100, na SSL ciphers za zamani.
5. **Washa Audit Logging** – baadhi ya vifaa vinaweza kutuma kushindwa kwa LDAP/SMTP kwenye syslog; linganisha binds zisizotarajiwa.
6. **Fuatilia clear-text LDAP binds** kutoka kwenye sources zisizo za kawaida (kwa kawaida printers zinapaswa kuwasiliana tu na DCs).
7. **SNMPv3 au zima SNMP** – community `public` mara nyingi hu-leak usanidi wa kifaa na LDAP.

---

## References

- [1] [It's just a printer… What's the worst that could happen?](https://grimhacker.com/2018/03/09/just-a-printer/)
- [2] [Xerox Versalink C7025 Multifunction Printer: Pass-Back Attack Vulnerabilities (Fixed)](https://www.rapid7.com/blog/post/2025/02/14/xerox-versalink-c7025-multifunction-printer-pass-back-attack-vulnerabilities-fixed/)
- [3] [CP2025-004 Vulnerability Mitigation/Remediation for Production Printers, Office/Small Office Multifunction Printers and Laser Printers](https://psirt.canon/advisory-information/cp2025-004/)
- [4] [Obtaining Domain Credentials through a Printer with Netcat](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [5] [Exploiting Multifunction Printers During A Penetration Test Engagement](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

{{#include ../../banners/hacktricks-training.md}}
