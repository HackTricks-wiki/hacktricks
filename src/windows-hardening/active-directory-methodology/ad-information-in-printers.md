# Taarifa katika Printers

{{#include ../../banners/hacktricks-training.md}}

Kuna blogu kadhaa kwenye Internet ambazo **zinaangazia hatari za kuacha printers zikiwa zimesanidiwa kwa LDAP na credentials za logon za default/weak**.  \
Hii ni kwa sababu mshambuliaji anaweza **kuidanganya printer ili iauthenticate dhidi ya rogue LDAP server** (kwa kawaida `nc -vv -l -p 389` au `slapd -d 2` inatosha) na kunasa **credentials za printer katika clear-text**.

Pia, printers kadhaa huwa na **logs zenye usernames** au zinaweza hata **kupakua usernames zote** kutoka kwa Domain Controller.

Hii yote **sensitive information** pamoja na **ukosefu wa usalama** unaoonekana mara kwa mara hufanya printers zivutie sana kwa attackers.

Baadhi ya blogu za utangulizi kuhusu mada hii:

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)<sup>[[4]](#references)</sup>
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)<sup>[[5]](#references)</sup>

---

## Usanidi wa Printer

- **Mahali**: Orodha ya LDAP server kwa kawaida hupatikana katika web interface (mfano, *Network ➜ LDAP Setting ➜ Setting Up LDAP*).
- **Tabia**: Embedded web servers nyingi huruhusu marekebisho ya LDAP server **bila kuingiza tena credentials** (kipengele cha usability → security risk).
- **Exploit**: Elekeza anwani ya LDAP server kwenye host inayodhibitiwa na attacker na utumie kitufe cha *Test Connection* / *Address Book Sync* ili kulazimisha printer ibind kwako.

---

## Kunasa Credentials

### Method 1 – Netcat Listener
```bash
sudo nc -k -v -l -p 389     # Plain LDAP only
```
MFP ndogo/za zamani zinaweza kutuma *simple-bind* rahisi ambapo bind DN na password vinaonekana kwenye raw BER stream. Vifaa vya kisasa kwa kawaida hufanya query ya anonymous kwanza kisha kujaribu bind, hivyo matokeo hutofautiana.<sup>[[1]](#references)</sup>

Kisikiaji cha `nc` cha kawaida kwenye 636/3269 hupokea tu TLS ciphertext; kujaribu LDAPS kunahitaji LDAP endpoint yenye uwezo wa TLS, na redirection inapaswa kushindikana wakati kifaa kinathibitisha kwa usahihi certificate ya server.

### Method 2 – LDAP server ghushi kamili (inapendekezwa)

Kwa sababu vifaa vingi vitafanya anonymous search *kabla* ya ku-authenticate, kusimamisha LDAP daemon halisi hutoa matokeo yanayoaminika zaidi:<sup>[[1]](#references)</sup>
```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # set any base-DN – it will not be validated

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```
Wakati printer inafanya lookup yake, utaona credentials zilizo katika clear-text kwenye debug output.

> 💡  Responder inajumuisha rogue LDAP na SMB authentication services. LDAP bind rahisi inaweza kufichua password iliyosanidiwa, ilhali NTLM authentication huzalisha challenge-response material; usieleze matokeo yote mawili kama password ya clear-text.

---

## Recent Pass-Back Vulnerabilities (2024-2025)

Pass-back *si* suala la kinadharia – vendors wanaendelea kuchapisha advisories katika 2024/2025 zinazoeleza hasa aina hii ya attack.

### Xerox VersaLink – CVE-2024-12510 & CVE-2024-12511

Firmware ≤ 57.69.91 ya Xerox VersaLink C70xx MFPs iliwezesha admin aliye-authenticate (au mtu yeyote wakati default creds bado zipo) kufanya yafuatayo:

* **CVE-2024-12510 – LDAP pass-back**: kubadilisha anwani ya LDAP server na ku-trigger lookup, na kusababisha device ku-leak Windows credentials zilizosanidiwa kwenda kwenye host inayodhibitiwa na attacker.
* **CVE-2024-12511 – SMB/FTP pass-back**: suala hilohilo kupitia destinations za *scan-to-folder*, liki-leak NetNTLMv2 au FTP clear-text creds.<sup>[[2]](#references)</sup>

Listener rahisi kama huu:
```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```
au seva SMB server (`impacket-smbserver`) inatosha kuvuna credentials.

### Canon imageRUNNER / imageCLASS – Ushauri wa 20 Mei 2025

Canon ilithibitisha udhaifu wa **SMTP/LDAP pass-back** katika safu kadhaa za bidhaa za Laser & MFP. Mshambulizi mwenye admin access anaweza kurekebisha usanidi wa server na kupata credentials zilizohifadhiwa za LDAP **au** SMTP (mashirika mengi hutumia akaunti yenye privileged access ili kuruhusu scan-to-mail).<sup>[[3]](#references)</sup>

Mwongozo wa vendor unapendekeza wazi:

1. Kusasisha hadi firmware iliyo na patch mara tu inapopatikana.
2. Kutumia admin passwords imara na za kipekee.
3. Kuepuka akaunti za AD zenye privileged access kwa ajili ya printer integration.

---

### Vifaa vya Brother na OEM variants – admin access inayotokana na serial hadi service credentials

Disclosure iliyoratibiwa ya 2025 ilionyesha chain yenye manufaa hasa kwenye vifaa vya Brother vilivyoathirika; sehemu za vulnerability set pia zinaathiri OEM models, kwa hiyo thibitisha model halisi dhidi ya vendor advisory yake. Mshambulizi asiye na authentication anaweza kupata serial ya kifaa kupitia HTTP/HTTPS/IPP kwenye firmware iliyo hatarini, huku serials pia zikipatikana kupitia management protocols kama SNMP au PJL. Ikiwa factory password haikuwahi kubadilishwa, serial hutengeneza administrator password kwa njia ya deterministic. Baada ya kufanya authentication, pass-back flaw tofauti CVE-2024-51984 hufichua external-service passwords zilizosanidiwa kama LDAP au FTP katika plaintext, na kubadilisha printer-management access kuwa network credentials zinazoweza kutumika tena. Firmware hurekebisha service-password disclosure, lakini vifaa vilivyotengenezwa hapo awali bado vinahitaji operator kubadilisha initial administrator password inayotokana na serial.<sup>[[6]](#references)</sup>

Metasploit ya sasa inajumuisha auxiliary module inayogundua serial kupitia HTTP, SNMP, au PJL, inatengeneza candidate initial password, na kwa hiari kuithibitisha dhidi ya web console. `DiscoverSerialVia=AUTO` hujaribu discovery paths zinazotumika; toa `TargetSerial` badala yake wakati asset inventory tayari ina serial.<sup>[[7]](#references)</sup>
```text
msfconsole -q
use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978
set RHOSTS <printer-ip>
set DiscoverSerialVia AUTO
run
```
Tumia matokeo haya pekee kuthibitisha assets zilizoidhinishwa. Ikiwa password itafanya kazi inategemea model halisi na, muhimu zaidi, ikiwa factory administrator password tayari imebadilishwa.<sup>[[6]](#references)[[7]](#references)</sup>

---

## Automated Enumeration / Exploitation Tools

| Tool | Purpose | Example |
|------|---------|---------|
| **PRET** (Printer Exploitation Toolkit) | Matumizi mabaya ya PostScript/PJL/PCL, ufikiaji wa file-system, ukaguzi wa default-creds, *SNMP discovery* | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | Kukusanya configuration (ikiwemo address books & LDAP creds) kupitia HTTP/HTTPS | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | Kuendesha huduma za rogue authentication na capture/relay NetNTLM kutoka SMB callbacks | `sudo responder -I eth0 -v` |
| **Metasploit Brother auxiliary** | Kugundua serial, kupata candidate factory administrator password, na kuthibitisha ufikiaji wa web-console | `use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978` |

---

## Hardening & Detection

1. **Patch / firmware-update** MFPs kwa wakati (angalia taarifa za vendor PSIRT).
2. **Badilisha factory administrator passwords** – firmware pekee haiondoi initial passwords zinazotokana na serial kutoka kwenye Brother/OEM devices zilizoathirika na kutengenezwa hapo awali.<sup>[[6]](#references)</sup>
3. **Least-Privilege Service Accounts** – usiwahi kutumia Domain Admin kwa LDAP/SMB/SMTP; zuia kwenye OU scopes za *read-only*.
4. **Zuia Management Access** – weka printer web/IPP/SNMP interfaces kwenye management VLAN au nyuma ya ACL/VPN.
5. **Punguza printer egress** – ruhusu kila device kuwasiliana tu na DC/LDAP, mail, DNS/NTP, print, na scan-file destinations zinazotarajiwa. Pass-back inahitaji callback kwenda endpoint iliyochaguliwa na attacker.
6. **Disable Unused Protocols** – FTP, Telnet, raw-9100, SSL ciphers za zamani.
7. **Enable Audit Logging** – baadhi ya devices zinaweza kurekodi LDAP/SMTP failures kupitia syslog; linganisha binds zisizotarajiwa.
8. **Fuatilia authentication destinations** – toa alert printer inapoanzisha LDAP, SMB, SMTP, au FTP kwenda host iliyo nje ya allowlist yake, hasa mara tu baada ya management login au configuration change.
9. **SNMPv3 au disable SNMP** – community `public` mara nyingi huleak device na serial information.

---



---

## References

- [1] [Ni printer tu… Ni jambo gani baya zaidi linaloweza kutokea?](https://grimhacker.com/2018/03/09/just-a-printer/)
- [2] [Xerox Versalink C7025 Multifunction Printer: Vulnerabilities za Pass-Back Attack (Zimetatuliwa)](https://www.rapid7.com/blog/post/2025/02/14/xerox-versalink-c7025-multifunction-printer-pass-back-attack-vulnerabilities-fixed/)
- [3] [CP2025-004 Vulnerability Mitigation/Remediation kwa Production Printers, Office/Small Office Multifunction Printers na Laser Printers](https://psirt.canon/advisory-information/cp2025-004/)
- [4] [Kupata Domain Credentials kupitia Printer kwa kutumia Netcat](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [5] [Kuexploit Multifunction Printers wakati wa Penetration Test Engagement](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [6] [Brother Devices Nyingi: Vulnerabilities Nyingi (ZIMETATULIWA)](https://www.rapid7.com/blog/post/multiple-brother-devices-multiple-vulnerabilities-fixed/)
- [7] [Metasploit: Brother default administrator authentication bypass module](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978.rb)
{{#include ../../banners/hacktricks-training.md}}
