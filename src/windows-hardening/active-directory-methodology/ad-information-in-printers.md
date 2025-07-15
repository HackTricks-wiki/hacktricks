# Habari katika Printa

{{#include ../../banners/hacktricks-training.md}}

Kuna blogu kadhaa kwenye Mtandao ambazo **zinasisitiza hatari za kuacha printa zikiwa zimewekwa na LDAP zikiwa na** akauti za kuingia za kawaida/dhaifu.  \
Hii ni kwa sababu mshambuliaji anaweza **kudanganya printa kujiunga na seva ya LDAP isiyo halali** (kawaida `nc -vv -l -p 389` au `slapd -d 2` inatosha) na kukamata **akauti za printa kwa maandiko wazi**.

Pia, printa kadhaa zitakuwa na **kumbukumbu za majina ya watumiaji** au zinaweza hata kuwa na uwezo wa **kupakua majina yote ya watumiaji** kutoka kwa Kituo cha Kikoa.

Habari hii **nyeti** na **ukosefu wa usalama** wa kawaida inafanya printa kuwa za kuvutia sana kwa washambuliaji.

Baadhi ya blogu za utangulizi kuhusu mada hii:

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

---
## Mipangilio ya Printa

- **Mahali**: Orodha ya seva ya LDAP kwa kawaida hupatikana kwenye kiolesura cha wavuti (mfano *Network ➜ LDAP Setting ➜ Setting Up LDAP*).
- **Tabia**: Seva nyingi za wavuti zilizojumuishwa zinaruhusu mabadiliko ya seva ya LDAP **bila kuingiza tena akauti** (kipengele cha matumizi → hatari ya usalama).
- **Kuvunja**: Elekeza anwani ya seva ya LDAP kwa mwenyeji anayedhibitiwa na mshambuliaji na tumia kitufe cha *Test Connection* / *Address Book Sync* kulazimisha printa kujiunga na wewe.

---
## Kukamata Akauti

### Njia 1 – Netcat Listener
```bash
sudo nc -k -v -l -p 389     # LDAPS → 636 (or 3269)
```
Small/old MFPs zinaweza kutuma *simple-bind* rahisi katika maandiko wazi ambayo netcat inaweza kukamata. Vifaa vya kisasa kawaida hufanya uchunguzi wa kutokujulikana kwanza na kisha kujaribu kuunganisha, hivyo matokeo yanatofautiana.

### Method 2 – Full Rogue LDAP server (recommended)

Kwa sababu vifaa vingi vitatoa utafutaji wa kutokujulikana *kabla* ya kuthibitisha, kusimika daemon halisi ya LDAP kunatoa matokeo ya kuaminika zaidi:
```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # set any base-DN – it will not be validated

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```
Wakati printer inafanya utafutaji wake utaona akiba ya wazi ya taarifa za kuingia katika matokeo ya debug.

> 💡 Unaweza pia kutumia `impacket/examples/ldapd.py` (Python rogue LDAP) au `Responder -w -r -f` kukusanya NTLMv2 hashes kupitia LDAP/SMB.

---
## Uthibitisho wa Hivi Karibuni wa Pass-Back (2024-2025)

Pass-back *sio* suala la nadharia – wauzaji wanaendelea kuchapisha taarifa katika 2024/2025 ambazo zinaelezea kwa usahihi darasa hili la shambulio.

### Xerox VersaLink – CVE-2024-12510 & CVE-2024-12511

Firmware ≤ 57.69.91 ya Xerox VersaLink C70xx MFPs iliruhusu admin aliyeidhinishwa (au mtu yeyote wakati akiba za kawaida zinabaki) kufanya:

* **CVE-2024-12510 – LDAP pass-back**: kubadilisha anwani ya seva ya LDAP na kuanzisha utafutaji, ikisababisha kifaa kuvuja taarifa za kuingia za Windows zilizowekwa kwa mwenye shambulio.
* **CVE-2024-12511 – SMB/FTP pass-back**: suala sawa kupitia *scan-to-folder* maeneo, ikivuja NetNTLMv2 au FTP akiba ya wazi ya taarifa za kuingia.

Msikilizaji rahisi kama:
```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```
or a rogue SMB server (`impacket-smbserver`) is enough to harvest the credentials.

### Canon imageRUNNER / imageCLASS – Advisory 20 Mei 2025

Canon ilithibitisha udhaifu wa **SMTP/LDAP pass-back** katika mfululizo wa bidhaa za Laser & MFP. Mshambuliaji mwenye ufikiaji wa admin anaweza kubadilisha usanidi wa seva na kupata akiba ya taarifa za kuingia za LDAP **au** SMTP (mashirika mengi hutumia akaunti yenye mamlaka kuruhusu skana-kwa-barua).

Mwongozo wa muuzaji unashauri wazi:

1. Kusasisha firmware iliyorekebishwa mara tu inapatikana.
2. Kutumia nywila za admin zenye nguvu na za kipekee.
3. Kuepuka akaunti za AD zenye mamlaka kwa ajili ya uunganisho wa printer.

---
## Zana za Uhesabuji wa Otomatiki / Ukatili

| Zana | Kusudi | Mfano |
|------|---------|---------|
| **PRET** (Printer Exploitation Toolkit) | Unyanyasaji wa PostScript/PJL/PCL, ufikiaji wa mfumo wa faili, ukaguzi wa default-creds, *SNMP discovery* | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | Kukusanya usanidi (ikiwemo vitabu vya anwani & LDAP creds) kupitia HTTP/HTTPS | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | Kukamata & kuhamasisha NetNTLM hashes kutoka SMB/FTP pass-back | `responder -I eth0 -wrf` |
| **impacket-ldapd.py** | Huduma ya LDAP isiyo na uzito kupokea viunganishi vya maandiko wazi | `python ldapd.py -debug` |

---
## Kuimarisha & Ugunduzi

1. **Patch / firmware-update** MFPs mara moja (angalia taarifa za PSIRT za muuzaji).
2. **Akaunti za Huduma za Least-Privilege** – kamwe usitumie Domain Admin kwa LDAP/SMB/SMTP; punguza kwa *read-only* OU scopes.
3. **Punguza Ufikiaji wa Usimamizi** – weka interfaces za printer web/IPP/SNMP katika VLAN ya usimamizi au nyuma ya ACL/VPN.
4. **Zima Protokali Zisizotumika** – FTP, Telnet, raw-9100, ciphers za SSL za zamani.
5. **Washa Usajili wa Ukaguzi** – baadhi ya vifaa vinaweza syslog LDAP/SMTP failures; linganisha viunganishi visivyotarajiwa.
6. **Fuatilia Viunganishi vya LDAP vya Maandishi Wazi** kutoka vyanzo visivyo vya kawaida (printer zinapaswa kuzungumza tu na DCs).
7. **SNMPv3 au zima SNMP** – jamii `public` mara nyingi inavuja usanidi wa kifaa & LDAP.

---
## Marejeleo

- [https://grimhacker.com/2018/03/09/just-a-printer/](https://grimhacker.com/2018/03/09/just-a-printer/)
- Rapid7. “Xerox VersaLink C7025 MFP Pass-Back Attack Vulnerabilities.” Februari 2025.
- Canon PSIRT. “Vulnerability Mitigation Against SMTP/LDAP Passback for Laser Printers and Small Office Multifunction Printers.” Mei 2025.

{{#include ../../banners/hacktricks-training.md}}
