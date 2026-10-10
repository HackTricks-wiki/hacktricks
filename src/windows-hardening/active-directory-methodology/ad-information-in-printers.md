# Taarifa katika Printa

{{#include ../../banners/hacktricks-training.md}}

Kuna blogu kadhaa kwenye Internet ambazo **zinaangazia hatari za kuacha printa zikiwa zimesanidiwa kutumia LDAP zikiwa na sifa-msingi/dhaifu za kuingia**.  \
Hii ni kwa sababu mshambulizi anaweza **kuhadaa printa ithibitishe utambulisho wake dhidi ya seva hasidi ya LDAP** (kwa kawaida, `nc -vv -l -p 389` au `slapd -d 2` inatosha) na kunasa **sifa za printa katika maandishi yasiyosimbwa**.

Pia, printa kadhaa huwa na **kumbukumbu zenye majina ya watumiaji** au zinaweza hata **kupakua majina yote ya watumiaji** kutoka kwa Domain Controller.

Taarifa hizi zote **nyeti** na **ukosefu wa kawaida wa usalama** hufanya printa zivutie sana kwa washambuliaji.

Baadhi ya blogu za utangulizi kuhusu mada hii:

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)<sup>[[4]](#references)</sup>
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)<sup>[[5]](#references)</sup>

---

## Usanidi wa Printa

- **Mahali**: Orodha ya seva za LDAP kwa kawaida hupatikana kwenye kiolesura cha wavuti (k.m. *Network ➜ LDAP Setting ➜ Setting Up LDAP*).
- **Tabia**: Seva nyingi za wavuti zilizopachikwa huruhusu marekebisho ya seva ya LDAP **bila kuingiza tena sifa za kuingia** (kipengele cha urahisi → hatari ya usalama).
- **Unyonyaji**: Elekeza upya anwani ya seva ya LDAP kwenye seva inayodhibitiwa na mshambuliaji, kisha utumie kitufe cha *Test Connection* / *Address Book Sync* ili kulazimisha printa ifanye bind kwako.

---

## Kunasa Sifa za Kuingia

### Mbinu ya 1 – Kisikilizaji cha Netcat

```bash
sudo nc -k -v -l -p 389     # Plain LDAP only
```

MFP ndogo/za zamani zinaweza kutuma *simple-bind* rahisi ambapo bind DN na nenosiri vinaonekana kwenye mtiririko ghafi wa BER. Vifaa vya kisasa kwa kawaida huanza kwa kufanya query isiyojulikana kisha kujaribu bind, kwa hiyo matokeo hutofautiana.<sup>[[1]](#references)</sup>

Kisikilizi cha kawaida cha `nc` kwenye 636/3269 hupokea tu ciphertext ya TLS; kupima LDAPS kunahitaji endpoint ya LDAP inayoweza kutumia TLS, na uelekezaji upya unapaswa kushindwa kifaa kinapothibitisha cheti cha seva ipasavyo.

### Method 2 – Seva kamili ya Rogue LDAP (inayopendekezwa)

Kwa kuwa vifaa vingi vitatuma search isiyojulikana *kabla* ya kuthibitisha utambulisho, kuanzisha daemon halisi ya LDAP hutoa matokeo ya kuaminika zaidi:<sup>[[1]](#references)</sup>

```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # set any base-DN – it will not be validated

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```

Wakati printa inapofanya utafutaji wake, utaona credentials za maandishi wazi kwenye matokeo ya utatuzi.

> 💡 Responder inajumuisha huduma ghushi za uthibitishaji za LDAP na SMB. LDAP bind rahisi inaweza kufichua password iliyosanidiwa, ilhali uthibitishaji wa NTLM huzalisha nyenzo za challenge-response; usieleze matokeo yote mawili kama password ya maandishi wazi.

---

## Vulnerabilities za Hivi Karibuni za Pass-Back (2024-2025)

Pass-back si suala la kinadharia – vendors wanaendelea kuchapisha advisories mwaka 2024/2025 zinazoeleza aina hii ya shambulio moja kwa moja.

### Xerox VersaLink – CVE-2024-12510 & CVE-2024-12511

Firmware ≤ 57.69.91 ya Xerox VersaLink C70xx MFPs ilimwezesha admin aliyeidhinishwa (au mtu yeyote ikiwa credentials chaguomsingi bado zinatumika) kufanya yafuatayo:

* **CVE-2024-12510 – LDAP pass-back**: kubadilisha anwani ya seva ya LDAP na kuanzisha utafutaji, na kusababisha kifaa kuvuja credentials za Windows zilizosanidiwa kwenda kwa host inayodhibitiwa na mshambulizi.
* **CVE-2024-12511 – SMB/FTP pass-back**: tatizo lilelile kupitia maeneo ya *scan-to-folder*, na kuvuja NetNTLMv2 au credentials za FTP za maandishi wazi.<sup>[[2]](#references)</sup>

Listener rahisi kama:

```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```

au seva hasidi ya SMB (`impacket-smbserver`) inatosha kuvuna credentials.  

### Canon imageRUNNER / imageCLASS – Ushauri wa 20 Mei 2025

Canon ilithibitisha udhaifu wa **SMTP/LDAP pass-back** katika mistari mingi ya bidhaa za Laser na MFP. Mshambulizi mwenye ufikiaji wa admin anaweza kurekebisha usanidi wa seva na kupata credentials zilizohifadhiwa za LDAP **au** SMTP (mashirika mengi hutumia akaunti yenye mamlaka makubwa ili kuwezesha uchanganuzi kwenda kwenye barua pepe).<sup>[[3]](#references)</sup>

Mwongozo wa mtengenezaji unapendekeza wazi:

1. Kusasisha firmware yenye viraka punde inapopatikana.
2. Kutumia manenosiri thabiti na ya kipekee ya admin.
3. Kuepuka kutumia akaunti za AD zenye mamlaka makubwa kuunganisha printa.

---

### Vifaa vya Brother na matoleo ya OEM – ufikiaji wa admin unaotokana na namba ya serial, unaofichua credentials za huduma

Ufichuzi ulioratibiwa wa mwaka 2025 ulionyesha mnyororo wenye manufaa hasa kwenye vifaa vya Brother vilivyoathiriwa; sehemu za seti ya udhaifu pia huathiri modeli za OEM, kwa hivyo hakiki modeli husika dhidi ya ushauri wa mtengenezaji wake. Mshambulizi asiyehitaji uthibitishaji anaweza kupata namba ya serial ya kifaa kupitia HTTP/HTTPS/IPP kwenye firmware iliyo hatarini, huku namba za serial zikipatikana pia kupitia itifaki za usimamizi kama SNMP au PJL. Ikiwa nenosiri la kiwandani halijawahi kubadilishwa, namba ya serial huamua nenosiri la msimamizi. Baada ya kujithibitisha, dosari tofauti ya pass-back CVE-2024-51984 hufichua manenosiri ya huduma za nje zilizosanidiwa, kama LDAP au FTP, katika maandishi wazi; hivyo ufikiaji wa usimamizi wa printa hugeuka kuwa credentials za mtandao zinazoweza kutumika tena. Firmware hurekebisha ufichuaji wa nenosiri la huduma, lakini vifaa vilivyotengenezwa awali bado vinahitaji msimamizi kubadilisha nenosiri la awali la msimamizi linalotokana na namba ya serial.<sup>[[6]](#references)</sup>

Metasploit ya sasa inajumuisha module ya auxiliary inayotambua namba ya serial kupitia HTTP, SNMP, au PJL, hutengeneza nenosiri la awali linalowezekana, na kwa hiari hulihakiki dhidi ya dashibodi ya wavuti. `DiscoverSerialVia=AUTO` hujaribu njia za utambuzi zinazotumika; toa `TargetSerial` badala yake ikiwa orodha ya vifaa tayari ina namba ya serial.<sup>[[7]](#references)</sup>

```text
msfconsole -q
use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978
set RHOSTS <printer-ip>
set DiscoverSerialVia AUTO
run
```

Tumia matokeo haya kuthibitisha tu vifaa vilivyoidhinishwa. Ikiwa nenosiri litafanya kazi hutegemea modeli halisi na, muhimu zaidi, ikiwa nenosiri la msimamizi lililotolewa na kiwanda tayari limebadilishwa.<sup>[[6]](#references)[[7]](#references)</sup>

---

## Zana za Uhesabuji / Udukuzi wa Kiotomatiki

| Zana | Kusudi | Mfano |
|------|---------|---------|
| **PRET** (Printer Exploitation Toolkit) | Matumizi mabaya ya PostScript/PJL/PCL, ufikiaji wa mfumo wa faili, ukaguzi wa vitambulisho chaguomsingi, *ugunduzi wa SNMP* | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | Kukusanya usanidi (ikiwemo vitabu vya anwani na vitambulisho vya LDAP) kupitia HTTP/HTTPS | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | Kuendesha huduma ghushi za uthibitishaji na kunasa/kupeleka tena NetNTLM kutoka kwa miito ya SMB | `sudo responder -I eth0 -v` |
| **Metasploit Brother auxiliary** | Kugundua nambari ya ufuatiliaji, kupata nenosiri la msimamizi la kiwandani linalowezekana na kuthibitisha ufikiaji wa dashibodi ya wavuti | `use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978` |

---

## Kuimarisha Usalama na Ugunduzi

1. **Sakinisha viraka / sasisha firmware** ya MFP mara moja (angalia matangazo ya PSIRT ya mtengenezaji).
2. **Badilisha nenosiri la msimamizi lililotolewa na kiwanda** – firmware pekee haiondoi nenosiri la awali linalotokana na nambari ya ufuatiliaji kwenye vifaa vya Brother/OEM vilivyoathiriwa na vilivyotengenezwa hapo awali.<sup>[[6]](#references)</sup>
3. **Akaunti za huduma zenye ruhusa za chini kabisa** – usiwahi kutumia Domain Admin kwa LDAP/SMB/SMTP; punguza ruhusa ziwe *za kusoma pekee* katika mawanda ya OU.
4. **Zuia ufikiaji wa usimamizi** – weka violesura vya wavuti/IPP/SNMP vya printa kwenye VLAN ya usimamizi au nyuma ya ACL/VPN.
5. **Dhibiti miunganisho ya printa kwenda nje** – ruhusu kila kifaa kuwasiliana tu na DC/LDAP, barua pepe, DNS/NTP, uchapishaji na maeneo ya faili za uchanganuzi yanayotarajiwa. Pass-back huhitaji muunganisho wa kurudi kwenye endpoint iliyochaguliwa na mshambuliaji.
6. **Zima itifaki zisizotumika** – FTP, Telnet, raw-9100, na cipher za zamani za SSL.
7. **Washa kumbukumbu za ukaguzi** – baadhi ya vifaa vinaweza kutuma makosa ya LDAP/SMTP kwa syslog; linganisha miunganisho isiyotarajiwa.
8. **Fuatilia maeneo ya uthibitishaji** – toa tahadhari printa inapoanzisha LDAP, SMB, SMTP au FTP kwenda kwa seva ambayo haipo kwenye orodha iliyoruhusiwa, hasa mara tu baada ya kuingia kwa usimamizi au mabadiliko ya usanidi.
9. **Tumia SNMPv3 au zima SNMP** – jumuiya ya `public` mara nyingi huvuja taarifa za kifaa na nambari ya ufuatiliaji.

---



---

## References

- [1] [Ni printa tu… Nini kibaya zaidi kinachoweza kutokea?](https://grimhacker.com/2018/03/09/just-a-printer/)
- [2] [Printa ya Kazi Nyingi ya Xerox Versalink C7025: Udhaifu wa Shambulio la Pass-Back (Umerekebishwa)](https://www.rapid7.com/blog/post/2025/02/14/xerox-versalink-c7025-multifunction-printer-pass-back-attack-vulnerabilities-fixed/)
- [3] [CP2025-004 Kupunguza/Kurekebisha Udhaifu kwa Printa za Uzalishaji, Printa za Kazi Nyingi za Ofisini/Ofisi Ndogo na Printa za Laser](https://psirt.canon/advisory-information/cp2025-004/)
- [4] [Kupata Vitambulisho vya Domain kupitia Printa kwa Netcat](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [5] [Kutumia Printa za Kazi Nyingi Wakati wa Zoezi la Jaribio la Kupenya](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [6] [Vifaa Vingi vya Brother: Udhaifu Mbalimbali (UMEREKEBISHWA)](https://www.rapid7.com/blog/post/multiple-brother-devices-multiple-vulnerabilities-fixed/)
- [7] [Metasploit: Moduli ya Brother ya kukwepa uthibitishaji wa msimamizi chaguomsingi](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978.rb)
{{#include ../../banners/hacktricks-training.md}}
