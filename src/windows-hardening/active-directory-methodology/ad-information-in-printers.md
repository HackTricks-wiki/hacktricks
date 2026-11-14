# Taarifa katika Printers

{{#include ../../banners/hacktricks-training.md}}

Printer yenye credentials za LDAP zilizohifadhiwa inaweza kuzifichua iwapo setting ya server yake itabadilishwa, kisha ika-authenticate kwenye endpoint hasidi.<sup>[[2]](#references)</sup> Matokeo hutegemea bind method: simple bind isiyolindwa hufichua password, ilhali SASL challenge-response bind haifichui password kama plaintext.<sup>[[8]](#references)</sup> Tazama [LDAP authentication and transport security](../../network-services-pentesting/pentesting-ldap.md#cleartext-credentials-and-tls-downgrade-risks).

Pia, printers kadhaa zitakuwa na **logs zenye usernames** au huenda hata zikaweza **kupakua usernames zote** kutoka kwa Domain Controller.

Taarifa hizi zote **nyeti** na **ukosefu wa usalama** ulio wa kawaida huzifanya printers zivutie sana kwa attackers.

Baadhi ya blogu za utangulizi kuhusu mada hii:

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)<sup>[[4]](#references)</sup>
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)<sup>[[5]](#references)</sup>

---

## Mipangilio ya Printer

- **Mahali**: Orodha ya LDAP server kwa kawaida hupatikana kwenye web interface (k.m. *Network ➜ LDAP Setting ➜ Setting Up LDAP*).
- **Tabia**: Web servers nyingi zilizopachikwa huruhusu mabadiliko ya LDAP server **bila kuingiza credentials tena** (kipengele cha urahisi → hatari ya usalama).
- **Exploit**: Elekeza upya anwani ya LDAP server kwenye host inayodhibitiwa na attacker na utumie kitufe cha *Test Connection* / *Address Book Sync* kulazimisha printer i-bind kwako.

---

## Kunasa Credentials

### Method 1 – Netcat Listener

```bash
sudo nc -k -v -l -p 389     # Plain LDAP only
```

BindRequest rahisi inaweza kufichua bind DN na nenosiri kwenye mtiririko wa BER, hata kama seva itakataa kuingia baadaye. Utafutaji usiojulikana au mazungumzo ya SASL pekee hayafichui nenosiri hilo lililohifadhiwa.<sup>[[8]](#references)</sup>

Kisikilizi cha kawaida cha `nc` kwenye 636/3269 huona TLS handshake, si LDAP bind. LDAPS huhitaji endpoint inayoweza kutumia TLS. Uthibitishaji wa cheti pekee hauzuii pass-back ikiwa printa inakubali jina la hostname lililobadilishwa na endpoint mpya ina cheti halali cha hostname hiyo; mteja lazima pia adhibiti ni seva ipi iliyoidhinishwa kupokea kitambulisho kilichohifadhiwa.<sup>[[8]](#references)</sup>

### Mbinu ya 2 – Full Rogue LDAP server (inayopendekezwa)

Printa inaweza kuhitaji jibu halali la LDAP kabla ya kujaribu bind.<sup>[[10]](#references)</sup> Seva kamili ya LDAP inaweza kushughulikia ubadilishanaji huo wa awali, lakini haiwezi kumfanya mteja aliyefungamanishwa na utaratibu imara wa SASL au seva ya TLS iliyokusudiwa kufichua nenosiri lake.<sup>[[8]](#references)[[10]](#references)</sup>

```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # use a base DN compatible with the printer lookup

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```

Chukulia lookup kama ushahidi wa muunganisho, si uthibitisho wa kufichuliwa kwa nenosiri. Nenosiri hufichuliwa tu ikiwa client itatuma bind yenye nenosiri la maandishi wazi; kagua utaratibu halisi wa bind na hali ya TLS.<sup>[[8]](#references)</sup>

> 💡 Responder inajumuisha huduma ghushi za uthibitishaji za LDAP na SMB. Bind rahisi ya LDAP inaweza kufichua nenosiri lililosanidiwa, ilhali uthibitishaji wa NTLM hutoa data ya challenge-response; usieleze matokeo yote mawili kama nenosiri la maandishi wazi.

### Uteuzi wa utaratibu wa SASL

Baadhi ya clients za LDAP za printer huchagua kutoka kwenye taratibu zinazotangazwa na server ya LDAP.<sup>[[8]](#references)[[10]](#references)</sup> Utafiti ulionyesha kuwa client iliyo tayari kukubali utaratibu wa SASL wa maandishi wazi uliotangazwa inaweza kutuma nenosiri, ilhali mazungumzo yake ya kawaida ya NTLM yangetoa tu data ya challenge-response.<sup>[[9]](#references)[[10]](#references)</sup> Huu ni **ukosefu wa usalama katika sera ya client**, si sifa ya bind zote za SASL: client inayohitaji utaratibu imara zaidi au kuthibitisha TLS server iliyokusudiwa inapaswa kukataa muunganisho badala yake.<sup>[[8]](#references)</sup> OpenLDAP huzima kwa chaguomsingi taratibu za SASL zinazoweza kutumia maandishi wazi, kwa hivyo daemon ya kawaida haithibitishi kuwa tabia hii ipo kwenye printer.<sup>[[11]](#references)</sup>

---

## Athari za Hivi Karibuni za Pass-Back (2024-2025)

Pass-back *si suala la kinadharia* – wachuuzi wanaendelea kuchapisha taarifa za usalama mwaka 2024/2025 zinazoeleza aina hii ya shambulio moja kwa moja.

### Xerox VersaLink – CVE-2024-12510 & CVE-2024-12511

Firmware ≤ 57.69.91 ya Xerox VersaLink C70xx MFPs iliruhusu admin aliyeidhinishwa (au mtu yeyote ikiwa nywila za chaguomsingi hazijabadilishwa) kufanya yafuatayo:

* **CVE-2024-12510 – LDAP pass-back**: kubadilisha anwani ya LDAP server na kuanzisha lookup, na kusababisha kifaa kuvuja credentials za Windows zilizosanidiwa kwa host inayodhibitiwa na mshambuliaji.
* **CVE-2024-12511 – SMB/FTP pass-back**: tatizo lilelile kupitia maeneo ya *scan-to-folder*, na kuvuja NetNTLMv2 au credentials za FTP za maandishi wazi.<sup>[[2]](#references)</sup>

Listener rahisi kama vile:

```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```

au seva mbovu ya SMB (`impacket-smbserver`) inatosha kuvuna credentials.  

### Canon imageRUNNER / imageCLASS – Ushauri wa 20 Mei 2025

Canon ilithibitisha udhaifu wa **SMTP/LDAP pass-back** katika safu nyingi za bidhaa za Laser na MFP. Mshambulizi mwenye ufikiaji wa admin anaweza kubadilisha usanidi wa seva na kupata credentials zilizohifadhiwa za LDAP **au** SMTP (mashirika mengi hutumia akaunti yenye haki za juu kuwezesha scan-to-mail).<sup>[[3]](#references)</sup>

Mwongozo wa mtengenezaji unapendekeza wazi:

1. Kusasisha firmware yenye kiraka mara tu inapopatikana.
2. Kutumia nywila za admin imara na za kipekee.
3. Kuepuka kutumia akaunti za AD zenye haki za juu kwa muunganisho wa printer.

---

### Vifaa vya Brother na matoleo ya OEM – ufikiaji wa admin unaotokana na serial na credentials za huduma

Ufichuzi ulioratibiwa mwaka 2025 ulionyesha mnyororo wenye manufaa hasa kwenye vifaa vya Brother vilivyoathirika; sehemu za seti ya udhaifu huathiri pia modeli za OEM, kwa hiyo hakiki modeli husika dhidi ya ushauri wa mtengenezaji wake. Mshambuliaji asiyehitaji uthibitishaji anaweza kupata serial ya kifaa kupitia HTTP/HTTPS/IPP kwenye firmware iliyo hatarini, huku serial zikipatikana pia kupitia itifaki za usimamizi kama SNMP au PJL. Ikiwa nywila ya kiwandani haikuwahi kubadilishwa, serial hutumika moja kwa moja kupata nywila ya admin. Baada ya kuthibitishwa, hitilafu tofauti ya pass-back CVE-2024-51984 hufichua kwa maandishi ya kawaida nywila za huduma za nje zilizosanidiwa, kama LDAP au FTP, na hivyo kugeuza ufikiaji wa usimamizi wa printer kuwa credentials za mtandao zinazoweza kutumiwa tena. Firmware hutatua ufichuaji wa nywila za huduma, lakini vifaa vilivyotengenezwa awali bado vinahitaji msimamizi kubadilisha nywila ya awali ya admin inayotokana na serial.<sup>[[6]](#references)</sup>

Metasploit ya sasa ina moduli saidizi inayotambua serial kupitia HTTP, SNMP au PJL, huzalisha nywila ya awali inayowezekana, na kwa hiari huithibitisha dhidi ya dashibodi ya wavuti. `DiscoverSerialVia=AUTO` hujaribu njia zinazotumika za utambuzi; toa `TargetSerial` badala yake ikiwa orodha ya rasilimali tayari ina serial.<sup>[[7]](#references)</sup>

```text
msfconsole -q
use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978
set RHOSTS <printer-ip>
set DiscoverSerialVia AUTO
run
```

Tumia matokeo haya kuthibitisha tu vifaa vilivyoidhinishwa. Ikiwa nenosiri litafanya kazi hutegemea modeli husika na, muhimu zaidi, ikiwa nenosiri la msimamizi lililowekwa kiwandani tayari limebadilishwa.<sup>[[6]](#references)[[7]](#references)</sup>

---

## Zana za Uhesabuji wa Kiotomatiki / Unyonyaji

| Zana | Kusudi | Mfano |
|------|---------|---------|
| **PRET** (Printer Exploitation Toolkit) | Matumizi mabaya ya PostScript/PJL/PCL, ufikiaji wa mfumo wa faili, ukaguzi wa default-creds, *ugunduzi wa SNMP*; tazama [tathmini ya PJL](../../network-services-pentesting/9100-pjl.md) | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | Kukusanya usanidi (ikiwemo vitabu vya anwani na vitambulisho vya LDAP) kupitia HTTP/HTTPS | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | Kuendesha huduma za uthibitishaji ghushi na kunasa/kupeleka NetNTLM kutoka kwa miito ya SMB | `sudo responder -I eth0 -v` |
| **Metasploit Brother auxiliary** | Kugundua nambari ya mfululizo, kubaini nenosiri linalowezekana la msimamizi lililowekwa kiwandani, na kuthibitisha ufikiaji wa kiweko cha wavuti | `use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978` |

---

## Kuimarisha Usalama na Ugunduzi

1. **Sakinisha viraka / sasisha firmware** za MFP mara moja (angalia matangazo ya PSIRT ya mtengenezaji).
2. **Badilisha nywila za msimamizi zilizowekwa kiwandani** – firmware pekee haiondoi nywila za awali zinazotokana na nambari za mfululizo kwenye vifaa vilivyoathiriwa vya Brother/OEM vilivyotengenezwa awali.<sup>[[6]](#references)</sup>
3. **Akaunti za Huduma zenye Haki za Kiwango cha Chini** – usitumie kamwe Domain Admin kwa LDAP/SMB/SMTP; punguza upeo wa OU uwe wa *kusoma pekee*.
4. **Zuia Ufikiaji wa Usimamizi** – weka violesura vya wavuti/IPP/SNMP vya printa kwenye VLAN ya usimamizi au nyuma ya ACL/VPN.
5. **Dhibiti trafiki inayotoka kwenye printa** – ruhusu kila kifaa kuwasiliana tu na DC/LDAP, barua pepe, DNS/NTP, uchapishaji na maeneo lengwa ya faili za uchanganuzi yanayotarajiwa. Pass-back huhitaji muunganisho wa kurudi kwenye endpoint iliyochaguliwa na mshambuliaji.
6. **Zima Itifaki Zisizotumika** – FTP, Telnet, raw-9100, misimbo fiche ya zamani ya SSL.
7. **Washa Uwekaji wa Kumbukumbu za Ukaguzi** – baadhi ya vifaa vinaweza kutuma hitilafu za LDAP/SMTP kwa syslog; linganisha bind zisizotarajiwa.
8. **Fuatilia maeneo lengwa ya uthibitishaji** – toa tahadhari printa inapoanzisha LDAP, SMB, SMTP au FTP kwenda kwa seva pangishi iliyo nje ya allowlist yake, hasa mara tu baada ya kuingia kwenye usimamizi au kubadilisha usanidi.
9. **Tumia SNMPv3 au zima SNMP** – jumuiya ya `public` mara nyingi huvuja taarifa za kifaa na nambari ya mfululizo.

---



---



## References

- [1] [Ni printa tu… Nini kibaya zaidi kinachoweza kutokea?](https://grimhacker.com/2018/03/09/just-a-printer/)
- [2] [Printa ya Kazi Nyingi Xerox Versalink C7025: Udhaifu wa Shambulio la Pass-Back (Umerekebishwa)](https://www.rapid7.com/blog/post/2025/02/14/xerox-versalink-c7025-multifunction-printer-pass-back-attack-vulnerabilities-fixed/)
- [3] [CP2025-004 Kupunguza/Kurekebisha Athari kwa Printa za Uzalishaji, Printa za Kazi Nyingi za Ofisi/Ofisi Ndogo na Printa za Laser](https://psirt.canon/advisory-information/cp2025-004/)
- [4] [Kupata Vitambulisho vya Domain kupitia Printa kwa Netcat](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [5] [Kunyonyaji Printa za Kazi Nyingi Wakati wa Ushirikiano wa Jaribio la Kupenya](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [6] [Vifaa Nyingi vya Brother: Athari Nyingi (ZIMEREKEBISHWA)](https://www.rapid7.com/blog/post/multiple-brother-devices-multiple-vulnerabilities-fixed/)
- [7] [Metasploit: Moduli ya kukwepa uthibitishaji wa msimamizi chaguomsingi wa Brother](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978.rb)
- [8] [RFC 4513 – Mbinu za uthibitishaji na mifumo ya usalama ya LDAP](https://datatracker.ietf.org/doc/html/rfc4513)
- [9] [Seva ya Docker ya LDAP passback](https://github.com/cybertrinchera/ldap-passback-docker)
- [10] [Shambulio la LDAP pass back – ACCEIS](https://www.acceis.fr/ldap-pass-back-attack/)
- [11] [slapd-config(5) – Sifa za usalama za SASL](https://man7.org/linux/man-pages/man5/slapd-config.5.html)
{{#include ../../banners/hacktricks-training.md}}
