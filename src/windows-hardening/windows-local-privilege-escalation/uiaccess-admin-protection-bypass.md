# Contournements d'Admin Protection via UIAccess

{{#include ../../banners/hacktricks-training.md}}

## Aperçu
- Windows AppInfo expose `RAiLaunchAdminProcess` pour lancer des processus UIAccess (destinés à l'accessibilité). UIAccess contourne la plupart des filtrages de messages User Interface Privilege Isolation (UIPI) afin que les logiciels d'accessibilité puissent contrôler des UI à IL supérieur.
- Activer UIAccess directement requiert `NtSetInformationToken(TokenUIAccess)` avec **SeTcbPrivilege**, donc les appelants à faible privilège s'appuient sur le service. Le service effectue trois vérifications sur le binaire ciblé avant d'activer UIAccess :
- Le manifeste embarqué contient `uiAccess="true"`.
- Signé par n'importe quel certificat de confiance dans le magasin racine Local Machine (aucune exigence EKU/Microsoft).
- Situé dans un chemin réservé aux administrateurs sur le lecteur système (par ex., `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`, en excluant certains sous-chemins inscriptibles).
- `RAiLaunchAdminProcess` n'affiche aucune invite de consentement pour les lancements UIAccess (sinon les outils d'accessibilité ne pourraient pas contrôler l'invite).

## Token shaping and integrity levels
- Si les vérifications réussissent, AppInfo **copie le token de l'appelant**, active UIAccess et augmente le Integrity Level (IL) :
- Administrateur limité (dans Administrators mais en mode filtré) ➜ **High IL**.
- Utilisateur non-admin ➜ IL augmenté de **+16 niveaux** jusqu'à un plafond **High** (System IL n'est jamais attribué).
- Si le token de l'appelant possède déjà UIAccess, l'IL reste inchangé.
- Astuce « ratchet » : un processus UIAccess peut désactiver UIAccess sur lui-même, relancer via `RAiLaunchAdminProcess`, et gagner un autre incrément de +16 IL. Medium➜High nécessite 255 relances (bruyant, mais fonctionne).

## Pourquoi UIAccess permet d'échapper à Admin Protection
- UIAccess permet à un processus à IL inférieur d'envoyer des messages de fenêtre vers des fenêtres à IL supérieur (contournant les filtres UIPI). À **IL égal**, des primitives UI classiques comme `SetWindowsHookEx` **permettent l'injection de code/le chargement d'une DLL** dans n'importe quel processus possédant une fenêtre (y compris les **message-only windows** utilisées par COM).
- Admin Protection lance le processus UIAccess sous l'**identité de l'utilisateur limité** mais à **High IL**, silencieusement. Une fois du code arbitraire exécuté dans ce processus UIAccess à High IL, l'attaquant peut s'injecter dans d'autres processus High IL sur le bureau (même appartenant à d'autres utilisateurs), rompant la séparation prévue.

## HWND-to-process handle primitive (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- Sur Windows 10 1803+ l'API a été déplacée dans Win32k (`NtUserGetWindowProcessHandle`) et peut ouvrir un handle de processus en utilisant un `DesiredAccess` fourni par l'appelant. Le chemin noyau utilise `ObOpenObjectByPointer(..., KernelMode, ...)`, ce qui contournes les vérifications d'accès usuelles en mode utilisateur.
- Conditions préalables en pratique : la fenêtre cible doit être sur le même bureau, et les vérifications UIPI doivent réussir. Historiquement, un appelant avec UIAccess pouvait contourner un échec UIPI et obtenir quand même un handle noyau (corrigé par CVE-2023-41772).
- Impact : un handle de fenêtre devient une **capability** pour obtenir un handle de processus puissant (typiquement `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`) que l'appelant ne pourrait pas normalement ouvrir. Cela permet un accès cross-sandbox et peut rompre les frontières Protected Process / PPL si la cible expose une fenêtre (y compris message-only windows).
- Flux d'abus pratique : énumérer ou localiser des HWNDs (p.ex. `EnumWindows`/`FindWindowEx`), résoudre le PID propriétaire (`GetWindowThreadProcessId`), appeler `GetProcessHandleFromHwnd`, puis utiliser le handle retourné pour lecture/écriture mémoire ou primitives de détournement de code.
- Comportement après correctif : UIAccess n'accorde plus d'ouvertures en mode noyau en cas d'échec UIPI et les droits d'accès autorisés sont restreints à l'ensemble legacy des hooks ; Windows 11 24H2 ajoute des vérifications de protection de processus et des chemins plus sûrs activés par feature-flag. Désactiver UIPI au niveau système (`EnforceUIPI=0`) affaiblit ces protections.

## Faiblesses de validation des répertoires sécurisés (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo résout le chemin fourni via `GetFinalPathNameByHandle` puis applique des **vérifications allow/deny de chaînes** contre des racines/exclusions codées en dur. Plusieurs classes de contournement découlent de cette validation simpliste :
- **Directory named streams** : les répertoires inscriptibles exclus (p.ex. `C:\Windows\tracing`) peuvent être contournés avec un stream nommé sur le répertoire lui-même, p.ex. `C:\Windows\tracing:file.exe`. Les vérifications de chaîne voient `C:\Windows\` et ratent le sous-chemin exclu.
- **Writable file/directory inside an allowed root** : `CreateProcessAsUser` **n'exige pas une extension `.exe`**. Écraser n'importe quel fichier inscriptible sous une racine autorisée avec un payload exécutable fonctionne, ou copier un EXE signé `uiAccess="true"` dans n'importe quel sous-répertoire inscriptible (p.ex. des restes de mise à jour comme `Tasks_Migrated`) lui permet de passer la vérification de chemin sécurisé.
- **MSIX into `C:\Program Files\WindowsApps` (fixed)** : des non-admins pouvaient installer des packages MSIX signés placés dans `WindowsApps`, qui n'était pas exclu. Emballer un binaire UIAccess dans le MSIX puis le lancer via `RAiLaunchAdminProcess` produisait un processus UIAccess à **High IL sans invite**. Microsoft a atténué le problème en excluant ce chemin ; la capability MSIX restreinte `uiAccess` requiert déjà une installation admin.

## Attack workflow (High IL without a prompt)
1. Obtain/build a **signed UIAccess binary** (manifest `uiAccess="true"`).
2. Place it where AppInfo’s allowlist accepts it (or abuse a path-validation edge case/writable artifact as above).
3. Call `RAiLaunchAdminProcess` to spawn it **silently** with UIAccess + elevated IL.
4. From that High-IL foothold, target another High-IL process on the desktop using **window hooks/DLL injection** or other same-IL primitives to fully compromise the admin context.

## Énumérer les chemins inscriptibles candidats
Exécutez l'helper PowerShell pour découvrir les objets inscriptibles/écrasables à l'intérieur de racines nominalement sécurisées du point de vue d'un token choisi :
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- Exécuter en tant qu'administrateur pour une visibilité plus large ; définir `-ProcessId` sur un low-priv process afin de refléter l'accès de ce token.
- Filtrer manuellement pour exclure les sous-répertoires connus et interdits avant d'utiliser les candidats avec `RAiLaunchAdminProcess`.

## Articles connexes

Secure Desktop accessibility registry propagation LPE (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## Références
- [Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [GetProcessHandleFromHwnd (GPHFH) Deep Dive](https://projectzero.google/2026/02/gphfh-deep-dive.html)

{{#include ../../banners/hacktricks-training.md}}
