# Contournements de la protection administrateur via UIAccess

{{#include ../../banners/hacktricks-training.md}}

## Présentation
- Windows AppInfo expose `RAiLaunchAdminProcess` pour lancer des processus UIAccess (prévu pour l’accessibilité). UIAccess contourne la plupart du filtrage des messages de User Interface Privilege Isolation (UIPI), afin que les logiciels d’accessibilité puissent piloter des interfaces graphiques avec un IL supérieur.
- L’activation directe de UIAccess nécessite `NtSetInformationToken(TokenUIAccess)` avec **SeTcbPrivilege** ; les appelants faiblement privilégiés s’appuient donc sur le service. Le service effectue trois vérifications sur le binaire cible avant d’activer UIAccess :
- Le manifeste intégré contient `uiAccess="true"`.
- Le binaire est signé par un certificat approuvé par le magasin de certificats racine de la machine locale (aucune exigence d’EKU ou de Microsoft).
- Le binaire se trouve dans un chemin réservé aux administrateurs sur le lecteur système (par exemple `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`), à l’exclusion de certains sous-chemins accessibles en écriture.
- `RAiLaunchAdminProcess` n’affiche aucune invite de consentement pour les lancements UIAccess (sinon les outils d’accessibilité ne pourraient pas piloter l’invite).<sup>[[1]](#references)</sup>

## Façonnage des tokens et niveaux d’intégrité
- Si les vérifications réussissent, AppInfo **copie le token de l’appelant**, active UIAccess et augmente le niveau d’intégrité (IL) :
- Utilisateur administrateur limité (l’utilisateur appartient au groupe Administrators mais s’exécute avec un filtrage) ➜ **IL élevé**.
- Utilisateur non administrateur ➜ IL augmenté de **+16 niveaux** jusqu’à un plafond **High** (le System IL n’est jamais attribué).
- Si le token de l’appelant possède déjà UIAccess, l’IL reste inchangé.
- Astuce du « ratchet » : un processus UIAccess peut désactiver UIAccess sur lui-même, se relancer via `RAiLaunchAdminProcess` et obtenir une nouvelle augmentation de +16 niveaux d’IL. Le passage de Medium➜High nécessite 255 relances (bruyant, mais fonctionnel).<sup>[[1]](#references)</sup>

## Pourquoi UIAccess permet de contourner la protection administrateur
- UIAccess permet à un processus avec un IL inférieur d’envoyer des messages de fenêtre à des fenêtres avec un IL supérieur (en contournant les filtres UIPI). Avec un **IL égal**, les primitives UI classiques comme `SetWindowsHookEx` **autorisent effectivement l’injection de code/le chargement de DLL** dans tout processus qui possède une fenêtre (y compris les fenêtres « message-only » utilisées par COM).
- Admin Protection lance le processus UIAccess avec l’identité de l’utilisateur limité, mais avec un **IL élevé**, silencieusement. Dès qu’un code arbitraire s’exécute dans ce processus UIAccess avec un IL élevé, l’attaquant peut injecter du code dans d’autres processus avec un IL élevé sur le bureau (même s’ils appartiennent à d’autres utilisateurs), ce qui compromet la séparation prévue.<sup>[[1]](#references)</sup>

## Primitive de handle de processus à partir d’un HWND (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- Depuis Windows 10 1803, l’API a été déplacée dans Win32k (`NtUserGetWindowProcessHandle`) et peut ouvrir un handle de processus à l’aide d’un `DesiredAccess` fourni par l’appelant. Le chemin kernel utilise `ObOpenObjectByPointer(..., KernelMode, ...)`, ce qui contourne les contrôles d’accès user-mode normaux.<sup>[[2]](#references)</sup>
- Préconditions observées en pratique : la fenêtre cible doit se trouver sur le même bureau et les vérifications UIPI doivent réussir. Historiquement, un appelant disposant de UIAccess pouvait contourner l’échec UIPI et obtenir malgré tout un handle kernel-mode (corrigé par CVE-2023-41772).
- Impact : un handle de fenêtre devient une **capacité** permettant d’obtenir un handle de processus puissant (notamment `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`) que l’appelant ne pourrait normalement pas ouvrir. Cela permet un accès inter-sandbox et peut briser les limites Protected Process / PPL si la cible expose une fenêtre quelconque (y compris des fenêtres « message-only »).
- Flux d’abus pratique : énumérer ou localiser les HWND (par exemple avec `EnumWindows`/`FindWindowEx`), résoudre le PID propriétaire (`GetWindowThreadProcessId`), appeler `GetProcessHandleFromHwnd`, puis utiliser le handle retourné pour lire/écrire la mémoire ou employer des primitives de détournement de code.
- Comportement après correction : UIAccess n’accorde plus d’ouvertures kernel-mode en cas d’échec UIPI et les droits d’accès autorisés sont limités à l’ensemble de hooks historique ; Windows 11 24H2 ajoute des vérifications de protection des processus et des chemins plus sûrs contrôlés par des feature flags. La désactivation globale d’UIPI (`EnforceUIPI=0`) affaiblit ces protections.<sup>[[2]](#references)</sup>

## Faiblesses de validation des répertoires sécurisés (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo résout le chemin fourni via `GetFinalPathNameByHandle`, puis applique des **vérifications de chaînes** par rapport à des racines/exclusions codées en dur. Plusieurs classes de bypass découlent de cette validation simpliste :
- **Flux nommés de répertoires** : les répertoires accessibles en écriture exclus (par exemple `C:\Windows\tracing`) peuvent être contournés avec un flux nommé sur le répertoire lui-même, par exemple `C:\Windows\tracing:file.exe`. Les vérifications de chaînes voient `C:\Windows\` et ne détectent pas le sous-chemin exclu.
- **Fichier/répertoire accessible en écriture à l’intérieur d’une racine autorisée** : `CreateProcessAsUser` **n’exige pas d’extension `.exe`**. Écraser un fichier accessible en écriture sous une racine autorisée avec une payload exécutable fonctionne ; de même, copier un EXE signé avec `uiAccess="true"` dans n’importe quel sous-répertoire accessible en écriture (par exemple des résidus de mise à jour tels que `Tasks_Migrated` lorsqu’ils sont présents) lui permet de passer la vérification du chemin sécurisé.
- **MSIX dans `C:\Program Files\WindowsApps` (corrigé)** : les utilisateurs non administrateurs pouvaient installer des packages MSIX signés qui se retrouvaient dans `WindowsApps`, lequel n’était pas exclu. Placer un binaire UIAccess dans le MSIX, puis le lancer via `RAiLaunchAdminProcess`, permettait d’obtenir un **processus UIAccess avec un IL élevé, sans invite**. Microsoft a réduit ce risque en excluant ce chemin ; la capacité MSIX restreinte `uiAccess` elle-même nécessite déjà une installation par un administrateur.<sup>[[1]](#references)</sup>

## Workflow d’attaque (IL élevé sans invite)
1. Obtenir/construire un **binaire UIAccess signé** (manifeste `uiAccess="true"`).
2. Le placer à un emplacement accepté par l’allowlist d’AppInfo (ou exploiter un cas limite de validation du chemin/un artefact accessible en écriture comme indiqué ci-dessus).
3. Appeler `RAiLaunchAdminProcess` pour le lancer **silencieusement** avec UIAccess et un IL élevé.
4. Depuis ce foothold avec un IL élevé, cibler un autre processus avec un IL élevé sur le bureau à l’aide de **window hooks/l’injection de DLL** ou d’autres primitives avec un IL égal afin de compromettre entièrement le contexte administrateur.<sup>[[1]](#references)</sup>

## Énumération des chemins candidats accessibles en écriture
Exécutez l’helper PowerShell afin de découvrir les objets accessibles en écriture/écrasables à l’intérieur de racines nominalement sécurisées du point de vue d’un token choisi :<sup>[[1]](#references)</sup>
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- Exécutez en tant qu’Administrateur pour obtenir une visibilité plus large ; définissez `-ProcessId` sur un processus avec peu de privilèges afin de reproduire l’accès de son token.
- Filtrez manuellement pour exclure les sous-répertoires connus comme interdits avant d’utiliser les candidats avec `RAiLaunchAdminProcess`.

## Liens associés

Secure Desktop accessibility registry propagation LPE (RegPwn) :

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## Références

- [1] [Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [GetProcessHandleFromHwnd (GPHFH) Deep Dive](https://projectzero.google/2026/02/gphfh-deep-dive.html)

{{#include ../../banners/hacktricks-training.md}}
