# Contournements de la protection Admin via UIAccess

{{#include ../../banners/hacktricks-training.md}}

## Aperçu
- Windows AppInfo expose `RAiLaunchAdminProcess` pour lancer des processus UIAccess (destinés à l'accessibilité). UIAccess contourne la plupart des filtrages de messages User Interface Privilege Isolation (UIPI) afin que les logiciels d'accessibilité puissent piloter des interfaces à IL supérieur.
- L'activation directe de UIAccess nécessite `NtSetInformationToken(TokenUIAccess)` avec **SeTcbPrivilege**, donc les appelants à faibles privilèges s'appuient sur le service. Le service effectue trois vérifications sur le binaire cible avant d'activer UIAccess :
- Le manifeste embarqué contient `uiAccess="true"`.
- Signé par n'importe quel certificat approuvé par le magasin racine Local Machine (sans exigence EKU ni exigence Microsoft).
- Situé dans un chemin accessible uniquement aux administrateurs sur le disque système (par ex., `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`, en excluant certains sous‑chemins inscriptibles).
- `RAiLaunchAdminProcess` n'affiche aucune invite de consentement pour les lancements UIAccess (sinon les outils d'accessibilité ne pourraient pas piloter l'invite).

## Token shaping and integrity levels
- Si les vérifications réussissent, AppInfo **copie le token de l'appelant**, active UIAccess et augmente le niveau d'intégrité (IL) :
- Utilisateur admin limité (membre d'Administrators mais exécuté en filtré) ➜ **High IL**.
- Utilisateur non‑admin ➜ le IL augmente de **+16 niveaux** jusqu'au plafond **High** (le IL System n'est jamais attribué).
- Si le token appelant possède déjà UIAccess, le IL reste inchangé.
- Astuce de « ratchet » : un processus UIAccess peut désactiver UIAccess sur lui‑même, relancer via `RAiLaunchAdminProcess`, et obtenir un autre incrément de +16 IL. Medium➜High nécessite 255 relances (bruyant, mais fonctionne).

## Pourquoi UIAccess permet un contournement de la protection Admin
- UIAccess permet à un processus à IL inférieur d'envoyer des messages de fenêtres à des fenêtres à IL supérieur (contournant les filtres UIPI). À **IL égal**, les primitives UI classiques comme `SetWindowsHookEx` **permettent l'injection de code/le chargement de DLL** dans tout processus possédant une fenêtre (y compris les **message-only windows** utilisées par COM).
- Admin Protection lance le processus UIAccess sous l'**identité de l'utilisateur limité** mais à **High IL**, de manière silencieuse. Une fois que du code arbitraire s'exécute dans ce processus UIAccess à High IL, l'attaquant peut s'injecter dans d'autres processus à High IL sur le bureau (même appartenant à d'autres utilisateurs), rompant la séparation prévue.

## Faiblesses de la validation des répertoires sécurisés (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo résout le chemin fourni via `GetFinalPathNameByHandle` puis applique des **vérifications d'autorisation/refus par chaîne** contre des racines/exclusions codées en dur. Plusieurs classes de contournement découlent de cette validation simpliste :
- **Directory named streams**: les répertoires exclus inscriptibles (par ex., `C:\Windows\tracing`) peuvent être contournés avec un named stream sur le répertoire lui‑même, p.ex. `C:\Windows\tracing:file.exe`. Les vérifications de chaîne voient `C:\Windows\` et manquent le sous‑chemin exclu.
- **Writable file/directory inside an allowed root**: `CreateProcessAsUser` n'exige **pas une extension `.exe`**. Écraser n'importe quel fichier inscriptible sous une racine autorisée avec un payload exécutable fonctionne, ou copier un EXE signé avec `uiAccess="true"` dans n'importe quel sous‑répertoire inscriptible (par ex., restes de mises à jour comme `Tasks_Migrated` quand présents) le laisse passer la vérification de chemin sécurisé.
- **MSIX into `C:\Program Files\WindowsApps` (fixed)**: les non‑admin pouvaient installer des packages MSIX signés qui atterrissaient dans `WindowsApps`, qui n'était pas exclu. Emballer un binaire UIAccess dans le MSIX puis le lancer via `RAiLaunchAdminProcess` aboutissait à un processus UIAccess à **High IL sans invite**. Microsoft a corrigé en excluant ce chemin ; la capability MSIX restreinte `uiAccess` exige déjà une installation admin.

## Workflow d'attaque (High IL sans invite)
1. Obtenir/construire un **binaire UIAccess signé** (manifeste `uiAccess="true"`).
2. Le placer là où la liste d'autorisation d'AppInfo l'accepte (ou abuser d'un cas limite de validation de chemin/artefact inscriptible comme ci‑dessus).
3. Appeler `RAiLaunchAdminProcess` pour le lancer **silencieusement** avec UIAccess + IL élevé.
4. Depuis ce point d'appui à High IL, cibler un autre processus à High IL sur le bureau en utilisant des **window hooks/DLL injection** ou d'autres primitives au même IL pour compromettre complètement le contexte admin.

## Énumération des chemins écrivables candidats
Exécutez l'outil PowerShell pour découvrir les objets écrivables/sur‑écrivables à l'intérieur des racines nominalement sécurisées du point de vue d'un token choisi :
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- Exécuter en tant qu'Administrateur pour une visibilité accrue ; définir `-ProcessId` sur un processus à faibles privilèges pour refléter l'accès de ce token.
- Filtrer manuellement pour exclure les sous-répertoires connus non autorisés avant d'utiliser les candidats avec `RAiLaunchAdminProcess`.

## Références
- [Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)

{{#include ../../banners/hacktricks-training.md}}
