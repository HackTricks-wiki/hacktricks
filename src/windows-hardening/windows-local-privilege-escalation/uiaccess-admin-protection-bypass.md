# Contournements de la protection Admin via UIAccess

{{#include ../../banners/hacktricks-training.md}}

## Vue d’ensemble
- Windows AppInfo expose le chemin interne `RAiLaunchAdminProcess` utilisé pour démarrer les applications UIAccess dédiées à l’accessibilité. UIAccess permet certaines interactions à travers les limites de User Interface Privilege Isolation (UIPI) ; il ne s’agit pas d’un contournement général de toutes les limites de sécurité des processus.<sup>[[1]](#references)[[3]](#references)</sup>
- L’activation directe de UIAccess nécessite `NtSetInformationToken(TokenUIAccess)` avec **SeTcbPrivilege** ; les appelants à faibles privilèges dépendent donc du service. Le service effectue trois vérifications sur le binaire cible avant d’activer UIAccess :
- Le manifeste intégré contient `uiAccess="true"`.
- Le binaire est signé par un certificat approuvé par le magasin racine de la machine locale (aucune exigence d’EKU ou de certificat Microsoft).
- Le binaire se trouve dans un chemin réservé aux administrateurs sur le lecteur système (par exemple `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`), à l’exclusion de certains sous-chemins inscriptibles.
- `RAiLaunchAdminProcess` n’affiche aucune invite de consentement pour les lancements UIAccess (sinon les outils d’accessibilité ne pourraient pas contrôler l’invite).<sup>[[1]](#references)</sup>

## Modelage des tokens et niveaux d’intégrité
- Si les vérifications réussissent, AppInfo **copie le token de l’appelant**, active UIAccess et augmente le niveau d’intégrité (IL) :
- Utilisateur administrateur limité (l’utilisateur appartient au groupe Administrateurs mais s’exécute avec un filtrage) ➜ **IL élevé**.
- Utilisateur non administrateur ➜ IL augmenté de **+16 niveaux**, jusqu’à un plafond **High** (System IL n’est jamais attribué).
- Si le token de l’appelant possède déjà UIAccess, l’IL reste inchangé.
- Astuce du « ratchet » : un processus UIAccess peut désactiver UIAccess sur lui-même, se relancer via `RAiLaunchAdminProcess` et obtenir une nouvelle augmentation de **+16 niveaux**. Le passage de Medium➜High nécessite 255 relances (bruyant, mais fonctionnel).<sup>[[1]](#references)</sup>

## Pourquoi UIAccess permet de sortir de la protection Admin
- UIAccess permet à un processus avec un IL inférieur d’envoyer des messages de fenêtre à des fenêtres avec un IL supérieur (en contournant les filtres UIPI). Avec un **IL égal**, les primitives classiques de l’interface, comme `SetWindowsHookEx`, permettent bien l’injection de code/le chargement de DLL dans tout processus possédant une fenêtre (y compris les **message-only windows** utilisées par COM).
- Admin Protection lance le processus UIAccess avec l’identité de l’utilisateur limité, mais avec un **IL élevé**, sans invite. Dès qu’un code arbitraire s’exécute dans ce processus UIAccess avec un IL élevé, l’attaquant peut injecter du code dans d’autres processus avec un IL élevé sur le bureau (même s’ils appartiennent à d’autres utilisateurs), rompant ainsi la séparation prévue.<sup>[[1]](#references)</sup>

## Primitive de handle de processus depuis un HWND (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- Sur Windows 10 1803+, l’API a été déplacée dans Win32k (`NtUserGetWindowProcessHandle`) et peut ouvrir un handle de processus avec un `DesiredAccess` fourni par l’appelant. Le chemin du noyau utilise `ObOpenObjectByPointer(..., KernelMode, ...)`, ce qui contourne les vérifications d’accès normales en user mode.<sup>[[2]](#references)</sup>
- Conditions préalables en pratique : la fenêtre cible doit se trouver sur le même bureau et les vérifications UIPI doivent réussir. Historiquement, un appelant disposant de UIAccess pouvait contourner l’échec UIPI et obtenir malgré tout un handle en mode noyau (corrigé par CVE-2023-41772).
- Impact historique : un handle de fenêtre devenait une **capacité** permettant d’accéder au processus, notamment avec `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE` ou `PROCESS_VM_OPERATION`, alors que l’appelant n’aurait normalement pas pu les obtenir. Avant les correctifs documentés, cela pouvait traverser les limites des sandbox et des protected processes lorsqu’une cible exposait une fenêtre, notamment une message-only window.<sup>[[2]](#references)</sup>
- Flux d’abus pratique : énumérer ou localiser les HWND (par exemple avec `EnumWindows`/`FindWindowEx`), résoudre le PID propriétaire (`GetWindowThreadProcessId`), appeler `GetProcessHandleFromHwnd`, puis utiliser le handle retourné pour lire/écrire la mémoire ou exécuter des primitives de détournement de code.
- Comportement après correctif : UIAccess n’accorde plus d’ouvertures en mode noyau lorsque la vérification UIPI échoue, et les droits d’accès autorisés sont limités à l’ensemble de hooks historique ; Windows 11 24H2 ajoute des vérifications de protection des processus et des chemins plus sûrs contrôlés par des feature flags. La désactivation globale d’UIPI (`EnforceUIPI=0`) affaiblit ces protections.<sup>[[2]](#references)</sup>

## Faiblesses de validation des répertoires sécurisés (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo résout le chemin fourni via `GetFinalPathNameByHandle`, puis applique des **vérifications textuelles d’autorisation/refus** contre des racines et exclusions codées en dur. Plusieurs classes de contournement découlent de cette validation simpliste :
- **Flux nommés de répertoires** : les répertoires inscriptibles exclus (par exemple `C:\Windows\tracing`) peuvent être contournés avec un flux nommé sur le répertoire lui-même, par exemple `C:\Windows\tracing:file.exe`. Les vérifications textuelles voient `C:\Windows\` et ignorent le sous-chemin exclu.
- **Fichier/répertoire inscriptible à l’intérieur d’une racine autorisée** : `CreateProcessAsUser` **n’exige pas d’extension `.exe`**. Écraser un fichier inscriptible sous une racine autorisée avec une charge utile exécutable fonctionne ; de même, copier un EXE signé avec `uiAccess="true"` dans n’importe quel sous-répertoire inscriptible (par exemple des résidus de mise à jour tels que `Tasks_Migrated` lorsqu’ils sont présents) lui permet de passer la vérification du chemin sécurisé.
- **MSIX dans `C:\Program Files\WindowsApps` (corrigé)** : les utilisateurs non administrateurs pouvaient installer des packages MSIX signés qui étaient placés dans `WindowsApps`, lequel n’était pas exclu. L’empaquetage d’un binaire UIAccess dans le MSIX, puis son lancement via `RAiLaunchAdminProcess`, produisait un **processus UIAccess avec un IL élevé, sans invite**. Microsoft a atténué le problème en excluant ce chemin ; la capability MSIX restreinte `uiAccess` exigeait déjà une installation par un administrateur.<sup>[[1]](#references)</sup>

## Workflow d’attaque (IL élevé sans invite)
1. Obtenir/construire un **binaire UIAccess signé** (manifeste `uiAccess="true"`). Pour une évaluation réaliste, effectuer les tests avec du matériel de confiance et des chemins explicitement autorisés pour le laboratoire ; ne pas ajouter de certificat d’attaquant au magasin racine de la machine locale d’un système de production.
2. Le placer dans un emplacement accepté par l’allowlist d’AppInfo (ou exploiter une particularité de validation du chemin/un artefact inscriptible comme indiqué ci-dessus).
3. Appeler `RAiLaunchAdminProcess` pour le démarrer **silencieusement** avec UIAccess et un IL élevé.
4. Depuis ce point d’appui avec un IL élevé, cibler un autre processus avec un IL élevé sur le bureau au moyen de **window hooks/injection de DLL** ou d’autres primitives avec un IL égal, afin de compromettre entièrement le contexte administrateur.<sup>[[1]](#references)</sup>

## Énumération des chemins inscriptibles candidats
Exécutez l’helper PowerShell pour découvrir les objets inscriptibles/pouvant être écrasés à l’intérieur de racines théoriquement sécurisées du point de vue d’un token choisi :<sup>[[1]](#references)</sup>
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- Exécutez en tant qu’administrateur pour une visibilité plus large ; définissez `-ProcessId` sur un processus avec peu de privilèges afin de reproduire l’accès de son token.
- Filtrez manuellement pour exclure les sous-répertoires connus comme interdits avant d’utiliser les candidats avec `RAiLaunchAdminProcess`.

## Connexe

Secure Desktop accessibility registry propagation LPE (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## References

- [1] [Contourner la protection de l’administrateur en abusant de UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [Analyse approfondie de GetProcessHandleFromHwnd (GPHFH)](https://projectzero.google/2026/02/gphfh-deep-dive.html)
- [3] [Microsoft Learn — Applications UIAccess](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works#uiaccess-applications)
{{#include ../../banners/hacktricks-training.md}}
