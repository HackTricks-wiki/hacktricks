# LPE via la propagation du registre des fonctionnalités d’accessibilité du Secure Desktop (RegPwn)

{{#include ../../banners/hacktricks-training.md}}

## Vue d’ensemble

Les fonctionnalités d’accessibilité de Windows enregistrent la configuration utilisateur sous HKCU et la propagent vers des emplacements HKLM spécifiques à chaque session. Lors d’une transition vers le **Secure Desktop** (écran de verrouillage ou invite UAC), les composants **SYSTEM** recopient ces valeurs. Si la **clé HKLM spécifique à la session est accessible en écriture par l’utilisateur**, elle devient un point de contrôle privilégié pour les écritures, qui peut être redirigé à l’aide de **liens symboliques du registre**, permettant ainsi une **écriture arbitraire dans le registre avec les privilèges SYSTEM**.<sup>[[1]](#references)</sup>

La technique RegPwn exploite cette chaîne de propagation avec une petite fenêtre de course, stabilisée à l’aide d’un **opportunistic lock (oplock)** sur un fichier utilisé par `osk.exe`.<sup>[[1]](#references)</sup>

## Chaîne de propagation du registre (Accessibilité -> Secure Desktop)

Exemple de fonctionnalité : **On-Screen Keyboard** (`osk`). Les emplacements concernés sont les suivants :

- **Liste des fonctionnalités à l’échelle du système** :
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs`
- **Configuration spécifique à l’utilisateur (accessible en écriture par l’utilisateur)** :
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
- **Configuration HKLM spécifique à la session (créée par `winlogon.exe`, accessible en écriture par l’utilisateur)** :
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- **ruche utilisateur Secure Desktop/par défaut (contexte SYSTEM)** :
- `HKU\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`

Propagation lors d’une transition vers le Secure Desktop (version simplifiée) :

1. **`atbroker.exe` de l’utilisateur** copie `HKCU\...\ATConfig\osk` vers `HKLM\...\Session<session id>\ATConfig\osk`.
2. **`atbroker.exe` s’exécutant avec SYSTEM** copie `HKLM\...\Session<session id>\ATConfig\osk` vers `HKU\.DEFAULT\...\ATConfig\osk`.
3. **`osk.exe` s’exécutant avec SYSTEM** recopie `HKU\.DEFAULT\...\ATConfig\osk` vers `HKLM\...\Session<session id>\ATConfig\osk`.

Si le sous-arbre HKLM de la session est accessible en écriture par l’utilisateur, les étapes 2 et 3 fournissent une écriture SYSTEM via un emplacement que l’utilisateur peut remplacer.<sup>[[1]](#references)</sup>

## Primitive : écriture arbitraire dans le registre avec SYSTEM via des liens du registre

Remplacez la clé spécifique à la session accessible en écriture par l’utilisateur par un **lien symbolique du registre** pointant vers une destination choisie par l’attaquant. Lorsque la copie SYSTEM est effectuée, elle suit le lien et écrit les valeurs contrôlées par l’attaquant dans la clé cible arbitraire.

Idée clé :

- Cible de l’écriture victime (accessible en écriture par l’utilisateur) :
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- L’attaquant remplace cette clé par un **lien du registre** vers n’importe quelle autre clé.
- SYSTEM effectue la copie et écrit dans la clé choisie par l’attaquant avec les permissions SYSTEM.

Cela fournit une primitive d’**écriture arbitraire dans le registre avec SYSTEM**.<sup>[[1]](#references)</sup>

## Gagner la fenêtre de course avec des oplocks

Une courte fenêtre de temps existe entre le démarrage de **`osk.exe` s’exécutant avec SYSTEM** et l’écriture de la clé spécifique à la session. Pour rendre l’exploit fiable, l’exploit place un **oplock** sur :
```
C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml
```
Lorsque l’oplock se déclenche, l’attaquant remplace la clé HKLM par session par un registry link, laisse l’écriture effectuée par SYSTEM aboutir, puis supprime le lien.<sup>[[1]](#references)</sup>

## Flux d’exploitation par exemple (vue d’ensemble)

1. Obtenir l’**ID de session** actuel depuis l’access token.
2. Démarrer une instance masquée de `osk.exe` et patienter brièvement (pour garantir le déclenchement de l’oplock).
3. Écrire les valeurs contrôlées par l’attaquant dans :
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
4. Définir un **oplock** sur `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`.
5. Déclencher le **Secure Desktop** (`LockWorkstation()`), ce qui force SYSTEM à démarrer `atbroker.exe` / `osk.exe`.
6. Lors du déclenchement de l’oplock, remplacer `HKLM\...\Session<session id>\ATConfig\osk` par un **registry link** vers une cible arbitraire.
7. Patienter brièvement le temps que la copie effectuée par SYSTEM se termine, puis supprimer le lien.<sup>[[1]](#references)</sup>

## Transformer la primitive en exécution SYSTEM

Une chaîne simple consiste à écraser une valeur de **configuration de service** (par exemple, `ImagePath`), puis à démarrer le service. Le PoC RegPwn écrase la valeur `ImagePath` de **`msiserver`** et le déclenche en instanciant l’**objet COM MSI**, ce qui permet l’exécution de code en tant que **SYSTEM**.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

## Associé

Pour d’autres comportements liés à Secure Desktop / UIAccess, voir :

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

## References

- [1] [RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [2] [PoC RegPwn](https://github.com/mdsecactivebreach/RegPwn)
{{#include ../../banners/hacktricks-training.md}}
