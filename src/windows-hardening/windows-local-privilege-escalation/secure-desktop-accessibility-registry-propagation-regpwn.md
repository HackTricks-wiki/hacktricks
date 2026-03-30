# Secure Desktop Accessibility Registry Propagation LPE (RegPwn)

{{#include ../../banners/hacktricks-training.md}}

## Vue d'ensemble

Les fonctionnalités Accessibility de Windows conservent la configuration utilisateur sous HKCU et la propagent vers les emplacements HKLM par session. Lors d'une transition **Secure Desktop** (écran de verrouillage ou invite UAC), les composants **SYSTEM** recopient ces valeurs. Si la clé HKLM par session est modifiable par l'utilisateur, elle devient un point d'étranglement d'écriture privilégiée qui peut être redirigé avec des **registry symbolic links**, conduisant à un **arbitrary SYSTEM registry write**.

La technique RegPwn abuse cette chaîne de propagation avec une petite fenêtre de course stabilisée via un **opportunistic lock (oplock)** sur un fichier utilisé par `osk.exe`.

## Registry Propagation Chain (Accessibility -> Secure Desktop)

Exemple de fonctionnalité : **On-Screen Keyboard** (`osk`). Les emplacements pertinents sont :

- **Liste des fonctionnalités système** :
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs`
- **Configuration par utilisateur (modifiable par l'utilisateur)** :
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
- **Configuration HKLM par session (créée par `winlogon.exe`, modifiable par l'utilisateur)** :
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- **Secure desktop/ruche utilisateur par défaut (contexte SYSTEM)** :
- `HKU\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`

Propagation lors d'une transition Secure Desktop (simplifié) :

1. **`atbroker.exe` côté utilisateur** copie `HKCU\...\ATConfig\osk` vers `HKLM\...\Session<session id>\ATConfig\osk`.
2. **`atbroker.exe` côté SYSTEM** copie `HKLM\...\Session<session id>\ATConfig\osk` vers `HKU\.DEFAULT\...\ATConfig\osk`.
3. **`osk.exe` côté SYSTEM** copie `HKU\.DEFAULT\...\ATConfig\osk` de nouveau vers `HKLM\...\Session<session id>\ATConfig\osk`.

Si la sous-arborescence HKLM de la session est modifiable par l'utilisateur, les étapes 2 et 3 fournissent une écriture SYSTEM via un emplacement que l'utilisateur peut remplacer.

## Primitive : Arbitrary SYSTEM Registry Write via Registry Links

Remplacez la clé HKLM par session modifiable par l'utilisateur par un **registry symbolic link** qui pointe vers une destination choisie par l'attaquant. Quand la copie par SYSTEM a lieu, elle suit le lien et écrit des valeurs contrôlées par l'attaquant dans la clé cible arbitraire.

Idée clé :

- Cible d'écriture victime (modifiable par l'utilisateur) :
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- L'attaquant remplace cette clé par un **registry link** vers n'importe quelle autre clé.
- SYSTEM effectue la copie et écrit dans la clé choisie par l'attaquant avec les permissions SYSTEM.

Cela fournit une primitive **arbitrary SYSTEM registry write**.

## Winning the Race Window with Oplocks

Il existe une courte fenêtre temporelle entre le démarrage de **`osk.exe` côté SYSTEM** et l'écriture de la clé par session. Pour rendre cela fiable, l'exploit place un **oplock** sur:
```
C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml
```
Quand l'oplock se déclenche, l'attaquant remplace la clé HKLM par session par un registry link, permet à SYSTEM d'écrire, puis supprime le lien.

## Exemple de flux d'exploitation (haut niveau)

1. Récupérer l'**ID de session** courant depuis l'access token.
2. Démarrer une instance cachée de `osk.exe` et attendre brièvement (s'assurer que l'oplock se déclenchera).
3. Écrire des valeurs contrôlées par l'attaquant dans :
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
4. Placer un **oplock** sur `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`.
5. Déclencher le **Secure Desktop** (`LockWorkstation()`), provoquant le démarrage sous SYSTEM de `atbroker.exe` / `osk.exe`.
6. Lorsque l'oplock se déclenche, remplacer `HKLM\...\Session<session id>\ATConfig\osk` par un **registry link** pointant vers une cible arbitraire.
7. Attendre brièvement la fin de la copie par SYSTEM, puis supprimer le lien.

## Conversion du primitif en exécution SYSTEM

Une chaîne simple consiste à écraser une valeur de **service configuration** (par ex., `ImagePath`) puis démarrer le service. Le RegPwn PoC écrase le `ImagePath` de **`msiserver`** et le déclenche en instanciant le **MSI COM object**, entraînant une exécution de code en **SYSTEM**.

## Articles connexes

Pour d'autres comportements de Secure Desktop / UIAccess, voir :

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

## References

- [RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [RegPwn PoC](https://github.com/mdsecactivebreach/RegPwn)

{{#include ../../banners/hacktricks-training.md}}
