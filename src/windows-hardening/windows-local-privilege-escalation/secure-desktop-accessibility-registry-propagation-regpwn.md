# Secure Desktop Accessibility Registry Propagation LPE (RegPwn)

{{#include ../../banners/hacktricks-training.md}}

## Aperçu

Les fonctionnalités Windows Accessibility conservent la configuration utilisateur sous HKCU et la propagent vers des emplacements HKLM propres à chaque session. Lors d'une transition vers le **Secure Desktop** (écran de verrouillage ou invite UAC), les composants **SYSTEM** recopient ces valeurs. Si la **per-session HKLM key** est writable par l'utilisateur, elle devient un point d'écriture privilégié qui peut être redirigé avec des **registry symbolic links**, permettant ainsi une **arbitrary SYSTEM registry write**.<sup>[[1]](#references)</sup>

La technique RegPwn exploite cette chaîne de propagation avec une courte race window stabilisée grâce à un **opportunistic lock (oplock)** sur un fichier utilisé par `osk.exe`.<sup>[[1]](#references)</sup>

## Registry Propagation Chain (Accessibility -> Secure Desktop)

Exemple de fonctionnalité : **On-Screen Keyboard** (`osk`). Les emplacements concernés sont :

- **System-wide feature list** :
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs`
- **Per-user configuration (user-writable)** :
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
- **Per-session HKLM config (created by `winlogon.exe`, user-writable)** :
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- **Secure desktop/default user hive (SYSTEM context)** :
- `HKU\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`

Propagation lors d'une transition vers le secure desktop (simplifiée) :

1. **User `atbroker.exe`** copie `HKCU\...\ATConfig\osk` vers `HKLM\...\Session<session id>\ATConfig\osk`.
2. **SYSTEM `atbroker.exe`** copie `HKLM\...\Session<session id>\ATConfig\osk` vers `HKU\.DEFAULT\...\ATConfig\osk`.
3. **SYSTEM `osk.exe`** recopie `HKU\.DEFAULT\...\ATConfig\osk` vers `HKLM\...\Session<session id>\ATConfig\osk`.

Si le sous-arbre HKLM de la session est writable par l'utilisateur, les étapes 2/3 fournissent une écriture SYSTEM via un emplacement que l'utilisateur peut remplacer.<sup>[[1]](#references)</sup>

## Primitive: Arbitrary SYSTEM Registry Write via Registry Links

Remplacez la clé per-session writable par l'utilisateur par un **registry symbolic link** qui pointe vers une destination choisie par l'attaquant. Lorsque la copie SYSTEM a lieu, elle suit le lien et écrit les valeurs contrôlées par l'attaquant dans la clé cible arbitraire.

Idée principale :

- Cible d'écriture de la victime (user-writable) :
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- L'attaquant remplace cette clé par un **registry link** vers n'importe quelle autre clé.
- SYSTEM effectue la copie et écrit dans la clé choisie par l'attaquant avec les permissions SYSTEM.

Cela fournit une primitive d'**arbitrary SYSTEM registry write**.<sup>[[1]](#references)</sup>

## Winning the Race Window with Oplocks

Il existe une courte fenêtre temporelle entre le démarrage de **SYSTEM `osk.exe`** et l'écriture dans la clé per-session. Pour rendre l'exploit fiable, l'exploit place un **oplock** sur :
```
C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml
```
Lorsque l’oplock se déclenche, l’attaquant remplace la clé HKLM propre à la session par un registry link, laisse l’écriture effectuée par SYSTEM aboutir, puis supprime le link.<sup>[[1]](#references)</sup>

## Exemple de déroulement de l’exploitation (vue d’ensemble)

1. Récupérer l’**ID de session** actuel depuis l’access token.
2. Démarrer une instance masquée de `osk.exe` et attendre brièvement (pour s’assurer que l’oplock se déclenchera).
3. Écrire des valeurs contrôlées par l’attaquant dans :
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
4. Définir un **oplock** sur `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`.
5. Déclencher le **Secure Desktop** (`LockWorkstation()`), ce qui entraîne le démarrage de `atbroker.exe` / `osk.exe` par SYSTEM.
6. Lors du déclenchement de l’oplock, remplacer `HKLM\...\Session<session id>\ATConfig\osk` par un **registry link** vers une cible arbitraire.
7. Attendre brièvement que la copie effectuée par SYSTEM soit terminée, puis supprimer le link.<sup>[[1]](#references)</sup>

## Transformer la primitive en exécution SYSTEM

Une chaîne simple consiste à écraser une valeur de **configuration de service** (par exemple, `ImagePath`), puis à démarrer le service. Le PoC RegPwn écrase la valeur `ImagePath` de **`msiserver`** et le déclenche en instanciant l’**objet COM MSI**, ce qui entraîne l’exécution de code en **SYSTEM**.<sup>[[1]](#references)[[2]](#references)</sup>

## Contenu associé

Pour d’autres comportements liés au Secure Desktop / UIAccess, voir :

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

## Références

- [1] [RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [2] [RegPwn PoC](https://github.com/mdsecactivebreach/RegPwn)

{{#include ../../banners/hacktricks-training.md}}
